// Package psiphon is the Psiphon outbound provider plugin for the goose
// proxy-pool engine.
//
// It embeds github.com/goose-network/psiphon-tunnel-core as a Go library and
// runs its controllers directly — no local SOCKS or HTTP proxy sits between
// goose and the tunnels. Two seams make that work:
//
//   - dials go through controller.Dial, in process (outbound.go);
//   - the tunnels' own TCP connections to their Psiphon servers dial through
//     the engine's layer-3/4 stack — the system kernel stack or the gvisor
//     netstack — via Config.SetCustomDialer (tunnel.go).
//
// # The real server list
//
// tunnel-core's background RemoteServerListFetcher downloads the signed
// server list (verified against the production RSA keys embedded in
// defaults.go), auto-updating it exactly like the official Psiphon client.
// The provider scans the datastore and emits one goose outbound per pinnable
// server — IP, region, protocols — plus one general outbound that lets
// tunnel-core pick any server. The engine shows every one of them through
// its admin API, so the web UI displays Psiphon's actual servers, and each
// can be pooled, pinned, or filtered like any other outbound.
//
// # Zero-config operation
//
// With no config at all the provider runs out of the box: it synthesizes a
// psiphon.config carrying the production Psiphon network's propagation
// channel, sponsor ID, remote server list URLs, and signing keys, so the
// fetcher populates the datastore on its own. A config_path still wins when
// supplied (self-hosted or custom networks).
//
// # Config
//
// The provider config is a JSON object; every field is optional:
//
//	{
//	  "config_path":      "/path/to/psiphon.config", // optional; default embedded network config
//	  "server_list_path": "/path/to/server_list.dat", // optional; imported into the datastore
//	  "data_dir":         "/path/to/data-root",      // optional; default "psiphon-data"
//	  "upstream_proxy":   "socks5://127.0.0.1:7890",  // optional; routes tunnel-core's own dials
//	  "establish_timeout_seconds": 120,                // optional
//	  "outbound_id":      "psiphon"                    // optional, default "psiphon"
//	}
//
// upstream_proxy routes tunnel-core's connections (tunnel dials and list
// fetches) through an explicit proxy URL. When set it overrides the engine
// stack for tunnel dials: tunnel-core's CustomDialer takes precedence over
// UpstreamProxyURL, so honoring both is impossible and the explicit route
// wins.
//
// # Fresh-deployment default
//
// This plugin is zero-config, so it declares itself the engine's default
// provider via pub.RegisterDefaultProvider: an engine started with no
// providers configured seeds a psiphon provider and is routable out of the
// box.
package psiphon

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"

	pub "github.com/goose-network/goose-plugin-api"
)

// serverIdleReap is how long a pinned server tunnel with no open
// connections may sit idle before the reaper stops it. The next dial to
// that server starts a fresh controller.
const serverIdleReap = 10 * time.Minute

// Provider is a goose outbound provider backed by tunnel-core controllers. It
// implements pub.Provider and Close (the engine calls Close when the spec is
// deleted or changed).
type Provider struct {
	cfg providerConfig

	// configJSON is the sanitized base config every tunnel loads: defaults
	// or the operator's config_path, with the runtime-owned fields stripped
	// and the upstream proxy injected.
	configJSON []byte
	dataDir    string

	// stackDialer is the engine's L3/L4 dialer injected under
	// pub.StackDialerKey; nil means tunnel-core dials directly.
	stackDialer pub.StackDialer

	ctx    context.Context
	cancel context.CancelFunc

	// main is the general tunnel: tunnel-core picks any server. Pinned
	// per-server tunnels live in p.pinned.
	main *tunnelCore

	mu      sync.Mutex
	servers map[string]serverInfo    // last scan, by IP: the pin sources
	pinned  map[string]*serverTunnel // live per-server controllers, by IP

	watchCh chan struct{}
	unsub   func() // notice hub unsubscribe

	// lastListDownload is when the remote server list last landed in the
	// datastore (unix nano; 0 = never), set by handleNotice and surfaced
	// through Status.
	lastListDownload atomic.Int64

	closeOnce sync.Once
}

// providerConfig is the deserialized provider config map.
type providerConfig struct {
	ConfigPath              string `json:"config_path"`
	ServerListPath          string `json:"server_list_path"`
	DataDir                 string `json:"data_dir"`
	UpstreamProxy           string `json:"upstream_proxy"`
	EstablishTimeoutSeconds int    `json:"establish_timeout_seconds"`
	OutboundID              string `json:"outbound_id"`
}

// NewProvider is the ProviderFactory registered as "psiphon". It loads the
// config, opens the datastore, starts the general tunnel, and subscribes to
// tunnel-core notices; Outbounds emits the general outbound once the tunnel
// is up and the per-server outbounds as soon as the datastore has entries.
func NewProvider(cfg map[string]any) (pub.Provider, error) {
	// The notice hub is a process global; installing it here means notices
	// are routed to providers the moment the first one exists.
	installNoticeHub()

	pc, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}
	stackDialer := pub.AsStackDialer(cfg)

	var configJSON []byte
	if pc.ConfigPath != "" {
		configJSON, err = os.ReadFile(pc.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("psiphon provider: read config %s: %w", pc.ConfigPath, err)
		}
	} else {
		// Zero-config: synthesize the production-network config so the
		// remote-server-list fetcher can retrieve the server list itself.
		configJSON = defaultConfigJSON()
	}
	configJSON, err = sanitizeConfig(configJSON, pc.UpstreamProxy)
	if err != nil {
		return nil, fmt.Errorf("psiphon provider: sanitize config: %w", err)
	}

	if err := os.MkdirAll(pc.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("psiphon provider: mkdir data dir: %w", err)
	}
	dataDir, _ := filepath.Abs(pc.DataDir)

	ctx, cancel := context.WithCancel(context.Background())
	p := &Provider{
		cfg:         pc,
		configJSON:  configJSON,
		dataDir:     dataDir,
		stackDialer: stackDialer,
		ctx:         ctx,
		cancel:      cancel,
		servers:     map[string]serverInfo{},
		pinned:      map[string]*serverTunnel{},
		watchCh:     make(chan struct{}, 1),
	}

	// The general tunnel is created (config committed) but not started until
	// the datastore is open on its config: the controller's Run loop reads
	// the datastore immediately.
	main, err := newTunnelCore(configJSON, tunnelOptions{
		label:             pc.OutboundID,
		dataRootDirectory: dataDir,
		establishTimeout:  p.establishTimeout(),
	}, stackDialer)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("psiphon provider: %w", err)
	}
	p.main = main

	// The datastore is refcounted in tunnel-core: opened once here, shared
	// by the general tunnel and every pinned controller, closed in Close.
	if err := psiphon.OpenDataStore(main.config); err != nil {
		cancel()
		main.stop()
		return nil, fmt.Errorf("psiphon provider: open datastore: %w", err)
	}

	// An operator-supplied server_list.dat seeds the datastore before the
	// fetcher has ever run. Best effort: the fetcher remains the source of
	// truth for a config with remote server list URLs.
	if pc.ServerListPath != "" {
		if err := psiphon.ImportEmbeddedServerEntries(ctx, main.config, pc.ServerListPath, ""); err != nil {
			fmt.Printf("psiphon provider: import server list %s: %v\n", pc.ServerListPath, err)
		}
	}

	p.unsub = hub.subscribe(p.handleNotice)
	registerLiveProvider(p)
	main.start()
	go p.reapLoop(ctx)

	fmt.Printf("psiphon provider: started (outbound id %q, data dir %s)\n", pc.OutboundID, dataDir)
	return p, nil
}

func parseConfig(cfg map[string]any) (providerConfig, error) {
	// The engine injects live dialer values (pub.StackDialerKey, and
	// pub.UpstreamDialerKey for routed fetches) into the same map; they are
	// consumed via AsStackDialer and must not round-trip through the JSON
	// marshal below (and would break it, were the values ever
	// non-marshalable). Clone first: the injected map belongs to the caller.
	cfg = maps.Clone(cfg)
	for _, k := range []string{pub.StackDialerKey, pub.UpstreamDialerKey} {
		delete(cfg, k)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return providerConfig{}, fmt.Errorf("marshal provider config: %w", err)
	}
	var pc providerConfig
	if err := json.Unmarshal(raw, &pc); err != nil {
		return providerConfig{}, fmt.Errorf("parse provider config: %w", err)
	}
	if pc.OutboundID == "" {
		pc.OutboundID = "psiphon"
	}
	if pc.EstablishTimeoutSeconds <= 0 {
		pc.EstablishTimeoutSeconds = 120
	}
	if pc.DataDir == "" {
		// Anchor the persisted datastore (server list, tunnel state) next to
		// the engine's own state rather than /tmp: the working directory is
		// /data on the docker volume and wherever the engine's goose.db lives
		// locally, so the server list survives restarts and /tmp writability
		// (e.g. distroless nonroot) is never a question.
		pc.DataDir = "psiphon-data"
	}
	return pc, nil
}

// establishTimeout is how long a dial waits for its tunnel to establish.
func (p *Provider) establishTimeout() time.Duration {
	return time.Duration(p.cfg.EstablishTimeoutSeconds) * time.Second
}

// handleNotice reacts to tunnel-core notices: tunnel establishment and
// remote-server-list downloads both signal the engine to re-poll, so the
// general outbound appears the moment the tunnel is up and the per-server
// outbounds seconds after each list download. The list download also
// timestamps itself for Status.
func (p *Provider) handleNotice(n notice) {
	switch n.Type {
	case "Tunnels":
		if count, ok := n.Data["count"].(float64); ok && count > 0 {
			p.signalWatch()
		}
	case "RemoteServerListResourceDownloaded":
		p.lastListDownload.Store(time.Now().UnixNano())
		p.signalWatch()
	}
}

// Name returns the provider plugin name.
func (p *Provider) Name() string { return "psiphon" }

// Watch returns the change signal channel.
func (p *Provider) Watch() <-chan struct{} { return p.watchCh }

// Outbounds returns the provider's outbound set: the general outbound (once
// the main tunnel is established) plus one outbound per pinnable server in
// the datastore. Per-server outbounds do not wait for the main tunnel — each
// dials through its own lazily-started pinned controller.
func (p *Provider) Outbounds(_ context.Context) ([]pub.OutboundConfig, error) {
	servers, err := scanPinnableServers(p.cfg.UpstreamProxy != "")
	if err != nil {
		// Transient datastore trouble: keep the engine's existing pools; the
		// next refresh signal retries.
		return nil, err
	}

	// Publish the scan for the dial path (pin sources) before emitting.
	p.mu.Lock()
	srv := make(map[string]serverInfo, len(servers))
	for _, s := range servers {
		srv[s.IP] = s
	}
	p.servers = srv
	p.mu.Unlock()

	out := make([]pub.OutboundConfig, 0, len(servers)+1)
	if p.main.established.Load() {
		out = append(out, pub.OutboundConfig{
			ID:       p.cfg.OutboundID,
			Protocol: "psiphon",
			Config: map[string]any{
				"id":     p.cfg.OutboundID,
				"tunnel": p.cfg.OutboundID,
			},
		})
	}
	for _, s := range servers {
		out = append(out, pub.OutboundConfig{
			ID:       p.cfg.OutboundID + "-" + s.IP,
			Protocol: "psiphon",
			Config: map[string]any{
				"id":        p.cfg.OutboundID + "-" + s.IP,
				"tunnel":    p.cfg.OutboundID,
				"server":    s.IP,
				"address":   s.Address,
				"region":    s.Region,
				"protocols": s.Protocols,
			},
		})
	}
	return out, nil
}

// Status reports the provider's live self-assessment for the engine's
// provider observability view (pub.StatusReporter): tunnel phase, server
// list freshness, and which per-server tunnels are currently pinned up with
// connections riding them.
func (p *Provider) Status() pub.ProviderStatus {
	p.mu.Lock()
	defer p.mu.Unlock()

	details := map[string]any{
		"data_dir":        p.dataDir,
		"upstream_proxy":  p.cfg.UpstreamProxy != "",
		"engine_stack":    p.stackDialer != nil && p.cfg.UpstreamProxy == "",
		"servers_in_list": len(p.servers),
	}

	var phase, message string
	switch {
	case p.main == nil:
		phase = "starting"
		message = "tunnel not started"
	case p.main.stopped():
		phase = "stopped"
	case p.main.established.Load():
		phase = "running"
	default:
		phase = "establishing"
		message = fmt.Sprintf("waiting for the general tunnel (timeout %s)", p.establishTimeout())
	}

	if ts := p.lastListDownload.Load(); ts > 0 {
		details["last_list_download"] = time.Unix(0, ts).UTC().Format(time.RFC3339)
	} else {
		details["last_list_download"] = "never"
	}

	if len(p.pinned) > 0 {
		pinned := make([]string, 0, len(p.pinned))
		open := 0
		for ip, st := range p.pinned {
			pinned = append(pinned, ip)
			open += int(st.open.Load())
		}
		sort.Strings(pinned)
		details["pinned_tunnels"] = pinned
		details["open_connections"] = open
	}

	return pub.ProviderStatus{
		State:   phase,
		Message: message,
		Details: details,
	}
}

// Close stops the provider: notice subscription and registry entry first
// (new dials fail fast), then the tunnels, then the shared datastore. It is
// idempotent.
func (p *Provider) Close() error {
	p.closeOnce.Do(func() {
		if p.unsub != nil {
			p.unsub()
		}
		unregisterLiveProvider(p)
		p.cancel()
		if p.main != nil {
			p.main.stop()
		}
		p.mu.Lock()
		pinned := make([]*serverTunnel, 0, len(p.pinned))
		for _, st := range p.pinned {
			pinned = append(pinned, st)
		}
		p.pinned = map[string]*serverTunnel{}
		p.mu.Unlock()
		for _, st := range pinned {
			st.stop()
		}
		psiphon.CloseDataStore()
		fmt.Printf("psiphon provider: stopped (outbound id %q)\n", p.cfg.OutboundID)
	})
	return nil
}

// dialMain connects through the general tunnel, waiting for it to establish.
func (p *Provider) dialMain(ctx context.Context, target string) (net.Conn, error) {
	if p.main == nil {
		return nil, fmt.Errorf("psiphon: no general tunnel (provider not started)")
	}
	if err := p.main.waitEstablished(ctx, p.establishTimeout()); err != nil {
		return nil, err
	}
	return p.main.Dial(target)
}

// dialServer connects through the pinned controller for one server,
// starting it lazily on first use. The open-connection pin taken here holds
// the reaper off until the engine closes the connection.
func (p *Provider) dialServer(ctx context.Context, ip, target string) (net.Conn, error) {
	st, err := p.serverTunnelState(ip)
	if err != nil {
		return nil, err
	}
	st.open.Add(1)
	t, err := p.tunnelForServer(st)
	if err != nil {
		st.open.Add(-1)
		return nil, err
	}
	st.touch()
	if err := t.waitEstablished(ctx, p.establishTimeout()); err != nil {
		st.open.Add(-1)
		return nil, err
	}
	conn, err := t.Dial(target)
	if err != nil {
		st.open.Add(-1)
		return nil, err
	}
	return &countingConn{Conn: conn, done: func() { st.open.Add(-1) }}, nil
}

// serverTunnelState returns the pinned-tunnel state for ip, creating it from
// the last scan when absent. An ip missing from the scan is a stale outbound
// config (the server left the list) or a hand-written mistake: error, don't
// dial blind.
func (p *Provider) serverTunnelState(ip string) (*serverTunnel, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.pinned[ip]; ok {
		return st, nil
	}
	info, ok := p.servers[ip]
	if !ok {
		return nil, fmt.Errorf("psiphon: server %s is not in the current list", ip)
	}
	st := &serverTunnel{ip: ip, encoded: info.Encoded}
	p.pinned[ip] = st
	return st, nil
}

// tunnelForServer returns a live pinned tunnel for st, starting one when
// none is running and no recent start failure is being held. Callers hold
// st's open-connection pin, so the reaper stays off for the duration.
func (p *Provider) tunnelForServer(st *serverTunnel) (*tunnelCore, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.tunnel != nil && !st.tunnel.stopped() {
		return st.tunnel, nil
	}
	if st.startErr != nil && time.Since(st.startAt) < serverStartRetryInterval {
		return nil, st.startErr
	}
	st.touch()
	t, err := newTunnelCore(p.configJSON, tunnelOptions{
		label:             fmt.Sprintf("%s[%s]", p.cfg.OutboundID, st.ip),
		dataRootDirectory: p.dataDir,
		targetServerEntry: st.encoded,
		establishTimeout:  p.establishTimeout(),
	}, p.stackDialer)
	if err != nil {
		st.startErr, st.startAt = err, time.Now()
		return nil, err
	}
	st.tunnel, st.startErr = t, nil
	t.start()
	return t, nil
}

// reapLoop stops pinned server tunnels that have no open connections and
// have gone idle. It exits with the provider's context.
func (p *Provider) reapLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.reapOnce()
		}
	}
}

func (p *Provider) reapOnce() {
	p.mu.Lock()
	var reap []*serverTunnel
	for ip, st := range p.pinned {
		if st.open.Load() != 0 || st.tunnel == nil {
			continue
		}
		if st.idleFor() < serverIdleReap {
			continue
		}
		reap = append(reap, st)
		delete(p.pinned, ip)
	}
	p.mu.Unlock()
	for _, st := range reap {
		fmt.Printf("psiphon provider: reaping idle tunnel %s[%s]\n", p.cfg.OutboundID, st.ip)
		st.stop()
	}
}

// signalWatch notifies the engine (non-blocking) that the outbound set may
// have changed.
func (p *Provider) signalWatch() {
	select {
	case p.watchCh <- struct{}{}:
	default:
	}
}

// sanitizeConfig strips host-specific and runtime-owned fields from the
// Psiphon config. The Windows Migrate* paths' backslashes break the
// upgrade-file regex on Linux; the runtime-owned fields (data root, local
// proxy ports, target server entry, notice routing, timeouts, ...) are set
// by the plugin per controller and must not leak in from the file. It does
// NOT strip DisableRemoteServerListFetcher from the general config — the
// background fetcher is what auto-updates the server list. The optional
// upstream proxy is injected.
func sanitizeConfig(raw []byte, upstreamProxy string) ([]byte, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config JSON: %w", err)
	}
	for _, k := range []string{
		"MigrateDataStoreDirectory",
		"MigrateObfuscatedServerListDownloadDirectory",
		"MigrateRemoteServerListDownloadFilename",
		"MigrateUpgradeDownloadFilename",
		"DataRootDirectory",
		"LocalSocksProxyPort",
		"LocalHttpProxyPort",
		"LocalSocksProxy", // legacy alias, when the config predates the bool form
		"EgressRegion",
		"DeviceRegion",
		"NetworkID",
		"NetworkIDGetter",
		"ClientPlatform",
		"EstablishTunnelTimeoutSeconds",
		"TargetServerEntry",
		"DisableLocalSocksProxy",
		"DisableLocalHTTPProxy",
		"EmitDiagnosticNotices",
		"EmitDiagnosticNoticesToFiles",
		"UseNoticeFiles",
		"DisableServerEntriesReporter",
		"DisableTactics",
		"UpstreamProxyUrl",
		"UpstreamProxyURL",
	} {
		delete(cfg, k)
	}
	if upstreamProxy != "" {
		b, _ := json.Marshal(upstreamProxy)
		cfg["UpstreamProxyURL"] = b
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("re-marshal config: %w", err)
	}
	return out, nil
}

// init registers the provider factory with the goose plugin registry, and
// declares the zero-config plugin as the fresh-deployment default provider.
// Import this package with a blank import in the engine binary to activate
// it:
//
//	import _ "github.com/goose-network/goose-plugin-psiphon"
func init() {
	pub.RegisterProvider("psiphon", NewProvider)
	// Zero-config: this plugin runs on its embedded production-network
	// defaults with an empty config map, so a fresh engine (no providers
	// configured) seeds a psiphon provider. The engine does this generically
	// from the registry declaration — nothing psiphon-specific lives there.
	pub.RegisterDefaultProvider(pub.DefaultProvider{Provider: "psiphon"})
}
