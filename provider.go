// Package psiphon is the Psiphon outbound provider plugin for the goose
// proxy-pool engine.
//
// It embeds github.com/Psiphon-Labs/psiphon-tunnel-core as a Go library and
// starts a Psiphon tunnel, then exposes the tunnel's local SOCKS proxy as a
// goose outbound. The engine merges that outbound into a managed pool, so any
// goose inbound routed through the pool forwards traffic through Psiphon.
//
// # Auto-updating server list
//
// tunnel-core's background RemoteServerListFetcher is left enabled (we do not
// set DisableRemoteServerListFetcher), so the server list auto-updates the
// same way the Psiphon Windows client's does: the signed remote server list is
// downloaded from the config URLs, verified with
// RemoteServerListSignaturePublicKey / ServerEntrySignaturePublicKey, and new
// entries are stored in the BoltDB datastore. Handshake responses may also
// discover entries. The provider signals Watch() when the tunnel first
// establishes and on each remote-list download, so the engine re-polls and the
// pool reflects the current state.
//
// From goose's perspective all Psiphon servers are reached through the single
// local SOCKS proxy that tunnel-core runs, so the provider emits one socks5
// outbound whose address is that local port. (The rich per-server metadata is
// kept inside tunnel-core, which owns server selection.)
//
// # Config
//
// The provider config is a JSON object:
//
//	{
//	  "config_path":      "/path/to/psiphon.config",
//	  "server_list_path": "/path/to/server_list.dat",
//	  "data_dir":         "/path/to/data-root",
//	  "upstream_proxy":   "socks5://127.0.0.1:7890",  // optional
//	  "establish_timeout_seconds": 120,                // optional
//	  "outbound_id":      "psiphon"                    // optional, default "psiphon"
//	}
//
// config_path and server_list_path are the real psiphon.config and
// server_list.dat from a Psiphon install (see the demo for how to obtain them).
package psiphon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary/clientlib"
	pub "github.com/goose-network/goose-plugin-api"
)

// Provider is a goose outbound provider backed by a Psiphon tunnel-core
// tunnel. It implements pub.Provider.
type Provider struct {
	cfg providerConfig

	// tunnel state
	mu      sync.Mutex
	tunnel  *clientlib.PsiphonTunnel
	socksPort int
	ready   bool

	// watch signals the engine that the outbound set may have changed
	// (tunnel established, or server list refreshed).
	watchCh chan struct{}

	// stop cancels the tunnel start goroutine; stopWg waits for it.
	stop     context.CancelFunc
	stopWg   sync.WaitGroup
}

// providerConfig is the deserialized provider config map.
type providerConfig struct {
	ConfigPath                string `json:"config_path"`
	ServerListPath            string `json:"server_list_path"`
	DataDir                   string `json:"data_dir"`
	UpstreamProxy             string `json:"upstream_proxy"`
	EstablishTimeoutSeconds   int    `json:"establish_timeout_seconds"`
	OutboundID                string `json:"outbound_id"`
}

// New is the ProviderFactory registered as "psiphon". It parses the config
// map and starts the tunnel-core tunnel in the background; Outbounds returns
// the SOCKS outbound once the tunnel is established, and an empty set until
// then.
func New(cfg map[string]any) (pub.Provider, error) {
	pc, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}
	if pc.OutboundID == "" {
		pc.OutboundID = "psiphon"
	}
	if pc.EstablishTimeoutSeconds <= 0 {
		pc.EstablishTimeoutSeconds = 120
	}

	p := &Provider{
		cfg:     pc,
		watchCh: make(chan struct{}, 1),
	}

	if err := p.startTunnel(); err != nil {
		return nil, fmt.Errorf("psiphon provider: start tunnel: %w", err)
	}
	return p, nil
}

func parseConfig(cfg map[string]any) (providerConfig, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return providerConfig{}, fmt.Errorf("marshal provider config: %w", err)
	}
	var pc providerConfig
	if err := json.Unmarshal(raw, &pc); err != nil {
		return providerConfig{}, fmt.Errorf("parse provider config: %w", err)
	}
	if pc.ConfigPath == "" {
		return providerConfig{}, fmt.Errorf("psiphon provider: config_path is required")
	}
	if pc.DataDir == "" {
		pc.DataDir = filepath.Join(os.TempDir(), "goose-psiphon-data")
	}
	return pc, nil
}

// startTunnel launches the tunnel-core tunnel in a background goroutine. It
// returns once the tunnel start attempt is underway (not once established);
// the goroutine flips p.ready and signals Watch when establishment succeeds.
func (p *Provider) startTunnel() error {
	configJSON, err := os.ReadFile(p.cfg.ConfigPath)
	if err != nil {
		return fmt.Errorf("read config %s: %w", p.cfg.ConfigPath, err)
	}
	configJSON, err = sanitizeConfig(configJSON, p.cfg.UpstreamProxy)
	if err != nil {
		return fmt.Errorf("sanitize config: %w", err)
	}

	embeddedServerList := ""
	if p.cfg.ServerListPath != "" {
		b, err := os.ReadFile(p.cfg.ServerListPath)
		if err != nil {
			return fmt.Errorf("read server list %s: %w", p.cfg.ServerListPath, err)
		}
		embeddedServerList = string(b)
	}

	if err := os.MkdirAll(p.cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}
	dataDirAbs, _ := filepath.Abs(p.cfg.DataDir)

	clientPlatform := "Linux_goose-plugin-psiphon"
	networkID := "GOOSE-PSIPHON"
	timeout := p.cfg.EstablishTimeoutSeconds
	disableHTTP := true

	params := clientlib.Parameters{
		DataRootDirectory:             &dataDirAbs,
		ClientPlatform:                &clientPlatform,
		NetworkID:                     &networkID,
		EstablishTunnelTimeoutSeconds: &timeout,
		EmitDiagnosticNoticesToFiles:  true,
		DisableLocalHTTPProxy:         &disableHTTP,
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.stop = cancel

	// Notice receiver: watch for tunnel establishment and remote-server-list
	// downloads. Both signal Watch() so the engine re-polls Outbounds.
	noticeCh := make(chan clientlib.NoticeEvent, 256)
	go func() {
		for n := range noticeCh {
			p.handleNotice(n)
		}
	}()
	noticeReceiver := func(n clientlib.NoticeEvent) {
		select {
		case noticeCh <- n:
		default:
		}
	}

	p.stopWg.Add(1)
	go func() {
		defer p.stopWg.Done()
		defer close(noticeCh)
		tunnel, err := clientlib.StartTunnel(ctx, configJSON, embeddedServerList, params, nil, noticeReceiver)
		if err != nil {
			fmt.Fprintf(os.Stderr, "psiphon provider: StartTunnel failed: %v\n", err)
			return
		}
		p.mu.Lock()
		p.tunnel = tunnel
		p.socksPort = tunnel.SOCKSProxyPort
		p.ready = true
		p.mu.Unlock()
		fmt.Printf("psiphon provider: tunnel established, local SOCKS port %d\n", tunnel.SOCKSProxyPort)
		p.signalWatch()

		// Block until the tunnel is stopped. StartTunnel returns only after
		// the controller exits, so we don't need to wait separately; but we
		// must keep tunnel.Stop() available for Close. The controller runs in
		// its own goroutines inside StartTunnel; when ctx is canceled it
		// returns. We wait on ctx here so the goroutine stays alive for the
		// tunnel's lifetime.
		<-ctx.Done()
		tunnel.Stop()
		p.mu.Lock()
		p.ready = false
		p.tunnel = nil
		p.mu.Unlock()
	}()

	return nil
}

// handleNotice reacts to tunnel-core notices: tunnel establishment and
// remote-server-list downloads both signal the engine to re-poll.
func (p *Provider) handleNotice(n clientlib.NoticeEvent) {
	switch n.Type {
	case "Tunnels":
		// count > 0 means an active tunnel; the establishment is also handled
		// in startTunnel's goroutine, but signal here too for promptness.
		if count, ok := n.Data["count"].(float64); ok && count > 0 {
			p.signalWatch()
		}
	case "RemoteServerListResourceDownloaded":
		// A remote server list download completed; the datastore has new
		// entries. Signal so the engine re-polls (the outbound address is
		// stable, but this keeps the pool's view of availability fresh and
		// leaves room for future per-server expansion).
		p.signalWatch()
	}
}

// Name returns the provider plugin name.
func (p *Provider) Name() string { return "psiphon" }

// Watch returns the change signal channel.
func (p *Provider) Watch() <-chan struct{} { return p.watchCh }

// Outbounds returns the current set of outbound configs. Until the tunnel is
// established it returns an empty slice (the engine keeps the pool empty);
// once established it returns a single socks5 outbound pointing at the
// tunnel's local SOCKS proxy.
func (p *Provider) Outbounds(_ context.Context) ([]pub.OutboundConfig, error) {
	p.mu.Lock()
	ready := p.ready
	port := p.socksPort
	id := p.cfg.OutboundID
	p.mu.Unlock()
	if !ready || port == 0 {
		return nil, nil
	}
	return []pub.OutboundConfig{
		{
			ID:       id,
			Protocol: "socks5",
			Config: map[string]any{
				"id":      id,
				"address": fmt.Sprintf("127.0.0.1:%d", port),
			},
		},
	}, nil
}

// Close stops the tunnel and waits for the goroutine to exit.
func (p *Provider) Close() error {
	if p.stop != nil {
		p.stop()
	}
	p.stopWg.Wait()
	return nil
}

// signalWatch notifies the engine (non-blocking) that the outbound set may
// have changed.
func (p *Provider) signalWatch() {
	select {
	case p.watchCh <- struct{}{}:
	default:
	}
}

// sanitizeConfig strips host-specific fields from the Psiphon config (Windows
// Migrate* paths whose backslashes break the upgrade-file regex on Linux, and
// runtime-overridden fields) and injects the optional upstream proxy. It does
// NOT strip DisableRemoteServerListFetcher, so the background server-list
// fetcher stays enabled — that is what auto-updates the server list.
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
		"EgressRegion",
		"DeviceRegion",
		"NetworkID",
		"ClientPlatform",
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

// init registers the provider factory with the goose plugin registry. Import
// this package with a blank import in the engine binary to activate it:
//
//	import _ "github.com/goose-network/goose-plugin-psiphon"
func init() {
	pub.RegisterProvider("psiphon", New)
}
