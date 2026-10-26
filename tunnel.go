// tunnel.go: one tunnel-core controller's lifecycle.
//
// A tunnelCore owns one psiphon.Controller: it loads and commits its own
// Config, runs the controller's Run loop in a goroutine, reports tunnel
// establishment, dials through the controller in memory, and stops cleanly.
//
// The provider drives two shapes with the same type:
//
//   - the general tunnel: no TargetServerEntry, tunnel-core picks any server;
//   - one pinned tunnel per server: TargetServerEntry pins the controller to
//     a single encoded server entry, lazily started on first use and reaped
//     when idle.
//
// # In-memory dials
//
// tunnel-core runs its controller without any local SOCKS/HTTP listeners
// (DisableLocalSocksProxy/DisableLocalHTTPProxy); dials go straight to
// controller.Dial, which returns the tunnel's net.Conn in process. No
// loopback proxy sits between goose and the plugin.
//
// # The engine stack
//
// When the engine injected its layer-3/4 stack dialer (pub.StackDialerKey)
// and no upstream_proxy was configured, the config hands tunnel-core that
// dialer via Config.SetCustomDialer: the tunnel's own TCP connections to its
// Psiphon server then dial through the engine's configured network stack
// (system kernel or gvisor) instead of bare sockets. An upstream_proxy
// overrides it — tunnel-core's CustomDialer takes precedence over
// UpstreamProxyURL in DialConfig, so setting both would silently ignore the
// user's explicit fetch route.
package psiphon

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"

	pub "github.com/goose-network/goose-plugin-api"
)

// clientPlatform identifies this client to Psiphon servers and stats.
const clientPlatform = "Linux_goose-plugin-psiphon"

// tunnelCore runs one tunnel-core controller.
type tunnelCore struct {
	config      *psiphon.Config // committed; the provider needs it for OpenDataStore
	controller  *psiphon.Controller
	ctx         context.Context
	cancel      context.CancelFunc
	runWG       sync.WaitGroup
	stopOnce    sync.Once
	started     atomic.Bool
	isStopped   atomic.Bool
	established atomic.Bool
	label       string
}

// stackDialerFunc adapts the engine's stack dialer to tunnel-core's
// common.Dialer function type. Tunnel-core hands the dialer bare dial
// addresses, including domains; the engine stack resolves them.
func stackDialerFunc(d pub.StackDialer) common.Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.Dial(ctx, network, address)
	}
}

// tunnelOptions parametrizes newTunnelCore: the two shapes share everything
// except the pin and the shutdown-lean knobs.
type tunnelOptions struct {
	// label names the tunnel in log lines ("psiphon" or "psiphon[x.x.x.x]").
	label string
	// dataRootDirectory is where the datastore and downloaded files live;
	// set on the config (the sanitizer strips the JSON's copy).
	dataRootDirectory string
	// targetServerEntry pins the controller to one encoded server entry;
	// empty lets tunnel-core pick any server.
	targetServerEntry string
	// establishTimeout bounds waitEstablished and the controller's own
	// establishment budget.
	establishTimeout time.Duration
}

// newTunnelCore loads configJSON, applies the plugin's runtime parameters and
// options, and commits — creating the controller without starting it. Call
// start after any datastore setup (the general tunnel's datastore must be
// open before the controller runs; pinned tunnels share the open one).
//
// stackDialer may be nil (dial directly). The config JSON must already be
// sanitized (host-specific fields stripped, upstream proxy injected).
func newTunnelCore(configJSON []byte, opts tunnelOptions, stackDialer pub.StackDialer) (*tunnelCore, error) {
	config, err := psiphon.LoadConfig(configJSON)
	if err != nil {
		return nil, fmt.Errorf("psiphon: load config: %w", err)
	}

	// Runtime parameters, mirroring the ClientLibrary's. Commit serializes
	// none of these, so they are set per controller instance.
	if opts.dataRootDirectory != "" {
		config.DataRootDirectory = opts.dataRootDirectory
		config.MigrateDataStoreDirectory = opts.dataRootDirectory
		config.MigrateObfuscatedServerListDownloadDirectory = opts.dataRootDirectory
		config.MigrateRemoteServerListDownloadFilename = opts.dataRootDirectory + "/server_list_compressed"
	}
	config.ClientPlatform = clientPlatform
	config.NetworkID = "GOOSE-PSIPHON"
	timeoutSeconds := int(opts.establishTimeout / time.Second)
	if timeoutSeconds < 1 {
		timeoutSeconds = 120
	}
	config.EstablishTunnelTimeoutSeconds = &timeoutSeconds

	// No local proxies: goose dials in memory. No notice files: diagnostics
	// (including the remote-server-list download signal) reach the notice hub.
	config.DisableLocalSocksProxy = true
	config.DisableLocalHTTPProxy = true
	config.EmitDiagnosticNotices = true
	config.UseNoticeFiles = nil

	if opts.targetServerEntry != "" {
		// A pinned controller exists only to reach its one server: it must not
		// fetch lists, apply tactics, or report entries.
		config.TargetServerEntry = opts.targetServerEntry
		config.DisableRemoteServerListFetcher = true
		config.DisableTactics = true
		noReport := true
		config.DisableServerEntriesReporter = &noReport
	}

	// Route the tunnel's own TCP connections to its Psiphon server through
	// the engine's network stack (see the file comment for the upstream
	// interaction).
	if stackDialer != nil {
		config.SetCustomDialer(stackDialerFunc(stackDialer))
	}

	if err := config.Commit(true); err != nil {
		return nil, fmt.Errorf("psiphon: commit config: %w", err)
	}

	controller, err := psiphon.NewController(config)
	if err != nil {
		return nil, fmt.Errorf("psiphon: new controller: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &tunnelCore{
		config:     config,
		controller: controller,
		ctx:        ctx,
		cancel:     cancel,
		label:      opts.label,
	}, nil
}

// start launches the controller's Run loop and the establishment watcher.
// The datastore must already be open.
func (t *tunnelCore) start() {
	if t.isStopped.Load() || !t.started.CompareAndSwap(false, true) {
		return
	}
	t.runWG.Add(1)
	go func() {
		defer t.runWG.Done()
		t.controller.Run(t.ctx)
	}()
	// Establishment can't be observed through notices (they are global, not
	// per controller), so watch the controller directly.
	go t.awaitEstablishment(t.ctx)
	fmt.Printf("psiphon: tunnel %s started\n", t.label)
}

// awaitEstablishment flips the established flag once the controller has an
// active tunnel. It exits when the tunnel stops. The provider reacts to the
// main tunnel's establishment through the global "Tunnels" notice; pinned
// dials poll waitEstablished.
func (t *tunnelCore) awaitEstablishment(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if t.controller.HasActiveTunnel() {
			t.established.Store(true)
			fmt.Printf("psiphon: tunnel %s established\n", t.label)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// waitEstablished blocks until the tunnel has an active tunnel, the tunnel
// stops, or ctx ends. It returns the stop/ctx error for context.
func (t *tunnelCore) waitEstablished(ctx context.Context, timeout time.Duration) error {
	if t.established.Load() {
		return nil
	}
	if t.isStopped.Load() {
		return fmt.Errorf("psiphon: tunnel %s stopped", t.label)
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if t.established.Load() {
			return nil
		}
		select {
		case <-wctx.Done():
			return fmt.Errorf("psiphon: tunnel %s did not establish within %s: %w", t.label, timeout, wctx.Err())
		case <-ticker.C:
			if t.isStopped.Load() {
				return fmt.Errorf("psiphon: tunnel %s stopped while establishing", t.label)
			}
		}
	}
}

// Dial connects to target (host:port) through the tunnel, in memory. It
// fails fast when the tunnel has stopped.
func (t *tunnelCore) Dial(target string) (net.Conn, error) {
	if !t.established.Load() {
		return nil, fmt.Errorf("psiphon: tunnel %s not established", t.label)
	}
	conn, err := t.controller.Dial(target, nil)
	if err != nil {
		return nil, fmt.Errorf("psiphon: tunnel %s dial %s: %w", t.label, target, err)
	}
	return conn, nil
}

// stopped reports whether stop has run.
func (t *tunnelCore) stopped() bool { return t.isStopped.Load() }

// stop cancels the controller's Run loop and waits for it to shut down. It is
// idempotent.
func (t *tunnelCore) stop() {
	t.stopOnce.Do(func() {
		t.isStopped.Store(true)
		t.cancel()
		t.runWG.Wait()
	})
}

// The pinned-protocol stub below keeps the server scan's protocol listing
// honest about which conditionally compiled transports this build carries.
// QUIC and refraction networking compile in by default (they are disabled
// only through PSIPHON_DISABLE_* build tags this build does not set);
// in-proxy transports need a coordinator client this config never has.
type enabledComponents struct{}

func (enabledComponents) QUICEnabled() bool                 { return true }
func (enabledComponents) RefractionNetworkingEnabled() bool { return false }
func (enabledComponents) InproxyEnabled() bool              { return false }

// supportedProtocols lists the tunnel protocols a server entry supports in
// this build. Informational: the provider surfaces it in per-server outbound
// configs so the web UI can show what each server speaks.
func supportedProtocols(entry *protocol.ServerEntry, useUpstreamProxy bool) []string {
	protocols := entry.GetSupportedProtocols(
		enabledComponents{},
		useUpstreamProxy,
		nil, // limitTunnelProtocols: none configured
		nil, // limitTunnelDialPortNumbers: none configured
		nil, // limitQUICVersions: none configured
		false)
	out := make([]string, 0, len(protocols))
	out = append(out, protocols...)
	return out
}
