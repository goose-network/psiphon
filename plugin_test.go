package psiphon

import (
	"context"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"

	pub "github.com/goose-network/goose-plugin-api"
)

// encodeTestEntry builds a syntactically valid encoded server entry for the
// pinned-shape tests, the same encoding Config.TargetServerEntry consumes.
func encodeTestEntry(t *testing.T) string {
	t.Helper()
	encoded, err := protocol.EncodeServerEntry(&protocol.ServerEntry{
		IpAddress:       "192.0.2.10",
		WebServerPort:   "443",
		WebServerSecret: "test-secret",
		Region:          "TEST",
		Capabilities:    []string{"SSHAPI"},
	})
	if err != nil {
		t.Fatalf("EncodeServerEntry: %v", err)
	}
	return encoded
}

// TestSanitizeConfigStripsRuntimeFields verifies the sanitizer strips the
// runtime-owned fields the plugin sets per controller (a leaked
// TargetServerEntry would pin the general tunnel; leaked notice-file routing
// would swallow the server-list signal; a leaked data root would split
// state) and injects the upstream proxy.
func TestSanitizeConfigStripsRuntimeFields(t *testing.T) {
	raw := `{
		"PropagationChannelId": "0000000000000000",
		"SponsorId": "0000000000000000",
		"DataRootDirectory": "/leaky",
		"MigrateDataStoreDirectory": "/leaky",
		"LocalSocksProxyPort": 1080,
		"EgressRegion": "DE",
		"NetworkID": "OTHER",
		"ClientPlatform": "Windows",
		"EstablishTunnelTimeoutSeconds": 1,
		"TargetServerEntry": "deadbeef",
		"DisableRemoteServerListFetcher": true,
		"DisableLocalSocksProxy": false,
		"EmitDiagnosticNotices": false,
		"UseNoticeFiles": {"RotatingFileSize": 1024},
		"UpstreamProxyUrl": "http://leaky"
	}`
	out, err := sanitizeConfig([]byte(raw), "socks5://127.0.0.1:7890")
	if err != nil {
		t.Fatalf("sanitizeConfig: %v", err)
	}
	cfg, err := psiphon.LoadConfig(out)
	if err != nil {
		t.Fatalf("LoadConfig(sanitized): %v", err)
	}
	if cfg.DataRootDirectory != "" || cfg.MigrateDataStoreDirectory != "" {
		t.Fatalf("data root leaked: %q %q", cfg.DataRootDirectory, cfg.MigrateDataStoreDirectory)
	}
	if cfg.TargetServerEntry != "" {
		t.Fatalf("TargetServerEntry leaked: %q", cfg.TargetServerEntry)
	}
	if cfg.DisableRemoteServerListFetcher != true {
		t.Fatal("an operator's DisableRemoteServerListFetcher must be respected, not stripped")
	}
	if cfg.EmitDiagnosticNotices {
		t.Fatal("EmitDiagnosticNotices must be stripped: the plugin owns notice routing")
	}
	if cfg.UseNoticeFiles != nil {
		t.Fatalf("UseNoticeFiles leaked: %v", cfg.UseNoticeFiles)
	}
	if cfg.EgressRegion != "" || cfg.NetworkID != "" || cfg.ClientPlatform != "" {
		t.Fatalf("identity fields leaked: %q %q %q", cfg.EgressRegion, cfg.NetworkID, cfg.ClientPlatform)
	}
	if cfg.EstablishTunnelTimeoutSeconds != nil {
		t.Fatalf("EstablishTunnelTimeoutSeconds leaked: %d", *cfg.EstablishTunnelTimeoutSeconds)
	}
	if cfg.UpstreamProxyURL != "socks5://127.0.0.1:7890" {
		t.Fatalf("UpstreamProxyURL = %q", cfg.UpstreamProxyURL)
	}
}

// TestNewTunnelCorePinnedShape verifies the pinned controller's config
// posture: pinned to the target entry, no list fetching / tactics / entry
// reporting, no local proxies, diagnostics on the hub.
func TestNewTunnelCorePinnedShape(t *testing.T) {
	encoded := encodeTestEntry(t)
	tc, err := newTunnelCore(defaultConfigJSON(), tunnelOptions{
		label:             "psiphon[192.0.2.10]",
		dataRootDirectory: t.TempDir(),
		targetServerEntry: encoded,
		establishTimeout:  2 * time.Minute,
	}, nil)
	if err != nil {
		t.Fatalf("newTunnelCore(pinned): %v", err)
	}
	defer tc.stop()

	cfg := tc.config
	if cfg.TargetServerEntry != encoded {
		t.Fatalf("TargetServerEntry not pinned")
	}
	if !cfg.DisableRemoteServerListFetcher || !cfg.DisableTactics {
		t.Fatal("pinned controller must not fetch lists or tactics")
	}
	if cfg.DisableServerEntriesReporter == nil || !*cfg.DisableServerEntriesReporter {
		t.Fatal("pinned controller must not report entries")
	}
	if !cfg.DisableLocalSocksProxy || !cfg.DisableLocalHTTPProxy {
		t.Fatal("tunnels must not run local proxies: goose dials in memory")
	}
	if !cfg.EmitDiagnosticNotices || cfg.UseNoticeFiles != nil {
		t.Fatal("diagnostics must flow to the notice hub, not files")
	}
	if cfg.EstablishTunnelTimeoutSeconds == nil || *cfg.EstablishTunnelTimeoutSeconds != 120 {
		t.Fatalf("EstablishTunnelTimeoutSeconds = %v, want 120", cfg.EstablishTunnelTimeoutSeconds)
	}

	// Stopping before start is safe, and stop is idempotent.
	tc.stop()
	tc.stop()
	if !tc.stopped() {
		t.Fatal("stopped() after stop()")
	}
	// start after stop must not launch a Run loop.
	tc.start()
	select {
	case <-tc.ctx.Done():
	default:
		t.Fatal("ctx should be cancelled after stop")
	}
}

// TestNewTunnelCoreGeneralShape verifies the general tunnel keeps the list
// fetcher enabled (it is what auto-updates the servers the provider shows).
func TestNewTunnelCoreGeneralShape(t *testing.T) {
	tc, err := newTunnelCore(defaultConfigJSON(), tunnelOptions{
		label:             "psiphon",
		dataRootDirectory: t.TempDir(),
		establishTimeout:  90 * time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("newTunnelCore(general): %v", err)
	}
	defer tc.stop()

	if tc.config.DisableRemoteServerListFetcher {
		t.Fatal("general tunnel must keep the remote server list fetcher enabled")
	}
	if tc.config.TargetServerEntry != "" {
		t.Fatal("general tunnel must not be pinned")
	}
	if tc.config.EstablishTunnelTimeoutSeconds == nil || *tc.config.EstablishTunnelTimeoutSeconds != 90 {
		t.Fatalf("EstablishTunnelTimeoutSeconds = %v, want 90", tc.config.EstablishTunnelTimeoutSeconds)
	}
}

// TestOutboundFactory verifies the "psiphon" protocol factory parses the
// provider-emitted config shapes, and that dials fail fast without a live
// provider (the engine reports the error and falls back to other outbounds).
func TestOutboundFactory(t *testing.T) {
	general, err := New(map[string]any{"id": "psiphon", "tunnel": "psiphon"})
	if err != nil {
		t.Fatalf("New(general): %v", err)
	}
	if general.Protocol() != "psiphon" || general.ID() != "psiphon" || general.Address() != "" {
		t.Fatalf("general outbound: %q %q %q", general.ID(), general.Protocol(), general.Address())
	}

	server, err := New(map[string]any{
		"id":      "psiphon-192.0.2.10",
		"tunnel":  "psiphon",
		"server":  "192.0.2.10",
		"address": "192.0.2.10:443",
		"region":  "TEST",
	})
	if err != nil {
		t.Fatalf("New(server): %v", err)
	}
	if server.Address() != "192.0.2.10:443" {
		t.Fatalf("server outbound address = %q", server.Address())
	}

	// Defaults for a minimal hand-written config.
	bare, err := New(map[string]any{})
	if err != nil {
		t.Fatalf("New(bare): %v", err)
	}
	if bare.ID() != "psiphon" || bare.Protocol() != "psiphon" {
		t.Fatalf("bare outbound: %q %q", bare.ID(), bare.Protocol())
	}

	// UDP is refused without touching the registry.
	if _, err := bare.DialContext(context.Background(), pub.NetworkUDP, "example.com:53"); err == nil {
		t.Fatal("UDP dial should fail: Psiphon tunnels TCP only")
	}

	// No live provider registered under the tunnel id: fail fast with a
	// diagnosable error instead of hanging.
	if _, err := bare.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err == nil {
		t.Fatal("dial without a live provider should fail")
	}
}

// TestOutboundFactoryNeedsKnownServer verifies a per-server dial with a live
// provider errors for a server absent from the provider's scan cache rather
// than dialing blind.
func TestOutboundFactoryNeedsKnownServer(t *testing.T) {
	p := &Provider{
		cfg: providerConfig{OutboundID: "psiphon-test-needs-known"},
		servers: map[string]serverInfo{
			"192.0.2.10": {IP: "192.0.2.10", Encoded: encodeTestEntry(t)},
		},
		pinned: map[string]*serverTunnel{},
	}
	registerLiveProvider(p)
	defer unregisterLiveProvider(p)

	known, err := New(map[string]any{"id": "k", "tunnel": p.cfg.OutboundID, "server": "192.0.2.10"})
	if err != nil {
		t.Fatalf("New(known): %v", err)
	}
	// The dial reaches tunnel startup and fails there (no datastore in this
	// test); what matters is it gets past the scan-cache check. The error
	// must not be "not in the current list".
	_, dialErr := known.DialContext(context.Background(), pub.NetworkTCP, "example.com:80")
	if dialErr != nil && dialErr.Error() == "psiphon: server 192.0.2.10 is not in the current list" {
		t.Fatalf("known server rejected: %v", dialErr)
	}

	unknown, err := New(map[string]any{"id": "u", "tunnel": p.cfg.OutboundID, "server": "192.0.2.99"})
	if err != nil {
		t.Fatalf("New(unknown): %v", err)
	}
	if _, err := unknown.DialContext(context.Background(), pub.NetworkTCP, "example.com:80"); err == nil {
		t.Fatal("dial to a server outside the list should fail")
	}
}

// TestNoticeHubFanout verifies the hub delivers every notice to every
// subscriber and that unsubscribed callbacks stop receiving.
func TestNoticeHubFanout(t *testing.T) {
	var got []string
	unsub := hub.subscribe(func(n notice) { got = append(got, n.Type) })
	_ = hub.subscribe(func(n notice) { got = append(got, n.Type) })

	hub.dispatch([]byte(`{"noticeType":"Tunnels","data":{"count":1}}`))
	if len(got) != 2 {
		t.Fatalf("fanout delivered %d, want 2", len(got))
	}

	got = nil
	unsub()
	hub.dispatch([]byte(`{"noticeType":"Tunnels","data":{"count":1}}`))
	if len(got) != 1 {
		t.Fatalf("after unsubscribe delivered %d, want 1", len(got))
	}

	// Malformed events are dropped, not propagated.
	got = nil
	hub.dispatch([]byte(`{not json`))
	hub.dispatch([]byte(`{"data":{}}`)) // no noticeType
	if len(got) != 0 {
		t.Fatalf("malformed notices delivered %d, want 0", len(got))
	}
}

// TestHandleNoticeSignalsWatch verifies the two notice types the provider
// reacts to signal the engine: tunnel up and server-list download.
func TestHandleNoticeSignalsWatch(t *testing.T) {
	p := &Provider{watchCh: make(chan struct{}, 1)}

	p.handleNotice(notice{Type: "Tunnels", Data: map[string]any{"count": float64(1)}})
	select {
	case <-p.Watch():
	default:
		t.Fatal("Tunnels(count>0) should signal Watch")
	}

	p.handleNotice(notice{Type: "Tunnels", Data: map[string]any{"count": float64(0)}})
	select {
	case <-p.Watch():
		t.Fatal("Tunnels(count=0) should not signal Watch")
	default:
	}

	p.handleNotice(notice{Type: "RemoteServerListResourceDownloaded"})
	select {
	case <-p.Watch():
	default:
		t.Fatal("RemoteServerListResourceDownloaded should signal Watch")
	}
}

// TestParseConfigDefaults verifies the zero-config posture: defaults for
// outbound id, establish timeout, and the data dir.
func TestParseConfigDefaults(t *testing.T) {
	pc, err := parseConfig(map[string]any{})
	if err != nil {
		t.Fatalf("parseConfig(empty): %v", err)
	}
	if pc.OutboundID != "psiphon" {
		t.Fatalf("OutboundID = %q", pc.OutboundID)
	}
	if pc.EstablishTimeoutSeconds != 120 {
		t.Fatalf("EstablishTimeoutSeconds = %d", pc.EstablishTimeoutSeconds)
	}
	if pc.DataDir != "psiphon-data" {
		t.Fatalf("DataDir = %q", pc.DataDir)
	}

	// The engine-injected dialer keys must be stripped before the JSON
	// round-trip, and the caller's map must not be mutated.
	nonMarshalable := func() {} // funcs break json.Marshal
	in := map[string]any{
		pub.StackDialerKey:    nonMarshalable,
		pub.UpstreamDialerKey: nonMarshalable,
	}
	if _, err := parseConfig(in); err != nil {
		t.Fatalf("parseConfig with injected dialers: %v", err)
	}
	if _, still := in[pub.StackDialerKey]; !still {
		t.Fatal("parseConfig must not mutate the caller's config map")
	}
}
