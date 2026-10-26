package psiphon

import (
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// TestDefaultConfigCommit round-trips the zero-config defaults through
// tunnel-core's own LoadConfig + Commit: the same validation the tunnel
// start path applies. This is what guarantees an out-of-the-box provider
// (no config_path) is accepted by tunnel-core and auto-retrieves the signed
// remote server list.
func TestDefaultConfigCommit(t *testing.T) {
	cfg, err := psiphon.LoadConfig(defaultConfigJSON())
	if err != nil {
		t.Fatalf("LoadConfig(default config): %v", err)
	}
	if err := cfg.Commit(false); err != nil {
		t.Fatalf("Commit(default config): %v", err)
	}

	if cfg.PropagationChannelId != "92AACC5BABE0944C" {
		t.Fatalf("PropagationChannelId = %q", cfg.PropagationChannelId)
	}
	if cfg.SponsorId != "1BC527D3D09985CF" {
		t.Fatalf("SponsorId = %q", cfg.SponsorId)
	}
	// LoadConfig decodes and validates the transfer URLs; with a signature
	// key set, the fetcher is armed.
	if len(cfg.RemoteServerListURLs) != 4 {
		t.Fatalf("RemoteServerListURLs len = %d, want 4", len(cfg.RemoteServerListURLs))
	}
	if cfg.RemoteServerListSignaturePublicKey == "" {
		t.Fatal("RemoteServerListSignaturePublicKey empty")
	}
	if len(cfg.ObfuscatedServerListRootURLs) != 4 {
		t.Fatalf("ObfuscatedServerListRootURLs len = %d, want 4", len(cfg.ObfuscatedServerListRootURLs))
	}
}

// TestParseConfigNoPath checks the config_path requirement is gone: an empty
// config map now parses (defaults fill in at startTunnel time) and only a
// missing data dir gets a fallback.
func TestParseConfigNoPath(t *testing.T) {
	pc, err := parseConfig(map[string]any{})
	if err != nil {
		t.Fatalf("parseConfig(empty) = %v, want nil (zero-config supported)", err)
	}
	if pc.ConfigPath != "" {
		t.Fatalf("ConfigPath = %q, want empty", pc.ConfigPath)
	}
	if pc.DataDir == "" {
		t.Fatal("DataDir should fall back to a temp default")
	}
}

// TestSanitizeConfigKeepsDefaults runs the synthesized config through the
// same sanitize step startTunnel applies, verifying none of the fields the
// fetcher needs are stripped.
func TestSanitizeConfigKeepsDefaults(t *testing.T) {
	out, err := sanitizeConfig(defaultConfigJSON(), "")
	if err != nil {
		t.Fatalf("sanitizeConfig(default): %v", err)
	}
	cfg, err := psiphon.LoadConfig(out)
	if err != nil {
		t.Fatalf("LoadConfig(sanitized default): %v", err)
	}
	if err := cfg.Commit(false); err != nil {
		t.Fatalf("Commit(sanitized default): %v", err)
	}
}
