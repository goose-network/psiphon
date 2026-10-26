// outbound.go: the "psiphon" outbound protocol — goose dials Psiphon in
// memory.
//
// The provider (provider.go) emits outbound configs with protocol "psiphon":
// one general outbound (tunnel-core picks any server) plus one per server in
// the datastore's list. The factory registered here turns those configs into
// Outbounds whose DialContext resolves the live provider through the
// liveProviders registry and calls straight into its controller — no local
// SOCKS or HTTP proxy sits between the engine and the tunnel.
//
// Resolution happens at DIAL time, not build time: the engine rebuilds
// outbounds on every config bump, and a provider restart (spec edited) or a
// late provider start would otherwise leave built outbounds holding a dead
// provider pointer. The registry is keyed by the provider's general outbound
// ID ("psiphon" by default), which the engine enforces unique as an outbound
// ID, so per-server configs carry their owning provider's ID under
// "tunnel" and always find the live instance.
package psiphon

import (
	"context"
	"fmt"
	"net"
	"sync"

	pub "github.com/goose-network/goose-plugin-api"
)

// liveProviders maps the general outbound ID to the live provider instance.
var liveProviders sync.Map // string → *Provider

// registerLiveProvider publishes p under its general outbound ID. A provider
// being restarted under the same ID replaces the previous entry; the previous
// provider's Close removes the entry only when it still owns it.
func registerLiveProvider(p *Provider) {
	liveProviders.Store(p.cfg.OutboundID, p)
}

// unregisterLiveProvider removes p's registry entry when p still owns it, so
// a restarted replacement's entry is never clobbered by the old instance
// shutting down.
func unregisterLiveProvider(p *Provider) {
	liveProviders.CompareAndDelete(p.cfg.OutboundID, p)
}

// lookupLiveProvider returns the live provider serving the given tunnel ID.
func lookupLiveProvider(tunnelID string) (*Provider, bool) {
	p, ok := liveProviders.Load(tunnelID)
	if !ok {
		return nil, false
	}
	return p.(*Provider), true
}

// Outbound dials through Psiphon in memory: controller.Dial returns the
// tunnel's net.Conn directly, in process.
type Outbound struct {
	id      string
	address string // server ip:webPort, or "" for the general outbound
	tunnel  string // owning provider's general outbound ID (registry key)
	server  string // pinned server IP; "" dials through the general tunnel
	region  string // informational
}

// New is the factory registered as the "psiphon" outbound protocol. The
// provider emits these configs; they may also be written by hand:
//
//	{"id":"psiphon", "tunnel":"psiphon"}
//	  → any server, via the provider's general tunnel
//	{"id":"psiphon-1.2.3.4", "tunnel":"psiphon", "server":"1.2.3.4"}
//	  → pinned to one server from the provider's list
//
// The engine's "_dialer" stack injection is intentionally ignored here: the
// outbound's transport is the in-process tunnel, whose own connections to
// its Psiphon server already run through the engine stack (tunnel.go).
func New(cfg map[string]any) (pub.Outbound, error) {
	o := &Outbound{
		id:      strVal(cfg, "id"),
		address: strVal(cfg, "address"),
		tunnel:  strVal(cfg, "tunnel"),
		server:  strVal(cfg, "server"),
		region:  strVal(cfg, "region"),
	}
	if o.tunnel == "" {
		o.tunnel = "psiphon"
	}
	if o.id == "" {
		o.id = o.tunnel
	}
	return o, nil
}

func (o *Outbound) ID() string               { return o.id }
func (o *Outbound) Protocol() string         { return "psiphon" }
func (o *Outbound) Address() string          { return o.address }
func (o *Outbound) Location() *pub.Location  { return nil }
func (o *Outbound) Stats() pub.OutboundStats { return pub.OutboundStats{} }

// DialContext connects to target through the tunnel. Only TCP is supported:
// Psiphon tunnels TCP streams (its SOCKS front end — now disabled — never
// did UDP either).
func (o *Outbound) DialContext(ctx context.Context, network pub.Network, target string) (net.Conn, error) {
	if network != pub.NetworkTCP {
		return nil, fmt.Errorf("psiphon outbound: %s unsupported (only TCP)", network)
	}
	p, ok := lookupLiveProvider(o.tunnel)
	if !ok {
		return nil, fmt.Errorf("psiphon outbound: no live provider %q (is it configured and running?)", o.tunnel)
	}
	if o.server != "" {
		return p.dialServer(ctx, o.server, target)
	}
	return p.dialMain(ctx, target)
}

// strVal reads a string config field, tolerating JSON-numberified strings.
func strVal(cfg map[string]any, key string) string {
	v, _ := cfg[key].(string)
	return v
}

func init() {
	pub.Register("psiphon", New)
}
