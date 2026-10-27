// servers.go: the real Psiphon server list.
//
// The signed remote server list that tunnel-core's fetcher downloads lands
// in the shared BoltDB datastore. scanPinnableServers reads it back out and
// the provider emits one goose outbound per pinnable server, so the engine
// (and the web UI, via the admin API's outbounds endpoint) shows Psiphon's
// actual servers — IP, region, protocols — and any of them can be pooled,
// pinned, or filtered like any other outbound.
//
// Per-server dials run through a dedicated controller pinned to that one
// server via Config.TargetServerEntry. Pinned controllers start lazily on
// first dial (no point holding a tunnel per server in the list), are shared
// by every dial to that server, and are reaped after sitting idle with no
// open connections — see the reaper in provider.go.
package psiphon

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// serverInfo is one pinnable server from the datastore, in the form the
// provider emits and the web UI shows.
type serverInfo struct {
	IP        string
	Region    string
	Address   string // ip:webPort — the server's own TCP endpoint
	Encoded   string // the encoded server entry; pins a controller to it
	Protocols []string
}

// serverStartRetryInterval bounds how long a failed pinned-controller start
// is cached before a later dial retries it.
const serverStartRetryInterval = 30 * time.Second

// scanPinnableServers reads the datastore's current server entries and
// returns the ones a pinned controller can use: those supporting SSH API
// requests, which is what Config.TargetServerEntry requires.
//
// useUpstreamProxy filters the protocol listing to the direct-TCP protocols
// that can ride a proxy — true when tunnel dials go through a raw proxy URL
// OR an injected engine route (a goose outbound/pool/chain is a connected
// TCP tunnel, the same constraint); the engine stack needs no filtering (it
// is protocol-neutral layer 3/4).
func scanPinnableServers(useUpstreamProxy bool) ([]serverInfo, error) {
	var servers []serverInfo
	err := psiphon.ScanServerEntries(func(entry *protocol.ServerEntry) bool {
		if entry.IpAddress == "" || !entry.SupportsSSHAPIRequests() {
			return true
		}
		encoded, err := protocol.EncodeServerEntry(entry)
		if err != nil {
			fmt.Printf("psiphon: encode server entry %s: %v\n", entry.IpAddress, err)
			return true
		}
		info := serverInfo{
			IP:        entry.IpAddress,
			Region:    entry.Region,
			Encoded:   encoded,
			Protocols: supportedProtocols(entry, useUpstreamProxy),
		}
		if entry.WebServerPort != "" {
			info.Address = net.JoinHostPort(entry.IpAddress, entry.WebServerPort)
		}
		servers = append(servers, info)
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("psiphon: scan server entries: %w", err)
	}
	return servers, nil
}

// serverTunnel is the lazily-started pinned controller for one server, with
// the state the reaper and dial path need: the tunnel itself, a cached
// start failure, and how many engine connections are riding it.
type serverTunnel struct {
	ip      string
	encoded string

	mu       sync.Mutex
	tunnel   *tunnelCore
	startErr error
	startAt  time.Time

	open     atomic.Int32
	lastUsed atomic.Int64 // unix nano; set on start attempt and each dial
}

// touch marks the tunnel in use now.
func (st *serverTunnel) touch() { st.lastUsed.Store(time.Now().UnixNano()) }

// idleFor reports how long the tunnel has gone unused, assuming no open
// connections.
func (st *serverTunnel) idleFor() time.Duration {
	last := st.lastUsed.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(0, last))
}

// stop tears the pinned tunnel down and clears it, so the next dial starts a
// fresh controller. It is idempotent.
func (st *serverTunnel) stop() {
	st.mu.Lock()
	t := st.tunnel
	st.tunnel = nil
	st.mu.Unlock()
	if t != nil {
		t.stop()
	}
}

// countingConn releases the server tunnel's open-connection pin when the
// engine closes the connection.
type countingConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *countingConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}
