# goose-plugin-psiphon

A [Goose](../goose) outbound **provider** plugin backed by
[Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core) tunnel-core.

It embeds `psiphon-tunnel-core` as a Go library, runs its controllers
directly — with **no local SOCKS/HTTP proxy** in between — and exposes:

- one **general** outbound (`psiphon`, any server — tunnel-core picks), and
- one outbound **per real Psiphon server** from the auto-downloaded signed
  server list (IP, region, protocols), each pinned to its own server.

Goose merges all of them into a managed pool, so any inbound routed through
the pool forwards traffic through Psiphon, and the web UI shows the actual
server list.

## In-memory dials, engine-stack transport

The plugin registers the `"psiphon"` outbound protocol: its `DialContext`
calls `controller.Dial` in process, returning the tunnel's `net.Conn`
directly. The local SOCKS/HTTP proxies tunnel-core normally runs are
disabled — there is no loopback hop between Goose and the tunnel.

The tunnels' **own** TCP connections to their Psiphon servers dial through
the engine's layer-3/4 stack (the system kernel stack or the gvisor
netstack): the engine injects its stack dialer into the provider config
(`goose-plugin-api`'s `StackDialer`), and the plugin hands it to tunnel-core
via `Config.SetCustomDialer`. An explicit `upstream_proxy` overrides the
stack for tunnel dials (tunnel-core applies `CustomDialer` in preference to
`UpstreamProxyURL`, so both cannot be honored and the explicit route wins).

## Zero-config (out of the box)

The provider needs **no config at all**. With an empty `config` (or no
`config_path`), it synthesizes a `psiphon.config` embedding the production
Psiphon network parameters — propagation channel, sponsor ID, client version,
the four remote-server-list endpoints (S3 + fronted fallbacks), the RSA key
signing the list, and the ed25519 key signing handshake-discovered entries.
tunnel-core's `RemoteServerListFetcher` then downloads the signed server
list, verifies it, populates its datastore, and establishes a tunnel, exactly
as the official Windows client does on first run. The values live in
[`defaults.go`](defaults.go), extracted from the official `psiphon3.exe`; the
signing key was verified cryptographically against the live production server
list (`defaults_test.go` runs the synthesized config through tunnel-core's own
`LoadConfig`+`Commit` validation).

```json
{ "providers": [ { "id": "psiphon", "provider": "psiphon" } ] }
```

is a complete, working config. A user-supplied `config_path` overrides the
defaults (self-hosted / custom networks).

## Auto-updating server list

tunnel-core's background `RemoteServerListFetcher` is left **enabled** for
the general tunnel (the config's `DisableRemoteServerListFetcher` is not
set), so the server list auto-updates the same way the Psiphon Windows
client's does: the signed remote server list is downloaded,
signature-verified, and new entries are stored in the BoltDB datastore.

The provider scans the datastore on each poll and emits one outbound per
pinnable server (those supporting SSH API requests — what
`Config.TargetServerEntry` requires), with IDs like
`psiphon-203.0.113.7`. A notice hub fans tunnel-core's process-global
notices to every provider instance, so `Watch()` fires on tunnel
establishment and on each remote-list download seconds after it lands —
the pool (and the web UI) follows the list without waiting for the periodic
re-poll.

A per-server dial lazily starts a controller pinned to that one server
(`Config.TargetServerEntry`), shares it across concurrent connections, and
reaps it after 10 idle minutes with no open connections. All controllers
share one refcounted datastore.

## Import boundary

This plugin imports **only**
[`goose-plugin-api`](../goose-plugin-api) (the neutral plugin contract) and
`psiphon-tunnel-core`. It does **not** import Goose. Goose imports this
plugin (a blank import in
[`goose/include/register.go`](../goose/include/register.go)), which is what
triggers the `init()` registration of the `"psiphon"` provider. This keeps
the module graph acyclic.

## Config

The provider config is a JSON object passed under a `providers` entry in
Goose's config:

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `config_path` | no | embedded production config | Path to a real `psiphon.config` from a Psiphon install. Omitted: the plugin runs with the embedded production-network defaults (see *Zero-config* above) and auto-retrieves the server list. |
| `server_list_path` | no | — | Path to a `server_list.dat` to seed the datastore. If omitted, tunnel-core's remote fetcher populates it. |
| `data_dir` | no | `psiphon-data` (working dir) | Data root for tunnel-core's datastore + diagnostics, anchored next to the engine's own state so the server list survives restarts. |
| `upstream_proxy` | no | — | Upstream proxy URL tunnel-core uses to reach Psiphon servers (e.g. `socks5://127.0.0.1:7890`). Required on networks that block direct 443. Overrides the engine stack for tunnel dials. |
| `establish_timeout_seconds` | no | `120` | How long a dial waits for its tunnel to establish. |
| `outbound_id` | no | `"psiphon"` | ID of the general outbound; per-server IDs are `<outbound_id>-<ip>`. Must be unique across providers — outbound configs use it to find the live provider at dial time. |

`sanitizeConfig` strips host-specific and runtime-owned fields from the
Psiphon config (Windows `Migrate*` paths whose backslashes break the
upgrade-file regex on Linux, and the fields the plugin sets per controller:
data root, local proxy ports, notice routing, timeouts, target server entry,
…) and injects `UpstreamProxyURL`. An operator's
`DisableRemoteServerListFetcher` is respected, not stripped.

## Build

```bash
GOTOOLCHAIN=go1.26.8 go build ./...
```

The `go1.26.8` toolchain pin is required because `psiphon-tunnel-core`'s
`psiphon-tls` is ABI-incompatible with Go 1.27 (`tls.ConnectionState` field
count mismatch).

`go.mod` uses local `replace` directives to sibling repos:

```
replace github.com/goose-network/goose-plugin-api    => ../goose-plugin-api
replace github.com/Psiphon-Labs/psiphon-tunnel-core  => ../psiphon-tunnel-core
```

## Run with Goose

See the [Goose README](../goose/README.md) for a full config. In short:

```json
{
  "providers": [
    {
      "id": "psiphon-prov",
      "provider": "psiphon",
      "pool_id": "psiphon-pool",
      "config": {
        "config_path": "/path/to/psiphon.config",
        "server_list_path": "/path/to/server_list.dat",
        "data_dir": "/tmp/goose-psiphon-data",
        "upstream_proxy": "socks5://127.0.0.1:7890",
        "establish_timeout_seconds": 180
      }
    }
  ]
}
```

(The minimal form — `{"id": "psiphon", "provider": "psiphon"}` with no
`config` — also works; see *Zero-config*.)

Then route a request through Goose's SOCKS5 inbound:

```bash
curl --socks5-hostname 127.0.0.1:11080 https://api.ipify.org
```

The returned IP is a Psiphon exit, distinct from your direct IP.

## Caveats

- **Driving controllers directly.** The plugin does not use
  `ClientLibrary/clientlib`: that path allows exactly one tunnel per process
  (a `started` atomic) and closes its `connectedSignal` on the second
  `Tunnels {count>0}` notice (the fork's branch is named after that panic).
  Instead the plugin constructs `psiphon.Controller` itself — one general
  controller plus one lazily-started pinned controller per dialed server —
  over a single refcounted datastore. The fork carries the two seams this
  needs: `Config.SetCustomDialer` (engine-stack transport) and
  `Controller.HasActiveTunnel` (establishment polling, since process-global
  notices cannot be attributed to a controller).
- **Tunnel churn.** On restrictive networks/upstreams, tunnel-core tunnels
  may disconnect and re-establish every ~60s. Proxied fetches succeed only
  during a live-tunnel window; retry with backoff if a fetch returns empty.
