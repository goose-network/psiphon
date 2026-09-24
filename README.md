# goose-plugin-psiphon

A [Goose](../goose) outbound **provider** plugin backed by
[Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core) tunnel-core.

It embeds `psiphon-tunnel-core` as a Go library, starts a Psiphon tunnel,
and exposes the tunnel's local SOCKS proxy as a single socks5 outbound that
Goose merges into a managed pool. Any Goose inbound routed through that pool
forwards traffic through Psiphon.

## Auto-updating server list

tunnel-core's background `RemoteServerListFetcher` is left **enabled** (the
config's `DisableRemoteServerListFetcher` is not set), so the server list
auto-updates the same way the Psiphon Windows client's does: the signed
remote server list is downloaded, signature-verified, and new entries are
stored in the BoltDB datastore. The provider signals `Watch()` when the
tunnel first establishes and on each remote-list download, so Goose re-polls
and the pool reflects the current state.

From Goose's perspective all Psiphon servers are reached through the single
local SOCKS proxy that tunnel-core runs, so the provider emits one socks5
outbound whose address is that local port. Per-server selection is owned by
tunnel-core.

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
| `config_path` | yes | — | Path to a real `psiphon.config` from a Psiphon install. |
| `server_list_path` | no | — | Path to a `server_list.dat` to seed the datastore. If omitted, tunnel-core's remote fetcher populates it. |
| `data_dir` | no | `$TMPDIR/goose-psiphon-data` | Data root for tunnel-core's datastore + diagnostics. |
| `upstream_proxy` | no | — | Upstream proxy URL tunnel-core uses to reach Psiphon servers (e.g. `socks5://127.0.0.1:7890`). Required on networks that block direct 443. |
| `establish_timeout_seconds` | no | `120` | Tunnel establishment timeout. |
| `outbound_id` | no | `"psiphon"` | ID of the emitted socks5 outbound. |

`sanitizeConfig` strips host-specific fields from the Psiphon config
(Windows `Migrate*` paths whose backslashes break the upgrade-file regex on
Linux, and runtime-overridden fields like `LocalSocksProxyPort`,
`DataRootDirectory`, `NetworkID`, `ClientPlatform`) and injects
`UpstreamProxyURL`. It does **not** strip
`DisableRemoteServerListFetcher`, so the background server-list fetcher
stays enabled.

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

Then route a request through Goose's SOCKS5 inbound:

```bash
curl --socks5-hostname 127.0.0.1:11080 https://api.ipify.org
```

The returned IP is a Psiphon exit, distinct from your direct IP.

## Caveats

- **tunnel-core `connectedSignal` panic.** Upstream
  `ClientLibrary/clientlib/clientlib.go` closed `connectedSignal` on every
  `Tunnels {count>0}` notice without a guard; the second notice panicked
  `close of closed channel` and crashed the embedding process. The local
  tunnel-core checkout is patched with a `sync.Once` guard — keep that patch
  or the integration will crash on the 2nd tunnel notice.
- **Tunnel churn.** On restrictive networks/upstreams, tunnel-core tunnels
  may disconnect and re-establish every ~60s. Proxied fetches succeed only
  during a live-tunnel window; retry with backoff if a fetch returns empty.
