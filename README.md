# bitty-network

Bitty L1 Rust Core Extension: the shared, optional network runtime.

## Architecture

bitty-network is split into focused, composable crates for fine-grained plugin dependencies:

```text
bitty-network-api        # Pure API layer (zero dependencies)
    ↑
bitty-network-core       # Shared utilities
    ↑
bitty-network-dns        # DNS resolution & caching
bitty-network-tls        # TLS provider
    ↑
bitty-network            # HTTP/WebSocket backends
    ↑
bitty-net                # stdio coprocess component (wire protocol v1)

bitty-network-wire       # wire protocol v1 codec (std only; linked by core)
```

### Crates

- **`bitty-network-api`** — Light contract layer (request/response types, capability definitions, service traits). Zero implementation dependencies. This is the only crate plugins and cross-repo consumers ever depend on.
  
- **`bitty-network-core`** — Shared core functionality: diagnostics, policy vocabulary, runtime markers, protocol helpers.

- **`bitty-network-dns`** — DNS resolution with bounded LRU cache, per-record deadlines, and redacted diagnostic snapshots.

- **`bitty-network-tls`** — TLS trust provider: CA bundles, platform verifier, client identity (mTLS), X.509 certificate parsing.

- **`bitty-network`** — The real implementation (async runtime, transport, HTTP/WebSocket, proxy, policy) behind default-off Cargo features.

- **`bitty-network-wire`** — Native-component wire protocol v1 codec: length-prefixed frames (256 KiB max), fixed message tags, bounded fail-closed decoding. Dependency-free (`std` only, no serde); the only crate from this repository the Bitty core is specified to link under the accepted [DIR-030 native-component boundary](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/development/native-component-boundary.md). The byte layout is documented in the crate rustdoc.

- **`bitty-net`** — The `net` native component executable (lib + bin), built from this repository per DIR-030: an independently installed stdio coprocess that serves wire protocol v1 on stdin/stdout, re-checks the per-request grant handed to it by the Bitty core (never widening it), and executes HTTP through `bitty-network` (`http` feature). `bitty-net --version` prints the version. The core-side broker (spawn, digest verification, idle stop, crash backoff) is specified in DIR-030 but not yet implemented in the `bitty` repository — this crate is the component binary only.

- **`bitty-network-lua`** — The embedded Lua binding still linked by Bitty core today (`bitty-lua`/`bitty-runtime`, pinned at a fixed revision via `git` dependency, default-off `network` feature). DIR-030 specifies retiring this in favor of the `bitty-net` component plus a Lua front-end plugin, but that migration has not landed in the `bitty` repository yet; do not describe this crate as already deprecated or unused.

## Status

Offline backend plus two real transports. The default `bitty` binary stays network-free; the default-off `http` feature enables the embedded HTTP backend and the default-off `websocket` feature (which implies `http`) enables the capability-gated WebSocket backend (supply-chain approval in `deny.toml`). This runtime enters only when a network-capable consumer (AI provider, weather/GitHub/mail plugin, remote panel) is installed.

Bitty core currently consumes this repository only through `bitty-network-lua` (git dependency pinned to a fixed revision, see `bitty/crates/bitty-lua` and `bitty/crates/bitty-runtime`). The `bitty-net`/`bitty-network-wire` native-component path is accepted direction (DIR-030) and implemented here, but core's component broker is not yet built; `bitty-net` is not yet spawned by anything in production.

Full direction: `bitty-terminal-docs` `specifications/bitty-network-candidate.md` (#111); native-component model: `bitty-docs` [`docs/development/native-component-boundary.md`](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/development/native-component-boundary.md) (DIR-030, accepted direction, not yet `Verified`).

## Features

```toml
[features]
default = []           # Offline-only
http = [...]           # HTTP client + DNS + TLS + Proxy
websocket = ["http"]   # WebSocket + HTTP handshake
```

## Plugin Usage

### Minimal - API types only

```toml
[dependencies]
bitty-network-api = "0.0.1"
```

### DNS resolution only

```toml
[dependencies]
bitty-network-api = "0.0.1"
bitty-network-dns = "0.0.1"
```

### Full HTTP client

```toml
[dependencies]
bitty-network = { version = "0.0.1", features = ["http"] }
```

### Lua Integration

Today, Lua plugins reach the network through the embedded `bitty-network-lua`
binding linked into Bitty core (default-off `network` feature on
`bitty-lua`/`bitty-runtime`), not through the `bitty-net` component. DIR-030
specifies retiring the embedded binding in favor of brokered requests to the
`bitty-net` component plus a Lua front-end plugin; that migration is accepted
direction, not yet implemented in the `bitty` repository. The Lua surface
below is the planned shape for after that migration lands:

```lua
-- bitty-plugin.toml
[[requires.capabilities]]
id = "network.egress"
hosts = ["api.example.com"]

-- plugin.lua
local network = require("bitty.network")

network.request({
    method = "GET",
    url = "https://api.example.com/data"
}):then(function(response)
    print(response.body)
end)
```

See `docs/lua-integration/design.md` for the complete Lua API design.

## Documentation

- [Architecture Overview](docs/architecture/crate-structure.md)
- [Lua Integration Design](docs/lua-integration/design.md)
- API Documentation: `cargo doc --workspace --no-deps --open`

## Layout

- `crates/` — workspace members (bitty-network-api, bitty-network-core, bitty-network-dns, bitty-network-tls, bitty-network, bitty-network-wire, bitty-net, bitty-network-lua)
- `docs/` — architecture and integration documentation

## Gates

`just check` (fmt + clippy `-D warnings` + test). Rust channel pinned in `rust-toolchain.toml`; MSRV 1.85 (`rust-version` in the workspace root).
