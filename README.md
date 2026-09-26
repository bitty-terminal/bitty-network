# bitty-network

Bitty L1 Rust Core Extension: the shared, optional network runtime.

## Architecture

bitty-network is split into focused, composable crates for fine-grained plugin dependencies:

```
bitty-network-api        # Pure API layer (zero dependencies)
    ↑
bitty-network-core       # Shared utilities
    ↑
bitty-network-dns        # DNS resolution & caching
bitty-network-tls        # TLS provider
    ↑
bitty-network            # HTTP/WebSocket backends
```

### Crates

- **`bitty-network-api`** — Light contract layer (request/response types, capability definitions, service traits). Zero implementation dependencies. This is the only crate plugins and cross-repo consumers ever depend on.
  
- **`bitty-network-core`** — Shared core functionality: diagnostics, policy vocabulary, runtime markers, protocol helpers.

- **`bitty-network-dns`** — DNS resolution with bounded LRU cache, per-record deadlines, and redacted diagnostic snapshots.

- **`bitty-network-tls`** — TLS trust provider: CA bundles, platform verifier, client identity (mTLS), X.509 certificate parsing.

- **`bitty-network`** — The real implementation (async runtime, transport, HTTP/WebSocket, proxy, policy) behind default-off Cargo features.

## Status

Offline backend plus two real transports. The default `bitty` binary stays network-free; the default-off `http` feature enables the embedded HTTP backend and the default-off `websocket` feature (which implies `http`) enables the capability-gated WebSocket backend (supply-chain approval in `deny.toml`). This runtime enters only when a network-capable consumer (AI provider, weather/GitHub/mail plugin, remote panel) is installed.

Full direction: `bitty-terminal-docs` `specifications/bitty-network-candidate.md` (#111).

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
bitty-network-api = "0.1"
```

### DNS resolution only
```toml
[dependencies]
bitty-network-api = "0.1"
bitty-network-dns = "0.1"
```

### Full HTTP client
```toml
[dependencies]
bitty-network = { version = "0.1", features = ["http"] }
```

### Lua Integration

Lua plugins access network capabilities through the capability system:

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

- `crates/` — workspace members (bitty-network-api, bitty-network-core, bitty-network-dns, bitty-network-tls, bitty-network)
- `docs/` — architecture and integration documentation

## Gates

`just check` (fmt + clippy `-D warnings` + test). Rust channel pinned in `rust-toolchain.toml`; MSRV 1.85 (`rust-version` in the workspace root).
