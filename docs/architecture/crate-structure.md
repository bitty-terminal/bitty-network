# bitty-network Crate Architecture

## Overview

bitty-network is split into focused, composable crates to enable fine-grained plugin dependencies and clear separation of concerns.

## Crate Structure

```
bitty-network/
├── bitty-network-api/        # Pure API layer (zero dependencies)
│   ├── Request/Response types
│   ├── NetworkError definitions
│   ├── Capability definitions
│   └── NetworkService trait
│
├── bitty-network-core/        # Shared core functionality
│   ├── Diagnostics (redaction, sanitization)
│   ├── Policy vocabulary
│   ├── Runtime markers
│   └── Protocol helpers (WebSocket subprotocol negotiation)
│
├── bitty-network-dns/         # DNS resolution and caching
│   ├── Bounded LRU cache
│   ├── Per-record deadlines
│   └── Redacted diagnostic snapshots
│
├── bitty-network-tls/         # TLS provider
│   ├── Trust policy (CA bundles, platform verifier)
│   ├── Client identity (mTLS)
│   └── X.509 certificate parsing
│
└── bitty-network/             # HTTP + WebSocket backends
    ├── HTTP client (via reqwest)
    ├── WebSocket client (via tungstenite)
    ├── Proxy handling (HTTPS_PROXY, NO_PROXY, PAC)
    ├── Transport abstraction
    └── Offline backend (fail-closed)
```

## Dependency Graph

```
bitty-network-api  (no dependencies)
    ↑
bitty-network-core
    ↑
bitty-network-dns
bitty-network-tls
    ↑
bitty-network  (HTTP/WebSocket backends)
```

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

## Design Principles

1. **Layered Architecture**: API → Core → Specialized → Backends
2. **Zero Breaking Changes**: Backward compatibility at every phase
3. **Fine-grained Dependencies**: Plugins include only what they need
4. **Fail-closed Security**: Every feature behind capability gates
5. **MSRV 1.85**: Stable Rust, no nightly features

## Implementation Status

- ✅ Phase 1: bitty-network-core (PR #55)
- ✅ Phase 2: bitty-network-dns (PR #56)
- ✅ Phase 3: bitty-network-tls (PR #57)
- ⏸️ Further split deferred (backends are tightly coupled)

## Next Steps

1. Generate comprehensive API documentation
2. Design Lua integration layer (bitty-network-lua)
3. Create plugin development guide
4. Implement capability-based access control
