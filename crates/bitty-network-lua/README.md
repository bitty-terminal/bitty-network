# bitty-network-lua

Lua FFI bindings for bitty-network with shared runtime and dependency deduplication.

## Overview

This crate provides a Promise-based async API for Lua plugins to access network capabilities through Bitty's capability system. The key design principle is **shared runtime**: a single `NetworkService` instance is shared across all plugins, avoiding dependency hell while maintaining security isolation.

## Architecture

```
bitty-plugin-host (Rust)
    ↓ owns (singleton)
SharedNetworkRuntime
    ├── DNS Cache (shared)
    ├── TLS Session Cache (shared)
    ├── HTTP Connection Pool (shared)
    └── Capability Checker (per-plugin)
    ↓ exposes via FFI
bitty.network (Lua module)
    ↓ used by
Plugin A, Plugin B, Plugin C...
```

## Benefits

### Memory Efficiency
- DNS cache shared across all plugins
- TLS session cache shared
- HTTP connection pool shared (TCP connection reuse)

### Performance
- DNS query results reused across plugins
- TLS handshake results reused
- Keep-alive connections reused

### Resource Control
- Global concurrent request limit
- Per-plugin rate limiting
- Fair scheduling

### Security Isolation
- Per-plugin capability checking
- Plugin A cannot see Plugin B's requests/responses
- Audit log for all network activity

## Usage

### Rust Side (bitty-plugin-host)

```rust
use bitty_network_lua::{SharedNetworkRuntime, register_network_module};
use mlua::Lua;

// Create shared runtime ONCE
let runtime = SharedNetworkRuntime::new();

// Register network module ONCE
let lua = Lua::new();
register_network_module(&lua, runtime)?;

// Load plugins (they all share the same runtime)
for plugin in plugins {
    lua.load(&plugin.code).exec()?;
}
```

### Lua Side (Plugin)

```lua
local network = require("bitty.network")

-- Make HTTP request
network.request({
    method = "GET",
    url = "https://api.example.com/data"
}):then(function(response)
    print("Status:", response.status)
    print("Body:", response.body)
end):catch(function(error)
    print("Error:", error.message)
end)

-- Resolve DNS
network.resolve("api.example.com"):then(function(result)
    print("Addresses:", table.concat(result.addresses, ", "))
end)
```

## Capability System

Plugins must declare network capabilities in their manifest:

```toml
# bitty-plugin.toml
[[requires.capabilities]]
id = "network.egress"
reason = "Fetch weather data from API"
hosts = ["api.weather.com"]
```

Runtime enforcement:
- Requests to undeclared hosts are denied
- Per-plugin rate limits enforced
- All network activity audited

## Implementation Status

- [x] Crate structure
- [x] API design documentation
- [ ] Rust FFI implementation
- [ ] Promise implementation
- [ ] Capability enforcement
- [ ] Resource limits
- [ ] Lua wrapper API
- [ ] Example plugins
- [ ] Integration tests

## References

- [Lua Integration Design](../../docs/lua-integration/design.md)
- [Dependency Sharing Strategy](../../docs/lua-integration/dependency-sharing.md)
- [Architecture Overview](../../docs/architecture/crate-structure.md)
