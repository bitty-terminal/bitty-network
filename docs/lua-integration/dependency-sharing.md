# bitty-network Dependency Sharing Strategy

## Problem: Dependency Hell

When multiple Lua plugins require network capabilities, if each plugin independently loads `bitty-network`, it causes:

1. **Duplicate Dependencies**: The same Rust crate is loaded multiple times.
2. **Memory Waste**: DNS cache and TLS session cache are duplicated.
3. **Connection Pool Contention**: HTTP connection pools cannot be shared.
4. **Resource Exhaustion**: Each plugin maintains its own connection limit.

## Solution: Shared Network Runtime

### Architecture Design

```
bitty-plugin-host (Rust)
    ↓ owns (singleton)
NetworkRuntime (Rust)
    ├── DNS Cache (shared)
    ├── TLS Session Cache (shared)
    ├── HTTP Connection Pool (shared)
    └── Capability Checker (per-plugin)
    ↓ exposes via FFI
bitty.network (Lua module, loaded once)
    ↓ used by
Plugin A, Plugin B, Plugin C... (Lua)
```

### Key Principles

1. **Singleton Pattern**: Exactly one `NetworkRuntime` instance exists in `bitty-plugin-host`.
2. **Shared Resources**: DNS cache, TLS session cache, and connection pools are globally shared.
3. **Isolation and Control**: Each plugin maintains independent capabilities and resource limits.
4. **Lazy Initialization**: Initialization occurs only when the first plugin requests network access.

## Implementation

### 1. Rust Side - Shared Runtime

```rust
// In bitty-plugin-host/src/network.rs
use bitty_network::{NetworkService, HttpBackend};
use std::sync::{Arc, Mutex};

pub struct SharedNetworkRuntime {
    backend: Arc<dyn NetworkService>,
    capabilities: CapabilityRegistry,
    limits: ResourceLimits,
}

impl SharedNetworkRuntime {
    pub fn new() -> Self {
        let backend = Arc::new(HttpBackend::new(
            DnsCache::shared(),      // Shared DNS cache
            TlsProvider::shared(),   // Shared TLS session cache
            ConnectionPool::shared() // Shared HTTP connection pool
        ));
        
        Self {
            backend,
            capabilities: CapabilityRegistry::new(),
            limits: ResourceLimits::default(),
        }
    }
    
    pub fn request_for_plugin(
        &self,
        plugin_id: PluginId,
        request: Request
    ) -> Result<Promise<Response>> {
        // 1. Check plugin's capability
        self.capabilities.check(plugin_id, &request)?;
        
        // 2. Check plugin's resource limits
        self.limits.check(plugin_id)?;
        
        // 3. Execute request with shared backend
        self.backend.send(request)
    }
}
```

### 2. Lua FFI - Single Module Instance

```rust
// In bitty-network-lua/src/lib.rs
use mlua::{Lua, Table, UserData};

pub struct LuaNetworkModule {
    runtime: Arc<SharedNetworkRuntime>,
}

impl UserData for LuaNetworkModule {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("request", |lua, this, opts: Table| {
            let plugin_id = get_current_plugin_id(lua)?;
            let request = parse_request(opts)?;
            
            // All plugins use the SAME runtime
            this.runtime.request_for_plugin(plugin_id, request)
        });
    }
}

// Called once by bitty-plugin-host during initialization
pub fn register_network_module(lua: &Lua, runtime: Arc<SharedNetworkRuntime>) -> Result<()> {
    let network = LuaNetworkModule { runtime };
    
    // Register as global "bitty.network"
    let bitty: Table = lua.globals().get("bitty")?;
    bitty.set("network", network)?;
    
    Ok(())
}
```

### 3. Plugin Loading Flow

```rust
// In bitty-plugin-host
pub struct PluginHost {
    lua: Lua,
    network_runtime: Arc<SharedNetworkRuntime>, // Shared singleton
    loaded_plugins: HashMap<PluginId, Plugin>,
}

impl PluginHost {
    pub fn new() -> Self {
        let lua = Lua::new();
        
        // Create shared network runtime ONCE
        let network_runtime = Arc::new(SharedNetworkRuntime::new());
        
        // Register network module ONCE
        bitty_network_lua::register_network_module(&lua, network_runtime.clone())
            .expect("Failed to register network module");
        
        Self {
            lua,
            network_runtime,
            loaded_plugins: HashMap::new(),
        }
    }
    
    pub fn load_plugin(&mut self, manifest: Manifest) -> Result<()> {
        let plugin_id = manifest.id.clone();
        
        // Grant capabilities to plugin
        for cap in manifest.requires.capabilities {
            self.network_runtime.capabilities.grant(plugin_id, cap);
        }
        
        // Load plugin code (shares the SAME lua VM and network module)
        self.lua.load(&manifest.main_file).exec()?;
        
        Ok(())
    }
}
```

### 4. Lua Side - Transparent Usage

```lua
-- weather-plugin.lua
local network = require("bitty.network")  -- Gets shared instance

function fetch_weather()
    return network.request({ url = "..." })
end

-- mail-plugin.lua
local network = require("bitty.network")  -- Gets SAME shared instance

function check_mail()
    return network.request({ url = "..." })
end
```

## Resource Isolation

While underlying resources are shared, each plugin enforces independent limits:

```rust
pub struct ResourceLimits {
    per_plugin: HashMap<PluginId, PluginLimits>,
}

pub struct PluginLimits {
    max_concurrent_requests: usize,    // Maximum 10 concurrent requests per plugin
    max_requests_per_second: usize,    // Maximum 100 requests per second
    total_bandwidth_bytes: usize,      // Total bandwidth limit
}

impl ResourceLimits {
    pub fn check(&self, plugin_id: PluginId) -> Result<()> {
        let limits = self.per_plugin.get(&plugin_id)?;
        
        if limits.current_requests >= limits.max_concurrent_requests {
            return Err(RateLimitError::TooManyConcurrent);
        }
        
        if limits.requests_this_second >= limits.max_requests_per_second {
            return Err(RateLimitError::TooManyRequests);
        }
        
        Ok(())
    }
}
```

## Benefits

### 1. Memory Efficiency
- ✅ Single shared DNS cache (globally shared)
- ✅ Single shared TLS session cache
- ✅ Single shared HTTP connection pool (reuses TCP connections)

### 2. Performance Improvement
- ✅ DNS query results reused across plugins
- ✅ TLS handshake results reused across plugins
- ✅ Keep-alive connections reused across plugins

### 3. Resource Control
- ✅ Globally bounded concurrent request count
- ✅ Independent rate limit per plugin
- ✅ Fair scheduling (optional: weighted queue)

### 4. Security Isolation
- ✅ Independent capability verification per plugin
- ✅ Plugin A cannot inspect Plugin B's requests or responses
- ✅ Audit log records every plugin's network activity

## Example: DNS Cache Sharing

```
Time  Plugin    Action           DNS Cache State
----  ------    ------           ---------------
T0    Weather   resolve(api.weather.com)
                                 [api.weather.com -> 1.2.3.4] (cached)
                
T1    Mail      resolve(api.weather.com)
                ✅ Cache hit!    [api.weather.com -> 1.2.3.4] (reused)
                No DNS query sent
                
T2    News      resolve(api.news.com)
                                 [api.weather.com -> 1.2.3.4]
                                 [api.news.com -> 5.6.7.8] (cached)
```

## Configuration

```toml
# bitty.toml (global config)
[network]
enabled = true

[network.shared]
dns_cache_size = 1000            # Shared across all plugins
dns_ttl_max_seconds = 3600
tls_session_cache_size = 100
connection_pool_max = 100        # Total connections

[network.per_plugin]
max_concurrent_requests = 10     # Per plugin limit
max_requests_per_second = 100
max_request_body_bytes = 1048576
max_response_body_bytes = 10485760
```

## Migration Path

### Phase 1: Foundation (Current)
- ✅ Modular crate structure
- ✅ Lua integration design
- ⏳ Shared runtime implementation

### Phase 2: Basic Sharing
- Create `SharedNetworkRuntime`
- Implement capability isolation
- Basic resource limits

### Phase 3: Advanced Features
- DNS cache sharing
- TLS session cache
- Connection pool
- Rate limiting

### Phase 4: Monitoring
- Per-plugin metrics
- Audit logging
- Debug tooling

## References

- Similar patterns:
  - Browser: shared DNS/TLS cache across tabs
  - Node.js: global event loop shared by modules
  - Python: import system deduplicates modules
