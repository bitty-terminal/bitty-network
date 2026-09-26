# bitty-network Dependency Sharing Strategy

## Problem: Dependency Hell

当多个 Lua 插件都需要网络功能时，如果每个插件都独立加载 `bitty-network`，会导致：

1. **重复依赖**：同一个 Rust crate 被加载多次
2. **内存浪费**：DNS 缓存、TLS session cache 被复制多份
3. **连接池冲突**：HTTP 连接池无法共享
4. **资源耗尽**：每个插件都有自己的 connection limit

## Solution: Shared Network Runtime

### 架构设计

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

### 关键原则

1. **单例模式**：`NetworkRuntime` 在 `bitty-plugin-host` 中只有一个实例
2. **共享资源**：DNS 缓存、TLS cache、连接池全局共享
3. **隔离控制**：每个插件有独立的 capability 和 resource limits
4. **懒加载**：只有当第一个插件请求网络功能时才初始化

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

虽然底层资源共享，但每个插件有独立的限制：

```rust
pub struct ResourceLimits {
    per_plugin: HashMap<PluginId, PluginLimits>,
}

pub struct PluginLimits {
    max_concurrent_requests: usize,    // 每个插件最多 10 个并发请求
    max_requests_per_second: usize,    // 每秒最多 100 个请求
    total_bandwidth_bytes: usize,      // 总带宽限制
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

### 1. 内存效率
- ✅ DNS 缓存只有一份（全局共享）
- ✅ TLS session cache 只有一份
- ✅ HTTP 连接池只有一份（复用 TCP 连接）

### 2. 性能提升
- ✅ DNS 查询结果跨插件复用
- ✅ TLS handshake 结果跨插件复用
- ✅ Keep-alive 连接跨插件复用

### 3. 资源控制
- ✅ 全局并发请求数可控
- ✅ 每个插件有独立的 rate limit
- ✅ 公平调度（可选：加权队列）

### 4. 安全隔离
- ✅ 每个插件有独立的 capability 检查
- ✅ 插件 A 无法看到插件 B 的请求/响应
- ✅ 审计日志记录每个插件的网络活动

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
