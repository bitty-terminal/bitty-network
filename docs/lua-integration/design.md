# bitty-network Lua Integration Design

## Goals

1. **Expose network capabilities to Lua plugins** via Plugin API v1
2. **Maintain security boundaries** - no direct grid/cursor access
3. **Follow capability system** - explicit permission grants
4. **Fail-closed by default** - plugins have no network access unless granted

## Architecture

```
Lua Plugin (user code)
    ↓ requires
bitty.network (Lua module)
    ↓ FFI boundary
bitty-network (Rust crate)
    ↓ capability check
bitty-plugin-host (Rust)
```

## Capability Model

### Network Capabilities

```lua
-- bitty-plugin.toml
[[requires.capabilities]]
id = "network.egress"
reason = "Fetch weather data from API"
hosts = ["api.weather.com"]

[[requires.capabilities]]
id = "network.ingress"
reason = "Receive webhooks"
ports = [8080]
```

### Capability Definitions

```toml
# In bitty-network-api
[capabilities]
network.egress = "Outbound HTTP/HTTPS requests"
network.ingress = "Inbound connections (server mode)"
network.websocket = "WebSocket client connections"
network.dns = "DNS resolution"
```

## Lua API Design

### Option A: Direct FFI (Low-level)

```lua
local network = require("bitty.network")

-- Synchronous blocking call
local response = network.http_request({
    method = "GET",
    url = "https://api.example.com/data",
    headers = {
        ["User-Agent"] = "Bitty/0.1"
    },
    timeout_ms = 5000
})

if response.status == 200 then
    print(response.body)
end
```

**Pros:**
- Simple FFI boundary
- Direct mapping to Rust NetworkService trait
- Easy to implement

**Cons:**
- Blocks Lua VM
- No async/await pattern
- Poor UX for long requests

### Option B: Callback-based (Async)

```lua
local network = require("bitty.network")

network.http_request({
    method = "GET",
    url = "https://api.example.com/data",
    on_response = function(response)
        if response.status == 200 then
            print(response.body)
        end
    end,
    on_error = function(error)
        print("Error: " .. error.message)
    end
})
```

**Pros:**
- Non-blocking
- Familiar callback pattern
- Works with Lua's single-threaded model

**Cons:**
- Callback hell for complex flows
- Error handling scattered

### Option C: Promise-like (Recommended)

```lua
local network = require("bitty.network")

local request = network.http_request({
    method = "GET",
    url = "https://api.example.com/data"
})

-- Register continuation
request:then(function(response)
    print("Status:", response.status)
    print("Body:", response.body)
end):catch(function(error)
    print("Error:", error.message)
end)

-- Or await-style (if Lua coroutines)
local response = await(request)
```

**Pros:**
- Chainable
- Clear error handling
- Can be wrapped for coroutine-based async/await
- Future-proof for bitty-plugin-host's async executor

**Cons:**
- More complex FFI implementation
- Requires request handle management

## Recommended API Structure

### Core Network Module

```lua
-- bitty-network-lua/network.lua
local network = {}

-- HTTP client
function network.request(opts)
    -- opts: { method, url, headers, body, timeout_ms }
    -- Returns: Promise
end

-- DNS resolution
function network.resolve(hostname)
    -- Returns: Promise<{ addresses: string[], ttl: number }>
end

-- WebSocket client
function network.websocket(url, opts)
    -- Returns: WebSocket handle
end

return network
```

### Promise Implementation

```lua
-- bitty-network-lua/promise.lua
local Promise = {}

function Promise.new(executor)
    -- executor: function(resolve, reject)
    -- Returns: Promise object
end

function Promise:then(on_fulfilled, on_rejected)
    -- Chainable
end

function Promise:catch(on_rejected)
    -- Sugar for :then(nil, on_rejected)
end

return Promise
```

## Integration with bitty-plugin-host

### Rust Side

```rust
// bitty-network-lua/src/lib.rs
use bitty_network::{NetworkService, Request, Response};
use mlua::{Lua, Table, Function, UserData};

pub struct LuaNetworkService {
    inner: Box<dyn NetworkService>,
    capability_checker: CapabilityChecker,
}

impl UserData for LuaNetworkService {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("request", |lua, this, opts: Table| {
            // 1. Check capability: network.egress
            // 2. Parse opts into Request
            // 3. Spawn async task
            // 4. Return Promise handle
        });
    }
}
```

### Loading Flow

```rust
// In bitty-plugin-host
let lua = Lua::new();

// Register network module
let network_service = LuaNetworkService::new(
    create_network_service(),
    plugin_capabilities
);
lua.globals().set("network", network_service)?;

// Load plugin
lua.load(plugin_code).exec()?;
```

## Security Controls

### 1. Capability Enforcement

```rust
fn check_capability(&self, request: &Request) -> Result<(), CapabilityError> {
    let host = request.url.host_str().ok_or(InvalidUrl)?;
    
    if !self.capabilities.allows_egress_to(host) {
        return Err(CapabilityError::EgressDenied { host });
    }
    
    Ok(())
}
```

### 2. Resource Limits

```lua
-- Enforced by bitty-plugin-host
[limits]
max_concurrent_requests = 10
max_request_body_bytes = 1048576  # 1MB
max_response_body_bytes = 10485760  # 10MB
timeout_ms = 30000  # 30 seconds
```

### 3. Audit Trail

```rust
// Every network request logged
audit_log.record(AuditEntry {
    plugin_id,
    timestamp,
    capability: "network.egress",
    action: "http_request",
    target: request.url.host(),
    result: Success | Denied
});
```

## Example Plugin

```lua
-- weather-plugin.lua
local network = require("bitty.network")

function fetch_weather(city)
    local url = string.format("https://api.weather.com/v1/current?city=%s", city)
    
    return network.request({
        method = "GET",
        url = url,
        headers = {
            ["User-Agent"] = "Bitty Weather Plugin"
        }
    }):then(function(response)
        if response.status == 200 then
            local data = json.decode(response.body)
            return {
                temp = data.temperature,
                conditions = data.conditions
            }
        else
            error("API error: " .. response.status)
        end
    end)
end

-- Register command
bitty.commands.register({
    name = "weather",
    description = "Show current weather",
    execute = function(args)
        local promise = fetch_weather(args.city or "San Francisco")
        
        promise:then(function(weather)
            bitty.ui.notify(string.format(
                "Temperature: %d°F\nConditions: %s",
                weather.temp,
                weather.conditions
            ))
        end):catch(function(error)
            bitty.ui.notify("Error: " .. error.message)
        end)
    end
})
```

## Implementation Plan

### Phase 1: Foundation
1. ✅ Rust crate structure (core, dns, tls)
2. ⏳ Create bitty-network-lua crate
3. ⏳ Implement basic FFI bindings
4. ⏳ Promise-based async API

### Phase 2: Integration
1. ⏳ Plugin capability enforcement
2. ⏳ Resource limits and budgets
3. ⏳ Audit logging
4. ⏳ Error handling and diagnostics

### Phase 3: Polish
1. ⏳ Comprehensive documentation
2. ⏳ Example plugins
3. ⏳ Testing framework
4. ⏳ Performance benchmarks

## Open Questions

1. **Coroutine Integration**: Should we use Lua coroutines for async/await sugar?
2. **WebSocket API**: How to expose bidirectional streaming to Lua?
3. **DNS Caching**: Should Lua plugins have direct access to DNS cache?
4. **TLS Configuration**: Should plugins configure CA bundles or use system defaults?

## References

- Plugin API v1: `bitty-docs/specifications/plugin-api.md`
- Capability System: `bitty-docs/specifications/capability-system.md`
- Lua VM: `bitty/crates/bitty-lua` (phodopus-based)
- Network Service: `bitty-network-api/src/lib.rs`
