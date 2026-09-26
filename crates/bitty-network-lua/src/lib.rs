//! Lua FFI bindings for bitty-network with shared runtime.
//!
//! This crate provides a Promise-based async API for Lua plugins to access
//! network capabilities through the capability system. Key features:
//!
//! - **Shared Runtime**: Single NetworkService instance shared across all plugins
//! - **Capability Isolation**: Per-plugin capability checking
//! - **Resource Limits**: Per-plugin rate limiting and quotas
//! - **Promise-based API**: Clean async handling for Lua
//!
//! # Architecture
//!
//! ```text
//! bitty-plugin-host (owns singleton)
//!     ↓
//! SharedNetworkRuntime
//!     ├── DNS Cache (shared)
//!     ├── TLS Session Cache (shared)
//!     ├── HTTP Connection Pool (shared)
//!     └── Capability Checker (per-plugin)
//!     ↓
//! LuaNetworkModule (FFI boundary)
//!     ↓
//! Lua Plugins (bitty.network API)
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use bitty_network_lua::{SharedNetworkRuntime, register_network_module};
//! use mlua::Lua;
//!
//! let lua = Lua::new();
//! let runtime = SharedNetworkRuntime::new();
//! register_network_module(&lua, runtime)?;
//!
//! // Plugins can now use: local network = require("bitty.network")
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

use bitty_network::NetworkService;
use bitty_network_api::{Request, Response, NetworkError};
use mlua::{Lua, Table, UserData, UserDataMethods, Result as LuaResult, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Shared network runtime singleton.
///
/// This is the single instance that all plugins use for network operations.
/// Resources (DNS cache, TLS sessions, connection pool) are shared, but
/// capabilities and limits are enforced per-plugin.
pub struct SharedNetworkRuntime {
    backend: Arc<Mutex<Box<dyn NetworkService>>>,
    // TODO: Add CapabilityRegistry
    // TODO: Add ResourceLimits
}

impl SharedNetworkRuntime {
    /// Create a new shared network runtime.
    ///
    /// This should be called once by `bitty-plugin-host` during initialization.
    pub fn new() -> Self {
        // TODO: Initialize with actual backend
        // For now, this is a skeleton
        todo!("Initialize backend with DNS cache, TLS provider, connection pool")
    }

    /// Execute a network request for a specific plugin.
    ///
    /// This checks the plugin's capabilities and resource limits before
    /// executing the request.
    pub async fn request_for_plugin(
        &self,
        _plugin_id: String,
        _request: Request,
    ) -> Result<Response, NetworkError> {
        // TODO: Implement capability check
        // TODO: Implement resource limit check
        // TODO: Execute request via backend
        todo!("Implement request_for_plugin")
    }
}

impl Default for SharedNetworkRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Lua network module exposed to plugins as `bitty.network`.
pub struct LuaNetworkModule {
    runtime: Arc<SharedNetworkRuntime>,
}

impl UserData for LuaNetworkModule {
    fn add_methods<'lua, M: UserDataMethods<'lua, Self>>(methods: &mut M) {
        // network.request({ method = "GET", url = "..." })
        methods.add_method("request", |_lua, _this, _opts: Table| {
            // TODO: Parse options into Request
            // TODO: Get current plugin ID from Lua context
            // TODO: Execute request via runtime
            // TODO: Return Promise handle
            LuaResult::Ok(())
        });

        // network.resolve("hostname")
        methods.add_method("resolve", |_lua, _this, _hostname: String| {
            // TODO: Implement DNS resolution
            LuaResult::Ok(())
        });
    }
}

/// Register the network module in the Lua VM.
///
/// This should be called once by `bitty-plugin-host` after creating the
/// `SharedNetworkRuntime`.
///
/// # Example
///
/// ```rust,no_run
/// use bitty_network_lua::{SharedNetworkRuntime, register_network_module};
/// use mlua::Lua;
///
/// let lua = Lua::new();
/// let runtime = SharedNetworkRuntime::new();
/// register_network_module(&lua, runtime)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn register_network_module(
    lua: &Lua,
    runtime: SharedNetworkRuntime,
) -> LuaResult<()> {
    let network = LuaNetworkModule {
        runtime: Arc::new(runtime),
    };

    // Register as global "bitty.network"
    let bitty: Table = match lua.globals().get("bitty") {
        Ok(table) => table,
        Err(_) => {
            let table = lua.create_table()?;
            lua.globals().set("bitty", table.clone())?;
            table
        }
    };

    bitty.set("network", network)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_network_module() {
        let lua = Lua::new();
        let runtime = SharedNetworkRuntime::new();
        register_network_module(&lua, runtime).unwrap();

        // Verify bitty.network is registered
        let result: Value = lua
            .load("return type(bitty.network)")
            .eval()
            .unwrap();
        
        assert_eq!(result, Value::String(lua.create_string("userdata").unwrap()));
    }
}
