//! Phodopus FFI bindings for bitty-network with shared runtime.
//!
//! This crate provides network capabilities to Lua plugins via Phodopus, Bitty's
//! pure-Rust stackless Lua VM. Key features:
//!
//! - **Shared Runtime**: Single NetworkService instance shared across all plugins
//! - **Capability Isolation**: Per-plugin capability checking
//! - **Resource Limits**: Per-plugin rate limiting and quotas
//! - **Phodopus Integration**: Native Callback-based API (no mlua dependency)
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
//! NetworkCallback (Phodopus CallbackFn)
//!     ↓
//! Lua Plugins (bitty.network API)
//! ```
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use bitty_network_lua::SharedNetworkRuntime;
//! use phodopus::Lua;
//!
//! // Create the shared runtime (once per process)
//! let runtime = SharedNetworkRuntime::new();
//!
//! // Create Phodopus VM
//! let mut lua = Lua::full();
//!
//! // Register network module (skeleton)
//! lua.try_enter(|ctx| {
//!     bitty_network_lua::register_network_module(ctx, &runtime)
//! })?;
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

use bitty_network_api::{NetworkError, Request, Response};
use phodopus::{Context, Error, Table};

/// Shared network runtime singleton.
///
/// This is the single instance that all plugins use for network operations.
/// Resources (DNS cache, TLS sessions, connection pool) are shared, but
/// capabilities and limits are enforced per-plugin.
///
/// # Implementation Note
///
/// This is currently a skeleton. The actual backend integration will be
/// implemented once the Phodopus async bridge and capability system are
/// fully integrated with bitty-plugin-host.
pub struct SharedNetworkRuntime {
    // Future: backend reference
    // backend: Arc<dyn NetworkService>,

    // Future: capability registry
    // capabilities: Arc<CapabilityRegistry>,

    // Future: resource limits
    // limits: Arc<ResourceLimits>,
    _placeholder: (),
}

impl SharedNetworkRuntime {
    /// Create a new shared network runtime.
    ///
    /// This should be called once by `bitty-plugin-host` during initialization.
    ///
    /// # Implementation Status
    ///
    /// This is a skeleton implementation. It creates an empty runtime without
    /// actual backend initialization. Real network operations will be added
    /// once the Phodopus async integration is complete.
    #[must_use]
    pub fn new() -> Self {
        Self { _placeholder: () }
    }

    /// Execute a network request for a specific plugin.
    ///
    /// This checks the plugin's capabilities and resource limits before
    /// executing the request.
    ///
    /// # Implementation Status
    ///
    /// This is a skeleton. It will panic if called.
    ///
    /// # Future Implementation
    ///
    /// 1. Check plugin's `network.egress` capability
    /// 2. Verify request against allowed domains/ports
    /// 3. Check resource limits (rate limiting, concurrent requests)
    /// 4. Execute request via backend
    /// 5. Return response or typed error
    pub async fn request_for_plugin(
        &self,
        _plugin_id: &str,
        _request: Request,
    ) -> Result<Response, NetworkError> {
        // Skeleton: not yet implemented
        // Will be implemented once:
        // 1. Phodopus async suspension bridge is integrated
        // 2. Capability system is wired into bitty-plugin-host
        // 3. Backend initialization is complete
        unimplemented!("request_for_plugin: awaiting Phodopus async integration")
    }
}

impl Default for SharedNetworkRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Register the network module in a Phodopus VM.
///
/// This creates a `bitty.network` table in the Lua globals with network
/// operation callbacks.
///
/// # Implementation Status
///
/// This is a skeleton that creates the table structure but does not yet
/// register actual callbacks. Callback registration requires:
///
/// 1. Implementing `Callback` trait for network operations
/// 2. Phodopus async suspension bridge for request/response
/// 3. Integration with bitty-plugin-host's capability system
///
/// # Example
///
/// ```rust,no_run
/// use bitty_network_lua::{SharedNetworkRuntime, register_network_module};
/// use phodopus::Lua;
///
/// let mut lua = Lua::full();
/// let runtime = SharedNetworkRuntime::new();
///
/// lua.try_enter(|ctx| {
///     register_network_module(ctx, &runtime)
/// })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn register_network_module<'gc>(
    ctx: Context<'gc>,
    _runtime: &SharedNetworkRuntime,
) -> Result<(), Error<'gc>> {
    let globals = ctx.globals();

    // Create bitty table if not exists
    let bitty = match globals.get::<_, Table>(ctx, "bitty") {
        Ok(table) => table,
        Err(_) => {
            let table = Table::new(&ctx);
            globals.set(ctx, "bitty", table)?;
            table
        }
    };

    // Create network table
    let network = Table::new(&ctx);

    // Register test callbacks (demonstrating Phodopus Callback integration)
    let echo_cb = callback::create_echo_callback(&ctx);
    let info_cb = callback::create_info_callback(&ctx);

    network.set(ctx, "echo", echo_cb)?;
    network.set(ctx, "info", info_cb)?;

    // Future: Register real network operation callbacks
    // let request_callback = Callback::from_fn(&ctx, |ctx, _exec, mut stack| {
    //     // Parse Lua args from stack
    //     // Get plugin_id from context
    //     // Call runtime.request_for_plugin()
    //     // Return result
    //     Ok(CallbackReturn::Return)
    // });
    // network.set(ctx, "request", request_callback)?;

    // Future: Register resolve callback
    // let resolve_callback = Callback::from_fn(&ctx, |ctx, _exec, mut stack| {
    //     // Similar pattern for DNS resolution
    //     Ok(CallbackReturn::Return)
    // });
    // network.set(ctx, "resolve", resolve_callback)?;

    bitty.set(ctx, "network", network)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use phodopus::Lua;

    #[test]
    fn test_shared_runtime_new() {
        // Should not panic - skeleton is valid
        let _runtime = SharedNetworkRuntime::new();
    }

    #[test]
    fn test_register_network_module() {
        let mut lua = Lua::full();
        let runtime = SharedNetworkRuntime::new();

        lua.try_enter(|ctx| {
            register_network_module(ctx, &runtime)?;

            // Verify bitty.network table exists
            let globals = ctx.globals();
            let bitty: Table = globals.get(ctx, "bitty")?;
            let network: Table = bitty.get(ctx, "network")?;

            // Table should exist but be empty (skeleton)
            let _ = network;

            Ok(())
        })
        .expect("registration should succeed");
    }

    #[tokio::test]
    #[should_panic(expected = "not implemented")]
    async fn test_request_for_plugin_unimplemented() {
        let runtime = SharedNetworkRuntime::new();
        let request = Request::get("https://example.com");

        let _ = runtime.request_for_plugin("test-plugin", request).await;
    }
}
pub mod callback;
