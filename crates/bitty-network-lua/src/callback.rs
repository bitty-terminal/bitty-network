//! Phodopus callback implementations for network operations.
//!
//! This module contains the Callback trait implementations that bridge
//! Lua function calls to Rust network operations.

use phodopus::{Callback, CallbackReturn, Context, FromValue, String as LuaString, Table};

/// Create a simple "echo" callback for testing Phodopus integration.
///
/// This callback takes a string argument and returns it back,
/// demonstrating the basic pattern for Phodopus callbacks.
///
/// # Example
///
/// ```lua
/// local result = bitty.network.echo("Hello, World!")
/// print(result)  -- prints: "Hello, World!"
/// ```
pub fn create_echo_callback<'gc>(ctx: &Context<'gc>) -> Callback<'gc> {
    Callback::from_fn(ctx, |ctx, _exec, mut stack| {
        // Read the first argument from the stack
        let input = stack.get(0);

        // Check if it's a string
        if let Ok(s) = LuaString::from_value(ctx, input) {
            // Echo back the string
            let bytes = s.as_bytes();
            let output = LuaString::from_slice(&ctx, bytes);
            stack.replace(ctx, output);
        } else {
            // Return nil if not a string
            use phodopus::Value;
            stack.replace(ctx, Value::Nil);
        }

        Ok(CallbackReturn::Return)
    })
}

/// Create a simple "info" callback that returns runtime information.
///
/// This callback takes no arguments and returns a table with information
/// about the network runtime, demonstrating table creation in callbacks.
///
/// # Example
///
/// ```lua
/// local info = bitty.network.info()
/// print(info.version)  -- prints version string
/// ```
pub fn create_info_callback<'gc>(ctx: &Context<'gc>) -> Callback<'gc> {
    Callback::from_fn(ctx, |ctx, _exec, mut stack| {
        // Create a table with runtime information
        let info_table = Table::new(&ctx);

        // Add version field
        let version_key = LuaString::from_slice(&ctx, b"version");
        let version_value = LuaString::from_slice(&ctx, b"0.1.0-skeleton");
        info_table.set(ctx, version_key, version_value)?;

        // Add status field
        let status_key = LuaString::from_slice(&ctx, b"status");
        let status_value = LuaString::from_slice(&ctx, b"skeleton");
        info_table.set(ctx, status_key, status_value)?;

        // Return the table
        stack.replace(ctx, info_table);

        Ok(CallbackReturn::Return)
    })
}

#[cfg(test)]
mod tests {
    use phodopus::{Closure, Executor, Lua};

    #[test]
    fn test_echo_callback() {
        let mut lua = Lua::full();

        let stashed = lua
            .try_enter(|ctx| {
                // Register network module first
                let runtime = crate::SharedNetworkRuntime::new();
                crate::register_network_module(ctx, &runtime)?;

                // Create a test script that calls bitty.network.echo
                let script = b"return bitty.network.echo('test message')";
                let closure = Closure::load(ctx, None, script)?;

                // Create executor and stash it
                let executor = Executor::start(ctx, closure.into(), ());
                Ok(ctx.stash(executor))
            })
            .expect("failed to set up echo test");

        // Execute outside of try_enter - use Rust String for FromMultiValue
        let result: String = lua.execute(&stashed).expect("echo callback should work");
        assert_eq!(result, "test message");
    }

    #[test]
    fn test_info_callback() {
        let mut lua = Lua::full();

        let stashed = lua
            .try_enter(|ctx| {
                // Register network module first
                let runtime = crate::SharedNetworkRuntime::new();
                crate::register_network_module(ctx, &runtime)?;

                // Create a test script that calls bitty.network.info
                let script = b"local t = bitty.network.info(); return t.version";
                let closure = Closure::load(ctx, None, script)?;

                // Create executor and stash it
                let executor = Executor::start(ctx, closure.into(), ());
                Ok(ctx.stash(executor))
            })
            .expect("failed to set up info test");

        // Execute outside of try_enter - use Rust String for FromMultiValue
        let version: String = lua.execute(&stashed).expect("info callback should work");
        assert_eq!(version, "0.1.0-skeleton");
    }
}
