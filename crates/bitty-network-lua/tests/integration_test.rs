use bitty_network_lua::{SharedNetworkRuntime, register_network_module};
use phodopus::{Closure, Executor, Lua};

#[test]
fn test_echo_integration() {
    let mut lua = Lua::full();

    let stashed = lua
        .try_enter(|ctx| {
            let runtime = SharedNetworkRuntime::new();
            register_network_module(ctx, &runtime)?;

            // Debug: check what bitty.network contains
            let script = br#"
            print("=== DEBUG ===")
            print("bitty:", bitty)
            print("bitty.network:", bitty.network)
            print("bitty.network.echo:", bitty.network.echo)
            print("Calling echo...")
            local result = bitty.network.echo('test')
            print("Result type:", type(result))
            print("Result value:", result)
            return result
        "#;

            let closure = Closure::load(ctx, None, script)?;
            let executor = Executor::start(ctx, closure.into(), ());
            Ok(ctx.stash(executor))
        })
        .expect("setup failed");

    match lua.execute::<String>(&stashed) {
        Ok(result) => println!("Success: {}", result),
        Err(e) => println!("Error: {:?}", e),
    }
}
