-- bitty.network Lua API
-- This is the Lua-side wrapper around the Rust FFI bindings.
-- Provides a clean, idiomatic Lua API for network operations.

local network = {}

--- Make an HTTP request.
-- @param opts table Request options
--   - method: string (GET, POST, etc.)
--   - url: string
--   - headers: table (optional)
--   - body: string (optional)
--   - timeout_ms: number (optional)
-- @return Promise Promise that resolves to response
function network.request(opts)
    -- TODO: Call FFI binding
    -- TODO: Return Promise
    error("network.request not implemented")
end

--- Resolve a hostname to IP addresses.
-- @param hostname string Hostname to resolve
-- @return Promise Promise that resolves to { addresses: string[], ttl: number }
function network.resolve(hostname)
    -- TODO: Call FFI binding
    -- TODO: Return Promise
    error("network.resolve not implemented")
end

--- Create a WebSocket connection.
-- @param url string WebSocket URL
-- @param opts table WebSocket options (optional)
-- @return WebSocket WebSocket handle
function network.websocket(url, opts)
    -- TODO: Implement WebSocket API
    error("network.websocket not implemented")
end

return network
