# bitty-network

Bitty L1 Rust Core Extension: the shared, optional network runtime.

- `crates/bitty-network-api` — light contract layer (request/response types,
  capability definitions, service traits). Zero implementation dependencies.
  This is the only crate plugins and cross-repo consumers ever depend on.
- `crates/bitty-network` — the real implementation (async runtime, transport,
  HTTP/WebSocket, TLS, DNS, proxy, policy) behind default-off Cargo features.

Status: shell only. No sockets, no network dependencies yet. The default
`bitty` binary stays network-free; this runtime enters only when a
network-capable consumer (AI provider, weather/GitHub/mail plugin, remote
panel) is installed. Full direction:
`bitty-terminal-docs` `specifications/bitty-network-candidate.md` (#111).

## Layout

- `crates/` — workspace members (`bitty-network-api`, `bitty-network`)
- `docs/` — repo process documents (mounted where applicable)

## Gates

`just check` (fmt + clippy `-D warnings` + test). Rust channel pinned in
`rust-toolchain.toml`; MSRV 1.85 (`rust-version` in the workspace root).
