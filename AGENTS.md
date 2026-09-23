# bitty-network AGENTS.md

L1 Rust Core Extension: shared optional network runtime (`bitty-network-api` +
`bitty-network`). Default-off; the `bitty` binary stays network-free.

## Rules

- English only for all content (code comments, docs, commits, Issues, PRs).
- Rust edition 2024, MSRV 1.85 (no let-chains; desugar to nested `if let`).
  Channel pinned in `rust-toolchain.toml`; never bump pins in unrelated tasks.
- Quality gates only via the justfile: `just check`
  (fmt + `clippy -D warnings` + tests). Never invoke formatters/linters bare.
- `#![forbid(unsafe_code)]` in every crate. No `unwrap`/`expect`/`panic` in
  non-test code; typed errors only.
- Never hardcode host/environment values (paths, usernames, URLs, ports).
  Constants for policy/bound/timeout/default values, never magic literals.
- No network dependencies until a scoped task authorizes the real
  implementation. The shell crates stay dependency-free by default.
- `bitty-network-api` stays implementation-free: no HTTP/TLS/runtime
  dependencies, ever. Consumers depend on `-api` only.
- Ephemeral scratch under `/tmp/bitty/`; durable material under repo-local
  gitignored `recording/`. Disk hygiene: remove task target dirs on close.
- Implementation goes to scoped subagents with independent review; no
  self-review. No commit/push/merge without explicit task authorization.
