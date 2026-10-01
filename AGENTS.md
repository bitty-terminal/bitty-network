# bitty-network AGENTS.md

L1 Rust Core Extension: shared optional network runtime (`bitty-network-api` +
`bitty-network`). Default-off; the `bitty` binary stays network-free.
The `bitty-net` crate builds the `net` native component (stdio coprocess,
DIR-030) and `bitty-network-wire` is its dependency-free protocol v1 codec,
the only crate of this repository the core links. `bitty-network-lua` is
deprecated (embedded binding retired by DIR-030).

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
- `bitty-network-wire` stays dependency-free (`std` only, no serde); every
  decode is bounded and fail-closed. Tag values and limits are fixed by
  protocol v1; changing them is a protocol version bump.
- `bitty-net` writes protocol frames only to stdout and diagnostics only to
  stderr, never logging URLs, header values, or bodies.
- Ephemeral scratch under `/tmp/bitty/`; durable material under repo-local
  gitignored `recording/`. Disk hygiene: remove task target dirs on close.
- Implementation goes to scoped subagents with independent review; no
  self-review. No commit/push/merge without explicit task authorization.
