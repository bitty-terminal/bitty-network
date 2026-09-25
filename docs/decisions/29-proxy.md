# #29: proxy feature — one meaning, wired

Status: decided and wired at the policy layer (CTX-0015, lane D).

Parent: #16 (future backends umbrella).

## Decision

The `proxy` gate enables **environment-proxy inheritance** and nothing else:

- With `proxy`: backends may inherit `HTTPS_PROXY`/`NO_PROXY` from the
  environment (current `HttpNetworkService::new` behavior).
- Without `proxy`: the environment is ignored — egress is direct-only
  unless the caller passes an explicit proxy.
- Explicit proxies (`HttpNetworkService::with_proxy`) stay always-on in
  both cases: explicit construction is a deliberate operator/test act, not
  ambient authority, so the gate must not disable it.

## Rationale

The gate was meaningless because proxy handling worked identically with
and without it. Of the two candidate meanings, gating environment
inheritance is the fail-closed choice: the process environment is ambient
authority that can silently reroute egress, so the default (gate off)
must ignore it. An explicit proxy URL, by contrast, is already an
opt-in at the call site and needs no second switch. This also matches the
standing rule that proxy handling stays explicit and observable.

## Wiring (this lane)

- New `src/proxy.rs` policy module (no I/O, no env reads): the single
  `env_proxy_enabled()` predicate plus unit tests pinning both sides.
- `tests/offline.rs` pins the predicate in the CI feature matrix (which
  runs that target once per gate).
- `Cargo.toml` annotates the `proxy` feature with this meaning.

## Backend integration (for the owning lane, not edited here)

`src/http.rs` is owned by sibling lanes this slice, so the one-line
integration below is recorded here instead of applied:

```rust
// In `HttpNetworkService::new`: skip the environment unless the gate
// opts in; explicit `with_proxy` is unaffected.
let (https_proxy, no_proxy) = if crate::proxy::env_proxy_enabled() {
    (https_proxy_from_env(), no_proxy_from_env())
} else {
    (None, String::new())
};
```

Until that lands, the policy predicate and its tests are the contract;
`HttpNetworkService::new` still inherits the environment unconditionally.

## Acceptance

- `cargo test -p bitty-network --lib` (gate off): env inheritance disabled.
- `cargo test -p bitty-network --lib --features proxy` (gate on): enabled.
- CI matrix legs for `proxy` and every other gate stay green.
