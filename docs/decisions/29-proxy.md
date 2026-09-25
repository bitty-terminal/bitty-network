# #29: proxy feature — one meaning, wired

Status: decided and wired (CTX-0015, lane D: policy layer; CTX-0034: HTTP
backend integration).

Parent: #16 (future backends umbrella).

## Decision

The `proxy` gate enables **environment-proxy inheritance** and nothing else:

- With `proxy`: backends may inherit `HTTP_PROXY`, `HTTPS_PROXY`,
  `ALL_PROXY`, and `NO_PROXY` (each in both spellings) from the environment.
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

## Backend integration (CTX-0034)

`HttpNetworkService::new` is the one place the gate decides, and it decides
before any variable is read:

```rust
// In `HttpNetworkService::new`: skip the environment unless the gate
// opts in; explicit `with_proxy` is unaffected.
if !crate::proxy::env_proxy_enabled() {
    return Self::from_egress(capability, ProxyRoute::default(), String::new(), false);
}
```

Gate off, `proxy_from_env`, `no_proxy_from_env`, and `ProxyRoute::from_env`
are never called, so no ambient proxy URL is read, retained, or rejected.
Gate on, the environment is snapshotted exactly as before.

This gate is independent of the unconditional egress controls (CTX-0028):
`.no_proxy()` and `Policy::none()` on every reqwest client, and
credential-bearing proxy URLs rejected before any `Proxy::all` or
`.proxy()` call, apply in both configurations. The gate withholds
_environment inheritance_ only; an explicit `with_proxy` route keeps
working either way.

## Acceptance

- `cargo test -p bitty-network --test http` (gate off): the ambient proxy
  is never used, the request reaches the origin, and `with_proxy` still
  routes through an explicit proxy.
- `cargo test -p bitty-network --test http --features http,proxy` (gate
  on): the ambient proxy is used, and an unusable configured proxy fails
  closed.
- `cargo test -p bitty-network --test offline --features proxy` and the
  CI matrix legs for `proxy` and every other gate stay green.
