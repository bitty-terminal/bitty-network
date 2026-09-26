# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Refactor**: Extracted TLS trust and client-identity provider into new
  `bitty-network-tls` crate (`#56`, phase 3/7 of crate split). Moved `tls` module
  from `bitty-network` to `bitty-network-tls` (~2433 lines: lib.rs, provider.rs,
  x509.rs). The TLS crate includes rustls, rustls-platform-verifier, rustls-pki-types,
  idna, and zeroize dependencies. `bitty-network` re-exports the tls module when
  the http feature is enabled. Zero breaking changes to external API; all existing
  tests pass unchanged. Test file `tls_baseline_properties.rs` updated to reference
  the new crate location.
- **Refactor**: Extracted DNS resolution and caching into new `bitty-network-dns`
  crate (`#56`, phase 2/7 of crate split). Moved `dns` module from `bitty-network`
  to `bitty-network-dns`. The DNS crate is dependency-free (stdlib only) and
  gated behind the `http` feature in `bitty-network`. `bitty-network` re-exports
  the dns module when the http feature is enabled. Zero breaking changes to
  external API; all existing tests pass unchanged.
- **Refactor**: Extracted shared core functionality into new `bitty-network-core`
  crate (`#56`, phase 1/7 of crate split). Moved `diagnostics`, `policy`,
  `runtime`, and `protocol` modules from `bitty-network` to `bitty-network-core`.
  `bitty-network` now re-exports these modules from the core crate. Zero breaking
  changes to external API; all existing tests pass unchanged. This establishes
  the foundation for further modularization of the network stack.

### Added

- Inspector feed audit vocabulary in `bitty-network-api` (`#31`): per-plugin
  per-host audit entry types (`AuditEntry`, `AuditDecision`) and `AuditSink`
  trait for the host to implement. Backends emit entries on every capability
  check outcome (allow/deny) with host, port, method, timestamp, and a plugin
  identity hook. No PII beyond host/port, bounded memory enforced by the host's
  sink implementation. Types only in the API crate; actual backend integration
  deferred pending host-side plugin-identity mapping.
- Embedded offline `NetworkService` with capability-first enforcement: every
  request is checked against the caller's manifest-declared egress
  capabilities before dispatch, and anything undeclared fails closed with a
  typed error. Zero new implementation dependencies for the offline slice.
- Embedded HTTP backend behind the default-off `http` feature: the first real
  transport with supply-chain approval recorded in `deny.toml`.
- Capability-gated WebSocket backend over `tungstenite` behind the
  default-off `websocket` feature.
- Hardened WebSocket transport and plain-HTTP proxy tunneling for issue #38:
  operation-wide DNS/TCP/CONNECT/handshake/receive/send/close deadlines,
  frame/message/aggregate byte and count budgets, bounded pending writes,
  fail-closed CONNECT parsing with tunnel-byte preservation, and explicit
  rejection of authenticated proxy URLs until credential policy lands.
- Opt-in response transfer budget in the HTTP backend: over-budget responses
  fail closed with the previously reserved `NetworkError::Budget`.
- Fail-closed egress port and method-verb checks in the capability gate
  (`bitty-network#13`): manifest-declared ports and verbs are enforced, not
  just hosts.
- Direction decisions for the five no-code gates (CTX-0015): client-only by
  construction with `server` fail-closed (`#26`), `quic` as a
  direction-not-contract marker (`#27`), the `proxy` gate meaning
  environment-proxy inheritance with explicit proxies always-on (`#29`),
  BN-6 bridge move criteria and shape with embedded as the only backend
  (`#30`), and oauth deferral with the bitty-ai owners (`#28`).
- Direction decision for PAC evaluation (`#24`): explicit unsupported with
  no platform lookup and no embedded JavaScript, and explicit proxy
  precedence. The refusal is currently silent, so the posture is not fail
  closed; fail-closed behavior is a pre-adoption requirement, not a
  current control.
- Shared bounded DNS answer cache in the `dns` module (`bitty-network#23`),
  with `DnsCache`, the process-wide `dns::shared()` instance, and
  `dns::resolve_shared()` as the adoption point for a dial path. Positive and
  negative entries, at most `DNS_CACHE_MAX_ENTRIES` (128) held, positive
  entries servable for `DNS_CACHE_TTL` (30s) and negative ones for the
  shorter `DNS_NEGATIVE_CACHE_TTL` (5s). The cache sits below the capability
  check and is keyed on exactly the authorized `(normalized host, port)`
  query, so an answer is never shared across two queries the allowlist
  treats as different. Reuse never extends a deadline: an entry's expiry is
  capped by the absolute deadline of the lookup that produced it, a probe
  whose own caller deadline has already passed misses instead of serving,
  and only the caller that received an answer inside its own deadline writes
  one — never the detached worker whose late answer arrives after that
  deadline was abandoned. A recorded refusal is distinguishable from an
  absence, a timeout or cancellation is never stored, and an empty answer is
  recorded as the negative it is. No backend is wired to it yet: the
  WebSocket dial path still carries its own resolver and permit pool, and
  the HTTP backend resolves inside reqwest (whose pinned
  `ClientBuilder::dns_resolver` is the adoption hook). Both wirings are
  changes in files this lane does not own, so the cache's bounds and
  authority rules are what this change delivers, not a dialed answer.
  `bitty-network#23` therefore stays open on this change: the criterion it
  leads with, "used by every backend", is unmet, and the work is split —
  the cache and its seam land here, while each of the two adopters needs its
  own task in the `http` and `websocket` lanes.
- Documented the key obligation each DNS cache adopter inherits, because it is
  not derivable from the hook: reqwest's override point is
  `Resolve::resolve(&self, name: Name)`, and `Name` is a bare host with no
  port and no way to attach one, so the port half of the cache key cannot be
  obtained from the resolver hook at all (nor from the ports of the returned
  addresses, which an explicit URL port overrides). An adopter must key the
  cache on exactly the pair the capability check authorized — the check's own
  host string, and the port taken from the request — because a host-only key
  is _coarser_ than the allowlist's per-host port set and would serve one
  port's answer to another port's authorized query, the cross-query reuse
  this cache otherwise rules out. The observable half is now pinned against
  the real `bitty_network_api::NetworkCapability` as an independent oracle:
  the cache's key granularity and the allowlist's decision granularity are
  asserted to be the same relation, so a coarsened key would contradict the
  allowlist and fail. The remaining half — whether a future adapter hands
  over the right string — is not observable until that adapter exists and is
  a wiring-time review obligation.
- Unified TLS provider for HTTP and WebSocket (CTX-0021, `#21`/`#22`), behind
  the `http` feature, in `tls` and its new `tls::x509` reader:
  - A caller-supplied CA bundle is **additive**. It adds validated anchors to
    the platform's native root store and never replaces, shadows, or disables
    a native root, and a platform store that cannot be loaded fails closed
    rather than falling back to custom-only trust. **Supplying a bundle does
    not restrict native trust** — there is no custom-only mode.
  - Bundle sources are mutually exclusive (an explicit path or inline PEM, never
    a URL), read and parsed once at construction, never discovered from the
    environment or a default location, and one bad entry fails the whole load:
    no partial trust set.
  - An admitted anchor must carry `basicConstraints` `CA=TRUE` and, when
    `keyUsage` is present, `keyCertSign`; use an admitted signature algorithm
    and public-key algorithm and key size; and parse its subject and issuer.
    Validity is `notBefore <= now < notAfter` with no grace period, checked at
    construction and again before every new TLS destination. Path building,
    path length, and name constraints stay with `rustls`/`rustls-webpki`.
  - Client identity is off by default, indivisible (chain _and_ key), and
    selected per new TLS destination by exact canonical host after IDNA
    normalization — no wildcard, no suffix, no default, reselected on redirect,
    never selected by the proxy authority, and never reused across hosts because
    each identity gets its own client and pool. A rule never waives the name,
    chain, validity, or key-use checks, and an unusable identity is a typed
    failure rather than a silent "no client certificate".
  - New policy vocabulary in `bitty-network-api`: `TlsConfig`, `PemSource`,
    `ClientIdentity`, `ClientIdentityRule`, the `TlsFailure` taxonomy, and
    `NetworkError::Tls`. The crate stays dependency-free and the vocabulary
    still moves no byte.
  - No new crate enters the shipped dependency graph: `rustls`,
    `rustls-platform-verifier`, `rustls-pki-types`, `idna`, and `zeroize` were
    already resolved through the reqwest and tungstenite trees and become
    direct dependencies here; X.509 attribute parsing is a self-contained strict
    DER reader rather than a new parsing dependency. `rcgen` is a dev-dependency
    only, so tests mint their CA and keys at runtime and no certificate or key
    fixture is committed.
- Inspector feed decision (`#31`, CTX-0023): the audit-entry vocabulary keyed
  per plugin per host, the host-implemented sink seam, a synchronous emit point
  with no queue in this crate, and a fail-closed rule that refuses the exchange
  whose entry cannot be recorded. Docs only; the issue stays open and no
  vocabulary, sink, emitter, or bound is implemented.

### Changed

- Toolchain parity with the `bitty` gates: MSRV 1.85, OS matrix, `cargo-deny`
  audit, and pinned tooling (`just check`, `scripts/rust-channel.sh`).
- Single-feature fail-closed CI matrix (`client`/`server`/`quic`/`proxy`/
  `oauth`): each feature is verified in isolation so unowned direction
  decisions cannot silently enable surface.
- CTX-0034 applies the `proxy` feature gate to `HttpNetworkService::new`:
  without the feature the service reads no proxy variable at all
  (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`, in either
  casing), so egress is direct-only and an ambient proxy cannot be
  inherited; with the feature, current behavior is unchanged. Explicit
  `with_proxy` construction is never gated. The unconditional
  reqwest controls (`.no_proxy()` and `Policy::none()` on every client, and
  credential-bearing proxy URLs rejected) come from CTX-0028 and are
  unaffected by this feature.
- Pinned the `idna_adapter` and ICU tree to 1.85-compatible versions.
- CTX-0021 makes the HTTP backend hold one client per TLS identity slot instead
  of one client per egress route, so a client-identity policy can be expressed
  at all. The egress controls are unchanged and now have a single
  implementation: every client still carries `.no_proxy()` and `Policy::none()`
  before anything else is injected, credential-bearing proxy URLs are still
  rejected before a client is built, and the client constructors the decision
  record cites by signature still exist and are still reached.
- CTX-0021 pins `time` to an MSRV-1.85-compatible release, as a dev-dependency
  of the test-only certificate generation, and records one narrowly justified
  advisory exception in `deny.toml` for it (dev-only, unreachable RFC 2822
  parser, and the fix needs rustc 1.88).
- CTX-0021 resolves three defects found reviewing the inherited
  implementation. An explicit proxy is no longer dropped when a TLS policy is
  configured: the per-identity client applies every configured proxy scope
  instead of collapsing the route to a single all-scope URL, which had sent
  proxied traffic direct. A plaintext `ws://` handshake no longer evaluates the
  TLS policy, so an anchor that has expired since construction cannot refuse a
  connection that reads no trust anchor. An inline key source is parsed in
  place rather than copied into a second heap buffer.
- CTX-0021 round two. The branch is rebased onto `origin/main` (`7c6fdd3`); the
  previous head was cut from `5d98440`, so its diff against `main` read as a
  revert of the PAC decision and its pins, and `decision_citations` and
  `proxy_credential_policy` were red on the stale base. Both are green from
  `main`'s own fix; neither was changed here.
- CTX-0021 round two repairs the PAC pin suite, which CTX-0021 itself broke by
  introducing `src/tls/` as a module directory beside `src/tls.rs`. The crate
  source enumerator read one level deep and asserted every entry was a `.rs`
  file, so the new directory failed the layout assertion and six of the eight
  pins went red. The walk is now recursive and holds every entry to the same
  rule, so a module directory cannot become a way to hide a source file from the
  scan. The two ordering pins and the injection-site list are updated for the
  per-identity client, which is where proxy injection and the credential check
  now live; each is pinned more strictly than before, and none is relaxed. No
  egress control changed: every client still carries `.no_proxy()` and
  `Policy::none()`, `Client::new()` and `unwrap_or_else` remain banned, and
  `client_with_tls` still checks for userinfo immediately before each
  `builder.proxy(...)`.
- CTX-0021 round two closes three coverage gaps found in review and records two
  honest negatives. `is_exact_identity_host` had no test, so a body of `true`
  produced no red; it is now covered clause by clause. The empty-`basicConstraints`
  and too-short-`keyUsage` arms of the X.509 reader are now exercised, as is
  every level of the three-deep `Name` walk. A missing client in an identity slot
  is now reported as `NetworkError::Offline` rather than a client-identity
  failure, because the slot is empty when the service holds no client and no
  identity is at fault. The deny-all fallback in `HttpNetworkService::new` now
  records that it was taken, so a fail-closed service is distinguishable from one
  built during an outage.
- CTX-0021 round two **withdraws** an earlier claim. Two overlapping layers
  enforce that a client-identity rule host is an exact DNS name — a structural
  check and IDNA — and the report asserted that removing both turned four pins
  red. Measured, it does not: the suite stays green with both removed. IDNA is
  the stronger layer and the guarantee rests on it. The record now says so, and
  the X.509 `keyUsage` length guard is likewise recorded as provably redundant
  with the DER padding check rather than as pinned coverage.

### Security

- The DNS cache is a new place where a resolved address is reused, so its
  authority properties are pinned rather than assumed (`bitty-network#23`): a
  cached answer is only reachable by a caller that already passed the
  capability check for that same query, the key is never coarser than the
  allowlist's `(host, port)` equivalence class, and reuse cannot turn an
  expired deadline or a cancelled call into a free answer. The entry-count
  bound keeps a shared cache from being a memory-growth vector reachable by
  anyone who can make the host resolve names.
- CTX-0028 closes the third-round WebSocket deadline and proxy-safety gaps:
  receive operations install one temporary read/write deadline for automatic
  control replies, DNS uses bounded elastic permits so caller deadlines return
  while timed-out OS lookups release permits when the OS returns (exhaustion
  surfaces `NetworkError::Timeout`), and every reqwest client disables ambient
  system-proxy discovery. Standard proxy environment variables are checked
  explicitly; credentialed values are rejected before a reqwest client or
  retained proxy state is built and never reach service errors, process output,
  or `Debug`.
- CTX-0029 pins scheme-specific proxy precedence over `ALL_PROXY` and counts
  each fragmented WebSocket message at its first data frame. Child-process
  waits remain bounded, secret scanning precedes success assertions, and DNS
  saturation reports a typed timeout at the full permit capacity.
- CTX-0041 makes the documented redirect deadline real: a followed hop chain
  now shares one effective per-request deadline instead of resetting the
  timeout per hop, so slow hops cannot multiply the caller's budget. A
  source-level regression test pins `.no_proxy()` on every reqwest client
  (inert while the pinned reqwest omits `system-proxy`), and
  `Request::max_body_bytes` no longer documents `None` as "no cap".
- Capability-first enforcement is the trust boundary: no ambient network
  access exists anywhere in the crate graph; the default `bitty` binary stays
  network-free and this runtime enters only when a network-capable consumer
  is installed.
- CTX-0021 adds no trust surface by default: with no `TlsConfig` the backends
  keep their own native-root construction untouched, and a supplied bundle
  cannot narrow what is trusted. Private keys, inline key bytes, and
  credential-bearing paths never reach `Debug`, `Display`, an error string, or
  a serialization surface; the key-bearing types use hand-written redacting
  `Debug` and hand-written zeroing drops, and the crate takes no `serde`
  dependency at all, so no configuration, snapshot, IPC, or test-artifact
  representation exists that could carry key material. A canary test proves it
  against a key generated at runtime.
- CTX-0021 revocation policy is unchanged and is the one requirement the record
  defers to review rather than to code: chain verification is `rustls-webpki`'s
  and performs no revocation checking, exactly as the pinned base did. Making
  revocation mandatory is a new decision with its own compatibility impact, not
  something this change could add quietly.
- CTX-0021 does not rely on `rustls-platform-verifier` to fail closed. In 0.7.0
  `new_with_extra_roots` adds the supplied roots to the store _before_ reading
  the platform store and refuses only an empty store, so a platform store that
  yields nothing would leave a verifier trusting exactly the supplied
  certificates — the custom-only mode the decision record does not define. The
  provider therefore proves the native load with an independent extra-root-free
  read and refuses with `TlsFailure::NativeRootsUnavailable`. The probe runs
  only when custom roots are supplied, which is the only case where the store is
  non-empty beforehand.
- CTX-0021 records one limit it cannot close from here: `rustls` 0.23.45
  zeroizes its record buffers, ciphers, and HMACs, but does not wipe a client's
  signing key when a configuration is dropped. The provider keeps no second copy
  of a key — an inline source is parsed in place and a path read is zeroized on
  the way out — and the remaining copy is owned by the pinned crypto provider.
  Tightening it would mean replacing that provider, which is a new decision.
