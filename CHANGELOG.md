# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
  recorded as the negative it is. The HTTP backend still cannot share it
  (reqwest owns its resolver internals); the WebSocket dial path adopting
  the seam is a follow-up in the websocket lane.

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
