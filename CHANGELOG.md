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

### Changed

- Toolchain parity with the `bitty` gates: MSRV 1.85, OS matrix, `cargo-deny`
  audit, and pinned tooling (`just check`, `scripts/rust-channel.sh`).
- Single-feature fail-closed CI matrix (`client`/`server`/`quic`/`proxy`/
  `oauth`): each feature is verified in isolation so unowned direction
  decisions cannot silently enable surface.
- Pinned the `idna_adapter` and ICU tree to 1.85-compatible versions.

### Security

- CTX-0027 closes the second-round WebSocket deadline and proxy-safety gaps:
  receive operations now bound automatic control replies, DNS uses a bounded
  cancellable worker pool, and proxy credentials are rejected before service
  state is built or exposed through `Debug`.
- Capability-first enforcement is the trust boundary: no ambient network
  access exists anywhere in the crate graph; the default `bitty` binary stays
  network-free and this runtime enters only when a network-capable consumer
  is installed.
