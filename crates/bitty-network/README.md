# `bitty-network`

> Part of the `bitty` workspace. Canonical product and architecture
> documentation lives in `bitty-terminal-docs` (mounted at `docs/`) and
> shared governance in `bitty-docs`; this file is a crate-local map, not a
> canonical contract.

## Purpose

`bitty-network` is the implementation behind `bitty-network-api`: an
embedded offline `NetworkService` (`offline`, capability-first and
fail-closed) plus a module skeleton (`runtime`, `transport`, `protocol`,
`tls`, `dns`, `policy`) holding marker types only. Sockets arrive in a
follow-up task (see the sealing note in `src/lib.rs`).

## Embedded-first, networkd-later

The terminal stays embedded-first: no network daemon today, no background
tasks, no ambient connectivity. A `networkd` out-of-process owner may arrive
later; until then every consumer starts offline and this crate moves no
bytes. Its only dependency is the path-local `bitty-network-api` vocabulary.

## API-stable promise

Transports evolve here, behind `NetworkService`. The vocabulary in
`bitty-network-api` stays stable: additive changes only, no renames and no
signature breaks without a dedicated task and a migration note. Consumers
depend on `-api` only and reach this crate via IPC or service lookup —
never as a direct dependency.

## Features

All default-off, all empty (no new dependencies yet):

- `client`, `server` — initiator/listener roles (`client` resolves to the
  offline backend; `server` stays fail-closed).
- `http`, `websocket` — protocol wire code (`http` resolves to the offline
  backend; `websocket` stays fail-closed).
- `quic` — QUIC transport (fail-closed).
- `proxy`, `oauth` — egress policy and credential flows (fail-closed).

## Boundaries

- One dependency: `bitty-network-api` via path; `std` otherwise.
- No I/O, no sockets, no background tasks.
- Zero `unsafe`, per the workspace lint and `src/lib.rs`.

## Layout

- `Cargo.toml` — package metadata, path dependency on `-api`, empty
  default-off features.
- `src/lib.rs` — backend docs plus `-api` re-exports.
- `src/offline.rs` — embedded offline `NetworkService` (`OfflineNetworkService`,
  `OfflineSocket`); capability checked first, everything else fail-closed.
- `tests/offline.rs` — acceptance tests (deny-all, allowlist hit/miss,
  offline response, feature-gate presence).
- `src/runtime.rs` — executor-ownership marker.
- `src/transport.rs` — TCP/UDP/QUIC markers.
- `src/protocol.rs` — HTTP/WS markers.
- `src/tls.rs` — TLS marker.
- `src/dns.rs` — resolver marker.
- `src/policy.rs` — capability/policy re-exports.
