# `bitty-network`

> Part of the `bitty` workspace. Canonical product and architecture
> documentation lives in `bitty-terminal-docs` (mounted at `docs/`) and
> shared governance in `bitty-docs`; this file is a crate-local map, not a
> canonical contract.

## Purpose

`bitty-network` is the implementation behind `bitty-network-api`: an
embedded offline `NetworkService` (`offline`, capability-first and
fail-closed), a first real HTTP transport (`http`, behind the default-off
`http` feature), plus a module skeleton (`runtime`, `transport`, `protocol`,
`tls`, `dns`, `policy`) holding marker types only. Sockets beyond plain HTTP
arrive in a follow-up task (see the sealing note in `src/lib.rs`).

## Embedded-first, networkd-later

The terminal stays embedded-first: no network daemon today, no background
tasks, no ambient connectivity. A `networkd` out-of-process owner may arrive
later; until then every consumer starts offline, and only the default-off
`http` feature moves bytes (via `src/http.rs`). Its only dependencies are
the path-local `bitty-network-api` vocabulary plus, behind `http`, the
pinned reqwest tree (see `deny.toml` for the supply-chain approval).

## API-stable promise

Transports evolve here, behind `NetworkService`. The vocabulary in
`bitty-network-api` stays stable: additive changes only, no renames and no
signature breaks without a dedicated task and a migration note. Consumers
depend on `-api` only and reach this crate via IPC or service lookup —
never as a direct dependency.

## Features

All default-off. Only `http` carries dependencies (reqwest `=0.13.5`,
exact pin in `Cargo.toml`, approval in `deny.toml`):

- `client`, `server` — initiator/listener roles (`client` resolves to the
  offline backend; `server` stays fail-closed).
- `http`, `websocket` — protocol wire code (`http` enables the real
  `HttpNetworkService` and keeps the offline resolution alongside it;
  `websocket` stays fail-closed).
- `quic` — QUIC transport (fail-closed).
- `proxy`, `oauth` — egress policy and credential flows (fail-closed).

## Boundaries

- Dependencies: `bitty-network-api` via path everywhere; the reqwest tree
  only behind the default-off `http` feature (`std` otherwise).
- No I/O, no sockets, no background tasks outside `src/http.rs` (gated).
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
