# `bitty-network`

> Part of the `bitty` workspace. Canonical product and architecture
> documentation lives in `bitty-terminal-docs` (mounted at `docs/`) and
> shared governance in `bitty-docs`; this file is a crate-local map, not a
> canonical contract.

## Purpose

`bitty-network` is the implementation behind `bitty-network-api`: an
embedded offline `NetworkService` (`offline`, capability-first and
fail-closed), real HTTP and WebSocket transports (`http` and `websocket`,
behind the default-off features of the same names), plus a module skeleton
(`runtime`, `transport`, `protocol`, `tls`, `dns`, `policy`) holding marker
types only (see the sealing note in `src/lib.rs`).

## Embedded-first, networkd-later

The terminal stays embedded-first: no network daemon today, no background
tasks, no ambient connectivity. A `networkd` out-of-process owner may arrive
later; until then every consumer starts offline, and only the default-off
`http`/`websocket` features move bytes (via `src/http.rs` and
`src/websocket.rs`). Its only dependencies are
the path-local `bitty-network-api` vocabulary plus, behind the features, the
pinned reqwest and tungstenite trees (see `deny.toml` for the supply-chain approval).

## API-stable promise

Transports evolve here, behind `NetworkService`. The vocabulary in
`bitty-network-api` stays stable: additive changes only, no renames and no
signature breaks without a dedicated task and a migration note. Consumers
depend on `-api` only and reach this crate via IPC or service lookup —
never as a direct dependency.

## Features

All default-off. `http` carries the reqwest tree (`=0.13.5`, exact pin in
`Cargo.toml`, approval in `deny.toml`); `websocket` carries the tungstenite
tree (`=0.30.0`, same pinning) and implies `http`:

- `client`, `server` — initiator/listener roles (`client` resolves to the
  offline backend; `server` stays fail-closed).
- `http`, `websocket` — protocol wire code (`http` enables the real
  `HttpNetworkService` and keeps the offline resolution alongside it;
  `websocket` enables the capability-gated handshake on that same backend,
  returning an open `WebSocketSocket`).
- `quic` — QUIC transport (fail-closed).
- `proxy`, `oauth` — egress policy and credential flows (fail-closed).

## Boundaries

- Dependencies: `bitty-network-api` via path everywhere; the reqwest and
  tungstenite trees only behind the default-off `http`/`websocket` features
  (`std` otherwise).
- No I/O, no sockets, no background tasks outside `src/http.rs` and
  `src/websocket.rs` (gated).
- Zero `unsafe`, per the workspace lint and `src/lib.rs`.

## Layout

- `Cargo.toml` — package metadata, path dependency on `-api`, empty
  default-off features.
- `src/lib.rs` — backend docs plus `-api` re-exports.
- `src/offline.rs` — embedded offline `NetworkService` (`OfflineNetworkService`,
  `OfflineSocket`); capability checked first, everything else fail-closed.
- `src/http.rs` — shared-client HTTP backend (`HttpNetworkService`,
  capability-first, proxy from the environment, per-request timeouts).
- `src/websocket.rs` — capability-gated WebSocket handshake over tungstenite
  (`WebSocketSocket`, `WsMessage`); proxy decision reused from the HTTP
  backend, rustls native roots, fail-closed timeouts.
- `tests/http.rs` — HTTP acceptance tests (round-trip, proxy, timeout,
  denial, fail-closed WebSocket without the feature).
- `tests/websocket.rs` — WebSocket acceptance tests, loopback-only
  (connect/echo, denial, proxy tunnel, timeout, close).
- `tests/offline.rs` — acceptance tests (deny-all, allowlist hit/miss,
  offline response, feature-gate presence).
- `src/runtime.rs` — executor-ownership marker.
- `src/transport.rs` — TCP/UDP/QUIC markers.
- `src/protocol.rs` — HTTP/WS markers.
- `src/tls.rs` — TLS marker.
- `src/dns.rs` — resolver marker.
- `src/policy.rs` — capability/policy re-exports.
