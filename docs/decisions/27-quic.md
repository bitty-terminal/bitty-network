# #27: quic transport — direction, not contract

Status: decided (CTX-0015, lane D).

Parent: #16 (future backends umbrella).

## Decision

Keep the `quic` gate with an explicit direction-not-contract statement
(written below), instead of removing it.

## Why keep rather than remove

Removal was the alternative. Keeping wins on balance:

- The name `quic` is already referenced by the `transport::Quic` marker docs
  and the CI feature matrix; removal churns both for zero behavior change.
- A reserved, fail-closed gate keeps the matrix proving the negative (the
  gate enables nothing) on every run, instead of losing that coverage.
- Reserving the name prevents a future transport from grabbing an
  inconsistent feature name.

Keeping costs one line in `Cargo.toml` and one matrix leg; removal would
cost doc/CI edits across files this lane does not own.

## Direction-not-contract statement

`quic` names a possible future direction. It promises no transport, no
dependency, no API, and no selection behavior. A real QUIC transport
arrives only with all of the following:

1. Supply-chain approval in `deny.toml` (no new network dependency until a
   scoped task authorizes it).
2. An MSRV-1.85-compatible crate pick.
3. The same capability-first enforcement as the existing backends
   (check-then-send, typed denials, fail-closed errors).
4. Acceptance tests at least as strong as the `http`/`websocket` suites.

## Gate posture

- `quic = []` remains: no code keys off it; the CI matrix leg plus the
  offline fail-closed test pin the no-op.
- `transport::Quic` stays a marker (no sockets).
