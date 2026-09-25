# #26: server feature — stay client-only by construction

Status: decided (CTX-0015, lane D).

Parent: #16 (future backends umbrella).

## Decision

Stay client-only by construction (BN-3). No listen path is added, and the
`server` Cargo feature stays as an accepted fail-closed no-op: it must
compile and must enable no I/O.

## Rationale

- Grants are egress-only today. `NetworkCapability` has no listen API, so a
  listen path can never be granted by construction — there is nothing a
  server socket could check itself against.
- Listening needs a separate capability verb and allowlist (bind host/port
  grants), plus UE- and security-corpus review. None of that is scoped here.
- No current consumer needs inbound connectivity; every named consumer (AI
  providers, weather/GitHub/mail plugins, remote panels) is an initiator.

## Gate posture

- `server = []` remains: no code keys off it, and the single-feature CI
  matrix leg (`--features server` + the offline fail-closed test) proves it
  stays a no-op.
- `OfflineNetworkService` remains the only resolution under the gate.

## Revisit criteria

A listen path may be proposed only with: a named consumer, a listen
capability verb in `bitty-network-api`, UE review, and security-corpus
sign-off. Until then this decision stands.
