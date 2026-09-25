# #30: Service Bridge / external bitty-networkd (BN-6)

Status: decided, docs only — no daemon code in this slice (CTX-0015,
lane D).

Parent: #16 (future backends umbrella).

## Decision

Embedded-first now; an external `bitty-networkd` later. Embedded stays
the only backend until the move criteria below all hold. This record
defines the criteria and the bridge shape so a future slice can build
the daemon without renegotiating them.

## Move criteria (all required)

1. **API-stability bar on the `NetworkService` boundary.** The
   `bitty-network-api` vocabulary changes additively only (no renames, no
   signature breaks without a dedicated migration task, per the crate
   promise). Consumers depend on `-api` only and reach the implementation
   via service lookup — never as a direct dependency — so the daemon can
   replace the embedded backend behind the same trait.
2. **Conformance suite passes unchanged.** The offline, HTTP, and
   WebSocket acceptance suites run green against a daemon-backed
   `NetworkService` with identical assertions (capability denials, error
   taxonomy, timeout and budget behavior).
3. **Capability handoff is check-identical.** Every request is checked
   against the handed grant before dispatch, with the same
   `Offline`/`Denied`/`Timeout`/`Budget` taxonomy the embedded backends
   produce today.

## Bridge shape

- **IPC transport:** a local-socket framed protocol (Unix-domain socket;
  exact framing is daemon-slice scope). No TCP loopback by default — the
  bridge must not widen reachability.
- **Capability handoff:** the host hands a serialized `NetworkCapability`
  snapshot per session (tighter: per call); the daemon re-checks every
  request against the handed grant and never widens it. The daemon holds
  no ambient authority of its own.
- **Failure semantics:** daemon absent or unreachable fails closed as
  `NetworkError::Offline` — the same error the offline backend yields
  today, so consumers cannot distinguish "no daemon" from "no network"
  and no caller needs new error handling.

## Non-goals of this slice

No daemon binary, no IPC code, no socket activation. Embedded
(`OfflineNetworkService`, plus `http`/`websocket` behind their features)
is the only backend.
