# #24: proxy PAC evaluation — explicit unsupported, fail closed

Status: decided, docs only — no PAC evaluation in this slice (CTX-0032).

Parent: #15 (BN-2 policy depth slice).

Builds on: #29 (`docs/decisions/29-proxy.md`) — the `proxy` feature is
the environment-inheritance opt-in. This record adds the PAC posture
and the tier order below; it does not change what the gate means.

## Decision

bitty-network **never evaluates PAC** and never reads platform system
proxy configuration. The system/PAC tier of the precedence is refused,
not emulated: proxy selection is decided only by our own code, from
the two sources below, and every selected URL passes the same
credential check before a client is built.

This is the explicit unsupported-fail-closed candidate, chosen over
embedded JavaScript evaluation and over platform lookup.

## Why not the alternatives

**Embedded JavaScript evaluation (rejected).** A PAC file is a
program, so evaluation needs a JavaScript engine. None is approved in
`deny.toml`, every candidate is a new dependency tree needing approval
with an MSRV-1.85 and `#![forbid(unsafe_code)]` analysis of its own,
and the ones that could plausibly clear that bar carry a JIT or FFI
core whose unsafe surface we would be taking on wholesale. It also
widens the trust boundary on a security-relevant path: the evaluated
program comes from an ambient operator file and runs on every
connection decision, so an engine bug becomes a routing bug.

**Platform lookup (rejected).** Reading macOS SystemConfiguration, the
Windows registry, or GNOME/KDE settings means FFI into system
libraries — `unsafe` code in crates that forbid it — plus per-platform
parsing that the CI matrix cannot prove, since each OS leg behaves
differently and the unrun platforms are exactly where the ambient
settings live. It also resolves to the same ambient authority the
`proxy` gate already treats as opt-in: a machine setting silently
rerouting egress is the failure mode #29 was written to keep out of
the default.

**A recognized PAC subset (rejected, named for the record).**
Evaluating only the patterns we support is worse than not evaluating:
the result is silently wrong on exactly the requests the operator
expected PAC to route differently, and a wrong proxy decision is a
security decision made badly. Unsupported is honest; a subset is not.

## Precedence

Tiers are consulted in order; the first tier that yields a usable
answer wins, and no lower tier overrides a higher one.

| Tier | Source                      | State                    |
| ---- | --------------------------- | ------------------------ |
| 1    | Explicit `with_proxy` URL   | Implemented today        |
| 2    | Environment proxy variables | Implemented today        |
| 3    | System settings / PAC file  | Refused, not implemented |

**Tier 1 — explicit override (implemented).** `with_proxy` pins one
proxy URL and ignores the environment entirely. It stays available
with or without the `proxy` feature: explicit construction is a
deliberate operator act, not ambient authority (#29).

**Tier 2 — environment (implemented).** The standard proxy variables
plus `NO_PROXY`/`no_proxy` as the bypass list. Scheme-specific names
beat the generic fallback, uppercase names beat lowercase, and a
bypassed host takes the direct client. Whether this tier is consulted
at all is the `proxy` feature (#29): with the gate off the environment
is ignored and egress is direct-only.

On the branch this record is written from (`origin/main`), tier 2
reads `HTTPS_PROXY` and `NO_PROXY`. The `HTTP_PROXY`/`ALL_PROXY`
fan-out and the per-variable credential check land with the sibling
lane (CTX-0028) described under the `no_proxy()` interaction below;
this record neither restates nor pre-empts that lane's code.

**Tier 3 — system/PAC (refused, not implemented).** No platform
lookup, no PAC file read, no PAC evaluation, on any platform. A
`pac:` URL or a platform proxy setting is therefore never a usable
answer and is never inherited, even with the `proxy` gate on: the
gate governs environment inheritance, and tier 3 is refused outright.

Refusal is total, and therefore silent today: with no system/PAC
tier, an operator whose machine is configured for a PAC sees exactly
the behavior of no proxy configuration at all. That is the honest
consequence of never reading the file, and it is why any future
adoption has to carry the reason codes below instead of inheriting
this silence.

## Fail-closed on unevaluable input

A PAC we cannot evaluate must not become a direct-egress fallback.
Failing open is the specific failure this record forbids: the
operator's configuration asked for proxied egress, and silently
sending direct traffic misrepresents what the process did.

The table is the contract any future system/PAC work must meet, not
current behavior — bitty-network has no system/PAC tier to fail in
today. Every case ends at the same terminal state,
`NetworkError::Offline` on every request through the service, while
staying distinguishable from the outside by its reported reason:

| Case                           | Reason reported   |
| ------------------------------ | ----------------- |
| PAC file unreadable            | `unreadable`      |
| PAC file unparseable           | `unparseable`     |
| PAC returns no usable proxy    | `no-proxy`        |
| PAC names a proxy needing auth | `unauthenticated` |

The authenticating case additionally never retains the URL it came
from, and the first three never get far enough to yield a route.

The requirements behind that table:

- The request fails closed as a typed error, exactly as an unusable
  configured proxy does today — never a silent direct send, never a
  hang, never a retry loop.
- The failure names the reason from the table above and the kind of
  source it came from, so an operator can tell "my PAC is broken"
  from "my PAC was refused by design". Both surface the same
  `NetworkError` variant: the reason is the diagnostic, not a new
  public error type.
- No URL, path, or file content from a PAC source is retained or
  logged. A PAC URL can carry userinfo, so the rule that keeps
  credential-bearing proxy URLs out of logs applies to every string
  read from that source.
- Construction stays `Result`-shaped on the existing split: an
  explicitly requested unevaluable source returns the typed error to
  the caller, while an ambient source degrades the service to
  fail-closed for every request — the same split `with_proxy` and
  `new` already have.

**One evaluable result is not a failure.** A PAC that evaluates
cleanly to `DIRECT` is an answer, not an unevaluable case, and it is
honored as a direct-egress decision — but only when tiers 1 and 2
yielded nothing, since precedence means a PAC never overrides an
explicit or environment proxy. The capability check still runs first,
so an ambient `DIRECT` cannot widen reachability past the granted
policy; under the default deny-all capability nothing is sent at all.

**PAC and credentials are orthogonal.** A PAC naming a proxy that
requires authentication is rejected by the same userinfo check that
guards tiers 1 and 2, before any client is built. A PAC is never a
credential source: nothing it returns satisfies a proxy challenge, and
credential storage and rotation stay out of scope here (CTX-0033). A
challenge a proxy raises anyway is an ordinary transport failure and
surfaces as `NetworkError::Offline`.

## `no_proxy()` interaction

Ambient discovery stays off, and PAC must not switch it back on.

CTX-0028 disabled reqwest's ambient system-proxy discovery by calling
`.no_proxy()` on every client this crate builds, alongside pinning
reqwest with `default-features = false` — so `system-proxy` and the
platform discovery behind it are absent from the resolved feature
graph entirely, not merely unused. The fix exists because ambient
discovery is an unvalidated path: an ambient credentialed
`HTTP_PROXY`, or a platform setting, could otherwise be used without
ever passing the credential check — the one control keeping proxy
credentials out of this process. PAC adoption would reopen that hole
through a different door.

Rules for any future system/PAC work:

- **One injection point.** Every proxy URL, whatever its source, is
  validated by the same function that validates `with_proxy` and the
  environment today: reject userinfo, then parse, then build the
  `reqwest::Proxy`. A PAC evaluator produces a URL and hands it to
  that function. It gets no second path, and never builds a client
  first to validate later.
- **Discovery stays off.** The client builder keeps `.no_proxy()`.
  Reading a PAC file is reading a file; letting reqwest discover a
  platform proxy is a different, unvalidated route. Only the first is
  ever revisited.
- **The gate is not the control.** `no_proxy()` and the credential
  check are the control. The `proxy` feature decides whether tier 2 is
  consulted at all; it is never a reason to re-enable discovery.
- **Regression guard.** A PAC slice ships a test pinning that ambient
  platform configuration cannot influence the selected client, and a
  review that finds discovery re-enabled returns a security defect,
  not a feature request.

## What this record does not authorize

No PAC code, no platform lookup, no new dependency, no change to
`no_proxy()` or to the credential check. Issue #24 stays open: this is
its decision half only, and the implementation half (fixture-proxied
precedence tests for tiers 1 and 2) is a separate scoped task.

Revisit criteria, all required before a PAC slice may start:

1. `deny.toml` approval for the proposed engine, with an MSRV-1.85
   and `#![forbid(unsafe_code)]` analysis of its tree.
2. A security-corpus review of executing an ambient, operator-supplied
   program on every connection decision.
3. Recorded decisions for the `DIRECT` result and for PAC sources of
   authentication, both resolved above as unreachable today.
4. The one-injection-point and regression-guard rules above built
   into the slice's acceptance, not left to review.

## Acceptance

- `just check`, `just check-http`, `just check-websocket` pass: this
  record changes no code, so the gates confirm nothing else moved.
- `gitleaks detect --source .` clean.
