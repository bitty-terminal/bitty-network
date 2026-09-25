# #24: proxy PAC evaluation — explicit unsupported, fail closed

Status: decided, docs only — no PAC evaluation in this slice (CTX-0032).

Parent: #15 (BN-2 policy depth slice).

Builds on: #29 (`docs/decisions/29-proxy.md`) — the intended `proxy`
feature meaning is environment-inheritance opt-in. On `origin/main` the
policy predicate exists, but `HttpNetworkService::new` wiring is still
pending (CTX-0034). This record adds the PAC posture and the tier order
below; it does not change what the gate is intended to mean.

## Decision

bitty-network's own routing code **never evaluates PAC** and never
intentionally reads platform system proxy configuration. The system/PAC
tier of the precedence is refused, not emulated. The intended
repository-owned selection uses the two sources below, but reqwest's
automatic environment matcher is still active on `origin/main` and is
not covered by that intended contract. Every selected URL must pass one
credential check before a client is built. That check is not present on
`origin/main`; the completed CTX-0028 implementation is still unmerged,
so this record treats it as a pending arrival rather than a current
control.

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
intended `proxy` gate treats as opt-in: a machine setting silently
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

| Tier | Source                      | State                              |
| ---- | --------------------------- | ---------------------------------- |
| 1    | Explicit `with_proxy` URL   | Available today; validation target |
| 2    | Environment proxy variables | Target; gate not wired             |
| 3    | System settings / PAC file  | Refused, not implemented           |

**Tier 1 — explicit override (available today; full validation is a
target).** `with_proxy` selects one explicit proxy URL and stays
available with or without the `proxy` feature: explicit construction is
a deliberate operator act, not ambient authority (#29). The complete
userinfo rejection and one-injection-point contract below is a target
until the explicit URL is validated before client construction; it is
not a current guarantee.

**Tier 2 — environment (target; not gated on `origin/main`).** The
current explicit reader reads `HTTPS_PROXY` first, then `https_proxy`,
and joins `NO_PROXY` and `no_proxy` as its bypass list. It has no
`HTTP_PROXY`/`ALL_PROXY` fan-out and no per-variable credential check.
`HttpNetworkService::new` reads this environment unconditionally, and
`env_proxy_enabled()` has no non-test caller. With the `proxy` feature
off, the environment is still inherited: this is the unsafe current
direction, not fail-closed behavior. CTX-0034 must wire the predicate
before this record can describe the gate as operative. The fan-out and
credential check are separate pending implementation work; completed
CTX-0028 work is not present on this baseline and cannot be treated as
a landed control.

**Tier 3 — system/PAC (refused, not implemented).** No platform
lookup, no PAC file read, no PAC evaluation, on any platform. A
`pac:` URL or a platform proxy setting is therefore never a usable
answer and is never inherited as a PAC route, even with the `proxy`
gate on. This refusal is separate from the pending gate wiring and
from reqwest's automatic environment matcher described below.

Refusal is total, and therefore silent today: with no system/PAC
tier, an operator whose machine is configured for a PAC sees exactly
the behavior of no proxy configuration at all. That is an explicit
unresolved risk, not an approved transparent fallback. The operator may
send direct traffic that bypasses a mandatory egress path such as
egress filtering, DLP, TLS inspection, or geo and compliance controls,
with no error, warning, or log. No user-visible signal exists today.
Before any future PAC adoption, the implementation must provide a
startup diagnostic or documented user-visible signal whenever a
configured or observable PAC/system setting is refused; without that
mitigation, adoption is blocked. This requirement does not relax the
fail-closed rule for an unevaluable PAC.

## Fail-closed on unevaluable input

A PAC we cannot evaluate must not become a direct-egress fallback.
Failing open is the specific failure this record forbids: the
operator's configuration asked for proxied egress, and silently
sending direct traffic misrepresents what the process did.

The table is a future diagnostic contract, not current behavior —
bitty-network has no system/PAC tier to fail in today. A future ambient
source must end at the same terminal state, `NetworkError::Offline`, on
every request through the service. The reason column is a future
diagnostic value: `NetworkError::Offline` is currently a unit variant
with the constant display text `network offline`, and it is already a
catch-all for capability denial, malformed headers, an unparseable
proxy URL, and non-timeout transport failures. It cannot by itself
make these four cases distinguishable.

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
  explicit proxy does today — never a silent direct send, never a
  hang, never a retry loop.
- A future diagnostic channel must name the reason from the table and
  the kind of source it came from, so an operator can tell "my PAC is
  broken" from "my PAC was refused by design". The reason is not a new
  public error variant, and no such variant is authorized here.
- **Open point — diagnostic carrier:** the current four-variant public
  taxonomy and unit `NetworkError::Offline` cannot carry four distinct
  reasons. A separate API decision must choose a compatible carrier
  outside that taxonomy, or explicitly amend the taxonomy in a scoped
  task. Until that decision lands, four-way distinguishability is
  unresolved and no implementation may claim that `NetworkError::Offline`
  provides it.
- No URL, path, or file content from a PAC source is retained or
  logged. A PAC URL can carry userinfo, so the rule that keeps
  credential-bearing proxy URLs out of logs applies to every string
  read from that source.
- Construction must remain `Result`-shaped on the existing split once
  a source is implemented: an explicitly requested unevaluable source
  returns the typed error to the caller, while an ambient source
  degrades the service to fail-closed for every request. The current
  `new` constructor is not `Result`-shaped, so this is a target
  contract, not a claim about today's API.

**A future evaluable `DIRECT` result requires an authority decision.**
A PAC that evaluates cleanly to `DIRECT` would be an answer, not an
unevaluable case, but it is not an unconditional closure. It could be
honored only when tiers 1 and 2 yielded nothing; an ambient PAC result
must not silently override explicit or environment proxy authority.
The capability check still runs first, so a `DIRECT` result cannot widen
reachability past the granted policy. That check limits reachability,
not authority, and therefore does not settle whether an ambient PAC may
override a configured proxy. This is an open decision for any future
slice; no implementation may resolve it by assumption. Under the
default deny-all capability nothing is sent at all.

**PAC and credentials are orthogonal.** A PAC naming a proxy that
requires authentication must be rejected by the same userinfo check
required for the explicit and environment paths, before any client is
built. That check is a pending requirement on `origin/main`, not a
current guarantee. A PAC is never a credential source: nothing it
returns satisfies a proxy challenge, and credential storage and
rotation stay out of scope here (CTX-0033). A challenge a proxy raises
anyway is an ordinary transport failure and surfaces as
`NetworkError::Offline`.

## `no_proxy()` interaction

Ambient discovery must stay off, but it is not off on `origin/main`.

**Current origin/main baseline.** `origin/main` contains no
`.no_proxy()` call in `crates/`; those calls exist only in the unmerged
CTX-0028 work. `HttpNetworkService::client_with` therefore builds
clients with reqwest's default `auto_sys_proxy = true`. In reqwest
0.13.5, `ClientBuilder::build` pushes `ProxyMatcher::system()` whenever
that flag is true, and hyper-util 0.1.20's `Builder::from_system()` calls
`from_env()` unconditionally; its `client-proxy-system` feature gates
only macOS and Windows platform lookups. Consequently, on `origin/main`,
reqwest can silently inherit `ALL_PROXY`, `HTTP_PROXY`, and `HTTPS_PROXY`
(including their lowercase forms) and honor `NO_PROXY`/`no_proxy`,
with no credential check in this crate. The absent `system-proxy`
feature does not disable environment inheritance. This
record must not claim that exposure is closed.

Rules for any future system/PAC work:

- **One injection point.** Every proxy URL, whatever its source, must
  pass through one shared validation function: reject userinfo, then
  parse, then build the `reqwest::Proxy`. A PAC evaluator produces a URL
  and hands it to that function. It gets no second path, and never
  builds a client first to validate later. That function and its
  credential check are pending on `origin/main`, not a current control.
- **Discovery stays off.** Every client builder in a landed
  implementation must call `.no_proxy()` before adding a selected route.
  This is a target requirement, not a description of the current
  baseline. Reading a PAC file is reading a file; letting reqwest
  discover a platform proxy is a different, unvalidated route. Only the
  PAC source is ever revisited; platform discovery remains refused.
- **The gate is not the control.** `.no_proxy()` and the credential
  check are separate controls. The `proxy` feature decides whether tier
  2 is consulted at all; it is never a reason to re-enable discovery.
  CTX-0034's gate wiring is related, but it does not by itself add the
  credential check; `.no_proxy()` remains a separate required control.
- **Regression guard.** A PAC slice ships tests pinning that ambient
  environment and platform configuration cannot influence the selected
  client, and a review that finds discovery re-enabled returns a
  security defect, not a feature request.

## What this record does not authorize

No PAC code, no platform lookup, no new dependency, and no implementation
of the pending tier-2 gate, `.no_proxy()` call, or credential check.
Issue #24 stays open: this is its decision half only, and the
implementation half (fixture-proxied precedence tests for tiers 1 and 2)
is a separate scoped task.

Revisit criteria, all required before a PAC slice may start:

1. `deny.toml` approval for the proposed engine, with an MSRV-1.85
   and `#![forbid(unsafe_code)]` analysis of its tree.
2. A security-corpus review of executing an ambient, operator-supplied
   program on every connection decision.
3. A separate API decision resolving the diagnostic carrier for the
   four PAC failure reasons without silently changing the pinned
   four-variant public taxonomy.
4. Recorded decisions for the authority of a future `DIRECT` result
   and for PAC sources of authentication. Neither is resolved above;
   no PAC path exists today.
5. A startup diagnostic or documented user-visible signal for a
   configured or observable PAC/system setting that is refused, so the
   direct-egress bypass hazard is not silent.
6. The one-injection-point and regression-guard rules above built into
   the slice's acceptance, not left to review.

## Acceptance

- `just check`, `just check-http`, `just check-websocket`, and
  `just typecheck` pass: this record changes no code, so the gates
  confirm nothing else moved.
- `gitleaks detect --source .` clean.
