# #24: proxy PAC evaluation — explicit unsupported, not fail closed while refusal is silent

Status: decided, docs only — explicit unsupported; current refusal is
silent, not fail closed (CTX-0032).

Parent: #15 (BN-2 policy depth slice).

Builds on: #29 (`docs/decisions/29-proxy.md`) — the intended `proxy`
feature meaning is environment-inheritance opt-in. On current `origin/main`
(`de77e17`), the policy predicate exists, but `HttpNetworkService::new`
still reads the environment unconditionally. The completed but unmerged
CTX-0034 commit `f51240a` implements that gate, but it is not part of the
current baseline. This record adds the PAC posture and the tier order below;
it does not change what the gate is intended to mean.

## Decision

bitty-network's own routing code **never evaluates PAC** and never
intentionally reads platform system proxy configuration. The system/PAC
tier of the precedence is refused, not emulated. The intended
repository-owned selection uses the two sources below, but reqwest's
automatic environment matcher is still active on `origin/main` and is
not covered by that intended contract. Every selected URL must pass one
credential check before a client is built. That check is not present on
`origin/main`; the completed but unmerged CTX-0028 commit `9fc413e` supplies
the HTTP/ALL fan-out and credential validation, pending integration. This
record treats those controls as pending arrivals rather than current
controls.

The current explicit-unsupported posture is **not fail closed**: a refused
PAC/system setting is silent today, and direct egress can bypass an operator's
mandatory path. Fail-closed behavior is a required pre-adoption property for
a future PAC implementation, not a current control. This posture is chosen
over embedded JavaScript evaluation and over platform lookup.

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
| 2    | Environment proxy variables | Target; current baseline unsafe    |
| 3    | System settings / PAC file  | Refused, not implemented           |

**Tier 1 — explicit override (available today; full validation is a
target).** `with_proxy` selects one explicit proxy URL and stays
available with or without the `proxy` feature: explicit construction is
a deliberate operator act, not ambient authority (#29). The complete
userinfo rejection and one-injection-point contract below is supplied by
completed but unmerged CTX-0028 commit `9fc413e`, pending integration; it
is not a current `origin/main` guarantee.

**Tier 2 — environment (target; current `origin/main` baseline is
unsafe).** On current `origin/main`, the explicit reader reads
`HTTPS_PROXY` first, then `https_proxy`, and joins `NO_PROXY` and
`no_proxy` as its bypass list. It has no `HTTP_PROXY`/`ALL_PROXY` fan-out
and no per-variable credential check. `HttpNetworkService::new` reads this
environment unconditionally, and `env_proxy_enabled()` has no non-test
caller. With the `proxy` feature off, the environment is still inherited:
this is the unsafe current baseline, not fail-closed behavior. The
completed but unmerged CTX-0034 commit `f51240a` implements the feature
gate by wrapping the environment reads in `env_proxy_enabled()`
(`http.rs:154-159`) and adds `.no_proxy()` at `http.rs:217-221` and
`http.rs:444-450`; it does not add HTTP/ALL fan-out or credential
validation. The completed but unmerged CTX-0028 commit `9fc413e` supplies
that fan-out and credential validation, as well as its own `.no_proxy()`
calls. Both lanes are pending integration; neither is merged.

**Tier 3 — system/PAC (refused, not implemented).** No platform
lookup, no PAC file read, no PAC evaluation, on any platform. A
`pac:` URL or a platform proxy setting is therefore never a usable
answer and is never inherited as a PAC route, even with the `proxy`
gate on. This refusal is separate from the completed but unmerged
CTX-0034 commit `f51240a` and from reqwest's automatic environment
matcher described below.

Refusal is total, and therefore silent today: with no system/PAC tier,
an operator whose machine is configured for a PAC sees exactly the
behavior of no proxy configuration at all. That is an explicit unresolved
risk, not an approved transparent fallback. The operator may send direct
traffic that bypasses a mandatory egress path such as egress filtering,
DLP, TLS inspection, or geo and compliance controls, with no error,
warning, or log. No user-visible signal exists today, so the current
posture is not fail closed. Before any future PAC adoption, the
implementation must provide a testable, non-lookup signal for a
caller-supplied PAC/system source: a documented diagnostic event emitted
before any request can send must identify the refused source, and a
fixture must assert that event and zero direct sends. Platform lookup
remains refused, so this record does not claim detection of ambient
platform settings. Adoption is blocked until that criterion is
implemented and tested; the future unevaluable-PAC path must still fail
closed.

## Required fail-closed behavior for a future PAC implementation

A PAC we cannot evaluate must not become a direct-egress fallback in a
future implementation. Failing open is the specific failure this record
forbids: the operator's configuration asked for proxied egress, and
silently sending direct traffic misrepresents what the process did. The
current explicit-unsupported refusal is silent and is not fail closed;
this section is a pre-adoption contract, not a current behavior claim.

The table is a future diagnostic contract, not current behavior —
bitty-network has no system/PAC tier to fail in today. A future ambient
source must end at the same terminal state, `NetworkError::Offline`, on
every request through the service. The reason column is a future
diagnostic value: `NetworkError::Offline` is currently a unit variant
with the constant display text `network offline`, and it is already a
catch-all for capability denial, malformed headers, an unparseable
proxy URL, and non-timeout transport failures. It cannot by itself
make these four post-source cases distinguishable.

| Case                                                | Reason reported       |
| --------------------------------------------------- | --------------------- |
| PAC file unreadable                                 | `pac-unreadable`      |
| PAC file unparseable                                | `pac-unparseable`     |
| PAC returns no usable proxy                         | `pac-no-proxy`        |
| Credential-free PAC-selected proxy returns HTTP 407 | `proxy-challenge-407` |

A PAC result containing URL userinfo is a separate **pre-client
rejection**, named `pac-url-userinfo`: it is rejected before client
construction and is never retained or logged. It is not the same event
as `proxy-challenge-407`. A credential-free PAC-selected proxy may
return HTTP 407 only after dialing; that challenge is unknowable before
the connection and is not an inference from the PAC result. The current
API maps the later 407 to generic `NetworkError::Offline`; a future
diagnostic carrier must map it separately from `pac-url-userinfo`.

The requirements behind that table:

- A future unevaluable source fails closed as a typed error, exactly as
  an unusable explicit proxy must — never a silent direct send, never a
  hang, never a retry loop.
- A future diagnostic channel must name the reason from the table and
  the kind of source it came from, so an operator can tell "my PAC is
  broken" from "my PAC was refused by design". The reason is not a new
  public error variant, and no such variant is authorized here.
- **Open point — diagnostic carrier (accountable task: CTX-0022, the
  planned PAC implementation lane for #24):** the current four-variant
  public taxonomy and unit `NetworkError::Offline` cannot carry the four
  post-source reasons plus the separate `pac-url-userinfo` rejection. A
  separate API decision owned by CTX-0022 must choose a compatible
  carrier outside that taxonomy, or explicitly amend the taxonomy in a
  scoped task. Until that decision lands, the named cases are
  indistinguishable through `NetworkError::Offline` and no
  implementation may claim that it provides them.
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

**PAC URL userinfo and proxy challenges are separate events.** A PAC
result containing URL userinfo (`pac-url-userinfo`) must be rejected by
the same one-injection userinfo check required for the explicit and
environment paths, before any client is built. The check is absent on
current `origin/main`; completed but unmerged CTX-0028 commit `9fc413e`
supplies that validation for the existing paths, and a future PAC
evaluator must call the same function. Completed but unmerged CTX-0034
commit `f51240a` supplies the feature gate and `.no_proxy()` calls, not
credential validation.

A PAC is never a credential source: nothing it returns satisfies a proxy
challenge, and credential storage and rotation stay out of scope here
(CTX-0033). A credential-free PAC-selected proxy can issue HTTP 407 only
after the request is sent. That separate `proxy-challenge-407` event is
not predictable before dialing; the current API maps the later challenge
to generic `NetworkError::Offline`, while a future diagnostic carrier must
map it distinctly from `pac-url-userinfo`.

## `no_proxy()` interaction

Ambient discovery must stay off, but it is not off on `origin/main`.

**Current origin/main baseline.** `origin/main` contains no
`.no_proxy()` call in `crates/`. The calls are supplied by two unmerged
lanes: completed CTX-0028 commit `9fc413e` and completed CTX-0034 commit
`f51240a`; neither is merged. `HttpNetworkService::client_with` therefore
builds clients with reqwest's default `auto_sys_proxy = true`. In reqwest
0.13.5, `ClientBuilder::build` pushes `ProxyMatcher::system()` whenever
that flag is true, and hyper-util 0.1.20's `Builder::from_system()` calls
`from_env()` unconditionally; its `client-proxy-system` feature gates
only macOS and Windows platform lookups. Consequently, on `origin/main`,
reqwest can silently inherit `ALL_PROXY`, `HTTP_PROXY`, and `HTTPS_PROXY`
(including their lowercase forms) and honor `NO_PROXY`/`no_proxy`,
with no credential check in this crate. The absent `system-proxy`
feature does not disable environment inheritance. This record must not
claim that exposure is closed.

Rules for any future system/PAC work:

- **One injection point.** Every proxy URL, whatever its source, must
  pass through one shared validation function: reject userinfo, then
  parse, then build the `reqwest::Proxy`. A PAC evaluator produces a URL
  and hands it to that function. It gets no second path, and never
  builds a client first to validate later. Current `origin/main` lacks
  that function and its credential check; completed but unmerged CTX-0028
  commit `9fc413e` supplies the validation for existing explicit and
  environment paths, and a future PAC evaluator must call it.
- **Discovery stays off.** Every client builder in a landed
  implementation must call `.no_proxy()` before adding a selected route.
  The calls are supplied by unmerged CTX-0028 commit `9fc413e` and
  unmerged CTX-0034 commit `f51240a`; neither is merged. Reading a PAC
  file is reading a file; letting reqwest discover a platform proxy is a
  different, unvalidated route. Only the PAC source is ever revisited;
  platform discovery remains refused.
- **The gate is not the control.** `.no_proxy()` and the credential
  check are separate controls. The `proxy` feature decides whether tier
  2 is consulted at all; it is never a reason to re-enable discovery.
  Completed but unmerged CTX-0034 commit `f51240a` wires the gate and
  its `.no_proxy()` calls, but it does not add the credential check;
  completed but unmerged CTX-0028 commit `9fc413e` supplies that check
  and the HTTP/ALL fan-out.
- **Regression guard.** A PAC slice ships tests pinning that ambient
  environment and platform configuration cannot influence the selected
  client, and a review that finds discovery re-enabled returns a
  security defect, not a feature request.

## What this record does not authorize

No PAC code, no platform lookup, no new dependency, and no merge or
integration of the unmerged CTX-0034 commit `f51240a` or CTX-0028 commit
`9fc413e`. Their controls remain pending integration; this record does
not turn either commit into a current `origin/main` guarantee. Issue #24
stays open: this is its decision half only, and the implementation half
(fixture-proxied precedence tests for tiers 1 and 2) is a separate scoped
task.

Revisit criteria, all required before a PAC slice may start:

1. `deny.toml` approval for the proposed engine, with an MSRV-1.85
   and `#![forbid(unsafe_code)]` analysis of its tree.
2. A security-corpus review of executing an ambient, operator-supplied
   program on every connection decision.
3. A separate API decision owned by CTX-0022, the planned PAC
   implementation lane for #24, resolving the diagnostic carrier for the
   four post-source reasons plus `pac-url-userinfo` without silently
   changing the pinned four-variant public taxonomy.
4. Recorded decisions for the authority of a future `DIRECT` result and
   for the distinct PAC URL-userinfo rejection and post-dial HTTP 407
   challenge. Neither is resolved above; no PAC path exists today.
5. A testable, non-lookup diagnostic event for a caller-supplied
   PAC/system source that is refused: the event must identify the source
   before any request can send, and a fixture must assert the event and
   zero direct sends. Platform lookup remains refused, and no detection
   of ambient platform settings is claimed.
6. The one-injection-point and regression-guard rules above built into
   the slice's acceptance, not left to review.

## Acceptance

- `just check`, `just check-http`, `just check-websocket`, and
  `just typecheck` pass: this record changes no code, so the gates
  confirm nothing else moved.
- `gitleaks detect --source .` clean.
