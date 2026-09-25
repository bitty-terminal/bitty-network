# #24: proxy PAC evaluation — explicit unsupported, not fail closed while refusal is silent

Status: decided, docs only — explicit unsupported; current refusal is
silent, not fail closed (CTX-0032). Baseline claims rewritten against
`integrate/lanes-abc` and CTX-0045; decision unchanged.

Parent: #15 (BN-2 policy depth slice).

Builds on: #29 (`docs/decisions/29-proxy.md`) — the intended `proxy`
feature meaning is environment-inheritance opt-in. The policy predicate
`env_proxy_enabled()` exists on `origin/main` (`proxy.rs:25-27`), but on
`origin/main` it has no production caller at all, and on the integration
branch it still has none: `HttpNetworkService::new` reads the environment
unconditionally in both. CTX-0034 (`f51240a`) implements that gate and is
being rebased onto the integration branch by CTX-0043. This record adds
the PAC posture and the tier order below; it does not change what the gate
is intended to mean.

## Code states this record is written against

This branch is based on `integrate/lanes-abc` (`941c235`), **not** on
`origin/main`. Three distinct code states are therefore in play, and every
control claim below names the one it refers to. Conflating them is what made
earlier drafts of this record wrong three review rounds running.

| State                      | Commit    | In `origin/main`? |
| -------------------------- | --------- | ----------------- |
| **A** — merged             | `de77e17` | Yes, this is it   |
| **B** — this branch's base | `941c235` | No                |
| **C** — the tier-2 gate    | `f51240a` | No                |

**A** is `origin/main` itself. **B** is `integrate/lanes-abc`, 12 commits
ahead of A and open as PR #44, which is **not merged**; A does not contain
it. **C** is CTX-0034, off both A and B, currently being rebased onto B by
CTX-0043 — that rebase keeps only the cargo feature gate and drops the
`.no_proxy()` calls B already carries.

A control is **merged** only if it appears in A. Everything in B and C is
reviewed but unmerged, so a reader of `origin/main` today has none of it.

## Control inventory

Verified by reading the tree at each commit. `file:line` is on B unless the
row says otherwise.

| Control                               | Provided by           | Location                   | In A?          |
| ------------------------------------- | --------------------- | -------------------------- | -------------- |
| `.no_proxy()` on every client builder | `9fc413e` CTX-0028    | `http.rs:380, 829, 847`    | No             |
| Test pin for the above                | `941c235` CTX-0041    | `tests/http.rs:698-727`    | No             |
| `Policy::none()`, hops re-authorized  | `a207005` CTX-0012    | `http.rs:381, 831, 848`    | No             |
| One credential check per proxy URL    | `9fc413e` CTX-0028    | `http.rs:807-812`          | No             |
| Userinfo detection for that check     | `833b31e` CTX-0027    | `http.rs:798-805`          | No             |
| `HTTP_PROXY`/`ALL_PROXY` fan-out      | `9fc413e` CTX-0028    | `http.rs:136-147, 256-291` | No             |
| Fail-closed on rejected env proxy     | `9fc413e` CTX-0028    | `http.rs:303, 355-361`     | No             |
| `CountBudget`, a fifth variant        | `076b030` CTX-0026    | api `lib.rs:284-287`       | No             |
| Redacted URL/header diagnostics       | `77dae1d` CTX-0014    | `diagnostics.rs:49, 132`   | No             |
| `env_proxy_enabled()` predicate       | CTX-0015, i.e. A      | `proxy.rs:25-27`           | Predicate only |
| Tier-2 gate wiring the predicate      | `f51240a` = state C   | `http.rs:155` on C         | No             |
| reqwest `=0.13.5`, no `system-proxy`  | A, unchanged by B     | `Cargo.toml:26`            | Yes            |
| hyper-util 0.1.20 env inheritance     | upstream, locked in A | `matcher.rs:228-249`       | Yes            |

## Decision

bitty-network's own routing code **never evaluates PAC** and never
intentionally reads platform system proxy configuration. The system/PAC
tier of the precedence is refused, not emulated.

On state B, the repository-owned selection the record intends is the code
that actually runs there: reqwest's automatic environment matcher is
disabled on every client builder, every selected URL passes one credential
check before a client is built, and an unusable environment proxy fails
closed rather than falling back to direct. All three come from B and are
unmerged. On state A none of them hold: the two builder sites at
`http.rs:210` and `http.rs:438` call neither `.no_proxy()` nor
`Policy::none()`, and no credential check exists anywhere. A reader of
`origin/main` must assume the A behavior.

The current explicit-unsupported posture is **not fail closed**: a refused
PAC/system setting is silent in every state above, and direct egress can
bypass an operator's mandatory path. Fail-closed behavior is a required
pre-adoption property for a future PAC implementation, not a current
control. This posture is chosen over embedded JavaScript evaluation and over
platform lookup.

A second fail-open exists on the merged state A alone, and is named here so
it is not mistaken for the PAC hazard: on A an unparseable environment proxy
is discarded so the request goes direct (`http.rs:156-161`), which is silent
egress past a configured proxy. `9fc413e` (CTX-0028) replaces that with a
fail-closed `proxy_rejected` path (`http.rs:355-361`) on B, so the hazard is
real for a reader of `origin/main` and already fixed but unmerged elsewhere.
A third gap, the `proxy` feature gate itself, is state C and still open
everywhere.

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

| Tier | Source                | A (merged)            | B (base)                | C (gate)      |
| ---- | --------------------- | --------------------- | ----------------------- | ------------- |
| 1    | Explicit `with_proxy` | no check              | checked                 | same          |
| 2    | Environment vars      | inherited, fails open | inherited, fails closed | feature-gated |
| 3    | System / PAC          | refused               | refused                 | refused       |

**Tier 1 — explicit override (available in every state; credential-checked
only on B).** `with_proxy` selects one explicit proxy URL and stays
available with or without the `proxy` feature: explicit construction is
a deliberate operator act, not ambient authority (#29). The complete
userinfo rejection and one-injection-point contract below is supplied by
`9fc413e` (CTX-0028) on B and is **not merged**; on A `with_proxy` has no
credential check at all, so A does not satisfy the contract this record
states.

**Tier 2 — environment (inherited unconditionally everywhere; fail-open on
A, fail-closed-if-unusable on B, feature-gated only in C).**

**What A reads.** `HTTPS_PROXY` then `https_proxy` (`http.rs:106`), joined
with `NO_PROXY` and `no_proxy` as its bypass list (`http.rs:111`). No
`HTTP_PROXY`, no `ALL_PROXY`, no per-variable credential check, and an
unparseable value silently degrades to direct (`http.rs:156-161`).

**What B reads — a different set, not a superset of A's wording.**
`HTTP_PROXY`/`http_proxy`, `HTTPS_PROXY`/`https_proxy`,
`ALL_PROXY`/`all_proxy`, and `NO_PROXY`/`no_proxy`
(`http.rs:136-147`), with uppercase tried before lowercase in each pair
(`http.rs:880-886`) and scheme-specific beating the generic fallback
(`http.rs:284-290`). Every value passes `validated_proxy_url`
(`http.rs:807-812`), and a rejected value sets `proxy_rejected` so every
request fails closed (`http.rs:355-361`) instead of going direct.

**The gate is still missing in both.** `HttpNetworkService::new` calls
`ProxyRoute::from_env()` unconditionally on A and on B
(`http.rs:316` on B), and `env_proxy_enabled()` has no production caller on
either. With the `proxy` feature off, both states still inherit the
environment. State C, `f51240a` (CTX-0034), is the only code that wires the
gate, by wrapping the environment reads in `env_proxy_enabled()`
(`http.rs:154-159` on C). It adds no fan-out and no credential validation,
and CTX-0043 is rebasing it onto B while dropping the `.no_proxy()` calls B
already has. C is unmerged and not in this branch's base.

Tier 2 is HTTP-only. The WebSocket backend reads no proxy environment at
all: the only `env::var` calls in the crate are `http.rs:882` and
`http.rs:892`.

**Tier 3 — system/PAC (refused, not implemented, in every state).** No
platform lookup, no PAC file read, no PAC evaluation, on any platform, in A,
B, or C. A `pac:` URL or a platform proxy setting is therefore never a
usable answer and is never inherited as a PAC route, even with the `proxy`
gate on. This refusal is independent of the CTX-0034 gate and of reqwest's
automatic environment matcher described below.

Refusal is total, and therefore silent in all three states: with no
system/PAC tier anywhere, an operator whose machine is configured for a PAC
sees exactly the behavior of no proxy configuration at all. That is an
explicit unresolved risk, not an approved transparent fallback. The
operator may send direct traffic that bypasses a mandatory egress path
such as egress filtering, DLP, TLS inspection, or geo and compliance
controls, with no error, warning, or log. No user-visible signal exists in
any state, so the current posture is not fail closed. Before any future
PAC adoption, the implementation must provide a testable, non-lookup signal
for a caller-supplied PAC/system source: a documented diagnostic event
emitted before any request can send must identify the refused source, and a
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
diagnostic value: `NetworkError::Offline` is a unit variant with the
constant display text `network offline` in **both** A
(`bitty-network-api/src/lib.rs:271, 290`) and B
(`bitty-network-api/src/lib.rs:271, 294`), and it is already a catch-all
for capability denial, malformed headers, a rejected proxy URL, and
non-timeout transport failures. That is what makes the carrier problem
real, and the unit-variant part of it survives the integration branch
unchanged. It cannot by itself make these four post-source cases
distinguishable.

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
the connection and is not an inference from the PAC result. Both the
merged state A and this branch's base B map such a later 407 to generic
`NetworkError::Offline` with no distinguishing detail; a future
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
  planned PAC implementation lane for #24):** unit `NetworkError::Offline`
  plus the pinned public taxonomy cannot carry the four post-source reasons
  plus the separate `pac-url-userinfo` rejection. The taxonomy is **four**
  variants on A (`Denied`, `Offline`, `Timeout`, `Budget`;
  `bitty-network-api/src/lib.rs:264-284`) and **five** on B, which adds
  `CountBudget` from `076b030` (CTX-0026)
  (`bitty-network-api/src/lib.rs:284-287`) — unmerged. A separate API
  decision owned by CTX-0022 must choose a compatible carrier outside that
  taxonomy, or explicitly amend the taxonomy in a scoped task; whichever it
  picks, it must be written against B's five-variant shape, because that is
  the base any implementation will start from. Until that decision lands,
  the named cases are indistinguishable through `NetworkError::Offline` and
  no implementation may claim that it provides them.
- **Open point — stale sibling pin (not fixable in this record).**
  `docs/decisions/30-bridge.md:29` still names the taxonomy as
  `Offline`/`Denied`/`Timeout`/`Budget`, which is correct for A and stale
  for B. Correcting it is a `30-bridge.md` edit and outside this record's
  scope; it is recorded here so the next task to touch the taxonomy owns
  both files.
- No URL, path, or file content from a PAC source is retained or
  logged. A PAC URL can carry userinfo, so the rule that keeps
  credential-bearing proxy URLs out of logs applies to every string
  read from that source.
- Construction must remain `Result`-shaped on the existing split once
  a source is implemented: an explicitly requested unevaluable source
  returns the typed error to the caller, while an ambient source
  degrades the service to fail-closed for every request. Neither A nor B
  has that shape — `HttpNetworkService::new` returns `Self` in both
  (`http.rs:149` on A, `http.rs:314` on B) — so this is a target
  contract, not a claim about either state's API.

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
environment paths, before any client is built. That check is absent
entirely on A; `9fc413e` (CTX-0028) supplies it as
`validated_proxy_url` (`http.rs:807-812`, unmerged, on B), and a future PAC
evaluator must call that same function. CTX-0034 `f51240a` supplies the
feature gate, not credential validation.

A PAC is never a credential source: nothing it returns satisfies a proxy
challenge, and credential storage and rotation stay out of scope here
(CTX-0033). A credential-free PAC-selected proxy can issue HTTP 407 only
after the request is sent. That separate `proxy-challenge-407` event is
not predictable before dialing; both A and B map the later challenge
to generic `NetworkError::Offline`, while a future diagnostic carrier must
map it distinctly from `pac-url-userinfo`.

## `no_proxy()` interaction

Ambient discovery must stay off. It is off on this branch's base (B) and
still on on the merged state (A).

**Coverage is complete on B, and absent on A.** Every reqwest client in the
crate is built in `http.rs`, and all three builder chains call `.no_proxy()`
before any route is added: `http.rs:380` in `client_with`, `http.rs:829` in
`proxy_client`, and `http.rs:847` in `proxy_route_client`. `941c235`
(CTX-0041) adds a source-level test,
`every_client_builder_disables_ambient_proxy_and_redirects`
(`tests/http.rs:698-727`), that walks every `Client::builder()` chain in
`http.rs`, asserts each one contains `.no_proxy()` **and**
`Policy::none()`, and fails if an unconfigured `Client::new()`,
`Client::default()`, or `ClientBuilder::new()` appears. That is a real
regression guard, not a comment. `websocket.rs` builds no reqwest client at
all, so there is no second construction path to cover. All of this is
unmerged.

On A the two builder chains (`http.rs:210`, `http.rs:438`) call neither
`.no_proxy()` nor `Policy::none()`, and `origin/main` contains no
`.no_proxy()` call anywhere in `crates/`. A therefore builds its clients
with reqwest's default `auto_sys_proxy = true`.

**Why the feature graph does not save A.** In reqwest 0.13.5,
`ClientBuilder` defaults `auto_sys_proxy` to `true`
(`async_impl/client.rs:310`) and `build` pushes `ProxyMatcher::system()`
whenever that flag is set (`async_impl/client.rs:417-418`);
`Proxy::system()` calls `matcher::Matcher::from_system()` (`proxy.rs:517`).
hyper-util 0.1.20's `Builder::from_system()` calls `Self::from_env()` first,
unconditionally (`matcher.rs:238-240`), and its `client-proxy-system`
feature gates **only** the macOS and Windows lookups
(`matcher.rs:242-246`). `from_env` reads `ALL_PROXY`/`all_proxy`,
`HTTP_PROXY`/`http_proxy`, `HTTPS_PROXY`/`https_proxy`, and
`NO_PROXY`/`no_proxy` (`matcher.rs:231-234`) plus `REQUEST_METHOD` for
CGI detection (`matcher.rs:230`).

The negative is non-vacuous, and was re-checked on B: `cargo tree
--locked --features http` resolves hyper-util's `client-proxy` but **not**
`client-proxy-system`, and `system-configuration` and `windows-registry`
appear nowhere in `Cargo.lock`. So on A reqwest can silently inherit
`ALL_PROXY`, `HTTP_PROXY`, and `HTTPS_PROXY` with their lowercase forms and
honor `NO_PROXY`/`no_proxy`, with no credential check anywhere in the
crate, while this crate's own reader handles only `HTTPS_PROXY`. The
absent `system-proxy` feature does not disable environment inheritance. On
A this record must not claim that exposure is closed.

Rules for any future system/PAC work:

- **One injection point.** Every proxy URL, whatever its source, must
  pass through one shared validation function: reject userinfo, then
  parse, then build the `reqwest::Proxy`. A PAC evaluator produces a URL
  and hands it to that function. It gets no second path, and never
  builds a client first to validate later. A has no such function at all;
  `9fc413e` (CTX-0028) supplies it as `validated_proxy_url`
  (`http.rs:807-812`, unmerged, on B) for the existing explicit and
  environment paths, and a future PAC evaluator must call it.
- **Discovery stays off.** Every client builder in a landed
  implementation must call `.no_proxy()` before adding a selected route.
  On B that is already true on 3 of 3 chains and pinned by
  `tests/http.rs:698-727`; on A it is true on 0 of 2. A PAC evaluator does
  not change this. Reading a PAC file is reading a file; letting reqwest
  discover a platform proxy is a different, unvalidated route. Only the
  PAC source is ever revisited; platform discovery remains refused.
- **The gate is not the control.** `.no_proxy()` and the credential
  check are separate controls, and neither is the `proxy` feature. That
  feature decides whether tier 2 is consulted at all; it is never a reason
  to re-enable discovery. On B the two are independent and both present:
  `9fc413e` (CTX-0028) supplies `.no_proxy()` and the credential check, and
  CTX-0034 `f51240a` supplies the gate alone. CTX-0043 is rebasing that
  gate onto B while dropping the `.no_proxy()` duplicates B already
  carries, so after it lands the gate is the only thing CTX-0034
  contributes. None of the three is merged.
- **Regression guard.** A PAC slice ships tests pinning that ambient
  environment and platform configuration cannot influence the selected
  client, and a review that finds discovery re-enabled returns a
  security defect, not a feature request. `tests/http.rs:698-727` already
  pins the client-builder half of this on B; the ambient half still needs
  the tier-2 gate from C to be meaningful.

## What this record does not authorize

No PAC code, no platform lookup, no new dependency, and no merge of the
integration branch or of CTX-0034 `f51240a`. PR #44 stays open and
unmerged; `9fc413e` and the rest of B are reviewed but not in
`origin/main`, and this record does not turn any B control into a merged
guarantee. Issue #24 stays open: this is its decision half only, and the
implementation half (fixture-proxied precedence tests for tiers 1 and 2) is
a separate scoped task.

Revisit criteria, all required before a PAC slice may start:

1. `deny.toml` approval for the proposed engine, with an MSRV-1.85
   and `#![forbid(unsafe_code)]` analysis of its tree.
2. A security-corpus review of executing an ambient, operator-supplied
   program on every connection decision.
3. A separate API decision owned by CTX-0022, the planned PAC
   implementation lane for #24, resolving the diagnostic carrier for the
   four post-source reasons plus `pac-url-userinfo` without silently
   changing the public taxonomy. That taxonomy is four variants on
   `origin/main` and five on `integrate/lanes-abc`, which adds
   `CountBudget` from `076b030` (CTX-0026); the decision must be written
   against the five-variant shape and must also correct the now-stale
   `Offline`/`Denied`/`Timeout`/`Budget` list at
   `docs/decisions/30-bridge.md:29`.
4. Recorded decisions for the authority of a future `DIRECT` result and
   for the distinct PAC URL-userinfo rejection and post-dial HTTP 407
   challenge. Neither is resolved above; no PAC path exists today.
5. A testable, non-lookup diagnostic event for a caller-supplied
   PAC/system source that is refused: the event must identify the source
   before any request can send, and a fixture must assert the event and
   zero direct sends. Platform lookup remains refused, and no detection
   of ambient platform settings is claimed.
6. The one-injection-point and regression-guard rules above built into
   the slice's acceptance, not left to review. The client-builder half is
   already mechanically pinned by `tests/http.rs:698-727` on
   `integrate/lanes-abc`; the slice must extend that pin rather than
   assume it, and must keep it green once the tier-2 gate from CTX-0034
   lands.
7. PR #44 merged, so that the tier-1 credential check, the fail-closed
   environment rejection, the `HTTP_PROXY`/`ALL_PROXY` fan-out, and the
   `.no_proxy()` coverage this record relies on are actually in
   `origin/main`. Until then every one of them is unmerged, and a PAC
   slice must not be scoped as though they were.

## Acceptance

- `just check`, `just check-http`, `just check-websocket`, and
  `just typecheck` pass: this record changes no code, so the gates
  confirm nothing else moved.
- `gitleaks detect --source .` clean.
- Every control named above cites a commit, and every commit cited is
  labeled merged or unmerged. A reviewer re-checking this record against
  `git grep` at the named commit must reach the same conclusion.
