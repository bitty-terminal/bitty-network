# #24: proxy PAC evaluation — explicit unsupported, not fail closed while refusal is silent

Status: decided, docs only — explicit unsupported; current refusal is
silent, not fail closed (CTX-0032). Control claims rest on one base pin and
on property-pinning tests instead of a per-control commit table (CTX-0046);
the decision itself is unchanged.

Parent: #15 (BN-2 policy depth slice).

Builds on: #29 (`docs/decisions/29-proxy.md`) — the intended `proxy`
feature meaning is environment-inheritance opt-in. The policy predicate
`env_proxy_enabled()` exists (`proxy.rs:25-27`), but on the base it has no
production caller at all: `HttpNetworkService::new` reads the environment
unconditionally (`http.rs:314-321`). The gate that wires it is committed
separately — see the divergence row in the base pin below. This record adds
the PAC posture and the tier order; it does not change what the gate is
intended to mean.

## Verified base

Control claims are scoped to exactly one base, and the pin is a single
ref-plus-commit pair, so drift is mechanically detectable instead of being a
table somebody has to remember to update.

| Role                                        | Ref                               | Commit    |
| ------------------------------------------- | --------------------------------- | --------- |
| **base** — scopes every control claim       | `integrate/lanes-abc`             | `941c235` |
| divergence — the merged state               | `origin/main`                     | `de77e17` |
| divergence — the committed tier-2 gate work | `ctx-0034/fix-proxy-feature-gate` | `29a66b1` |

Check all three:

```sh
git rev-parse integrate/lanes-abc ctx-0034/fix-proxy-feature-gate origin/main
```

**Scope rule.** Only the row marked **base** scopes a control claim. A
base-scoped claim describes that tree and nothing else. When
`integrate/lanes-abc` moves off `941c235`, the _Base-scoped facts_ list
below is re-verified: one pass over a short list of `file:line` entries,
each of which either still holds or does not. No table is edited and no
per-control provenance is maintained, because a per-control table cannot
self-maintain — the commit graph moves on every merge and rebase, which is
what made three earlier drafts of this record wrong in a row.

The two **divergence** rows are not bases and no control claim resolves
against them. They exist because two facts here cannot be stated without
naming a tree. First, the controls are **unmerged**: `941c235` is not an
ancestor of `origin/main` and PR #44 is open, so a reader of `origin/main`
has none of them. That answer is uniform across the whole control set, which
is exactly why this record carries no per-control merge column — there is
nothing per-control left to track. Second, the tier-2 gate exists today
only as committed-but-unpushed work on its own branch, and a PAC slice has
to know what it will inherit.

`29a66b1` has parent `941c235`, so the gate is written against this exact
base and needs no rebase. Its live shape is an early return in
`HttpNetworkService::new` when `env_proxy_enabled()` is false
(`http.rs:326` on that commit), which keeps the base's credential predicate
and validator at `http.rs:813` and `http.rs:822`, and adds
`explicit_proxy_with_credentials_is_rejected` (`tests/http.rs:453`). That
commit's superseded predecessor `f51240a` is on no ref, and no claim in this
record rests on it.

## How this record justifies its claims

Three kinds of claim, each with a different way to go stale.

### Base-scoped facts

Statements about the tree at the base pin. Re-verify when the base moves.

- Tier 2 reads `HTTP_PROXY`/`http_proxy`, `HTTPS_PROXY`/`https_proxy`,
  `ALL_PROXY`/`all_proxy`, and `NO_PROXY`/`no_proxy`
  (`http.rs:136-147`), with uppercase tried before lowercase in each pair
  (`http.rs:880-886`) and scheme-specific beating the generic fallback
  (`http.rs:284-290`).
- The three **proxy** variables each pass `validated_proxy_url`
  (`http.rs:807-812`) before a client is built, and a rejected value sets
  `proxy_rejected` (`http.rs:318`) so every request fails closed
  (`http.rs:355-361`) instead of going direct.
- The **bypass list** deliberately does not: `NO_PROXY`/`no_proxy` are
  comma-joined unvalidated at `http.rs:889-895`, and an entry there can only
  _widen_ direct egress. That is not a credential surface, but it is a
  second, unaudited way to leave the proxy, so it is named here rather than
  folded into the validated set. An earlier draft of this record claimed
  every environment value passed `validated_proxy_url`; that was false.
- `HttpNetworkService::new` reads the environment unconditionally and
  returns `Self` rather than a `Result` (`http.rs:314-321`).
- `env_proxy_enabled()` exists (`proxy.rs:25-27`) and has no production
  caller.
- The WebSocket backend reads no environment at all: the only `env::var`
  calls in the crate are `http.rs:882` and `http.rs:892`.
- The public error taxonomy has five variants on the base
  (`bitty-network-api/src/lib.rs:264-288`), adding `CountBudget`
  (`:284-287`) to the four that are merged.

### Divergence-scoped facts

Statements about a divergence row above. Re-verify when that ref moves.

- **Merged state.** Reads only `HTTPS_PROXY`/`https_proxy`
  (`http.rs:106`) plus `NO_PROXY`/`no_proxy` (`http.rs:111`), through
  `https_proxy_from_env()` (`http.rs:150`, `http.rs:460`). There is no
  `ProxyRoute` type there at all — `git grep ProxyRoute de77e17` returns
  nothing — so this record makes no claim about that type on the merged
  state, in either direction. No `HTTP_PROXY`, no `ALL_PROXY`, no
  per-variable credential check, and an unparseable value is discarded so the
  request goes direct (`http.rs:156-161`).
- **Merged state, clients.** The two builder chains (`http.rs:210`,
  `http.rs:438`) call neither `.no_proxy()` nor `Policy::none()`, and a
  failed build falls back to an unconfigured
  `reqwest::blocking::Client::new()` (`http.rs:216`) — reqwest's default
  `auto_sys_proxy = true`. `git grep 'no_proxy()' de77e17` returns nothing.
- **Merged state, taxonomy.** Four variants
  (`bitty-network-api/src/lib.rs:264-284`); `Offline` is a unit variant at
  `:271` with the constant display at `:290`. The predicate sits one line
  higher than on the base, at `proxy.rs:24-26`.
- **Gate commit.** The early return, the two credential helpers, and the new
  credential-rejection test are as described in the base-pin section.

### Pinned properties

Requirements, not facts. Each is enforced by one named test in
`crates/bitty-network/tests/pac_decision_pins.rs`, so a change that breaks one
fails the suite instead of quietly falsifying this record. Seven of the eight
run in the default leg; all eight run under `just check-http` and
`just check-websocket`.

1. **Ambient discovery is off at every client construction site, and no
   fallback client can exist.** Every `Client::builder()` chain in every
   module of the crate calls both `.no_proxy()` and `Policy::none()`, and
   `Client::new()`, `Client::default()`, `ClientBuilder::new()`, and
   `unwrap_or_else` are all absent, because any of them could produce a
   client carrying reqwest's default `auto_sys_proxy = true` while still
   looking fail-closed.
   Test: `every_client_construction_site_disables_ambient_discovery`.
2. **`http.rs` is the only client construction site**, so there is no second,
   unreviewed path for a future proxy source to build a client on.
   Test: `http_is_the_only_reqwest_client_construction_site`.
3. **The explicit path checks credentials before it injects a proxy.**
   Test: `credential_check_precedes_proxy_injection_on_the_explicit_path`.
4. **The environment path checks credentials before it injects a proxy**, so
   a rejected value sets `proxy_rejected` instead of reaching a client.
   Test: `credential_check_precedes_proxy_injection_on_the_environment_path`.
5. **There is exactly one injection point.** Every `reqwest::Proxy`/`.proxy(`
   in the crate must sit inside `client_with`, `proxy_client`,
   `reqwest_proxy`, or `proxy_route_client`, which is checked by call rather
   than by name, so no second validator escapes it under any name. The
   validator is then counted three ways: `validated_proxy_url` and
   `proxy_url_has_credentials` are each defined once and only in `http.rs`;
   exactly one function in the crate has the shared validator signature, so a
   renamed drop-in copy fails too; and `explicit` and `from_env` must still
   call it by that name before injecting, so a rename of the original fails as
   well. `proxy_client` re-checks before its own `Proxy::all` rather than
   trusting its caller.
   Test: `proxy_injection_stays_inside_the_named_construction_paths`.
6. **A credential-bearing explicit proxy URL fails closed without dialing**:
   `NetworkError::Offline`, no credential echoed, zero connections.
   Test: `credential_bearing_explicit_proxy_fails_closed_without_dialing`.
7. **`NetworkError::Offline` stays a unit variant with the constant display
   `network offline`**, because the diagnostic-carrier open point below
   depends on exactly that.
   Test: `offline_stays_a_unit_variant_with_a_constant_display`.
8. **Only `http.rs` reads the process environment**, so tier 2 is HTTP-only.
   Test: `proxy_environment_is_read_only_by_the_http_backend`.

A control that does not exist yet fails its pin, which is intended: every
control this record relies on is unmerged work, and a silently dropped
control is a security defect rather than a documentation nit.

`tests/http.rs` still exercises the ambient rejection end to end with
`ambient_proxy_environment_is_explicit_and_credential_safe` (which re-execs
itself as a child process, because mutating the environment is `unsafe` in
edition 2024 and this crate forbids `unsafe_code`); that pin is referenced,
not restated. Its former companion
`every_client_builder_disables_ambient_proxy_and_redirects` is deleted rather
than kept beside `every_client_construction_site_disables_ambient_discovery`,
because the pin above is a strict superset of it — the same two builder-chain
assertions and the same three banned constructors, over every module instead of
`http.rs` alone, plus the `unwrap_or_else` ban, and in every CI leg instead of
two — and two scanners for one property drift apart, which is the defect this
record was rewritten to remove. What the pins above add that no `http.rs` test
can reach is the single-injection-point rule and the _ordering_ of the
credential check against proxy injection, which no behavioural test can
distinguish, because "validated before injecting" and "validated, and injected
anyway" look identical from outside the process. Note also that
`tests/http.rs` sits behind `#![cfg(feature = "http")]`, so the pin it still
owns does not run in the default gate. Seven of the pins above are not
feature-gated and run in every leg; the eighth,
`credential_bearing_explicit_proxy_fails_closed_without_dialing`, cannot be
ungated, because it constructs `HttpNetworkService`, whose re-export
`lib.rs:69-70` is behind the same feature.

## Decision

bitty-network's own routing code **never evaluates PAC** and never
intentionally reads platform system proxy configuration. The system/PAC tier
of the precedence is refused, not emulated.

On the base, the repository-owned selection the record intends is the code
that actually runs there: reqwest's automatic environment matcher is
disabled on every client builder, every selected proxy URL passes one
credential check before a client is built, and an unusable environment proxy
fails closed rather than falling back to direct. All three are base-scoped
facts or pinned properties, and none of them is merged. On the merged state
none of them hold: the two builder sites call neither `.no_proxy()` nor
`Policy::none()`, there is no credential check anywhere, and a failed build
falls back to an unconfigured `Client::new()`. A reader of `origin/main`
must assume that behavior.

The current explicit-unsupported posture is **not fail closed**: a refused
PAC/system setting is silent in every state above, and direct egress can
bypass an operator's mandatory path. Fail-closed behavior is a required
pre-adoption property for a future PAC implementation, not a current
control. This posture is chosen over embedded JavaScript evaluation and over
platform lookup.

A second fail-open exists on the merged state alone, and is named here so it
is not mistaken for the PAC hazard: there an unparseable environment proxy
is discarded so the request goes direct (`http.rs:156-161` on that commit),
which is silent egress past a configured proxy. The base replaces that with
a fail-closed `proxy_rejected` path (`http.rs:355-361`), so the hazard is
real for a reader of `origin/main` and already fixed but unmerged elsewhere.
A third gap, the `proxy` feature gate itself, is the divergence commit
`29a66b1` and is still open everywhere.

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

| Tier | Source                | merged (`de77e17`)    | base (`941c235`)        | gate (`29a66b1`) |
| ---- | --------------------- | --------------------- | ----------------------- | ---------------- |
| 1    | Explicit `with_proxy` | no check              | checked                 | same             |
| 2    | Environment vars      | inherited, fails open | inherited, fails closed | feature-gated    |
| 3    | System / PAC          | refused               | refused                 | refused          |

Implemented is the middle column and, for tier 2 only, the right one; the
left column is what a reader of `origin/main` gets today. Nothing in the
middle or right column is merged.

**Tier 1 — explicit override (available in every state; credential-checked
only on the base and on the gate commit).** `with_proxy` selects one
explicit proxy URL and stays available with or without the `proxy` feature:
explicit construction is a deliberate operator act, not ambient authority
(#29). The complete userinfo rejection and one-injection-point contract
below is supplied on the base and is **not merged**; on the merged state
`with_proxy` has no credential check at all, so it does not satisfy the
contract this record states. The gate commit keeps the base's explicit path
verbatim, which is why its tier-1 cell reads "same" and not "unchecked" —
the superseded `f51240a` did not, and an earlier draft of this record
credited the gate commit with the base's check by naming the wrong commit.

**Tier 2 — environment (inherited unconditionally on the base and on the
merged state; fail-open on the merged state, fail-closed-if-unusable on the
base, feature-gated only in the gate commit).**

**What the merged state reads.** `HTTPS_PROXY` then `https_proxy`
(`http.rs:106`), joined with `NO_PROXY` and `no_proxy` as its bypass list
(`http.rs:111`). No `HTTP_PROXY`, no `ALL_PROXY`, no per-variable credential
check, and an unparseable value silently degrades to direct
(`http.rs:156-161`).

**What the base reads — a different set, not a superset of the merged
state's wording.** `HTTP_PROXY`/`http_proxy`, `HTTPS_PROXY`/`https_proxy`,
`ALL_PROXY`/`all_proxy`, and `NO_PROXY`/`no_proxy` (`http.rs:136-147`),
with uppercase tried before lowercase in each pair (`http.rs:880-886`) and
scheme-specific beating the generic fallback (`http.rs:284-290`). The three
proxy values each pass `validated_proxy_url` (`http.rs:807-812`), and a
rejected value sets `proxy_rejected` so every request fails closed
(`http.rs:355-361`) instead of going direct. The bypass list is _not_ part
of that validated set; see the base-scoped facts above.

**The gate is still missing in both.** `HttpNetworkService::new` calls
`ProxyRoute::from_env()` unconditionally on the base
(`http.rs:314-321`), and `env_proxy_enabled()` has no production caller
there. The merged state has no `ProxyRoute` type to call: it reads through
`https_proxy_from_env()` (`http.rs:150`, `http.rs:460`) and likewise
inherits unconditionally, and `env_proxy_enabled()` has no production caller
there either. With the `proxy` feature off, both states still inherit the
environment.

The gate commit `29a66b1` is the only code that wires the predicate, by
returning an empty route and an empty bypass list from `HttpNetworkService::new`
when `env_proxy_enabled()` is false (`http.rs:326` on that commit). It adds
no fan-out and no credential validation — it keeps the base's, at
`http.rs:813` and `http.rs:822` on that commit — and it needs no rebase,
because its parent is this base. It is unpushed, it is not in PR #44, and
it is not in this branch.

Tier 2 is HTTP-only. The WebSocket backend reads no proxy environment at
all: the only `env::var` calls in the crate are `http.rs:882` and
`http.rs:892`.

**Tier 3 — system/PAC (refused, not implemented, in every state).** No
platform lookup, no PAC file read, no PAC evaluation, on any platform, on
any of the three trees. A `pac:` URL or a platform proxy setting is
therefore never a usable answer and is never inherited as a PAC route, even
with the `proxy` gate on. This refusal is independent of the tier-2 gate and
of reqwest's automatic environment matcher described below.

Refusal is total, and therefore silent in all three states: with no
system/PAC tier anywhere, an operator whose machine is configured for a PAC
sees exactly the behavior of no proxy configuration at all. That is an
explicit unresolved risk, not an approved transparent fallback. The
operator may send direct traffic that bypasses a mandatory egress path
such as egress filtering, DLP, TLS inspection, or geo and compliance
controls, with no error, warning, or log. No user-visible signal exists in
any state, so the current posture is not fail closed. The release notes say
the same thing, so the shipped artifact does not imply a fail-closed posture
it does not have (`CHANGELOG.md:36-40`). Before any future PAC adoption, the
implementation must provide a testable, non-lookup signal for a
caller-supplied PAC/system source: a documented diagnostic event emitted
before any request can send must identify the refused source, and a fixture
must assert that event and zero direct sends. Platform lookup remains
refused, so this record does not claim detection of ambient platform
settings. Adoption is blocked until that criterion is implemented and
tested; the future unevaluable-PAC path must still fail closed.

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
constant display text `network offline` on the base
(`bitty-network-api/src/lib.rs:271, 294`) and on the merged state
(`:271, 290`), and it is already a catch-all for capability denial,
malformed headers, a rejected proxy URL, and non-timeout transport failures.
That is what makes the carrier problem real, and the unit-variant part of it
survives the integration branch unchanged — which is why
`offline_stays_a_unit_variant_with_a_constant_display` pins it: if `Offline`
ever gains a payload or a dynamic message, this open point has to be
revisited before a PAC slice relies on it. It cannot by itself make these
four post-source cases distinguishable.

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
merged state and the base map such a later 407 to generic
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
  variants on the merged state (`bitty-network-api/src/lib.rs:264-284`) and
  **five** on the base, which adds `CountBudget` (`:284-287`) — unmerged. A
  separate API decision owned by CTX-0022 must choose a compatible carrier
  outside that taxonomy, or explicitly amend the taxonomy in a scoped task;
  whichever it picks, it must be written against the base's five-variant
  shape, because that is the base any implementation will start from. Until
  that decision lands, the named cases are indistinguishable through
  `NetworkError::Offline` and no implementation may claim that it provides
  them.
- **Open point — stale sibling pin (not fixable in this record).**
  `docs/decisions/30-bridge.md:29` still names the taxonomy as
  `Offline`/`Denied`/`Timeout`/`Budget`, which is correct for the merged
  state and stale for the base. Correcting it is a `30-bridge.md` edit and
  outside this record's scope; it is recorded here so the next task to touch
  the taxonomy owns both files.
- No URL, path, or file content from a PAC source is retained or
  logged. A PAC URL can carry userinfo, so the rule that keeps
  credential-bearing proxy URLs out of logs applies to every string
  read from that source. The existing redaction control is
  `redacted_url` (`diagnostics.rs:49`), which drops userinfo, query, and
  fragment and is applied when a URL enters a diagnostic snapshot
  (`diagnostics.rs:183`).
- Construction must remain `Result`-shaped on the existing split once
  a source is implemented: an explicitly requested unevaluable source
  returns the typed error to the caller, while an ambient source
  degrades the service to fail-closed for every request. Neither the base
  nor the merged state has that shape — `HttpNetworkService::new` returns
  `Self` in both (`http.rs:314` on the base, `http.rs:149` on the merged
  state) — so this is a target contract, not a claim about either API.

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
entirely on the merged state; the base supplies it as
`validated_proxy_url` (`http.rs:807-812`, unmerged), pinned by
`proxy_injection_stays_inside_the_named_construction_paths` and
`credential_check_precedes_proxy_injection_on_the_explicit_path`, and a
future PAC evaluator must call that same function. The gate commit supplies
the feature gate, not credential validation.

A PAC is never a credential source: nothing it returns satisfies a proxy
challenge, and credential storage and rotation stay out of scope here
(CTX-0033). A credential-free PAC-selected proxy can issue HTTP 407 only
after the request is sent. That separate `proxy-challenge-407` event is
not predictable before dialing; both the merged state and the base map the
later challenge to generic `NetworkError::Offline`, while a future
diagnostic carrier must map it distinctly from `pac-url-userinfo`.

## `no_proxy()` interaction

Ambient discovery must stay off. It is off on the base and still on in the
merged state.

**Coverage is complete on the base, and absent in the merged state.** Every
reqwest client in the crate is built in `http.rs`, and all three builder
chains call `.no_proxy()` before any route is added: `http.rs:380` in
`client_with`, `http.rs:829` in `proxy_client`, and `http.rs:847` in
`proxy_route_client`. `websocket.rs` builds no reqwest client at all, so
there is no second construction path to cover. One test pins this:
`tests/pac_decision_pins.rs::every_client_construction_site_disables_ambient_discovery`
walks every `Client::builder()` chain in every module of the crate, fails if
an unconfigured `Client::new()`, `Client::default()`, or
`ClientBuilder::new()` appears anywhere, bans the `unwrap_or_else` fallback,
and runs in all three CI legs. It replaces the narrower
`tests/http.rs::every_client_builder_disables_ambient_proxy_and_redirects`,
which covered the same two builder-chain assertions and the same three
constructors over `http.rs` alone and ran in two of the three legs; the
duplicate is deleted so one scanner owns the property. The pin is not
vacuous: the pinned reqwest build omits its `system-proxy` feature, so
`.no_proxy()` has no observable runtime effect here and no behavioural test
can fail when it is dropped, and the pin asserts it found at least one
builder chain rather than passing over an empty scan. All of this is
unmerged.

In the merged state the two builder chains (`http.rs:210`, `http.rs:438`)
call neither `.no_proxy()` nor `Policy::none()`, and `origin/main` contains
no `.no_proxy()` call anywhere in `crates/`. It therefore builds its clients
with reqwest's default `auto_sys_proxy = true`, and a failed build falls
back to an unconfigured `Client::new()` (`http.rs:216`), which is the same
exposure by a second route.

**Why the feature graph does not save the merged state.** In reqwest 0.13.5
(`crates/bitty-network/Cargo.toml:26`, default features off), `ClientBuilder`
defaults `auto_sys_proxy` to `true` (`async_impl/client.rs:310`) and `build`
pushes `ProxyMatcher::system()` whenever that flag is set
(`async_impl/client.rs:417-418`); `Proxy::system()` calls
`matcher::Matcher::from_system()` (`proxy.rs:517`). hyper-util 0.1.20's
`Builder::from_system()` calls `Self::from_env()` first, unconditionally
(`matcher.rs:238-240`), and its `client-proxy-system` feature gates **only**
the macOS and Windows lookups (`matcher.rs:242-246`). `from_env` reads
`ALL_PROXY`/`all_proxy`, `HTTP_PROXY`/`http_proxy`,
`HTTPS_PROXY`/`https_proxy`, and `NO_PROXY`/`no_proxy`
(`matcher.rs:231-234`) plus `REQUEST_METHOD` for CGI detection
(`matcher.rs:230`).

The negative is non-vacuous, and was re-checked on the base:
`cargo tree --locked --features http` resolves hyper-util's `client-proxy`
but **not** `client-proxy-system`, and `system-configuration` and
`windows-registry` appear nowhere in `Cargo.lock`. So on the merged state
reqwest can silently inherit `ALL_PROXY`, `HTTP_PROXY`, and `HTTPS_PROXY`
with their lowercase forms and honor `NO_PROXY`/`no_proxy`, with no
credential check anywhere in the crate, while this crate's own reader
handles only `HTTPS_PROXY`. The absent `system-proxy` feature does not
disable environment inheritance. On the merged state this record must not
claim that exposure is closed.

Rules for any future system/PAC work:

- **One injection point.** Every proxy URL, whatever its source, must
  pass through one shared validation function: reject userinfo, then
  parse, then build the `reqwest::Proxy`. A PAC evaluator produces a URL
  and hands it to that function. It gets no second path, and never
  builds a client first to validate later. The merged state has no such
  function at all; the base supplies it as `validated_proxy_url`
  (`http.rs:807-812`, unmerged) for the existing explicit and
  environment paths, and a future PAC evaluator must call it. Pinned by
  `proxy_injection_stays_inside_the_named_construction_paths`.
- **Discovery stays off.** Every client builder in a landed
  implementation must call `.no_proxy()` before adding a selected route.
  On the base that is already true on 3 of 3 chains; in the merged state
  it is true on 0 of 2. A PAC evaluator does not change this. Reading a
  PAC file is reading a file; letting reqwest discover a platform proxy is
  a different, unvalidated route. Only the PAC source is ever revisited;
  platform discovery remains refused. Pinned by
  `every_client_construction_site_disables_ambient_discovery`.
- **The gate is not the control.** `.no_proxy()` and the credential
  check are separate controls, and neither is the `proxy` feature. That
  feature decides whether tier 2 is consulted at all; it is never a reason
  to re-enable discovery. On the base the two are independent and both
  present: the base supplies `.no_proxy()` and the credential check, and the
  gate commit `29a66b1` supplies the gate alone, on top of that same base,
  so after it lands the gate is the only thing it contributes. None of the
  three is merged.
- **Regression guard.** A PAC slice ships tests pinning that ambient
  environment and platform configuration cannot influence the selected
  client, and a review that finds discovery re-enabled returns a
  security defect, not a feature request.
  `every_client_construction_site_disables_ambient_discovery` already pins
  the client-builder half on the base, at crate scope and in every CI leg;
  the ambient half still needs the tier-2 gate to be meaningful, and the
  crate-wide pins above must stay green when it lands.

## What this record does not authorize

No PAC code, no platform lookup, no new dependency, and no merge of the
integration branch or of the gate commit `29a66b1`. PR #44 stays open and
unmerged; the base and the rest of the integration branch are reviewed but
not in `origin/main`, and this record does not turn any base control into a
merged guarantee. Issue #24 stays open: this is its decision half only, and
the implementation half (fixture-proxied precedence tests for tiers 1 and 2)
is a separate scoped task.

Revisit criteria, all required before a PAC slice may start:

1. `deny.toml` approval for the proposed engine, with an MSRV-1.85
   and `#![forbid(unsafe_code)]` analysis of its tree.
2. A security-corpus review of executing an ambient, operator-supplied
   program on every connection decision.
3. A separate API decision owned by CTX-0022, the planned PAC
   implementation lane for #24, resolving the diagnostic carrier for the
   four post-source reasons plus `pac-url-userinfo` without silently
   changing the public taxonomy. That taxonomy is four variants in
   `origin/main` and five on the base, which adds `CountBudget`
   (`bitty-network-api/src/lib.rs:284-287`); the decision must be written
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
   already mechanically pinned, at crate scope and in every CI leg, by
   `crates/bitty-network/tests/pac_decision_pins.rs`; the
   slice must extend those pins rather than assume them, and must keep them
   green once the tier-2 gate lands.
7. PR #44 merged, so that the tier-1 credential check, the fail-closed
   environment rejection, the `HTTP_PROXY`/`ALL_PROXY` fan-out, and the
   `.no_proxy()` coverage this record relies on are actually in
   `origin/main`. Until then every one of them is unmerged, and a PAC
   slice must not be scoped as though they were.

## Acceptance

- `just check`, `just check-http`, `just check-websocket`, and
  `just typecheck` pass: the only code change is a new test file, so the
  gates confirm the pins are green and nothing else moved.
- `gitleaks detect --source .` clean.
- The base pin reproduces: `git rev-parse integrate/lanes-abc
ctx-0034/fix-proxy-feature-gate origin/main` prints the three commits
  in the base-pin table. A reviewer who finds a different value knows
  exactly which claim classes to re-verify — the base-scoped and
  divergence-scoped lists — and does not have to audit a provenance table.
- Every pinned property above has a named test that fails when the property
  is broken; a test that cannot fail is treated as a defect, not as
  coverage.
- A reviewer re-checking a base-scoped or divergence-scoped fact reaches
  the same conclusion with `git grep`/`git show` at the named commit and
  `file:line`.
- Give each checkout of this tree its own `CARGO_TARGET_DIR`. Cargo keys a
  path package by its workspace-relative path, so two checkouts of the same
  tree sharing one target directory collide on the same unit-graph key and the
  second build fails over artifacts it did not produce. That is a false red:
  re-run the gate with a target directory of its own before reading it as a
  real failure.
