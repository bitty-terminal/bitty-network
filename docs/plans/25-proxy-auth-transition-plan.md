# #25: authenticated proxy transition plan

Status: planning only. This document is a plan, not a decision, and it grants
no implementation authorization.

Authority: `docs/decisions/25-proxy-auth.md` (the "record"). Where this
document and the record differ, the record is correct and this document is
wrong. Nothing here revises a requirement, weakens a criterion, or accepts the
record. The record's fail-closed rejection of credential-bearing proxy URLs
stays in force, and issue #25 stays open, until the record's own transition
criteria are met, independently reviewed, and only then changed by a later
task.

Base: the merged `origin/main` at `5d98440`. Every current-state statement
below is scoped to that commit. Citations use the record's symbol form
`` `path::anchor` ``; no line numbers are used anywhere in this document.

## Purpose and scope

The record defines the required design for authenticated proxies and states
fourteen transition criteria. This document answers three questions the record
deliberately leaves to an implementation:

1. For each criterion, what is the concrete code change, what test proves it,
   which executable property pin it interacts with, and in what order it lands.
2. Which criteria are independent and which are strictly ordered, and why.
3. Whether the two load-bearing orderings the record defers are actually
   realizable — where credential resolution sits relative to the single
   injection point, and whether a rotated generation can be kept out of a
   request that already passed the authorization boundary.

### Why this file is not under `docs/decisions/`

This repository has one document tree, `docs/decisions/`, and everything in it
is a decision. A transition plan is not a decision, and the record is explicit
that a draft, a plan, or a passing fixture does not lift its gate. Filing a
plan next to the records would invite exactly the confusion the record warns
against, so the plan lives in its own tree and says at its own head that it
grants no authorization. Nothing in `docs/decisions/` changes.

Out of scope: selecting an authentication protocol, authorizing a dependency,
changing the record, enabling an authenticated proxy path, or implementing
anything. The record states that protocol selection and confidential transport
are a separate implementation decision, and that if no such transport exists,
authenticated proxies remain unsupported. This plan does not pre-approve that
decision either.

## What is actually true today

Stated from the working tree, not from the record's inventory, so the plan's
starting point is checked rather than inherited.

Present and usable:

- `crates/bitty-network/src/http.rs::fn client_with(proxy: Option<reqwest::Proxy>) -> Option<reqwest::blocking::Client>`
  already builds every reqwest client with `.no_proxy()` and
  `.redirect(reqwest::redirect::Policy::none())`, as do
  `crates/bitty-network/src/http.rs::fn proxy_client(url: &str) -> Option<reqwest::blocking::Client>`
  and
  `crates/bitty-network/src/http.rs::fn proxy_route_client(route: &ProxyRoute) -> Option<reqwest::blocking::Client>`.
  Automatic client redirects are therefore already off everywhere, and
  `crates/bitty-network/tests/http.rs::fn every_client_builder_disables_ambient_proxy_and_redirects() {`
  holds that.
- `crates/bitty-network/src/http.rs::fn proxy_url_has_credentials(url: &str) -> bool {`
  plus the guards in
  `crates/bitty-network/src/http.rs::fn validated_proxy_url(` and
  `crates/bitty-network/src/http.rs::fn proxy_client(url: &str) -> Option<reqwest::blocking::Client> {`
  reject proxy-URL userinfo before any `Proxy::all`, `.proxy()`, or client
  build, on the explicit and the environment path.
- `crates/bitty-network/src/http.rs::fn send(&self, request: &Request) -> Result<Response, NetworkError> {`
  is an owned redirect loop bounded by
  `crates/bitty-network/src/http.rs::pub const MAX_REDIRECT_HOPS: usize = 5;`
  and the request deadline, and it strips caller headers on a destination-origin
  change via
  `crates/bitty-network/src/http.rs::fn strip_cross_origin_headers(headers: &mut Vec<(String, String)>)`
  gated by `crates/bitty-network/src/http.rs::fn same_origin(first: &str, second: &str) -> bool {`.
- `crates/bitty-network/src/websocket.rs::fn tunnel_via_proxy(` writes a
  `CONNECT` line built from
  `crates/bitty-network/src/websocket.rs::fn format_authority(host: &str, port: u16) -> String {`
  and carries no credential, and
  `crates/bitty-network/src/websocket.rs::fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), NetworkError> {`
  rejects userinfo in the authority.

Absent, and load-bearing for this plan:

- **Response provenance is not tracked anywhere.** In
  `crates/bitty-network/src/http.rs::fn send(&self, request: &Request) -> Result<Response, NetworkError> {`
  a `3xx` is followed whenever a `location` header is present. Nothing records
  whether the response came from the destination or from the proxy. This is the
  direct cause of the P1-to-P2 leak path below.
- **Header stripping has no proxy term.** The condition in
  `crates/bitty-network/src/http.rs::fn send(&self, request: &Request) -> Result<Response, NetworkError> {`
  is a destination comparison only. A hop that keeps the same destination and
  moves to a different forward proxy keeps `Authorization`, `Cookie`, and
  `Proxy-Authorization`.
- **Origin matching is not canonicalization.**
  `crates/bitty-network/src/http.rs::fn same_origin(first: &str, second: &str) -> bool {`
  is built from `Request::host()` and `Request::port()`, and
  `crates/bitty-network/src/http.rs::fn resolve_redirect(hop_url: &str, location: &str) -> String {`
  is string surgery. Neither is an origin type.
- **The proxy default port is decided by a transport boolean.**
  `crates/bitty-network/src/websocket.rs::fn tunnel_via_proxy(` accepts only an
  `http` proxy scheme and then calls
  `crates/bitty-network/src/websocket.rs::fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), NetworkError> {`
  with a literal `80`. An `https` proxy without an explicit port is rejected
  rather than canonicalized to 443.
- **No pool identity exists.**
  `crates/bitty-network/src/http.rs::struct Egress {` holds one shared
  `reqwest::blocking::Client` per route, and
  `crates/bitty-network/src/http.rs::struct ProxyRoute {` holds one client for
  the whole route. There is no key, no generation, no scope epoch, and no
  lease; the only reuse decision in the tree is
  `crates/bitty-network/src/http.rs::fn client_for(&self, url: &str, host: &str) -> Option<&reqwest::blocking::Client>`,
  which switches on the proxy decision alone.
- **The diagnostic constructors are unwired.**
  `crates/bitty-network/src/diagnostics.rs::pub fn redacted_url(url: &str) -> String {`
  and its siblings have no caller in either backend.
- **The API vocabulary types leak.** `Request`, `WebSocketRequest`, and
  `Response` (`crates/bitty-network-api/src/lib.rs::pub struct Request {`,
  `crates/bitty-network-api/src/lib.rs::pub struct WebSocketRequest {`,
  `crates/bitty-network-api/src/lib.rs::pub struct Response {`) all derive
  `Debug` and `PartialEq`, and `crates/bitty-network-api/src/lib.rs::pub enum NetworkError {`
  has a `Denied` variant carrying a raw `domain: String` that both `Debug` and
  `Display` echo.

## Criterion-by-criterion plan

Each entry names the code change, the test that proves it, the pin it touches,
and its position in the order. "New" tests are additions to
`crates/bitty-network/tests/proxy_credential_policy.rs` and the backend test
modules unless stated otherwise.

### 1. Independent acceptance records this decision and updates its status

No code. Independent acceptance of the record, then a status edit in the record
itself. This is the only criterion that can be worked now, and it does not
enable anything: acceptance is a precondition for the implementation task, not
a substitute for it.

Pins: none. Order: first, alone.

### 2. A separately scoped implementation supplies the eight mechanisms

This is the umbrella criterion. It splits into the ordered work below, and each
part is claimed by the criterion that tests it:

| Mechanism                  | Where it must live                                                                                                     | Tested by |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------- | --------- |
| single provider handle     | a provider trait in `bitty-network`, installed on the service at construction; the API crate stays implementation-free | 11, 12b   |
| `CanonicalOrigin`          | one new module, one parser, one closed port table                                                                      | 4         |
| injection boundary         | one `proxy` module function, called by both backends                                                                   | 5, 6, 12b |
| redirect owner             | the existing owned loop in `send`, extended                                                                            | 5, 6      |
| scope registry             | one owner behind the service, not a service field                                                                      | 7, 8      |
| lease protocol             | one lease type plus its guard discipline                                                                               | 7, 9      |
| remote-revocation protocol | one evidence type, provider-supplied                                                                                   | 10        |
| redaction boundary         | hand-written `Debug` on every credential-bearing type                                                                  | 12        |

Pins: `every_citation_in_the_record_names_a_symbol_that_exists` fails the moment
any of the record's `tree::[absent]` identifiers appears in `crates/`. See
[Property pins this plan would move](#property-pins-this-plan-would-move).

### 3. Baseline and permanent-rejection tests

Most of this already exists and is pinned. The gaps to close:

- Malformed environment proxy configuration failing the service closed is
  implemented (`crates/bitty-network/src/http.rs::fn ensure_proxy_usable(&self) -> Result<(), NetworkError> {`)
  but is not covered by a pin. Add an explicit test that an unparseable
  `HTTPS_PROXY` yields a service whose every request fails closed and whose
  service retains no URL, and that no fallback to direct egress occurs.
- `crates/bitty-network/src/http.rs::pub fn with_proxy(` returning a typed failure
  before retaining or dialing is implemented but not pinned. Add coverage
  alongside the existing `explicit_credentialed_proxy_is_rejected_without_exposed_secret`.
- WebSocket rejection before proxy or destination dialing is implemented and
  named in
  `crates/bitty-network/src/websocket.rs::fn authenticated_proxy_is_rejected_before_dial() {`.

Pins: this criterion is the regression suite for
`credentialed_proxy_url_never_reaches_proxy_construction`, which must keep
passing unchanged. Order: before any credential code, always.

### 4. Canonicalization tests

Add one `CanonicalOrigin` type with a structured parser, IDNA and IP-literal
normalization, and a closed four-entry default-port table
(`http`/`ws` -> 80, `https`/`wss` -> 443). Replace every ad-hoc origin
computation with it: `same_origin`, `resolve_redirect`'s output, the
`Request::host()`/`Request::port()` pair behind the origin comparison, and the
literal `80` default in `tunnel_via_proxy`.

Tests, all new: `http` proxy absent port is 80; `https` proxy absent port is
443; explicit default ports equal absent ones; all four destination schemes
across absent, explicit-default, and non-default ports; mixed-case scheme and
host; equivalent Unicode and IDNA host forms; IPv4; IPv6; a percent-encoded
authority delimiter failing closed; and a WebSocket destination retaining `ws`
versus `wss` so the TLS boolean is derived only after canonicalization.

Pins: none move. The important property is that this lands **before**
authorization, for the reason given in
[Leak path 5](#leak-path-5-default-port-normalization-for-proxy-and-destination).

### 5. Redirect tests

Changes, all inside the existing owned loop:

- Track response provenance. A `3xx` is admissible only when it arrived inside
  an established `CONNECT` tunnel. A `3xx` on a forward-proxied plain-HTTP leg
  is rejected before redirect processing, because the transport cannot prove it
  came from the destination.
- Add the proxy term to the stripping condition: strip `Authorization`,
  `Cookie`, and `Proxy-Authorization` when the destination origin _or the proxy
  origin_ changes, and rebuild host headers.
- On every hop: reevaluate `NO_PROXY`, re-select the route, canonicalize,
  resolve a fresh record snapshot, take a fresh scope epoch, generation, lease,
  and attachment, and discard the prior attachment, client, pooled connection,
  and tunnel.
- Constrain path-only reuse to the exact current pool key plus a current lease.
- Reject caller-supplied `Proxy-Authorization` before dispatch, at the API
  boundary, so the header can only ever be produced by the injection point.

Tests, all new: a proxy-origin-only change to a different forward proxy strips
all three headers (today it does not); a followed hop inside a tunnel obtains
fresh scope and authorization; path-only reuse is refused for a stale key;
`NO_PROXY` is reevaluated per hop; ambiguous provenance fails closed.

Pins: `every_client_builder_disables_ambient_proxy_and_redirects` must keep
passing. Order: after 4 and 7, because reuse is expressed in the pool key.

### 6. Proxy-redirect tests

Changes: the provenance rule from criterion 5, plus a hard refusal to follow
any `Location` that arrives on a proxy leg, including a `CONNECT` response and
a forward-proxy response outside a tunnel. Nothing is copied to `P2`: no
attachment, no client, no connection, no header, no lease.

Tests, all new, with a loopback `P1` and `P2`: a `302` from `P1` is refused
and `P2` records zero hits; a `CONNECT` response carrying a `3xx` is refused
and no tunnel opens; a forward-proxy `3xx` outside a tunnel is refused; and a
`tunnel`-internal `3xx` is followed without any attachment crossing the hop.

Pins: none. Order: with 5, immediately after it.

### 7. Pool tests

Changes: one scope registry owner; one structured five-field pool key (proxy
origin, destination origin, credential-record identity, generation, scope
epoch); checkout that revalidates every key field and takes a lease under the
read-side guard before a connection is usable; invalidation under the exclusive
guard that marks the key inactive, removes it from lookup, cancels leases,
closes every owned client, connection, and tunnel, and waits for release.
Replace the single shared client in `Egress` and `ProxyRoute` with
registry-owned, scope-keyed clients.

Tests, all new, concurrent: a connection is unusable without a current lease;
pools never reuse across differing proxy origin, destination origin, record
identity, generation, or scope epoch; **two distinct records with equal
generation and equal scope epoch still get distinct pools and no object crosses
between them**; checkout failure never falls back to another pool; and a thread
waiting in checkout either takes a lease on the new key or fails closed.

Pins: none directly, but every later criterion is expressed in this key. Order:
after 4, before 5, 8, and 9.

### 8. Scope tests

Changes: an allowed-destination snapshot is immutable after publication;
any addition, removal, or replacement publishes a new snapshot with a new scope
epoch and invalidates every object built from the old one before the wider
scope is usable. Selection never combines destinations from two snapshots and
never falls back to an earlier scope. No wildcard, suffix match, ambient
default, or "same host as the request" shortcut.

Tests, all new: publish `{A}` and prove its attachment, client, pool,
connection, and tunnel cannot serve `B`; publish `{A,B}` with a new epoch and
prove every old object was invalidated before `B` was reached; prove a stale
epoch fails closed; prove a wildcard and a suffix match are refused.

Pins: none. Order: after 7; it is invalidation expressed in the pool key.

### 9. In-flight rotation tests

Changes: the check-and-write guard discipline described in
[Ordering question 2](#ordering-question-2-can-a-rotated-generation-be-kept-out-of-a-request-that-already-crossed-the-boundary).
Long-lived tunnel and protocol writers hold a lease for their lifetime and
revalidate before every write. Rotation enters a draining state that prevents
new leases, cancels old leases, closes old clients, connections, and tunnels,
and waits for bounded shutdown; a shutdown timeout faults authenticated proxy
use and does not activate the replacement.

Tests, all new: synchronize a request after it acquires generation `G` and
before its final write, rotate while it is paused, and prove no `G` write
occurs after rotation completion; the same for a tunnel writer; cancellation;
close-and-wait; shutdown timeout faulting closed; and no fallback reopening on
any failure path.

Pins: none. Order: after 7 (leases must exist) and before 10 (activation is
gated on it).

### 10. Remote-revocation tests

Changes: a provider-supplied revocation operation whose confirmation is bound
to the canonical proxy origin and the old credential identifier, and which
proves session termination or an authenticated current inventory showing no
remaining session, plus rejection of the old credential and acceptance of the
replacement, with no secret in evidence. Activation is refused unless that
proof holds.

Tests, all new, against a loopback fixture: the new generation stays staged and
unusable while the old credential is accepted; **a fresh authentication
rejection with no session-termination proof is refused**; a stale, ambiguous,
partial, negative, or missing confirmation leaves authenticated proxy use
disabled; a proxy with no revocation or expiry operation leaves it disabled; and
a valid confirmation permits activation. A passing fixture must not be
satisfiable as a revocation signal.

Pins: none. Order: last of the credential criteria.

**This criterion may be unsatisfiable against a real proxy, and the plan says
so now rather than discovering it later.** If the selected proxy offers no
revocation or expiry operation, or no authenticated confirmation signal, the
correct outcome is that authenticated proxy use stays disabled — not that the
criterion is relaxed. See
[Criterion 10 is a possible dead end](#criterion-10-is-a-possible-dead-end).

### 11. `NO_PROXY` and provider tests

Changes: bypass is decided before any provider call. A bypassed request uses
direct egress and constructs, checks out, or carries no proxy authorization,
client, connection, or tunnel. Non-bypass resolution reads the provider exactly
once per hop and selects exactly one current record. Malformed proxy
configuration is never ignored. No path falls back to direct or unauthenticated
egress.

Tests, all new: a bypassed request makes zero provider calls and sends no
proxy credential; non-bypass resolves exactly one current record; every redirect
reevaluates bypass; a malformed proxy variable fails the service closed rather
than being ignored; and no failure path reaches direct or unauthenticated
egress.

Pins: the environment half of
`credentialed_proxy_url_never_reaches_proxy_construction` is the regression
evidence. Order: before the injection point exists, so that "bypass precedes
resolution" is true by construction.

### 12. Redaction tests

This criterion splits, because its two halves have different dependencies.

**12a, API vocabulary — independent of every credential mechanism.** Add
hand-written redacting `Debug` for `Request`, `WebSocketRequest`, and
`Response`; keep `PartialEq`/`Eq` (permitted only alongside a redacting
`Debug`); give `NetworkError` a redacting `Debug` and `Display` so the
`Denied` domain is not echoed raw, and decide explicitly whether a credential-
bearing error type carries a `source` chain at all. Wire the existing
`diagnostics` constructors into both backends' error paths. Replace the
raw-URL-in-assertion-message patterns in the HTTP integration tests with
redacted structural assertions.

Pins: **this moves
`api_vocabulary_types_still_derive_debug_and_equality_and_still_leak`**, in both
directions — see the pin section. Order: any time; it is the one criterion
that can complete without the credential implementation.

**12b, credential-bearing types — depends on 2.** Hand-written redacting
`Debug` on the provider handle, record, snapshot, attachment, lease, client,
pool, connection, and tunnel wrappers, and the revocation evidence. No
`Serialize`/`Deserialize` on any of them; sanitized projections statically
shaped with no `#[serde(flatten)]` and no dynamic map. No `expect`, `unwrap`,
or `panic!` on credential paths; third-party errors mapped immediately to
caller-safe variants with no retained source whose chain can hold a URL or
header. Traces and metrics, if those dependencies are ever added, use static
allowlists with no origin, host, identifier, generation, or epoch as a label.

Tests, all new: distinct username, password, URL, header, generation, and
scope-epoch canaries absent from `Debug`, `Display`, source chains, panic
output, child-process output, and crash output; a deliberately triggered failed
equality assertion in a child process, since the record requires that coverage
and nothing triggers one today; `dbg!` and snapshot scans; and, if tracing or
metrics land, an in-memory exporter scan.

Order: after 2, before 13.

### 13. Repository-owned recipes and secret scan

Run `just check`, `just check-http`, `just check-websocket`, `just typecheck`,
and `just actionlint`; the HTTP and WebSocket feature recipes are mandatory.
Run `gitleaks detect --source .` and remove task-created target directories.

Pins: this is where every pin is exercised. **This criterion is not currently
satisfiable** — see [Prerequisite: the gate is red on `origin/main`](#prerequisite-the-gate-is-red-on-originmain).

### 14. Independent implementation security review

An independent reviewer, not the implementer, finds no unresolved blocking
issue. Only a later task may then change the record's status or enable an
authenticated proxy path. This plan is not that review and does not satisfy
it.

## Sequencing

### Independent

- **Criterion 1** is independent of all code and comes first.
- **Criterion 3** is independent of the credential work and must precede it:
  it is the baseline that proves the permanent rejection still holds.
- **Criterion 4** is independent of the provider, registry, lease, and
  revocation work. It is pure parsing and a closed table.
- **Criterion 12a** is independent of every credential mechanism. Closing the
  API-vocabulary leak needs no credential to exist.
- **Criterion 13** and **criterion 14** are independent of each other only in
  the sense that 14 follows 13; neither can start early.

Criteria 4, 3, and 12a can be developed in parallel, and none of them
invalidates a pin except 12a, which deliberately moves one.

### Strictly ordered, and why each edge is load-bearing

| Edge                                   | Reason it is a security ordering, not a cosmetic one                                                                                                                                                                                |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 -> everything                        | acceptance is the precondition for a scoped implementation task existing                                                                                                                                                            |
| 3 -> 2                                 | the baseline rejection must be proven before anything is allowed near a proxy leg                                                                                                                                                   |
| 4 -> 2                                 | authorization compares origins. A non-canonical origin makes the _same_ record match under one path and not another, so a credential scoped to one port becomes usable against a port the operator never approved. See leak path 5. |
| 11 -> 2                                | bypass must precede resolution, or a bypassed request constructs provider state                                                                                                                                                     |
| 2 (registry, key, lease) -> 5, 6, 8, 9 | every one of those criteria is expressed in the pool key or the lease. A redirect cannot "reuse only a connection from that exact pool key" before a pool key exists.                                                               |
| 5 -> 6                                 | provenance rejection happens inside the owned redirect loop                                                                                                                                                                         |
| 7 -> 8                                 | scope widening is invalidation of key-bound objects                                                                                                                                                                                 |
| 7 -> 9                                 | a rotation guard needs a lease to guard                                                                                                                                                                                             |
| 9 -> 10                                | activation is gated on rotation completion semantics                                                                                                                                                                                |
| 2, 5-10, 12 -> 13 -> 14                | the gates, then the independent review                                                                                                                                                                                              |

The spine:

```
                                     1  (acceptance)
                                      |
             +-------------+-----------+-----------+
             |             |                       |
             3             4                       12a
  baseline    canonical-    API vocabulary
  rejection   ization       redaction
             |             |                       |
             +-------------+-----------+-----------+
                                      |
                                      v
                       11  bypass decided before resolution
                                      |
                                      v
                    2   provider + registry + pool key + lease
                                      |
                                      v
                    7   pool key, lease, invalidation
                                      |
                                      v
                    5   redirects  ->  6  proxy-redirect refusal
                                      |
                                      v
                    8   scope epoch
                                      |
                                      v
                    9   in-flight rotation
                                      |
                                      v
                   10   zero-overlap remote revocation
                                      |
                                      v
                   12b  credential-type redaction
                                      |
                                      v
                    13  gates  ->  14  independent review
```

The edges that carry the most security weight are 4 -> 2, 2 -> 7, and 7 -> 9.
The first decides whether a scope means anything; the second decides whether
any object is identity-bearing at all; the third is the only thing standing
between a rotated credential and an in-flight request.

## Ordering question 1: where does credential resolution sit?

**Resolution sits immediately upstream of the single injection point, inside
the same module, and neither backend ever sees the provider.**

The record fixes both ends. It requires exactly one wire-injection point that
"runs after capability checks, final route selection, redirect processing, and
canonical-origin normalization, but immediately before the first byte of the
proxy leg is sent", and it requires that "neither backend may read the
provider, parse proxy userinfo, construct an authentication header, or
implement fallback lookup on its own". Those two constraints together leave
exactly one shape:

```
backend
  capability check
  -> NO_PROXY bypass decision          (criterion 11: before any provider call)
  -> final route selection              (which proxy, if any)
  -> canonical-origin normalization     (criterion 4: one origin type)
  -> proxy::authorize_leg(...)          <- resolution happens HERE, in the proxy
  |     - reload the current record snapshot from the provider
  |     - check binding 1: proxy origin == record proxy origin
  |     - check binding 2: destination origin in snapshot's allowed set
  |     - check generation and scope epoch are current
  |     - call proxy::inject_authorization(...)   <- THE one injection point
  |     - take a lease bound to proxy origin + destination origin +
  |       record identity + generation + scope epoch
  -> first byte of the proxy leg
```

The resolution step is _not_ the injection point, and the distinction matters:
`inject_authorization` is handed the proxy origin, destination origin, transport
kind, generation, scope epoch, and record-snapshot identity, and returns the
opaque attachment bound to all of them. It does not look anything up. That is
what keeps "exactly one implementation point" true — header construction lives
in exactly one function — while the provider read lives in exactly one other
function, and neither is in a backend.

Both backends call `authorize_leg`, never `inject_authorization` directly, and
never the provider. `tunnel_via_proxy` and `send` are structurally symmetric at
this boundary, which is the only way the record's "exactly one implementation
point because proxy authentication is a property of the selected proxy route"
claim survives contact with two backends.

**The credential is scoped to both origins by construction, not by check.** The
scope snapshot is a set of `CanonicalOrigin` destinations, and the lease's pool
key contains both the proxy origin and the destination origin. A credential
resolved for `proxy:8080` + `destination:443` produces an attachment that is
unusable for `proxy:8080` + `destination:8443`, and unusable for
`proxy:9090` + `destination:443`, because either change changes the pool key
and the key is the only way to reach a connection.

**One trap this shape must avoid.** The injection point sits immediately before
the first proxy byte, so on the HTTP leg the attachment has to be attached to
the request at the last possible moment. Two implementations are wrong:

- _Embedding the credential in the reqwest client_ — for example a proxy
  constructed with basic auth. The client is long-lived, so it keeps emitting
  the old credential after rotation completes, which is a direct violation of
  "once rotation reports completion, no old-generation credential or attachment
  can be selected, checked out, or written". The credential must not live in a
  client.
- _Leaving it in the caller's header list_ where a direct-egress branch could
  send it to the origin. Hence the API boundary must reject a caller-supplied
  `Proxy-Authorization` outright, and the attachment is added only on the
  proxied branch.

## Ordering question 2: can a rotated generation be kept out of an in-flight request?

**Stated without hedging: the local guard discipline the record requires is
achievable, and it is achievable on both legs, but it is not achievable with
`reqwest` owning the HTTP socket. And physical network atomicity — the guarantee
that the remote proxy has not seen old-generation bytes when rotation reports
completion — is not achievable at all, is not claimed here, and is not claimed
by the record.**

Three separate claims, kept apart because conflating them is exactly how this
kind of plan fails review.

### What is achievable: a real local linearization

The record's requirement is a _local_ linearization: the writer takes a shared
guard, revalidates, and writes only while holding it; rotation takes the
exclusive guard and publishes retirement only after waiting. Given that, a
writer either acquired the guard before rotation's exclusive section — in which
case its write completes inside the critical section and rotation's close-and-
wait must wait for it — or rotation's exclusive section came first, in which
case the writer's revalidation fails and no write begins. There is no third
case. That is a genuine mutual-exclusion proof, and it is implementable.

**On the WebSocket `CONNECT` leg this is straightforward**, because
`bitty-network` owns the socket and performs the write itself. Hold the shared
guard across the `CONNECT` write and the transport flush, and the proof holds
exactly as stated.

**On the HTTP leg it is not straightforward, and the reason is worth stating
precisely.** `reqwest::blocking` performs the proxy write inside its own
`send()` call. No API exposes a hook that runs under a caller-held guard
immediately before the first byte of the proxy leg. So there are exactly two
honest options, and the plan takes the second:

- **Hold the lease across `send()`.** This does produce a local linearization,
  and it is stronger on the write than required. Its cost is that the critical
  section now spans the entire transaction including the response read, bounded
  by the request deadline rather than by a write. Rotation's bounded shutdown
  would then time out whenever an HTTP request is in flight and **fault
  authenticated proxy use closed**, which is fail-closed and permitted by the
  record, but it means rotation effectively cannot complete under load. That is
  a bad property to ship deliberately.
- **Move the authenticated HTTP proxy leg onto a `bitty-network`-owned socket**
  — an absolute-form request to a plain-HTTP forward proxy, or a `CONNECT`
  tunnel for `https` — so both backends apply one identical guard discipline
  and there is genuinely one injection point with one behaviour. This is the
  only option that gives the uniform guarantee, and it is the one this plan
  selects. It costs a substantial amount of new transport code and new
  supply-chain surface, which is a reason it needs its own scoped task and its
  own security review, not a reason to soften the criterion.

The third option — check the lease, drop the guard, then send — does **not**
satisfy the record and is rejected outright. It is the shape a plan would drift
into by accident, so it is named here to be ruled out.

### What is not achievable, and what remains

Not achievable: any guarantee about what the remote proxy has already received
and acted upon. Once bytes leave the host, no local guard can recall them. The
record says this itself — "bytes already accepted by a remote proxy before
completion remain a remote fact, which is why the zero-overlap confirmation
precedes completion" — and this plan does not improve on it.

Residual risk after the local linearization is complete, stated plainly:

1. An old-generation `CONNECT` may already be established at the remote proxy
   when rotation begins. The local guard cannot close a remote session. The only
   control is criterion 10's remote revocation with session-termination proof.
2. A proxy that offers no revocation or expiry operation leaves that residual
   permanently unmitigated. The fail-closed answer is that authenticated proxy
   use stays disabled for that proxy. No local mechanism substitutes.
3. In-flight HTTP requests that began before rotation and hold no lease at the
   moment of rotation are not covered by the guard at all, because the guard
   protects the _write_. If the transport is `bitty-network`-owned, the write is
   guarded. If any authenticated leg is ever left on a library-owned socket, that
   leg is outside the guarantee and must be treated as unsupported rather than
   as best-effort.
4. The zero-overlap bound is a property of the proxy's behaviour, not of this
   client. A test fixture cannot establish it; only a real proxy's authenticated
   confirmation can.

So: criterion 9 is satisfiable, and satisfiable with a proof rather than a hope,
**provided** the authenticated HTTP leg is client-owned. Criterion 10 is
satisfiable only against a proxy that supports revocation, and the plan does not
pretend otherwise.

## The five leak paths

### Leak path 1: proxy redirect from `P1` to `P2`

Today `send` follows any `location` it sees, with no provenance, so a `P1` that
answers `302` is followed and `P2` receives the hop. Closure: provenance is
tracked, and a `3xx` is admissible **only** when it arrived inside an
established `CONNECT` tunnel. On a forward-proxied plain-HTTP leg the transport
cannot prove the response came from the destination, so a `3xx` there is
rejected before redirect processing. The test proves `P2` records zero hits and
that no attachment, client, connection, header, or lease crosses. Pinned by
criterion 6.

A deliberate consequence: a forward-proxied plain-HTTP destination that answers
`3xx` stops working. That is the correct trade, and it is the same trade the
record makes by refusing to send a credential over an unconfidential hop.

### Leak path 2: automatic client redirect

Already closed. `Policy::none()` is set on all three client constructors and
held by `every_client_builder_disables_ambient_proxy_and_redirects`. The plan's
obligation is to keep it that way through the transport change: if the
authenticated HTTP leg becomes client-owned, its request builder must also
disable redirects, and that new builder needs the same test. Not a new risk; a
new place to regress.

### Leak path 3: pool reuse across credential identity

Today `Egress` and `ProxyRoute` each hold one long-lived client and
`client_for` switches on the proxy decision alone, so any reuse is reuse across
every credential identity, generation, and scope. Closure: the five-field pool
key plus lease-only access, so reuse is impossible unless all five fields match.
The load-bearing case is two distinct records with equal generation and equal
scope epoch: because the two counters are separately monotonic and not jointly
identifying, the record identity is what separates them, and the test proves
distinct pools with no object crossing. Pinned by criterion 7.

### Leak path 4: destination-scope widening after binding

Closure: snapshots are immutable after publication, and any change publishes a
new epoch and invalidates every object bound to the old epoch **before** the
wider scope is usable. Widening `{A}` to `{A,B}` cannot be served by a pool,
connection, or attachment created for `{A}`, because those carry the old epoch
in their key and lookup refuses them. The test publishes `{A}`, proves `B` is
unreachable, then publishes `{A,B}` and proves every old object was invalidated
first. Pinned by criterion 8.

### Leak path 5: default-port normalization for proxy and destination

This is the leak path that makes criterion 4 a security prerequisite rather
than a tidiness requirement, and it has a present half and a prospective half.
They must not be confused.

Present: there is no origin type, so every origin comparison is
parser-dependent. `same_origin` is built from `Request::host()` and
`Request::port()`, which the record itself declines to credit with
canonicalization, and `resolve_redirect` is string surgery.
`tunnel_via_proxy` reduces the proxy scheme to a transport boolean and then
passes a literal `80` to `parse_authority`, so its notion of a proxy origin is
whatever that one call site decides.

Prospective, and the reason the ordering is 4 before 2: the moment an `https`
proxy is admitted — which the record's default-port table requires, and which
`tunnel_via_proxy` currently refuses outright rather than canonicalizing — the
default port has to come from somewhere. If it is decided per call site, then
the origin a credential is checked against depends on which code path parsed
the URL. A record scoped to `proxy:80` can then be compared against an origin
another path renders as `proxy:443`, or as `proxy` with no port at all, and a
mismatch that ought to fail closed can instead match a port the operator never
approved. The bug is not present; the ordering that prevents it is.

Closure: one `CanonicalOrigin` type, one closed table, used by every origin
comparison, by authorization, by pool keys, by redirect resolution, and by
`CONNECT` target validation. `http` proxy absent port is 80, `https` proxy
absent port is 443, an explicit default port equals an absent one, and `ws`
versus `wss` survives canonicalization with the TLS boolean derived only
afterwards. Then, and only then, does authorization read origins. Pinned by
criterion 4.

## Property pins this plan would move

Four pins exist. Two are untouched by design, one is untouched in kind but
requires a data update in the same change as the code, and one moves
deliberately. Separately, one of the four is already red on `origin/main` for a
reason that has nothing to do with this plan; the last row records that.

| Pin                                                                       | Verdict                                                                                        | Justification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `credentialed_proxy_url_never_reaches_proxy_construction`                 | **does not move — neutral, and load-bearing that way**                                         | The record keeps proxy-URL userinfo **permanently** rejected and states that userinfo is never a credential source, including for an environment proxy. Credentials come only from the provider handle. Because of that, this pin keeps passing verbatim, and criterion 3 keeps it as the regression suite. The plan is deliberately shaped to preserve this: had it resolved credentials by parsing userinfo out of the proxy URL, the pin would break and criterion 3 would fail. This is the single most important sequencing constraint in the plan — the credential source must be the provider, never the URL.                                                                                                                                                          |
| `http_network_service_debug_is_hand_written_and_cannot_emit_a_credential` | **neutral**                                                                                    | Criterion 12b adds credential-bearing types, but the service keeps its hand-written `Debug` printing only capability, a `proxy_configured` boolean, a `proxy_rejected` boolean, and `finish_non_exhaustive`. The pin's behavioural half scans a formatted proxy-configured service for a canary host, and a `CanonicalOrigin` proxy origin is not a credential and is not printed. Two ways to break it accidentally: giving the service a `#[derive(Debug)]` (the source half fails), or printing a proxy origin host into the service's `Debug` to make debugging easier. Neither is needed.                                                                                                                                                                                |
| `every_citation_in_the_record_names_a_symbol_that_exists`                 | **neutral in kind, mandatory in timing — the property is preserved, the data must be updated** | Implementing criterion 2 puts `ProxyCredentialProvider`, `CanonicalOrigin`, `AuthorizationLease`, and `inject_authorization` into `crates/`, so the record's `tree::[absent]` claims for those identifiers go stale and the pin goes red. The record requires exactly this response: fix the code or the record in the same change, never by deleting the assertion. So each `[absent]` claim converts into a presence claim citing the new symbol, in the same commit that introduces the symbol. The property — every locator resolves, every negative claim is still true — is unchanged; only its data changes. The record's Location cell for the same row cites `crates/bitty-network/src/proxy.rs::pub fn env_proxy_enabled() -> bool {`, so that symbol must survive. |
| `api_vocabulary_types_still_derive_debug_and_equality_and_still_leak`     | **moves — security strengthening, deliberately**                                               | Criterion 12a's whole purpose is to close the leak this pin asserts is still open. The pin is designed to fail in both directions, and its own comment says the mitigation and the test change together and the record is updated in the same change. So: the `PartialEq` assertions stay, the `assert!`-based comparisons stay (they never format an operand), and the three leak assertions invert to assert the canaries are **absent**. The pin's guarantee is not lost, it is transposed from "the leak is visible" to "the mitigation is visible" — a strictly stronger state, because after the change the suite fails if anyone re-derives `Debug` on a credential-capable type. Deleting the pin instead of transposing it would be the regression.                  |
| `every_citation_in_the_record_names_a_symbol_that_exists` (current state) | **already red on `origin/main`, not caused by this plan**                                      | See below.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

### Prerequisite: the gate is red on `origin/main`

`just check` fails on a pristine `origin/main` at `5d98440`, in a clean worktree,
before this plan adds anything:

```text
every_citation_in_the_record_names_a_symbol_that_exists ... FAILED
crates/bitty-network/src/http.rs::[absent] env_proxy_enabled cites
[absent] env_proxy_enabled, but that text is present; the record's
negative claim is stale
```

Cause: the environment-proxy gate fix landed before the record and its citation
pin, so the pin was red on arrival and nobody re-read the record's inventory
against the tree afterwards. `HttpNetworkService::new` now calls
`crate::proxy::env_proxy_enabled()`, so the record's negative claim for that
text in that file is false.

Consequence for this plan, stated plainly: **criterion 13 is not satisfiable
today**, and no amount of implementation work in this lane can satisfy it,
because the failure is in a test this lane may not edit and in a record this
lane may not edit. Correcting that stale claim is a separate, small, owned
change that must land before criterion 13 can be evaluated. It is a
prerequisite, not part of this plan, and it is not a finding against the
record's substance — the record's inventory row already says the gate is owned
elsewhere and records the state deliberately; only the citation anchor is stale.

## Criterion 10 is a possible dead end

Stated up front so it is not discovered during implementation: if the proxy that
the eventual protocol selection names offers no revocation or expiry operation,
or no authenticated confirmation signal, then **criterion 10 cannot be met and
authenticated proxy use must remain disabled for that proxy.** The record is
explicit that "local retirement is never described as remote revocation, and a
successful fixture is not a revocation signal", and that a fresh authentication
rejection alone is insufficient.

This plan does not propose a workaround, and it does not propose relaxing the
zero-overlap bound. It records that the honest outcome of criterion 10 may be
"no authenticated proxy support for proxies that cannot revoke", which is a
legitimate result of planning against the record rather than a reason to amend
it. The protocol-selection decision the record defers should be made with this
outcome in view.

## What must be true before implementation may start

This plan grants no implementation authorization. Implementation may begin only
when all of the following hold:

1. The record has been independently accepted and its status updated
   (criterion 1).
2. A scoped implementation task exists, with a named owner, a file scope that
   does not overlap any other lane, and an explicit statement that it may touch
   source and manifests.
3. The authentication protocol and the confidential transport have been chosen
   by the separate implementation security decision the record requires, and
   the choice is compatible with criterion 10's revocation requirement or it
   has been recorded as leaving authenticated proxy use disabled.
4. The stale citation claim that makes `just check` red on `origin/main` is
   corrected by an owned change, so criterion 13 can be evaluated at all.
5. A decision is recorded on whether the authenticated HTTP proxy leg becomes
   `bitty-network`-owned, because criterion 9's guarantee depends on it and
   reqwest-owned writes cannot satisfy the record's guard discipline.
6. The dependency question is answered without an unreviewed dependency or
   protocol (criterion 2's own wording), including whatever the client-owned
   transport implies for the supply chain and for `deny.toml`.
7. The reviewer for criterion 14 is registered and is not the implementer.

Until every item above holds, the fail-closed rejection of credential-bearing
proxy URLs remains the posture, no authenticated proxy path is enabled, issue
#25 remains open, and the record's status is not changed.

## Open points

- Whether the authenticated HTTP leg is client-owned is the largest open
  structural question, and it decides whether criterion 9 is met by proof or
  merely by a wider critical section.
- Whether any proxy satisfying operators' needs can satisfy criterion 10 is
  unknown and may be answerable only by measurement against real proxies.
- The record defers protocol selection; this plan cannot narrow that.
