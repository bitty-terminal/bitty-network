# #25: authenticated proxy credentials — fail-closed policy

Status: proposed; design-stage security-corpus review corrected by CTX-0037,
CTX-0039, CTX-0044, and CTX-0046; authenticated proxy support is not
implemented on the base pin or on `de77e17`.

Parent: #15 (BN-2 policy depth slice).

## Base pin and how to read this record

**Base pin: `refs/heads/integrate/lanes-abc` at `941c235`.** Every claim in
this record about what the integration branch does is scoped to exactly that
commit and is valid only for it. The pin is a single ref-plus-commit pair so
that drift is checkable mechanically rather than by reading a table:

```console
git rev-parse refs/heads/integrate/lanes-abc
```

When that command no longer prints the `941c235` commit id, the base has moved.
Every control claim in this record is then stale until it has been re-verified
against the new head, and this section must be updated in the same change. A
control that is no longer present on the new head is recorded as absent, never
carried forward. No claim in this record is inherited across a base move
without re-verification.

This record also names one immutable historical comparator, the merged mainline
commit `de77e17`. A claim about an immutable commit cannot go stale, so claims
about `de77e17` are stated once, here and where they are used, and describe the
pre-remediation state this decision exists to correct. `de77e17` is not a base
and is never credited with a control.

`941c235` is a verified, independently reviewed integration branch awaiting a
code-owner approval that only the repository owner can grant. Nothing on it is
merged. A control credited to the base pin is therefore _unmerged and available
to no consumer_, and it does not satisfy any transition criterion in this record
until it is merged and independently reviewed as merged code. A control credited
to `de77e17` is merged but is the pre-remediation state that this record exists
to correct.

PR #43 (head `ctx-0013/fix-ws-deadline-proxy`) is open and unmerged; its head
commit is an ancestor of `941c235`, so its proxy and WebSocket content is present
inside the integration branch under CTX-0040 and CTX-0041. PR #43 itself
contributes no merged control.

Throughout this record, "the base pin" means `941c235`. Where the merged
mainline differs, the text says `de77e17` explicitly. Where a control is absent
from both, the text says "absent from both" rather than implying a pending
branch supplies it.

### Specified is not implemented

Every requirement in this record is one of exactly two things, and the record
says which one **at the point where the requirement is stated**:

- **implemented** — claimed only for a control the
  [Control inventory](#control-inventory) records as present on the base pin,
  and claimed only as unmerged and available to no consumer; or
- **[specified, not implemented]** — a requirement this record states and that
  no code implements, on the base pin or on `de77e17`.

The marker is part of the sentence that states the requirement. It is not a
pointer to another table, and a reader who is never shown the inventory must
still be unable to reach a conclusion about code. A section whose requirements
are entirely unimplemented carries the marker once, at its head, before any
requirement in it is stated. A section that mixes implemented and unimplemented
requirements carries the marker on each unimplemented requirement, at that
requirement. The inventory supplements this by listing code-level state per
control; it is never the thing that makes the distinction.

## Decision

This record defines the required design for authenticated proxies. It does not
implement authentication, select an authentication protocol, or authorize a
dependency. The design it defines is **[specified, not implemented]** in full.

The design does not weaken the existing pre-dial rejection requirement. A proxy
URL containing userinfo is rejected permanently before the URL is retained,
copied into a client, logged, or dialed. Proxy-URL userinfo is never a
credential source, including for an environment proxy. An authenticated
implementation may narrow the broader "authentication unsupported" posture only
after every transition criterion in this record is met and independently
approved.

The provider and environment separation remains mandatory:
`ProxyCredentialProvider` reads secrets only through its caller-provided
interface, while proxy environment variables remain credential-free routing
inputs. The backend never reads a secret from the environment. This
architectural rule is independent of whether the existing paths enforce it, and
this record does not credit the architectural rule with any behavioural control.
The behavioural state of the existing paths is stated per control in the
[Control inventory](#control-inventory), scoped to the
[base pin](#base-pin-and-how-to-read-this-record).

## Credential source and scope snapshots

**[specified, not implemented]** — every mechanism named in this section
(`ProxyCredentialProvider`, the record snapshot, the scope epoch, the allowed
destination set, and the `proxy::inject_authorization` wire-injection boundary)
exists in no code on the base pin or on `de77e17`. None of these identifiers
appears anywhere in the tree. Everything below is stated so that an
implementation can be scoped against it, not because anything enforces it
today. The architectural separation this section mandates is likewise stated
without behavioural credit, as noted under [Decision](#decision).

The single credential source is one caller-provided
`ProxyCredentialProvider` handle installed on `HttpNetworkService` at
construction. The provider owns lookup, remote lifecycle operations, and
rotation; `bitty-network` owns no second credential source and performs no
implicit environment-variable, keyring, secret-file, or configuration-file
lookup. The HTTP and WebSocket paths share that one provider handle.

A provider record contains only non-secret routing metadata and opaque secret
material:

- a stable, non-secret credential identifier;
- one `CanonicalOrigin` for the proxy to which the credential may authenticate;
- an immutable snapshot of the exact `CanonicalOrigin` destinations for which
  the credential may be used;
- a monotonically increasing credential generation; and
- a monotonically increasing scope epoch.

An allowed-destination set is immutable after publication. Any addition,
removal, or replacement publishes a new snapshot with a new scope epoch; it
never mutates a snapshot already used by an attachment, client, pool, or tunnel.
Widening `{A}` to `{A,B}` therefore invalidates every object created from the
old snapshot before the wider scope can be used for `B`. Selection never
combines destinations from two snapshots or falls back to an earlier scope.

A credential is usable only when both bindings match the same current record
snapshot:

1. The actual proxy `CanonicalOrigin` exactly matches the record's proxy
   origin.
2. The effective destination `CanonicalOrigin` exactly matches one member of
   that snapshot's allowed destination set.

Wildcards, suffix matching, ambient defaults, and "same host as the request"
shortcuts are prohibited. A malformed route, missing record, stale generation,
stale scope epoch, or mismatch fails closed before client construction,
checkout, dialing, or writing. It never falls back to an older record, an
unauthenticated proxy, or direct egress.

The single wire-injection point is a future internal
`proxy::inject_authorization` boundary. It runs after capability checks, final
route selection, redirect processing, and canonical-origin normalization, but
immediately before the first byte of the proxy leg is sent. It receives the
actual proxy origin, effective destination origin, transport kind, credential
generation, scope epoch, and record-snapshot identity. It returns an opaque,
short-lived proxy-only authorization attachment bound to all of those values.

Both the HTTP proxy-request path and the WebSocket `CONNECT` path must call
this one boundary. Neither backend may read the provider, parse proxy userinfo,
construct an authentication header, or implement fallback lookup on its own.
There is exactly one implementation point because proxy authentication is a
property of the selected proxy route, not of an origin request or either
backend independently.

The attachment is added only to the proxy leg. It is never copied into the
end-to-end request, forwarded through a tunnel, serialized, or exposed to the
origin. Caller-supplied `Proxy-Authorization` headers are rejected before
dispatch and removed before every hop. No backend may recover an attachment
from a request, cache, redirect, or error value.

## Canonical origins

**[specified, not implemented]** — no `CanonicalOrigin` type exists on the base
pin or on `de77e17`. The canonicalization rules and the closed default-port
table below are requirements for a future implementation, and the
canonicalization tests named here do not exist either. The URL and port
extraction that does exist (`Request::host`, `Request::port`, and the
WebSocket target parser) is best-effort splitting, not this canonicalization,
and is never credited with it.

Routing, authorization, pooling, redirect decisions, and `CONNECT` target
validation use one `CanonicalOrigin` type containing exactly:

- a lowercase scheme;
- a canonically encoded ASCII host or IP literal; and
- an effective `u16` port.

A structured URL parser performs parsing. DNS names are converted through
IDNA and lowercased, IP literals use their parser-normalized binary form, and
malformed hosts, missing hosts, invalid ports, ambiguous delimiters, and
percent-encoded authority delimiters fail closed. Scheme and host case changes
do not change the canonical value. The path, query, and fragment are excluded
from origin matching.

The default-port table is closed and applies to both proxy and destination
origins:

| Scheme  | Default port |
| ------- | ------------ |
| `http`  | 80           |
| `ws`    | 80           |
| `https` | 443          |
| `wss`   | 443          |

An absent port uses the table. An explicit port must be valid and is preserved;
an explicit default port canonicalizes to the same origin as an absent default
port. No proxy scheme may default to port 80 merely because a parser reduced
it to a transport boolean. WebSocket parsing retains `ws` versus `wss` in the
destination origin; the TLS boolean is derived only after canonicalization and
is never the authorization identity.

Proxy origins support only the schemes selected by the implementation security
decision. At minimum, the canonicalization tests must cover `http` proxy
without a port as 80, `https` proxy without a port as 443, and their explicit
default ports as equal. Destination tests must cover `http`, `ws`, `https`, and
`wss` with absent, explicit-default, and non-default ports, mixed-case scheme
and host input, equivalent Unicode and IDNA host forms, IPv4, and IPv6.

## `NO_PROXY` ordering

The bypass decision in isolation is implemented and recorded in the
[Control inventory](#control-inventory): `NO_PROXY` and `no_proxy` are read at
construction, `.no_proxy()` is called on every client builder, and a bypassed
request takes direct egress. Everything in this section about credential
resolution, provider calls, and per-hop re-evaluation is
**[specified, not implemented]** — none of it is enforced, because no credential
is ever resolved on any baseline.

Routing environment input is parsed and structurally validated before it is
retained. A `NO_PROXY` decision is then made before credential resolution. A
bypassed request uses direct egress and neither queries the provider nor
constructs, checks out, or carries proxy authorization, clients, connections,
or tunnels. `NO_PROXY` never authorizes a wildcard destination scope and never
causes a malformed proxy setting to be ignored.

Every redirect and tunnel-target change reevaluates `NO_PROXY` for the new
effective destination. A request cannot enter the provider path while bypassed
and later inherit provider state after a hop selects a proxy, or enter the
provider path and later inherit it after a hop becomes bypassed.

## Redirects, proxy responses, and `CONNECT`

Every HTTP client used by this decision has automatic redirects explicitly
disabled before any proxy is installed. The implementation owns a redirect
loop with a named finite hop limit and the request's total deadline. Exceeding
either bound fails closed; no library-owned redirect loop is permitted.

Every redirect is a separate authorization decision. Before following a
location, the implementation:

1. resolves the location against the previous effective URL and canonicalizes
   the new destination;
2. reevaluates `NO_PROXY`, capability, route selection, and proxy origin;
3. selects a current immutable record snapshot and obtains a new scope epoch,
   generation, attachment, and lease;
4. removes the prior proxy authorization and every hop-specific connection or
   tunnel; and
5. rebuilds host headers and strips caller `Authorization` and `Cookie`, and
   removes caller `Proxy-Authorization`, whenever either the destination origin
   or the proxy origin changes.

The old authorization, client, pooled connection, and tunnel cannot be reused
when either origin changes. A path-only change on the same proxy origin,
destination origin, scope epoch, and generation may reuse only a connection
from that exact pool key with a current lease. Header stripping and fresh
authorization are still required for that hop.

**[specified, not implemented]** — the proxy-origin half of step 5 above.
Stripping on a _destination_-origin change is implemented on the base pin.
Stripping on a _proxy-origin-only_ change to a different forward proxy is
**[specified, not implemented]**: the stripping condition on the base pin
compares destinations only and has no proxy term, so a hop that keeps the same
destination and moves to a different forward proxy retains `Authorization`,
`Cookie`, and `Proxy-Authorization`. The implemented half must not be read as
covering the unimplemented half. This decision does not rely on tunnel
confidentiality to retain sensitive headers, so the unimplemented half is an
open gap, not a covered case.

Steps 1, 2, 4, and 5's destination-origin half are implemented on the base pin.
Steps 3 and 5's proxy-origin half, and every credential-resolving clause in
this list, are **[specified, not implemented]**.

A redirect response is accepted as an origin redirect only when the transport
can prove it came from the tunneled destination. A `3xx` produced by a proxy,
including a `CONNECT` response or a forward-proxy response outside an
established tunnel, is rejected before it can enter the redirect loop. Proxy
redirects from `P1` to `P2` are never followed, and no attachment, client,
connection, header, or lease is copied to `P2`. Ambiguous response provenance
fails closed.

**[specified, not implemented]** — the whole paragraph above. Response
provenance is not tracked on the base pin: the redirect loop cannot distinguish
a `3xx` that came from the tunneled destination from one a proxy produced, and
it has no tunnel from which to prove either. Nothing implements proxy-`3xx`
rejection, `P1`-to-`P2` refusal, or fail-closed handling of ambiguous
provenance.

A tunnel target is fixed by its `CONNECT` request to the canonical destination
host and effective port. Any redirect, retry, reconnect, or protocol action
that would change that target closes the old tunnel and repeats `NO_PROXY`,
canonicalization, scope checks, route selection, and authorization. No
credential issued for one target may be replayed to another. After `CONNECT`,
only end-to-end tunnel data crosses that boundary; proxy authorization never
enters the tunnel.

The fixed `CONNECT` target itself is implemented on the base pin, and the
`CONNECT` request line is built from a resolved host and port, so it carries no
credential. Every requirement in the paragraph above that depends on a
credential, a scope check, or a canonical origin is **[specified, not
implemented]**: the tunnel never carries one, so target-change replay is
prevented today by the absence of credentials rather than by these rules.

## Environment routing and fail-closed construction

Environment variables remain routing inputs only. `HTTP_PROXY`, `HTTPS_PROXY`,
and `ALL_PROXY` plus their lowercase forms may select a credential-free proxy
origin. Every client builder must disable ambient system and PAC proxy
discovery before installing the already validated, explicit route; an
unselected variable, platform proxy, or PAC result cannot change egress.

Environment values are parsed before retention. A malformed proxy URL, an
unsupported proxy scheme, or any proxy-URL userinfo poisons service
construction: the service retains no unusable URL or client and every request
fails closed until a new service is constructed. Explicit `with_proxy`
configuration returns a typed failure before retaining or dialing. No failure
falls back to direct egress, an older route, or unauthenticated proxy use. This
whole paragraph is **[specified, not implemented]** except for its permanent
rejection of proxy-URL userinfo, which is implemented on the base pin, unmerged,
and pinned by `credentialed_proxy_url_never_reaches_proxy_construction`. The
permanent rejection is the current posture this record requires; it is not the
malformed-configuration and unsupported-scheme handling, which is
**[specified, not implemented]**.

The merged baseline is defective in this area. On `origin/main` commit
`de77e17`, HTTP environment handling reads only `HTTPS_PROXY`/`https_proxy` and
`NO_PROXY`/`no_proxy`; `HttpNetworkService::new` discards an unusable configured
proxy and becomes direct, `proxy_client` has no structural userinfo rejection,
the WebSocket path strips proxy userinfo and proceeds to dial, and no client
builder calls `.no_proxy()`.

The base pin repairs most of that list but not all of it. It now reads
`HTTP_PROXY`, `HTTPS_PROXY`, and
`ALL_PROXY` with their lowercase forms (`crates/bitty-network/src/http.rs:136`,
`:139`, `:142`, used at `:257`, `:260`, `:263`); `HttpNetworkService::new`
records the failure and fails every request closed rather than becoming direct
(`:311`-`:323`, `:355`-`:359`, called from `:774` and `:785`); `proxy_client`
rejects proxy-URL userinfo before `Proxy::all` (`:820`-`:834`); the WebSocket
proxy leg rejects userinfo before dialing (see
[Control inventory](#control-inventory)); and every client builder calls
`.no_proxy()` and `Policy::none()` (`:378`-`:388`, `:828`-`:831`,
`:845`-`:849`). These are unmerged and available to no consumer, and they are
pinned as properties rather than asserted as facts; see
[Executable property pins](#executable-property-pins). The requirement in the
first paragraph of this section is **[specified, not implemented]** in its
`with_proxy` half: the base pin still retains the verbatim validated URL string
rather than a structurally sanitized endpoint, and the redirect loop still
conditions sensitive-header stripping on a destination-origin change alone.
Both are recorded as open below and marked in place where they are stated.

## Pool ownership, checkout, and invalidation

**[specified, not implemented]** — there is no scope registry, no pool key, no
lease type, and no invalidation path in any code on the base pin or on
`de77e17`. The base pin pools connections by reqwest's own pool key, which
contains no credential-record identity, no generation, and no scope epoch.
Everything in this section is a requirement for a future implementation.

Every authenticated client and connection pool has one scope registry owner.
A pool key is a structured value containing at least:

- canonical proxy origin;
- canonical destination origin;
- the stable, non-secret credential-record identity;
- credential generation; and
- scope epoch.

The identity is a collision-free, provider-scoped non-secret record identity,
never secret material. The key may include transport and protocol
discriminants, but no code path may omit any of these five fields.

**[specified, not implemented]** — the cross-record uniqueness rule in the next
paragraph, in full. Generation and scope epoch are not assumed globally unique
across records: two different records with equal generation and scope epoch must
still have different pool keys and can never share a pool. An equivalent
globally unique opaque credential generation is permitted only when it has the
same collision-free property. No code enforces this, because no record identity
exists to collide: a reader must not infer that the two fields being separately
monotonic makes them jointly identifying.

A client, pool, connection, authorization attachment, or tunnel is owned by
exactly one registry entry and is accessible only while holding a lease obtained
from that entry. Shared clients cannot be reached through an unscoped service
field.

Checkout occurs under the registry synchronization protocol. While holding its
read-side guard, the implementation reloads the current record snapshot,
revalidates every pool-key field, confirms that the entry is active, increments
the entry's in-flight lease count, and only then returns a connection. A
connection without that atomic validation and lease cannot be used. Every
checkout failure is closed; it never searches another pool as fallback.

Invalidation occurs under the corresponding exclusive guard. It prevents new
checkouts, marks the old key inactive, removes it from lookup, cancels its
leases, closes every client, pooled connection, and tunnel that it owns, and
waits for all leases to release before the old state can be destroyed. Dropping
a shared reference is not invalidation. A thread waiting in checkout either
obtains a lease for the new current key or fails closed; it cannot observe the
old key as active and use it later.

The same scope-epoch invalidation applies when an allowed-destination snapshot
changes, even if credential generation does not. It invalidates every prior
attachment, client, pool, connection, and tunnel. Cache lifetime never overrides
scope or rotation.

## Rotation, leases, and remote revocation

**[specified, not implemented]** — no `AuthorizationLease`, no rotation
protocol, and no remote-revocation path exists on the base pin or on
`de77e17`. There is no credential to rotate and no proxy session to revoke.
Everything in this section is a requirement for a future implementation, and
none of it may be read as a description of current behaviour.

Every authorization attachment carries an `AuthorizationLease` tied to its
record snapshot, scope epoch, generation, and pool key. The final
check-and-write operation holds a shared synchronization guard, reloads the
current scope and generation, verifies that the lease is active, and writes
only while that guard remains held. Rotation takes the exclusive guard before
publishing retirement. Consequently, a write that passed an earlier boundary
either completes before retirement is published or cannot begin afterward. This
is a realizable local linearization, not physical network atomicity: the shared
guard must remain held through the complete underlying write and any required
transport flush before the check-and-write operation can complete.

Rotation is a fail-closed state transition, not an operator instruction to
overlap credentials:

1. Stage the replacement without exposing it to selection.
2. Enter a local draining state that prevents new leases, cancels old leases,
   closes old clients, connections, and tunnels, and waits for their bounded
   shutdown. A shutdown timeout faults authenticated proxy use; it does not
   activate the replacement.
3. Require remote revocation of the old credential and a confirmation bound to
   the canonical proxy origin and old credential identifier. Before the
   replacement can be activated, the confirmation must prove that every
   already-authenticated proxy session using the old credential has been
   terminated and cannot continue, or that an authenticated, current inventory
   proves that no such session remains; a fresh authentication rejection alone
   is insufficient. It must also prove that an authentication attempt using the
   old credential is rejected and that the replacement is accepted, without
   exposing either secret in evidence.

   **[specified, not implemented]** — step 3 in full, including the
   session-termination proof and the authenticated-inventory alternative. No
   code requests remote revocation, receives or evaluates a confirmation, binds
   one to a proxy origin and credential identifier, or inspects a session
   inventory. The "a fresh authentication rejection alone is insufficient" rule
   in particular has no implementation and no test: a reader must not treat the
   zero-overlap bound below as verified.

4. Publish the new generation and any changed scope epoch only after the
   confirmation. Reopen new leases only after all old state has been invalidated
   and destroyed.

The permitted credential-overlap bound is zero. The new credential is not sent
to the proxy while the old credential remains accepted. If the proxy has no
revocation or expiry operation, cannot provide an authenticated confirmation
signal, or returns an ambiguous, stale, partial, or negative result, rotation
fails closed and authenticated proxy use remains disabled. Local retirement is
never described as remote revocation, and a successful fixture is not a
revocation signal.

Long-lived tunnel and protocol writers hold a lease for their lifetime. They
must revalidate it before every write, and rotation closes and waits for their
transport rather than merely invalidating future lookup. Once rotation reports
completion, no old-generation credential or attachment can be selected, checked
out, or written. Bytes already accepted by a remote proxy before completion
remain a remote fact, which is why the zero-overlap confirmation precedes
completion.

Rotation failure, stale metadata, incomplete invalidation, provider
unavailability, or uncertain remote state never causes fallback to an old
credential, an unauthenticated proxy, or direct egress.

## Storage rules

The first paragraph below is a live repository property, enforced by review and
by `gitleaks detect --source .` in the quality gates. Every requirement in the
rest of this section is **[specified, not implemented]**: there is no secret
store integration, no provider memory, no secret buffer, and no
credential-bearing type on the base pin or on `de77e17`, so none of the runtime
rules below is enforced or observable.

No plaintext proxy secret is committed to this repository. Source, tests,
fixtures, examples, snapshots, diagnostics, and documentation must contain no
usable username, password, token, or credential value; security tests use
obvious non-secret canaries.

The embedding application may persist credentials only in an OS-protected
secret store. `bitty-network` does not read or write a plaintext credential
file and does not accept a secret from an environment variable. Runtime secret
material exists only in the provider's protected process memory and the minimum
ephemeral transport buffers needed to authenticate a proxy connection.
Secret-bearing values must not be cloned merely for diagnostics, transport
selection, or service cloning. Owned secret buffers are cleared on drop. If a
transport cannot guarantee that lifecycle, the implementation isolates or wraps
the state so it is generation-tagged and evicted, and the limitation requires
explicit implementation security approval.

A type that owns or references a provider secret, proxy client, connection,
tunnel, authorization attachment, credential-bearing request, or remote
revocation evidence is credential-bearing. Durable caches must not contain
secret material. Any in-memory object that can retain secret material is
bound to the full pool key and is invalidated by scope-epoch and generation
changes.

## Redaction and diagnostics

**[specified, not implemented]** — the first two paragraphs of this section are
requirements, and the sections that follow state requirement by requirement which
parts of them exist. The controls that do exist are named in the
[Control inventory](#control-inventory) and pinned by the
[executable property pins](#executable-property-pins); nothing else in this
section is a control on any baseline, and no part of it is a statement that an
authenticated proxy is safe to build on.

Logs, errors, traces, metrics, panic messages, test failure output, snapshots,
and crash diagnostics must never contain proxy usernames, passwords, tokens,
raw userinfo, complete credential-bearing URLs, authorization-header values, or
unredacted third-party error chains. Diagnostics may identify a redacted proxy
origin only after structural removal of userinfo. Rejection paths report a
stable caller-safe error without echoing the raw environment value, explicit
URL, request, or third-party error text.

Redaction is structural, not best-effort replacement in a formatted string.
Malformed and percent-encoded userinfo must be removed by parsing into a
sanitized endpoint before any observable value is created. A raw proxy URL may
not be retained only to redact it later.

### Baseline `Debug` and API request types

The merged baseline does not provide the claimed safe diagnostics. On
`origin/main` commit `de77e17`, `HttpNetworkService` and `Egress` derive
`Debug`, `Egress` retains `https_proxy`, and `with_proxy` retains the raw URL.
In `bitty-network-api`, `Request` and `WebSocketRequest` derive `Debug` and can
contain credential-bearing header values and URLs. The merged baseline
therefore has no hand-written redacting `Debug` for these types and no safe
basis for claiming that a failed equality assertion is redacted.

The base pin changes part of this and must not be credited with the rest. It
removed the `Debug` derive from `HttpNetworkService` and from `Egress` and
added a hand-written redacting `Debug` for the service
(`crates/bitty-network/src/http.rs:212`, `:217`-`:225`); it prints only
`capability`, a `proxy_configured` boolean, a `proxy_rejected` boolean, and
`finish_non_exhaustive`, so it emits no URL and no field of `Egress`. The
`https_proxy` field was then removed from `Egress` and replaced with
`ProxyRoute` (`:235`-`:240`, `:298`-`:304`), so no `https_proxy` field exists on
the base pin at all. `Egress` has no `Debug` impl of any kind on the base pin,
so it is not printable through any path. The redaction property of the
service's `Debug` is not asserted here but pinned, by
`http_network_service_debug_is_hand_written_and_cannot_emit_a_credential`; see
[Executable property pins](#executable-property-pins).

Two of the four defects in the preceding paragraph are therefore closed on the
base pin and two are not. A third, separate defect sits on the API surface.
All three open items are, and every one of them is **[specified, not
implemented]**:

1. `with_proxy` does not retain a structurally sanitized endpoint.
   `validated_proxy_url` returns `url.to_owned()` (`http.rs:807`-`:812`), and
   `ProxyRoute::explicit` stores that verbatim string in `ProxyRoute.all`
   (`:243`-`:254`). The retained value is now guaranteed credential-free and
   parseable, because the retention happens behind the userinfo and parse
   checks, but it is still the caller's exact bytes rather than a
   parse-into-sanitized-endpoint projection. This record's structural-redaction
   requirement is therefore still unmet on the base pin.
2. `Request` still derives `Debug`, `Clone`, `PartialEq`, and `Eq`
   (`crates/bitty-network-api/src/lib.rs:334`-`:335`) and still holds a `url`
   string plus a `headers` vector of `(name, value)` pairs, either of which can
   carry a credential. `WebSocketRequest` is the same
   (`api/src/lib.rs:463`-`:464`, `url` plus `protocols`), and its `url` is
   demonstrably credential-capable because the backend's own target parser
   accepts and strips userinfo from it
   (`crates/bitty-network/src/websocket.rs:991`-`:1003`, exercised by
   `target_parses_ipv6_userinfo_and_port` at `websocket.rs:1455`-`:1457`).
   `Response` also derives `Debug` and `PartialEq` and carries a `headers`
   vector (`api/src/lib.rs:432`-`:440`). The API crate's only change on the
   integration line is the `CountBudget` variant, added by `076b030` (CTX-0026)
   together with its `NetworkError` documentation; it changed no derive on any
   request or response type, and the derives are identical on `de77e17` and on
   the base pin. The integration branch does not replace the API request
   derives.
3. `NetworkError` still derives `Debug` and `PartialEq`
   (`api/src/lib.rs:263`) and its `Denied` variant still carries a raw
   `domain: String` that both `Debug` and `Display` echo
   (`api/src/lib.rs:293`). It has no third-party source chain today, because
   `impl std::error::Error for NetworkError {}` (`api/src/lib.rs:308`) declares
   no `source`, so the source-chain requirement is satisfied vacuously rather
   than by a redaction boundary. That is not a safe basis for a future
   authenticated-proxy error type that does carry sources.

The base pin also carries a `diagnostics` module
(`crates/bitty-network/src/diagnostics.rs`) that
constructs redacted snapshots rather than redacting later:
`redacted_url` (`:49`), `redacted_headers` (`:132`), `summarize_body` (`:141`),
`connect_authority` (`:150`), and `DiagnosticRequest` (`:159`). These have the
structural-redaction shape this record requires, so that shape is
**[specified, not implemented]**: the shape is not a control. The constructors
are, however, wired into nothing. No caller outside `diagnostics.rs` itself
references `redacted_url`, `redacted_headers`, `summarize_body`,
`connect_authority`, `safe_host`, or `DiagnosticRequest` on the base pin, and
the module's own header states that wiring them into the backends' error paths
is a follow-up merge (`diagnostics.rs:12`-`:14`). An unwired helper is not a
control on any request path.

PR #43 is open and unmerged. Its head is an ancestor of `941c235`, so the
content described above reached the integration branch through CTX-0040 and
CTX-0041 rather than through PR #43, and it is still not on `origin/main`.

Any type that can hold or reference proxy credential material must implement a
hand-written redacting `Debug`; deriving `Debug` on that type is prohibited.
This includes service and egress configuration, provider handles, credential
records and snapshots, authorization values and leases, client, pool,
connection and tunnel wrappers, remote-revocation evidence, errors, and
credential-capable API request types. `Display`, error conversion, structured
fields, and diagnostic accessors apply the same rule. A redacted `Debug` must
be implemented before an equality assertion can be allowed to format the type.

### Serialization and equality

Credential-bearing, credential-referencing, and attachment types must not
implement `Serialize` or `Deserialize`. Configuration, snapshot, IPC, metrics,
and diagnostic serialization requires a separate sanitized data type whose
fields are an explicit allowlist; implementing a serde trait on a raw provider,
request, client, connection, tunnel, attachment, lease, or error type to later
hide fields is prohibited.

**[specified, not implemented]** — the static-shape rule in the next paragraph,
in full. No raw or sanitized projection may use `#[serde(flatten)]`, a flattened
helper type, or an arbitrary map or other dynamic map as a serialization escape
hatch. Sanitized projections must be statically shaped: every serialized field
is named in the allowlist, with no hidden or catch-all field introduced through
flattening or dynamic insertion. No sanitized projection type exists on any
baseline, and no serialization of any kind occurs, so nothing enforces this and
nothing tests it.

The `Serialize`/`Deserialize` ban above is a different matter and must not be
confused with it. That ban is satisfied on the base pin only _vacuously_,
because neither crate depends on `serde`, so no type can implement a serde
trait. Vacuous satisfaction is a property of the dependency set, not a
redaction boundary, and it disappears the moment anyone adds a serde
dependency. Serialization failure messages must be redacted too.

`PartialEq` and `Eq` are permitted only when the same type has a hand-written
redacted `Debug` and its fields do not expose secrets through comparison
failures. The current `Request` and `WebSocketRequest` derives do not meet this
gate, and they do not meet it on either baseline: the derives are unchanged
between the merged mainline `de77e17` and the base pin
(`crates/bitty-network-api/src/lib.rs:334`-`:335` and `:463`-`:464`). That
failure is **[specified, not implemented]** — it is an unmet gate on
credential-capable types, and it is pinned in both directions by
`api_vocabulary_types_still_derive_debug_and_equality_and_still_leak` so that it
cannot be quietly resolved without this record being revisited. The
child-process failed-`PartialEq` redaction test required above does not exist on
the base pin: the credential cases at `tests/http.rs:321`-`:352` run in a child
process and scan its combined output, but nothing there triggers a failed
equality assertion on a credential-bearing type, because no backend formats one.

### Errors, panics, and third-party sources

**[specified, not implemented]** — this section in full. The `expect`,
`unwrap`, and `panic!` prohibition is unenforced and untested on credential
paths, and the source-chain rule is satisfied only vacuously: `NetworkError`
declares no `source` today, so there is no chain to redact. A vacuously
satisfied source-chain rule is not a redaction boundary and is not a safe basis
for a future authenticated-proxy error type that does carry sources.

Credential-bearing paths do not use `expect`, `unwrap`, `panic!`, unchecked
formatting, or unchecked string conversion of a third-party error. They map
transport, URL-parser, TLS, HTTP-client, and proxy errors immediately to stable
caller-safe error variants. Formatting a third-party error with `Debug` or
`Display`, converting it with `to_string`, or retaining it solely as a source
is prohibited when its chain can contain a raw URL or header.

A public error's source chain either omits the third-party source or exposes
only a separately redacted, non-retaining summary. Tests inject errors whose
URL, source, and source-chain fields contain distinct canaries and verify all
`Debug`, `Display`, source-chain, panic-catch, and crash-output paths remain
free of them. Where the type under test has a derived `Debug`, those tests
deliberately trigger a failed equality assertion in a child process and prove
that the captured combined output contains neither a raw URL nor a header
canary; that child-process coverage is itself **[specified, not
implemented]** on every baseline, because nothing triggers a failed equality
assertion on a credential-bearing type today.

### Traces

**[specified, not implemented]** — this section in full. Neither crate depends
on `tracing` on the base pin or on `de77e17`, so there is no span, no event, no
exporter, and no allowlist to enforce or scan.

Tracing uses statically named spans and events with explicit attribute
allowlists. A span may contain a canonical redacted origin only when necessary
for debugging; it never contains a raw or complete URL, path, query, hostname
when an origin-level class is sufficient, header, authorization attachment,
credential identifier, generation, scope epoch, or secret. Event attributes use
stable enums, bounded error classes, booleans, and non-secret counts. Dynamic
request data is excluded. Tests export spans and events to an in-memory
exporter and scan every attribute name and value for credential canaries.

### Metrics

**[specified, not implemented]** — this section in full. Neither crate depends
on a metrics facade on the base pin or on `de77e17`, so there is no descriptor,
no label schema, and no exemplar to constrain.

Metric descriptors and label schemas are static. Labels are limited to bounded
enums or booleans such as transport kind, outcome, and failure class. Proxy
origins, destination origins, URLs, hosts, paths, header names, credential
identifiers, generations, scope epochs, and other request-derived strings are
prohibited as labels and values. Metric values may contain only documented
counts, durations, and byte totals; secret bytes and strings are prohibited.

Exemplars may contain only a trace ID, span ID, and the same allowlisted bounded
attributes. Request, response, error, span event, and URL fields are prohibited.
Tests inspect metric descriptors, labels, values, and exemplars and prove that
high-cardinality URL fields cannot be emitted.

### Test and diagnostic output

The prohibition in the first paragraph below is binding now and is
**[specified, not implemented]** as a redaction control: it is a rule for future
authenticated-proxy work, and the current test suite violates it, as the second
paragraph records.

Tests must not place raw URLs, headers, requests, responses, connections,
attachments, errors, or source chains into `assert_eq!`, `assert_ne!`, `dbg!`,
snapshots, assertion messages, or captured child-process output. Tests compare
sanitized projections, bounded enums, booleans, lengths, or fingerprints.
Snapshot fixtures contain only redacted data, and snapshot updates fail closed
when raw credential-capable data is present.

The current tests interpolate raw observed proxy request text into assertion
messages. On the base pin the HTTP integration tests capture the first request the
loopback probe received and print it verbatim in the failure message, including
the HTTP absolute-form request line at the proxy
(`crates/bitty-network/tests/http.rs:447`-`:451`) and the destination request
line and header assertions on a followed hop
(`crates/bitty-network/tests/http.rs:565`-`:578`); the origin-form case is the
same pattern at `tests/http.rs:287`-`:291`. Those patterns are prohibited for
authenticated proxy work and must be replaced by redacted structural
assertions before this gate can pass. The pins in
`crates/bitty-network/tests/proxy_credential_policy.rs` follow the prohibition
and are written to be the replacement shape.

The WebSocket `CONNECT` line is not an instance of this on the base pin, and this
record does not claim it is. The WebSocket loopback proxy fixtures read the
`CONNECT` head only to find the `\r\n\r\n` terminator and then discard it
(`crates/bitty-network/src/websocket.rs:2188`-`:2194`); no fixture retains it and
no assertion message interpolates it. The emitted `CONNECT` request line is
built from `format_authority` over a resolved host and port
(`websocket.rs:1185`-`:1186`), so it carries no credential today. That is a
property of the current fixture, not a redacted-diagnostic control, and it does
not satisfy this gate for an authenticated proxy that does send a credential.

## Security-corpus review note

### Reviewed baseline

This design-stage review inspected issue #25, this decision, the proxy feature
decision, the HTTP and WebSocket proxy boundaries, environment proxy handling,
credential routing and host changes, storage and rotation, cache lifetime,
diagnostic exposure, and the lane A/B/C work collected on the integration
branch. It identified missing implementation controls and required future
regression coverage; it did not execute absent regression tests or credit
unmerged code as an existing control.

The review was performed against the [base
pin](#base-pin-and-how-to-read-this-record) and the immutable merged mainline
`de77e17` (PR #44 is open, `BLOCKED`, `REVIEW_REQUIRED`, not merged). Round one
reviewed the merged mainline. Round two re-verified the merged mainline and
independently confirmed that the named regressions and `.no_proxy()` were absent
there. CTX-0044 rebased this record onto the base pin and re-verified every
control against it, because several controls this record requires exist only
there and the earlier "pending PR" framing under-described them and
over-described the branch as a single pending change. CTX-0046 replaced the
per-control commit table with the base pin and the
[executable property pins](#executable-property-pins); it re-read the same
tree and changed no control state.

At the merged mainline `de77e17`, pre-dial proxy-URL userinfo rejection,
fail-closed handling of unusable environment proxy configuration, and a
hand-written redacting `Debug` are not present. `HttpNetworkService` and
`Egress` derive `Debug` and retain `https_proxy`; `with_proxy` retains the raw
URL; `HttpNetworkService::new` drops unusable environment configuration and
becomes direct; `proxy_client` lacks structural userinfo rejection; the
WebSocket path strips userinfo and proceeds to dial; no client builder calls
`.no_proxy()`; and the named regressions are absent.

### Round-2 finding disposition

Round two (PX-0081, checkpoint `01M3CFQKB2PAXM6NPRY18Y6PV0`) closed B2, B4, B5,
B6, B8, and B10 through B16, and left B1, B3, B7, and B9 partial while raising
four new blocking findings. Fix round CTX-0039 (commit `2d35d17`) reported all
four closed. CTX-0044 re-read each against `941c235` and records the disposition
below.

"Closed" in this table means exactly one thing: the requirement is now stated
unambiguously in this record. It never means a control is implemented. Because
the point of this table is a compact summary, its Disposition cell carries the
same qualifier the detailed requirement carries at its own location, so a reader
who reads only this table cannot reach the wrong conclusion about code:

- **"closed as a requirement; [specified, not implemented]"** — stated
  completely in this record, and no code implements it on the base pin or on
  `de77e17`.
- **"closed as a requirement; implemented on the base pin, unmerged"** —
  stated completely _and_ present in the [Control
  inventory](#control-inventory), still available to no consumer.

Every requirement named in the "Requirement now stated at" column carries its
own `[specified, not implemented]` marker at that location, so the qualifier
does not depend on reading this table. This table is a summary of a
distinction made elsewhere, never the place the distinction is made.

| Finding                                                         | Was      | Requirement now stated at                                              | Disposition                                                                                                                                                |
| --------------------------------------------------------------- | -------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B1 redirect ownership                                           | partial  | "Redirects, proxy responses, and `CONNECT`", steps 1-5                 | closed as a requirement; mixed — see the per-step markers at steps 1-5                                                                                     |
| B3 pool key completeness                                        | partial  | "Pool ownership, checkout, and invalidation"; criterion 7              | closed as a requirement; **[specified, not implemented]**                                                                                                  |
| B7 remote revocation                                            | partial  | "Rotation, leases, and remote revocation", step 3                      | closed as a requirement; **[specified, not implemented]**                                                                                                  |
| B9 serialization shape                                          | partial  | "Serialization and equality"; criterion 12                             | closed as a requirement; **[specified, not implemented]**                                                                                                  |
| N1 header stripping on either origin change                     | blocking | step 5 of the redirect list and the block after it; criterion 5        | closed as a requirement; **[specified, not implemented]** on the proxy-origin half; implemented on the base pin, unmerged, for the destination-origin half |
| N2 pool key uniqueness including credential-record identity     | blocking | the five-field pool key, the non-uniqueness paragraph, and criterion 7 | closed as a requirement; **[specified, not implemented]**                                                                                                  |
| N3 no-flatten, no-arbitrary-map serialization rule              | blocking | "Serialization and equality"; criterion 12                             | closed as a requirement; **[specified, not implemented]**                                                                                                  |
| N4 remote revocation terminating already-authenticated sessions | blocking | step 3 of the rotation list; criterion 10                              | closed as a requirement; **[specified, not implemented]**                                                                                                  |

All four `N` rows are therefore **[specified, not implemented]** requirements.
Their code-level state is also listed in the [Control
inventory](#control-inventory) for completeness, but the marker above is what
makes the distinction, and it is repeated at the requirement itself.

### Control inventory

Every row below was read out of the base-pinned working tree at `941c235`, not
inferred from a pull request description or a task report. The table is scoped
to the [base pin](#base-pin-and-how-to-read-this-record): when the pin moves,
every row must be re-read, and this table is updated in the same change as the
pin. No row is merged; the base pin is open under PR #44. "Merge status" states
whether a consumer can obtain that code today. A row whose state is not
`present` means the control is absent from both the base pin and `de77e17` and
is a requirement of this record, not a claim about existing code.

This table deliberately carries no per-control "providing commit" column. A
per-control commit attribution cannot self-maintain: the commit graph moves on
every merge and rebase, so such a column is wrong again by the next commit and
cannot be checked without reading it. What replaces it is the single base pin
above, which `git rev-parse` verifies mechanically, plus the property pins in
[Executable property pins](#executable-property-pins), which fail the suite
rather than a document when a control regresses.

| Control                                                                                                                                                 | State on the base pin                           | Merge status     | Location                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hand-written redacting `Debug` for `HttpNetworkService`                                                                                                 | present                                         | unmerged, PR #44 | `crates/bitty-network/src/http.rs:217`-`:225`                                                                                                                                                                                                                                                                                                                              |
| `Egress` has neither a `Debug` derive nor a `Debug` impl                                                                                                | present                                         | unmerged, PR #44 | `http.rs:298`-`:304`                                                                                                                                                                                                                                                                                                                                                       |
| `Egress` no longer retains an `https_proxy` field                                                                                                       | present                                         | unmerged, PR #44 | `http.rs:235`-`:240`, `:298`-`:304`                                                                                                                                                                                                                                                                                                                                        |
| `ALL_PROXY` read alongside `HTTP_PROXY` and `HTTPS_PROXY`                                                                                               | present                                         | unmerged, PR #44 | `http.rs:136`, `:139`, `:142`; used `:257`, `:260`, `:263`                                                                                                                                                                                                                                                                                                                 |
| `with_proxy` returns a typed failure before retaining or dialing                                                                                        | present                                         | unmerged, PR #44 | `http.rs:243`-`:254`, `:347`-`:353`; test `http.rs:1049`-`:1059`                                                                                                                                                                                                                                                                                                           |
| `proxy_url_has_credentials` structural userinfo predicate                                                                                               | present                                         | unmerged, PR #44 | `http.rs:798`-`:805`                                                                                                                                                                                                                                                                                                                                                       |
| `validated_proxy_url` rejects userinfo before any `Proxy::all` or `.proxy()`, on the explicit path and on the environment path                          | present                                         | unmerged, PR #44 | `http.rs:807`-`:812`, `:820`-`:834`, `:243`-`:265`                                                                                                                                                                                                                                                                                                                         |
| Fail closed on unusable environment configuration, with no direct fallback                                                                              | present                                         | unmerged, PR #44 | `http.rs:311`-`:323`, `:355`-`:359`, called from `:774` and `:785`                                                                                                                                                                                                                                                                                                         |
| Credential-bearing environment proxy URL rejected before retention, with child-process canary coverage                                                  | present                                         | unmerged, PR #44 | `crates/bitty-network/tests/http.rs:321`-`:352`                                                                                                                                                                                                                                                                                                                            |
| WebSocket proxy leg rejects userinfo before dialing                                                                                                     | present                                         | unmerged, PR #44 | `crates/bitty-network/src/websocket.rs:1007`-`:1010`, `:1177`-`:1184`; test `:2789`-`:2809`                                                                                                                                                                                                                                                                                |
| Named regression `authenticated_proxy_is_rejected_before_dial`                                                                                          | present                                         | unmerged, PR #44 | `crates/bitty-network/src/websocket.rs:2789`-`:2809`                                                                                                                                                                                                                                                                                                                       |
| `.no_proxy()` and `Policy::none()` on every reqwest client construction                                                                                 | present                                         | unmerged, PR #44 | `http.rs:378`-`:388`, `:828`-`:831`, `:845`-`:849`; pin test `tests/http.rs:699`-`:726`                                                                                                                                                                                                                                                                                    |
| Redirect following disabled on every client; owned bounded hop loop                                                                                     | present                                         | unmerged, PR #44 | `http.rs:169`, `:381`, `:441`-`:491`                                                                                                                                                                                                                                                                                                                                       |
| Fixed `CONNECT` target; no target change after the tunnel opens                                                                                         | present                                         | unmerged, PR #44 | `websocket.rs:1167`-`:1195`; target built at `:1185`                                                                                                                                                                                                                                                                                                                       |
| Sensitive-header stripping on a destination-origin change                                                                                               | present                                         | unmerged, PR #44 | `http.rs:187`-`:188`, `:475`-`:476`, `:711`-`:717`; test `tests/http.rs:549`-`:585`                                                                                                                                                                                                                                                                                        |
| Redacted diagnostic snapshot constructors                                                                                                               | present, but wired into no caller               | unmerged, PR #44 | `crates/bitty-network/src/diagnostics.rs:49`, `:132`, `:141`, `:150`, `:159`; no caller outside the module, and `diagnostics.rs:12`-`:14` defers the wiring                                                                                                                                                                                                                |
| Named regression `credentialed_proxy_fails_closed_without_debug_secret`                                                                                 | **absent from both baselines**                  | not applicable   | no occurrence in the tree on the base pin. The property it was meant to guard — a credential cannot escape through the service's `Debug` — is instead pinned by `http_network_service_debug_is_hand_written_and_cannot_emit_a_credential`; the nearest pre-existing coverage is `explicit_credentialed_proxy_is_rejected_without_exposed_secret` at `http.rs:1049`-`:1059` |
| Sensitive-header stripping on a **proxy-origin-only** change (N1)                                                                                       | **absent from both baselines**                  | not applicable   | `http.rs:475` conditions stripping on `!same_origin(&url, &destination)`, a destination comparison with no proxy term; `same_origin` is `:689`-`:697`. The requirement is marked **[specified, not implemented]** in [Redirects, proxy responses, and `CONNECT`](#redirects-proxy-responses-and-connect)                                                                   |
| `with_proxy` retains a structurally sanitized endpoint rather than the caller's bytes                                                                   | **absent from both baselines**                  | not applicable   | `validated_proxy_url` returns `url.to_owned()` (`http.rs:811`) into `ProxyRoute.all` (`:247`); the retained value is credential-free but not parse-derived                                                                                                                                                                                                                 |
| `Request`, `WebSocketRequest`, and `Response` free of derived `Debug` and `PartialEq`                                                                   | **absent from both baselines**                  | not applicable   | `crates/bitty-network-api/src/lib.rs:334`-`:335`, `:463`-`:464`, `:432`-`:440`. **[specified, not implemented]** and pinned in both directions by `api_vocabulary_types_still_derive_debug_and_equality_and_still_leak`, so the derive set cannot change without the change failing                                                                                        |
| Forbidden `Serialize`/`Deserialize` on credential-bearing types                                                                                         | **absent from both baselines, and unreachable** | not applicable   | neither crate depends on `serde` on the base pin, so no type can implement a serde trait; the ban is satisfied by the dependency set, not by a redaction boundary                                                                                                                                                                                                          |
| `ProxyCredentialProvider`, `CanonicalOrigin`, scope registry, pool key, `AuthorizationLease`, `proxy::inject_authorization`, remote-revocation evidence | **absent from both baselines**                  | not applicable   | none of these identifiers exists in the tree on the base pin; `crates/bitty-network/src/proxy.rs` is a 49-line feature-gate predicate module. This record defines them                                                                                                                                                                                                     |
| Tracing attribute allowlist and static metric label schema with exemplars                                                                               | **absent from both baselines**                  | not applicable   | neither crate depends on `tracing` or on a metrics facade on the base pin; there is no exporter, descriptor, or label schema to enforce or scan                                                                                                                                                                                                                            |
| Child-process failed-`PartialEq`-assertion redaction coverage                                                                                           | **absent from both baselines**                  | not applicable   | `tests/http.rs:227`-`:270` spawns a child and the credential cases at `:321`-`:352` scan its combined stdout and stderr, but nothing on the base pin triggers a failed equality assertion on a credential-bearing type, because the only credential-bearing types with a derived `Debug` are the API vocabulary types, which no backend formats                            |
| Environment-proxy inheritance gated on the `proxy` feature                                                                                              | **absent from both baselines**                  | not applicable   | `HttpNetworkService::new` calls `ProxyRoute::from_env` unconditionally (`http.rs:311`-`:323`) and `http.rs` never calls `proxy::env_proxy_enabled()` (`proxy.rs:24`-`:27`). Owned by CTX-0034 and remediated under CTX-0043; recorded here as a fact about the base pin, not as this record's scope                                                                        |

The single most important consequence of this table: the base pin
closes the pre-dial userinfo rejection gap on both the explicit and the
environment path, but it closes it as _permanent rejection of proxy-URL
userinfo_. That is exactly the posture this record requires today, and it is
not progress toward authenticated proxies. Nothing on the base pin reads a
credential, stores one, injects one, or revokes one.

### Executable property pins

Factual claims about code are the failure mode this record has already hit
three times: they were true when written and silently wrong after the next
merge. The claims that can be expressed as a property are therefore expressed
as a test instead, in
`crates/bitty-network/tests/proxy_credential_policy.rs`. A change that breaks
one of these fails the suite, so it cannot invalidate this document unnoticed.

| Pin                                                                       | Property it enforces                                                                                                                                                                                                                                                                                                                                                      | Claims in this record it replaces                                                                                                                                                                                                           |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `http_network_service_debug_is_hand_written_and_cannot_emit_a_credential` | `HttpNetworkService` has a hand-written redacting `Debug` — no `Debug` derive on the type — and `format!("{service:?}")` of a proxy-configured service emits no proxy URL, host, port, user, or password                                                                                                                                                                  | the hand-written-`Debug` row, and the claim that the service's `Debug` cannot emit a credential                                                                                                                                             |
| `api_vocabulary_types_still_derive_debug_and_equality_and_still_leak`     | `Request`, `WebSocketRequest`, and `Response` still derive `Debug` and `PartialEq`, **and** the derived `Debug` still emits a header value, a URL userinfo, and a subprotocol                                                                                                                                                                                             | the `Request`/`WebSocketRequest`/`Response` derives row, and the open item that the derives are an unmitigated leak. Fails in both directions: removing a derive breaks the build, and adding a redacting `Debug` fails the leak assertions |
| `credentialed_proxy_url_never_reaches_proxy_construction`                 | no credential-bearing proxy URL reaches `Proxy::all` or `.proxy()`, on the explicit path (five userinfo shapes, each rejected with a typed failure before retention and before dialing) and on the environment path (a child process per variable, requiring a closed failure, no canary on any observable channel, and zero hits on both the origin and the proxy probe) | the predicate, the explicit-path rejection, and the environment-path rejection rows, including the requirement that a credential-free proxy URL is still accepted                                                                           |

Each pin is mutation-checked: the property was broken in a scratch copy and the
corresponding test was observed to fail, in both directions where both exist.
The pins are scoped to the [base pin](#base-pin-and-how-to-read-this-record)
like the inventory. If the base moves, re-read the inventory and re-run the
pins; if a pin fails, treat it as a control regression and fix the code or this
record in the same change, never by deleting the assertion.

The pins do not cover, and cannot cover, the requirements that are
**[specified, not implemented]**: there is no code to pin. Those requirements
are held by the in-place markers described under
[Specified is not implemented](#specified-is-not-implemented), and by nothing
else.

### Findings

On the merged mainline `de77e17` the pre-dial rejection requirement is
necessary but not implemented. On the base pin that
specific gap is closed for proxy-URL userinfo on both the explicit and the
environment path, and it is closed in the direction this record requires; the
API diagnostic path, the `with_proxy` sanitization requirement, the
proxy-origin-only header-stripping requirement, and every provider-side control
remain unimplemented on both baselines, while the provider/backend separation is
architecturally sound. This design requires explicit redirect ownership,
proxy-redirect rejection, immutable scope snapshots, complete pool keys,
synchronized leases, close-and-wait rotation, zero-overlap remote revocation,
canonical origins, and structural redaction across language and
observability channels. Every one of those is **[specified, not
implemented]**; the sentence lists what the design requires, not what exists.

No authenticated-proxy implementation was reviewed, on either baseline. The
base pin does own a redirect loop, and that loop does re-evaluate the
capability and the proxy decision per hop, but it performs no credential
authorization: there is no attachment, no lease, and no scope epoch to renew, so
it is not the redirect interception this record requires. There is likewise no
implementation evidence for provider lifecycle, wire injection, connection
pooling keyed by scope, lease synchronization, cache eviction, tunnel
invalidation, protocol selection, remote revocation, or diagnostic redaction on
any request path. The design also does not authorize sending credentials over an
unconfidential proxy hop. A separate implementation decision must select an
authentication protocol and confidential transport. If no such transport exists,
authenticated proxies remain unsupported.

This is a design-stage review, not an implementation review or third-party-use
approval. The note records requirements and remaining gates; it does not
accept the decision, replace the current rejection requirement, or claim that a
future implementation is secure.

## Transition criteria

The fail-closed rejection requirement remains in force until this decision is
accepted, implemented, and independently reviewed. Every criterion below is
required before any authenticated proxy path may be enabled.

**Every criterion below is [specified, not implemented].** Not one of them is
satisfied by the base pin or by `de77e17`. The criteria are stated here as
requirements and are deliberately not weakened to reflect the partial,
unmerged coverage recorded in the [Control inventory](#control-inventory) or
pinned by the [executable property pins](#executable-property-pins). A
criterion whose supporting tests exist only on the unmerged integration branch
is not met, because merged, independently reviewed, credential-capable code is
the only thing that can satisfy a transition gate.

1. Independent acceptance records this decision and updates its status.
2. A separately scoped implementation supplies the single provider, canonical
   origin type, injection boundary, redirect owner, scope registry, lease
   protocol, remote-revocation protocol, and redaction boundary without an
   unreviewed dependency or protocol.
3. Baseline and permanent-rejection tests prove that explicit and environment
   proxy URLs containing userinfo fail before retention, client construction,
   dialing, or fallback; malformed environment proxy configuration makes the
   service fail closed; every client disables ambient proxy discovery; and
   WebSocket rejection occurs before proxy or destination dialing.
4. Canonicalization tests cover absent, explicit-default, and non-default ports
   for both proxy and destination origins; `https` proxy without a port is 443;
   all four destination schemes use the closed table; mixed-case, IDNA, IPv4,
   and IPv6 forms canonicalize deterministically; and WebSocket scheme is not
   lost behind a TLS boolean.
5. Redirect tests prove automatic client redirects are disabled, the owned
   loop is bounded by hop count and total deadline, every destination hop
   reevaluates `NO_PROXY` and obtains fresh scope and authorization, changed
   destination or proxy origins (including a proxy-origin-only change to a
   different forward proxy) strip `Authorization`, `Cookie`, and
   `Proxy-Authorization` and invalidate connections, path-only reuse is
   limited to the exact current pool key, and ambiguous provenance fails
   closed.
6. Proxy-redirect tests prove that `3xx` from `P1`, including `CONNECT`
   responses and forward-proxy responses outside a tunnel, is rejected before
   redirect processing and that no attachment, client, connection, header, or
   lease reaches `P2`.
7. Pool tests concurrently exercise checkout, invalidation, and destruction to
   prove that a connection is usable only under a current lease and that pools
   for different proxy origins, destination origins, credential-record
   identities, generations, or scope epochs are never reused. Two records with
   equal generation and scope epoch must still have distinct pools and no
   authenticated object may cross between them.
8. Scope tests publish `{A}`, prove its objects cannot serve a newly widened
   `{A,B}` scope, then publish `{A,B}` with a new immutable snapshot and prove
   that every old attachment, client, pool, connection, and tunnel is
   invalidated before `B` can be reached.
9. In-flight rotation tests synchronize a request after it acquires generation
   `G` but before its final write, rotate while it is paused, and prove no `G`
   write occurs after rotation completion. They also cover tunnel writers,
   cancellation, close-and-wait, shutdown timeout, and fail-closed behavior
   without reopening a fallback.
10. Remote-revocation tests prove the overlap bound is zero: a new generation
    remains staged and unusable while the old credential is accepted; missing,
    stale, ambiguous, negative, or impossible revocation leaves authenticated
    proxy use disabled; and an authenticated confirmation bound to proxy origin
    and credential identity permits activation only after the old credential is
    rejected, all already-authenticated sessions using it are terminated or an
    authenticated inventory proves that none remain, and the replacement is
    accepted. A fresh rejection without session termination or proof that none
    remain is insufficient.
11. `NO_PROXY` and provider tests prove bypass makes no provider call and sends
    no proxy credential, non-bypass resolves exactly one current record, every
    redirect reevaluates the bypass decision, malformed proxy configuration is
    never ignored, and no path falls back to direct or unauthenticated egress.
12. Redaction tests cover hand-written `Debug` and `Display` on service,
    provider, record, attachment, lease, client, pool, connection, tunnel,
    `Request`, `WebSocketRequest`, and error types; forbidden serde traits and
    explicit rejection of `#[serde(flatten)]` or arbitrary/dynamic-map
    sanitized projections; failed `PartialEq`/`Eq` assertion output;
    `expect`/`unwrap`/panic paths;
    third-party `Debug`, `Display`, string conversion, retained source, and
    source chains; tracing span and event attributes; metric descriptors,
    labels, values, and exemplars; raw assertion messages; `dbg!`; snapshots;
    and child-process or crash output. Distinct username, password, URL,
    header, generation, and scope-epoch canaries must be absent from every
    captured channel.
13. The implementation task runs and passes the repository-owned recipes
    `just check`, `just check-http`, `just check-websocket`, `just typecheck`,
    and `just actionlint`. The HTTP and WebSocket feature recipes are
    mandatory; default `just check` alone is insufficient. The task also runs
    `gitleaks detect --source .` and removes task-created target directories.
14. An independent implementation security review finds no unresolved blocking
    issue. Only after that review may a later task change this record's status
    or enable an authenticated proxy path.

No draft decision, available credential provider, successful fixture, pending
PR, or passing unit test by itself lifts this gate. Issue #25 remains open
until the later implementation and review lifecycle completes.
