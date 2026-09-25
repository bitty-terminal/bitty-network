# #25: authenticated proxy credentials — fail-closed policy

Status: proposed; design-stage security-corpus review corrected by CTX-0037;
authenticated proxy support is not implemented on the reviewed baseline.

Parent: #15 (BN-2 policy depth slice).

## Decision

This record defines the required design for authenticated proxies. It does not
implement authentication, select an authentication protocol, or authorize a
dependency.

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
architectural rule does not imply that the reviewed backend already enforces
userinfo rejection or fail-closed environment handling.

## Credential source and scope snapshots

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
| ------- | -----------: |
| `http`  |           80 |
| `ws`    |           80 |
| `https` |          443 |
| `wss`   |          443 |

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
5. rebuilds host headers and strips caller `Authorization`, `Cookie`, and
   `Proxy-Authorization` whenever the destination origin changes.

The old authorization, client, pooled connection, and tunnel cannot be reused
when either origin changes. A path-only change on the same proxy origin,
destination origin, scope epoch, and generation may reuse only a connection
from that exact pool key with a current lease. Header stripping and fresh
authorization are still required for that hop.

A redirect response is accepted as an origin redirect only when the transport
can prove it came from the tunneled destination. A `3xx` produced by a proxy,
including a `CONNECT` response or a forward-proxy response outside an
established tunnel, is rejected before it can enter the redirect loop. Proxy
redirects from `P1` to `P2` are never followed, and no attachment, client,
connection, header, or lease is copied to `P2`. Ambiguous response provenance
fails closed.

A tunnel target is fixed by its `CONNECT` request to the canonical destination
host and effective port. Any redirect, retry, reconnect, or protocol action
that would change that target closes the old tunnel and repeats `NO_PROXY`,
canonicalization, scope checks, route selection, and authorization. No
credential issued for one target may be replayed to another. After `CONNECT`,
only end-to-end tunnel data crosses that boundary; proxy authorization never
enters the tunnel.

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
falls back to direct egress, an older route, or unauthenticated proxy use.

The reviewed baseline is defective in this area. On `origin/main` commit
`de77e17`, HTTP environment handling reads only `HTTPS_PROXY`/`https_proxy` and
`NO_PROXY`/`no_proxy`; `HttpNetworkService::new` discards an unusable configured
proxy and becomes direct, `proxy_client` has no structural userinfo rejection,
the WebSocket path strips proxy userinfo and proceeds to dial, and no client
builder calls `.no_proxy()`. The provider/backend separation above is a design
requirement, not evidence that these existing paths enforce it.

## Pool ownership, checkout, and invalidation

Every authenticated client and connection pool has one scope registry owner.
A pool key is a structured value containing at least:

- canonical proxy origin;
- canonical destination origin;
- credential generation; and
- scope epoch.

The key may include transport and protocol discriminants, but no code path may
omit one of these four fields. A client, pool, connection, authorization
attachment, or tunnel is owned by exactly one registry entry and is accessible
only while holding a lease obtained from that entry. Shared clients cannot be
reached through an unscoped service field.

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

Every authorization attachment carries an `AuthorizationLease` tied to its
record snapshot, scope epoch, generation, and pool key. The final
check-and-write operation holds a shared synchronization guard, reloads the
current scope and generation, verifies that the lease is active, and writes
only while that guard remains held. Rotation takes the exclusive guard before
publishing retirement. Consequently, a write that passed an earlier boundary
either completes before retirement is published or cannot begin afterward.

Rotation is a fail-closed state transition, not an operator instruction to
overlap credentials:

1. Stage the replacement without exposing it to selection.
2. Enter a local draining state that prevents new leases, cancels old leases,
   closes old clients, connections, and tunnels, and waits for their bounded
   shutdown. A shutdown timeout faults authenticated proxy use; it does not
   activate the replacement.
3. Require remote revocation of the old credential and a confirmation bound to
   the canonical proxy origin and old credential identifier. The confirmation
   must prove that an authentication attempt using the old credential is
   rejected and that the replacement is accepted, without exposing either
   secret in evidence.
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

The reviewed baseline does not provide the claimed safe diagnostics. On
`origin/main` commit `de77e17`, `HttpNetworkService` and `Egress` derive
`Debug`, `Egress` retains `https_proxy`, and `with_proxy` retains the raw URL.
In `bitty-network-api`, `Request` and `WebSocketRequest` derive `Debug` and can
contain credential-bearing header values and URLs. The reviewed baseline
therefore has no hand-written redacting `Debug` for these types and no safe
basis for claiming that a failed equality assertion is redacted.

PR #43 is open and blocked. Its pending branch contains a hand-written
`HttpNetworkService` `Debug`, pre-dial WebSocket userinfo rejection,
fail-closed environment handling, `.no_proxy()`, and related tests, but those
changes are not on `origin/main`; it does not replace the API request derives
or satisfy this decision's transition criteria.

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
hide fields is prohibited. Serialization failure messages must be redacted too.

`PartialEq` and `Eq` are permitted only when the same type has a hand-written
redacted `Debug` and its fields do not expose secrets through comparison
failures. The current `Request` and `WebSocketRequest` derives do not meet this
gate. Tests deliberately trigger a failed equality assertion in a child process
and prove that captured output contains neither a raw URL nor a header canary.

### Errors, panics, and third-party sources

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
free of them.

### Traces

Tracing uses statically named spans and events with explicit attribute
allowlists. A span may contain a canonical redacted origin only when necessary
for debugging; it never contains a raw or complete URL, path, query, hostname
when an origin-level class is sufficient, header, authorization attachment,
credential identifier, generation, scope epoch, or secret. Event attributes use
stable enums, bounded error classes, booleans, and non-secret counts. Dynamic
request data is excluded. Tests export spans and events to an in-memory
exporter and scan every attribute name and value for credential canaries.

### Metrics

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

Tests must not place raw URLs, headers, requests, responses, connections,
attachments, errors, or source chains into `assert_eq!`, `assert_ne!`, `dbg!`,
snapshots, assertion messages, or captured child-process output. Tests compare
sanitized projections, bounded enums, booleans, lengths, or fingerprints.
Snapshot fixtures contain only redacted data, and snapshot updates fail closed
when raw credential-capable data is present.

The current tests interpolate raw observed proxy request text into assertion
messages, including the HTTP absolute-form request and the WebSocket
`CONNECT` line. Those patterns are prohibited for authenticated proxy work and
must be replaced by redacted structural assertions before this gate can pass.

## Security-corpus review note

### Reviewed baseline

This design-stage review inspected issue #25, this decision, the proxy feature
decision, the HTTP and WebSocket proxy boundaries on `origin/main` commit
`de77e17`, environment proxy handling, credential routing and host changes,
storage and rotation, cache lifetime, diagnostic exposure, and the open CTX-0028
work associated with PR #43. It identified missing implementation controls and
required future regression coverage; it did not execute absent regression
tests or credit unmerged code as an existing control.

At `origin/main` commit `de77e17`, pre-dial proxy-URL userinfo rejection,
fail-closed handling of unusable environment proxy configuration, and a
hand-written redacting `Debug` are not present. `HttpNetworkService` and
`Egress` derive `Debug` and retain `https_proxy`; `with_proxy` retains the raw
URL; `HttpNetworkService::new` drops unusable environment configuration and
becomes direct; `proxy_client` lacks structural userinfo rejection; the
WebSocket path strips userinfo and proceeds to dial; no client builder calls
`.no_proxy()`; and the named regressions are absent. PR #43 is open and
blocked, and its related corrections remain pending rather than reviewed
baseline controls.

### Findings

The current pre-dial rejection requirement is necessary but not implemented as
claimed on the reviewed baseline. The environment and API diagnostic paths are
currently defective, while the provider/backend separation is architecturally
sound. This design requires explicit redirect ownership, proxy-redirect
rejection, immutable scope snapshots, complete pool keys, synchronized leases,
close-and-wait rotation, zero-overlap remote revocation, canonical origins, and
structural redaction across language and observability channels.

No authenticated-proxy implementation was reviewed. There is no implementation
evidence for provider lifecycle, wire injection, redirect interception,
connection pooling, lease synchronization, cache eviction, tunnel
invalidation, protocol selection, remote revocation, or diagnostic redaction.
The design also does not authorize sending credentials over an unconfidential
proxy hop. A separate implementation decision must select an authentication
protocol and confidential transport. If no such transport exists,
authenticated proxies remain unsupported.

This is a design-stage review, not an implementation review or third-party-use
approval. The note records requirements and remaining gates; it does not
accept the decision, replace the current rejection requirement, or claim that a
future implementation is secure.

## Transition criteria

The fail-closed rejection requirement remains in force until this decision is
accepted, implemented, and independently reviewed. Every criterion below is
required before any authenticated proxy path may be enabled.

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
   origins strip sensitive headers and invalidate connections, path-only reuse
   is limited to the exact current pool key, and ambiguous provenance fails
   closed.
6. Proxy-redirect tests prove that `3xx` from `P1`, including `CONNECT`
   responses and forward-proxy responses outside a tunnel, is rejected before
   redirect processing and that no attachment, client, connection, header, or
   lease reaches `P2`.
7. Pool tests concurrently exercise checkout, invalidation, and destruction to
   prove that a connection is usable only under a current lease and that pools
   for different proxy origins, destination origins, generations, or scope
   epochs are never reused.
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
    rejected and the replacement accepted.
11. `NO_PROXY` and provider tests prove bypass makes no provider call and sends
    no proxy credential, non-bypass resolves exactly one current record, every
    redirect reevaluates the bypass decision, malformed proxy configuration is
    never ignored, and no path falls back to direct or unauthenticated egress.
12. Redaction tests cover hand-written `Debug` and `Display` on service,
    provider, record, attachment, lease, client, pool, connection, tunnel,
    `Request`, `WebSocketRequest`, and error types; forbidden serde traits;
    failed `PartialEq`/`Eq` assertion output; `expect`/`unwrap`/panic paths;
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
