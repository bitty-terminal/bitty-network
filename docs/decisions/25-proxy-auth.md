# #25: authenticated proxy credentials — fail-closed policy

Status: proposed; design-stage security-corpus review filed, implementation
remains fail-closed (CTX-0033).

Parent: #15 (BN-2 policy depth slice).

## Decision

This record defines the required design for authenticated proxies. It does not
implement authentication, select an authentication protocol, or authorize a
dependency.

The current behavior remains unchanged: credential-bearing proxy URLs are
rejected before dialing, unusable environment proxy configuration fails closed,
and no request falls back to direct egress. In particular, the WebSocket
rejection pinned by `authenticated_proxy_is_rejected_before_dial` and the HTTP
rejection and redacting `Debug` pinned by
`credentialed_proxy_fails_closed_without_debug_secret` remain mandatory.

A later implementation may narrow the broader "authentication unsupported"
posture only after every transition criterion below is met. It must not accept
proxy-URL userinfo as a credential source; that rejection is permanent under
this decision.

## Credential source and injection point

The single credential source is one caller-provided
`ProxyCredentialProvider` handle installed on `HttpNetworkService` at
construction. The provider owns lookup and rotation; `bitty-network` owns no
second credential source and performs no implicit environment-variable,
keyring, secret-file, or configuration-file lookup. The HTTP and WebSocket
paths share that one provider handle.

A provider record contains only non-secret routing metadata and opaque secret
material:

- a stable, non-secret credential identifier;
- the exact normalized proxy origin the credential may authenticate to;
- an explicit set of exact normalized destination origins it may be used for;
- the current credential generation.

The single wire-injection point is a future internal
`proxy::inject_authorization` boundary. It runs after capability checks, final
route selection, redirect processing, and proxy/destination normalization, but
immediately before the first byte of the proxy leg is sent. It receives the
actual proxy origin, effective destination origin, transport kind, and current
credential generation. It returns an opaque, short-lived proxy-only
authorization attachment.

Both the HTTP proxy-request path and the WebSocket `CONNECT` path must call
this one boundary. Neither backend may read the provider, parse userinfo,
construct an authentication header, or implement fallback lookup on its own.
There is exactly one implementation point because proxy authentication is a
property of the selected proxy route, not of an origin request or either
backend independently.

The attachment is added only to the proxy leg. It is never copied into the
end-to-end request, forwarded through a tunnel, or exposed to the origin.
Caller-supplied `Proxy-Authorization` request headers are rejected or removed
before dispatch so they cannot bypass provider scoping.

## Credential scope and host changes

A credential is usable only when both bindings match:

1. The actual proxy scheme, normalized host, and effective port exactly match
   the record's proxy origin.
2. The effective destination scheme, normalized host, and effective port
   exactly match one of the record's allowed destination origins.

Matching is exact after IDNA and default-port normalization. Wildcards,
suffix matching, ambient defaults, and "same host as the request" shortcuts are
prohibited. A malformed route, missing record, stale generation, or mismatch
fails closed before client construction, dialing, or writing. It never falls
back to an older credential, an unauthenticated proxy, or direct egress.

A `NO_PROXY` decision is made before credential resolution. A bypassed request
uses direct egress and neither queries the provider nor carries proxy
credentials.

Redirects are separate authorization decisions. Before following each redirect,
the implementation resolves the new effective destination and selected proxy
again. If the destination origin or proxy origin changes, the old
authorization, client, pooled connection, and tunnel are discarded. The new hop
must independently match a current provider record or the redirect fails
closed. A path-only change on the same exact origin may reuse only a
still-current, correctly scoped connection.

A tunnel target is fixed by its `CONNECT` request. Any redirect, retry, or
protocol action that would change that target must close the old tunnel and
repeat route selection, scope checks, and authorization for the new target. No
credential issued for one target may be replayed to another. After `CONNECT`,
only end-to-end tunnel data crosses that boundary; proxy authorization never
enters the tunnel.

Environment variables remain routing inputs only. `HTTP_PROXY`, `HTTPS_PROXY`,
and `ALL_PROXY` plus their lowercase forms may select a credential-free proxy
origin, but any value containing URL userinfo is rejected structurally before
the value is retained, cloned, copied into a client, or dialed. An unusable
credentialed value fails the whole proxied request closed and never causes a
direct fallback.

## Storage rules

No plaintext proxy secret is committed to this repository. Source, tests,
fixtures, examples, snapshots, diagnostics, and documentation must contain no
usable username, password, token, or credential value; security tests use
obvious non-secret fixtures.

The embedding application may persist credentials only in an OS-protected
secret store. `bitty-network` does not read or write a plaintext credential
file and does not accept a secret from an environment variable. Runtime secret
material exists only in the provider's protected process memory and the minimum
ephemeral transport buffers needed to authenticate a proxy connection.
Secret-bearing values must not be cloned merely for diagnostics, transport
selection, or service cloning. Owned secret buffers must be cleared on drop; if
a transport cannot guarantee that lifecycle, the implementation must isolate or
wrap that state so it is generation-tagged and evicted, and the limitation must
be accepted during implementation security review.

A type that owns or references a provider, proxy client, connection, tunnel, or
authorization attachment is treated as credential-bearing even if the secret
is currently redacted. Durable caches must not contain secret material. Any
in-memory client, connection pool, authorization, or tunnel that can retain
secret material is generation-tagged and subject to the eviction rules below.

## Rotation and eviction

Rotation is an atomic provider operation. The provider increments the
generation, marks the previous generation retired, and publishes the replacement
before any new-generation request is allowed. Selection never falls back to a
retired generation.

A credential is invalidated locally at the next authorization boundary.
Before a retired credential can be used, the generation check rejects it and
the request fails closed. If it has already been written to a proxy, local
rotation cannot recall bytes on the network; proxy-side revocation and
credential overlap are separate operator-controlled properties. The local
service must nevertheless stop all reuse of the retired generation, close its
authenticated clients and tunnels, and obtain fresh authorization before
continuing.

A rotated credential can be evicted from a cache and must be: cache lifetime
is not a substitute for rotation. Secret material itself is never cached.
Before the first new-generation proxy operation, every cache entry, pooled
connection, client, and tunnel tagged with the retired generation must be
invalidated and dropped. A cache that cannot prove this invalidation makes the
service fail closed and prevents authenticated proxy use.

Rotation failure, stale metadata, incomplete cache invalidation, or provider
unavailability never causes fallback to the old credential, an
unauthenticated proxy, or direct egress.

## Redaction and diagnostics

Logs, errors, traces, metrics, panic messages, test failure output, and crash
diagnostics must never contain proxy usernames, passwords, tokens, raw
userinfo, complete credential-bearing URLs, or authorization-header values.
Diagnostics may identify a redacted proxy origin only after structural removal
of userinfo. Rejection paths report a stable caller-safe error without echoing
the raw environment value, explicit URL, or third-party error text.

Redaction is structural, not best-effort replacement in a formatted string.
Malformed and percent-encoded userinfo must be removed by parsing into a
sanitized endpoint before any observable value is created. A raw proxy URL may
not be retained only to redact it later.

Any type that can hold or reference proxy credential material must implement
a hand-written redacting `Debug`; deriving `Debug` on that type is prohibited.
This includes service and egress configuration, provider handles, credential
records, authorization values, client/connection/tunnel wrappers, and errors
that can reference any of them. `Display`, error conversion, structured logging
fields, and diagnostic accessors must apply the same rule.

CTX-0028 is a binding design lesson. It found that `HttpNetworkService`
retained and cloned credential-bearing proxy URLs and that derived `Debug`
could emit the username and password into a caller log. Its correction rejects
credentialed URLs before client construction, fails unusable environment
configuration closed, and hand-writes a credential-free `Debug`. A future
authenticated implementation must preserve those properties and add coverage
for every new credential-bearing or credential-referencing type.

## Security-corpus review note

### Reviewed

This design-stage review covered issue #25, this decision, the existing proxy
feature decision, the HTTP and WebSocket proxy boundaries, the CTX-0028
credential-retention and derived-`Debug` finding, environment proxy handling,
credential routing and host changes, storage and rotation, cache lifetime, and
diagnostic exposure. It also checked the two fail-closed regression names cited
above as required invariants.

### Findings

The existing pre-dial rejection, environment fail-closed behavior, and
hand-written redacting `Debug` are necessary controls and must remain. The
design removes ambiguous credential sources, binds every use to both an exact
proxy and an exact destination, requires reauthorization after redirects or
tunnel target changes, and makes rotation actively invalidate prior-generation
state.

No authenticated-proxy implementation was reviewed. There is no implementation
evidence yet for provider lifecycle, wire injection, redirect interception,
connection pooling, cache eviction, tunnel invalidation, protocol selection,
or diagnostic redaction. The design also does not authorize sending credentials
over an unconfidential proxy hop. A separate implementation decision must
select an authentication protocol and transport that does not expose the
secret; if no such transport is available, authenticated proxies remain
unsupported.

This is a design-stage review, not an implementation review or third-party-use
approval. The note records design requirements and remaining gates; it does not
accept the decision, replace the current rejection, or claim that a future
implementation is secure.

## Transition criteria

The current fail-closed rejection remains in force until this decision is
accepted, implemented, and independently reviewed. All of the following are
required before any authenticated proxy path may be enabled:

1. Independent acceptance records this decision and updates its status.
2. A separately scoped implementation supplies the single provider and
   injection boundary without adding an unreviewed dependency or protocol.
3. HTTP and WebSocket tests prove exact proxy and destination scoping, no
   credential on an origin request, and reauthorization after every redirect or
   tunnel target change.
4. Environment and explicit proxy URLs containing userinfo still fail before
   retention, client construction, dialing, or direct fallback, and neither
   existing cited regression is weakened.
5. Log, error, and diagnostic tests cover every credential-bearing type and
   prove that usernames, passwords, tokens, raw URLs, and authorization values
   are absent.
6. Rotation tests prove that retired credentials cannot be selected or reused,
   that old-generation clients and tunnels are closed and evicted, and that no
   older, unauthenticated, or direct fallback occurs.
7. The repository quality gates and secret scan pass, followed by an
   independent implementation security review with no unresolved blocking
   finding.

No draft decision, available credential provider, successful fixture, or passing
unit test by itself lifts this gate. Issue #25 remains open until the later
implementation and review lifecycle completes.
