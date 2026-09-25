# #21/#22: unified TLS provider — trust and client identity

Status: decided at design stage; implementation and third-party use remain
gated (CTX-0031).

Base pin: ref `integrate/lanes-abc` at commit `941c235` ([CTX-0041]), the
parent of the commit that adds this file. Every current-state statement in this
record is scoped to that ref-plus-commit pair and describes `941c235`, not
`origin/main` (`de77e17`), which does not contain it; readers must not carry
these statements onto `origin/main` without re-verifying them.

The base pin is a scope declaration, not a checked invariant. The pin suite
named below is evaluated against this branch's working tree, so it reports what
this branch's sources do and says nothing about which commit they came from.
This branch currently adds only this record and the test file to that base, so
the working tree and the base agree; that agreement is maintained by a human
merging forward and re-reading, and the suite does not verify it.

**Scoping rule.** Current-state claims hold at the base named above and
nowhere else, and nothing here keeps them true automatically. In particular the
suite does not pin the base: it reads the working tree through `include_str!`,
so it never observes `941c235`, and moving the base ref on its own — without
merging it into this branch — leaves every pin green and invisible to it. What
the pins enforce is the narrower property the sentences below actually rest on,
and the two cases that produces are:

- A base move that is merged here and **changes** a pinned property turns the
  suite red. The property assertion no longer holds, and its message names the
  record sentence to re-read.
- A base move that is merged here and **leaves every pinned property intact**
  keeps the suite green. That is deliberate rather than a gap: the pins are
  properties, not provenance, so a merge that preserves them is not a
  regression. It is also the limit of the guarantee — a current-state sentence
  can stop being true without any pin noticing — so re-verification after a
  base move stays a human obligation that no assertion discharges.

A pin on the base commit itself is deliberately absent. "The base is
`941c235`" would restate the paragraph above instead of checking anything and
would be deleted on sight at the next merge, which is why no assertion in
`crates/bitty-network/tests/tls_baseline_properties.rs` names a commit.

Parent: #14 (unified TLS provider slice; custom CA and client identity).

## Decision

Define one future TLS-provider vocabulary for both HTTP and WebSocket. This
record fixes the trust, identity-selection, storage, and redaction contracts;
it does not define or implement a `TlsConfig` type. At the pinned base,
`src/tls.rs` is only a sealed marker: it has no policy type, certificate data,
crypto, or I/O.

## CA-bundle vocabulary and trust model

The future vocabulary has one optional CA source with two mutually exclusive
forms:

- **Bundle path:** a caller-supplied path to a PEM bundle containing one or
  more CA certificates.
- **Inline PEM:** caller-supplied bytes containing the same PEM certificate
  bundle.

A configuration that supplies both forms is invalid; precedence is not
defined. An empty path, empty byte string, unreadable path, bundle with no
certificate, malformed certificate, or non-certificate PEM object is a
configuration error. The provider must not skip only the bad entry, fall back
to another source, or continue with a partial trust set.

In this record, a "validated custom root" is a complete X.509 certificate
with `basicConstraints` present and `CA=TRUE`; if `keyUsage` is present, it
includes `keyCertSign`; and its signature algorithm, public-key algorithm, and
key size are supported by both backends. Its subject and issuer names must be
parseable. At construction and again before a handshake uses the root,
`notBefore <= now < notAfter`; expired or not-yet-valid certificates are
configuration or handshake failures, with no grace period, stale-cache reuse,
or partial-bundle acceptance.

Each supplied certificate is an explicit custom trust anchor, not a blanket
leaf exemption. A peer leaf is accepted only when its presented chain
verifies to a native root or a supplied custom anchor, including
issuer/signature checks and applicable intermediate constraints; the leaf
must also pass the identity check below. The implementation review must
verify algorithm and key-size policy, chain construction, path-length and
name constraints, leaf key-usage/extended-key-usage behavior, and the
selected revocation policy. A successful parse alone is not certificate
validation, and no unavailable required check may silently downgrade trust.

A path is read and parsed once while the shared provider is constructed, not
on every handshake. Accepted certificates are appended to the native root set
to form one trust configuration consumed by both backends. Inline PEM follows
the same parse and validation path. No CA source is discovered from ambient
environment variables, a default filesystem location, or a platform-specific
search path.

The trust model is additive. Supplying either bundle form preserves every
native root and adds the validated custom roots; it does not replace, shadow,
or disable native roots. If native roots cannot be loaded, construction or the
handshake fails rather than silently continuing with custom-only trust. This
record defines no custom-only mode. Adding one requires an explicit future
decision that records the narrower trust model and its compatibility impact.

When the CA source is unset, the provider performs no bundle read or PEM
parse, installs no custom root, and uses the native roots exactly as the
backends use them at the pinned base. Those native roots are supplied by the
two transport stacks, not by this crate's own TLS module: the HTTP backend
gets them from reqwest `=0.13.5` with `default-features = false` and features
`["blocking", "rustls"]`, whose rustls-platform-verifier path reads the
platform root store (arrived with the HTTP backend in `08dd525`, verified at
the pinned base); the WebSocket backend gets them from tungstenite's
`rustls-tls-native-roots` feature. The resolved graph carries
`rustls-native-certs` and `rustls-platform-verifier` and carries no
`webpki-roots` bundle store, so on the native targets this crate is built and
tested for (Linux, macOS, Windows) the trust anchors are the platform's. The
only bundled CA source anywhere in that verifier tree is wasm32-only, and this
crate is a blocking-socket runtime that is not built for wasm32. `src/tls.rs`
provides no trust behavior at all and is not part of either path. HTTP and
WebSocket receive the same native trust configuration, and all existing
hostname and certificate verification remains in force. This is the default
and preserves that behavior.

## Client-identity policy

Client identity is optional and disabled by default. When enabled, one identity
consists of a certificate chain and its matching private-key source. The two are
one indivisible policy: a rule that selects an identity without both parts, or
a chain and key that do not match, is invalid and fails closed before a
handshake. Each certificate or key source is either an explicit file path or
caller-supplied PEM bytes. There is no default identity, environment lookup,
directory search, or implicit fallback.

Each identity rule names exact target hosts. Selection uses the canonical DNS
hostname of the final TLS target, after URL parsing and IDNA normalization.
Matching is case-insensitive and exact: wildcards, suffix matching, and a
default identity are not permitted. A host with no exact rule receives no
client certificate. Reusing one identity on several hosts therefore requires
listing each host explicitly; a certificate configured for one host is never
selected merely because another host is a parent, subdomain, redirect target,
or shares a suffix.

Here, "issued for" means cryptographic certificate identity validation for
the canonical target, not merely that a rule names the host. The selected
certificate must pass the backend's X.509 SAN/subject verification for that
target; SAN is authoritative, and a subject fallback is not assumed unless
the selected verifier explicitly supports and documents it. Rule assignment
selects an identity but never waives certificate name, chain, validity, or
key-use checks. A rule match with a certificate that is not valid for the
target fails closed.

Selection happens for every new TLS destination. Redirects reselect from the
redirect target, the proxy authority is not the identity selector, and pooled
connections authenticated with one client identity cannot be reused for a
different host. A selected identity that cannot be loaded, parsed, or paired
with its key is a typed failure; the provider must not silently downgrade that
connection to no client certificate.

## Credential storage and redaction

No plaintext secret is committed to this repository. Private keys,
passphrases, inline key bytes, and credential-bearing source values must not
appear in source, examples, snapshots, fixtures, or test data. Tests that need
a client certificate generate a test-only CA and private key at runtime, keep
the key outside the repository, and remove it when the test ends. The issue
#21 acceptance test must use an ephemeral local TLS endpoint on loopback with
that runtime-generated CA, exercise the HTTP and WebSocket paths, and make no
external network request. It must cover successful custom-root validation and
rejection of an untrusted endpoint without committing any key or certificate
fixture. This is an implementation requirement for CTX-0021; the current
design-stage record does not claim that such a test exists.

A file source is an explicit path supplied by the caller and read only when the
provider is built. The library does not create, discover, or persist credential
files. Inline key material is runtime-only, is accepted only as an explicit
source, and is not copied into durable configuration. The implementation must
minimize retained byte copies and zeroize owned temporary private-key buffers.
The operator remains responsible for access controls on any credential file.

Private-key material never appears in logs, error strings, `Display` output,
diagnostics, traces, panic messages, serialized output, or test output. Errors
use stable typed categories and must not embed PEM contents, key bytes,
passphrases, credential-bearing URLs, or raw key-source paths. Diagnostic
output may report non-secret facts such as whether an identity is configured
or whether a selected host matched a rule.

Secret-safe serialization is mandatory for every key-bearing and transitively
key-bearing type. A type containing a key source, or any wrapper or service
that can reach one, must not derive `Serialize` or `Deserialize`. Any
supported serde surface must use a hand-written redacted representation or a
separate non-secret DTO; it may emit only source-kind and selection metadata,
never raw paths, bytes, PEM, passphrases, or credential-bearing values, and a
deserializer must not reconstruct key material from that representation. This
covers configuration, diagnostics, snapshots, IPC, persistence, and test
artifacts.

Every new TLS configuration type, and every wrapper or service type that can
transitively reach key material, must use a hand-written redacting `Debug`
implementation. Deriving `Debug` on a type containing a key source is
prohibited. The safe form may expose source-kind and selection metadata, but
not raw paths, bytes, PEM, passphrases, or credential-bearing values.

At the pinned base the credential-facing controls this record leans on are
present but not on the default branch: the hand-written redacting `Debug` for
`HttpNetworkService` and the credential-bearing proxy-URL rejection arrived
with CTX-0028 (`9fc413e`, verified at the pinned base), which is an ancestor of
`941c235` and **not** of `origin/main` (`de77e17`) and is pending
code-owner approval on open PR #44 (also on PR #43). Those controls are
therefore absent from the `origin/main` baseline, and this record does not rely
on them. The TLS implementation must provide equivalent controls and prove them
independently, whether or not PR #44 merges.

Before implementation review, canary coverage must generate a unique in-memory
key and exercise `Debug`, `Display`, errors, logs, diagnostics, and every
supported serialization path, including configuration, snapshot, IPC, and
test-artifact representations. The resulting text and bytes must contain
neither the canary nor equivalent raw key material; a derived or transitive
serializer that emits a key is a test failure.

## How this record's current-state claims are verified

Every current-state claim in this record was verified at the pinned base
against the properties in `crates/bitty-network/tests/tls_baseline_properties.rs`
(`just check`, `just check-http`, and `just check-websocket` all run them). A
claim with no pin behind it is unverified and must be re-established before it
is relied on. The pins are deliberately properties of behavior, manifests, and
the resolved dependency graph, not of commit identity: they keep holding when
the graph is rebased or merged, and they fail the moment a change breaks the
property a sentence depends on. A change that alters a pinned property is
therefore expected to break a pin on purpose, so the record is re-read instead
of drifting. The converse is equally true and is stated here so the two are not
confused: a change that moves a current-state sentence without altering any
pinned property breaks nothing, and the scoping rule above — not the suite — is
what covers that case.

The transport-level egress control this record leans on — every reqwest client
builder disabling ambient system-proxy discovery and redirect following, and no
unconfigured client constructor bypassing them — is pinned by
`every_client_builder_disables_ambient_proxy_and_redirects` in
`crates/bitty-network/tests/http.rs`.

One pin asserts a gap on purpose: the absence of a bundled root store
(`webpki-roots`) in the resolved graph, because one appearing would silently
change the trust model the additive-roots rules above depend on.

The pin that previously recorded the `proxy` gate as an unconsulted predicate
has been **inverted**. When CTX-0034's call-site wiring landed, the deficiency
assertion fired by design and the record was re-verified against the new state.
`proxy_gate_is_consulted_before_any_environment_read` now pins the stronger
property in the other direction: `HttpNetworkService::new` consults the gate
**and** short-circuits before either environment reader runs, so a build
without `proxy` reads no proxy variable at all rather than reading one and
discarding it. That is a better property than the deficiency it replaced, and
it is the one that actually withholds the authority.

CTX-0034's unmerged work rebased onto this base and dropped its own duplicate
`.no_proxy()` insertions as redundant, so the reconciliation is a completed
event rather than a pending one: at this base there is exactly one
`.no_proxy()` implementation, present on all three reqwest client builders in
`src/http.rs`.

## Security-corpus review note

### Reviewed

- Issues #21 and #22, their parent #14, and the CTX-0021 implementation scope.
- The `tls.rs` marker and both native-root paths at the pinned base: the
  reqwest `blocking`+`rustls` stack for HTTP and the tungstenite
  `rustls-tls-native-roots` stack for WebSocket, with no bundled root store in
  the resolved graph.
- The merged lane-D decisions: client-only construction (#26), the deferred
  credential gate (#28), explicit proxy handling (#29), and the unchanged QUIC
  and bridge boundaries (#27 and #30). Decision #29 is merged as a predicate
  and its tests; its `HttpNetworkService::new` call-site wiring has since
  landed as well, so the gate is now consulted and short-circuits before any
  environment read, which
  `proxy_gate_is_consulted_before_any_environment_read` pins.
- The CTX-0028 proxy-credential and derived-`Debug` proposal, whose controls
  are present at this base, are carried by open PRs #43 and #44, and are
  absent from the `origin/main` (`de77e17`) baseline.

### Findings

The safe default is the one the two backends already implement at the pinned
base: platform native roots and no client certificate. `src/tls.rs` contributes
neither. The main design risks are silent native-root replacement, partial or
ignored CA configuration, weak or ambiguous certificate validation, an ambient
client identity, cross-host identity reuse after a redirect or through
connection pooling, and credential disclosure through formatting, errors, or
serialization. The decisions above make those cases explicit, fail closed,
and independently testable.

No TLS provider implementation controls were reviewed because the TLS policy
type and implementation do not exist. The HTTP baseline was checked
independently against the pinned base: the CTX-0028 redaction controls are
present there and absent from `origin/main` (`de77e17`), pending code-owner
approval on open PRs #43 and #44. This is a design-stage security-corpus
review, not an implementation review and not third-party-use approval.

### Gate posture

CTX-0021, the consumer implementation lane, cannot start until this record
exists on its base branch. It must implement the policy without weakening the
capability, proxy, or typed-error contracts already decided for the backends.
CTX-0028's redaction controls are present at the pinned base and remain PENDING
against `origin/main` until PR #44 lands and is independently verified; this
record does not treat them as landed on the default branch, and the TLS
implementation must supply and verify its own controls rather than assuming
them. The same rule applies to CTX-0034: its `proxy` feature gate call-site
wiring is unmerged, so CTX-0021 must not treat the `proxy` feature as a wired
gate on `origin/main` or on this base.

BN-8 remains ordered: this design review first, then CTX-0021 implementation,
then implementation-level security review. Third-party use stays blocked until
the implementation lands and receives that review. The implementation review
must verify native-plus-custom root composition, CA constraints and validity
at construction and handshake, chain and trust-anchor behavior, algorithm and
key-size policy, bundle failure behavior, HTTP/WebSocket parity, the required
ephemeral loopback TLS test with no external network, exact host selection
across redirects and pooled connections, fail-closed identity loading, and
canary-based redaction across `Debug`, `Display`, errors, logs, diagnostics,
and every supported serialization path. Any proposal to replace native roots
or add an ambient/default client identity returns for a new decision and
security review.
