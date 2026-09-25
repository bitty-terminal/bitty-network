# #21/#22: unified TLS provider — trust and client identity

Status: decided at design stage; implementation and third-party use remain
gated (CTX-0031).

Parent: #14 (unified TLS provider slice; custom CA and client identity).

## Decision

Define one future TLS-provider vocabulary for both HTTP and WebSocket. This
record fixes the trust, identity-selection, storage, and redaction contracts;
it does not define or implement a `TlsConfig` type. The current `tls.rs` module
is only a sealed marker: it has no policy type, certificate data, crypto, or
I/O.

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
current backends do. HTTP and WebSocket receive the same native trust
configuration, and all existing hostname and certificate verification remains
in force. This is the default and preserves current behavior.

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

At the review baseline, `origin/main` is `de77e17`. Its
`crates/bitty-network/src/http.rs` still derives `Debug` for
`HttpNetworkService` and `Egress` and stores accepted proxy URL strings,
including potentially credential-bearing URLs. Commit `9fc413e` (CTX-0028)
contains the hand-written redacting `Debug` and related credential handling,
but it is not an ancestor of `origin/main`; it is carried by PR #43 and remains
pending code-owner approval. CTX-0028's redaction controls are therefore
PENDING, not present, and are not relied on by this record. The TLS
implementation must provide equivalent controls and prove them independently.

Before implementation review, canary coverage must generate a unique in-memory
key and exercise `Debug`, `Display`, errors, logs, diagnostics, and every
supported serialization path, including configuration, snapshot, IPC, and
test-artifact representations. The resulting text and bytes must contain
neither the canary nor equivalent raw key material; a derived or transitive
serializer that emits a key is a test failure.

## Security-corpus review note

### Reviewed

- Issues #21 and #22, their parent #14, and the CTX-0021 implementation scope.
- The current `tls.rs` marker and the HTTP and WebSocket native-root paths.
- The merged lane-D decisions: client-only construction (#26), the deferred
  credential gate (#28), explicit proxy handling (#29), and the unchanged QUIC
  and bridge boundaries (#27 and #30).
- The CTX-0028 proxy-credential and derived-`Debug` proposal, whose controls
  are pending in PR #43 and absent from the `origin/main` baseline.

### Findings

The safe default is the current one: native roots and no client certificate.
The main design risks are silent native-root replacement, partial or ignored
CA configuration, weak or ambiguous certificate validation, an ambient client
identity, cross-host identity reuse after a redirect or through connection
pooling, and credential disclosure through formatting, errors, or
serialization. The decisions above make those cases explicit, fail closed,
and independently testable.

No TLS provider implementation controls were reviewed because the TLS policy
type and implementation do not exist. The HTTP baseline was checked
independently: the CTX-0028 redaction controls are pending in PR #43, not
present on `origin/main`. This is a design-stage security-corpus review, not
an implementation review and not third-party-use approval.

### Gate posture

CTX-0021, the consumer implementation lane, cannot start until this record
exists on its base branch. It must implement the policy without weakening the
capability, proxy, or typed-error contracts already decided for the backends.
CTX-0028's redaction controls remain PENDING until PR #43 lands and is
independently verified; this record does not treat them as current, and the
TLS implementation must supply and verify its own controls rather than
assuming them.

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
