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
the key outside the repository, and remove it when the test ends.

A file source is an explicit path supplied by the caller and read only when the
provider is built. The library does not create, discover, or persist credential
files. Inline key material is runtime-only, is accepted only as an explicit
source, and is not copied into durable configuration. The implementation must
minimize retained byte copies and zeroize owned temporary private-key buffers.
The operator remains responsible for access controls on any credential file.

Private-key material never appears in logs, error strings, `Display` output,
diagnostics, traces, panic messages, or test output. Errors use stable typed
categories and must not embed PEM contents, key bytes, passphrases,
credential-bearing URLs, or raw key-source paths. Diagnostic output may report
non-secret facts such as whether an identity is configured or whether a
selected host matched a rule.

Every new TLS configuration type, and every wrapper or service type that can
transitively reach key material, must use a hand-written redacting `Debug`
implementation. Deriving `Debug` on a type containing a key source is
prohibited. The safe form may expose source-kind and selection metadata, but
not raw paths, bytes, PEM, passphrases, or credential-bearing values.

This is a direct application of the CTX-0028 finding in this repository: a
derived `Debug` on `HttpNetworkService` could expose a proxy credential. That
defect was fixed with a hand-written `Debug` that emitted only non-secret proxy
state. TLS configuration follows the same rule and adds negative tests with a
canary key value before implementation review.

## Security-corpus review note

### Reviewed

- Issues #21 and #22, their parent #14, and the CTX-0021 implementation scope.
- The current `tls.rs` marker and the HTTP and WebSocket native-root paths.
- The merged lane-D decisions: client-only construction (#26), the deferred
  credential gate (#28), explicit proxy handling (#29), and the unchanged QUIC
  and bridge boundaries (#27 and #30).
- The CTX-0028 proxy-credential and derived-`Debug` precedent.

### Findings

The safe default is the current one: native roots and no client certificate.
The main design risks are silent native-root replacement, partial or ignored
CA configuration, an ambient client identity, cross-host identity reuse after a
redirect or through connection pooling, and credential disclosure through
formatting or errors. The decisions above make those cases explicit,
fail closed, and independently testable.

No implementation controls were reviewed because none exist. This is a
design-stage security-corpus review, not an implementation review and not
third-party-use approval.

### Gate posture

CTX-0021, the consumer implementation lane, cannot start until this record
exists on its base branch. It must implement the policy without weakening the
capability, proxy, or typed-error contracts already decided for the backends.

BN-8 remains ordered: this design review first, then CTX-0021 implementation,
then implementation-level security review. Third-party use stays blocked until
the implementation lands and receives that review. The implementation review
must verify native-plus-custom root composition, bundle failure behavior,
HTTP/WebSocket parity, exact host selection across redirects and pooled
connections, fail-closed identity loading, and canary-based redaction across
`Debug`, `Display`, errors, logs, and diagnostics. Any proposal to replace
native roots or add an ambient/default client identity returns for a new
decision and security review.
