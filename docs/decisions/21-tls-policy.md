# #21/#22: unified TLS provider — trust and client identity

Status: decided at design stage; implementation and third-party use remain
gated (CTX-0031).

Base described by this record: branch `integrate/lanes-abc` at commit
`941c235` ([CTX-0041]), the parent of the commit that adds this file.
`origin/main` is `de77e17` and does **not** contain that base, so every
current-state statement below describes `941c235` and not `origin/main`;
readers must not carry these statements onto `origin/main` without
re-verifying them. The full control inventory with per-control providing
commit and merge status is in "Verified baseline and control provenance"
below.

Parent: #14 (unified TLS provider slice; custom CA and client identity).

## Decision

Define one future TLS-provider vocabulary for both HTTP and WebSocket. This
record fixes the trust, identity-selection, storage, and redaction contracts;
it does not define or implement a `TlsConfig` type. At the base described
above, `tls.rs` is only a sealed marker (inventory entry 1): it has no policy
type, certificate data, crypto, or I/O.

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
backends do at the base described above (inventory entries 1 and 9). HTTP and
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

At the verified baseline (`integrate/lanes-abc` `941c235`), the
credential-facing controls this record depends on are attributed in
"Verified baseline and control provenance" below. The short form: the
redacting `Debug` and the credential-URL rejection come from `9fc413e`
(CTX-0028), which is an ancestor of `941c235` but **not** of `origin/main`
(`de77e17`) and is therefore pending code-owner approval on open PR #44
(also on PR #43). CTX-0028's redaction controls are present at this base and
absent from `origin/main`; they are not relied on by this record. The TLS
implementation must provide equivalent controls and prove them
independently, whether or not PR #44 merges.

Before implementation review, canary coverage must generate a unique in-memory
key and exercise `Debug`, `Display`, errors, logs, diagnostics, and every
supported serialization path, including configuration, snapshot, IPC, and
test-artifact representations. The resulting text and bytes must contain
neither the canary nor equivalent raw key material; a derived or transitive
serializer that emits a key is a test failure.

## Verified baseline and control provenance

This section is the single place where a control is paired with the commit
or task that provides it and with its merge status. A control that appears
anywhere in this record without an entry here is unverified and must be
re-established before it is relied on.

Base: `integrate/lanes-abc` at `941c235` ([CTX-0041]). `origin/main` is
`de77e17` ([CTX-0015], merged as PR #40) and does not contain `941c235`; PR
#44 is open and awaiting a code-owner approval only the repository owner can
grant. `f51240a` (CTX-0034) is on `ctx-0034/fix-proxy-feature-gate` only: it
is an ancestor of neither `941c235` nor `origin/main` and has no PR.

Each entry names the control, the commit or task that provides it, that
commit's merge status, and the control's presence at `941c235` and at
`de77e17`. Line numbers are `crates/bitty-network/src/http.rs` line numbers
in the commit named by the entry, unless another path is given.

1. **TLS is a sealed marker** — no policy type, certificate data, crypto, or
   I/O. Provided by `a3c06f2` (shell transplant, PR #1); `src/tls.rs` is
   byte-identical at `de77e17` and `941c235`. Merged. Present at both, as a
   marker.
2. **Derived `Debug` on `HttpNetworkService` and `Egress`**, with
   `Egress.https_proxy: Option<String>` holding the accepted proxy URL.
   Provided by `de77e17` at `:123` and `:134`. Merged into `origin/main`.
   Absent at `941c235`; present at `de77e17`.
3. **Hand-written redacting `Debug` for `HttpNetworkService`** at `:217`, with
   `Egress` carrying `#[derive(Clone)]` only at `:299`. Provided by `9fc413e`
   (CTX-0028). An ancestor of `941c235` and of the `ctx-0013` head, so it is
   carried by open PRs #43 and #44; **not** an ancestor of `origin/main`.
   Present at `941c235`; absent at `de77e17`.
4. **Credential-bearing proxy URL rejection**, `proxy_url_has_credentials` at
   `:798`. Provided by `9fc413e` (CTX-0028). Merge status as entry 3. Present
   at `941c235`; absent at `de77e17` and absent at `f51240a`.
5. **reqwest system-proxy discovery disabled** — `.no_proxy()` on every client
   builder: `client_with` at `:380`, `proxy_client` at `:829`, and
   `proxy_route_client` at `:847`. Provided by `9fc413e` (CTX-0028), which
   carries its own `.no_proxy()` pair at its `http.rs:297` and `http.rs:541`.
   Merge status as entry 3. Present at `941c235` at all three sites; absent at
   `de77e17`, which has no `.no_proxy()` call anywhere.
6. **A second, independent `.no_proxy()` implementation** at `:218` and
   `:447`, written independently of entry 5 and not derived from it, together
   with the `env_proxy_enabled()` call-site wiring at `:155`. Provided by
   `f51240a` (CTX-0034). **Unmerged**: no PR, and an ancestor of neither
   `941c235` nor `origin/main`. Absent at both.
7. **`env_proxy_enabled()` predicate and its unit tests**
   (`src/proxy.rs:25`), the `proxy` feature annotation, and the
   `tests/offline.rs` pin. Provided by `de77e17` (PR #40). Merged into
   `origin/main`. Present at both refs.
8. **Proxy feature gate applied in `HttpNetworkService::new`.** Provided by
   `f51240a` (CTX-0034), which implements the contract that merged decision
   #29 records but deliberately did not apply. **Unmerged**: no PR. **Absent
   at `941c235`**, where `http.rs:315` reads `NO_PROXY`/`no_proxy` from the
   environment unconditionally — exactly the pre-wiring state decision #29
   states. Absent at `de77e17` as well.
9. **WebSocket TLS via rustls with native roots and no custom CA**
   (`src/websocket.rs:23` at `941c235`; `:20` at `de77e17`). Provided by
   `a6772ad` (PR #8). Merged into `origin/main`. Present at both refs.
10. **Merged lane-D decisions #26, #27, #28, #29, and #30.** Provided by
    `de77e17` (PR #40). Merged into `origin/main`. Present at both refs.

Two consequences follow, and both are load-bearing:

- Entries 5 and 6 are two implementations of one control, not one control
  recorded twice. `.no_proxy()` is present at the base only through
  `9fc413e`. If CTX-0034 (`f51240a`) is merged later, its pair must be
  reconciled against entry 5, and the reconciliation — not either commit
  alone — is what an implementation review may treat as the
  ambient-proxy-off control.
- Entry 7 without entry 8 is the present state of the merged `#29` contract:
  the predicate and its tests are merged, the call-site wiring is not. This
  record relies on neither; it states the gap so no reader mistakes a merged
  predicate for a wired gate.

## Security-corpus review note

### Reviewed

- Issues #21 and #22, their parent #14, and the CTX-0021 implementation scope.
- The `tls.rs` marker and the HTTP and WebSocket native-root paths at the
  base described above (inventory entries 1 and 9).
- The merged lane-D decisions: client-only construction (#26), the deferred
  credential gate (#28), explicit proxy handling (#29), and the unchanged QUIC
  and bridge boundaries (#27 and #30). Decision #29 is merged as a predicate
  and its tests only (`de77e17`); its `HttpNetworkService::new` call-site
  wiring is provided by unmerged `f51240a` (CTX-0034) and is absent at this
  base, as inventory entries 7 and 8 record.
- The CTX-0028 proxy-credential and derived-`Debug` proposal, whose controls
  are present at this base through `9fc413e`, are carried by open PRs #43 and
  #44, and are absent from the `origin/main` (`de77e17`) baseline.

### Findings

The safe default is the one the backends already implement at this base
(inventory entries 1 and 9): native roots and no client certificate.
The main design risks are silent native-root replacement, partial or ignored
CA configuration, weak or ambiguous certificate validation, an ambient client
identity, cross-host identity reuse after a redirect or through connection
pooling, and credential disclosure through formatting, errors, or
serialization. The decisions above make those cases explicit, fail closed,
and independently testable.

No TLS provider implementation controls were reviewed because the TLS policy
type and implementation do not exist. The HTTP baseline was checked
independently against `941c235`: the CTX-0028 redaction controls are present
at that base through `9fc413e` and absent from `origin/main` (`de77e17`),
pending code-owner approval on open PRs #43 and #44. This is a design-stage
security-corpus review, not an implementation review and not third-party-use
approval.

### Gate posture

CTX-0021, the consumer implementation lane, cannot start until this record
exists on its base branch. It must implement the policy without weakening the
capability, proxy, or typed-error contracts already decided for the backends.
CTX-0028's redaction controls are present at the base this record describes
and remain PENDING against `origin/main` until PR #44 lands and is
independently verified; this record does not treat them as landed on the
default branch, and the TLS implementation must supply and verify its own
controls rather than assuming them. The same rule applies to CTX-0034
(`f51240a`): its proxy feature gate call-site wiring and its second
`.no_proxy()` pair are unmerged, so CTX-0021 must not treat the `proxy`
feature as a wired gate on `origin/main` or on this base.

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
