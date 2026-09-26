//! `bitty-network-api`: stable network vocabulary (types only).
//!
//! This crate is the single vocabulary through which Bitty components name
//! network work: HTTP [`Request`]/[`Response`], [`WebSocketRequest`],
//! capability ([`NetworkCapability`], [`OfflineFirst`]), failure
//! ([`NetworkError`]), and the [`NetworkService`] boundary that
//! implementations serve behind.
//!
//! # Sealing note
//!
//! Types only. This crate performs no I/O, opens no sockets, spawns no
//! background tasks, and takes no implementation dependencies (its manifest
//! is dependency-free; `std` only). Anything that needs the network today
//! must still go through its existing path; nothing here can move a byte.
//! Sockets and transports arrive in follow-up tasks behind
//! [`NetworkService`], implemented in `bitty-network`.
//!
//! # Example
//!
//! ```
//! use bitty_network_api::{NetworkCapability, NetworkError};
//!
//! let offline = NetworkCapability::offline();
//! assert!(offline.is_offline());
//! assert_eq!(
//!     offline.check("example.com"),
//!     Err(NetworkError::Offline)
//! );
//!
//! let capped = NetworkCapability::offline().with_domain("example.com");
//! assert!(capped.allows("example.com"));
//! assert!(!capped.allows("elsewhere.example"));
//! ```

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Domain allowlist describing what a network consumer may contact.
///
/// The default is deny-all: [`NetworkCapability::offline`] holds no domains
/// and rejects every host with [`NetworkError::Offline`]. Consumers opt in
/// per domain with [`NetworkCapability::with_domain`]; there is no wildcard.
/// Matching is exact on the lowercased host, so `example.com` never covers
/// `sub.example.com` — each name must be listed.
///
/// Per-host ports ([`NetworkCapability::with_domain_ports`]) and HTTP methods
/// ([`NetworkCapability::restrict_methods`]) narrow a grant further. A domain
/// with no port entry allows every port (the legacy [`with_domain`] grant);
/// once a port entry exists, only listed ports pass. A method restriction is
/// additive: once any method is listed, only listed methods pass. Both layers
/// fail closed.
///
/// # Cross-repo contract (bitty manifest egress)
///
/// The bitty host owns the plugin-manifest egress table
/// (`[[network.egress]]` with `host` + `ports`, paired with
/// `network.connect:HOST[:PORT]` capabilities; see
/// `bitty-terminal/bitty#1335`). The host intersects the plugin's effective
/// grants with that table and hands the result to this crate as a
/// `NetworkCapability`; this crate enforces the handed grant (host, port,
/// method) and never widens it. Grants here are client-initiated egress
/// only: there is no API that permits listening, so a listen path can never
/// be granted by construction.
///
/// [`with_domain`]: NetworkCapability::with_domain
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkCapability {
    allowed_domains: HashSet<String>,
    allowed_ports: HashMap<String, HashSet<u16>>,
    allowed_methods: Option<HashSet<HttpMethod>>,
}

impl NetworkCapability {
    /// Deny-all capability: no domain is allowed (offline-first default).
    #[must_use]
    pub fn offline() -> Self {
        Self::default()
    }

    /// Allow one additional exact domain (builder style).
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.allowed_domains.insert(normalize_domain(domain.into()));
        self
    }

    /// True when no domain is allowed.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.allowed_domains.is_empty()
    }

    /// True when `domain` is on the allowlist (exact, case-insensitive).
    #[must_use]
    pub fn allows(&self, domain: &str) -> bool {
        self.allowed_domains.contains(&normalize_domain(domain))
    }

    /// Check `domain` against the allowlist.
    ///
    /// Returns `Ok(())` when the domain is allowed, [`NetworkError::Offline`]
    /// when the capability is deny-all, and [`NetworkError::Denied`] when
    /// other domains are allowed but this one is not.
    pub fn check(&self, domain: &str) -> Result<(), NetworkError> {
        if self.allows(domain) {
            Ok(())
        } else if self.is_offline() {
            Err(NetworkError::Offline)
        } else {
            Err(NetworkError::Denied {
                domain: normalize_domain(domain),
            })
        }
    }

    /// Allow `domain` on exactly `ports` (builder style).
    ///
    /// Implies [`NetworkCapability::with_domain`]: the domain is added to the
    /// allowlist and its port entry is replaced with `ports`. An empty `ports`
    /// denies every port on that domain (fail closed); a domain with no port
    /// entry (the plain [`with_domain`] grant) allows every port.
    ///
    /// [`with_domain`]: NetworkCapability::with_domain
    #[must_use]
    pub fn with_domain_ports(
        mut self,
        domain: impl Into<String>,
        ports: impl IntoIterator<Item = u16>,
    ) -> Self {
        let normalized = normalize_domain(domain.into());
        self.allowed_domains.insert(normalized.clone());
        self.allowed_ports
            .insert(normalized, ports.into_iter().collect());
        self
    }

    /// True when `domain` is allowed AND `port` passes its port entry.
    ///
    /// A domain with no port entry allows every port; a domain with an entry
    /// allows only listed ports.
    #[must_use]
    pub fn allows_port(&self, domain: &str, port: u16) -> bool {
        if !self.allows(domain) {
            return false;
        }
        match self.allowed_ports.get(&normalize_domain(domain)) {
            None => true,
            Some(ports) => ports.contains(&port),
        }
    }

    /// Check `domain` plus `port` against the allowlist.
    ///
    /// Same error taxonomy as [`NetworkCapability::check`]: `Ok(())` when
    /// both pass, [`NetworkError::Offline`] when deny-all, and
    /// [`NetworkError::Denied`] otherwise (unknown domain or unlisted port).
    pub fn check_host_port(&self, domain: &str, port: u16) -> Result<(), NetworkError> {
        if self.allows_port(domain, port) {
            Ok(())
        } else if self.is_offline() {
            Err(NetworkError::Offline)
        } else {
            Err(NetworkError::Denied {
                domain: normalize_domain(domain),
            })
        }
    }

    /// Narrow this grant to exactly the listed HTTP methods (builder style).
    ///
    /// Additive across calls: each call unions its methods into the
    /// restriction. With no restriction every method passes (the legacy
    /// grant); once any method is listed, only listed methods pass (fail
    /// closed). Applies to [`Request`] checks via
    /// [`NetworkCapability::check_request`]; WebSocket handshakes carry no
    /// method and are unaffected.
    #[must_use]
    pub fn restrict_methods(mut self, methods: impl IntoIterator<Item = HttpMethod>) -> Self {
        self.allowed_methods
            .get_or_insert_with(HashSet::new)
            .extend(methods);
        self
    }

    /// True when `method` passes the method restriction (every method passes
    /// while no restriction is recorded).
    #[must_use]
    pub fn allows_method(&self, method: HttpMethod) -> bool {
        self.allowed_methods
            .as_ref()
            .map(|methods| methods.contains(&method))
            .unwrap_or(true)
    }

    /// Denial for one request-shaped check: [`NetworkError::Offline`] when
    /// deny-all, else [`NetworkError::Denied`] for `domain`.
    fn denied(&self, domain: &str) -> NetworkError {
        if self.is_offline() {
            NetworkError::Offline
        } else {
            NetworkError::Denied {
                domain: normalize_domain(domain),
            }
        }
    }

    /// Check one HTTP [`Request`]: host, then port, then method.
    ///
    /// The port comes from [`Request::port`]; a request with no determinable
    /// port (no scheme, unknown scheme, unparseable port) is denied fail
    /// closed. Backends call this before touching any socket.
    pub fn check_request(&self, request: &Request) -> Result<(), NetworkError> {
        let host = request.host();
        self.check(host)?;
        match request.port() {
            Some(port) => self.check_host_port(host, port)?,
            None => return Err(self.denied(host)),
        }
        if self.allows_method(request.method) {
            Ok(())
        } else {
            Err(self.denied(host))
        }
    }

    /// Check one [`WebSocketRequest`] handshake: host, then port.
    ///
    /// Same fail-closed port rule as [`NetworkCapability::check_request`];
    /// handshakes carry no HTTP method so no method layer applies.
    pub fn check_handshake(&self, request: &WebSocketRequest) -> Result<(), NetworkError> {
        let host = request.host();
        self.check(host)?;
        match request.port() {
            Some(port) => self.check_host_port(host, port),
            None => Err(self.denied(host)),
        }
    }
}

/// Marker policy: networking is unavailable until a capability says otherwise.
///
/// Offline-first means every consumer starts from [`NetworkCapability::offline`]
/// and must be handed an explicit allowlist before any socket work (which
/// itself lands in a follow-up task). This type exists so call sites and
/// signatures can name the policy; it carries no data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct OfflineFirst {
    _private: (),
}

impl OfflineFirst {
    /// Name the offline-first policy at a call site.
    #[must_use]
    pub fn policy() -> Self {
        Self { _private: () }
    }
}

/// Typed network failure for current and future network consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// The domain is not on the capability allowlist.
    Denied {
        /// Normalized domain that was rejected.
        domain: String,
    },
    /// The capability is deny-all (offline); no domain is reachable.
    Offline,
    /// An allowed operation exceeded its deadline.
    Timeout {
        /// Deadline that expired.
        after: Duration,
    },
    /// An allowed operation would exceed a byte transfer budget enforced by
    /// an HTTP response or WebSocket transport.
    Budget {
        /// Byte budget that would be exceeded.
        limit_bytes: u64,
    },
    /// An allowed operation would exceed a frame or message count budget.
    CountBudget {
        /// Item-count budget that would be exceeded.
        limit_items: u64,
    },
    /// The TLS layer refused the connection for a typed trust or
    /// client-identity reason.
    ///
    /// A distinct category from [`NetworkError::Offline`] on purpose: the
    /// socket may well be reachable, and the refusal is a policy decision
    /// (untrusted chain, expired anchor, unusable client identity) that an
    /// operator has to be able to tell apart from an unreachable host. The
    /// payload is a stable [`TlsFailure`] category and never carries PEM
    /// contents, key bytes, passphrases, credential-bearing URLs, or raw
    /// key-source paths.
    Tls {
        /// Stable TLS failure category.
        reason: TlsFailure,
    },
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied { domain } => write!(f, "network denied: {domain}"),
            Self::Offline => write!(f, "network offline"),
            Self::Timeout { after } => {
                write!(f, "network timeout after {}ms", after.as_millis())
            }
            Self::Budget { limit_bytes } => {
                write!(f, "network budget exceeded: {limit_bytes} bytes")
            }
            Self::CountBudget { limit_items } => {
                write!(f, "network count budget exceeded: {limit_items} items")
            }
            Self::Tls { reason } => write!(f, "network tls refused: {reason}"),
        }
    }
}

/// Stable typed category for every TLS trust or client-identity refusal.
///
/// The categories are deliberately closed rather than open-ended: each one
/// names a distinct policy decision, and a new decision adds a variant here
/// (with its own [`fmt::Display`] arm) instead of collapsing into a generic
/// "TLS error" that would hide which control fired. No variant embeds PEM
/// contents, key bytes, a passphrase, a credential-bearing URL, or a raw
/// key-source path, so the whole taxonomy is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsFailure {
    /// The CA source is unusable: both bundle forms supplied, an empty path,
    /// an empty byte string, an unreadable path, a bundle with no
    /// certificate, a malformed certificate, or a non-certificate PEM object.
    ///
    /// A malformed entry fails the whole load; the provider never skips the
    /// bad entry and never continues with a partial trust set.
    CaSourceInvalid,
    /// A supplied certificate is not usable as an explicit trust anchor: no
    /// `basicConstraints`, `CA=FALSE`, a `keyUsage` without `keyCertSign` when
    /// `keyUsage` is present, an unsupported signature or public-key
    /// algorithm, an unsupported key size, or an unparseable subject or
    /// issuer name.
    CaRootRejected,
    /// A supplied root failed its validity window: `notBefore <= now <
    /// notAfter` did not hold, with no grace period and no stale-cache reuse.
    CaRootNotValid,
    /// The platform's native root store could not be loaded, so construction
    /// or the handshake fails.
    ///
    /// The trust model is additive: there is no custom-only mode, so a failed
    /// native-root load can never be papered over by custom roots.
    NativeRootsUnavailable,
    /// A client identity is unusable: a rule without both the chain and the
    /// key, a chain and key that do not match, or a source that cannot be
    /// loaded or parsed. The provider never downgrades such a connection to
    /// "no client certificate".
    IdentityInvalid,
    /// Two identity rules name the same canonical host, so selection would be
    /// ambiguous. Construction fails rather than picking one.
    IdentityHostAmbiguous,
    /// A rule names more hosts than [`MAX_HOSTS_PER_IDENTITY_RULE`], or the
    /// policy names more rules than [`MAX_CLIENT_IDENTITY_RULES`].
    IdentityLimitExceeded,
    /// A rule names a host that is not an exact DNS name: empty, carrying a
    /// scheme, port, path, wildcard, or any other non-host syntax.
    RuleHostInvalid,
}

impl fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaSourceInvalid => write!(f, "ca source invalid"),
            Self::CaRootRejected => write!(f, "ca root rejected"),
            Self::CaRootNotValid => write!(f, "ca root not valid"),
            Self::NativeRootsUnavailable => write!(f, "native roots unavailable"),
            Self::IdentityInvalid => write!(f, "client identity invalid"),
            Self::IdentityHostAmbiguous => write!(f, "client identity host ambiguous"),
            Self::IdentityLimitExceeded => write!(f, "client identity limit exceeded"),
            Self::RuleHostInvalid => write!(f, "identity rule host invalid"),
        }
    }
}

impl std::error::Error for TlsFailure {}

// --- TLS policy vocabulary (no I/O, no crypto) ----------------------------
//
// Everything in this section is intent only: it names where a CA bundle, a
// client certificate chain, and a client private key come from, and which
// exact hosts an identity applies to. It reads no file, parses no PEM, holds
// no parsed certificate, and performs no cryptography; a backend turns it into
// a real trust configuration.
//
// # Additive trust, and what a bundle does not do
//
// `TlsConfig::ca` is *additive*. Supplying either bundle form preserves every
// native root the platform store holds and adds the validated custom roots on
// top. It never replaces, shadows, or disables a native root, and there is no
// custom-only mode. **A supplied bundle therefore does not restrict native
// trust**: a host trusted by the platform stays trusted even when a bundle is
// configured, and an operator who expects a bundle to narrow trust is
// mistaken. A platform root store that cannot be loaded fails the construction
// or the handshake rather than silently continuing with custom-only trust.
// The same warning is repeated on `TlsConfig` itself, next to the field it
// applies to.

/// Largest number of exact hosts one [`ClientIdentityRule`] may name.
///
/// Reusing one identity across hosts therefore means listing each host, and
/// the bound keeps one rule from turning into an unbounded allowlist. Exceeding
/// it is a configuration error ([`TlsFailure::IdentityLimitExceeded`]), not a
/// silent truncation.
pub const MAX_HOSTS_PER_IDENTITY_RULE: usize = 16;

/// Largest number of [`ClientIdentityRule`]s one [`TlsConfig`] may carry.
///
/// Client identity is disabled by default, so a policy that names identities
/// is already an explicit operator act; the bound keeps the per-identity
/// connection pools a backend must build finite. Exceeding it is a
/// configuration error ([`TlsFailure::IdentityLimitExceeded`]), not a silent
/// truncation.
pub const MAX_CLIENT_IDENTITY_RULES: usize = 8;

/// One caller-supplied PEM source: an explicit file path, or inline bytes.
///
/// Both forms are explicit. There is no environment lookup, no default
/// location, no directory search, and no implicit fallback, and a URL is never
/// a source: this type accepts a path or bytes, nothing else.
///
/// This type reaches private-key material, so it never derives `Debug`, never
/// derives `Clone`, and never derives any serialization trait. Its
/// [`fmt::Debug`] is hand-written and reports the source kind only — never the
/// path, the bytes, or the PEM.
pub enum PemSource {
    /// An explicit path supplied by the caller.
    File {
        /// Caller-supplied path. Read only when a backend builds its provider.
        path: PathBuf,
    },
    /// Caller-supplied PEM bytes.
    Inline {
        /// Inline PEM bytes. Zeroed when the value is dropped.
        pem: Vec<u8>,
    },
}

impl PemSource {
    /// Explicit file-path source.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File { path: path.into() }
    }

    /// Inline PEM source.
    #[must_use]
    pub fn inline(pem: impl Into<Vec<u8>>) -> Self {
        Self::Inline { pem: pem.into() }
    }

    /// Non-secret source-kind label for diagnostics.
    ///
    /// One of `file` or `inline`; safe to log and to put in a [`fmt::Debug`]
    /// rendering because it names no path and no bytes.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Inline { .. } => "inline",
        }
    }
}

/// Hand-written redacting [`fmt::Debug`]: the source kind only.
///
/// A derived `Debug` on a type that reaches a private key would print the
/// path or the bytes, so the implementation is written out instead of derived.
impl fmt::Debug for PemSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PemSource")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// Zero the inline bytes this source owns before releasing them.
///
/// A private key handed to the policy as bytes should not stay readable in the
/// heap after the policy is gone, so the initialized bytes are overwritten on
/// drop. This is a plain `fill(0)`, which is a best-effort wipe and not a
/// guaranteed one: the standard library gives no guarantee that the write is not
/// optimized away as dead once the allocation is about to be freed, and this
/// crate stays dependency-free (`std` only) so it cannot reach a `zeroize`
/// guarantee. The copies this crate can speak for are handled properly by the
/// backend, which reads an inline source in place and zeroizes every buffer it
/// allocates itself.
impl Drop for PemSource {
    fn drop(&mut self) {
        if let Self::Inline { pem } = self {
            pem.fill(0);
        }
    }
}

/// One client identity: a certificate chain and its matching private key.
///
/// The two parts are indivisible. There is no constructor that takes only a
/// chain or only a key, so a policy cannot name an identity that would be
/// selected without both halves, and a chain that does not match its key is
/// rejected by the backend that loads it rather than surfacing at handshake
/// time.
pub struct ClientIdentity {
    chain: PemSource,
    key: PemSource,
}

impl ClientIdentity {
    /// Identity from an explicit chain source and an explicit key source.
    ///
    /// Both arguments are required; there is no single-part constructor and no
    /// default identity.
    #[must_use]
    pub fn new(chain: PemSource, key: PemSource) -> Self {
        Self { chain, key }
    }

    /// The certificate-chain source.
    #[must_use]
    pub fn chain(&self) -> &PemSource {
        &self.chain
    }

    /// The private-key source.
    #[must_use]
    pub fn key(&self) -> &PemSource {
        &self.key
    }
}

/// Hand-written redacting [`fmt::Debug`]: the source kinds only.
///
/// [`ClientIdentity`] reaches key material, so `Debug` is written out rather
/// than derived and reports no path, no bytes, and no PEM.
impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("chain_source", &self.chain.kind())
            .field("key_source", &self.key.kind())
            .finish_non_exhaustive()
    }
}

/// One client-identity rule: exact target hosts plus the identity to use.
///
/// Selection is exact and case-insensitive on the canonical DNS hostname of
/// the final TLS target after URL parsing and IDNA normalization. There is no
/// wildcard, no suffix matching, and no default identity, so a host with no
/// exact rule receives no client certificate, and a certificate configured for
/// one host is never selected merely because another host is a parent, a
/// subdomain, a redirect target, or shares a suffix. Reusing one identity on
/// several hosts therefore means listing each host explicitly.
///
/// A rule selects an identity; it never waives the certificate name, chain,
/// validity, or key-use checks the backend applies to the selected
/// certificate. Naming a host the selected certificate is not valid for fails
/// closed.
pub struct ClientIdentityRule {
    hosts: Vec<String>,
    identity: ClientIdentity,
}

impl ClientIdentityRule {
    /// Rule naming `hosts` exactly, using `identity`.
    ///
    /// `hosts` must be non-empty and each entry must be a bare exact DNS name;
    /// the backend rejects a wildcard, a scheme, a port, a path, or an empty
    /// entry with [`TlsFailure::RuleHostInvalid`] rather than quietly dropping
    /// it. No entry is interpreted as a pattern.
    #[must_use]
    pub fn new<I, H>(hosts: I, identity: ClientIdentity) -> Self
    where
        I: IntoIterator<Item = H>,
        H: Into<String>,
    {
        let hosts = hosts.into_iter().map(Into::into).collect();
        Self { hosts, identity }
    }

    /// The exact hosts this rule names, as supplied.
    #[must_use]
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// The identity selected for those hosts.
    #[must_use]
    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }
}

/// Hand-written redacting [`fmt::Debug`]: host names and source kinds only.
///
/// Host names and the number of rules are the non-secret facts diagnostics are
/// allowed to report; the key and chain sources stay kind-only, and no path or
/// byte ever appears.
impl fmt::Debug for ClientIdentityRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentityRule")
            .field("hosts", &self.hosts)
            .field("chain_source", &self.identity.chain.kind())
            .field("key_source", &self.identity.key.kind())
            .finish_non_exhaustive()
    }
}

/// TLS policy handed to a backend: one optional CA source plus identity rules.
///
/// The default is the safe one: no CA source and no client identity. A backend
/// given the default performs no bundle read and no PEM parse, installs no
/// custom root, presents no client certificate, and uses the platform's native
/// roots exactly as it does without a policy.
///
/// This type reaches key material through [`ClientIdentityRule`], so it never
/// derives `Debug`, `Clone`, or any serialization trait; its [`fmt::Debug`] is
/// hand-written and redacted.
#[derive(Default)]
pub struct TlsConfig {
    ca: Option<PemSource>,
    identities: Vec<ClientIdentityRule>,
}

impl TlsConfig {
    /// Policy with no CA source and no client identity: native roots, no
    /// client certificate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Policy that adds the validated certificates in `ca` to the native roots.
    ///
    /// Additive, never a replacement.
    ///
    /// Supplying a bundle preserves every native root and adds the validated
    /// custom roots; it never replaces, shadows, or disables a native root.
    /// **A supplied bundle therefore does not restrict native trust**: a host
    /// the platform trusts stays trusted, and there is no custom-only mode. An
    /// operator who expects a bundle to narrow trust is mistaken. A platform
    /// root store that cannot be loaded fails construction or the handshake
    /// rather than silently continuing with custom-only trust.
    #[must_use]
    pub fn with_ca(mut self, ca: PemSource) -> Self {
        self.ca = Some(ca);
        self
    }

    /// Policy that selects `rule`'s identity for the exact hosts it names.
    #[must_use]
    pub fn with_identity(mut self, rule: ClientIdentityRule) -> Self {
        self.identities.push(rule);
        self
    }

    /// The optional CA source, if any.
    #[must_use]
    pub fn ca(&self) -> Option<&PemSource> {
        self.ca.as_ref()
    }

    /// The configured identity rules, in declaration order.
    #[must_use]
    pub fn identities(&self) -> &[ClientIdentityRule] {
        &self.identities
    }

    /// True when the policy changes nothing: no CA source and no identity.
    ///
    /// A backend uses this to keep its own native-root construction untouched
    /// instead of substituting an equivalent one, so the default path behaves
    /// exactly as it does without a policy.
    #[must_use]
    pub fn is_native_only(&self) -> bool {
        self.ca.is_none() && self.identities.is_empty()
    }
}

/// Hand-written redacting [`fmt::Debug`]: configuration shape, no secrets.
///
/// Reports whether a CA source is configured and of which kind, how many
/// identity rules are configured, and the exact hosts they name. It never
/// reports a path, a byte, a PEM, or a passphrase.
impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut view = f.debug_struct("TlsConfig");
        match &self.ca {
            Some(ca) => {
                view.field("ca_configured", &true);
                view.field("ca_source_kind", &ca.kind());
            }
            None => {
                view.field("ca_configured", &false);
            }
        }
        view.field("identity_rules", &self.identities.len());
        for rule in &self.identities {
            view.field("identity_hosts", &rule.hosts);
        }
        view.finish()
    }
}

/// A rule host is only usable as an exact DNS name.
///
/// Structural check only: it rejects what can never be a host (an empty name,
/// a wildcard, a scheme, a port, a path, userinfo, or control bytes) and
/// leaves IDNA normalization and case folding to the backend, which
/// canonicalizes the rule hosts and the destination host with the same
/// function so the two always agree.
fn is_exact_host_candidate(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('.')
        && !host.contains("..")
        && !host.contains(['*', '?', '/', ':', '@', '#', '[', ']', '\\'])
        && !host.chars().any(char::is_whitespace)
        && !host.chars().any(char::is_control)
}

/// True when `host` is a bare exact DNS name this crate accepts in a rule.
///
/// The canonical (lowercased, IDNA-normalized, trailing-dot-free) form is
/// produced by the backend; this only rejects syntax that can never be a host.
#[must_use]
pub fn is_exact_identity_host(host: &str) -> bool {
    is_exact_host_candidate(host.trim().trim_end_matches('.'))
}

impl std::error::Error for NetworkError {}

/// HTTP method for [`Request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    /// Read-only retrieval.
    Get,
    /// Create a subordinate resource.
    Post,
    /// Replace the target resource.
    Put,
    /// Remove the target resource.
    Delete,
    /// Retrieval without a body.
    Head,
    /// Capability discovery.
    Options,
    /// Partial modification.
    Patch,
}

/// Outgoing HTTP request vocabulary (no I/O).
///
/// A value of this type describes intent only; executing it is the
/// [`NetworkService`] implementor's job. Check
/// [`NetworkCapability::check`] on [`Request::host`] before sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Request method.
    pub method: HttpMethod,
    /// Full URL (for example `https://example.com/path`).
    pub url: String,
    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Request body bytes (empty for bodyless methods).
    pub body: Vec<u8>,
    /// Per-request deadline, when the caller sets one.
    pub timeout: Option<Duration>,
    /// Response body cap in bytes, when the caller sets one.
    ///
    /// Enforced fail-closed by backends that move bytes: a response larger
    /// than the cap yields [`NetworkError::Budget`] instead of a truncated
    /// body. `None` (the default) means the caller sets no explicit cap, so
    /// the backend's mandatory ceiling applies; a `Some` value may narrow
    /// that ceiling but never widens it.
    pub max_body_bytes: Option<u64>,
}

impl Request {
    /// Bodyless `GET` request for `url`.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: None,
            max_body_bytes: None,
        }
    }

    /// `POST` request for `url` with `body`.
    #[must_use]
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: Vec::new(),
            body: body.into(),
            timeout: None,
            max_body_bytes: None,
        }
    }

    /// Append one header (builder style).
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the per-request deadline (builder style).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the response body cap in bytes (builder style).
    ///
    /// See [`Request::max_body_bytes`]; `None` is the default (no explicit
    /// caller cap, so the backend ceiling applies).
    #[must_use]
    pub fn with_max_body_bytes(mut self, limit_bytes: u64) -> Self {
        self.max_body_bytes = Some(limit_bytes);
        self
    }

    /// Best-effort host authority of [`Request::url`].
    ///
    /// Strips the scheme, userinfo, and port so the result feeds
    /// [`NetworkCapability::check`] directly. Returns an empty string when
    /// the URL carries no parseable authority.
    #[must_use]
    pub fn host(&self) -> &str {
        url_host(&self.url)
    }

    /// Best-effort destination port of [`Request::url`].
    ///
    /// Returns the explicit port when the authority carries a parseable one,
    /// else the scheme default (`443` for `https`/`wss`, `80` for
    /// `http`/`ws`), else `None`. [`NetworkCapability::check_request`]
    /// denies portless requests fail closed.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        url_port(&self.url)
    }
}

/// HTTP response vocabulary (no I/O).
///
/// Produced by [`NetworkService`] implementors; carries no socket handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Numeric status code (for example `200`).
    pub status: u16,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// True for `2xx` statuses.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// First header value for `name` (case-insensitive on the name).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// WebSocket handshake request vocabulary (no I/O).
///
/// Describes the upgrade handshake only; the established stream type is the
/// implementor's [`NetworkService::Socket`] associated type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketRequest {
    /// Full URL (for example `wss://example.com/socket`).
    pub url: String,
    /// Requested subprotocols, in preference order.
    pub protocols: Vec<String>,
    /// Handshake deadline, when the caller sets one.
    pub timeout: Option<Duration>,
}

impl WebSocketRequest {
    /// Handshake request for `url` with no subprotocols.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            protocols: Vec::new(),
            timeout: None,
        }
    }

    /// Offer one more subprotocol (builder style).
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    /// Set the handshake deadline (builder style).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Best-effort host authority of [`WebSocketRequest::url`]; see
    /// [`Request::host`] for the extraction rule.
    #[must_use]
    pub fn host(&self) -> &str {
        url_host(&self.url)
    }

    /// Best-effort destination port of [`WebSocketRequest::url`]; see
    /// [`Request::port`] for the rule. [`NetworkCapability::check_handshake`]
    /// denies portless handshakes fail closed.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        url_port(&self.url)
    }
}

/// Service boundary behind which network implementations live.
///
/// Consumers depend on this trait (via `bitty-network-api`) and reach the
/// implementation through IPC or service lookup; they never depend on the
/// implementing crate directly. Callers check the [`NetworkCapability`]
/// before invoking either method and treat [`NetworkError::Offline`] /
/// [`NetworkError::Denied`] as normal fail-closed control flow.
///
/// # Example
///
/// ```
/// use bitty_network_api::{
///     NetworkError, NetworkService, Request, Response, WebSocketRequest,
/// };
///
/// struct Offline;
///
/// impl NetworkService for Offline {
///     type Socket = ();
///
///     fn request(&self, _request: &Request) -> Result<Response, NetworkError> {
///         Err(NetworkError::Offline)
///     }
///
///     fn websocket(
///         &self,
///         _request: &WebSocketRequest,
///     ) -> Result<Self::Socket, NetworkError> {
///         Err(NetworkError::Offline)
///     }
/// }
/// ```
pub trait NetworkService {
    /// Established-connection type for [`NetworkService::websocket`].
    type Socket;

    /// Execute one HTTP [`Request`] synchronously.
    ///
    /// Returns [`NetworkError::Offline`] / [`NetworkError::Denied`] when the
    /// caller's capability rejects [`Request::host`].
    fn request(&self, request: &Request) -> Result<Response, NetworkError>;

    /// Perform one WebSocket handshake, returning the open stream.
    ///
    /// Returns [`NetworkError::Offline`] / [`NetworkError::Denied`] when the
    /// caller's capability rejects [`WebSocketRequest::host`].
    fn websocket(&self, request: &WebSocketRequest) -> Result<Self::Socket, NetworkError>;
}

/// Lowercase and trim one trailing dot (`example.com.`); keep matching exact.
fn normalize_domain(domain: impl AsRef<str>) -> String {
    domain.as_ref().trim().trim_end_matches('.').to_lowercase()
}

/// Best-effort port extraction over the URL vocabulary (no parsing
/// dependencies): explicit authority port when parseable, else the scheme
/// default (`443` for `https`/`wss`, `80` for `http`/`ws`), else `None`.
/// IPv6 brackets are honored; userinfo is stripped before the split.
fn url_port(url: &str) -> Option<u16> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let explicit = if let Some(stripped) = hostport.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((_, tail)) => tail.strip_prefix(':'),
            None => None,
        }
    } else {
        hostport.split_once(':').map(|(_, port)| port)
    };
    match explicit {
        Some(text) => text.parse::<u16>().ok(),
        None => match scheme.to_lowercase().as_str() {
            "https" | "wss" => Some(443),
            "http" | "ws" => Some(80),
            _ => None,
        },
    }
}

/// Best-effort host extraction over the URL vocabulary (no parsing
/// dependencies): strip the scheme, take the authority, drop userinfo and
/// port; IPv6 brackets are honored.
fn url_host(url: &str) -> &str {
    let after_scheme = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => url,
    };
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    if let Some(stripped) = hostport.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((host, _)) => host,
            None => stripped,
        }
    } else {
        match hostport.split_once(':') {
            Some((host, _)) => host,
            None => hostport,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_denies_everything() {
        let cap = NetworkCapability::offline();
        assert!(cap.is_offline());
        assert!(!cap.allows("example.com"));
        assert_eq!(cap.check("example.com"), Err(NetworkError::Offline));
    }

    #[test]
    fn allowlist_is_exact_and_case_insensitive() {
        let cap = NetworkCapability::offline().with_domain("Example.COM.");
        assert!(!cap.is_offline());
        assert!(cap.allows("example.com"));
        assert!(!cap.allows("sub.example.com"));
        assert_eq!(
            cap.check("other.example"),
            Err(NetworkError::Denied {
                domain: "other.example".to_owned()
            })
        );
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            NetworkError::Offline.to_string(),
            "network offline".to_owned()
        );
        assert_eq!(
            NetworkError::Timeout {
                after: Duration::from_secs(2)
            }
            .to_string(),
            "network timeout after 2000ms".to_owned()
        );
        assert_eq!(
            NetworkError::Budget { limit_bytes: 8 }.to_string(),
            "network budget exceeded: 8 bytes".to_owned()
        );
        assert_eq!(
            NetworkError::CountBudget { limit_items: 3 }.to_string(),
            "network count budget exceeded: 3 items".to_owned()
        );
    }

    #[test]
    fn request_builders_carry_intent() {
        let request = Request::get("https://example.com/path")
            .with_header("Accept", "text/plain")
            .with_timeout(Duration::from_secs(5))
            .with_max_body_bytes(1024);
        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(request.host(), "example.com");
        assert_eq!(
            request.headers,
            vec![("Accept".to_owned(), "text/plain".to_owned())]
        );
        assert_eq!(request.timeout, Some(Duration::from_secs(5)));
        assert_eq!(request.max_body_bytes, Some(1024));

        let post = Request::post("http://example.com:8080/submit", vec![1, 2]);
        assert_eq!(post.method, HttpMethod::Post);
        assert_eq!(post.host(), "example.com");
        assert_eq!(post.body, vec![1, 2]);
        assert_eq!(post.max_body_bytes, None);
    }

    #[test]
    fn host_extraction_is_best_effort() {
        assert_eq!(
            Request::get("https://user@example.com./a?b#c").host(),
            "example.com."
        );
        assert_eq!(
            Request::get("ws://sub.example.com/socket").host(),
            "sub.example.com"
        );
        assert_eq!(Request::get("http://[::1]:8080/").host(), "::1");
        assert_eq!(Request::get("example.com").host(), "example.com");
        assert_eq!(Request::get("").host(), "");
    }

    #[test]
    fn response_helpers_read_status_and_headers() {
        let response = Response {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "text/plain".to_owned())],
            body: b"hi".to_vec(),
        };
        assert!(response.is_success());
        assert_eq!(response.header("content-type"), Some("text/plain"));
        assert_eq!(response.header("missing"), None);

        let failure = Response {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(!failure.is_success());
    }

    #[test]
    fn websocket_request_builders_carry_intent() {
        let handshake = WebSocketRequest::new("wss://example.com:443/socket")
            .with_protocol("chat")
            .with_timeout(Duration::from_secs(3));
        assert_eq!(handshake.host(), "example.com");
        assert_eq!(handshake.protocols, vec!["chat".to_owned()]);
        assert_eq!(handshake.timeout, Some(Duration::from_secs(3)));
    }

    #[test]
    fn offline_service_stub_fails_closed() {
        struct Offline;

        impl NetworkService for Offline {
            type Socket = ();

            fn request(&self, _request: &Request) -> Result<Response, NetworkError> {
                Err(NetworkError::Offline)
            }

            fn websocket(&self, _request: &WebSocketRequest) -> Result<Self::Socket, NetworkError> {
                Err(NetworkError::Offline)
            }
        }

        let service = Offline;
        assert_eq!(
            service.request(&Request::get("https://example.com")),
            Err(NetworkError::Offline)
        );
        assert_eq!(
            service.websocket(&WebSocketRequest::new("wss://example.com")),
            Err(NetworkError::Offline)
        );
    }

    #[test]
    fn port_extraction_prefers_explicit_then_scheme_default() {
        assert_eq!(Request::get("https://example.com/path").port(), Some(443));
        assert_eq!(
            Request::get("http://example.com:8080/submit").port(),
            Some(8080)
        );
        assert_eq!(
            WebSocketRequest::new("wss://example.com:9443/socket").port(),
            Some(9443)
        );
        assert_eq!(
            WebSocketRequest::new("ws://example.com/socket").port(),
            Some(80)
        );
        assert_eq!(Request::get("http://[::1]:8080/").port(), Some(8080));
        assert_eq!(Request::get("https://user@example.com/a").port(), Some(443));
        assert_eq!(Request::get("example.com").port(), None);
        assert_eq!(Request::get("gopher://example.com/").port(), None);
        assert_eq!(Request::get("https://example.com:notaport/").port(), None);
        assert_eq!(Request::get("").port(), None);
    }

    #[test]
    fn port_grant_is_fail_closed_per_host() {
        let capped = NetworkCapability::offline().with_domain_ports("example.com", [443]);
        assert!(capped.allows("example.com"));
        assert!(capped.allows_port("example.com", 443));
        assert!(!capped.allows_port("example.com", 80));
        assert!(!capped.allows_port("other.example", 443));
        assert_eq!(capped.check_host_port("example.com", 443), Ok(()));
        assert_eq!(
            capped.check_host_port("example.com", 80),
            Err(NetworkError::Denied {
                domain: "example.com".to_owned()
            })
        );
        assert_eq!(
            NetworkCapability::offline().check_host_port("example.com", 443),
            Err(NetworkError::Offline)
        );
    }

    #[test]
    fn empty_port_list_denies_every_port() {
        let capped = NetworkCapability::offline().with_domain_ports("example.com", []);
        assert!(capped.allows("example.com"));
        assert!(!capped.allows_port("example.com", 443));
    }

    #[test]
    fn legacy_domain_grant_keeps_every_port() {
        let capped = NetworkCapability::offline().with_domain("example.com");
        assert!(capped.allows_port("example.com", 443));
        assert!(capped.allows_port("example.com", 8080));
        assert_eq!(
            capped.check_request(&Request::get("https://example.com/")),
            Ok(())
        );
    }

    #[test]
    fn check_request_enforces_host_port_method() {
        let capped = NetworkCapability::offline()
            .with_domain_ports("example.com", [443])
            .restrict_methods([HttpMethod::Get]);
        assert_eq!(
            capped.check_request(&Request::get("https://example.com/")),
            Ok(())
        );
        assert_eq!(
            capped.check_request(&Request::post("https://example.com/", vec![1])),
            Err(NetworkError::Denied {
                domain: "example.com".to_owned()
            })
        );
        assert_eq!(
            capped.check_request(&Request::get("http://example.com:8080/")),
            Err(NetworkError::Denied {
                domain: "example.com".to_owned()
            })
        );
        assert_eq!(
            capped.check_request(&Request::get("https://other.example/")),
            Err(NetworkError::Denied {
                domain: "other.example".to_owned()
            })
        );
        assert_eq!(
            capped.check_request(&Request::get("example.com")),
            Err(NetworkError::Denied {
                domain: "example.com".to_owned()
            })
        );
        assert_eq!(
            NetworkCapability::offline().check_request(&Request::get("https://example.com/")),
            Err(NetworkError::Offline)
        );
    }

    #[test]
    fn check_handshake_enforces_host_port_without_methods() {
        let capped = NetworkCapability::offline()
            .with_domain_ports("example.com", [443])
            .restrict_methods([HttpMethod::Get]);
        assert_eq!(
            capped.check_handshake(&WebSocketRequest::new("wss://example.com/socket")),
            Ok(())
        );
        assert_eq!(
            capped.check_handshake(&WebSocketRequest::new("ws://example.com:8080/socket")),
            Err(NetworkError::Denied {
                domain: "example.com".to_owned()
            })
        );
    }

    #[test]
    fn method_restriction_is_additive_and_defaults_open() {
        let open = NetworkCapability::offline().with_domain("example.com");
        assert!(open.allows_method(HttpMethod::Post));
        let capped = open
            .restrict_methods([HttpMethod::Get])
            .restrict_methods([HttpMethod::Post]);
        assert!(capped.allows_method(HttpMethod::Get));
        assert!(capped.allows_method(HttpMethod::Post));
        assert!(!capped.allows_method(HttpMethod::Delete));
    }

    /// N1: `is_exact_identity_host` had no coverage, so a body of
    /// `true` produced no red. Each rejection below is pinned separately, so
    /// dropping any single clause of `is_exact_host_candidate` turns this red
    /// rather than silently widening what a rule host may name.
    #[test]
    fn exact_identity_host_accepts_only_a_bare_dns_name() {
        for host in [
            "example.com",
            "a",
            "xn--bcher-kva.example",
            "sub.example.com",
            "example.com.",
            "  example.com  ",
            "9example.com",
            "example-1.example",
        ] {
            assert!(
                is_exact_identity_host(host),
                "{host:?} is a bare DNS name and must be accepted"
            );
        }

        for (host, why) in [
            ("", "an empty name is not a host"),
            ("   ", "whitespace only"),
            (
                ".example.com",
                "a leading dot is a suffix, not an exact name",
            ),
            ("example..com", "an empty interior label"),
            ("..", "only dots"),
            ("*.example.com", "a wildcard is not an exact name"),
            ("exam?ple.com", "a glob character is not a host byte"),
            ("example.com/path", "a path"),
            ("example.com:443", "a port"),
            ("user@example.com", "userinfo"),
            ("user:pass@example.com", "credentials"),
            ("https://example.com", "a scheme"),
            ("example.com#frag", "a fragment"),
            ("[::1]", "an IP literal in brackets"),
            ("::1", "an unbracketed address"),
            ("back\\slash.example", "a separator"),
            ("exam\nple.com", "an interior control byte"),
            ("example\u{7}com", "a delete byte"),
            ("ex ample.com", "interior whitespace"),
        ] {
            assert!(
                !is_exact_identity_host(host),
                "{host:?} must be refused because {why}"
            );
        }
    }

    /// The structural layer rejects by shape; IDNA normalization is the
    /// backend's job, so a name that is shaped like a host but is not a legal
    /// one is *accepted* here and refused there. This test records that seam
    /// explicitly, so the two layers are not later mistaken for one.
    ///
    /// `exam!ple.com` is the witness: it passes every structural clause (no
    /// wildcard, no scheme, no port, no userinfo, no whitespace) and is refused
    /// by `idna::domain_to_ascii_strict`. The record's "no wildcard, no suffix,
    /// no default" claim therefore rests on IDNA for the legal-name question and
    /// on this function for the shape question, and the backend pins the IDNA
    /// half in `tests/tls_client_identity.rs`.
    #[test]
    fn structural_layer_is_strictly_about_shape_and_defers_idna() {
        // Shape-legal, IDNA-illegal: accepted here, refused by the backend.
        assert!(is_exact_identity_host("exam!ple.com"));
        assert!(is_exact_identity_host("exämple.com"));
        // Shape-illegal even though IDNA would accept the name itself.
        assert!(!is_exact_identity_host("*.exämple.com"));
        // Trailing-dot and surrounding-whitespace tolerance is deliberate: the
        // backend canonicalizes both sides with the same function, so accepting
        // them here cannot desynchronize the rule host from the destination.
        // It extends to a trailing *control* byte, because `trim` removes one
        // along with the whitespace; the refusal is for control bytes that
        // survive trimming, i.e. ones in the interior.
        assert!(is_exact_identity_host("Example.COM."));
        assert!(is_exact_identity_host("\texample.com\n"));
    }
}
