//! The provider itself: trust composition, identity loading, and selection.
//!
//! The contracts this implements are stated on the parent module
//! ([`super`]); this file is the code that carries them. The one that matters
//! most here is restated because this is where it is implemented: the trust
//! model is **additive**, so **a supplied bundle does not restrict native
//! trust**. [`build_verifier`] is the only place a root set is composed, and it
//! can only add to the platform store.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use bitty_network_api::{
    ClientIdentityRule, MAX_CLIENT_IDENTITY_RULES, MAX_HOSTS_PER_IDENTITY_RULE, PemSource,
    TlsConfig, TlsFailure,
};
use rustls::ClientConfig;
use rustls_pki_types::pem::SectionKind;
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
#[allow(unused_imports)]
use rustls_platform_verifier::Verifier;
use zeroize::Zeroizing;

use super::x509;

/// Which transport a client configuration is being built for.
///
/// The two backends negotiate different ALPN protocols, so ALPN is per
/// transport. Everything that decides *trust* — the root set, the verifier, the
/// client identities — is shared, which is the HTTP/WebSocket parity the record
/// requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTransport {
    /// The HTTP backend (`reqwest` blocking).
    Http,
    /// The WebSocket backend (`tungstenite`).
    WebSocket,
}

/// ALPN protocol list for the HTTP backend, matching what it negotiates without
/// a policy: `http/1.1` only, because its `http2` feature is off.
const HTTP_ALPN: [&[u8]; 1] = [b"http/1.1"];

/// Index of the "no client identity" slot in a transport's configuration list.
///
/// Slot 0 is always the configuration that presents no client certificate, so a
/// host with no exact rule resolves to it and still gets the configured trust.
const NO_IDENTITY_SLOT: usize = 0;

/// Largest PEM source this provider will read, in bytes.
///
/// A PEM bundle or key chain is kilobytes. The bound stops a path pointing at an
/// unbounded file from being pulled into memory whole, and it is a policy value
/// rather than an intrinsic one.
const MAX_PEM_BYTES: u64 = 1024 * 1024;

/// What a backend must use for one new TLS destination.
///
/// Two facts, resolved together so a caller cannot take the client certificate
/// for one decision and the trust configuration for another.
///
/// `ClientConfig` has no `PartialEq`, so this type does not either; equality is
/// not a question a caller should be asking about a resolved TLS selection.
#[derive(Clone)]
pub struct TlsSelection {
    /// Identity slot for this destination; [`NO_IDENTITY_SLOT`] means no client
    /// certificate is presented.
    slot: usize,
    /// The configuration the backend must use, or `None` to keep its own.
    ///
    /// `None` happens only when the policy is the default. A configured policy
    /// always yields `Some`, so "no client identity" can never be reached by
    /// confusing this with a default policy.
    config: Option<Arc<ClientConfig>>,
}

impl TlsSelection {
    /// Identity slot for this destination; `0` presents no client certificate.
    #[must_use]
    pub fn slot(&self) -> usize {
        self.slot
    }
    /// The configuration to hand a backend, or `None` to keep its own.
    #[must_use]
    pub fn config(&self) -> Option<Arc<ClientConfig>> {
        self.config.as_ref().map(Arc::clone)
    }
}

/// Hand-written redacting [`fmt::Debug`]: the decision, never the material.
///
/// A selection transitively reaches key material — it hands out the
/// configuration that holds the client identity — so this type may not derive
/// `Debug`. It does not need to: the only facts a caller can act on are which
/// identity slot was resolved and whether a configuration was produced, and both
/// are non-secret. Deriving would instead forward whatever the upstream
/// `ClientConfig` happens to render, which today is only an algorithm name but is
/// not this crate's decision to keep true.
impl fmt::Debug for TlsSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSelection")
            .field("slot", &self.slot)
            .field("config_present", &self.config.is_some())
            .finish()
    }
}

/// The shared TLS provider: one trust configuration and the client identities.
///
/// Built once by [`TlsProvider::build`] and immutable afterwards. Cheap to
/// clone: every field is a `Vec`, a `HashMap`, or an `Arc`.
pub struct TlsProvider {
    /// True when the policy is the default: no CA source and no identity. The
    /// backends then keep their own native-root construction untouched, so the
    /// default path behaves exactly as it does without a policy — no bundle
    /// read, no PEM parse, no injected configuration.
    native_only: bool,
    /// The admitted custom roots as `rustls` certificates, for the verifier.
    der_roots: Vec<CertificateDer<'static>>,
    /// Validity windows of the same roots, re-checked before every new TLS
    /// destination.
    windows: Vec<x509::AdmittedRoot>,
    /// Per-transport configurations, indexed by identity slot. Slot
    /// [`NO_IDENTITY_SLOT`] presents no client certificate.
    http: Vec<Arc<ClientConfig>>,
    websocket: Vec<Arc<ClientConfig>>,
    /// Exact canonical host to identity slot.
    selection: HashMap<String, usize>,
}

impl TlsProvider {
    /// Build the provider for `config`, reading every source exactly once.
    ///
    /// The only fallible part is the policy itself: a source that cannot be read
    /// or parsed, a certificate that is not an admissible anchor, a rule that is
    /// not an exact host list, two rules claiming one host, or a chain and key
    /// that do not pair. Each is a typed [`TlsFailure`], and none of them can
    /// produce a partially loaded provider.
    pub fn build(config: TlsConfig) -> Result<Self, TlsFailure> {
        // Rule hosts are validated and canonicalized before any key material is
        // read, so a bad host list never leaves a half-loaded identity behind.
        let selection = selection_index(config.identities())?;
        let (der_roots, windows) = load_roots(config.ca())?;
        if config.is_native_only() {
            // Nothing to configure: no bundle read and no PEM parse happened
            // above, and the backends' own native-root construction stands.
            return Ok(Self {
                native_only: true,
                der_roots,
                windows,
                http: Vec::new(),
                websocket: Vec::new(),
                selection,
            });
        }
        // The platform store is read once here and shared by every
        // configuration through one `Arc`, so N identities do not mean N native
        // root loads.
        let verifier = build_verifier(der_roots.clone())?;
        let mut identities = Vec::with_capacity(config.identities().len());
        for rule in config.identities() {
            identities.push(IdentityConfigs::load(&verifier, rule)?);
        }
        Ok(Self {
            native_only: false,
            der_roots,
            windows,
            http: transport_configs(&verifier, &identities, TlsTransport::Http)?,
            websocket: transport_configs(&verifier, &identities, TlsTransport::WebSocket)?,
            selection,
        })
    }

    /// The selection for a new TLS destination to `host`.
    ///
    /// This runs for every new destination — every redirect hop included — and
    /// re-checks the custom roots' validity windows first, so an anchor that
    /// expired after construction fails the connection instead of being reused
    /// from a stale cache.
    pub fn select(&self, transport: TlsTransport, host: &str) -> Result<TlsSelection, TlsFailure> {
        self.select_at(transport, host, SystemTime::now())
    }

    /// [`TlsProvider::select`] against an explicit clock.
    ///
    /// The re-check has to be provable without waiting for a certificate to
    /// expire, so the instant is a parameter rather than a hidden
    /// `SystemTime::now()`. Production callers use `select`.
    fn select_at(
        &self,
        transport: TlsTransport,
        host: &str,
        now: SystemTime,
    ) -> Result<TlsSelection, TlsFailure> {
        for window in &self.windows {
            if !window.is_valid_at(now) {
                return Err(TlsFailure::CaRootNotValid);
            }
        }
        let slot = self.identity_slot(host);
        if self.native_only {
            return Ok(TlsSelection { slot, config: None });
        }
        let configs = match transport {
            TlsTransport::Http => &self.http,
            TlsTransport::WebSocket => &self.websocket,
        };
        // Every slot is filled by `transport_configs`, so this is a totality
        // backstop rather than a policy branch: a miss would mean falling back
        // to the backend's own trust, which is exactly the downgrade that must
        // not happen silently.
        match configs.get(slot) {
            Some(config) => Ok(TlsSelection {
                slot,
                config: Some(Arc::clone(config)),
            }),
            None => Err(TlsFailure::CaSourceInvalid),
        }
    }

    /// The provider for the default policy: native roots, no client
    /// certificate, and nothing for a backend to inject.
    ///
    /// This is what the backends' own construction already is, so a service
    /// built from it performs no bundle read, no PEM parse, and no
    /// configuration substitution.
    #[must_use]
    pub fn native_only() -> Self {
        Self {
            native_only: true,
            der_roots: Vec::new(),
            windows: Vec::new(),
            http: Vec::new(),
            websocket: Vec::new(),
            selection: HashMap::new(),
        }
    }

    /// The configuration for one identity slot and transport, without consulting
    /// a host.
    ///
    /// The HTTP backend needs this at construction: a `reqwest` client's TLS
    /// configuration is fixed when the client is built, so one client per slot
    /// carries the per-destination decision made once, up front. `None` means
    /// "keep the backend's own native-root construction", which is what a
    /// default policy produces.
    pub fn config_for_slot(
        &self,
        transport: TlsTransport,
        slot: usize,
    ) -> Option<Arc<ClientConfig>> {
        if self.native_only {
            return None;
        }
        let configs = match transport {
            TlsTransport::Http => &self.http,
            TlsTransport::WebSocket => &self.websocket,
        };
        configs.get(slot).map(Arc::clone)
    }

    /// One plus the number of identity slots: the size of a per-slot client set.
    #[must_use]
    pub fn identity_slot_count(&self) -> usize {
        if self.native_only {
            return 1;
        }
        self.http.len().max(1)
    }

    /// The identity slot for `host`: [`NO_IDENTITY_SLOT`] when no exact rule
    /// names it.
    ///
    /// A host that cannot be canonicalized matches no rule, which is the
    /// fail-closed direction: no identity is presented rather than a guess.
    pub fn identity_slot(&self, host: &str) -> usize {
        canonicalize_destination(host)
            .and_then(|canonical| self.selection.get(&canonical).copied())
            .unwrap_or(NO_IDENTITY_SLOT)
    }

    /// True when a client identity is configured for `host`.
    ///
    /// A non-secret diagnostic: it reports the decision, never the identity.
    #[must_use]
    pub fn selects_identity(&self, host: &str) -> bool {
        self.identity_slot(host) != NO_IDENTITY_SLOT
    }

    /// Number of exact hosts named across all identity rules.
    #[must_use]
    pub fn identity_host_count(&self) -> usize {
        self.selection.len()
    }

    /// Number of admitted custom roots.
    #[must_use]
    pub fn custom_root_count(&self) -> usize {
        self.der_roots.len()
    }
}

/// Hand-written `Debug` for the provider.
///
/// The provider transitively reaches loaded private keys inside the `rustls`
/// configurations, so `Debug` is written out rather than derived: a derived one
/// would print certificate bytes, and the configurations it holds are the
/// closest thing to key material in the type. It reports configuration shape and
/// rule hosts — the non-secret facts diagnostics are allowed to carry — and
/// never a path, a byte, a PEM, or a passphrase.
impl fmt::Debug for TlsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut view = f.debug_struct("TlsProvider");
        view.field("native_only", &self.native_only);
        view.field("custom_roots", &self.der_roots.len());
        view.field("identity_hosts", &self.identity_host_count());
        let mut hosts: Vec<&str> = self.selection.keys().map(String::as_str).collect();
        hosts.sort_unstable();
        view.field("hosts", &hosts);
        view.finish()
    }
}

impl Clone for TlsProvider {
    fn clone(&self) -> Self {
        Self {
            native_only: self.native_only,
            der_roots: self.der_roots.clone(),
            windows: self.windows.to_vec(),
            http: self.http.clone(),
            websocket: self.websocket.clone(),
            selection: self.selection.clone(),
        }
    }
}

/// One identity's two configurations, one per transport.
struct IdentityConfigs {
    http: Arc<ClientConfig>,
    websocket: Arc<ClientConfig>,
}

impl IdentityConfigs {
    /// Load, pair, and build one identity's configurations.
    ///
    /// The chain and key are read once and paired once, by `rustls` itself:
    /// `with_client_auth_cert` is the only place the pairing is proven, and its
    /// failure is `IdentityInvalid` rather than a handshake-time surprise. The
    /// second transport's configuration is a clone with the ALPN list cleared,
    /// so the key is parsed once and `rustls` holds exactly one copy per
    /// transport, which is the minimum the two-transport design needs.
    fn load(verifier: &Arc<Verifier>, rule: &ClientIdentityRule) -> Result<Self, TlsFailure> {
        let identity = rule.identity();
        let chain =
            parse_certificate_chain(&read_pem(identity.chain(), TlsFailure::IdentityInvalid)?)?;
        let key = parse_private_key(&read_pem(identity.key(), TlsFailure::IdentityInvalid)?)?;
        let mut http = base_config(Arc::clone(verifier))?
            .with_client_auth_cert(chain, key)
            .map_err(|_| TlsFailure::IdentityInvalid)?;
        http.alpn_protocols = alpn_for(TlsTransport::Http);
        let mut websocket = http.clone();
        websocket.alpn_protocols = alpn_for(TlsTransport::WebSocket);
        Ok(Self {
            http: Arc::new(http),
            websocket: Arc::new(websocket),
        })
    }
}

/// Build one transport's configuration list: slot 0 anonymous, then one slot per
/// identity in declaration order.
///
/// The order is the contract: slot `k` is rule `k - 1`, which is what
/// [`TlsProvider::selection_index`] numbers against.
fn transport_configs(
    verifier: &Arc<Verifier>,
    identities: &[IdentityConfigs],
    transport: TlsTransport,
) -> Result<Vec<Arc<ClientConfig>>, TlsFailure> {
    let mut configs = Vec::with_capacity(identities.len() + 1);
    let mut anonymous = base_config(Arc::clone(verifier))?.with_no_client_auth();
    anonymous.alpn_protocols = alpn_for(transport);
    configs.push(Arc::new(anonymous));
    for identity in identities {
        configs.push(Arc::clone(match transport {
            TlsTransport::Http => &identity.http,
            TlsTransport::WebSocket => &identity.websocket,
        }));
    }
    Ok(configs)
}

/// Validate and canonicalize every rule's hosts, and build the selection index.
///
/// Slot `k` belongs to rule `k - 1`, so the index and the configuration lists
/// stay in step. Hosts are validated and canonicalized *before* any key material
/// is read, so a bad host list never leaves a half-loaded identity behind.
fn selection_index(rules: &[ClientIdentityRule]) -> Result<HashMap<String, usize>, TlsFailure> {
    if rules.len() > MAX_CLIENT_IDENTITY_RULES {
        return Err(TlsFailure::IdentityLimitExceeded);
    }
    let mut selection: HashMap<String, usize> = HashMap::new();
    for (index, rule) in rules.iter().enumerate() {
        let declared = rule.hosts();
        if declared.is_empty() || declared.len() > MAX_HOSTS_PER_IDENTITY_RULE {
            return Err(TlsFailure::IdentityLimitExceeded);
        }
        for host in declared {
            if !bitty_network_api::is_exact_identity_host(host) {
                return Err(TlsFailure::RuleHostInvalid);
            }
            let host = canonical_host(host)?;
            // Two rules claiming one host would make selection ambiguous;
            // refusing beats picking one.
            if selection.contains_key(&host) {
                return Err(TlsFailure::IdentityHostAmbiguous);
            }
            selection.insert(host, index + 1);
        }
    }
    Ok(selection)
}

/// Canonical host of a TLS rule: IDNA-normalized, or a normalized IP literal.
///
/// The same function canonicalizes a rule's hosts and a destination's host, so
/// the two always agree on what "the same host" means. A host that cannot be
/// canonicalized is a typed failure for a *rule* host and a non-match for a
/// *destination*, which is fail-closed in both directions.
pub fn canonical_host(host: &str) -> Result<String, TlsFailure> {
    canonicalize_destination(host).ok_or(TlsFailure::RuleHostInvalid)
}

/// Canonical host of a TLS *destination*, or `None` when it has none.
///
/// Same rules as [`canonical_host`]; a destination that cannot be canonicalized
/// simply matches no identity rule.
fn canonicalize_destination(host: &str) -> Option<String> {
    let trimmed = host.trim().trim_end_matches('.');
    // A host that is only dots and whitespace has no name to canonicalize, and
    // `idna` accepts the empty string; refusing it here keeps an empty host from
    // matching a rule that was somehow written the same way.
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(address) = IpAddr::from_str(trimmed) {
        return Some(address.to_string());
    }
    // Strict UTS-46 ToASCII: it lowercases, so a rule written as a U-label and a
    // target presented as the A-label resolve to one host and neither spelling
    // can dodge an exact match, and its STD3 rules reject the shapes a DNS name
    // cannot have (an empty label, `_`, a label over 63 octets) instead of
    // letting them through as distinct hosts.
    idna::domain_to_ascii_strict(trimmed).ok()
}

/// Build the shared verifier: the platform root store plus the custom roots.
///
/// [`Verifier::new_with_extra_roots`] is what makes the composition additive in
/// one call: it loads the platform store, adds the supplied certificates to it,
/// and forwards a parse error for a bad one.
///
/// Its *failure* behaviour is the reason [`build_verifier_with`] exists. In
/// `rustls-platform-verifier` 0.7.0 the extra roots are added to the root store
/// **before** the platform store is read, and the only refusal is
/// `root_store.is_empty()`. So with a custom bundle configured, a platform store
/// that yields no usable root does **not** raise: the verifier comes back
/// holding the custom roots alone. That is precisely the custom-only trust this
/// record refuses, and the library documents the choice as deliberate, so it
/// cannot be relied on to fail closed. The native load is therefore proved
/// separately, and the refusal is this module's.
///
/// The probe runs only when custom roots are supplied, which is the only case
/// where the store is non-empty before the platform load. With no custom root
/// the library's own check is already exactly the right one, and the platform
/// store is not read twice.
fn build_verifier(extra_roots: Vec<CertificateDer<'static>>) -> Result<Arc<Verifier>, TlsFailure> {
    build_verifier_with(extra_roots, native_roots_loadable)
}

/// Whether the platform root store yields at least one usable trust anchor.
///
/// A second, independent read of the platform store, with no extra roots, so the
/// store's emptiness is observed before anything this crate supplies can fill it.
fn native_roots_loadable() -> bool {
    Verifier::new(crypto_provider()).is_ok()
}

/// [`build_verifier`] with the native-root probe injected, so the fail-closed
/// decision is testable without an unreadable platform store.
fn build_verifier_with(
    extra_roots: Vec<CertificateDer<'static>>,
    native_roots_loadable: impl FnOnce() -> bool,
) -> Result<Arc<Verifier>, TlsFailure> {
    if !extra_roots.is_empty() && !native_roots_loadable() {
        // Custom roots are present and the platform store produced nothing:
        // continuing would trust exactly the supplied certificates and nothing
        // else, which is the custom-only mode the record does not define.
        return Err(TlsFailure::NativeRootsUnavailable);
    }
    Verifier::new_with_extra_roots(extra_roots, crypto_provider())
        .map(Arc::new)
        .map_err(|_| TlsFailure::NativeRootsUnavailable)
}

/// The `rustls` cryptographic provider this crate pins.
///
/// Named in exactly one place because it is a choice, not a detail: it must be
/// the provider the reqwest and tungstenite trees already resolve, or the
/// configurations built here would not be the ones those backends verify with.
/// Passing it explicitly, rather than letting `ClientConfig::builder` pick up
/// ambient process-wide state, is also what keeps configuration construction
/// free of a branch that fails because two providers happen to be installed.
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The ALPN protocol list a transport negotiates.
fn alpn_for(transport: TlsTransport) -> Vec<Vec<u8>> {
    match transport {
        TlsTransport::Http => HTTP_ALPN.iter().map(|p| p.to_vec()).collect(),
        // The WebSocket handshake is not an ALPN protocol, and the backend's own
        // native-root path sets no ALPN list, so neither do we.
        TlsTransport::WebSocket => Vec::new(),
    }
}

/// A `ClientConfig` carrying `verifier`, with no client certificate.
///
/// The only fallible step is the protocol-version selection, which cannot fail
/// for a pinned provider; it is still mapped rather than unwrapped so this
/// function has no panic path.
fn base_config(
    verifier: Arc<Verifier>,
) -> Result<rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>, TlsFailure> {
    Ok(ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsFailure::NativeRootsUnavailable)?
        .dangerous()
        .with_custom_certificate_verifier(verifier))
}

/// PEM bytes one source produced.
///
/// A file source is read into a zeroizing buffer; an inline source is *borrowed*
/// from the policy, which is what keeps a private key from being copied into a
/// second heap buffer that would then have to be wiped separately. The policy
/// owns the original bytes and zeroes them when it drops.
enum PemBytes<'a> {
    /// The policy's own bytes, read in place.
    Borrowed(&'a [u8]),
    /// Bytes read from a path, wiped when this value drops.
    Owned(Zeroizing<Vec<u8>>),
}

impl std::ops::Deref for PemBytes<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(buffer) => buffer.as_slice(),
        }
    }
}

/// Read one PEM source into memory, zeroizing any bytes this read produced.
///
/// A file source is read only here, while the provider is built, and the buffer
/// holding it is wiped when it goes out of scope. `malformed` is the category
/// the caller wants for a read failure, so a CA source and a client-identity
/// source are reported under their own policies.
fn read_pem(source: &PemSource, malformed: TlsFailure) -> Result<PemBytes<'_>, TlsFailure> {
    match source {
        PemSource::File { path } => {
            let file = File::open(path).map_err(|_| malformed)?;
            let mut buffer = Zeroizing::new(Vec::new());
            BufReader::new(file)
                .take(MAX_PEM_BYTES)
                .read_to_end(&mut buffer)
                .map_err(|_| malformed)?;
            Ok(PemBytes::Owned(buffer))
        }
        PemSource::Inline { pem } => Ok(PemBytes::Borrowed(pem.as_slice())),
    }
}

/// Parse a PEM byte string into its sections, refusing anything malformed.
///
/// An empty source, a malformed PEM envelope, or a base64 body that does not
/// decode is a failure: there is no partial parse to continue from.
fn pem_sections(
    bytes: &[u8],
    malformed: TlsFailure,
) -> Result<Vec<(SectionKind, Vec<u8>)>, TlsFailure> {
    let mut reader = std::io::Cursor::new(bytes);
    let mut sections = Vec::new();
    while let Some((kind, data)) =
        rustls_pki_types::pem::from_buf(&mut reader).map_err(|_| malformed)?
    {
        sections.push((kind, data));
    }
    if sections.is_empty() {
        return Err(malformed);
    }
    Ok(sections)
}

/// Parse a client certificate chain: at least one certificate, nothing else.
///
/// A chain source that carries a private key, or any other non-certificate PEM
/// object, is refused rather than partly read.
fn parse_certificate_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsFailure> {
    let sections = pem_sections(pem, TlsFailure::IdentityInvalid)?;
    let mut chain = Vec::with_capacity(sections.len());
    for (kind, data) in sections {
        if kind != SectionKind::Certificate {
            return Err(TlsFailure::IdentityInvalid);
        }
        chain.push(CertificateDer::from(data));
    }
    Ok(chain)
}

/// Parse a private key: exactly one key section and nothing else.
///
/// PKCS#8, PKCS#1, and SEC1 are the three forms `rustls` accepts, matching the
/// encodings a certificate's own key can take.
fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsFailure> {
    let mut key = None;
    for (kind, data) in pem_sections(pem, TlsFailure::IdentityInvalid)? {
        let parsed = match kind {
            SectionKind::PrivateKey => Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(data))),
            SectionKind::RsaPrivateKey => {
                Some(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(data)))
            }
            SectionKind::EcPrivateKey => Some(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(data))),
            _ => None,
        };
        // A second key section is ambiguous: refuse rather than pick one.
        if parsed.is_some() && key.is_some() {
            return Err(TlsFailure::IdentityInvalid);
        }
        key = key.or(parsed);
    }
    key.ok_or(TlsFailure::IdentityInvalid)
}

/// Load and admit every certificate in a CA bundle, if one is configured.
///
/// Returns the certificates for the verifier and their validity windows for the
/// per-destination re-check. Every PEM section must be a certificate, there must
/// be at least one, and every certificate must be admissible as an explicit
/// trust anchor. One bad entry fails the whole load: there is no partial trust
/// set to continue with.
fn load_roots(
    source: Option<&PemSource>,
) -> Result<(Vec<CertificateDer<'static>>, Vec<x509::AdmittedRoot>), TlsFailure> {
    let Some(source) = source else {
        // No CA source means no bundle read and no PEM parse at all.
        return Ok((Vec::new(), Vec::new()));
    };
    let bytes = read_pem(source, TlsFailure::CaSourceInvalid)?;
    let mut roots = Vec::new();
    let mut windows = Vec::new();
    for (kind, data) in pem_sections(&bytes, TlsFailure::CaSourceInvalid)? {
        if kind != SectionKind::Certificate {
            // A non-certificate PEM object in a CA bundle is a configuration
            // error, not something to skip.
            return Err(TlsFailure::CaSourceInvalid);
        }
        let der = CertificateDer::from(data);
        let window = x509::admit_root(&der).map_err(|reason| match reason {
            // A certificate whose bytes do not parse, or whose validity window
            // cannot be stated exactly, is a malformed *source*: the record
            // groups "malformed certificate" with the other source errors. A
            // certificate that parses and is simply not a usable anchor is a
            // rejection, so an operator can tell a corrupt bundle from a wrong
            // one.
            x509::RootRejection::Malformed | x509::RootRejection::UnparseableValidity => {
                TlsFailure::CaSourceInvalid
            }
            _ => TlsFailure::CaRootRejected,
        })?;
        // The window is checked here as well as before every destination: an
        // anchor that is already expired is a configuration failure, not
        // something to accept now and re-check later.
        if !window.is_valid_at(SystemTime::now()) {
            return Err(TlsFailure::CaRootNotValid);
        }
        roots.push(der);
        windows.push(window);
    }
    Ok((roots, windows))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        date_time_ymd,
    };

    /// A self-signed runtime CA, minted in memory, as PEM a policy would take.
    fn runtime_root_pem() -> String {
        let mut params = CertificateParams::new(Vec::new()).expect("static CA parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, "runtime window anchor");
            name
        };
        params.not_before = date_time_ymd(2026, 1, 1);
        params.not_after = date_time_ymd(2046, 1, 1);
        let key = KeyPair::generate().expect("a runtime CA key");
        params.self_signed(&key).expect("a self-signed CA").pem()
    }

    /// A root admitted at construction is re-checked before every new TLS
    /// destination, so an anchor that leaves its window afterwards is refused
    /// rather than served from the construction-time decision.
    ///
    /// The record requires the window twice: "At construction and again before a
    /// handshake uses the root ... with no grace period, stale-cache reuse, or
    /// partial-bundle acceptance." The second check is the one a cached
    /// configuration would skip, so the instant is injected rather than waited
    /// for: a provider built while the anchor is valid must still refuse it once
    /// the anchor is not.
    #[test]
    fn a_root_is_re_checked_before_every_new_tls_destination() {
        let provider = TlsProvider::build(
            TlsConfig::new().with_ca(PemSource::inline(runtime_root_pem().into_bytes())),
        )
        .expect("the runtime CA is admitted while it is inside its window");

        let inside: SystemTime = date_time_ymd(2030, 1, 1).into();
        let after: SystemTime = date_time_ymd(2047, 1, 1).into();
        let before: SystemTime = date_time_ymd(2025, 1, 1).into();

        assert!(
            provider
                .select_at(TlsTransport::Http, "example.com", inside)
                .is_ok(),
            "an anchor inside its window is usable"
        );
        assert_eq!(
            provider
                .select_at(TlsTransport::Http, "example.com", after)
                .err(),
            Some(TlsFailure::CaRootNotValid),
            "an expired anchor must fail the new destination, not be reused from construction"
        );
        assert_eq!(
            provider
                .select_at(TlsTransport::Http, "example.com", before)
                .err(),
            Some(TlsFailure::CaRootNotValid),
            "a not-yet-valid anchor is refused in the same direction, with no grace period"
        );
    }

    /// A self-signed runtime CA, minted in memory, as DER a verifier would take.
    fn runtime_root() -> CertificateDer<'static> {
        let mut params = CertificateParams::new(Vec::new()).expect("static CA parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, "runtime additive anchor");
            name
        };
        params.not_before = date_time_ymd(2026, 1, 1);
        params.not_after = date_time_ymd(2046, 1, 1);
        let key = KeyPair::generate().expect("a runtime CA key");
        let certificate = params.self_signed(&key).expect("a self-signed CA");
        CertificateDer::from(certificate.der().to_vec())
    }

    /// Custom roots plus an unreadable platform store must fail closed.
    ///
    /// This is the property the library's own emptiness check does not provide:
    /// with the extra roots already in the store, `new_with_extra_roots` returns
    /// a verifier holding the custom roots alone, which is the custom-only trust
    /// the record refuses. The provider has to notice the missing native load
    /// itself, so the probe is driven to `false` here.
    #[test]
    fn custom_roots_with_an_unloadable_platform_store_fail_closed() {
        let result = build_verifier_with(vec![runtime_root()], || false);
        assert_eq!(
            result.err(),
            Some(TlsFailure::NativeRootsUnavailable),
            "custom roots must never become the whole trust set when the platform store is empty"
        );
    }

    /// The refusal is the provider's, and it is reached by consulting the probe.
    ///
    /// Asserting the outcome alone would also pass if the error came from
    /// somewhere else entirely, so the probe is instrumented to show it ran.
    #[test]
    fn the_native_load_is_proved_before_the_extra_roots_are_trusted() {
        let probed = Cell::new(false);
        let result = build_verifier_with(vec![runtime_root()], || {
            probed.set(true);
            false
        });
        assert_eq!(result.err(), Some(TlsFailure::NativeRootsUnavailable));
        assert!(
            probed.get(),
            "the native load must be observed, not inferred from the extra-root store"
        );
    }

    /// With no custom root there is nothing to prove, so the platform store is
    /// not read a second time.
    ///
    /// The library's emptiness check is already exactly right in this case,
    /// because nothing has been added to the store before the platform load.
    #[test]
    fn the_platform_store_is_not_probed_twice_without_a_custom_root() {
        let probed = Cell::new(false);
        let _ = build_verifier_with(Vec::new(), || {
            probed.set(true);
            false
        });
        assert!(
            !probed.get(),
            "a policy with no custom root must not pay for a second store read"
        );
    }
}
