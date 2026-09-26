//! Runtime-only test material for the TLS suites (CTX-0021).
//!
//! Every certificate and key here is generated inside the test process, at
//! runtime, and never written to disk. That is the point of the module: the
//! record forbids committing a private key or a certificate fixture, "including
//! test material", so a test that needs one has to mint it and throw it away.
//!
//! Nothing here is a long-lived secret. The keys are generated per call, used
//! only against an ephemeral loopback listener, and dropped when the test ends;
//! they authenticate nothing outside the test process.

#![allow(dead_code)]

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType, date_time_ymd,
};

/// A validity window that contains any plausible test run.
pub fn window_from() -> time::OffsetDateTime {
    date_time_ymd(2000, 1, 1)
}
/// The far end of [`window_from()`]'s window.
pub fn window_until() -> time::OffsetDateTime {
    date_time_ymd(2100, 1, 1)
}
/// A window entirely in the past.
pub fn expired_from() -> time::OffsetDateTime {
    date_time_ymd(1975, 1, 1)
}
/// The far end of the expired window.
pub fn expired_until() -> time::OffsetDateTime {
    date_time_ymd(1980, 1, 1)
}
/// A window entirely in the future.
pub fn future_from() -> time::OffsetDateTime {
    date_time_ymd(4000, 1, 1)
}
/// The far end of the future window.
pub fn future_until() -> time::OffsetDateTime {
    date_time_ymd(4090, 1, 1)
}

/// Loopback IPv4 literal. An address, not a name, so a test that uses it never
/// performs a name lookup.
pub const LOOPBACK: &str = "127.0.0.1";

/// A certificate and the key that belongs to it.
pub struct Issued {
    /// PEM-encoded certificate.
    pub pem: String,
    /// PEM-encoded private key for `pem`.
    pub key_pem: String,
    /// The parsed certificate, for signing further certificates.
    pub certificate: rcgen::Certificate,
    /// The key for `certificate`.
    pub key: KeyPair,
}

/// Certificate parameters with the requested constraints and window.
pub fn params(
    is_ca: IsCa,
    key_usages: Vec<KeyUsagePurpose>,
    from: time::OffsetDateTime,
    until: time::OffsetDateTime,
) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = is_ca;
    params.key_usages = key_usages;
    params.not_before = from;
    params.not_after = until;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "bitty runtime test certificate");
    params.distinguished_name = name;
    params
}

/// A fresh key pair.
pub fn key_pair() -> KeyPair {
    KeyPair::generate().expect("runtime test key pair")
}

/// A self-signed CA certificate, PEM-encoded.
pub fn ca_pem() -> String {
    ca_pem_with(
        IsCa::Ca(BasicConstraints::Unconstrained),
        vec![KeyUsagePurpose::KeyCertSign],
    )
}

/// A self-signed CA certificate with the requested CA constraints.
pub fn ca_pem_with(is_ca: IsCa, key_usages: Vec<KeyUsagePurpose>) -> String {
    self_signed(params(is_ca, key_usages, window_from(), window_until()))
}

/// A self-signed CA certificate PEM whose window is entirely in the past.
pub fn expired_ca_pem() -> String {
    self_signed(params(
        IsCa::Ca(BasicConstraints::Unconstrained),
        vec![KeyUsagePurpose::KeyCertSign],
        expired_from(),
        expired_until(),
    ))
}

/// A PEM private key, for the "a CA bundle must not carry a key" case.
pub fn key_pem() -> String {
    key_pair().serialize_pem()
}

/// A PEM whose certificate body is not a certificate: a well-formed envelope
/// around bytes no parser can accept as DER.
pub fn malformed_certificate_pem() -> String {
    "-----BEGIN CERTIFICATE-----\nZm9vYmFyYmF6\n-----END CERTIFICATE-----\n".to_owned()
}

/// A self-signed CA plus its key, for issuing leaves under it.
pub fn issuer() -> Issued {
    let key = key_pair();
    let certificate = params(
        IsCa::Ca(BasicConstraints::Unconstrained),
        vec![KeyUsagePurpose::KeyCertSign],
        window_from(),
        window_until(),
    )
    .self_signed(&key)
    .expect("runtime issuer certificate");
    Issued {
        pem: certificate.pem(),
        key_pem: key.serialize_pem(),
        certificate,
        key,
    }
}

/// A certificate chain and the private key that canary material is made of.
///
/// The pair is what a client identity needs, and the key is the value the
/// redaction canary checks for: a unique, in-memory, never-committed secret
/// that no rendered surface may carry.
pub fn canary_identity() -> Issued {
    leaf_for(&issuer(), &["canary.example.com"])
}

/// A leaf certificate valid for `dns_names`, signed by `issuer`.
///
/// The leaf never claims to be a CA, and it is issued with its own key so the
/// returned key always matches the returned certificate.
pub fn leaf_for(issuer: &Issued, dns_names: &[&str]) -> Issued {
    let key = key_pair();
    let mut params = params(
        IsCa::ExplicitNoCa,
        vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ],
        window_from(),
        window_until(),
    );
    params.use_authority_key_identifier_extension = true;
    params.subject_alt_names = dns_names
        .iter()
        .map(|name| SanType::DnsName((*name).to_owned().try_into().expect("ASCII SAN")))
        .collect();
    let certificate = params
        .signed_by(&key, &issuer.certificate, &issuer.key)
        .expect("runtime leaf certificate");
    Issued {
        pem: certificate.pem(),
        key_pem: key.serialize_pem(),
        certificate,
        key,
    }
}

/// A leaf certificate valid for the loopback address literal.
pub fn loopback_leaf(issuer: &Issued) -> Issued {
    let key = key_pair();
    let mut params = params(
        IsCa::ExplicitNoCa,
        vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ],
        window_from(),
        window_until(),
    );
    params.use_authority_key_identifier_extension = true;
    params.subject_alt_names = vec![SanType::IpAddress(std::net::IpAddr::V4(
        std::net::Ipv4Addr::LOCALHOST,
    ))];
    let certificate = params
        .signed_by(&key, &issuer.certificate, &issuer.key)
        .expect("runtime loopback leaf certificate");
    Issued {
        pem: certificate.pem(),
        key_pem: key.serialize_pem(),
        certificate,
        key,
    }
}

/// A self-signed CA certificate PEM valid only in the future.
pub fn future_ca_pem() -> String {
    self_signed_ca(future_from(), future_until())
}

/// A self-signed CA certificate PEM with the given window.
pub fn self_signed_ca(from: time::OffsetDateTime, until: time::OffsetDateTime) -> String {
    self_signed(params(
        IsCa::Ca(BasicConstraints::Unconstrained),
        vec![KeyUsagePurpose::KeyCertSign],
        from,
        until,
    ))
}

/// Self-sign `params` with a fresh key and return the PEM.
fn self_signed(params: CertificateParams) -> String {
    params
        .self_signed(&key_pair())
        .expect("runtime self-signed certificate")
        .pem()
}
