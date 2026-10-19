//! Per-launch certificate and key generation.
//!
//! Every helper launch gets fresh material: two ECDSA P-256 keypairs, one
//! self-signed leaf per role, two certificate pins, and the helper PKCS#8 key
//! that travels in the bootstrap manifest. No key, certificate, serial, or
//! pin is reused across launches.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use rustls_pki_types::CertificateDer;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::manifest::LaunchKeyBlock;
use crate::sha256::sha256;
use crate::{
    LAUNCH_CERT_MAX_BYTES, LAUNCH_KEY_MAX_BYTES, LAUNCH_KEY_TYPE_ECDSA_P256,
    LAUNCH_PROFILE_MUTUAL_CERTIFICATES,
};

/// Bytes of fresh randomness in a leaf serial number.
///
/// RFC 5280 permits at most 20 bytes; 16 bytes leaves margin while keeping the
/// encoded certificate small.
const SERIAL_BYTES: usize = 16;

/// Backdate applied to a generated leaf's `notBefore`, in seconds.
const VALIDITY_BACKDATE_SECONDS: i64 = 5 * 60;

/// Forward validity of a generated leaf, in seconds.
///
/// Hygiene only: the certificate digest pin, not this window, is the
/// authorization decision.
const VALIDITY_WINDOW_SECONDS: i64 = 60 * 60;

/// Internal role discriminator for the two launch leaves.
#[derive(Clone, Copy)]
enum LeafRole {
    CoreSupervisor,
    AiHelper,
}

impl LeafRole {
    fn label(self) -> &'static str {
        match self {
            Self::CoreSupervisor => "core-supervisor",
            Self::AiHelper => "ai-helper",
        }
    }

    fn extended_key_usage(self) -> ExtendedKeyUsagePurpose {
        match self {
            Self::CoreSupervisor => ExtendedKeyUsagePurpose::ClientAuth,
            Self::AiHelper => ExtendedKeyUsagePurpose::ServerAuth,
        }
    }
}

/// Fresh launch-scoped certificate and key material.
///
/// Private-key buffers are owned through [`Zeroizing`] and wiped when this
/// value is dropped. The rustls client configuration built from the Core leaf
/// retains its own parsed signing key; rustls 0.23.45 does not wipe that copy
/// when the configuration is dropped. rcgen likewise keeps a serialized
/// private-key copy inside its [`KeyPair`] until the generator returns, and
/// that copy is outside this crate's control.
pub struct LaunchMaterial {
    core_cert_der: CertificateDer<'static>,
    core_key_der: Zeroizing<Vec<u8>>,
    helper_cert_der: CertificateDer<'static>,
    helper_key_der: Zeroizing<Vec<u8>>,
    core_cert_sha256: [u8; 32],
    helper_cert_sha256: [u8; 32],
}

impl LaunchMaterial {
    /// Generate one fresh material set for a single helper launch.
    ///
    /// Both leaves share one validity window taken at generation time. Random
    /// serials and OS-random keypairs come from the aws-lc-rs provider.
    pub fn generate() -> Result<Self, LaunchMaterialError> {
        let now = unix_now()?;
        let (core_cert_der, core_key_der) = generate_leaf(LeafRole::CoreSupervisor, now)?;
        let (helper_cert_der, helper_key_der) = generate_leaf(LeafRole::AiHelper, now)?;

        let core_cert_sha256 = sha256(core_cert_der.as_ref());
        let helper_cert_sha256 = sha256(helper_cert_der.as_ref());

        Ok(Self {
            core_cert_der,
            core_key_der,
            helper_cert_der,
            helper_key_der,
            core_cert_sha256,
            helper_cert_sha256,
        })
    }

    /// DER-encoded `core-supervisor` client leaf.
    pub fn core_cert_der(&self) -> &CertificateDer<'static> {
        &self.core_cert_der
    }

    /// PKCS#8 DER private key matching [`Self::core_cert_der`].
    ///
    /// This is secret material. It is exposed only so the TLS client
    /// configuration can consume it; never log or format it.
    pub fn core_key_der(&self) -> &[u8] {
        &self.core_key_der
    }

    /// DER-encoded `ai-helper` server leaf.
    pub fn helper_cert_der(&self) -> &CertificateDer<'static> {
        &self.helper_cert_der
    }

    /// PKCS#8 DER private key matching [`Self::helper_cert_der`].
    ///
    /// This is secret material. It is exposed only so it can be placed in the
    /// bootstrap manifest; never log or format it.
    pub fn helper_key_der(&self) -> &[u8] {
        &self.helper_key_der
    }

    /// SHA-256 over the complete `core-supervisor` leaf certificate DER.
    pub fn core_cert_sha256(&self) -> [u8; 32] {
        self.core_cert_sha256
    }

    /// SHA-256 over the complete `ai-helper` leaf certificate DER.
    ///
    /// This is the pin the Core client presents to its TLS verifier.
    pub fn helper_cert_sha256(&self) -> [u8; 32] {
        self.helper_cert_sha256
    }

    /// Borrow the canonical launch key-material block for manifest encoding.
    pub fn key_block(&self) -> LaunchKeyBlock<'_> {
        LaunchKeyBlock {
            profile: LAUNCH_PROFILE_MUTUAL_CERTIFICATES,
            key_type: LAUNCH_KEY_TYPE_ECDSA_P256,
            core_cert_der: self.core_cert_der.as_ref(),
            helper_cert_der: self.helper_cert_der.as_ref(),
            helper_key_der: self.helper_key_der.as_slice(),
        }
    }
}

impl fmt::Debug for LaunchMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchMaterial")
            .field("core_cert_der_len", &self.core_cert_der.as_ref().len())
            .field("helper_cert_der_len", &self.helper_cert_der.as_ref().len())
            .field("core_key_der", &"<redacted>")
            .field("helper_key_der", &"<redacted>")
            .finish()
    }
}

/// Why launch material generation failed.
#[derive(Debug)]
pub enum LaunchMaterialError {
    /// The system clock is unavailable or outside the supported range.
    Clock,
    /// The operating system random source failed.
    Random,
    /// rcgen could not build a certificate or keypair.
    Generation(rcgen::Error),
    /// A generated certificate exceeded [`LAUNCH_CERT_MAX_BYTES`].
    CertificateTooLong {
        /// Role label of the oversized leaf.
        role: &'static str,
        /// Observed DER length.
        length: usize,
        /// Maximum accepted DER length.
        max: usize,
    },
    /// A generated private key exceeded [`LAUNCH_KEY_MAX_BYTES`].
    KeyTooLong {
        /// Role label of the oversized key.
        role: &'static str,
        /// Observed PKCS#8 length.
        length: usize,
        /// Maximum accepted PKCS#8 length.
        max: usize,
    },
}

impl fmt::Display for LaunchMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock => formatter.write_str("system clock unavailable for launch material"),
            Self::Random => formatter.write_str("random source unavailable for launch material"),
            Self::Generation(error) => {
                write!(formatter, "launch material generation failed: {error}")
            }
            Self::CertificateTooLong { role, length, max } => write!(
                formatter,
                "{role} certificate is {length} bytes, maximum {max}"
            ),
            Self::KeyTooLong { role, length, max } => {
                write!(
                    formatter,
                    "{role} private key is {length} bytes, maximum {max}"
                )
            }
        }
    }
}

impl std::error::Error for LaunchMaterialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Generation(error) => Some(error),
            _ => None,
        }
    }
}

fn generate_leaf(
    role: LeafRole,
    now: i64,
) -> Result<(CertificateDer<'static>, Zeroizing<Vec<u8>>), LaunchMaterialError> {
    let key_pair =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(LaunchMaterialError::Generation)?;
    let key_der = Zeroizing::new(key_pair.serialize_der());
    if key_der.len() > LAUNCH_KEY_MAX_BYTES {
        return Err(LaunchMaterialError::KeyTooLong {
            role: role.label(),
            length: key_der.len(),
            max: LAUNCH_KEY_MAX_BYTES,
        });
    }

    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(LaunchMaterialError::Generation)?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, role.label());
    // CA false is written explicitly, not omitted. No SAN is added because
    // the parameter vector above is empty.
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![role.extended_key_usage()];
    params.serial_number = Some(SerialNumber::from_slice(&fresh_serial()?));
    let not_before = now
        .checked_sub(VALIDITY_BACKDATE_SECONDS)
        .ok_or(LaunchMaterialError::Clock)?;
    let not_after = now
        .checked_add(VALIDITY_WINDOW_SECONDS)
        .ok_or(LaunchMaterialError::Clock)?;
    params.not_before = timestamp(not_before)?;
    params.not_after = timestamp(not_after)?;

    let certificate = params
        .self_signed(&key_pair)
        .map_err(LaunchMaterialError::Generation)?;
    let cert_der = certificate.der().clone();
    if cert_der.as_ref().len() > LAUNCH_CERT_MAX_BYTES {
        return Err(LaunchMaterialError::CertificateTooLong {
            role: role.label(),
            length: cert_der.as_ref().len(),
            max: LAUNCH_CERT_MAX_BYTES,
        });
    }

    Ok((cert_der, key_der))
}

fn fresh_serial() -> Result<[u8; SERIAL_BYTES], LaunchMaterialError> {
    let mut serial = [0u8; SERIAL_BYTES];
    // Use the same aws-lc-rs provider rustls uses rather than pulling the
    // aws-lc-rs ring-compatibility random API and its extra `untrusted`
    // dependency edge into the graph.
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut serial)
        .map_err(|_| LaunchMaterialError::Random)?;
    // Keep the DER INTEGER positive without adding a leading zero byte, and
    // make all-zero (non-conforming) serials impossible.
    serial[0] &= 0x7f;
    if serial.iter().all(|byte| *byte == 0) {
        serial[SERIAL_BYTES - 1] = 1;
    }
    Ok(serial)
}

fn unix_now() -> Result<i64, LaunchMaterialError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LaunchMaterialError::Clock)?;
    i64::try_from(elapsed.as_secs()).map_err(|_| LaunchMaterialError::Clock)
}

fn timestamp(seconds: i64) -> Result<OffsetDateTime, LaunchMaterialError> {
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| LaunchMaterialError::Clock)
}
