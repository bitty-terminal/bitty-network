//! Bounded launch-manifest encoder.
//!
//! The manifest is a single record: the fixed order described in the crate
//! documentation, followed immediately by the launch key-material block. This
//! module performs all bounds checks before allocating the output buffer and
//! rejects any field that does not fit its named bound. The output is wrapped
//! in [`Zeroizing`] because the key-material block carries the helper's
//! private key.

use std::fmt;

use zeroize::Zeroizing;

use crate::launch::LaunchMaterial;
use crate::{
    BOOTSTRAP_FORMAT_VERSION, CONTROL_BOOTSTRAP_MAX_BYTES, CONTROL_PROTOCOL_VERSION,
    CONTROL_STRING_MAX_BYTES, LAUNCH_CERT_MAX_BYTES, LAUNCH_KEY_MAX_BYTES,
    LAUNCH_KEY_TYPE_ECDSA_P256, LAUNCH_PROFILE_MUTUAL_CERTIFICATES, RANDOM_ID_BYTES,
};

/// Role byte for the `core-supervisor` TLS client.
const ROLE_CORE_SUPERVISOR: u8 = 1;
/// Role byte for the `ai-helper` TLS server.
const ROLE_AI_HELPER: u8 = 2;

/// Sole delegation purpose carried by a provider-publication launch.
pub const DELEGATION_PURPOSE: &str = "provider-routing-publication";

/// Control profile carried by a provider-publication launch.
pub const CONTROL_PROFILE: &str = "provider-publication-control/1";

/// Non-secret launch identity bound into the manifest.
///
/// All three strings are UTF-8, non-empty, and at most
/// [`CONTROL_STRING_MAX_BYTES`] bytes. They come from verified supervisor
/// configuration and component metadata, never from a caller request.
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchIdentity {
    /// Component name from the verified descriptor.
    pub component_name: String,
    /// Exact descriptor version.
    pub descriptor_version: String,
    /// Executable name from the verified descriptor.
    pub executable_name: String,
    /// SHA-256 of the verified component executable.
    pub executable_sha256: [u8; 32],
    /// Selected component protocol version.
    pub component_protocol_version: u16,
}

impl LaunchIdentity {
    /// Build an identity from its verified parts.
    pub fn new(
        component_name: impl Into<String>,
        descriptor_version: impl Into<String>,
        executable_name: impl Into<String>,
        executable_sha256: [u8; 32],
        component_protocol_version: u16,
    ) -> Self {
        Self {
            component_name: component_name.into(),
            descriptor_version: descriptor_version.into(),
            executable_name: executable_name.into(),
            executable_sha256,
            component_protocol_version,
        }
    }

    fn validate(&self) -> Result<(), ManifestError> {
        validate_string("component name", &self.component_name)?;
        validate_string("descriptor version", &self.descriptor_version)?;
        validate_string("executable name", &self.executable_name)
    }
}

impl fmt::Debug for LaunchIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchIdentity")
            .field("component_name", &self.component_name)
            .field("descriptor_version", &self.descriptor_version)
            .field("executable_name", &self.executable_name)
            .field("executable_sha256", &self.executable_sha256)
            .field(
                "component_protocol_version",
                &self.component_protocol_version,
            )
            .finish()
    }
}

/// Borrowed launch key-material block appended to the manifest.
///
/// Construction is deliberately explicit so a future profile can be encoded;
/// the encoder rejects every profile and key type this version does not
/// define. The helper private key is secret: the hand-written [`Debug`]
/// implementation redacts it.
#[derive(Clone, Copy)]
pub struct LaunchKeyBlock<'a> {
    /// Launch key-material profile tag.
    pub profile: u8,
    /// Launch key type tag.
    pub key_type: u8,
    /// DER-encoded `core-supervisor` leaf certificate.
    pub core_cert_der: &'a [u8],
    /// DER-encoded `ai-helper` leaf certificate.
    pub helper_cert_der: &'a [u8],
    /// PKCS#8 DER `ai-helper` private key.
    pub helper_key_der: &'a [u8],
}

impl<'a> LaunchKeyBlock<'a> {
    fn validate(&self) -> Result<(), ManifestError> {
        if self.profile != LAUNCH_PROFILE_MUTUAL_CERTIFICATES {
            return Err(ManifestError::UnsupportedLaunchProfile(self.profile));
        }
        if self.key_type != LAUNCH_KEY_TYPE_ECDSA_P256 {
            return Err(ManifestError::UnsupportedKeyType(self.key_type));
        }
        validate_bytes(
            "core certificate",
            self.core_cert_der,
            LAUNCH_CERT_MAX_BYTES,
        )?;
        validate_bytes(
            "helper certificate",
            self.helper_cert_der,
            LAUNCH_CERT_MAX_BYTES,
        )?;
        validate_bytes(
            "helper private key",
            self.helper_key_der,
            LAUNCH_KEY_MAX_BYTES,
        )
    }
}

impl fmt::Debug for LaunchKeyBlock<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchKeyBlock")
            .field("profile", &self.profile)
            .field("key_type", &self.key_type)
            .field("core_cert_der_len", &self.core_cert_der.len())
            .field("helper_cert_der_len", &self.helper_cert_der.len())
            .field("helper_key_der", &"<redacted>")
            .finish()
    }
}

/// Non-secret manifest binding one Core instance, one helper launch, and the
/// channels delegated to it.
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchManifest {
    core_instance_nonce: [u8; RANDOM_ID_BYTES],
    launch_nonce: [u8; RANDOM_ID_BYTES],
    identity: LaunchIdentity,
    control_channel_nonce: [u8; RANDOM_ID_BYTES],
    data_channel_nonce: [u8; RANDOM_ID_BYTES],
}

impl LaunchManifest {
    /// Build a manifest from trusted launch inputs.
    ///
    /// `core_instance_nonce` is stable for the Core instance; the other three
    /// nonces must be freshly generated for this launch and its two channels.
    /// No nonce is generated or reused here.
    pub fn new(
        core_instance_nonce: [u8; RANDOM_ID_BYTES],
        launch_nonce: [u8; RANDOM_ID_BYTES],
        identity: LaunchIdentity,
        control_channel_nonce: [u8; RANDOM_ID_BYTES],
        data_channel_nonce: [u8; RANDOM_ID_BYTES],
    ) -> Result<Self, ManifestError> {
        identity.validate()?;
        Ok(Self {
            core_instance_nonce,
            launch_nonce,
            identity,
            control_channel_nonce,
            data_channel_nonce,
        })
    }

    /// Encode the manifest followed by the canonical launch key-material block
    /// taken from `material`.
    ///
    /// The returned buffer is zeroized on drop because it contains the helper
    /// private key.
    pub fn encode(&self, material: &LaunchMaterial) -> Result<Zeroizing<Vec<u8>>, ManifestError> {
        self.encode_with_key_block(&material.key_block())
    }

    /// Encode the manifest followed by an explicit key-material block.
    ///
    /// This entry point exists so callers can encode or test a key block that
    /// was not produced by [`LaunchMaterial`]; all tags and bounds are still
    /// validated here.
    pub fn encode_with_key_block(
        &self,
        block: &LaunchKeyBlock<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ManifestError> {
        self.encode_with_limit(block, CONTROL_BOOTSTRAP_MAX_BYTES)
    }

    /// Core instance nonce bound into this manifest.
    pub fn core_instance_nonce(&self) -> &[u8; RANDOM_ID_BYTES] {
        &self.core_instance_nonce
    }

    /// Fresh launch nonce bound into this manifest.
    pub fn launch_nonce(&self) -> &[u8; RANDOM_ID_BYTES] {
        &self.launch_nonce
    }

    /// Verified component identity bound into this manifest.
    pub fn identity(&self) -> &LaunchIdentity {
        &self.identity
    }

    /// Control-channel nonce bound into this manifest.
    pub fn control_channel_nonce(&self) -> &[u8; RANDOM_ID_BYTES] {
        &self.control_channel_nonce
    }

    /// Data-channel nonce bound into this manifest.
    pub fn data_channel_nonce(&self) -> &[u8; RANDOM_ID_BYTES] {
        &self.data_channel_nonce
    }

    /// Encode with a caller-supplied total limit.
    ///
    /// Production callers use [`Self::encode`] or
    /// [`Self::encode_with_key_block`], whose limit is
    /// [`CONTROL_BOOTSTRAP_MAX_BYTES`]. The limit parameter exists so the
    /// bounded-write path can be exercised with a deliberately small budget.
    fn encode_with_limit(
        &self,
        block: &LaunchKeyBlock<'_>,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ManifestError> {
        let total = checked_total_len(self, block)?;
        if total > limit {
            return Err(ManifestError::TotalTooLong {
                length: total,
                max: limit,
            });
        }

        let mut output = Vec::with_capacity(total);
        push(&mut output, limit, &BOOTSTRAP_FORMAT_VERSION.to_be_bytes())?;
        push(&mut output, limit, &CONTROL_PROTOCOL_VERSION.to_be_bytes())?;
        push(&mut output, limit, &[ROLE_CORE_SUPERVISOR])?;
        push(&mut output, limit, &[ROLE_AI_HELPER])?;
        push(&mut output, limit, &self.core_instance_nonce)?;
        push(&mut output, limit, &self.launch_nonce)?;
        push_len_prefixed(&mut output, limit, self.identity.component_name.as_bytes())?;
        push_len_prefixed(
            &mut output,
            limit,
            self.identity.descriptor_version.as_bytes(),
        )?;
        push_len_prefixed(&mut output, limit, self.identity.executable_name.as_bytes())?;
        push(&mut output, limit, &self.identity.executable_sha256)?;
        push(
            &mut output,
            limit,
            &self.identity.component_protocol_version.to_be_bytes(),
        )?;
        push(&mut output, limit, &self.control_channel_nonce)?;
        push(&mut output, limit, &self.data_channel_nonce)?;
        push_len_prefixed(&mut output, limit, DELEGATION_PURPOSE.as_bytes())?;
        push_len_prefixed(&mut output, limit, CONTROL_PROFILE.as_bytes())?;
        push(&mut output, limit, &[block.profile])?;
        push(&mut output, limit, &[block.key_type])?;
        push_len_prefixed(&mut output, limit, block.core_cert_der)?;
        push_len_prefixed(&mut output, limit, block.helper_cert_der)?;
        push_len_prefixed(&mut output, limit, block.helper_key_der)?;

        Ok(Zeroizing::new(output))
    }
}

impl fmt::Debug for LaunchManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchManifest")
            .field("core_instance_nonce", &self.core_instance_nonce)
            .field("launch_nonce", &self.launch_nonce)
            .field("identity", &self.identity)
            .field("control_channel_nonce", &self.control_channel_nonce)
            .field("data_channel_nonce", &self.data_channel_nonce)
            .finish()
    }
}

/// Why a manifest cannot be encoded.
///
/// The variants carry only bounded metadata: field names, lengths, limits, and
/// rejected tags. No key bytes, certificate bytes, or nonce values appear in
/// an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// A bounded string or byte field was empty.
    EmptyField {
        /// Name of the rejected field.
        field: &'static str,
    },
    /// A field exceeded its named bound.
    FieldTooLong {
        /// Name of the rejected field.
        field: &'static str,
        /// Observed byte length.
        length: usize,
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The launch profile tag is not defined by this crate.
    UnsupportedLaunchProfile(u8),
    /// The launch key type tag is not defined by this crate.
    UnsupportedKeyType(u8),
    /// A length computation overflowed `usize`.
    LengthOverflow,
    /// The complete record exceeded the bootstrap limit.
    TotalTooLong {
        /// Computed record length.
        length: usize,
        /// Maximum accepted record length.
        max: usize,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField { field } => write!(formatter, "manifest field {field} is empty"),
            Self::FieldTooLong { field, length, max } => {
                write!(
                    formatter,
                    "manifest field {field} is {length} bytes, maximum {max}"
                )
            }
            Self::UnsupportedLaunchProfile(profile) => {
                write!(formatter, "unsupported launch profile {profile}")
            }
            Self::UnsupportedKeyType(key_type) => {
                write!(formatter, "unsupported launch key type {key_type}")
            }
            Self::LengthOverflow => formatter.write_str("manifest length computation overflowed"),
            Self::TotalTooLong { length, max } => write!(
                formatter,
                "manifest record is {length} bytes, maximum {max}"
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

fn validate_string(field: &'static str, value: &str) -> Result<(), ManifestError> {
    validate_bytes(field, value.as_bytes(), CONTROL_STRING_MAX_BYTES)
}

fn validate_bytes(field: &'static str, value: &[u8], max: usize) -> Result<(), ManifestError> {
    if value.is_empty() {
        return Err(ManifestError::EmptyField { field });
    }
    if value.len() > max {
        return Err(ManifestError::FieldTooLong {
            field,
            length: value.len(),
            max,
        });
    }
    Ok(())
}

fn checked_total_len(
    manifest: &LaunchManifest,
    block: &LaunchKeyBlock<'_>,
) -> Result<usize, ManifestError> {
    manifest.identity.validate()?;
    block.validate()?;

    let mut total = 0usize;
    // Bootstrap version, protocol version, and two role bytes.
    total = checked_add(total, 2 + 2 + 1 + 1)?;
    // Core instance nonce and launch nonce.
    total = checked_add(total, 2 * RANDOM_ID_BYTES)?;
    // Three u32 length prefixes plus the identity string bodies.
    total = checked_add(total, 3 * 4)?;
    total = checked_add(total, manifest.identity.component_name.len())?;
    total = checked_add(total, manifest.identity.descriptor_version.len())?;
    total = checked_add(total, manifest.identity.executable_name.len())?;
    // Executable digest.
    total = checked_add(total, 32)?;
    // Component protocol version, control nonce, data nonce.
    total = checked_add(total, 2 + 2 * RANDOM_ID_BYTES)?;
    // Delegation purpose and control profile, each length-prefixed.
    total = checked_add(total, 4 + DELEGATION_PURPOSE.len())?;
    total = checked_add(total, 4 + CONTROL_PROFILE.len())?;
    // Launch profile and key type.
    total = checked_add(total, 2)?;
    // Core cert, helper cert, helper key, each length-prefixed.
    total = checked_add(total, 4 + block.core_cert_der.len())?;
    total = checked_add(total, 4 + block.helper_cert_der.len())?;
    total = checked_add(total, 4 + block.helper_key_der.len())?;
    Ok(total)
}

fn checked_add(total: usize, addend: usize) -> Result<usize, ManifestError> {
    total
        .checked_add(addend)
        .ok_or(ManifestError::LengthOverflow)
}

/// Append bytes, checking the cumulative length before moving past `limit`.
///
/// `checked_total_len` already proves the final size fits, so this check is a
/// defensive invariant rather than the primary bound.
fn push(output: &mut Vec<u8>, limit: usize, bytes: &[u8]) -> Result<(), ManifestError> {
    let length = output
        .len()
        .checked_add(bytes.len())
        .ok_or(ManifestError::LengthOverflow)?;
    if length > limit {
        return Err(ManifestError::TotalTooLong { length, max: limit });
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn push_len_prefixed(
    output: &mut Vec<u8>,
    limit: usize,
    bytes: &[u8],
) -> Result<(), ManifestError> {
    let length = u32::try_from(bytes.len()).map_err(|_| ManifestError::LengthOverflow)?;
    push(output, limit, &length.to_be_bytes())?;
    push(output, limit, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LAUNCH_KEY_TYPE_ECDSA_P256;

    fn identity(name: &str) -> LaunchIdentity {
        LaunchIdentity::new(name, "1.0.0", "helper", [0x11; 32], 1)
    }

    fn manifest(name: &str) -> LaunchManifest {
        LaunchManifest::new([1; 32], [2; 32], identity(name), [3; 32], [4; 32])
            .expect("test manifest is valid")
    }

    fn block<'a>(core_cert: &'a [u8], helper_cert: &'a [u8], key: &'a [u8]) -> LaunchKeyBlock<'a> {
        LaunchKeyBlock {
            profile: LAUNCH_PROFILE_MUTUAL_CERTIFICATES,
            key_type: LAUNCH_KEY_TYPE_ECDSA_P256,
            core_cert_der: core_cert,
            helper_cert_der: helper_cert,
            helper_key_der: key,
        }
    }

    #[test]
    fn total_bound_is_reachable_and_enforced() {
        let name = "n".repeat(CONTROL_STRING_MAX_BYTES);
        let manifest = manifest(&name);
        let core_cert = [0x30u8; LAUNCH_CERT_MAX_BYTES];
        let helper_cert = [0x31u8; LAUNCH_CERT_MAX_BYTES];
        let key = [0x32u8; LAUNCH_KEY_MAX_BYTES];
        let block = block(&core_cert, &helper_cert, &key);

        let total = checked_total_len(&manifest, &block).expect("lengths fit");
        assert!(total <= CONTROL_BOOTSTRAP_MAX_BYTES);

        // A deliberately smaller budget must fail on the total, after every
        // individual field passed its own bound.
        let error = manifest
            .encode_with_limit(&block, 64)
            .expect_err("small budget must reject");
        assert_eq!(
            error,
            ManifestError::TotalTooLong {
                length: total,
                max: 64
            }
        );
    }

    #[test]
    fn total_rejects_a_lowered_budget_at_the_boundary() {
        let manifest = manifest("component");
        let block = block(&[1], &[2], &[3]);
        let total = checked_total_len(&manifest, &block).expect("lengths fit");

        assert!(manifest.encode_with_limit(&block, total).is_ok());
        assert_eq!(
            manifest
                .encode_with_limit(&block, total - 1)
                .expect_err("short"),
            ManifestError::TotalTooLong {
                length: total,
                max: total - 1
            }
        );
    }
}
