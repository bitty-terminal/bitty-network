//! Launch-scoped mutual-certificate provider-publication control transport
//! (Core side, slice 1).
//!
//! This crate implements the transport half of the authenticated
//! provider-publication control channel described by the Bitty AI draft
//! *Authenticated provider publication*: the trusted Core supervisor mints one
//! fresh certificate pair per helper launch, writes a bounded launch manifest
//! into the one-shot bootstrap channel, and then opens a mutually
//! authenticated TLS 1.3 stream on the dedicated control channel.
//!
//! It contains **no** process spawning, descriptor/handle plumbing, control
//! record state machine, frame/wire budget accounting, helper-side code, or
//! network listener. Streams are injected by the caller, so this crate never
//! resolves a host, opens a socket, or touches the filesystem.
//!
//! # Roles and key material
//!
//! Each launch gets two independent ECDSA P-256 keypairs and two self-signed
//! leaf certificates:
//!
//! | Role | TLS role | Extended key usage |
//! | --- | --- | --- |
//! | `core-supervisor` | client | `clientAuth` |
//! | `ai-helper` | server | `serverAuth` |
//!
//! Both leaves carry a fresh random 16-byte serial, no subject alternative
//! names, `basicConstraints` with CA false, and `keyUsage` limited to
//! `digitalSignature`. The validity window (`now - 5 minutes` through
//! `now + 1 hour`) is hygiene only and is **not** an authorization input: the
//! pin decision is the only certificate authorization rule.
//!
//! The helper leaf and its PKCS#8 key travel to the helper in the bootstrap
//! manifest. The Core leaf travels as the client certificate; its private key
//! stays in Core process memory and is handed to the rustls client
//! configuration. [`LaunchMaterial`] owns both private-key buffers and
//! zeroizes them on drop. Formatting is redacted; errors never carry key
//! bytes. As with every rustls-backed consumer in this workspace, the parsed
//! signing-key copy retained by the rustls configuration is not wiped when the
//! configuration is dropped.
//!
//! # Pins
//!
//! A pin is SHA-256 over the complete leaf certificate DER, not over its
//! subject public key. The helper pin is the only server identity the Core
//! client accepts; the Core pin is what the helper verifies. Both pins are
//! returned by [`LaunchMaterial`]. Digests are never transmitted inside the
//! manifest; each side hashes the leaf it received through bootstrap.
//!
//! # Launch manifest envelope
//!
//! The manifest is one bounded record with unsigned big-endian integers,
//! `u32`-length-prefixed variable byte strings, and no padding, framing
//! wrapper, or trailing bytes. Its concrete field order is:
//!
//! | Order | Field | Encoding |
//! | --- | --- | --- |
//! | 1 | Bootstrap format version | `u16`, value `1` |
//! | 2 | Control protocol version | `u16`, value `1` |
//! | 3 | Core role | `u8`, value `1` (`core-supervisor`, TLS client) |
//! | 4 | Helper role | `u8`, value `2` (`ai-helper`, TLS server) |
//! | 5 | Core instance nonce | 32 raw bytes |
//! | 6 | Launch nonce | 32 raw bytes |
//! | 7 | Component name | `u32` byte length + UTF-8 |
//! | 8 | Descriptor version | `u32` byte length + UTF-8 |
//! | 9 | Executable name | `u32` byte length + UTF-8 |
//! | 10 | Executable SHA-256 | 32 raw bytes |
//! | 11 | Component protocol version | `u16` |
//! | 12 | Control-channel nonce | 32 raw bytes |
//! | 13 | Data-channel nonce | 32 raw bytes |
//! | 14 | Delegation purpose | `u32` byte length + UTF-8, exactly [`DELEGATION_PURPOSE`] |
//! | 15 | Control profile | `u32` byte length + UTF-8, exactly [`CONTROL_PROFILE`] |
//! | 16 | Launch profile | `u8`, value `1` (launch-scoped mutual certificates) |
//! | 17 | Key type | `u8`, value `1` (ECDSA P-256) |
//! | 18 | Core leaf certificate | `u32` byte length + DER |
//! | 19 | Helper leaf certificate | `u32` byte length + DER |
//! | 20 | Helper private key | `u32` byte length + PKCS#8 DER |
//!
//! Items 1-15 are the manifest proper; items 16-20 are the key-material block
//! appended after it. The record ends exactly at the helper key. The whole
//! record is bounded by [`CONTROL_BOOTSTRAP_MAX_BYTES`]; identity strings by
//! [`CONTROL_STRING_MAX_BYTES`]; each certificate by [`LAUNCH_CERT_MAX_BYTES`];
//! the helper key by [`LAUNCH_KEY_MAX_BYTES`].
//!
//! Choices made where the draft only states a bound rather than a rule:
//!
//! - The three identity strings and every length-prefixed payload must be
//!   non-empty. The draft bounds length but does not explicitly permit empty
//!   strings; rejecting them fails closed on a supervisor metadata defect.
//! - There is no length field around the manifest itself. The bootstrap read
//!   is bounded by [`CONTROL_BOOTSTRAP_MAX_BYTES`] and must end exactly after
//!   the helper key.
//! - The two role bytes are a fixed `1, 2` sequence, not a tagged union.
//!
//! # TLS profile
//!
//! [`ControlClient`] builds a rustls [`ClientConfig`](rustls::ClientConfig)
//! with TLS 1.3 only, ALPN `provider-publication-control/1`, resumption and
//! session tickets disabled, early data disabled, SNI disabled, secret
//! extraction disabled, and a custom
//! [`ServerCertVerifier`](rustls::client::danger::ServerCertVerifier). The
//! verifier accepts exactly one end-entity certificate whose SHA-256 DER
//! digest equals the helper pin, rejects any intermediate certificate, and
//! delegates handshake signature checks to the rustls provider helpers. There
//! is no PKI, chain building, name check, or fallback.
//!
//! The rustls provider's default cipher suites and key-exchange groups are
//! used unchanged. Selecting an explicit group policy (for example a
//! post-quantum preference) remains a separate adoption decision; this crate
//! makes no claim beyond the pinned provider defaults.
//!
//! # Example
//!
//! ```no_run
//! use bitty_network_publication::{
//!     ControlClient, LaunchIdentity, LaunchManifest, LaunchMaterial,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let material = LaunchMaterial::generate()?;
//! let identity = LaunchIdentity::new(
//!     "example-component",
//!     "1.0.0",
//!     "example-helper",
//!     [0u8; 32],
//!     1,
//! );
//! let manifest = LaunchManifest::new(
//!     [1u8; 32],
//!     [2u8; 32],
//!     identity,
//!     [3u8; 32],
//!     [4u8; 32],
//! )?;
//! // The supervisor writes these bytes to the one-shot bootstrap channel and
//! // then drops the buffer; it is zeroized on drop.
//! let bootstrap_record = manifest.encode(&material)?;
//! # let _ = bootstrap_record;
//! // The client consumes the material; its private-key buffers zeroize after
//! // the rustls configuration is built.
//! let client = ControlClient::new(material)?;
//! # let _ = client;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod control;
mod launch;
mod manifest;
mod sha256;

pub use control::{ControlClient, ControlError, ControlSession};
pub use launch::{LaunchMaterial, LaunchMaterialError};
pub use manifest::{
    CONTROL_PROFILE, DELEGATION_PURPOSE, LaunchIdentity, LaunchKeyBlock, LaunchManifest,
    ManifestError,
};

/// Maximum size of one complete bootstrap record, manifest plus launch
/// key-material block, in bytes.
pub const CONTROL_BOOTSTRAP_MAX_BYTES: usize = 4096;

/// Maximum DER size of one launch leaf certificate, in bytes.
pub const LAUNCH_CERT_MAX_BYTES: usize = 1024;

/// Maximum PKCS#8 DER size of the helper launch private key, in bytes.
pub const LAUNCH_KEY_MAX_BYTES: usize = 256;

/// Maximum byte length of one manifest identity or fixed profile string.
pub const CONTROL_STRING_MAX_BYTES: usize = 128;

/// Length of every launch, channel, and Core instance nonce, in bytes.
pub const RANDOM_ID_BYTES: usize = 32;

/// ALPN protocol negotiated on the dedicated control stream.
pub const CONTROL_ALPN: &[u8] = b"provider-publication-control/1";

/// Bootstrap format version emitted by this encoder.
pub const BOOTSTRAP_FORMAT_VERSION: u16 = 1;

/// Provider-publication control protocol version emitted by this encoder.
pub const CONTROL_PROTOCOL_VERSION: u16 = 1;

/// Launch key-material profile: launch-scoped mutual certificates.
pub const LAUNCH_PROFILE_MUTUAL_CERTIFICATES: u8 = 1;

/// Launch key type: ECDSA over NIST P-256.
pub const LAUNCH_KEY_TYPE_ECDSA_P256: u8 = 1;
