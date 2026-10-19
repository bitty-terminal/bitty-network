//! SHA-256 over leaf certificate DER.
//!
//! One implementation is shared by launch-material pin derivation and the TLS
//! verifier, so a pin can never mean two different things inside this crate.
//! Hashing uses the aws-lc-rs provider already present through rustls.

/// Return the SHA-256 digest of `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut output = [0u8; 32];
    for (slot, byte) in output.iter_mut().zip(digest.as_ref().iter().copied()) {
        *slot = byte;
    }
    output
}
