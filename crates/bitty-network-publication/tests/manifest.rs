//! Manifest envelope, bound, and material round-trip tests.

mod support;

use bitty_network_publication::{
    CONTROL_BOOTSTRAP_MAX_BYTES, CONTROL_PROFILE, CONTROL_STRING_MAX_BYTES, DELEGATION_PURPOSE,
    LAUNCH_CERT_MAX_BYTES, LAUNCH_KEY_MAX_BYTES, LAUNCH_KEY_TYPE_ECDSA_P256,
    LAUNCH_PROFILE_MUTUAL_CERTIFICATES, LaunchIdentity, LaunchKeyBlock, LaunchManifest,
    LaunchMaterial, ManifestError, RANDOM_ID_BYTES,
};
use support::Reader;

fn identity(component_name: &str) -> LaunchIdentity {
    LaunchIdentity::new(
        component_name,
        "1.2.3",
        "bitty-provider-helper",
        [0xab; 32],
        7,
    )
}

fn manifest(name: &str) -> LaunchManifest {
    LaunchManifest::new(
        [0x11; RANDOM_ID_BYTES],
        [0x22; RANDOM_ID_BYTES],
        identity(name),
        [0x33; RANDOM_ID_BYTES],
        [0x44; RANDOM_ID_BYTES],
    )
    .expect("test manifest is valid")
}

fn canonical_block<'a>(core: &'a [u8], helper: &'a [u8], key: &'a [u8]) -> LaunchKeyBlock<'a> {
    LaunchKeyBlock {
        profile: LAUNCH_PROFILE_MUTUAL_CERTIFICATES,
        key_type: LAUNCH_KEY_TYPE_ECDSA_P256,
        core_cert_der: core,
        helper_cert_der: helper,
        helper_key_der: key,
    }
}

#[test]
fn encoding_matches_the_documented_envelope_exactly() {
    let manifest = manifest("component");
    let block = canonical_block(b"core-certificate", b"helper-certificate", b"helper-key");
    let encoded = manifest
        .encode_with_key_block(&block)
        .expect("manifest encodes");

    assert!(encoded.len() <= CONTROL_BOOTSTRAP_MAX_BYTES);
    let mut reader = Reader::new(&encoded);

    assert_eq!(reader.u16(), 1, "bootstrap format version");
    assert_eq!(reader.u16(), 1, "control protocol version");
    assert_eq!(reader.u8(), 1, "core-supervisor role");
    assert_eq!(reader.u8(), 2, "ai-helper role");
    assert_eq!(reader.take(RANDOM_ID_BYTES), [0x11; RANDOM_ID_BYTES]);
    assert_eq!(reader.take(RANDOM_ID_BYTES), [0x22; RANDOM_ID_BYTES]);
    assert_eq!(reader.len_prefixed(), b"component");
    assert_eq!(reader.len_prefixed(), b"1.2.3");
    assert_eq!(reader.len_prefixed(), b"bitty-provider-helper");
    assert_eq!(reader.take(32), [0xab; 32]);
    assert_eq!(reader.u16(), 7);
    assert_eq!(reader.take(RANDOM_ID_BYTES), [0x33; RANDOM_ID_BYTES]);
    assert_eq!(reader.take(RANDOM_ID_BYTES), [0x44; RANDOM_ID_BYTES]);
    assert_eq!(reader.len_prefixed(), DELEGATION_PURPOSE.as_bytes());
    assert_eq!(reader.len_prefixed(), CONTROL_PROFILE.as_bytes());
    assert_eq!(reader.u8(), LAUNCH_PROFILE_MUTUAL_CERTIFICATES);
    assert_eq!(reader.u8(), LAUNCH_KEY_TYPE_ECDSA_P256);
    assert_eq!(reader.len_prefixed(), b"core-certificate");
    assert_eq!(reader.len_prefixed(), b"helper-certificate");
    assert_eq!(reader.len_prefixed(), b"helper-key");
    assert!(reader.is_empty(), "no trailing bytes after the helper key");
}

#[test]
fn generated_material_is_carried_verbatim() {
    let material = LaunchMaterial::generate().expect("launch material");
    let manifest = manifest("component");
    let encoded = manifest.encode(&material).expect("manifest encodes");

    let mut reader = Reader::new(&encoded);
    reader.take(2 + 2 + 1 + 1 + 2 * RANDOM_ID_BYTES);
    reader.len_prefixed();
    reader.len_prefixed();
    reader.len_prefixed();
    reader.take(32);
    reader.take(2 + 2 * RANDOM_ID_BYTES);
    reader.len_prefixed();
    reader.len_prefixed();
    assert_eq!(reader.u8(), LAUNCH_PROFILE_MUTUAL_CERTIFICATES);
    assert_eq!(reader.u8(), LAUNCH_KEY_TYPE_ECDSA_P256);
    assert_eq!(reader.len_prefixed(), material.core_cert_der().as_ref());
    assert_eq!(reader.len_prefixed(), material.helper_cert_der().as_ref());
    assert_eq!(reader.len_prefixed(), material.helper_key_der());
    assert!(reader.is_empty());
}

#[test]
fn maximal_fields_fit_the_bootstrap_bound() {
    let name = "n".repeat(CONTROL_STRING_MAX_BYTES);
    let manifest = manifest(&name);
    let core_cert = [0x30u8; LAUNCH_CERT_MAX_BYTES];
    let helper_cert = [0x31u8; LAUNCH_CERT_MAX_BYTES];
    let key = [0x32u8; LAUNCH_KEY_MAX_BYTES];
    let block = canonical_block(&core_cert, &helper_cert, &key);

    let encoded = manifest
        .encode_with_key_block(&block)
        .expect("maximal manifest fits");
    assert!(encoded.len() <= CONTROL_BOOTSTRAP_MAX_BYTES);
    assert!(encoded.len() > 2048, "keys and certificates dominate");
}

#[test]
fn overlong_component_name_is_rejected() {
    let name = "n".repeat(CONTROL_STRING_MAX_BYTES + 1);
    let error = LaunchManifest::new(
        [0; RANDOM_ID_BYTES],
        [0; RANDOM_ID_BYTES],
        identity(&name),
        [0; RANDOM_ID_BYTES],
        [0; RANDOM_ID_BYTES],
    )
    .expect_err("overlong name must be rejected");
    assert_eq!(
        error,
        ManifestError::FieldTooLong {
            field: "component name",
            length: CONTROL_STRING_MAX_BYTES + 1,
            max: CONTROL_STRING_MAX_BYTES,
        }
    );
}

#[test]
fn empty_identity_string_is_rejected() {
    let error = LaunchManifest::new(
        [0; RANDOM_ID_BYTES],
        [0; RANDOM_ID_BYTES],
        identity(""),
        [0; RANDOM_ID_BYTES],
        [0; RANDOM_ID_BYTES],
    )
    .expect_err("empty name must be rejected");
    assert_eq!(
        error,
        ManifestError::EmptyField {
            field: "component name"
        }
    );
}

#[test]
fn overlong_certificate_is_rejected() {
    let manifest = manifest("component");
    let core_cert = [0u8; LAUNCH_CERT_MAX_BYTES + 1];
    let block = canonical_block(&core_cert, b"helper", b"key");
    let error = manifest
        .encode_with_key_block(&block)
        .expect_err("oversized core certificate must be rejected");
    assert_eq!(
        error,
        ManifestError::FieldTooLong {
            field: "core certificate",
            length: LAUNCH_CERT_MAX_BYTES + 1,
            max: LAUNCH_CERT_MAX_BYTES,
        }
    );
}

#[test]
fn overlong_helper_key_is_rejected() {
    let manifest = manifest("component");
    let key = [0u8; LAUNCH_KEY_MAX_BYTES + 1];
    let block = canonical_block(b"core", b"helper", &key);
    let error = manifest
        .encode_with_key_block(&block)
        .expect_err("oversized helper key must be rejected");
    assert_eq!(
        error,
        ManifestError::FieldTooLong {
            field: "helper private key",
            length: LAUNCH_KEY_MAX_BYTES + 1,
            max: LAUNCH_KEY_MAX_BYTES,
        }
    );
}

#[test]
fn unknown_profile_and_key_type_are_rejected() {
    let manifest = manifest("component");
    let unknown_profile = LaunchKeyBlock {
        profile: 2,
        ..canonical_block(b"core", b"helper", b"key")
    };
    assert_eq!(
        manifest
            .encode_with_key_block(&unknown_profile)
            .expect_err("unknown profile"),
        ManifestError::UnsupportedLaunchProfile(2)
    );

    let unknown_key_type = LaunchKeyBlock {
        profile: LAUNCH_PROFILE_MUTUAL_CERTIFICATES,
        key_type: 2,
        core_cert_der: b"core",
        helper_cert_der: b"helper",
        helper_key_der: b"key",
    };
    assert_eq!(
        manifest
            .encode_with_key_block(&unknown_key_type)
            .expect_err("unknown key type"),
        ManifestError::UnsupportedKeyType(2)
    );
}
