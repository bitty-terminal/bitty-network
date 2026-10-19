//! Launch-material tests: sizes, roles, validity, pins, freshness, redaction,
//! and generation cost.

mod support;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitty_network_publication::{
    LAUNCH_CERT_MAX_BYTES, LAUNCH_KEY_MAX_BYTES, LaunchMaterial, LaunchMaterialError,
};
use support::{
    OID_CLIENT_AUTH, OID_SERVER_AUTH, basic_constraints_ca_false, extended_key_usage_is, hex,
    key_usage_digital_signature_only, parse_certificate, sha256,
};

/// Deliberately generous ceiling for generating one full material set. The
/// measured value is expected to be tens of milliseconds; this bound only
/// catches an algorithmic or provider regression, not scheduler noise.
const GENERATION_BUDGET: Duration = Duration::from_secs(30);

/// Repeated generations used by the cost test, so one outlier cannot dominate.
const GENERATION_ROUNDS: usize = 8;

fn now_seconds() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the Unix epoch");
    i64::try_from(elapsed.as_secs()).expect("current time fits i64")
}

#[test]
fn material_is_bounded_and_role_scoped() {
    let material = LaunchMaterial::generate().expect("launch material");
    let now = now_seconds();

    assert!(material.core_cert_der().as_ref().len() <= LAUNCH_CERT_MAX_BYTES);
    assert!(material.helper_cert_der().as_ref().len() <= LAUNCH_CERT_MAX_BYTES);
    assert!(!material.core_cert_der().as_ref().is_empty());
    assert!(!material.helper_cert_der().as_ref().is_empty());
    assert!(material.core_key_der().len() <= LAUNCH_KEY_MAX_BYTES);
    assert!(material.helper_key_der().len() <= LAUNCH_KEY_MAX_BYTES);
    assert!(!material.core_key_der().is_empty());
    assert!(!material.helper_key_der().is_empty());

    let core = parse_certificate(material.core_cert_der().as_ref()).expect("core leaf DER");
    let helper = parse_certificate(material.helper_cert_der().as_ref()).expect("helper leaf DER");

    // Serial: 16 random bytes, positive, non-zero, distinct per leaf.
    assert_eq!(core.serial.len(), 16);
    assert_eq!(helper.serial.len(), 16);
    assert_eq!(core.serial[0] & 0x80, 0, "serial must be positive");
    assert!(core.serial.iter().any(|byte| *byte != 0));
    assert!(helper.serial.iter().any(|byte| *byte != 0));
    assert_ne!(core.serial, helper.serial);

    // Validity is bounded around generation time and carries no authority.
    assert!(core.not_before <= now);
    assert!(core.not_after > now);
    assert!((240..=600).contains(&(now - core.not_before)));
    assert!((3000..=3900).contains(&(core.not_after - now)));
    assert_eq!(core.not_before, helper.not_before);
    assert_eq!(core.not_after, helper.not_after);

    // No SAN; explicit CA false; digitalSignature only; role EKU.
    assert!(core.subject_alt_name.is_none());
    assert!(helper.subject_alt_name.is_none());
    assert!(basic_constraints_ca_false(
        core.basic_constraints
            .as_deref()
            .expect("core basicConstraints")
    ));
    assert!(basic_constraints_ca_false(
        helper
            .basic_constraints
            .as_deref()
            .expect("helper basicConstraints")
    ));
    assert!(key_usage_digital_signature_only(
        core.key_usage.as_deref().expect("core keyUsage")
    ));
    assert!(key_usage_digital_signature_only(
        helper.key_usage.as_deref().expect("helper keyUsage")
    ));
    assert!(extended_key_usage_is(
        core.extended_key_usage
            .as_deref()
            .expect("core extendedKeyUsage"),
        OID_CLIENT_AUTH
    ));
    assert!(extended_key_usage_is(
        helper
            .extended_key_usage
            .as_deref()
            .expect("helper extendedKeyUsage"),
        OID_SERVER_AUTH
    ));

    // Pins are SHA-256 over complete leaf DER.
    assert_eq!(
        material.core_cert_sha256(),
        sha256(material.core_cert_der().as_ref())
    );
    assert_eq!(
        material.helper_cert_sha256(),
        sha256(material.helper_cert_der().as_ref())
    );
    assert_ne!(material.core_cert_sha256(), material.helper_cert_sha256());
}

#[test]
fn every_generation_produces_fresh_material() {
    let first = LaunchMaterial::generate().expect("first material");
    let second = LaunchMaterial::generate().expect("second material");

    assert_ne!(first.core_cert_sha256(), second.core_cert_sha256());
    assert_ne!(first.helper_cert_sha256(), second.helper_cert_sha256());
    assert_ne!(first.core_cert_der(), second.core_cert_der());
    assert_ne!(first.helper_cert_der(), second.helper_cert_der());
    assert_ne!(first.core_key_der(), second.core_key_der());
    assert_ne!(first.helper_key_der(), second.helper_key_der());

    let first_core_serial = parse_certificate(first.core_cert_der().as_ref())
        .expect("first core DER")
        .serial;
    let second_core_serial = parse_certificate(second.core_cert_der().as_ref())
        .expect("second core DER")
        .serial;
    assert_ne!(first_core_serial, second_core_serial);
}

#[test]
fn debug_output_redacts_private_keys() {
    let material = LaunchMaterial::generate().expect("launch material");
    let core_key = hex(material.core_key_der());
    let helper_key = hex(material.helper_key_der());

    let debug = format!("{material:?}");
    assert!(!debug.contains(&core_key));
    assert!(!debug.contains(&helper_key));
    assert!(!debug.contains("PRIVATE KEY"));
    assert!(debug.contains("redacted"));

    let block_debug = format!("{:?}", material.key_block());
    assert!(!block_debug.contains(&helper_key));
    assert!(!block_debug.contains("PRIVATE KEY"));
    assert!(block_debug.contains("redacted"));
}

#[test]
fn generation_cost_stays_under_a_generous_bound() {
    let started = Instant::now();
    for _ in 0..GENERATION_ROUNDS {
        let material = LaunchMaterial::generate().expect("launch material");
        assert!(!material.core_cert_der().as_ref().is_empty());
    }
    let elapsed = started.elapsed();
    eprintln!(
        "launch material: {GENERATION_ROUNDS} generations in {elapsed:?} \
         ({:.1} ms each)",
        elapsed.as_secs_f64() * 1000.0 / GENERATION_ROUNDS as f64
    );
    assert!(
        elapsed < GENERATION_BUDGET,
        "generation took {elapsed:?}, budget {GENERATION_BUDGET:?}"
    );
}

#[test]
fn generation_errors_do_not_expose_material() {
    // There is no public constructor that forces a generation failure, but the
    // error surface itself is checked so a future variant cannot accidentally
    // render key bytes.
    let errors = [
        LaunchMaterialError::Clock,
        LaunchMaterialError::Random,
        LaunchMaterialError::CertificateTooLong {
            role: "core-supervisor",
            length: LAUNCH_CERT_MAX_BYTES + 1,
            max: LAUNCH_CERT_MAX_BYTES,
        },
        LaunchMaterialError::KeyTooLong {
            role: "ai-helper",
            length: LAUNCH_KEY_MAX_BYTES + 1,
            max: LAUNCH_KEY_MAX_BYTES,
        },
    ];
    for error in errors {
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("PRIVATE KEY"));
        assert!(!rendered.contains("30 82"));
    }
}
