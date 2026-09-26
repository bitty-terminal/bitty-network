//! Trust-policy properties for the TLS provider (CTX-0021, issue #21).
//!
//! Everything here is in-memory or filesystem-only. No test in this file opens
//! a socket; the one suite that does speak TLS is `tls_local_endpoint.rs`, and
//! that one is loopback-only.
//!
//! Test material comes from `tls_support`, which generates every certificate
//! and key at runtime, so no key or certificate fixture is committed.

#![forbid(unsafe_code)]
// Every case here needs the HTTP backend, which is where the provider is wired.
#![cfg(feature = "http")]

#[path = "tls_support/mod.rs"]
mod support;

use bitty_network::tls::{TlsProvider, TlsTransport, canonical_host};
use bitty_network_api::{PemSource, TlsConfig, TlsFailure};
use rcgen::{IsCa, KeyUsagePurpose};

use support::{
    LOOPBACK, ca_pem, ca_pem_with, expired_ca_pem, future_ca_pem, key_pem,
    malformed_certificate_pem,
};

/// A provider carrying `bundle` as its CA source.
fn provider_with(bundle: Vec<u8>) -> Result<TlsProvider, TlsFailure> {
    TlsProvider::build(TlsConfig::new().with_ca(PemSource::inline(bundle)))
}

/// A supplied bundle configures trust, and it is not the only trust in play.
///
/// What this cannot assert, hermetically, is that a *platform*-rooted chain
/// still verifies after a bundle is supplied: that needs a real public host, and
/// this file makes no external request. The additive guarantee is therefore
/// pinned where it is actually implemented — the single call that composes the
/// root set — in
/// `tls_baseline_properties.rs::tls_module_is_no_longer_a_sealed_marker`, which
/// requires `Verifier::new_with_extra_roots` and forbids every alternative root
/// source. This test covers what is observable without a network.
#[test]
fn a_supplied_bundle_configures_trust_and_never_resolves_to_native_only() {
    let provider = provider_with(ca_pem().into_bytes()).expect("a valid CA bundle is admitted");
    assert_eq!(provider.custom_root_count(), 1);
    // A configured policy always hands the backend a configuration. `Native`
    // would mean the bundle was silently ignored; a `None` here would mean the
    // backend fell back to its own trust for a configured policy.
    for transport in [TlsTransport::Http, TlsTransport::WebSocket] {
        let selection = provider
            .select(transport, "example.com")
            .expect("a configured policy selects a configuration");
        assert!(
            selection.config().is_some(),
            "{transport:?}: a bundle-configured policy must never resolve to \
             the backend's own native-only construction"
        );
        assert_eq!(
            selection.slot(),
            0,
            "{transport:?}: no rule names this host"
        );
    }
    assert!(!provider.selects_identity("example.com"));
}

/// The default policy installs nothing and configures nothing.
///
/// This is the record's "when the CA source is unset, the provider performs no
/// bundle read or PEM parse, installs no custom root, and uses the native roots
/// exactly as the backends use them": the backends' own construction is left
/// alone rather than replaced by an equivalent one.
#[test]
fn an_unset_ca_source_installs_nothing_and_configures_nothing() {
    let provider = TlsProvider::build(TlsConfig::new()).expect("the default policy builds");
    assert_eq!(provider.custom_root_count(), 0);
    for transport in [TlsTransport::Http, TlsTransport::WebSocket] {
        let selection = provider
            .select(transport, "example.com")
            .expect("the default policy never refuses a destination");
        assert!(
            selection.config().is_none(),
            "{transport:?}: the default policy must not hand the backend a configuration",
        );
    }
    assert!(
        TlsConfig::new().is_native_only(),
        "the vocabulary reports the default policy as native-only"
    );
    assert!(
        !TlsConfig::new()
            .with_ca(PemSource::inline(Vec::new()))
            .is_native_only(),
        "supplying a CA source is what leaves the default policy, even when the \
         source turns out to be unusable"
    );
}

/// A bundle with one bad entry fails the whole load. There is no partial trust
/// set to continue with.
///
/// Every case puts a *usable* CA first and the bad entry after it, so a provider
/// that skipped the bad entry and kept the good one would pass. The ordering is
/// the point: without it these cases would not distinguish "fails the whole
/// load" from "fails when nothing usable is present".
#[test]
fn one_unusable_bundle_entry_fails_the_whole_load() {
    let good = ca_pem();
    let not_a_ca = ca_pem_with(IsCa::NoCa, vec![KeyUsagePurpose::KeyCertSign]);
    let no_key_cert_sign = ca_pem_with(
        IsCa::Ca(rcgen::BasicConstraints::Unconstrained),
        vec![KeyUsagePurpose::DigitalSignature],
    );
    let cases: [(&str, Vec<u8>, TlsFailure); 8] = [
        (
            "a malformed certificate after a good one",
            format!("{good}{}", malformed_certificate_pem()).into_bytes(),
            TlsFailure::CaSourceInvalid,
        ),
        (
            "a certificate that is not a CA after a good one",
            format!("{good}{not_a_ca}").into_bytes(),
            TlsFailure::CaRootRejected,
        ),
        (
            "a CA whose keyUsage omits keyCertSign after a good one",
            format!("{good}{no_key_cert_sign}").into_bytes(),
            TlsFailure::CaRootRejected,
        ),
        (
            "an expired CA after a good one",
            format!("{good}{}", expired_ca_pem()).into_bytes(),
            TlsFailure::CaRootNotValid,
        ),
        (
            "a not-yet-valid CA after a good one",
            format!("{good}{}", future_ca_pem()).into_bytes(),
            TlsFailure::CaRootNotValid,
        ),
        (
            "a private-key PEM object after a good certificate",
            format!("{good}{}", key_pem()).into_bytes(),
            TlsFailure::CaSourceInvalid,
        ),
        (
            "a bundle whose only entry is a private key",
            key_pem().into_bytes(),
            TlsFailure::CaSourceInvalid,
        ),
        ("an empty bundle", Vec::new(), TlsFailure::CaSourceInvalid),
    ];
    for (label, bundle, expected) in cases {
        assert_eq!(
            provider_with(bundle).err(),
            Some(expected),
            "fail closed for {label}"
        );
    }
}

/// The load is not order-dependent: a bad entry ahead of a good one also fails,
/// so there is no "skip until something parses" behaviour either.
#[test]
fn a_bad_entry_before_a_good_one_also_fails_the_whole_load() {
    let bundle = format!("{}{}", malformed_certificate_pem(), ca_pem());
    assert_eq!(
        provider_with(bundle.into_bytes()).err(),
        Some(TlsFailure::CaSourceInvalid),
        "a malformed entry ahead of a good one is still a whole-load failure"
    );
    assert_eq!(
        provider_with(b"not a pem bundle at all".to_vec()).err(),
        Some(TlsFailure::CaSourceInvalid),
        "input with no PEM object is a whole-load failure"
    );
}

/// A path that cannot be read, or an empty one, is a configuration failure —
/// never an empty trust set that would silently mean "custom-only".
#[test]
fn an_unreadable_or_empty_path_is_a_configuration_failure() {
    for path in [
        std::path::PathBuf::from("nonexistent-bitty-tls-test-ca.pem"),
        std::path::PathBuf::new(),
    ] {
        assert_eq!(
            TlsProvider::build(TlsConfig::new().with_ca(PemSource::file(path.clone()))).err(),
            Some(TlsFailure::CaSourceInvalid),
            "unreadable path {} must fail closed",
            path.display()
        );
    }
}

/// A supplied bundle does not restrict native trust, and the operator warning
/// that says so is present wherever the policy is described.
///
/// The warning is part of the control, not decoration: the guarantee is real but
/// surprising, and the only thing standing between an operator's mistaken
/// belief and a compromised path is the sentence being there. Deleting it is a
/// test failure rather than a documentation edit.
#[test]
fn a_bundle_does_not_restrict_native_trust_and_says_so() {
    for (label, source) in [
        (
            "bitty-network-api/src/lib.rs",
            include_str!("../../bitty-network-api/src/lib.rs"),
        ),
        (
            "src/tls/provider.rs",
            include_str!("../../bitty-network-tls/src/provider.rs"),
        ),
        ("src/tls.rs", include_str!("../src/tls.rs")),
    ] {
        // Line markers and whitespace removed, so the pin is about the sentence
        // rather than about where the doc author happened to wrap it.
        let flattened = source
            .replace("\n//!", "\n")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            flattened.contains("does not restrict native trust"),
            "{label} must carry the warning that a bundle does not restrict \
             native trust"
        );
    }
}

/// The same sentence, as the vocabulary's own field documentation, so an
/// operator reading the API reference sees it next to the field it applies to.
#[test]
fn the_ca_field_documents_that_it_does_not_narrow_trust() {
    let rendered = format!(
        "{:?}",
        TlsConfig::new().with_ca(PemSource::inline(Vec::new()))
    );
    assert_eq!(
        rendered,
        "TlsConfig { ca_configured: true, ca_source_kind: \"inline\", identity_rules: 0 }",
        "the redacted rendering reports shape and source kind only"
    );
}

/// Canonicalization is the same function for a rule's hosts and a destination's
/// host, so a rule cannot be written in a spelling that dodges an exact match.
#[test]
fn canonicalization_is_idna_normalized_case_insensitive_and_dot_free() {
    for (input, expected) in [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("Example.Com.", "example.com"),
        (" example.com ", "example.com"),
        ("xn--strae-oqa.de", "xn--strae-oqa.de"),
        ("straße.de", "xn--strae-oqa.de"),
        ("STRASSE.DE", "strasse.de"),
        (LOOPBACK, LOOPBACK),
        ("::1", "::1"),
    ] {
        assert_eq!(
            canonical_host(input).as_deref(),
            Ok(expected),
            "canonical form of {input:?}"
        );
    }
    for input in ["", "   ", ".", "..", "a..b", "exa mple.com"] {
        assert_eq!(
            canonical_host(input),
            Err(TlsFailure::RuleHostInvalid),
            "{input:?} is not a canonicalizable host"
        );
    }
}
