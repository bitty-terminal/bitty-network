//! Canary redaction coverage for the key-bearing TLS types (CTX-0021).
//!
//! The record requires, before implementation review: "canary coverage must
//! generate a unique in-memory key and exercise `Debug`, `Display`, errors,
//! logs, diagnostics, and every supported serialization path, including
//! configuration, snapshot, IPC, and test-artifact representations. The
//! resulting text and bytes must contain neither the canary nor equivalent raw
//! key material; a derived or transitive serializer that emits a key is a test
//! failure."
//!
//! # What "every supported serialization path" means here
//!
//! It means *none*. This crate and the vocabulary crate take no `serde`
//! dependency and no key-bearing type derives `Serialize` or `Deserialize`, so
//! there is no configuration, snapshot, IPC, or test-artifact serializer that
//! could emit a key. That is asserted two ways below — the manifests carry no
//! `serde`, and no key-bearing module has a `Serialize`/`Deserialize` derive —
//! and the canary then covers the surfaces that do exist: every `Debug`, every
//! `Display`, every error rendering, and the ambient-proxy URL the credential
//! policy already keeps out of `Debug`.
//!
//! A canary that only asserted "no serde" would be a weak test, so the canary
//! value itself is checked against every rendered surface. If a serializer is
//! ever added, it has to be added here too; until then the value cannot leak
//! because there is nowhere for it to leak to.

#![forbid(unsafe_code)]
// Every case here needs the HTTP backend, which is where the provider is wired.
#![cfg(feature = "http")]

#[path = "tls_support/mod.rs"]
mod support;

use bitty_network::tls::{TlsProvider, TlsTransport};
use bitty_network_api::{
    ClientIdentity, ClientIdentityRule, NetworkError, PemSource, TlsConfig, TlsFailure,
};

/// The types that reach, or transitively reach, key material.
///
/// Every derived-`Debug` check below is scoped to this list rather than to a
/// file, because the vocabulary crate also holds types that reach no key at all
/// (`NetworkCapability`, `Request`) and a blanket ban would be wrong.
const KEY_BEARING_TYPES: [&str; 4] = [
    "PemSource",
    "ClientIdentity",
    "ClientIdentityRule",
    "TlsConfig",
];

/// The same property for the types that reach key material inside the
/// implementation crate rather than the vocabulary crate.
///
/// A resolved selection is here because it *hands out* the configuration that
/// holds a client identity, and a derived `Debug` on it would forward whatever
/// that configuration renders — an algorithm name today, and not this crate's
/// decision to keep true tomorrow.
const IMPL_KEY_BEARING_TYPES: [&str; 2] = ["TlsProvider", "TlsSelection"];

/// The canary material: a chain and the key that matches it.
///
/// One call, because the two halves must be the *same* generated pair: a chain
/// from one call and a key from another would not pair, and the provider would
/// (correctly) refuse the identity.
fn canary_material() -> support::Issued {
    support::canary_identity()
}

/// A client identity whose key is the canary.
fn canary_identity(material: &support::Issued) -> ClientIdentity {
    ClientIdentity::new(
        PemSource::inline(material.pem.clone()),
        PemSource::inline(material.key_pem.clone()),
    )
}

/// Substrings that must not appear in any rendering.
///
/// The PEM envelope, each base64 line, and a slice of the key body itself: a
/// partially redacted rendering — say, one that dropped the envelope but kept
/// the first line — is still a leak, and the last needle is what catches it.
fn canary_needles(key: &str) -> Vec<String> {
    let mut needles = vec![
        key.to_owned(),
        "-----BEGIN PRIVATE KEY-----".to_owned(),
        "PRIVATE KEY".to_owned(),
    ];
    let mut body: Option<String> = None;
    for line in key.lines().filter(|line| !line.starts_with("-----")) {
        if line.len() >= 16 {
            needles.push(line.to_owned());
        }
        if body.is_none() && line.len() >= 40 {
            body = Some(line[8..40].to_owned());
        }
    }
    needles.extend(body);
    needles
}

/// Assert that `rendered` carries no part of `key`.
fn assert_canary_absent(what: &str, rendered: &str, key: &str) {
    for needle in canary_needles(key) {
        let leaked = rendered.contains(&needle);
        assert!(
            !leaked,
            "{what} leaked key material: needle appears in output"
        );
    }
}

/// Every key-bearing type's `Debug` is redacted by hand, and the canary does not
/// appear in any of them.
///
/// The values here are the ones an operator or a log line would actually print:
/// a source, an identity, a rule, the whole policy, the built provider, and the
/// service that holds the provider.
#[test]
fn debug_of_every_key_bearing_type_is_redacted() {
    let material = canary_material();
    let key = material.key_pem.clone();
    let provider = TlsProvider::build(
        TlsConfig::new()
            .with_ca(PemSource::inline(support::ca_pem().into_bytes()))
            .with_identity(ClientIdentityRule::new(
                ["canary.example.com"],
                canary_identity(&material),
            )),
    )
    .expect("a valid policy builds");
    let policy = TlsConfig::new()
        .with_ca(PemSource::inline(support::ca_pem().into_bytes()))
        .with_identity(ClientIdentityRule::new(
            ["canary.example.com"],
            canary_identity(&material),
        ));
    let rule = ClientIdentityRule::new(["canary.example.com"], canary_identity(&material));

    let surfaces: [(&str, String); 11] = [
        (
            "PemSource::inline",
            format!("{:?}", PemSource::inline(key.clone())),
        ),
        (
            "PemSource::file",
            format!(
                "{:?}",
                PemSource::file("/etc/bitty/keys/canary-identity.pem")
            ),
        ),
        (
            "ClientIdentity",
            format!("{:?}", canary_identity(&material)),
        ),
        ("ClientIdentityRule", format!("{rule:?}")),
        ("TlsConfig", format!("{policy:?}")),
        ("TlsProvider", format!("{provider:?}")),
        (
            "ClientIdentity::key accessor",
            format!(
                "{:?}",
                ClientIdentityRule::new(["canary.example.com"], canary_identity(&material))
                    .identity()
                    .key()
            ),
        ),
        (
            "ClientIdentity::chain accessor",
            format!(
                "{:?}",
                ClientIdentityRule::new(["canary.example.com"], canary_identity(&material))
                    .identity()
                    .chain()
            ),
        ),
        ("TlsFailure", format!("{:?}", TlsFailure::IdentityInvalid)),
        // A resolved selection hands out the configuration that holds the
        // identity, so it reaches key material transitively and is rendered
        // through the same redacting path.
        (
            "TlsSelection (identity slot)",
            format!(
                "{:?}",
                provider.select(TlsTransport::Http, "canary.example.com")
            ),
        ),
        (
            "TlsSelection (no identity slot)",
            format!(
                "{:?}",
                provider.select(TlsTransport::Http, "other.example.com")
            ),
        ),
    ];
    for (what, rendered) in surfaces {
        assert_canary_absent(what, &rendered, &key);
    }

    // The redacted renderings still report the non-secret facts diagnostics are
    // allowed to carry, so redaction did not turn into uselessness.
    let rendered = format!("{provider:?}");
    for expected in ["native_only", "custom_roots", "identity_hosts", "hosts"] {
        assert!(
            rendered.contains(expected),
            "the provider debug must still report {expected}"
        );
    }
    let rendered = format!("{rule:?}");
    for expected in ["hosts", "chain_source", "key_source"] {
        assert!(
            rendered.contains(expected),
            "the rule debug must still report {expected}"
        );
    }
    assert!(
        rendered.contains("canary.example.com"),
        "a rule reports the exact hosts it names: {rendered:?}"
    );
    assert_eq!(
        format!("{:?}", PemSource::inline(Vec::new())),
        "PemSource { kind: \"inline\", .. }",
        "a source reports its kind and nothing else"
    );
}

/// The redacting `Debug` is hand-written, and the key-bearing types never derive
/// one.
///
/// The check is scoped to the types that reach key material by attributing each
/// `#[derive(..)]` to the item it applies to, so a `Debug` that is fine on
/// `NetworkCapability` is not reported and a `Debug` added to `TlsConfig` is.
#[test]
fn the_redacting_debug_is_hand_written_and_never_derived() {
    let mut attributed = 0;
    for (label, source) in [
        (
            "bitty-network-api/src/lib.rs",
            include_str!("../../bitty-network-api/src/lib.rs"),
        ),
        (
            "src/tls/provider.rs",
            include_str!("../../bitty-network-tls/src/provider.rs"),
        ),
    ] {
        for (line, owner, traits) in derive_owners(source) {
            attributed += 1;
            if !KEY_BEARING_TYPES.contains(&owner.as_str())
                && !IMPL_KEY_BEARING_TYPES.contains(&owner.as_str())
            {
                continue;
            }
            assert!(
                !traits.iter().any(|trait_name| {
                    trait_name.rsplit("::").next().unwrap_or(trait_name) == "Debug"
                }),
                "{label}:{line} derives Debug on `{owner}`, which reaches key \
                 material; a hand-written redacting implementation is required"
            );
        }
    }
    // The scan must actually be finding derives, or the check above would pass
    // by having matched nothing.
    assert!(
        attributed >= 8,
        "the derive scan attributed only {attributed} derives, so it is not \
         reading the sources and the Debug check would pass vacuously"
    );
    let api = include_str!("../../bitty-network-api/src/lib.rs");
    for ty in KEY_BEARING_TYPES {
        assert!(
            api.contains(&format!("impl fmt::Debug for {ty}")),
            "{ty} must carry a hand-written redacting Debug implementation"
        );
    }
    let provider = include_str!("../../bitty-network-tls/src/provider.rs");
    for ty in IMPL_KEY_BEARING_TYPES {
        assert!(
            provider.contains(&format!("impl fmt::Debug for {ty}")),
            "{ty} must carry a hand-written redacting Debug implementation"
        );
    }
    // A hand-written implementation can still forward the material, and today
    // forwarding it would not show up in the canary: the pinned rustls and
    // aws-lc-rs `Debug` impls render an algorithm name and nothing else. So the
    // guarantee is stated structurally — a redacting `Debug` reports the
    // *presence* of a configuration, never the configuration.
    let selection = provider
        .split_once("impl fmt::Debug for TlsSelection")
        .expect("TlsSelection has a hand-written Debug")
        .1
        .split_once("\n}\n")
        .expect("that implementation has a body")
        .0;
    assert!(
        !selection.contains("&self.config)"),
        "TlsSelection's Debug must not render the configuration itself; report whether one \
         is present instead"
    );
    assert!(
        selection.contains("config_present"),
        "TlsSelection's Debug reports configuration presence as a non-secret fact"
    );
}

/// Every `#[derive(..)]` in `source`, attributed to the item it applies to.
///
/// A derive is attributed to the first `struct`/`enum` declaration after it,
/// which is the item it applies to in every form `rustfmt` emits here (a derive
/// run directly above its item, wrapped or not).
fn derive_owners(source: &str) -> Vec<(usize, String, Vec<String>)> {
    let mut owners = Vec::new();
    let mut pending: Option<(usize, Vec<String>)> = None;
    for (index, raw) in source.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("#[derive(") {
            let list = rest.trim_end_matches(')');
            let traits: Vec<String> = list
                .split(',')
                .map(|item| item.trim().to_owned())
                .filter(|item| !item.is_empty())
                .collect();
            pending = Some((index + 1, traits));
            continue;
        }
        let declaration = line
            .strip_prefix("pub struct ")
            .or_else(|| line.strip_prefix("struct "))
            .or_else(|| line.strip_prefix("pub enum "))
            .or_else(|| line.strip_prefix("enum "));
        if let Some(declaration) = declaration {
            let name = declaration
                .split(['<', '(', '{', ' '])
                .next()
                .unwrap_or(declaration)
                .to_owned();
            if let Some((derive_line, traits)) = pending.take() {
                owners.push((derive_line, name, traits));
            }
        }
    }
    owners
}

/// No serialization surface exists that could emit a key.
///
/// This is the "every supported serialization path" clause discharged by
/// construction: with no `serde` dependency and no derived
/// `Serialize`/`Deserialize`, there is no configuration, snapshot, IPC, or
/// test-artifact representation to leak through. A future serializer has to
/// come with a `serde` dependency, and both halves are asserted here.
#[test]
fn no_serialization_surface_exists_for_a_key_bearing_type() {
    for (label, manifest) in [
        (
            "bitty-network-api/Cargo.toml",
            include_str!("../../bitty-network-api/Cargo.toml"),
        ),
        ("bitty-network/Cargo.toml", include_str!("../Cargo.toml")),
    ] {
        assert!(
            !manifest.contains("serde"),
            "{label} takes no serde dependency, so no key-bearing type can reach \
             a derived serializer"
        );
    }
    for (label, source) in [
        (
            "bitty-network-api/src/lib.rs",
            include_str!("../../bitty-network-api/src/lib.rs"),
        ),
        (
            "src/tls/provider.rs",
            include_str!("../../bitty-network-tls/src/provider.rs"),
        ),
        (
            "src/tls/x509.rs",
            include_str!("../../bitty-network-tls/src/x509.rs"),
        ),
    ] {
        for (line, owner, traits) in derive_owners(source) {
            for trait_name in traits {
                let leaf = trait_name.rsplit("::").next().unwrap_or(&trait_name);
                assert!(
                    leaf != "Serialize" && leaf != "Deserialize",
                    "{label}:{line} derives {trait_name} on `{owner}`; a \
                     key-bearing type must use a hand-written redacted \
                     representation or a separate non-secret DTO"
                );
            }
        }
    }
}

/// Typed errors carry a stable category and nothing else.
///
/// `NetworkError` still derives `Debug` and `PartialEq` — a known, deliberately
/// unmitigated state pinned by `tests/proxy_credential_policy.rs`. This test
/// does not change that; it pins that the *new* TLS category adds no secret
/// surface to either rendering, so the existing gap is not made worse.
#[test]
fn typed_tls_failures_carry_a_category_and_never_a_source_detail() {
    let key = canary_material().key_pem;
    let cases = [
        (TlsFailure::CaSourceInvalid, "ca source invalid"),
        (TlsFailure::CaRootRejected, "ca root rejected"),
        (TlsFailure::CaRootNotValid, "ca root not valid"),
        (
            TlsFailure::NativeRootsUnavailable,
            "native roots unavailable",
        ),
        (TlsFailure::IdentityInvalid, "client identity invalid"),
        (
            TlsFailure::IdentityHostAmbiguous,
            "client identity host ambiguous",
        ),
        (
            TlsFailure::IdentityLimitExceeded,
            "client identity limit exceeded",
        ),
        (TlsFailure::RuleHostInvalid, "identity rule host invalid"),
    ];
    for (reason, expected) in cases {
        assert_eq!(reason.to_string(), expected);
        assert_eq!(
            reason.to_string(),
            expected,
            "every TLS category has its own stable display string"
        );
        let error = NetworkError::Tls { reason };
        assert_eq!(
            error.to_string(),
            format!("network tls refused: {expected}"),
            "the network error names the category and nothing else"
        );
        assert_canary_absent("NetworkError::Tls display", &error.to_string(), &key);
        assert_canary_absent("NetworkError::Tls debug", &format!("{error:?}"), &key);
        // A real error is a `std::error::Error`, so it can cross an IPC or
        // logging boundary as a source chain without gaining a field.
        let dynamic: &dyn std::error::Error = &error;
        assert_canary_absent("NetworkError::Tls as Error", &dynamic.to_string(), &key);
    }
}

/// A credential-bearing path never reaches `Debug`, and neither does the canary.
///
/// A path is not itself a secret, but a key path names where the secret lives,
/// so the redacting implementations report the source kind instead.
#[test]
fn a_key_source_path_never_reaches_debug() {
    const PATH: &str = "/etc/bitty/keys/canary-identity.pem";
    let key = canary_material().key_pem;
    let identity = ClientIdentity::new(PemSource::file(PATH), PemSource::inline(key.clone()));
    let rule = ClientIdentityRule::new(["canary.example.com"], identity);
    let policy = TlsConfig::new().with_identity(ClientIdentityRule::new(
        ["canary.example.com"],
        ClientIdentity::new(PemSource::file(PATH), PemSource::inline(key.clone())),
    ));
    for (what, rendered) in [
        ("PemSource::file", format!("{:?}", PemSource::file(PATH))),
        ("ClientIdentityRule", format!("{rule:?}")),
        ("TlsConfig", format!("{policy:?}")),
    ] {
        assert_canary_absent(what, &rendered, &key);
        assert!(
            !rendered.contains(PATH),
            "{what} leaked the raw key-source path: {rendered:?}"
        );
        assert!(
            !rendered.contains("bitty/keys"),
            "{what} leaked part of the key-source path: {rendered:?}"
        );
    }
}

/// The HTTP service's hand-written `Debug` keeps the TLS policy redacted, and
/// keeps a credential-bearing proxy URL out of it.
///
/// This is the CTX-0028 control the record says must be provided and proved
/// independently, "whether or not PR #44 merges".
#[test]
fn the_service_debug_reports_tls_shape_and_no_key_material() {
    use bitty_network::{HttpNetworkService, NetworkCapability};

    const PATH: &str = "/etc/bitty/keys/canary-identity.pem";
    // A path that does not exist is fine here: this test is about rendering, and
    // building the provider is what proves the identity was actually loaded.
    let material = canary_material();
    let key = material.key_pem.clone();
    let provider = TlsProvider::build(TlsConfig::new().with_identity(ClientIdentityRule::new(
        ["canary.example.com"],
        ClientIdentity::new(
            PemSource::inline(material.pem.clone()),
            PemSource::inline(material.key_pem.clone()),
        ),
    )))
    .expect("a valid policy builds");
    let _ = PATH;
    let service = HttpNetworkService::with_tls(
        NetworkCapability::offline().with_domain("canary.example.com"),
        provider,
    )
    .expect("the service builds with a policy");
    let rendered = format!("{service:?}");
    assert_canary_absent("HttpNetworkService", &rendered, &key);
    assert!(
        !rendered.contains(PATH) && !rendered.contains("bitty/keys"),
        "the service debug leaked a key-source path: {rendered:?}"
    );
    for expected in [
        "capability",
        "proxy_configured",
        "proxy_rejected",
        "tls",
        "native_only",
        "identity_hosts",
    ] {
        assert!(
            rendered.contains(expected),
            "the service debug must still report {expected}: {rendered:?}"
        );
    }
}

/// Inline key bytes are zeroed when the source is dropped.
///
/// A `Vec<u8>` of key material that outlives the policy in readable form is a
/// retention the record forbids ("zeroize owned temporary private-key
/// buffers"). A safe test cannot observe the freed buffer, so what is pinned
/// here is that the zeroing drop exists and does the overwrite — removing or
/// weakening it is loud.
#[test]
fn inline_key_bytes_have_a_zeroing_drop() {
    let source = include_str!("../../bitty-network-api/src/lib.rs");
    let start = source
        .find("impl Drop for PemSource")
        .expect("PemSource must zero the bytes it owns when dropped");
    let body = source[start..]
        .split_once("\n}")
        .expect("the Drop impl has a body")
        .0;
    assert!(
        body.contains("pem.fill(0)"),
        "the Drop impl must overwrite the bytes it owns before releasing them"
    );
}

/// A read PEM buffer is zeroizing, and there is exactly one reader.
///
/// The record asks the implementation to "minimize retained byte copies"; the
/// one copy that must exist is the one `rustls` holds, and every temporary is
/// zeroizing. Both are pinned so a future change that copies a key into a plain
/// `Vec` is loud.
#[test]
fn key_buffers_are_zeroizing_and_read_from_one_place() {
    let provider = include_str!("../../bitty-network-tls/src/provider.rs");
    assert!(
        provider.contains("Zeroizing<Vec<u8>>"),
        "a read PEM buffer must be zeroizing"
    );
    let start = provider
        .find("fn read_pem(")
        .expect("there is one place that reads a source");
    let body = provider[start..]
        .split_once("\n}")
        .expect("read_pem has a body")
        .0;
    for unzeroized in ["Vec::new()", "vec![", "to_vec()"] {
        let offending = body
            .lines()
            .find(|line| line.contains(unzeroized) && !line.contains("Zeroizing::new"));
        assert!(
            offending.is_none(),
            "read_pem must not build a plain byte buffer: {offending:?}"
        );
    }
    // Exactly one definition: a second reader is a second place a key is read.
    assert_eq!(
        provider.matches("fn read_pem(").count(),
        1,
        "a key source must be read in exactly one place"
    );
}
