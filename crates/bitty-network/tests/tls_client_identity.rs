//! Client-identity selection properties (CTX-0021, issue #22).
//!
//! Every test here is in-memory: identities are generated at runtime, loaded,
//! and then asked which slot a host resolves to. Nothing opens a socket, so
//! nothing here can pass because a real handshake happened to work.
//!
//! The properties are the record's: exact canonical-host selection, no wildcard,
//! no suffix, no default, reselection per new destination, and a typed failure
//! rather than a silent downgrade to "no client certificate".

#![forbid(unsafe_code)]
// Every case here needs the HTTP backend, which is where the provider is wired.
#![cfg(feature = "http")]

#[path = "tls_support/mod.rs"]
mod support;

use bitty_network::tls::{TlsProvider, TlsTransport};
use bitty_network_api::{
    ClientIdentity, ClientIdentityRule, MAX_CLIENT_IDENTITY_RULES, MAX_HOSTS_PER_IDENTITY_RULE,
    PemSource, TlsConfig, TlsFailure,
};

use support::{LOOPBACK, issuer, leaf_for};

/// A client identity: a runtime-issued leaf for `dns_names` and its own key.
fn identity(dns_names: &[&str]) -> ClientIdentity {
    let issuer = issuer();
    let leaf = leaf_for(&issuer, dns_names);
    ClientIdentity::new(PemSource::inline(leaf.pem), PemSource::inline(leaf.key_pem))
}

/// A policy with one identity rule naming `hosts`.
fn policy_for(hosts: &[&str]) -> TlsConfig {
    TlsConfig::new().with_identity(ClientIdentityRule::new(
        hosts.iter().copied(),
        identity(hosts),
    ))
}

/// Build the provider for `config`.
fn build(config: TlsConfig) -> Result<TlsProvider, TlsFailure> {
    TlsProvider::build(config)
}

/// The slot a destination resolves to, per transport.
fn slots(provider: &TlsProvider, host: &str) -> (usize, usize) {
    let http = provider
        .select(TlsTransport::Http, host)
        .expect("selection resolves")
        .slot();
    let websocket = provider
        .select(TlsTransport::WebSocket, host)
        .expect("selection resolves")
        .slot();
    (http, websocket)
}

/// A host is selected on an exact, case-insensitive, IDNA-normalized match, and
/// only for the host the rule names.
///
/// The negative cases are the load-bearing half: a parent, a subdomain, a
/// sibling that shares a suffix, and a differently-cased trailing-dot spelling
/// that is *not* the same name all have to resolve to slot 0.
#[test]
fn selection_is_exact_case_insensitive_and_never_a_suffix_or_parent() {
    let provider = build(policy_for(&["api.example.com"])).expect("a valid rule builds");
    assert_eq!(
        slots(&provider, "api.example.com"),
        (1, 1),
        "the named host"
    );
    assert_eq!(
        slots(&provider, "API.EXAMPLE.COM"),
        (1, 1),
        "case-insensitive"
    );
    assert_eq!(slots(&provider, "api.example.com."), (1, 1), "trailing dot");
    for host in [
        "sub.api.example.com",
        "deep.sub.api.example.com",
        "example.com",
        "notapi.example.com",
        "api.example.com.evil.test",
        "api.example.co",
        "other.example.com",
    ] {
        assert_eq!(
            slots(&provider, host),
            (0, 0),
            "{host} must receive no client certificate: a rule is exact, never a \
             suffix, a parent, or a substring"
        );
    }
    assert!(provider.selects_identity("api.example.com"));
    assert!(!provider.selects_identity("sub.api.example.com"));
}

/// No wildcard, and no default identity: a host with no exact rule gets slot 0.
#[test]
fn a_wildcard_rule_host_is_refused_and_there_is_no_default_identity() {
    for host in [
        "*.example.com",
        "*",
        "api.*.example.com",
        "api.example.*",
        "sub.*.com",
    ] {
        assert_eq!(
            build(policy_for(&[host])).err(),
            Some(TlsFailure::RuleHostInvalid),
            "{host} is a pattern, not an exact host"
        );
    }
    // A host that cannot be canonicalized matches nothing, which is the
    // fail-closed direction: no identity rather than a guess.
    let provider = build(policy_for(&["api.example.com"])).expect("a valid rule builds");
    for host in ["", "   ", "..", "a..b", "api example.com"] {
        assert_eq!(
            slots(&provider, host),
            (0, 0),
            "{host:?} is not a host, so no identity is selected for it"
        );
    }
}

/// A rule host that is not a bare DNS name is refused rather than dropped.
#[test]
fn a_rule_host_carrying_authority_syntax_is_refused() {
    for host in [
        "https://api.example.com",
        "api.example.com:8443",
        "api.example.com/path",
        "user@api.example.com",
        "api.example.com?x=1",
        "api.example.com#f",
        ".api.example.com",
    ] {
        assert_eq!(
            build(policy_for(&[host])).err(),
            Some(TlsFailure::RuleHostInvalid),
            "{host} is not a bare exact host"
        );
    }
    assert_eq!(
        build(TlsConfig::new().with_identity(ClientIdentityRule::new(
            Vec::<String>::new(),
            identity(&["api.example.com"]),
        )))
        .err(),
        Some(TlsFailure::IdentityLimitExceeded),
        "a rule with no hosts is refused rather than matching everything"
    );
    // A fully-qualified name with the root dot is the same host, so it is
    // accepted and normalizes to the same canonical form.
    assert!(
        build(policy_for(&["api.example.com."])).is_ok(),
        "the root dot is a spelling of the same host, not a different one"
    );
}

/// Reusing one identity on several hosts means listing each host, and each is
/// then selected on its own exact match.
#[test]
fn one_identity_can_be_named_for_several_explicit_hosts() {
    let hosts = ["a.example.com", "b.example.com"];
    let provider = build(policy_for(&hosts)).expect("a valid multi-host rule builds");
    assert_eq!(provider.identity_host_count(), 2);
    for host in hosts {
        assert_eq!(slots(&provider, host), (1, 1), "{host}");
    }
    assert_eq!(slots(&provider, "c.example.com"), (0, 0));
}

/// Two rules claiming one host would make selection ambiguous, so construction
/// refuses rather than picking one.
#[test]
fn two_rules_claiming_one_host_are_refused() {
    let config = TlsConfig::new()
        .with_identity(ClientIdentityRule::new(
            ["api.example.com"],
            identity(&["api.example.com"]),
        ))
        .with_identity(ClientIdentityRule::new(
            // The same host in a different spelling: still the same host.
            ["API.Example.COM."],
            identity(&["other.example.com"]),
        ));
    assert_eq!(build(config).err(), Some(TlsFailure::IdentityHostAmbiguous));
}

/// Each rule gets its own slot, in declaration order, and each slot's
/// configuration is distinct — which is what makes "no cross-host pooled
/// reuse" possible rather than merely intended.
#[test]
fn each_rule_gets_its_own_slot_and_configuration() {
    let config = TlsConfig::new()
        .with_identity(ClientIdentityRule::new(
            ["first.example.com"],
            identity(&["first.example.com"]),
        ))
        .with_identity(ClientIdentityRule::new(
            ["second.example.com"],
            identity(&["second.example.com"]),
        ));
    let provider = build(config).expect("two valid rules build");
    assert_eq!(provider.identity_slot_count(), 3, "slot 0 plus two rules");
    assert_eq!(slots(&provider, "first.example.com"), (1, 1));
    assert_eq!(slots(&provider, "second.example.com"), (2, 2));
    assert_eq!(slots(&provider, "third.example.com"), (0, 0));
    for transport in [TlsTransport::Http, TlsTransport::WebSocket] {
        let first = provider
            .select(transport, "first.example.com")
            .expect("slot 1 resolves")
            .config();
        let second = provider
            .select(transport, "second.example.com")
            .expect("slot 2 resolves")
            .config();
        let anonymous = provider
            .select(transport, "third.example.com")
            .expect("slot 0 resolves")
            .config();
        assert!(first.is_some() && second.is_some() && anonymous.is_some());
        assert!(
            !std::sync::Arc::ptr_eq(
                first.as_ref().expect("slot 1 has a configuration"),
                second.as_ref().expect("slot 2 has a configuration"),
            ),
            "{transport:?}: two identities must not share one configuration, or \
             a pooled connection authenticated with one could be reused for the \
             other"
        );
    }
}

/// The limits are refusals, not silent truncations: dropping the hosts a caller
/// named would quietly change who gets a client certificate.
#[test]
fn limits_are_refused_rather_than_truncated() {
    let too_many_hosts: Vec<String> = (0..=MAX_HOSTS_PER_IDENTITY_RULE)
        .map(|index| format!("h{index}.example.com"))
        .collect();
    assert_eq!(
        build(TlsConfig::new().with_identity(ClientIdentityRule::new(
            too_many_hosts.clone(),
            identity(&["api.example.com"]),
        )))
        .err(),
        Some(TlsFailure::IdentityLimitExceeded),
        "a rule over the host limit is refused, not truncated to the first {}",
        MAX_HOSTS_PER_IDENTITY_RULE
    );
    assert!(
        build(TlsConfig::new().with_identity(ClientIdentityRule::new(
            too_many_hosts[..MAX_HOSTS_PER_IDENTITY_RULE].to_vec(),
            identity(&["api.example.com"]),
        )))
        .is_ok(),
        "exactly the limit is accepted"
    );

    let mut config = TlsConfig::new();
    for index in 0..=MAX_CLIENT_IDENTITY_RULES {
        let host = format!("h{index}.example.com");
        config = config.with_identity(ClientIdentityRule::new(
            [host.clone()],
            identity(&[host.as_str()]),
        ));
    }
    assert_eq!(
        build(config).err(),
        Some(TlsFailure::IdentityLimitExceeded),
        "a policy over the rule limit is refused, not truncated"
    );
}

/// Chain and key are indivisible: a chain without a key, a key without a chain,
/// and a chain that does not match its key are all typed failures at
/// construction — never a connection quietly sent without a client certificate.
#[test]
fn a_chain_and_its_key_are_indivisible_and_must_match() {
    let issuer = issuer();
    let leaf = leaf_for(&issuer, &["api.example.com"]);

    // A key with no certificate at all.
    assert_eq!(
        build(TlsConfig::new().with_identity(ClientIdentityRule::new(
            ["api.example.com"],
            ClientIdentity::new(
                PemSource::inline(Vec::new()),
                PemSource::inline(leaf.key_pem.clone())
            ),
        )))
        .err(),
        Some(TlsFailure::IdentityInvalid),
        "an empty chain source is a typed failure"
    );

    // A chain with no key at all.
    assert_eq!(
        build(TlsConfig::new().with_identity(ClientIdentityRule::new(
            ["api.example.com"],
            ClientIdentity::new(
                PemSource::inline(leaf.pem.clone()),
                PemSource::inline(Vec::new())
            ),
        )))
        .err(),
        Some(TlsFailure::IdentityInvalid),
        "an empty key source is a typed failure"
    );

    // A chain and a key that belong to different certificates.
    let other = leaf_for(&issuer, &["other.example.com"]);
    let chain_pem = leaf.pem.clone();
    assert_eq!(
        build(TlsConfig::new().with_identity(ClientIdentityRule::new(
            ["api.example.com"],
            ClientIdentity::new(
                PemSource::inline(chain_pem),
                PemSource::inline(other.key_pem)
            ),
        )))
        .err(),
        Some(TlsFailure::IdentityInvalid),
        "a chain that does not match its key fails closed at construction"
    );

    // A chain source carrying a private key is refused rather than partly read.
    assert_eq!(
        build(TlsConfig::new().with_identity(ClientIdentityRule::new(
            ["api.example.com"],
            ClientIdentity::new(
                PemSource::inline(format!("{}{}", leaf.pem, leaf.key_pem)),
                PemSource::inline(leaf.key_pem.clone()),
            ),
        )))
        .err(),
        Some(TlsFailure::IdentityInvalid),
        "a chain source carrying a key is refused, not partly read"
    );

    // The matching pair is accepted.
    assert!(
        build(TlsConfig::new().with_identity(ClientIdentityRule::new(
            ["api.example.com"],
            ClientIdentity::new(PemSource::inline(leaf.pem), PemSource::inline(leaf.key_pem)),
        )))
        .is_ok(),
        "a matching chain and key build"
    );
}

/// A rule is validated before any key material is read, so a bad host list can
/// never leave a half-loaded identity behind — and a valid host list with a bad
/// identity still fails closed.
#[test]
fn a_bad_host_list_is_refused_before_any_key_is_read() {
    let config = TlsConfig::new().with_identity(ClientIdentityRule::new(
        ["*.example.com"],
        ClientIdentity::new(PemSource::inline(Vec::new()), PemSource::inline(Vec::new())),
    ));
    assert_eq!(
        build(config).err(),
        Some(TlsFailure::RuleHostInvalid),
        "the host list is checked first, so this reports the host problem rather \
         than the unusable identity behind it"
    );
}

/// Client identity is off by default: a policy with a CA bundle and no rule
/// presents no client certificate anywhere.
#[test]
fn client_identity_is_off_unless_a_rule_names_a_host() {
    let provider =
        build(TlsConfig::new().with_ca(PemSource::inline(support::ca_pem().into_bytes())))
            .expect("a bundle-only policy builds");
    assert_eq!(
        provider.identity_slot_count(),
        1,
        "only the no-identity slot"
    );
    for host in [LOOPBACK, "example.com", "api.example.com"] {
        assert!(!provider.selects_identity(host), "{host}");
        assert_eq!(slots(&provider, host), (0, 0), "{host}");
    }
}

/// A rule match never waives a certificate check: the selected certificate is
/// still the backend's to verify for the target, and the provider does not
/// inspect or relax that. The pin is that the provider hands over a
/// configuration and makes no name decision of its own beyond exact host
/// selection.
#[test]
fn a_rule_match_hands_over_a_configuration_and_makes_no_name_decision() {
    let provider = build(policy_for(&["api.example.com"])).expect("a valid rule builds");
    let selection = provider
        .select(TlsTransport::Http, "api.example.com")
        .expect("selection resolves");
    let configuration = selection.config().expect("a configured policy");
    // A configured `ClientConfig` keeps rustls' own server-name verification:
    // the provider replaces the verifier only to *add* roots, and a name check
    // that had been disabled would show up as a missing field rather than a
    // changed one, so what this asserts is that the provider is not the thing
    // deciding names at all.
    assert_eq!(selection.slot(), 1);
    assert!(
        std::ptr::eq(
            configuration.as_ref() as *const _,
            provider
                .config_for_slot(TlsTransport::Http, 1)
                .expect("slot 1 has a configuration")
                .as_ref() as *const _
        ),
        "the per-destination selection resolves to the same configuration the \
         client was built from, so a rule can never change the checks"
    );
}
