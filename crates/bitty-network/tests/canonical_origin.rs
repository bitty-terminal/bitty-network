//! Integration tests for CanonicalOrigin (Criterion 4 of #25).
//!
//! Verifies:
//! - http proxy absent port is 80
//! - https proxy absent port is 443
//! - explicit default ports equal absent default ports
//! - all four destination schemes (http, ws, https, wss) across absent, explicit-default, and non-default ports
//! - mixed-case scheme and host canonicalization
//! - equivalent Unicode and IDNA (Punycode) host forms
//! - IPv4 literal normalization
//! - IPv6 literal normalization
//! - percent-encoded authority delimiters failing closed
//! - WebSocket destinations retaining ws versus wss so TLS boolean is derived only after canonicalization
//! - exclusion of path, query, and fragment from origin matching
//! - userinfo rejection fail-closed

#![forbid(unsafe_code)]

use bitty_network::{CanonicalOrigin, CanonicalOriginError};

#[test]
fn http_proxy_absent_port_defaults_to_80() {
    let proxy = CanonicalOrigin::parse("http://proxy.internal").expect("http proxy parses");
    assert_eq!(proxy.scheme(), "http");
    assert_eq!(proxy.host(), "proxy.internal");
    assert_eq!(proxy.port(), 80);
    assert_eq!(proxy.default_port(), 80);
    assert!(proxy.is_default_port());
    assert!(!proxy.is_tls());
}

#[test]
fn https_proxy_absent_port_defaults_to_443() {
    let proxy =
        CanonicalOrigin::parse("https://secure-proxy.internal").expect("https proxy parses");
    assert_eq!(proxy.scheme(), "https");
    assert_eq!(proxy.host(), "secure-proxy.internal");
    assert_eq!(proxy.port(), 443);
    assert_eq!(proxy.default_port(), 443);
    assert!(proxy.is_default_port());
    assert!(proxy.is_tls());
}

#[test]
fn explicit_default_ports_equal_absent_ports() {
    let http_absent = CanonicalOrigin::parse("http://example.com").unwrap();
    let http_explicit = CanonicalOrigin::parse("http://example.com:80").unwrap();
    assert_eq!(http_absent, http_explicit);
    assert_eq!(http_absent.authority(), "example.com:80");

    let https_absent = CanonicalOrigin::parse("https://example.com").unwrap();
    let https_explicit = CanonicalOrigin::parse("https://example.com:443").unwrap();
    assert_eq!(https_absent, https_explicit);
    assert_eq!(https_absent.authority(), "example.com:443");

    let ws_absent = CanonicalOrigin::parse("ws://example.com").unwrap();
    let ws_explicit = CanonicalOrigin::parse("ws://example.com:80").unwrap();
    assert_eq!(ws_absent, ws_explicit);
    assert_eq!(ws_absent.authority(), "example.com:80");

    let wss_absent = CanonicalOrigin::parse("wss://example.com").unwrap();
    let wss_explicit = CanonicalOrigin::parse("wss://example.com:443").unwrap();
    assert_eq!(wss_absent, wss_explicit);
    assert_eq!(wss_absent.authority(), "example.com:443");
}

#[test]
fn destination_schemes_across_port_variants() {
    let test_matrix = [
        // (input, expected_scheme, expected_host, expected_port, expected_tls)
        (
            "http://api.example.com",
            "http",
            "api.example.com",
            80,
            false,
        ),
        (
            "http://api.example.com:80",
            "http",
            "api.example.com",
            80,
            false,
        ),
        (
            "http://api.example.com:8080",
            "http",
            "api.example.com",
            8080,
            false,
        ),
        (
            "https://api.example.com",
            "https",
            "api.example.com",
            443,
            true,
        ),
        (
            "https://api.example.com:443",
            "https",
            "api.example.com",
            443,
            true,
        ),
        (
            "https://api.example.com:9443",
            "https",
            "api.example.com",
            9443,
            true,
        ),
        (
            "ws://stream.example.com",
            "ws",
            "stream.example.com",
            80,
            false,
        ),
        (
            "ws://stream.example.com:80",
            "ws",
            "stream.example.com",
            80,
            false,
        ),
        (
            "ws://stream.example.com:9000",
            "ws",
            "stream.example.com",
            9000,
            false,
        ),
        (
            "wss://stream.example.com",
            "wss",
            "stream.example.com",
            443,
            true,
        ),
        (
            "wss://stream.example.com:443",
            "wss",
            "stream.example.com",
            443,
            true,
        ),
        (
            "wss://stream.example.com:9443",
            "wss",
            "stream.example.com",
            9443,
            true,
        ),
    ];

    for (url, scheme, host, port, tls) in test_matrix {
        let origin = CanonicalOrigin::parse(url).unwrap_or_else(|e| panic!("failed on {url}: {e}"));
        assert_eq!(origin.scheme(), scheme, "scheme mismatch for {url}");
        assert_eq!(origin.host(), host, "host mismatch for {url}");
        assert_eq!(origin.port(), port, "port mismatch for {url}");
        assert_eq!(origin.is_tls(), tls, "TLS mismatch for {url}");
    }
}

#[test]
fn mixed_case_scheme_and_host_normalization() {
    let lower = CanonicalOrigin::parse("https://service.example.org:443").unwrap();
    let mixed = CanonicalOrigin::parse("HtTpS://SeRvIcE.ExAmPlE.oRg:443").unwrap();
    let upper = CanonicalOrigin::parse("HTTPS://SERVICE.EXAMPLE.ORG:443").unwrap();

    assert_eq!(mixed, lower);
    assert_eq!(upper, lower);
    assert_eq!(mixed.scheme(), "https");
    assert_eq!(mixed.host(), "service.example.org");
}

#[test]
fn equivalent_unicode_and_idna_host_normalization() {
    // Unicode domain vs Punycode domain
    let unicode_origin = CanonicalOrigin::parse("https://münchen.de/path").unwrap();
    let punycode_origin = CanonicalOrigin::parse("https://xn--mnchen-3ya.de/path").unwrap();

    assert_eq!(unicode_origin, punycode_origin);
    assert_eq!(unicode_origin.host(), "xn--mnchen-3ya.de");

    // Mixed-case Unicode domain
    let mixed_unicode = CanonicalOrigin::parse("HTTPS://MÜNCHEN.DE").unwrap();
    assert_eq!(mixed_unicode, punycode_origin);
}

#[test]
fn ipv4_address_normalization() {
    let standard = CanonicalOrigin::parse("http://192.168.1.1:80").unwrap();
    let absent_port = CanonicalOrigin::parse("http://192.168.1.1").unwrap();

    assert_eq!(standard, absent_port);
    assert_eq!(standard.host(), "192.168.1.1");
    assert_eq!(standard.port(), 80);
    assert_eq!(standard.authority(), "192.168.1.1:80");
}

#[test]
fn ipv6_address_normalization() {
    // Bracketed IPv6: expanded vs compressed vs leading zeroes
    let compressed = CanonicalOrigin::parse("https://[2001:db8::1]:443").unwrap();
    let expanded =
        CanonicalOrigin::parse("https://[2001:0db8:0000:0000:0000:0000:0000:0001]").unwrap();
    let loopback = CanonicalOrigin::parse("http://[::1]:80").unwrap();
    let loopback_expanded = CanonicalOrigin::parse("http://[0:0:0:0:0:0:0:1]").unwrap();

    assert_eq!(compressed, expanded);
    assert_eq!(compressed.host(), "2001:db8::1");
    assert_eq!(compressed.authority(), "[2001:db8::1]:443");

    assert_eq!(loopback, loopback_expanded);
    assert_eq!(loopback.host(), "::1");
    assert_eq!(loopback.authority(), "[::1]:80");
}

#[test]
fn percent_encoded_authority_delimiters_fail_closed() {
    let delimiters = [
        ("http://user%40example.com/", "percent-encoded @"),
        ("http://example.com%3a80/", "percent-encoded :"),
        ("http://example.com%3A80/", "percent-encoded uppercase :"),
        ("http://example%2fcom/", "percent-encoded /"),
        ("http://example%2Fcom/", "percent-encoded uppercase /"),
        ("http://example%3fcom/", "percent-encoded ?"),
        ("http://example%3Fcom/", "percent-encoded uppercase ?"),
        ("http://example%23com/", "percent-encoded #"),
        ("http://example%5ccom/", "percent-encoded \\"),
        ("http://example%5Ccom/", "percent-encoded uppercase \\"),
        ("http://%5b::1%5d:80/", "percent-encoded [ and ]"),
    ];

    for (url, label) in delimiters {
        assert_eq!(
            CanonicalOrigin::parse(url),
            Err(CanonicalOriginError::PercentEncodedDelimiter),
            "expected fail closed for {label}: {url}"
        );
    }
}

#[test]
fn websocket_retains_ws_versus_wss_tls_derived_after_canonicalization() {
    let ws = CanonicalOrigin::parse("ws://gateway.local:80").unwrap();
    let wss = CanonicalOrigin::parse("wss://gateway.local:80").unwrap();

    assert_ne!(
        ws, wss,
        "ws and wss must not be equal even on the same port"
    );
    assert_eq!(ws.scheme(), "ws");
    assert_eq!(wss.scheme(), "wss");
    assert!(!ws.is_tls(), "ws is not TLS");
    assert!(wss.is_tls(), "wss is TLS");
}

#[test]
fn path_query_and_fragment_are_excluded_from_origin() {
    let origin1 = CanonicalOrigin::parse("http://example.com:8080").unwrap();
    let origin2 =
        CanonicalOrigin::parse("http://example.com:8080/deep/path/index.html?token=secret#section")
            .unwrap();

    assert_eq!(origin1, origin2);
    assert_eq!(origin2.scheme(), "http");
    assert_eq!(origin2.host(), "example.com");
    assert_eq!(origin2.port(), 8080);
}

#[test]
fn userinfo_credentials_fail_closed() {
    let credential_urls = [
        "http://user:pass@example.com/",
        "http://user@example.com/",
        "https://admin:secret@proxy.internal:8080/",
        "ws://guest:guest@broker.local/",
        "wss://operator:@secure.local/",
    ];

    for url in credential_urls {
        assert_eq!(
            CanonicalOrigin::parse(url),
            Err(CanonicalOriginError::UserinfoDisallowed),
            "userinfo must fail closed: {url}"
        );
    }
}

#[test]
fn unbracketed_ipv6_fails_closed() {
    assert_eq!(
        CanonicalOrigin::parse("http://::1:80/"),
        Err(CanonicalOriginError::InvalidHost)
    );
    assert_eq!(
        CanonicalOrigin::parse("http://2001:db8::1/"),
        Err(CanonicalOriginError::InvalidHost)
    );
}

#[test]
fn port_zero_and_overflow_fail_closed() {
    assert_eq!(
        CanonicalOrigin::parse("http://example.com:0/"),
        Err(CanonicalOriginError::InvalidPort)
    );
    assert_eq!(
        CanonicalOrigin::parse("http://example.com:65536/"),
        Err(CanonicalOriginError::InvalidPort)
    );
    assert_eq!(
        CanonicalOrigin::parse("http://example.com:-1/"),
        Err(CanonicalOriginError::InvalidPort)
    );
}
