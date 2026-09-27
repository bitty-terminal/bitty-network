//! Canonical origin parser and closed default-port table for #25 (Criterion 4).
//!
//! A [`CanonicalOrigin`] contains exactly:
//! - a lowercase scheme;
//! - a canonically encoded ASCII host or IP literal; and
//! - an effective `u16` port.
//!
//! # Parsing and Normalization Rules
//!
//! - Structured parser over the scheme, host, and port components.
//! - Closed four-entry default-port table (`http` -> 80, `ws` -> 80, `https` -> 443, `wss` -> 443).
//!   Any other scheme fails closed.
//! - Omitted ports default to the scheme default; explicit default ports canonicalize
//!   to the same origin as omitted ones.
//! - DNS hostnames are converted through IDNA (Punycode) and lowercased.
//! - IPv4 literals are parsed into [`std::net::Ipv4Addr`] and normalized into standard dotted-decimal form.
//! - IPv6 literals (bracketed in input) are parsed into [`std::net::Ipv6Addr`] and normalized
//!   into canonical RFC 5952 lowercase representation without brackets in the `host` field.
//! - Path, query, fragment, and userinfo are excluded from origin matching.
//! - Userinfo in authority (`@`) fails closed.
//! - Percent-encoded authority delimiters (`%40`, `%3a`, `%3A`, `%2f`, `%2F`, `%3f`, `%3F`,
//!   `%23`, `%5c`, `%5C`, `%5b`, `%5B`, `%5d`, `%5D`) fail closed.
//! - Ports out of range (0 or >65535) or malformed fail closed.
//! - WebSocket destinations retain `ws` versus `wss` so the TLS boolean is derived only
//!   after canonicalization ([`CanonicalOrigin::is_tls`]) and is never the authorization identity.

#![forbid(unsafe_code)]

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Errors encountered while parsing a [`CanonicalOrigin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalOriginError {
    /// The input is empty or cannot be parsed as a URL.
    MalformedUrl,
    /// The scheme is not in the closed default-port table (`http`, `ws`, `https`, `wss`).
    UnsupportedScheme,
    /// The host component is missing or empty.
    MissingHost,
    /// The host is malformed (invalid IDNA domain or invalid IP literal).
    InvalidHost,
    /// The port is invalid (e.g. 0, >65535, or non-numeric).
    InvalidPort,
    /// The URL contains userinfo (`@`), which is disallowed.
    UserinfoDisallowed,
    /// The URL contains percent-encoded authority delimiters, which fail closed.
    PercentEncodedDelimiter,
}

impl fmt::Display for CanonicalOriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedUrl => write!(f, "malformed URL input"),
            Self::UnsupportedScheme => {
                write!(f, "unsupported scheme: must be http, https, ws, or wss")
            }
            Self::MissingHost => write!(f, "missing or empty host authority"),
            Self::InvalidHost => write!(f, "invalid host authority (IDNA or IP parse failure)"),
            Self::InvalidPort => write!(f, "invalid port: must be between 1 and 65535"),
            Self::UserinfoDisallowed => write!(f, "userinfo in authority is forbidden"),
            Self::PercentEncodedDelimiter => {
                write!(f, "percent-encoded authority delimiter is forbidden")
            }
        }
    }
}

impl std::error::Error for CanonicalOriginError {}

impl From<CanonicalOriginError> for bitty_network_api::NetworkError {
    fn from(_: CanonicalOriginError) -> Self {
        bitty_network_api::NetworkError::Offline
    }
}

/// The closed default-port lookup table.
///
/// | Scheme  | Default port |
/// | ------- | ------------ |
/// | `http`  | 80           |
/// | `ws`    | 80           |
/// | `https` | 443          |
/// | `wss`   | 443          |
#[must_use]
pub fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("ws") {
        Some(80)
    } else if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss") {
        Some(443)
    } else {
        None
    }
}

/// Check for percent-encoded authority delimiters in `s`.
fn has_percent_encoded_delimiter(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' {
            let hex = &bytes[i + 1..i + 3];
            if hex.eq_ignore_ascii_case(b"40") // @
                || hex.eq_ignore_ascii_case(b"3a") // :
                || hex.eq_ignore_ascii_case(b"2f") // /
                || hex.eq_ignore_ascii_case(b"3f") // ?
                || hex.eq_ignore_ascii_case(b"23") // #
                || hex.eq_ignore_ascii_case(b"5c") // \
                || hex.eq_ignore_ascii_case(b"5b") // [
                || hex.eq_ignore_ascii_case(b"5d")
            // ]
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// A parsed, normalized canonical origin.
///
/// Routing, authorization, pooling, redirect decisions, and `CONNECT` target
/// validation use this type containing exactly:
/// - a lowercase scheme;
/// - a canonically encoded ASCII host or IP literal; and
/// - an effective `u16` port.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalOrigin {
    scheme: String,
    host: String,
    port: u16,
}

impl CanonicalOrigin {
    /// Parse and normalize a URL into a [`CanonicalOrigin`].
    ///
    /// Fails closed on:
    /// - Malformed URL shapes
    /// - Schemes outside the closed default-port table (`http`, `ws`, `https`, `wss`)
    /// - Authorities containing credentials / userinfo (`@`)
    /// - Authorities containing percent-encoded delimiters
    /// - Invalid / unparseable IP literals or malformed domain names
    /// - Port numbers outside 1..=65535
    pub fn parse(input: &str) -> Result<Self, CanonicalOriginError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(CanonicalOriginError::MalformedUrl);
        }

        let (raw_scheme, after_scheme) = input
            .split_once("://")
            .ok_or(CanonicalOriginError::MalformedUrl)?;

        if raw_scheme.is_empty()
            || !raw_scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return Err(CanonicalOriginError::UnsupportedScheme);
        }

        let scheme = raw_scheme.to_ascii_lowercase();
        let default_port =
            default_port_for_scheme(&scheme).ok_or(CanonicalOriginError::UnsupportedScheme)?;

        // The authority component ends at the first '/', '?', or '#'
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme);

        if authority.is_empty() {
            return Err(CanonicalOriginError::MissingHost);
        }

        if authority.contains('@') {
            return Err(CanonicalOriginError::UserinfoDisallowed);
        }

        if has_percent_encoded_delimiter(authority) {
            return Err(CanonicalOriginError::PercentEncodedDelimiter);
        }

        if authority.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(CanonicalOriginError::MalformedUrl);
        }

        let (raw_host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (ipv6_str, suffix) = bracketed
                .split_once(']')
                .ok_or(CanonicalOriginError::InvalidHost)?;

            let port = match suffix {
                "" => default_port,
                _ => {
                    let port_str = suffix
                        .strip_prefix(':')
                        .ok_or(CanonicalOriginError::InvalidPort)?;
                    parse_port(port_str)?
                }
            };

            (ipv6_str, port)
        } else {
            if authority.contains('[') || authority.contains(']') {
                return Err(CanonicalOriginError::InvalidHost);
            }

            if authority.matches(':').count() > 1 {
                return Err(CanonicalOriginError::InvalidHost);
            }

            if let Some((host_part, port_part)) = authority.split_once(':') {
                let port = parse_port(port_part)?;
                (host_part, port)
            } else {
                (authority, default_port)
            }
        };

        if raw_host.is_empty() {
            return Err(CanonicalOriginError::MissingHost);
        }

        let canonical_host = if let Ok(ipv6) = raw_host.parse::<Ipv6Addr>() {
            ipv6.to_string()
        } else if let Ok(ipv4) = raw_host.parse::<Ipv4Addr>() {
            ipv4.to_string()
        } else {
            if raw_host
                .chars()
                .any(|c| c == ':' || c == '/' || c == '\\' || c == '?' || c == '#')
            {
                return Err(CanonicalOriginError::InvalidHost);
            }
            normalize_domain(raw_host)?
        };

        Ok(Self {
            scheme,
            host: canonical_host,
            port,
        })
    }

    /// Lowercase scheme (`http`, `https`, `ws`, or `wss`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Canonically encoded ASCII host or IP literal.
    ///
    /// IPv6 literals are in standard lowercase compressed RFC 5952 representation without brackets.
    /// DNS hostnames are converted through IDNA into Punycode and lowercased.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Effective destination port (`u16`).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Scheme default port from the closed default-port table.
    #[must_use]
    pub fn default_port(&self) -> u16 {
        default_port_for_scheme(&self.scheme).unwrap_or(self.port)
    }

    /// True when the effective port equals the scheme's default port.
    #[must_use]
    pub fn is_default_port(&self) -> bool {
        self.port == self.default_port()
    }

    /// True if the scheme uses TLS (`https` or `wss`).
    ///
    /// The TLS boolean is derived only after canonicalization and is never
    /// the authorization identity.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.scheme == "https" || self.scheme == "wss"
    }

    /// Format authority for Host header and CONNECT target.
    ///
    /// IPv6 hosts are enclosed in brackets: `[::1]:443`.
    /// IPv4 and domain names are formatted as: `example.com:443`.
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Debug for CanonicalOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalOrigin")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

impl fmt::Display for CanonicalOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.authority())
    }
}

impl FromStr for CanonicalOrigin {
    type Err = CanonicalOriginError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn parse_port(s: &str) -> Result<u16, CanonicalOriginError> {
    if s.is_empty() {
        return Err(CanonicalOriginError::InvalidPort);
    }
    if !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(CanonicalOriginError::InvalidPort);
    }
    let port = s
        .parse::<u16>()
        .map_err(|_| CanonicalOriginError::InvalidPort)?;
    if port == 0 {
        return Err(CanonicalOriginError::InvalidPort);
    }
    Ok(port)
}

fn normalize_domain(domain: &str) -> Result<String, CanonicalOriginError> {
    // Trim any trailing dot for FQDN normalization
    let domain_trimmed = domain.strip_suffix('.').unwrap_or(domain);
    if domain_trimmed.is_empty() {
        return Err(CanonicalOriginError::MissingHost);
    }
    match idna::domain_to_ascii(domain_trimmed) {
        Ok(ascii) => {
            if ascii.is_empty() {
                return Err(CanonicalOriginError::MissingHost);
            }
            Ok(ascii)
        }
        Err(_) => Err(CanonicalOriginError::InvalidHost),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_proxy_absent_port_is_80() {
        let origin = CanonicalOrigin::parse("http://proxy.example.com").expect("parse http proxy");
        assert_eq!(origin.scheme(), "http");
        assert_eq!(origin.host(), "proxy.example.com");
        assert_eq!(origin.port(), 80);
        assert!(origin.is_default_port());
        assert!(!origin.is_tls());
    }

    #[test]
    fn https_proxy_absent_port_is_443() {
        let origin =
            CanonicalOrigin::parse("https://proxy.example.com").expect("parse https proxy");
        assert_eq!(origin.scheme(), "https");
        assert_eq!(origin.host(), "proxy.example.com");
        assert_eq!(origin.port(), 443);
        assert!(origin.is_default_port());
        assert!(origin.is_tls());
    }

    #[test]
    fn explicit_default_ports_equal_absent_ones() {
        assert_eq!(
            CanonicalOrigin::parse("http://example.com").unwrap(),
            CanonicalOrigin::parse("http://example.com:80").unwrap()
        );
        assert_eq!(
            CanonicalOrigin::parse("https://example.com").unwrap(),
            CanonicalOrigin::parse("https://example.com:443").unwrap()
        );
        assert_eq!(
            CanonicalOrigin::parse("ws://example.com").unwrap(),
            CanonicalOrigin::parse("ws://example.com:80").unwrap()
        );
        assert_eq!(
            CanonicalOrigin::parse("wss://example.com").unwrap(),
            CanonicalOrigin::parse("wss://example.com:443").unwrap()
        );
    }

    #[test]
    fn all_four_destination_schemes_across_port_variants() {
        let cases = [
            ("http://example.com", "http", "example.com", 80, false),
            ("http://example.com:80", "http", "example.com", 80, false),
            (
                "http://example.com:8080",
                "http",
                "example.com",
                8080,
                false,
            ),
            ("https://example.com", "https", "example.com", 443, true),
            ("https://example.com:443", "https", "example.com", 443, true),
            (
                "https://example.com:8443",
                "https",
                "example.com",
                8443,
                true,
            ),
            ("ws://example.com", "ws", "example.com", 80, false),
            ("ws://example.com:80", "ws", "example.com", 80, false),
            ("ws://example.com:8080", "ws", "example.com", 8080, false),
            ("wss://example.com", "wss", "example.com", 443, true),
            ("wss://example.com:443", "wss", "example.com", 443, true),
            ("wss://example.com:8443", "wss", "example.com", 8443, true),
        ];

        for (input, scheme, host, port, is_tls) in cases {
            let origin = CanonicalOrigin::parse(input).expect(input);
            assert_eq!(origin.scheme(), scheme, "scheme mismatch for {input}");
            assert_eq!(origin.host(), host, "host mismatch for {input}");
            assert_eq!(origin.port(), port, "port mismatch for {input}");
            assert_eq!(origin.is_tls(), is_tls, "tls mismatch for {input}");
        }
    }

    #[test]
    fn mixed_case_scheme_and_host() {
        let mixed = CanonicalOrigin::parse("HtTpS://ExAmPlE.cOm:443/Path?Query#Frag").unwrap();
        let canonical = CanonicalOrigin::parse("https://example.com:443").unwrap();
        assert_eq!(mixed, canonical);
        assert_eq!(mixed.scheme(), "https");
        assert_eq!(mixed.host(), "example.com");
    }

    #[test]
    fn equivalent_unicode_and_idna_host_forms() {
        let unicode = CanonicalOrigin::parse("https://bücher.example/").unwrap();
        let punycode = CanonicalOrigin::parse("https://xn--bcher-kva.example/").unwrap();
        assert_eq!(unicode, punycode);
        assert_eq!(unicode.host(), "xn--bcher-kva.example");
    }

    #[test]
    fn ipv4_normalization() {
        let origin = CanonicalOrigin::parse("http://127.0.0.1:80/path").unwrap();
        assert_eq!(origin.host(), "127.0.0.1");
        assert_eq!(origin.port(), 80);
        assert_eq!(origin, CanonicalOrigin::parse("http://127.0.0.1").unwrap());
    }

    #[test]
    fn ipv6_normalization() {
        let expanded =
            CanonicalOrigin::parse("https://[2001:0db8:0000:0000:0000:0000:0000:0001]:443")
                .unwrap();
        let compressed = CanonicalOrigin::parse("https://[2001:db8::1]").unwrap();
        assert_eq!(expanded, compressed);
        assert_eq!(compressed.host(), "2001:db8::1");
        assert_eq!(compressed.authority(), "[2001:db8::1]:443");
    }

    #[test]
    fn percent_encoded_authority_delimiters_fail_closed() {
        let bad = [
            "http://user%40example.com/",
            "http://example.com%3a80/",
            "http://example%2fcom/",
            "http://example%3fcom/",
            "http://example%23com/",
            "http://example%5ccom/",
            "http://%5b::1%5d/",
        ];
        for url in bad {
            assert_eq!(
                CanonicalOrigin::parse(url),
                Err(CanonicalOriginError::PercentEncodedDelimiter),
                "must fail closed on {url}"
            );
        }
    }

    #[test]
    fn websocket_retains_ws_versus_wss() {
        let ws = CanonicalOrigin::parse("ws://example.com").unwrap();
        let wss = CanonicalOrigin::parse("wss://example.com").unwrap();
        assert_ne!(ws, wss);
        assert_eq!(ws.scheme(), "ws");
        assert_eq!(wss.scheme(), "wss");
        assert!(!ws.is_tls());
        assert!(wss.is_tls());
    }

    #[test]
    fn userinfo_fails_closed() {
        assert_eq!(
            CanonicalOrigin::parse("http://user:pass@example.com/"),
            Err(CanonicalOriginError::UserinfoDisallowed)
        );
        assert_eq!(
            CanonicalOrigin::parse("http://user@example.com/"),
            Err(CanonicalOriginError::UserinfoDisallowed)
        );
    }

    #[test]
    fn invalid_schemes_fail_closed() {
        assert_eq!(
            CanonicalOrigin::parse("ftp://example.com"),
            Err(CanonicalOriginError::UnsupportedScheme)
        );
        assert_eq!(
            CanonicalOrigin::parse("file:///etc/passwd"),
            Err(CanonicalOriginError::UnsupportedScheme)
        );
    }

    #[test]
    fn invalid_ports_fail_closed() {
        assert_eq!(
            CanonicalOrigin::parse("http://example.com:0"),
            Err(CanonicalOriginError::InvalidPort)
        );
        assert_eq!(
            CanonicalOrigin::parse("http://example.com:65536"),
            Err(CanonicalOriginError::InvalidPort)
        );
        assert_eq!(
            CanonicalOrigin::parse("http://example.com:bad"),
            Err(CanonicalOriginError::InvalidPort)
        );
    }

    #[test]
    fn path_query_fragment_excluded() {
        let with_tail =
            CanonicalOrigin::parse("http://example.com:8080/foo/bar?baz=1#hash").unwrap();
        let bare = CanonicalOrigin::parse("http://example.com:8080").unwrap();
        assert_eq!(with_tail, bare);
        assert_eq!(with_tail.authority(), "example.com:8080");
        assert_eq!(with_tail.to_string(), "http://example.com:8080");
    }
}
