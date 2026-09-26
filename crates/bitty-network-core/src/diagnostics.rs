//! Redacted diagnostics: safe snapshots for logs and errors.
//!
//! Raw request/response/proxy data must never appear in ordinary `Debug` or
//! error output: header values carry credentials, bodies carry content,
//! URLs carry userinfo and secret-bearing queries, and control-plane
//! authorities (proxy `CONNECT` lines) echo operator infrastructure. The
//! snapshots here redact at *construction* — the secret never reaches the
//! struct, so no later `Debug` can leak it — while keeping correlation data:
//! methods, statuses, schemes, hosts, ports, paths, header names and counts,
//! body lengths, and deadlines.
//!
//! Wiring these snapshots into the backends' error paths (typed errors that
//! today echo raw domains, bodies, or proxy URLs) is a follow-up merge; the
//! vocabulary crates those errors live in are outside this lane's scope.
//!
//! Redaction rules, in one place:
//!
//! * [`redacted_url`]: keeps `scheme://host:port/path`, drops userinfo,
//!   queries, and fragments; control-bearing hosts become
//!   [`INVALID_HOST`], unparseable URLs become [`REDACTED_URL_VALUE`].
//! * [`redacted_headers`]: keeps header names in order, replaces every value
//!   with [`REDACTED`]. Values are redacted unconditionally (fail closed):
//!   even innocuous-looking headers can carry secrets.
//! * [`summarize_body`]: length only, never content.
//! * [`connect_authority`]: a `host:port` line safe for `CONNECT` logging.

use std::fmt;
use std::time::Duration;

/// Placeholder replacing any redacted value.
pub const REDACTED: &str = "[redacted]";

/// Placeholder for hosts carrying userinfo residue, control bytes, or
/// delimiter shapes (anything outside the safe host alphabet).
pub const INVALID_HOST: &str = "[invalid-host]";

/// Placeholder for URLs with no parseable `scheme://authority` shape.
pub const REDACTED_URL_VALUE: &str = "[redacted-url]";

/// Redact `url` to `scheme://host:port/path`, dropping userinfo, query, and
/// fragment.
///
/// The host passes through [`safe_host`], the port is kept only when it is
/// all digits, and the path is kept up to (not including) any `?` or `#`.
/// Anything without a `scheme://authority` shape becomes
/// [`REDACTED_URL_VALUE`]. Proxy URLs redact the same way (their userinfo is
/// credentials, never correlation data).
#[must_use]
pub fn redacted_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some(parts) => parts,
        None => return REDACTED_URL_VALUE.to_owned(),
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return REDACTED_URL_VALUE.to_owned();
    }
    let hostport = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let (host, port) = split_host_port(hostport);
    let safe = safe_host(host);
    let mut redacted = format!("{scheme}://");
    if safe.contains(':') {
        redacted.push('[');
        redacted.push_str(safe);
        redacted.push(']');
    } else {
        redacted.push_str(safe);
    }
    if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
        redacted.push(':');
        redacted.push_str(port);
    }
    redacted.push_str(clean_path(path));
    redacted
}

/// Split one authority tail into host and port, honoring IPv6 brackets.
///
/// Returns `(host, port)` with the port empty when absent; userinfo must
/// already be stripped.
fn split_host_port(hostport: &str) -> (&str, &str) {
    if let Some(bracketed) = hostport.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((host, tail)) => {
                let port = tail.strip_prefix(':').unwrap_or("");
                (host, port)
            }
            None => (bracketed, ""),
        }
    } else {
        match hostport.split_once(':') {
            Some((host, port)) => (host, port),
            None => (hostport, ""),
        }
    }
}

/// Keep the path up to (not including) any query or fragment marker.
fn clean_path(path: &str) -> &str {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    path.split_at(end).0
}

/// Render `host` for diagnostics, or [`INVALID_HOST`] when it is
/// control-bearing.
///
/// Safe hosts are non-empty ASCII of letters, digits, and `-._~%:` plus
/// IPv6 brackets. Anything else — userinfo residue (`@`), whitespace or
/// control bytes (header-injection shapes), path or query delimiters,
/// non-ASCII — is not correlation data and becomes [`INVALID_HOST`].
#[must_use]
pub fn safe_host(host: &str) -> &str {
    if host.is_empty() {
        return INVALID_HOST;
    }
    let safe = host.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'%' | b':' | b'[' | b']')
    });
    if safe { host } else { INVALID_HOST }
}

/// Redact one header list: names kept in order, every value replaced with
/// [`REDACTED`].
#[must_use]
pub fn redacted_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, _)| (name.clone(), REDACTED.to_owned()))
        .collect()
}

/// Summarize one body for diagnostics: length only, never content.
#[must_use]
pub fn summarize_body(len: usize) -> String {
    format!("body[{len} bytes]")
}

/// Render one `CONNECT` authority (`host:port`) safe for control-plane logs.
///
/// The host passes through [`safe_host`]; the port always renders (it is a
/// number, never a secret).
#[must_use]
pub fn connect_authority(host: &str, port: u16) -> String {
    format!("{}:{port}", safe_host(host))
}

/// Redacted snapshot of one outgoing request, for logs and errors.
///
/// Built redacted: [`DiagnosticRequest::new`] strips secrets before storing,
/// so formatting this value can never leak them.
#[derive(Clone, PartialEq, Eq)]
pub struct DiagnosticRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body_len: usize,
    timeout_ms: u64,
}

impl DiagnosticRequest {
    /// Snapshot `method` + `url` + `headers` + body length + deadline.
    ///
    /// The URL is stored via [`redacted_url`], header values via
    /// [`redacted_headers`], and only the body length is kept. A missing
    /// deadline (`None`) records as zero milliseconds.
    #[must_use]
    pub fn new(
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body_len: usize,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            method: method.to_owned(),
            url: redacted_url(url),
            headers: redacted_headers(headers),
            body_len,
            timeout_ms: timeout.map(|deadline| deadline.as_millis()).unwrap_or(0) as u64,
        }
    }
}

impl fmt::Debug for DiagnosticRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body", &summarize_body(self.body_len))
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

/// Redacted snapshot of one incoming response, for logs and errors.
///
/// Built redacted, like [`DiagnosticRequest`]: only the status, header
/// names, and body length are kept.
#[derive(Clone, PartialEq, Eq)]
pub struct DiagnosticResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body_len: usize,
}

impl DiagnosticResponse {
    /// Snapshot `status` + `headers` + body length.
    #[must_use]
    pub fn new(status: u16, headers: &[(String, String)], body_len: usize) -> Self {
        Self {
            status,
            headers: redacted_headers(headers),
            body_len,
        }
    }
}

impl fmt::Debug for DiagnosticResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiagnosticResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &summarize_body(self.body_len))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic non-secret sentinels: shaped like secrets so a leak is
    /// unmistakable, but minted for tests only.
    const SENTINEL_PASSWORD: &str = "SENTINEL-password-0001";
    const SENTINEL_TOKEN: &str = "SENTINEL-token-0002";
    const SENTINEL_HEADER: &str = "SENTINEL-header-0003";
    const SENTINEL_BODY_MARK: &str = "SENTINEL-body-0004";

    fn sentinel_headers() -> Vec<(String, String)> {
        vec![
            (
                "Authorization".to_owned(),
                format!("Bearer {SENTINEL_HEADER}"),
            ),
            ("Cookie".to_owned(), format!("session={SENTINEL_HEADER}")),
            ("X-Custom".to_owned(), "plain-value".to_owned()),
        ]
    }

    #[test]
    fn url_table_redacts_without_losing_correlation() {
        let cases = [
            (
                "https://snapshot-user:SENTINEL-password-0001@example.com:443/path",
                "https://example.com:443/path",
            ),
            (
                "https://example.com/path?token=SENTINEL-token-0002&next=1#frag",
                "https://example.com/path",
            ),
            ("http://user@example.com:8080/", "http://example.com:8080/"),
            ("wss://[::1]:9000/socket", "wss://[::1]:9000/socket"),
            ("https://example.com", "https://example.com"),
            ("https://example.com:notaport/x", "https://example.com/x"),
            ("not-a-url", "[redacted-url]"),
            ("", "[redacted-url]"),
            ("https:///no-authority", "[redacted-url]"),
        ];
        for (raw, expected) in cases {
            assert_eq!(redacted_url(raw), expected, "url: {raw}");
        }
    }

    #[test]
    fn control_bearing_hosts_become_invalid() {
        for hostile in [
            "exa mple.com",
            "example.com\r\nX-Injected: 1",
            "user@host",
            "example.com/path",
            "example.com?q=1",
            "exämple.com",
            "",
        ] {
            assert_eq!(safe_host(hostile), INVALID_HOST, "host: {hostile:?}");
        }
        assert_eq!(safe_host("example.com"), "example.com");
        assert_eq!(safe_host("::1"), "::1");
        assert_eq!(safe_host("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn headers_keep_names_drop_values() {
        let redacted = redacted_headers(&sentinel_headers());
        assert_eq!(
            redacted,
            vec![
                ("Authorization".to_owned(), REDACTED.to_owned()),
                ("Cookie".to_owned(), REDACTED.to_owned()),
                ("X-Custom".to_owned(), REDACTED.to_owned()),
            ]
        );
        assert!(redacted_headers(&[]).is_empty());
    }

    #[test]
    fn connect_authority_sanitizes_the_host() {
        assert_eq!(connect_authority("example.com", 443), "example.com:443");
        assert_eq!(connect_authority("bad\nhost", 443), "[invalid-host]:443");
    }

    #[test]
    fn request_debug_hides_secrets_keeps_correlation() {
        let url = format!(
            "https://snapshot-user:{SENTINEL_PASSWORD}@example.com:443/path?token={SENTINEL_TOKEN}"
        );
        let snapshot = DiagnosticRequest::new(
            "POST",
            &url,
            &sentinel_headers(),
            SENTINEL_BODY_MARK.len(),
            Some(Duration::from_secs(2)),
        );
        let shown = format!("{snapshot:?}");
        assert!(!shown.contains("SENTINEL"), "leak: {shown}");
        for correlation in [
            "POST",
            "example.com",
            "443",
            "/path",
            "Authorization",
            "Cookie",
            "body[18 bytes]",
            "2000",
        ] {
            assert!(
                shown.contains(correlation),
                "missing {correlation}: {shown}"
            );
        }
    }

    #[test]
    fn response_debug_hides_secrets_keeps_correlation() {
        let snapshot = DiagnosticResponse::new(200, &sentinel_headers(), 128);
        let shown = format!("{snapshot:?}");
        assert!(!shown.contains("SENTINEL"), "leak: {shown}");
        for correlation in ["200", "Authorization", "body[128 bytes]"] {
            assert!(
                shown.contains(correlation),
                "missing {correlation}: {shown}"
            );
        }
    }

    #[test]
    fn placeholders_are_stable() {
        assert_eq!(REDACTED, "[redacted]");
        assert_eq!(INVALID_HOST, "[invalid-host]");
        assert_eq!(REDACTED_URL_VALUE, "[redacted-url]");
        assert_eq!(summarize_body(0), "body[0 bytes]");
    }
}
