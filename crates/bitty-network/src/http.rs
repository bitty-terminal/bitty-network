//! Embedded HTTP backend: the first real transport behind [`NetworkService`].
//!
//! [`HttpNetworkService`] serves the trait with a single shared reqwest
//! blocking client: one client per service instance, reused across requests
//! so connections pool instead of being re-established per call. The client
//! is built once (proxy resolved from the environment at construction) and
//! every request flows through it.
//!
//! Request path, in order:
//!
//! 1. Capability first: [`NetworkCapability::check`] on [`Request::host`]
//!    runs before the client, the URL, or any socket is touched. Deny-all
//!    yields [`NetworkError::Offline`], an allowlist miss yields the typed
//!    [`NetworkError::Denied`], and nothing is sent in either case.
//! 2. The request is translated (method, URL, headers, body) and sent with
//!    the per-request deadline ([`Request::timeout`]) or
//!    [`DEFAULT_REQUEST_TIMEOUT`] when the caller sets none.
//! 3. Failures are typed: an expired deadline becomes
//!    [`NetworkError::Timeout`]; any other post-capability failure (refused
//!    connection, unparseable header, truncated body) fails closed as
//!    [`NetworkError::Offline`] — the backend cannot vouch for reachability,
//!    so it reports unreachable. A richer transport taxonomy is follow-up
//!    scope.
//!
//! Proxy: inherited from the environment, never from code. `HTTPS_PROXY` (or
//! lowercase `https_proxy`) names the proxy; `NO_PROXY` (or lowercase
//! `no_proxy`) lists bypassed hosts (exact match, case-insensitive; a
//! leading-dot entry matches subdomains; `*` bypasses everything). With no
//! proxy configured the backend sends directly — proxy-off default. An
//! unparseable proxy URL is ignored (direct egress, still
//! capability-gated), so operators must use valid URLs. Use
//! [`HttpNetworkService::with_proxy`] to pin an explicit proxy URL instead
//! (deterministic override for tests and operators).
//!
//! Timeouts: [`DEFAULT_REQUEST_TIMEOUT`] bounds every request unless the
//! caller overrides it per request. An expired deadline always surfaces
//! [`NetworkError::Timeout`], including when the proxy or the origin stalls.
//!
//! Budgets: [`Request::max_body_bytes`] caps the response body when the
//! caller sets one. The backend checks the declared `Content-Length` first
//! (no body bytes are read when it already exceeds the cap) and then streams
//! the body through a capped sink, so an over-long body fails closed with
//! [`NetworkError::Budget`] instead of being buffered or truncated. With no
//! cap set the body is read whole, as before. WebSocket message budgets are
//! follow-up scope.
//!
//! [`Request::max_body_bytes`]: bitty_network_api::Request::max_body_bytes
//! [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget
//!
//! Out of scope (issue #4): TLS custom CA (rustls platform verifier trusts
//! the native root store as-is) and pooling tuning (reqwest defaults).
//! WebSocket ([`NetworkService::websocket`]) stays fail-closed here unless
//! the `websocket` feature is enabled: without it, capability misses surface
//! the typed denial and allowlist hits yield [`NetworkError::Offline`]
//! because there is no upgrade path. With `websocket` enabled the handshake
//! runs through `crate::websocket` (capability-first, proxy decision
//! reused from this backend, rustls native roots) and returns an open
//! `WebSocketSocket`.
//!
//! [`NetworkService`]: bitty_network_api::NetworkService
//! [`NetworkCapability::check`]: bitty_network_api::NetworkCapability::check
//! [`Request::host`]: bitty_network_api::Request::host
//! [`Request::timeout`]: bitty_network_api::Request::timeout
//! [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
//! [`NetworkError::Denied`]: bitty_network_api::NetworkError::Denied
//! [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
//!
//! # Example
//!
//! ```no_run
//! use bitty_network::{HttpNetworkService, NetworkCapability, NetworkService, Request};
//!
//! let service = HttpNetworkService::new(
//!     NetworkCapability::offline().with_domain("example.com"),
//! );
//! // Capability misses never touch the network:
//! assert!(service.request(&Request::get("https://other.example/")).is_err());
//! ```

use std::io::Write;
use std::time::Duration;

use bitty_network_api::{
    HttpMethod, NetworkCapability, NetworkError, NetworkService, Request, Response,
    WebSocketRequest,
};
use reqwest::header::{HeaderName, HeaderValue};

/// Only the fail-closed `websocket()` (without the `websocket` feature)
/// resolves to the offline socket; with the feature the socket comes from
/// `crate::websocket`.
#[cfg(not(feature = "websocket"))]
use crate::offline::OfflineSocket;

/// Default per-request deadline when the caller sets no [`Request::timeout`].
///
/// Thirty seconds is generous for an embedded client that mostly polls small
/// payloads; interactive callers should still set tighter per-request
/// deadlines via [`Request::with_timeout`].
///
/// [`Request::with_timeout`]: bitty_network_api::Request::with_timeout
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Environment variables naming the HTTPS proxy, in precedence order.
const HTTPS_PROXY_VARS: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];

/// Environment variables listing proxy-bypassed hosts, in precedence order.
///
/// Both casings are honored; values are comma-joined when both are set.
const NO_PROXY_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// Embedded HTTP [`NetworkService`] over shared reqwest blocking clients.
///
/// Holds the caller's [`NetworkCapability`] and the egress clients built at
/// construction: one direct client plus, when the environment (or
/// [`HttpNetworkService::with_proxy`]) names a proxy, one proxied client.
/// Both are shared across requests (connection pools), and the per-request
/// proxy decision follows the environment bypass list. The default is
/// deny-all with proxy-off; see the [module docs](self) for the request path.
///
/// [`NetworkService`]: bitty_network_api::NetworkService
#[derive(Debug, Clone)]
pub struct HttpNetworkService {
    capability: NetworkCapability,
    egress: Egress,
}

/// Egress clients behind one service: direct always, proxied when configured.
///
/// The proxy URL and bypass list are snapshotted at construction so the
/// per-request decision is a pure function of the request host (see
/// [`select_proxy`]).
#[derive(Debug, Clone)]
struct Egress {
    direct: reqwest::blocking::Client,
    via_proxy: Option<reqwest::blocking::Client>,
    https_proxy: Option<String>,
    no_proxy: String,
}

impl HttpNetworkService {
    /// Serve HTTP under `capability`, proxy inherited from the environment.
    ///
    /// Reads `HTTPS_PROXY`/`https_proxy` and `NO_PROXY`/`no_proxy` once; an
    /// absent or unparseable proxy URL means direct egress (proxy-off
    /// default). Construction performs no I/O.
    #[must_use]
    pub fn new(capability: NetworkCapability) -> Self {
        let https_proxy = https_proxy_from_env();
        let no_proxy = no_proxy_from_env();
        let via_proxy = match https_proxy.as_deref() {
            Some(url) => proxy_client(url),
            None => None,
        };
        // An unparseable environment proxy must not route half-proxied: drop
        // it so the bypass decision below stays direct-only.
        let https_proxy = match via_proxy {
            Some(_) => https_proxy,
            None => None,
        };
        Self {
            capability,
            egress: Egress {
                direct: Self::client_with(None),
                via_proxy,
                https_proxy,
                no_proxy,
            },
        }
    }

    /// Serve HTTP under `capability` via one explicit proxy URL.
    ///
    /// Deterministic override for tests and operators: `proxy_url` replaces
    /// whatever the environment says (pass-through when the environment must
    /// win goes through [`HttpNetworkService::new`]). Returns
    /// [`NetworkError::Offline`] when `proxy_url` does not parse — fail
    /// closed, never half-proxied.
    pub fn with_proxy(
        capability: NetworkCapability,
        proxy_url: &str,
    ) -> Result<Self, NetworkError> {
        match proxy_client(proxy_url) {
            Some(via_proxy) => Ok(Self {
                capability,
                egress: Egress {
                    direct: Self::client_with(None),
                    via_proxy: Some(via_proxy),
                    https_proxy: Some(proxy_url.to_owned()),
                    no_proxy: String::new(),
                },
            }),
            None => Err(NetworkError::Offline),
        }
    }

    /// The capability this backend enforces (checked before every send).
    #[must_use]
    pub fn capability(&self) -> &NetworkCapability {
        &self.capability
    }

    /// Build one shared client around `proxy` (`None` for direct egress).
    ///
    /// The builder only fails on contradictory configuration, which the
    /// single-proxy construction above cannot produce; a direct client keeps
    /// the path infallible and fail-closed either way.
    fn client_with(proxy: Option<reqwest::Proxy>) -> reqwest::blocking::Client {
        let mut builder = reqwest::blocking::Client::builder();
        if let Some(proxy) = proxy {
            builder = builder.proxy(proxy);
        }
        match builder.build() {
            Ok(client) => client,
            Err(_) => reqwest::blocking::Client::new(),
        }
    }

    /// Pick the egress client for `host`: proxied when a proxy is configured
    /// and the host is not bypassed, direct otherwise.
    fn client_for(&self, host: &str) -> &reqwest::blocking::Client {
        match self.egress.via_proxy.as_ref() {
            Some(proxied) => {
                match select_proxy(
                    self.egress.https_proxy.as_deref(),
                    &self.egress.no_proxy,
                    host,
                ) {
                    Some(_) => proxied,
                    None => &self.egress.direct,
                }
            }
            None => &self.egress.direct,
        }
    }

    /// The proxy URL selected for `host`, if any: the configured proxy that
    /// is not bypassed for this host. Mirrors the per-request egress choice
    /// in [`client_for`](Self::client_for) so the WebSocket handshake tunnels
    /// through exactly the proxy a plain request would use.
    ///
    /// Only available with the `websocket` feature; the handshake path in
    /// `crate::websocket` consumes it.
    #[cfg(feature = "websocket")]
    pub(crate) fn proxy_url_for(&self, host: &str) -> Option<String> {
        match self.egress.via_proxy.as_ref() {
            Some(_) => select_proxy(
                self.egress.https_proxy.as_deref(),
                &self.egress.no_proxy,
                host,
            ),
            None => None,
        }
    }

    /// Capability-first rejection for `domain` (mirrors the offline backend).
    ///
    /// Only used by the fail-closed `websocket()` without the `websocket`
    /// feature; with the feature the capability check runs inline.
    #[cfg(not(feature = "websocket"))]
    fn reject(&self, domain: &str) -> NetworkError {
        match self.capability.check(domain) {
            Ok(()) => NetworkError::Offline,
            Err(error) => error,
        }
    }

    /// Translate one vocabulary request through the shared client.
    fn send(&self, request: &Request) -> Result<Response, NetworkError> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
            HttpMethod::Patch => reqwest::Method::PATCH,
        };
        let timeout = request.timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT);
        let mut outgoing = self
            .client_for(request.host())
            .request(method, request.url.clone())
            .timeout(timeout);
        for (name, value) in &request.headers {
            let name = match HeaderName::from_bytes(name.as_bytes()) {
                Ok(name) => name,
                Err(_) => return Err(NetworkError::Offline),
            };
            let value = match HeaderValue::from_str(value) {
                Ok(value) => value,
                Err(_) => return Err(NetworkError::Offline),
            };
            outgoing = outgoing.header(name, value);
        }
        if !request.body.is_empty() {
            outgoing = outgoing.body(request.body.clone());
        }
        let incoming = match outgoing.send() {
            Ok(incoming) => incoming,
            Err(error) => return Err(classify_transport(&error, timeout)),
        };
        let status = incoming.status().as_u16();
        let mut headers = Vec::new();
        for (name, value) in incoming.headers() {
            match value.to_str() {
                Ok(value) => headers.push((name.as_str().to_owned(), value.to_owned())),
                Err(_) => return Err(NetworkError::Offline),
            }
        }
        match read_capped(incoming, request.max_body_bytes, timeout) {
            Ok(body) => Ok(Response {
                status,
                headers,
                body,
            }),
            Err(error) => Err(error),
        }
    }
}

/// Read one response body, enforcing the caller's byte budget.
///
/// With `limit` set, a declared `Content-Length` above the cap fails closed
/// before any body byte is read, and the streamed copy below stops at the
/// same [`NetworkError::Budget`] instead of buffering past it (nothing is
/// truncated: the error replaces the whole body). Read failures keep the
/// [`classify_transport`] mapping (expired deadlines surface the effective
/// `after` deadline).
///
/// [`classify_transport`]: classify_transport
fn read_capped(
    mut incoming: reqwest::blocking::Response,
    limit: Option<u64>,
    after: Duration,
) -> Result<Vec<u8>, NetworkError> {
    let Some(limit) = limit else {
        return match incoming.bytes() {
            Ok(body) => Ok(body.to_vec()),
            Err(error) => Err(classify_transport(&error, after)),
        };
    };
    if let Some(declared) = incoming.content_length() {
        if declared > limit {
            return Err(NetworkError::Budget { limit_bytes: limit });
        }
    }
    let mut capped = CappedBody::new(limit);
    match incoming.copy_to(&mut capped) {
        Ok(_) => Ok(capped.body),
        Err(error) => {
            if capped.exceeded {
                Err(NetworkError::Budget { limit_bytes: limit })
            } else {
                Err(classify_transport(&error, after))
            }
        }
    }
}

/// [`std::io::Write`] sink that refuses bytes past its budget.
///
/// [`read_capped`] streams the response through this sink so an over-long
/// body fails closed: the first chunk that would cross `limit` flips
/// `exceeded` and aborts the copy instead of buffering or truncating.
struct CappedBody {
    body: Vec<u8>,
    limit: u64,
    exceeded: bool,
}

impl CappedBody {
    fn new(limit: u64) -> Self {
        Self {
            body: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for CappedBody {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next = self.body.len() as u64 + buf.len() as u64;
        if next > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::QuotaExceeded,
                "response body exceeds budget",
            ));
        }
        self.body.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Default for HttpNetworkService {
    /// Deny-all backend with environment proxy resolution.
    fn default() -> Self {
        Self::new(NetworkCapability::offline())
    }
}

impl NetworkService for HttpNetworkService {
    #[cfg(feature = "websocket")]
    type Socket = crate::websocket::WebSocketSocket;
    #[cfg(not(feature = "websocket"))]
    type Socket = OfflineSocket;

    fn request(&self, request: &Request) -> Result<Response, NetworkError> {
        self.capability.check(request.host())?;
        self.send(request)
    }

    /// Capability-gated handshake: without the `websocket` feature this
    /// stays fail-closed (offline on allowlist hits, typed denial
    /// otherwise); with the feature an allowed host performs the handshake
    /// in `crate::websocket` and returns the open socket.
    #[cfg(feature = "websocket")]
    fn websocket(&self, request: &WebSocketRequest) -> Result<Self::Socket, NetworkError> {
        self.capability.check(request.host())?;
        crate::websocket::connect(request, self.proxy_url_for(request.host()).as_deref())
    }

    #[cfg(not(feature = "websocket"))]
    fn websocket(&self, request: &WebSocketRequest) -> Result<Self::Socket, NetworkError> {
        Err(self.reject(request.host()))
    }
}

/// Build one proxied shared client for `url`, or `None` when it does not parse.
fn proxy_client(url: &str) -> Option<reqwest::blocking::Client> {
    match reqwest::Proxy::all(url) {
        Ok(proxy) => reqwest::blocking::Client::builder()
            .proxy(proxy)
            .build()
            .ok(),
        Err(_) => None,
    }
}

/// Map a post-capability transport failure to its typed error.
///
/// Expired deadlines become [`NetworkError::Timeout`] carrying the effective
/// deadline (`after`); everything else fails closed as
/// [`NetworkError::Offline`].
fn classify_transport(error: &reqwest::Error, after: Duration) -> NetworkError {
    if error.is_timeout() {
        NetworkError::Timeout { after }
    } else {
        NetworkError::Offline
    }
}

/// Proxy URL from the environment (`HTTPS_PROXY`, then `https_proxy`).
fn https_proxy_from_env() -> Option<String> {
    HTTPS_PROXY_VARS
        .iter()
        .find_map(|var| std::env::var(var).ok())
        .filter(|value| !value.trim().is_empty())
}

/// Bypass list from the environment (`NO_PROXY` plus `no_proxy`).
fn no_proxy_from_env() -> String {
    NO_PROXY_VARS
        .iter()
        .filter_map(|var| std::env::var(var).ok())
        .collect::<Vec<_>>()
        .join(",")
}

/// Decide the egress proxy for `host`: pure and unit-tested.
///
/// Returns `Some(url)` when `https_proxy` names a proxy and `host` is not
/// bypassed by `no_proxy`; `None` otherwise (proxy-off default). Matching is
/// case-insensitive on the host: exact entries, leading-dot entries covering
/// subdomains (`.example.com` bypasses `api.example.com` but not
/// `example.com` itself), and `*` bypassing everything. Entries carrying a
/// port never match a bare host — keep entries port-free.
fn select_proxy(https_proxy: Option<&str>, no_proxy: &str, host: &str) -> Option<String> {
    let proxy = https_proxy.filter(|url| !url.trim().is_empty())?;
    let host = host.trim().to_lowercase();
    if host.is_empty() {
        return None;
    }
    for entry in no_proxy.split(',') {
        let entry = entry.trim().to_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" || entry == host {
            return None;
        }
        if let Some(suffix) = entry.strip_prefix('.') {
            if !suffix.is_empty() && host.ends_with(&entry) {
                return None;
            }
        }
    }
    Some(proxy.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_off_by_default() {
        assert_eq!(select_proxy(None, "", "example.com"), None);
        assert_eq!(select_proxy(Some(""), "", "example.com"), None);
        assert_eq!(select_proxy(Some("   "), "", "example.com"), None);
        assert_eq!(select_proxy(None, "example.com", "example.com"), None);
    }

    #[test]
    fn proxy_applies_when_configured() {
        assert_eq!(
            select_proxy(Some("http://proxy:8080"), "", "example.com"),
            Some("http://proxy:8080".to_owned())
        );
        assert_eq!(
            select_proxy(Some("http://proxy:8080"), "other.example", "example.com"),
            Some("http://proxy:8080".to_owned())
        );
    }

    #[test]
    fn no_proxy_bypass_is_exact_and_case_insensitive() {
        assert_eq!(
            select_proxy(Some("http://proxy:8080"), "Example.COM", "example.com"),
            None
        );
        assert_eq!(
            select_proxy(
                Some("http://proxy:8080"),
                "other.example, example.com ",
                "example.com"
            ),
            None
        );
        assert_eq!(
            select_proxy(Some("http://proxy:8080"), "example.com", "sub.example.com"),
            Some("http://proxy:8080".to_owned())
        );
    }

    #[test]
    fn no_proxy_leading_dot_covers_subdomains() {
        assert_eq!(
            select_proxy(Some("http://proxy:8080"), ".example.com", "api.example.com"),
            None
        );
        assert_eq!(
            select_proxy(Some("http://proxy:8080"), ".example.com", "example.com"),
            Some("http://proxy:8080".to_owned())
        );
    }

    #[test]
    fn no_proxy_star_bypasses_everything() {
        assert_eq!(
            select_proxy(Some("http://proxy:8080"), "*", "example.com"),
            None
        );
    }

    #[test]
    fn empty_host_never_proxies() {
        assert_eq!(select_proxy(Some("http://proxy:8080"), "", ""), None);
    }

    #[test]
    fn default_backend_is_deny_all() {
        let service = HttpNetworkService::default();
        assert!(service.capability().is_offline());
    }

    #[test]
    fn explicit_proxy_rejects_garbage_url() {
        assert_eq!(
            HttpNetworkService::with_proxy(NetworkCapability::offline(), "://bad-url").err(),
            Some(NetworkError::Offline)
        );
    }

    /// Serve `body` once over loopback and return its URL.
    ///
    /// Binds an ephemeral port (never a fixed one); `with_length` decides
    /// whether the response declares `Content-Length`, exercising the
    /// pre-check and the chunked-read budget paths separately.
    fn serve_once(body: &'static [u8], with_length: bool) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let port = listener.local_addr().expect("loopback addr").port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("loopback accept");
            let mut head = vec![0u8; 4096];
            let _ = stream.read(&mut head);
            let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n".to_vec();
            if with_length {
                response
                    .extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
            }
            response.extend_from_slice(b"\r\n");
            response.extend_from_slice(body);
            let _ = stream.write_all(&response);
        });
        format!("http://127.0.0.1:{port}/")
    }

    /// Sixty-four bytes over the cap in both framing paths.
    const OVER_BUDGET_BODY: &[u8] =
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn budget_pre_check_rejects_declared_length() {
        let url = serve_once(OVER_BUDGET_BODY, true);
        let service =
            HttpNetworkService::new(NetworkCapability::offline().with_domain("127.0.0.1"));
        let request = Request::get(url).with_max_body_bytes(8);
        assert_eq!(
            service.request(&request),
            Err(NetworkError::Budget { limit_bytes: 8 })
        );
    }

    #[test]
    fn budget_chunked_read_rejects_close_delimited_body() {
        let url = serve_once(OVER_BUDGET_BODY, false);
        let service =
            HttpNetworkService::new(NetworkCapability::offline().with_domain("127.0.0.1"));
        let request = Request::get(url).with_max_body_bytes(8);
        assert_eq!(
            service.request(&request),
            Err(NetworkError::Budget { limit_bytes: 8 })
        );
    }

    #[test]
    fn budget_under_cap_returns_body_intact() {
        let url = serve_once(OVER_BUDGET_BODY, true);
        let service =
            HttpNetworkService::new(NetworkCapability::offline().with_domain("127.0.0.1"));
        let request = Request::get(url).with_max_body_bytes(1024);
        let response = service.request(&request).expect("under-cap body");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, OVER_BUDGET_BODY);
    }

    #[test]
    fn no_budget_reads_body_whole() {
        let url = serve_once(OVER_BUDGET_BODY, false);
        let service =
            HttpNetworkService::new(NetworkCapability::offline().with_domain("127.0.0.1"));
        let response = service.request(&Request::get(url)).expect("uncapped body");
        assert_eq!(response.body, OVER_BUDGET_BODY);
    }
}
