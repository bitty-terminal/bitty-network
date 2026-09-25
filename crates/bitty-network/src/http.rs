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
//! 1. Capability first: [`NetworkCapability::check_request`] (host, port,
//!    then method) runs before the client, the URL, or any socket is
//!    touched. Deny-all yields [`NetworkError::Offline`], an allowlist miss
//!    yields the typed [`NetworkError::Denied`], and nothing is sent in
//!    either case. Portless requests fail closed; see `Request::port`.
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
//! Proxy: [`HttpNetworkService::with_proxy`] is the deterministic override.
//! Otherwise standard proxy variables are snapshotted explicitly:
//! `HTTP_PROXY` applies to `http`/`ws`, `HTTPS_PROXY` to `https`/`wss`, and
//! `ALL_PROXY` is the fallback (uppercase names precede lowercase).
//! `NO_PROXY`/`no_proxy` lists bypassed hosts (exact match, case-insensitive;
//! a leading-dot entry matches subdomains; `*` bypasses everything).
//! Reqwest's ambient system/PAC discovery is disabled on every client, so
//! no unselected variable or platform proxy can bypass this decision. Any
//! configured proxy that cannot be parsed or carries userinfo is rejected
//! before a client is built: [`HttpNetworkService::with_proxy`] returns
//! [`NetworkError::Offline`], while environment configuration makes the
//! service fail closed for every request instead of silently switching to
//! direct egress. Credential-bearing URLs are never retained or logged.
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
//! cap set the body is read whole, as before. The WebSocket module enforces
//! frame, assembled-message, aggregate-byte, frame-count, message-count,
//! and pending-write-buffer budgets at the transport boundary.
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

/// Environment variables naming HTTP proxies, in precedence order.
const HTTP_PROXY_VARS: [&str; 2] = ["HTTP_PROXY", "http_proxy"];

/// Environment variables naming HTTPS proxies, in precedence order.
const HTTPS_PROXY_VARS: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];

/// Environment variables naming fallback proxies, in precedence order.
const ALL_PROXY_VARS: [&str; 2] = ["ALL_PROXY", "all_proxy"];

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
#[derive(Clone)]
pub struct HttpNetworkService {
    capability: NetworkCapability,
    egress: Egress,
}

impl std::fmt::Debug for HttpNetworkService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpNetworkService")
            .field("capability", &self.capability)
            .field("proxy_configured", &self.egress.route.configured())
            .field("proxy_rejected", &self.egress.proxy_rejected)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum ProxyScope {
    All,
    Http,
    Https,
}

#[derive(Clone, Default)]
struct ProxyRoute {
    http: Option<String>,
    https: Option<String>,
    all: Option<String>,
    client: Option<reqwest::blocking::Client>,
}

impl ProxyRoute {
    fn explicit(proxy_url: &str) -> Result<Self, NetworkError> {
        let all = validated_proxy_url(proxy_url, ProxyScope::All)?;
        let route = Self {
            all: Some(all),
            ..Self::default()
        };
        let client = proxy_route_client(&route).ok_or(NetworkError::Offline)?;
        Ok(Self {
            client: Some(client),
            ..route
        })
    }

    fn from_env() -> Result<Self, NetworkError> {
        let http = proxy_from_env(&HTTP_PROXY_VARS)
            .map(|url| validated_proxy_url(&url, ProxyScope::Http))
            .transpose()?;
        let https = proxy_from_env(&HTTPS_PROXY_VARS)
            .map(|url| validated_proxy_url(&url, ProxyScope::Https))
            .transpose()?;
        let all = proxy_from_env(&ALL_PROXY_VARS)
            .map(|url| validated_proxy_url(&url, ProxyScope::All))
            .transpose()?;
        let route = Self {
            http,
            https,
            all,
            client: None,
        };
        let client = if route.configured() {
            Some(proxy_route_client(&route).ok_or(NetworkError::Offline)?)
        } else {
            None
        };
        Ok(Self { client, ..route })
    }

    fn configured(&self) -> bool {
        self.http.is_some() || self.https.is_some() || self.all.is_some()
    }

    fn for_url(&self, url: &str) -> Option<&str> {
        if url_uses_tls(url) {
            self.https.as_deref().or(self.all.as_deref())
        } else {
            self.http.as_deref().or(self.all.as_deref())
        }
    }
}

/// Egress clients behind one service: direct always, proxied when configured.
///
/// The proxy URLs and bypass list are snapshotted at construction so the
/// per-request decision is a pure function of the request URL and host (see
/// [`select_proxy`]).
#[derive(Clone)]
struct Egress {
    direct: Option<reqwest::blocking::Client>,
    route: ProxyRoute,
    no_proxy: String,
    proxy_rejected: bool,
}

impl HttpNetworkService {
    /// Serve HTTP under `capability`, proxy inherited from the environment.
    ///
    /// Reads the standard proxy variables and `NO_PROXY`/`no_proxy` once; an
    /// absent proxy means direct egress (proxy-off default), while an
    /// unusable configured proxy makes the service fail closed. Construction
    /// performs no I/O.
    #[must_use]
    pub fn new(capability: NetworkCapability) -> Self {
        let no_proxy = no_proxy_from_env();
        let (route, proxy_rejected) = match ProxyRoute::from_env() {
            Ok(route) => (route, false),
            Err(_) => (ProxyRoute::default(), true),
        };
        Self::from_egress(capability, route, no_proxy, proxy_rejected)
    }

    fn from_egress(
        capability: NetworkCapability,
        route: ProxyRoute,
        no_proxy: String,
        proxy_rejected: bool,
    ) -> Self {
        Self {
            capability,
            egress: Egress {
                direct: Self::client_with(None),
                route,
                no_proxy,
                proxy_rejected,
            },
        }
    }

    /// Serve HTTP under `capability` via one explicit proxy URL.
    ///
    /// Deterministic override for tests and operators: `proxy_url` replaces
    /// whatever the environment says (pass-through when the environment must
    /// win goes through [`HttpNetworkService::new`]). Returns
    /// [`NetworkError::Offline`] when `proxy_url` does not parse or carries
    /// userinfo — fail closed, never half-proxied.
    pub fn with_proxy(
        capability: NetworkCapability,
        proxy_url: &str,
    ) -> Result<Self, NetworkError> {
        let route = ProxyRoute::explicit(proxy_url)?;
        Ok(Self::from_egress(capability, route, String::new(), false))
    }

    fn ensure_proxy_usable(&self) -> Result<(), NetworkError> {
        if self.egress.proxy_rejected {
            Err(NetworkError::Offline)
        } else {
            Ok(())
        }
    }

    /// The capability this backend enforces (checked before every send).
    #[must_use]
    pub fn capability(&self) -> &NetworkCapability {
        &self.capability
    }

    /// Build one shared client around `proxy` (`None` for direct egress).
    ///
    /// System-proxy discovery is disabled before the checked proxy is
    /// injected, so reqwest cannot introduce an ambient route later.
    fn client_with(proxy: Option<reqwest::Proxy>) -> Option<reqwest::blocking::Client> {
        let mut builder = reqwest::blocking::Client::builder().no_proxy();
        if let Some(proxy) = proxy {
            builder = builder.proxy(proxy);
        }
        builder.build().ok()
    }

    fn client_for(&self, url: &str, host: &str) -> Option<&reqwest::blocking::Client> {
        match self.selected_proxy(url, host) {
            Some(_) => self.egress.route.client.as_ref(),
            None => self.egress.direct.as_ref(),
        }
    }

    fn selected_proxy(&self, url: &str, host: &str) -> Option<&str> {
        let proxy = self.egress.route.for_url(url)?;
        if select_proxy(Some(proxy), &self.egress.no_proxy, host).is_some() {
            Some(proxy)
        } else {
            None
        }
    }

    /// The proxy URL selected for `url`, if any: the configured proxy that
    /// is not bypassed for this host. Mirrors the per-request egress choice
    /// in [`client_for`](Self::client_for) so the WebSocket handshake tunnels
    /// through exactly the proxy a plain request would use.
    ///
    /// Only available with the `websocket` feature; the handshake path in
    /// `crate::websocket` consumes it.
    #[cfg(feature = "websocket")]
    pub(crate) fn proxy_url_for(&self, url: &str, host: &str) -> Option<String> {
        self.selected_proxy(url, host).map(str::to_owned)
    }

    /// Capability-first rejection for `request` (mirrors the offline backend).
    ///
    /// Only used by the fail-closed `websocket()` without the `websocket`
    /// feature; with the feature the capability check runs inline.
    #[cfg(not(feature = "websocket"))]
    fn reject(&self, request: &WebSocketRequest) -> NetworkError {
        match self.capability.check_handshake(request) {
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
        let client = self
            .client_for(&request.url, request.host())
            .ok_or(NetworkError::Offline)?;
        let mut outgoing = client.request(method, request.url.clone()).timeout(timeout);
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
        self.capability.check_request(request)?;
        self.ensure_proxy_usable()?;
        self.send(request)
    }

    /// Capability-gated handshake: without the `websocket` feature this
    /// stays fail-closed (offline on allowlist hits, typed denial
    /// otherwise); with the feature an allowed host performs the handshake
    /// in `crate::websocket` and returns the open socket.
    #[cfg(feature = "websocket")]
    fn websocket(&self, request: &WebSocketRequest) -> Result<Self::Socket, NetworkError> {
        self.capability.check_handshake(request)?;
        self.ensure_proxy_usable()?;
        crate::websocket::connect(
            request,
            self.proxy_url_for(&request.url, request.host()).as_deref(),
        )
    }

    #[cfg(not(feature = "websocket"))]
    fn websocket(&self, request: &WebSocketRequest) -> Result<Self::Socket, NetworkError> {
        Err(self.reject(request))
    }
}

fn proxy_url_has_credentials(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return true;
    };
    rest.split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

fn validated_proxy_url(url: &str, scope: ProxyScope) -> Result<String, NetworkError> {
    if proxy_url_has_credentials(url) || reqwest_proxy(url, scope).is_err() {
        return Err(NetworkError::Offline);
    }
    Ok(url.to_owned())
}

fn reqwest_proxy(url: &str, scope: ProxyScope) -> Result<reqwest::Proxy, ()> {
    match scope {
        ProxyScope::All => reqwest::Proxy::all(url),
        ProxyScope::Http => reqwest::Proxy::http(url),
        ProxyScope::Https => reqwest::Proxy::https(url),
    }
    .map_err(|_| ())
}

fn proxy_route_client(route: &ProxyRoute) -> Option<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder().no_proxy();
    for (url, scope) in [
        (route.all.as_deref(), ProxyScope::All),
        (route.https.as_deref(), ProxyScope::Https),
        (route.http.as_deref(), ProxyScope::Http),
    ] {
        if let Some(url) = url {
            builder = builder.proxy(reqwest_proxy(url, scope).ok()?);
        }
    }
    builder.build().ok()
}

fn url_uses_tls(url: &str) -> bool {
    url.split_once("://").is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss")
    })
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

fn proxy_from_env(vars: &[&str]) -> Option<String> {
    vars.iter().find_map(|var| {
        std::env::var(var)
            .ok()
            .filter(|value| !value.trim().is_empty())
    })
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
/// Returns `Some(url)` when `proxy_url` names a proxy and `host` is not
/// bypassed by `no_proxy`; `None` otherwise (proxy-off default). Matching is
/// case-insensitive on the host: exact entries, leading-dot entries covering
/// subdomains (`.example.com` bypasses `api.example.com` but not
/// `example.com` itself), and `*` bypassing everything. Entries carrying a
/// port never match a bare host — keep entries port-free.
fn select_proxy(proxy_url: Option<&str>, no_proxy: &str, host: &str) -> Option<String> {
    let proxy = proxy_url.filter(|url| !url.trim().is_empty())?;
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
    fn proxy_route_prefers_scheme_specific_fallback() {
        let route = ProxyRoute {
            http: Some("http://http-proxy.test".to_owned()),
            https: Some("http://https-proxy.test".to_owned()),
            all: Some("http://all-proxy.test".to_owned()),
            client: None,
        };
        assert_eq!(
            route.for_url("http://origin.test"),
            Some("http://http-proxy.test")
        );
        assert_eq!(
            route.for_url("ws://origin.test"),
            Some("http://http-proxy.test")
        );
        assert_eq!(
            route.for_url("https://origin.test"),
            Some("http://https-proxy.test")
        );
        assert_eq!(
            route.for_url("wss://origin.test"),
            Some("http://https-proxy.test")
        );
        let fallback = ProxyRoute {
            all: route.all.clone(),
            ..ProxyRoute::default()
        };
        assert_eq!(
            fallback.for_url("http://origin.test"),
            Some("http://all-proxy.test")
        );
        assert_eq!(
            fallback.for_url("https://origin.test"),
            Some("http://all-proxy.test")
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

    #[test]
    fn explicit_credentialed_proxy_is_rejected_without_exposed_secret() {
        let secret = "fixture-pass";
        let proxy_url = format!("http://fixture-user:{secret}@proxy.test/");
        let error = HttpNetworkService::with_proxy(NetworkCapability::offline(), &proxy_url)
            .expect_err("credentialed proxy must fail closed");
        assert_eq!(error, NetworkError::Offline);
        assert!(!format!("{error:?}").contains(secret));
        assert!(!format!("{error:?}").contains("fixture-user"));
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
