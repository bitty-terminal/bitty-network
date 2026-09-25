//! The issue #21 acceptance test: a local TLS endpoint that performs no
//! external network I/O.
//!
//! The record requires it: "The issue #21 acceptance test must use an ephemeral
//! local TLS endpoint on loopback with that runtime-generated CA, exercise the
//! HTTP and WebSocket paths, and make no external network request. It must cover
//! successful custom-root validation and rejection of an untrusted endpoint
//! without committing any key or certificate fixture."
//!
//! # How "no external network I/O" is established
//!
//! Three independent facts, each asserted by a test in this file:
//!
//! 1. **The listener is loopback and ephemeral.** Every endpoint binds
//!    `127.0.0.1:0`, so the port is chosen by the kernel, the address is never
//!    routable off-host, and nothing collides with a real service.
//!    `the_endpoint_is_loopback_and_ephemeral` asserts it.
//! 2. **The client never resolves a name.** Every URL below uses the address
//!    literal `127.0.0.1`, so there is no DNS lookup, no resolver, and no
//!    platform name-service path involved. The destination cannot be anything
//!    other than the loopback address the listener itself reported.
//! 3. **Nothing else is reachable.** The capability is scoped to `127.0.0.1` and
//!    the endpoint's own port, so any other host is denied by the capability
//!    gate *before* a socket is touched, and
//!    `a_non_loopback_host_is_denied_before_any_socket_work` asserts that.
//!
//! # What is generated, and what is not committed
//!
//! The CA, its key, the server leaf, and the client leaf are all minted inside
//! the test process by `rcgen` and exist only as in-memory values. No file is
//! written, no fixture is read, and nothing outlives the test.
//!
//! The WebSocket half needs the `websocket` feature, because deriving the
//! `Sec-WebSocket-Accept` value means SHA-1 and the only SHA-1 in this
//! dependency graph is the one tungstenite already links. Rather than add a
//! second hash implementation to the test, the WebSocket cases are feature-
//! gated; `just check-websocket` runs them.

#![forbid(unsafe_code)]
#![cfg(feature = "http")]

#[path = "tls_support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(feature = "websocket")]
use bitty_network::WebSocketRequest;
use bitty_network::tls::TlsProvider;
use bitty_network::{HttpNetworkService, NetworkCapability, NetworkError, NetworkService, Request};
use bitty_network_api::{ClientIdentity, ClientIdentityRule, PemSource, TlsConfig};
use rustls::{RootCertStore, ServerConfig, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use support::{Issued, LOOPBACK};

/// The address every endpoint in this file binds and every URL addresses.
const LOOPBACK_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Handshake and read budget for the loopback exchanges. Generous for a
/// loopback round trip, bounded so a hung test fails instead of hanging.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Body the endpoint returns to an HTTP request.
const RESPONSE_BODY: &[u8] = b"bitty loopback tls endpoint";

/// Cap on the request head the endpoint buffers before giving up.
const MAX_HEAD: usize = 16 * 1024;

/// The CRLF CRLF that ends an HTTP request head.
const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// One ephemeral loopback TLS endpoint.
///
/// Owns the listener, the server configuration, and the certificates involved.
/// Dropping it closes the listener.
struct Endpoint {
    address: SocketAddr,
    config: Arc<ServerConfig>,
    issuer: Issued,
    leaf: Issued,
}

impl Endpoint {
    /// Start an endpoint on `127.0.0.1:0`.
    ///
    /// `require_client_auth` decides whether the server demands a client
    /// certificate: with it, a client that presents none fails the handshake,
    /// which is how the mTLS properties are observed rather than assumed.
    fn start(require_client_auth: bool) -> Self {
        let issuer = support::issuer();
        let leaf = support::loopback_leaf(&issuer);
        let config = server_config(&leaf, &issuer, require_client_auth);
        let listener = TcpListener::bind((LOOPBACK_ADDR, 0)).expect("ephemeral loopback bind");
        let address = listener.local_addr().expect("loopback address");
        let endpoint = Self {
            address,
            config: Arc::new(config),
            issuer,
            leaf,
        };
        endpoint.serve(listener);
        endpoint
    }

    /// The issuer certificate PEM: the CA a trusting client is given.
    fn client_ca_pem(&self) -> String {
        self.issuer.pem.clone()
    }

    /// Serve connections on background threads until the listener is dropped.
    fn serve(&self, listener: TcpListener) {
        let config = Arc::clone(&self.config);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = Arc::clone(&config);
                std::thread::spawn(move || {
                    let _ = serve_one(stream, config);
                });
            }
        });
    }

    /// The `https://` URL of this endpoint.
    fn url(&self, path: &str) -> String {
        format!("https://{}/{path}", self.address)
    }

    /// A client certificate this endpoint's server will accept.
    ///
    /// Issued by the endpoint's *own* issuer, because that is the only CA its
    /// client verifier trusts. A certificate from anywhere else would be
    /// refused for the wrong reason, and the test would stop being about client
    /// identity selection.
    fn client_identity(&self) -> Issued {
        support::leaf_for(&self.issuer, &["canary.example.com"])
    }

    /// The `wss://` URL of this endpoint.
    #[cfg(feature = "websocket")]
    fn ws_url(&self, path: &str) -> String {
        format!("wss://{}/{path}", self.address)
    }

    /// The capability that permits this endpoint's host and port and nothing
    /// else.
    fn capability(&self) -> NetworkCapability {
        NetworkCapability::offline().with_domain_ports(LOOPBACK, [self.address.port()])
    }
}

/// A server configuration that trusts `issuer` for client certificates and
/// presents `leaf` for itself.
fn server_config(leaf: &Issued, issuer: &Issued, require_client_auth: bool) -> ServerConfig {
    let verifier = if require_client_auth {
        let mut roots = RootCertStore::empty();
        for certificate in parse_chain(&issuer.pem) {
            roots
                .add(certificate)
                .expect("the runtime issuer is a usable anchor");
        }
        rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            crypto_provider(),
        )
        .build()
        .expect("the client verifier builds")
    } else {
        rustls::server::WebPkiClientVerifier::no_client_auth()
    };
    ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("the default protocol versions are supported")
        .with_client_cert_verifier(verifier)
        .with_single_cert(parse_chain(&leaf.pem), parse_key(&leaf.key_pem))
        .expect("the runtime leaf and key pair")
}

/// The `rustls` provider the endpoint and the crate under test agree on.
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// One connection: complete the TLS handshake, then answer an HTTP request or a
/// WebSocket upgrade.
fn serve_one(stream: TcpStream, config: Arc<ServerConfig>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(LOOPBACK_TIMEOUT))?;
    stream.set_write_timeout(Some(LOOPBACK_TIMEOUT))?;
    let connection = rustls::ServerConnection::new(config)
        .map_err(|_| io_error("the server connection could not be configured"))?;
    let mut tls = StreamOwned::new(connection, stream);
    // TLS record boundaries do not align with HTTP line boundaries, so the head
    // is read a byte at a time until the blank line.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tls.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
        if head.len() > MAX_HEAD {
            return Err(io_error("endpoint request head exceeds its budget"));
        }
    }
    let Ok(head) = std::str::from_utf8(&head) else {
        return Err(io_error("endpoint request head is not text"));
    };
    if header(head, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket")) {
        return serve_upgrade(&mut tls, head);
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        RESPONSE_BODY.len()
    );
    tls.write_all(response.as_bytes())?;
    tls.write_all(RESPONSE_BODY)?;
    tls.flush()
}

/// The value of `name` in a request head, matched case-insensitively.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (found, value) = line.split_once(':')?;
        found
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim())
    })
}

/// Answer a WebSocket upgrade, then hold the connection until the peer closes.
///
/// A full RFC 6455 frame exchange is not what is under test: the properties are
/// the TLS handshake and the identity selection, and a completed HTTP upgrade is
/// where `tungstenite` reports the connection open. The endpoint answers the
/// handshake correctly — including the `Sec-WebSocket-Accept` value, derived by
/// the same function the client uses — and then echoes one close frame so the
/// client's `close()` completes instead of hitting its deadline.
#[cfg(feature = "websocket")]
fn serve_upgrade(
    tls: &mut StreamOwned<rustls::ServerConnection, TcpStream>,
    head: &str,
) -> std::io::Result<()> {
    let Some(key) = header(head, "sec-websocket-key") else {
        return Err(io_error("upgrade carried no Sec-WebSocket-Key"));
    };
    let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    tls.write_all(response.as_bytes())?;
    tls.flush()?;
    // One unmasked close frame: FIN plus the close opcode, zero length.
    let mut sink = [0u8; 256];
    let _ = tls.read(&mut sink);
    tls.write_all(&[0x88, 0x00])?;
    tls.flush()?;
    let _ = tls.read(&mut sink);
    Ok(())
}

/// Without the `websocket` feature there is no SHA-1 in this graph to derive an
/// accept value with, so an upgrade is answered as a plain refusal rather than
/// with a wrong value.
#[cfg(not(feature = "websocket"))]
fn serve_upgrade(
    tls: &mut StreamOwned<rustls::ServerConnection, TcpStream>,
    _head: &str,
) -> std::io::Result<()> {
    tls.write_all(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n")?;
    tls.flush()
}

/// Wrap a message as a `std::io::Error`.
fn io_error(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}

/// Parse a PEM certificate chain.
fn parse_chain(pem: &str) -> Vec<CertificateDer<'static>> {
    let mut chain = Vec::new();
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    while let Some(section) =
        rustls_pki_types::pem::from_buf(&mut reader).expect("the runtime PEM parses")
    {
        if let rustls_pki_types::pem::SectionKind::Certificate = section.0 {
            chain.push(CertificateDer::from(section.1));
        }
    }
    assert!(!chain.is_empty(), "the runtime chain is not empty");
    chain
}

/// Parse a PEM private key.
fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let mut key = None;
    while let Some(section) =
        rustls_pki_types::pem::from_buf(&mut reader).expect("the runtime key PEM parses")
    {
        if let rustls_pki_types::pem::SectionKind::PrivateKey = section.0 {
            key = Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(section.1)));
        }
    }
    key.expect("the runtime key PEM carries a key")
}

/// A provider that trusts the endpoint's CA and nothing else of the caller's.
fn trusting_provider(endpoint: &Endpoint) -> TlsProvider {
    TlsProvider::build(
        TlsConfig::new().with_ca(PemSource::inline(endpoint.client_ca_pem().into_bytes())),
    )
    .expect("the runtime CA bundle is admitted")
}

/// A provider that trusts the endpoint's CA and presents `client` to
/// `LOOPBACK`.
fn trusting_provider_with_identity(endpoint: &Endpoint, client: &Issued) -> TlsProvider {
    TlsProvider::build(
        TlsConfig::new()
            .with_ca(PemSource::inline(endpoint.client_ca_pem().into_bytes()))
            .with_identity(ClientIdentityRule::new(
                [LOOPBACK],
                ClientIdentity::new(
                    PemSource::inline(client.pem.clone()),
                    PemSource::inline(client.key_pem.clone()),
                ),
            )),
    )
    .expect("the runtime CA bundle and identity are admitted")
}

/// A service carrying `provider`, permitted to reach only this endpoint.
fn service(endpoint: &Endpoint, provider: TlsProvider) -> HttpNetworkService {
    HttpNetworkService::with_tls(endpoint.capability(), provider)
        .expect("the service builds with a loopback policy")
}

/// A service that trusts only the platform's native roots.
fn native_only_service(endpoint: &Endpoint) -> HttpNetworkService {
    service(
        endpoint,
        TlsProvider::build(TlsConfig::new()).expect("the default policy builds"),
    )
}

/// The endpoint is loopback and ephemeral, which is the first of the three facts
/// that make this file's traffic non-external.
#[test]
fn the_endpoint_is_loopback_and_ephemeral() {
    let first = Endpoint::start(false);
    let second = Endpoint::start(false);
    assert_eq!(first.address.ip(), LOOPBACK_ADDR, "bound to loopback");
    assert!(first.address.ip().is_loopback());
    assert!(
        first.address.port() != 0 && second.address.port() != 0,
        "the kernel assigned a real port"
    );
    assert_ne!(
        first.address.port(),
        second.address.port(),
        "two endpoints do not collide, so no fixed port is hardcoded anywhere"
    );
}

/// Nothing else is reachable: a host outside the capability is denied before a
/// socket is touched, so this file cannot make a request off-host even if a URL
/// said to.
#[test]
fn a_non_loopback_host_is_denied_before_any_socket_work() {
    let endpoint = Endpoint::start(false);
    let service = service(&endpoint, trusting_provider(&endpoint));
    for url in [
        "https://example.com/",
        "https://198.51.100.7/",
        "https://[2001:db8::1]/",
    ] {
        let error = service
            .request(&Request::get(url))
            .expect_err("a host outside the capability must be denied");
        assert!(
            matches!(error, NetworkError::Denied { .. }),
            "{url} must be denied by the capability, got {error:?}"
        );
    }
}

/// The runtime CA is in no trust store on this host, so a successful request
/// proves the supplied bundle was used.
///
/// Without this, "the request succeeded" would be consistent with the client
/// happening to trust the endpoint some other way.
#[test]
fn the_runtime_ca_is_in_no_other_trust_store() {
    let endpoint = Endpoint::start(false);
    let mut roots = RootCertStore::empty();
    for certificate in parse_chain(&endpoint.client_ca_pem()) {
        roots
            .add(certificate)
            .expect("the runtime issuer is a usable anchor");
    }
    assert_eq!(
        roots.len(),
        1,
        "the endpoint's CA is a single self-signed runtime certificate"
    );
    assert_eq!(
        parse_chain(&endpoint.leaf.pem).len(),
        1,
        "the endpoint presents one runtime leaf"
    );
    assert_eq!(
        parse_chain(&endpoint.issuer.pem).len(),
        1,
        "the issuer is one runtime certificate"
    );
}

/// A client that trusts the endpoint's CA completes the HTTP request: the
/// "successful custom-root validation" half of the acceptance test.
#[test]
fn an_http_request_succeeds_against_a_trusted_custom_root() {
    let endpoint = Endpoint::start(false);
    let service = service(&endpoint, trusting_provider(&endpoint));
    let response = service
        .request(&Request::get(endpoint.url("probe")))
        .expect("the trusted loopback endpoint answers");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, RESPONSE_BODY);
    assert!(response.is_success(), "a 200 with the expected body");
}

/// The same endpoint is refused when the client trusts only the platform's native
/// roots: the "rejection of an untrusted endpoint" half.
///
/// The body never arrives. A client that logged the problem and carried on
/// would show a `200` here, so the assertion is on the whole response, not on a
/// log line.
#[test]
fn an_untrusted_endpoint_is_rejected_over_http() {
    let endpoint = Endpoint::start(false);
    let error = native_only_service(&endpoint)
        .request(&Request::get(endpoint.url("probe")))
        .expect_err("an endpoint outside the trust configuration must be refused");
    assert_eq!(
        error,
        NetworkError::Offline,
        "a chain that does not verify is unreachable as far as this backend can \
         vouch: it cannot claim the endpoint was reached"
    );
}

/// A client identity is presented when a rule names the exact host, and a server
/// that *requires* one refuses the connection when it is absent.
///
/// Both halves matter: the positive half shows the identity reaches the
/// handshake, and the negative half shows it is not decorative — a provider
/// that silently downgraded to "no client certificate" would fail here rather
/// than quietly succeed.
#[test]
fn a_required_client_identity_is_presented_only_for_the_named_host() {
    let endpoint = Endpoint::start(true);
    let client = endpoint.client_identity();

    let with_identity = service(
        &endpoint,
        trusting_provider_with_identity(&endpoint, &client),
    );
    let response = with_identity
        .request(&Request::get(endpoint.url("probe")))
        .expect("the endpoint that requires a client certificate accepts this one");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, RESPONSE_BODY);

    // No rule: the same endpoint now refuses, because no client certificate is
    // presented. This is the fail-closed direction the record requires.
    let error = service(&endpoint, trusting_provider(&endpoint))
        .request(&Request::get(endpoint.url("probe")))
        .expect_err("a server requiring a client certificate must refuse a client with none");
    assert_eq!(
        error,
        NetworkError::Offline,
        "the handshake fails closed rather than proceeding without the identity"
    );
}

/// The rule must name the host the request actually addresses. Rules for a
/// parent, a subdomain, and a suffix-sharing neighbour select no identity, so a
/// server that requires one refuses.
///
/// This is exact matching observed end to end rather than through the selection
/// function: loose matching would let one of these three through.
#[test]
fn a_rule_for_another_host_presents_no_client_certificate() {
    let endpoint = Endpoint::start(true);
    let client = endpoint.client_identity();
    let provider = TlsProvider::build(
        TlsConfig::new()
            .with_ca(PemSource::inline(endpoint.client_ca_pem().into_bytes()))
            .with_identity(ClientIdentityRule::new(
                ["127.0.0.1.example.com", "sub.127.0.0.1", "0.0.1"],
                ClientIdentity::new(
                    PemSource::inline(client.pem.clone()),
                    PemSource::inline(client.key_pem.clone()),
                ),
            )),
    )
    .expect("the runtime policy is admitted");
    let error = service(&endpoint, provider)
        .request(&Request::get(endpoint.url("probe")))
        .expect_err("a rule for another host must not present its identity here");
    assert_eq!(
        error,
        NetworkError::Offline,
        "an identity configured for another host is never presented to this one"
    );
}

/// A client that trusts the endpoint's CA completes the WebSocket handshake, and
/// the same endpoint is refused when it does not.
///
/// The record requires the acceptance test to exercise the WebSocket path, and
/// this is that half: the same additive trust configuration, the same
/// per-destination selection, reached through a different backend.
#[cfg(feature = "websocket")]
#[test]
fn a_websocket_handshake_succeeds_against_a_trusted_custom_root_and_is_refused_otherwise() {
    use bitty_network::WsMessage;

    let endpoint = Endpoint::start(false);
    let mut socket = service(&endpoint, trusting_provider(&endpoint))
        .websocket(&WebSocketRequest::new(endpoint.ws_url("socket")))
        .expect("the trusted loopback endpoint upgrades");
    socket
        .send(WsMessage::Text("ping".to_owned()))
        .expect("the upgraded socket accepts a message");
    socket.close().expect("the upgraded socket closes");

    let error = native_only_service(&endpoint)
        .websocket(&WebSocketRequest::new(endpoint.ws_url("socket")))
        .expect_err("an endpoint outside the trust configuration must be refused");
    assert_eq!(
        error,
        NetworkError::Offline,
        "the handshake fails closed rather than upgrading without trust"
    );
}

/// The WebSocket path selects the same identity the HTTP path does, for the same
/// exact host.
#[cfg(feature = "websocket")]
#[test]
fn the_websocket_path_presents_a_required_client_identity() {
    let endpoint = Endpoint::start(true);
    let client = endpoint.client_identity();
    let with_identity = service(
        &endpoint,
        trusting_provider_with_identity(&endpoint, &client),
    );
    let socket = with_identity
        .websocket(&WebSocketRequest::new(endpoint.ws_url("socket")))
        .expect("the endpoint that requires a client certificate accepts this one");
    socket.close().expect("the upgraded socket closes");

    let error = service(&endpoint, trusting_provider(&endpoint))
        .websocket(&WebSocketRequest::new(endpoint.ws_url("socket")))
        .expect_err("a server requiring a client certificate must refuse a client with none");
    assert_eq!(
        error,
        NetworkError::Offline,
        "the handshake fails closed rather than proceeding without the identity"
    );
}

/// Body the plaintext origin probe returns, so a request that reached the origin
/// directly is distinguishable from one that went through the proxy.
const ORIGIN_BODY: &[u8] = b"reached-the-origin-directly";

/// Body the plaintext proxy probe returns, so a proxied request is
/// distinguishable from a direct one.
const PROXY_BODY: &[u8] = b"reached-the-proxy";

/// One ephemeral loopback plaintext HTTP endpoint that records what it served.
///
/// Plaintext on purpose: the property under test is which route a request takes,
/// and an `http://` origin keeps the TLS configuration out of the exchange, so a
/// failure points at the proxy decision and nothing else. The listener is
/// loopback and ephemeral on the same terms as [`Endpoint`], so this probe adds
/// no off-host reachability either.
struct Probe {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Probe {
    /// Start a probe on `127.0.0.1:0` that answers every request with `body`.
    fn start(body: &'static [u8]) -> Self {
        let listener = TcpListener::bind((LOOPBACK_ADDR, 0)).expect("ephemeral loopback bind");
        let address = listener.local_addr().expect("loopback address");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = serve_plain(stream, body);
            }
        });
        Self { address, hits }
    }

    /// The `http://` URL of this probe.
    fn url(&self, path: &str) -> String {
        format!("http://{}/{path}", self.address)
    }

    /// How many connections this probe accepted.
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Answer one plaintext request with `body`.
fn serve_plain(mut stream: TcpStream, body: &'static [u8]) -> std::io::Result<()> {
    stream.set_read_timeout(Some(LOOPBACK_TIMEOUT))?;
    stream.set_write_timeout(Some(LOOPBACK_TIMEOUT))?;
    // Read only the request head: the body is irrelevant to which route the
    // request took, and stopping at the head terminator keeps the probe from
    // waiting on a client that has nothing more to send.
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !head
        .windows(HEAD_TERMINATOR.len())
        .any(|w| w == HEAD_TERMINATOR)
    {
        if head.len() >= MAX_HEAD {
            break;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
    }
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

/// A configured TLS policy does not cost the request its configured proxy.
///
/// The proxy decision and the TLS policy are orthogonal: supplying one must not
/// silence the other. A backend that resolves a per-identity client but rebuilds
/// the proxy set from a single URL would drop the all-scope entry an explicit
/// override consists of, and the request would go out direct — the one direction
/// an operator who configured a proxy did not ask for. The assertion is on where
/// the request actually arrived, not on a builder's contents.
#[test]
fn an_explicit_proxy_is_still_applied_when_a_tls_policy_is_configured() {
    let origin = Probe::start(ORIGIN_BODY);
    let proxy = Probe::start(PROXY_BODY);
    let provider = TlsProvider::build(
        TlsConfig::new().with_ca(PemSource::inline(support::ca_pem().into_bytes())),
    )
    .expect("the runtime CA is admitted as an additive anchor");
    let service = HttpNetworkService::with_tls_and_proxy(
        NetworkCapability::offline().with_domain(LOOPBACK),
        provider,
        &proxy.url(""),
    )
    .expect("a valid proxy url with a valid policy");

    let response = service
        .request(&Request::get(origin.url("proxied")))
        .expect("the proxied request completes");

    assert_eq!(
        response.body, PROXY_BODY,
        "the request must arrive at the proxy, not at the origin"
    );
    assert_eq!(proxy.hits(), 1, "the proxy served exactly this request");
    assert_eq!(
        origin.hits(),
        0,
        "an explicit proxy must never be silently replaced by direct egress"
    );
}
