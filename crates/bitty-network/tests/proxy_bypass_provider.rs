//! Integration tests for #25 (Criterion 11):
//! - NO_PROXY bypass precedence over provider resolution;
//! - Bypassed requests make 0 provider calls and send no proxy credentials;
//! - Non-bypass requests read the provider exactly once per hop and select exactly one record;
//! - Redirects re-evaluate bypass per hop (proxied -> bypassed and bypassed -> proxied);
//! - Malformed proxy configuration fails closed without being ignored;
//! - Provider failure or mismatch fails closed with zero fallback to direct or unauthenticated egress;
//! - WebSocket handshake enforces identical bypass precedence and fail-closed resolution.

#![cfg(all(feature = "http", feature = "websocket"))]
#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bitty_network::origin::CanonicalOrigin;
use bitty_network::proxy::{ProxyCredentialProvider, ProxyCredentialRecord};
use bitty_network::{
    HttpNetworkService, NetworkCapability, NetworkError, NetworkService, Request, WebSocketRequest,
    WsMessage,
};

/// Loopback HTTP probe server for testing direct and proxied hops.
struct Probe {
    port: u16,
    hits: Arc<AtomicUsize>,
    first_request: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Probe {
    fn start(handler: impl Fn(&str) -> Vec<u8> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback probe");
        listener.set_nonblocking(true).expect("probe nonblocking");
        let port = listener.local_addr().expect("probe port").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let first_request = Arc::new(Mutex::new(None::<String>));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_hits = Arc::clone(&hits);
        let thread_first = Arc::clone(&first_request);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("accepted stream blocking");
                        thread_hits.fetch_add(1, Ordering::SeqCst);
                        let head = read_head(stream.try_clone().expect("clone probe stream"));
                        if let Ok(mut guard) = thread_first.lock() {
                            if guard.is_none() {
                                *guard = Some(head.clone());
                            }
                        }
                        let response = handler(&head);
                        if let Ok(mut stream) = stream.try_clone() {
                            let _ = stream.write_all(&response);
                            let _ = stream.flush();
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            hits,
            first_request,
            stop,
            handle: Some(handle),
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn first_request(&self) -> Option<String> {
        self.first_request.lock().ok().and_then(|g| g.clone())
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_head(mut stream: TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 16_384 || buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Loopback WebSocket echo server for testing WebSocket handshake paths.
struct WsEchoServer {
    port: u16,
    tcp_hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl WsEchoServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback ws server");
        listener.set_nonblocking(true).expect("server nonblocking");
        let port = listener.local_addr().expect("server port").port();
        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_hits = Arc::clone(&tcp_hits);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("accepted stream blocking");
                        thread_hits.fetch_add(1, Ordering::SeqCst);
                        thread::spawn(move || {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                            if let Ok(mut socket) = tungstenite::accept(stream) {
                                while let Ok(msg) = socket.read() {
                                    if msg.is_text() || msg.is_binary() {
                                        let _ = socket.write(msg);
                                        let _ = socket.flush();
                                    } else if msg.is_close() {
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            tcp_hits,
            stop,
            handle: Some(handle),
        }
    }

    fn tcp_hits(&self) -> usize {
        self.tcp_hits.load(Ordering::SeqCst)
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

type ResolverFn = dyn Fn(&CanonicalOrigin, &CanonicalOrigin) -> Result<Option<ProxyCredentialRecord>, NetworkError>
    + Send
    + Sync;

struct MockProxyProvider {
    calls: Arc<AtomicUsize>,
    resolver: Box<ResolverFn>,
}

impl std::fmt::Debug for MockProxyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockProxyProvider")
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl MockProxyProvider {
    fn new(
        calls: Arc<AtomicUsize>,
        resolver: impl Fn(
            &CanonicalOrigin,
            &CanonicalOrigin,
        ) -> Result<Option<ProxyCredentialRecord>, NetworkError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            calls,
            resolver: Box::new(resolver),
        }
    }
}

impl ProxyCredentialProvider for MockProxyProvider {
    fn resolve(
        &self,
        proxy_origin: &CanonicalOrigin,
        destination_origin: &CanonicalOrigin,
    ) -> Result<Option<ProxyCredentialRecord>, NetworkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.resolver)(proxy_origin, destination_origin)
    }
}

#[test]
fn bypassed_request_makes_zero_provider_calls_and_sends_no_proxy_credential() {
    let origin = Probe::start(|_| ok_response(b"origin-direct-payload"));
    let proxy = Probe::start(|_| ok_response(b"proxy-payload-must-stay-unused"));
    let calls = Arc::new(AtomicUsize::new(0));

    let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), |_, _| {
        panic!("provider must not be called for bypassed requests");
    }));

    let capability = NetworkCapability::offline().with_domain("127.0.0.1");
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let service = HttpNetworkService::with_proxy_bypass_and_provider(
        capability,
        &proxy_url,
        "127.0.0.1",
        provider,
    )
    .expect("valid proxy bypass and provider construction");

    let req_url = format!("http://127.0.0.1:{}/resource", origin.port);
    let response = service
        .request(&Request::get(&req_url))
        .expect("bypassed request succeeds");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"origin-direct-payload");

    // Criterion 11 requirements:
    // 1. A bypassed request makes 0 provider calls
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // 2. Direct egress: proxy server got 0 connections
    assert_eq!(proxy.hits(), 0);
    // 3. Origin server received direct request
    assert_eq!(origin.hits(), 1);

    // 4. Sends no proxy credentials
    let head = origin.first_request().expect("first request recorded");
    assert!(
        !head.to_ascii_lowercase().contains("proxy-authorization"),
        "direct request must carry no Proxy-Authorization header"
    );

    origin.stop_and_join();
    proxy.stop_and_join();
}

#[test]
fn non_bypass_resolves_exactly_one_current_record() {
    let origin = Probe::start(|_| ok_response(b"origin-direct-payload"));
    let proxy = Probe::start(|_| ok_response(b"proxied-payload"));
    let calls = Arc::new(AtomicUsize::new(0));

    let proxy_origin =
        CanonicalOrigin::parse(&format!("http://127.0.0.1:{}", proxy.port)).expect("valid origin");
    let dest_origin =
        CanonicalOrigin::parse(&format!("http://127.0.0.1:{}", origin.port)).expect("valid origin");

    let expected_record = ProxyCredentialRecord {
        id: "cred-record-001".to_owned(),
        proxy_origin: proxy_origin.clone(),
        allowed_destinations: vec![dest_origin.clone()],
        generation: 1,
        scope_epoch: 1,
    };

    let record_clone = expected_record.clone();
    let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), move |p, d| {
        if p == &proxy_origin && d == &dest_origin {
            Ok(Some(record_clone.clone()))
        } else {
            Err(NetworkError::Offline)
        }
    }));

    let capability = NetworkCapability::offline().with_domain("127.0.0.1");
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let service = HttpNetworkService::with_proxy_bypass_and_provider(
        capability, &proxy_url, "", // no bypass: request must be routed through proxy
        provider,
    )
    .expect("valid service");

    let req_url = format!("http://127.0.0.1:{}/resource", origin.port);
    let response = service
        .request(&Request::get(&req_url))
        .expect("proxied request succeeds");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"proxied-payload");

    // Criterion 11 requirement:
    // Non-bypass resolution reads the provider exactly once per hop and selects exactly one record
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "provider must be called exactly once per hop"
    );
    assert_eq!(proxy.hits(), 1);
    assert_eq!(origin.hits(), 0);

    origin.stop_and_join();
    proxy.stop_and_join();
}

#[test]
fn every_redirect_reevaluates_bypass_decision() {
    // Subtest A: Proxied hop 1 -> 302 redirect -> Bypassed hop 2
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let bypassed_target = Probe::start(|_| ok_response(b"bypassed-target-payload"));

        let bypassed_url = format!("http://localhost:{}/final", bypassed_target.port);
        let bypassed_url_clone = bypassed_url.clone();

        let proxy = Probe::start(move |_| redirect_response(&bypassed_url_clone));

        let proxy_origin =
            CanonicalOrigin::parse(&format!("http://127.0.0.1:{}", proxy.port)).expect("origin");
        let hop1_dest_origin = CanonicalOrigin::parse("http://127.0.0.1:9999").expect("origin");

        let record = ProxyCredentialRecord {
            id: "rec-hop1".to_owned(),
            proxy_origin: proxy_origin.clone(),
            allowed_destinations: vec![hop1_dest_origin.clone()],
            generation: 1,
            scope_epoch: 1,
        };

        let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), move |p, d| {
            if p == &proxy_origin && d == &hop1_dest_origin {
                Ok(Some(record.clone()))
            } else {
                Err(NetworkError::Offline)
            }
        }));

        let capability = NetworkCapability::offline()
            .with_domain("127.0.0.1")
            .with_domain("localhost");

        let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
        let service = HttpNetworkService::with_proxy_bypass_and_provider(
            capability,
            &proxy_url,
            "localhost", // localhost is bypassed; 127.0.0.1 is proxied
            provider,
        )
        .expect("service");

        let response = service
            .request(&Request::get("http://127.0.0.1:9999/start"))
            .expect("redirect followed to bypassed destination");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"bypassed-target-payload");

        // Hop 1 called provider once. Hop 2 was bypassed and made 0 provider calls!
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "provider must be resolved only for the proxied hop 1, not bypassed hop 2"
        );
        assert_eq!(proxy.hits(), 1);
        assert_eq!(bypassed_target.hits(), 1);

        bypassed_target.stop_and_join();
        proxy.stop_and_join();
    }

    // Subtest B: Bypassed hop 1 -> 302 redirect -> Proxied hop 2
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let proxy = Probe::start(|_| ok_response(b"proxied-hop2-payload"));

        let hop2_url = format!("http://127.0.0.1:{}/final", proxy.port);
        let hop2_url_clone = hop2_url.clone();

        let initial_target = Probe::start(move |_| redirect_response(&hop2_url_clone));

        let proxy_origin =
            CanonicalOrigin::parse(&format!("http://127.0.0.1:{}", proxy.port)).expect("origin");
        let hop2_dest_origin =
            CanonicalOrigin::parse(&format!("http://127.0.0.1:{}", proxy.port)).expect("origin");

        let record = ProxyCredentialRecord {
            id: "rec-hop2".to_owned(),
            proxy_origin: proxy_origin.clone(),
            allowed_destinations: vec![hop2_dest_origin.clone()],
            generation: 1,
            scope_epoch: 1,
        };

        let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), move |p, d| {
            if p == &proxy_origin && d == &hop2_dest_origin {
                Ok(Some(record.clone()))
            } else {
                Err(NetworkError::Offline)
            }
        }));

        let capability = NetworkCapability::offline()
            .with_domain("127.0.0.1")
            .with_domain("localhost");

        let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
        let service = HttpNetworkService::with_proxy_bypass_and_provider(
            capability,
            &proxy_url,
            "localhost", // localhost is bypassed; 127.0.0.1 is proxied
            provider,
        )
        .expect("service");

        let start_url = format!("http://localhost:{}/start", initial_target.port);
        let response = service
            .request(&Request::get(&start_url))
            .expect("redirect followed to proxied destination");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"proxied-hop2-payload");

        // Hop 1 was bypassed (0 provider calls). Hop 2 was proxied (1 provider call). Total = 1!
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "provider must be called only for proxied hop 2, not bypassed hop 1"
        );
        assert_eq!(initial_target.hits(), 1);
        assert_eq!(proxy.hits(), 1);

        initial_target.stop_and_join();
        proxy.stop_and_join();
    }
}

#[test]
fn malformed_proxy_variable_fails_service_closed_without_being_ignored() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), |_, _| {
        panic!("provider must never be reached when proxy is malformed");
    }));

    let capability = NetworkCapability::offline().with_domain("127.0.0.1");

    // 1. Explicit invalid URL fails construction closed
    let err1 = HttpNetworkService::with_proxy_bypass_and_provider(
        capability.clone(),
        "://malformed-proxy-scheme",
        "",
        provider.clone(),
    );
    assert_eq!(err1.err(), Some(NetworkError::Offline));

    // 2. Explicit URL with userinfo fails construction closed
    let err2 = HttpNetworkService::with_proxy_bypass_and_provider(
        capability.clone(),
        "http://user:pass@127.0.0.1:8080",
        "",
        provider,
    );
    assert_eq!(err2.err(), Some(NetworkError::Offline));

    // Provider was never invoked
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn provider_failure_or_mismatch_fails_closed_without_fallback_to_direct_or_unauthenticated() {
    let origin = Probe::start(|_| ok_response(b"origin-direct-must-not-be-reached"));
    let proxy = Probe::start(|_| ok_response(b"proxy-must-not-be-reached"));

    let proxy_origin =
        CanonicalOrigin::parse(&format!("http://127.0.0.1:{}", proxy.port)).expect("origin");
    let dest_origin =
        CanonicalOrigin::parse(&format!("http://127.0.0.1:{}", origin.port)).expect("origin");

    let capability = NetworkCapability::offline().with_domain("127.0.0.1");
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);

    // Case 1: Provider returns Err(NetworkError::Offline)
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), |_, _| {
            Err(NetworkError::Offline)
        }));
        let service = HttpNetworkService::with_proxy_bypass_and_provider(
            capability.clone(),
            &proxy_url,
            "",
            provider,
        )
        .expect("service");

        let err = service
            .request(&Request::get(format!(
                "http://127.0.0.1:{}/data",
                origin.port
            )))
            .expect_err("must fail closed on provider error");
        assert_eq!(err, NetworkError::Offline);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(origin.hits(), 0);
        assert_eq!(proxy.hits(), 0);
    }

    // Case 2: Provider returns Ok(None) (missing record)
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), |_, _| Ok(None)));
        let service = HttpNetworkService::with_proxy_bypass_and_provider(
            capability.clone(),
            &proxy_url,
            "",
            provider,
        )
        .expect("service");

        let err = service
            .request(&Request::get(format!(
                "http://127.0.0.1:{}/data",
                origin.port
            )))
            .expect_err("must fail closed when provider returns None");
        assert_eq!(err, NetworkError::Offline);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(origin.hits(), 0);
        assert_eq!(proxy.hits(), 0);
    }

    // Case 3: Provider returns record with mismatched proxy origin
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let other_proxy = CanonicalOrigin::parse("http://127.0.0.1:54321").expect("origin");
        let mismatch_record = ProxyCredentialRecord {
            id: "mismatch-proxy".to_owned(),
            proxy_origin: other_proxy,
            allowed_destinations: vec![dest_origin.clone()],
            generation: 1,
            scope_epoch: 1,
        };
        let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), move |_, _| {
            Ok(Some(mismatch_record.clone()))
        }));
        let service = HttpNetworkService::with_proxy_bypass_and_provider(
            capability.clone(),
            &proxy_url,
            "",
            provider,
        )
        .expect("service");

        let err = service
            .request(&Request::get(format!(
                "http://127.0.0.1:{}/data",
                origin.port
            )))
            .expect_err("must fail closed on proxy origin mismatch");
        assert_eq!(err, NetworkError::Offline);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(origin.hits(), 0);
        assert_eq!(proxy.hits(), 0);
    }

    // Case 4: Provider returns record with mismatched destination origin
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let other_dest = CanonicalOrigin::parse("http://127.0.0.1:54322").expect("origin");
        let mismatch_record = ProxyCredentialRecord {
            id: "mismatch-dest".to_owned(),
            proxy_origin: proxy_origin.clone(),
            allowed_destinations: vec![other_dest],
            generation: 1,
            scope_epoch: 1,
        };
        let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), move |_, _| {
            Ok(Some(mismatch_record.clone()))
        }));
        let service = HttpNetworkService::with_proxy_bypass_and_provider(
            capability, &proxy_url, "", provider,
        )
        .expect("service");

        let err = service
            .request(&Request::get(format!(
                "http://127.0.0.1:{}/data",
                origin.port
            )))
            .expect_err("must fail closed on destination origin mismatch");
        assert_eq!(err, NetworkError::Offline);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(origin.hits(), 0);
        assert_eq!(proxy.hits(), 0);
    }

    origin.stop_and_join();
    proxy.stop_and_join();
}

#[test]
fn websocket_bypassed_handshake_makes_zero_provider_calls() {
    let ws_server = WsEchoServer::start();
    let proxy = Probe::start(|_| ok_response(b"proxy-must-stay-unused"));
    let calls = Arc::new(AtomicUsize::new(0));

    let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), |_, _| {
        panic!("provider must not be called for bypassed WebSocket handshake");
    }));

    let capability = NetworkCapability::offline().with_domain("127.0.0.1");
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let service = HttpNetworkService::with_proxy_bypass_and_provider(
        capability,
        &proxy_url,
        "127.0.0.1", // bypassed
        provider,
    )
    .expect("service");

    let ws_url = format!("ws://127.0.0.1:{}/ws", ws_server.port);
    let mut socket = service
        .websocket(&WebSocketRequest::new(&ws_url))
        .expect("bypassed handshake connects directly");

    // Echo test to verify live direct socket
    socket
        .send(WsMessage::Text("hello-bypassed-ws".to_owned()))
        .expect("send succeeds");
    let echoed = socket
        .recv_with_timeout(Duration::from_secs(5))
        .expect("recv succeeds");
    assert_eq!(echoed, WsMessage::Text("hello-bypassed-ws".to_owned()));

    // Verification of Criterion 11 requirements
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "bypassed WebSocket handshake makes exactly 0 provider calls"
    );
    assert_eq!(proxy.hits(), 0, "proxy must not be contacted");
    assert!(
        ws_server.tcp_hits() >= 1,
        "direct ws server must receive connection"
    );

    let _ = socket.close();
    ws_server.stop_and_join();
    proxy.stop_and_join();
}

#[test]
fn websocket_non_bypass_resolves_provider_and_fails_closed_on_mismatch() {
    let ws_server = WsEchoServer::start();
    let proxy = Probe::start(|_| ok_response(b"proxy-must-stay-unused"));
    let calls = Arc::new(AtomicUsize::new(0));

    let proxy_origin =
        CanonicalOrigin::parse(&format!("http://127.0.0.1:{}", proxy.port)).expect("origin");
    let other_dest = CanonicalOrigin::parse("ws://127.0.0.1:59999").expect("origin");

    // Provider returns record with mismatched destination origin
    let mismatch_record = ProxyCredentialRecord {
        id: "mismatched-ws-dest".to_owned(),
        proxy_origin,
        allowed_destinations: vec![other_dest],
        generation: 1,
        scope_epoch: 1,
    };

    let provider = Arc::new(MockProxyProvider::new(Arc::clone(&calls), move |_, _| {
        Ok(Some(mismatch_record.clone()))
    }));

    let capability = NetworkCapability::offline().with_domain("127.0.0.1");
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let service = HttpNetworkService::with_proxy_bypass_and_provider(
        capability, &proxy_url, "", // NOT bypassed: must resolve provider
        provider,
    )
    .expect("service");

    let ws_url = format!("ws://127.0.0.1:{}/ws", ws_server.port);
    let result = service.websocket(&WebSocketRequest::new(&ws_url));

    assert_eq!(
        result.err(),
        Some(NetworkError::Offline),
        "mismatched provider record must fail closed with NetworkError::Offline"
    );

    // Provider was resolved exactly once
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "provider was resolved for non-bypassed WebSocket request"
    );

    // Neither the proxy nor the destination server was dialed after provider mismatch
    assert_eq!(proxy.hits(), 0);
    assert_eq!(ws_server.tcp_hits(), 0);

    ws_server.stop_and_join();
    proxy.stop_and_join();
}
