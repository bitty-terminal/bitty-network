//! Acceptance tests for the embedded HTTP backend (issue #4).
//!
//! All servers are loopback `TcpListener`s on ephemeral ports: no external
//! network, no hardcoded ports. Coverage: plain round-trip through the
//! shared client, loopback bypass of an environment proxy, explicit ambient
//! proxy routing and credential rejection, timeout fail-closed with typed
//! [`NetworkError::Timeout`], capability-denied requests never touching a
//! socket, explicit-proxy routing, fail-closed WebSocket, and redirect
//! re-authorization (issue #37): same-origin hops followed with headers
//! intact, cross-origin hops stripped of sensitive headers, denied second
//! hops never sent, redirect loops stopped at the hop limit, and a hop chain
//! bounded by the caller's single deadline. The egress controls on every
//! reqwest client are pinned by a source-level assertion, because the
//! ambient system-proxy control they carry is inert under the pinned
//! reqwest feature set.
//!
//! [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout

#![cfg(feature = "http")]
#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::process::Stdio;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitty_network::http::MAX_REDIRECT_HOPS;
use bitty_network::{
    HttpNetworkService, NetworkCapability, NetworkError, NetworkService, Request, WebSocketRequest,
};

/// Loopback probe server: counts accepted connections, records the first
/// request head, and answers every connection with `handler(head)`.
///
/// The accept loop is non-blocking so [`Probe::stop_and_join`] always
/// terminates, including when zero connections arrive (the denied case).
struct Probe {
    port: u16,
    hits: Arc<AtomicUsize>,
    first_request: Arc<Mutex<Option<String>>>,
    all_requests: Arc<Mutex<Vec<String>>>,
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
        let all_requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_hits = Arc::clone(&hits);
        let thread_first = Arc::clone(&first_request);
        let thread_all = Arc::clone(&all_requests);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Accepted sockets inherit the listener's
                        // non-blocking mode on Windows and macOS (Linux
                        // clears it): restore blocking mode so the read
                        // timeout in `read_head` actually blocks.
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
                        if let Ok(mut guard) = thread_all.lock() {
                            guard.push(head.clone());
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
            all_requests,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn first_request(&self) -> Option<String> {
        self.first_request
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Every request head seen so far, in arrival order (redirect tests
    /// assert per-hop forwarding from this).
    fn requests(&self) -> Vec<String> {
        self.all_requests
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one request head (up to the blank line); server-side sloppiness is
/// fine because the client-side assertions carry the test.
fn read_head(mut stream: std::net::TcpStream) -> String {
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

/// Minimal framed HTTP/1.1 200 response with an explicit length.
fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn allow_loopback() -> HttpNetworkService {
    HttpNetworkService::new(NetworkCapability::offline().with_domain("127.0.0.1"))
}

const PROXY_CHILD_MODE: &str = "BITTY_NETWORK_PROXY_CHILD_MODE";
const PROXY_CHILD_ORIGIN: &str = "BITTY_NETWORK_PROXY_CHILD_ORIGIN";
const PROXY_CHILD_TEST: &str = "ambient_proxy_environment_is_explicit_and_credential_safe";
const PROXY_ENV_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];
const PROXY_BYPASS_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];
const PROXY_USER_FIXTURE: &str = "fixture-user";
const PROXY_PASSWORD_FIXTURE: &str = "fixture-pass";
const PROXY_CHILD_WAIT: Duration = Duration::from_secs(5);
const PROXY_CHILD_POLL: Duration = Duration::from_millis(10);

fn run_proxy_child() -> bool {
    let Ok(mode) = std::env::var(PROXY_CHILD_MODE) else {
        return false;
    };
    let origin = std::env::var(PROXY_CHILD_ORIGIN).expect("proxy child origin");
    let service = allow_loopback();
    match mode.as_str() {
        "credentials" => {
            let error = service
                .request(&Request::get(origin))
                .expect_err("credentialed ambient proxy must fail closed");
            let exposed = [
                format!("{service:?}"),
                format!("{error}"),
                format!("{error:?}"),
            ];
            assert!(
                exposed.iter().all(|value| {
                    !value.contains(PROXY_USER_FIXTURE) && !value.contains(PROXY_PASSWORD_FIXTURE)
                }),
                "credentialed proxy data reached observable output"
            );
        }
        "route" => {
            let response = service
                .request(&Request::get(origin))
                .expect("ambient HTTP proxy route succeeds");
            assert_eq!(response.body, b"via-proxy");
        }
        _ => panic!("unknown proxy child mode"),
    }
    true
}

fn run_proxy_child_process(
    mode: &str,
    variable: &str,
    proxy_url: &str,
    all_proxy_url: Option<&str>,
    origin_url: &str,
) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().expect("test binary"));
    command
        .arg(PROXY_CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .env(PROXY_CHILD_MODE, mode)
        .env(PROXY_CHILD_ORIGIN, origin_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in PROXY_ENV_VARS {
        command.env_remove(name);
    }
    for name in PROXY_BYPASS_VARS {
        command.env_remove(name);
    }
    command.env(variable, proxy_url);
    if let Some(all_proxy_url) = all_proxy_url {
        command.env("ALL_PROXY", all_proxy_url);
    }
    let mut child = command.spawn().expect("proxy child process");
    let deadline = Instant::now() + PROXY_CHILD_WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                panic!("proxy child process exceeded its wait bound");
            }
            Ok(None) => thread::sleep(PROXY_CHILD_POLL),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                panic!("proxy child process wait failed: {error}");
            }
        }
    }
    child.wait_with_output().expect("proxy child output")
}

#[test]
fn round_trip_get_through_shared_client() {
    let probe = Probe::start(|_| ok_response(b"hello"));
    let service = allow_loopback();

    let response = service
        .request(&Request::get(probe.url("/path")).with_header("Accept", "text/plain"))
        .expect("loopback round-trip succeeds");

    assert_eq!(response.status, 200);
    assert!(response.is_success());
    assert_eq!(response.body, b"hello");
    assert_eq!(response.header("content-type"), Some("text/plain"));
    let seen = probe.first_request().expect("server saw the request");
    assert!(
        seen.starts_with("GET /path "),
        "origin-form request line, got: {seen:?}"
    );

    // The same instance serves a second request: the client is shared, not
    // rebuilt per call.
    let again = service
        .request(&Request::get(probe.url("/second")))
        .expect("second round-trip succeeds");
    assert_eq!(again.body, b"hello");
    assert_eq!(probe.hits(), 2);

    probe.stop_and_join();
}

#[test]
fn loopback_bypasses_environment_proxy() {
    // Trivially green where no proxy env exists; where one does (dev
    // sandbox), success proves NO_PROXY bypass: the ambient proxy could never
    // reach loopback, so reaching it means the bypass matched.
    let probe = Probe::start(|_| ok_response(b"direct"));
    let service = allow_loopback();

    let response = service
        .request(&Request::get(probe.url("/")))
        .expect("loopback bypasses environment proxy");

    assert_eq!(response.body, b"direct");
    probe.stop_and_join();
}

#[test]
fn ambient_proxy_environment_is_explicit_and_credential_safe() {
    if run_proxy_child() {
        return;
    }

    for variable in PROXY_ENV_VARS {
        let origin = Probe::start(|_| ok_response(b"origin-must-stay-unused"));
        let proxy = Probe::start(|_| ok_response(b"proxy-must-stay-unused"));
        let proxy_url = format!(
            "http://{PROXY_USER_FIXTURE}:{PROXY_PASSWORD_FIXTURE}@{}",
            proxy.url("/").trim_start_matches("http://")
        );
        let output =
            run_proxy_child_process("credentials", variable, &proxy_url, None, &origin.url("/"));
        let origin_hits = origin.hits();
        let proxy_hits = proxy.hits();
        origin.stop_and_join();
        proxy.stop_and_join();
        let captured = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !captured.contains(PROXY_USER_FIXTURE)
                && !captured.contains(PROXY_PASSWORD_FIXTURE)
                && !captured.contains(&proxy_url),
            "proxy credential reached child output"
        );
        assert!(output.status.success(), "proxy credential child failed");
        assert_eq!(origin_hits, 0, "rejected proxy request reached origin");
        assert_eq!(proxy_hits, 0, "rejected proxy request reached proxy");
    }

    let origin = Probe::start(|_| ok_response(b"origin-must-stay-unused"));
    let proxy = Probe::start(|_| ok_response(b"via-proxy"));
    let all_proxy = Probe::start(|_| ok_response(b"via-all"));
    let output = run_proxy_child_process(
        "route",
        "HTTP_PROXY",
        &proxy.url("/"),
        Some(&all_proxy.url("/")),
        &origin.url("/"),
    );
    let origin_hits = origin.hits();
    let proxy_hits = proxy.hits();
    let all_proxy_hits = all_proxy.hits();
    origin.stop_and_join();
    proxy.stop_and_join();
    all_proxy.stop_and_join();
    assert!(output.status.success(), "ambient proxy route child failed");
    assert_eq!(origin_hits, 0, "ambient HTTP_PROXY was silently ignored");
    assert_eq!(
        proxy_hits, 1,
        "ambient HTTP_PROXY did not use the explicit route"
    );
    assert_eq!(
        all_proxy_hits, 0,
        "ALL_PROXY overrode the scheme-specific HTTP_PROXY"
    );
}

#[test]
fn timeout_fails_closed_with_typed_error() {
    let probe = Probe::start(|_| {
        thread::sleep(Duration::from_secs(2));
        ok_response(b"too late")
    });
    let service = allow_loopback();
    let deadline = Duration::from_millis(150);

    let error = service
        .request(&Request::get(probe.url("/slow")).with_timeout(deadline))
        .expect_err("slow origin must fail closed");

    assert_eq!(error, NetworkError::Timeout { after: deadline });
    // The request WAS sent (proving this is a timeout, not a denial) and the
    // body never arrived.
    assert_eq!(probe.hits(), 1);

    probe.stop_and_join();
}

#[test]
fn capability_denied_never_sends() {
    let probe = Probe::start(|_| ok_response(b"must not send"));
    let capped = HttpNetworkService::new(NetworkCapability::offline().with_domain("example.com"));

    assert_eq!(
        capped.request(&Request::get(probe.url("/"))),
        Err(NetworkError::Denied {
            domain: "127.0.0.1".to_owned()
        })
    );

    let deny_all = HttpNetworkService::default();
    assert_eq!(
        deny_all.request(&Request::get(probe.url("/"))),
        Err(NetworkError::Offline)
    );

    // The denial path performs zero I/O by construction; the pause only
    // guards against bizarre scheduling before asserting silence.
    thread::sleep(Duration::from_millis(150));
    assert_eq!(probe.hits(), 0);

    probe.stop_and_join();
}

#[test]
fn explicit_proxy_routes_through_proxy() {
    let origin = Probe::start(|_| ok_response(b"origin-direct"));
    let origin_url = origin.url("/from-origin");
    let proxy = Probe::start(|_| ok_response(b"via-proxy"));
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let service = HttpNetworkService::with_proxy(
        NetworkCapability::offline().with_domain("127.0.0.1"),
        &proxy_url,
    )
    .expect("valid proxy url");

    let response = service
        .request(&Request::get(origin_url))
        .expect("proxied request succeeds");

    assert_eq!(response.body, b"via-proxy");
    let seen = proxy.first_request().expect("proxy saw the request");
    assert!(
        seen.starts_with("GET http://127.0.0.1:"),
        "absolute-form request line at proxy, got: {seen:?}"
    );
    // The origin never saw a direct connection: everything went via proxy.
    assert_eq!(origin.hits(), 0);

    proxy.stop_and_join();
    origin.stop_and_join();
}

/// Without the `websocket` feature the handshake stays fail-closed: even an
/// allowed host yields `Offline` (no upgrade path), and capability misses
/// surface the typed denial without touching a socket. With the feature on
/// this behavior moves to `tests/websocket.rs`.
#[cfg(not(feature = "websocket"))]
#[test]
fn websocket_stays_fail_closed() {
    let allowed = allow_loopback();
    assert_eq!(
        allowed.websocket(&WebSocketRequest::new("ws://127.0.0.1/socket")),
        Err(NetworkError::Offline)
    );

    let capped = HttpNetworkService::new(NetworkCapability::offline().with_domain("example.com"));
    assert_eq!(
        capped.websocket(&WebSocketRequest::new("ws://other.example/socket")),
        Err(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
}

/// Capability-denied handshakes never send, with or without the
/// `websocket` feature (the check runs before any socket work).
#[test]
fn websocket_denied_never_sends() {
    let capped = HttpNetworkService::new(NetworkCapability::offline().with_domain("example.com"));
    assert_eq!(
        capped
            .websocket(&WebSocketRequest::new("ws://other.example/socket"))
            .err(),
        Some(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
}

/// Bare `302` response to `location` with an empty body.
fn redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Same-origin redirect is followed with headers intact (issue #37).
///
/// One probe serves `/start` as a root-relative redirect to `/final`;
/// the second hop must carry the caller's `Authorization` header because
/// the origin did not change.
#[test]
fn same_origin_redirect_is_followed_with_headers() {
    let probe = Probe::start(|head| {
        if head.starts_with("GET /start ") {
            redirect_response("/final")
        } else {
            ok_response(b"arrived")
        }
    });
    let service = allow_loopback();

    let response = service
        .request(&Request::get(probe.url("/start")).with_header("Authorization", "Bearer loopback"))
        .expect("same-origin redirect is followed");

    assert_eq!(response.body, b"arrived");
    let seen = probe.requests();
    assert_eq!(seen.len(), 2);
    assert!(
        seen[1].starts_with("GET /final "),
        "second hop hits the destination, got: {:?}",
        seen[1]
    );
    assert!(
        seen[1]
            .to_ascii_lowercase()
            .contains("authorization: bearer loopback"),
        "same-origin hop forwards credentials, got: {:?}",
        seen[1]
    );

    probe.stop_and_join();
}

/// Cross-origin redirect strips sensitive headers (issue #37).
///
/// The redirector points at a second probe on another port (a different
/// origin); the followed hop must arrive without `Authorization` or
/// `Cookie`.
#[test]
fn cross_origin_redirect_strips_sensitive_headers() {
    let origin = Probe::start(|_| ok_response(b"cross"));
    let origin_url = origin.url("/landed");
    let redirector = Probe::start(move |_| redirect_response(&origin_url));
    let service = allow_loopback();

    let response = service
        .request(
            &Request::get(redirector.url("/start"))
                .with_header("Authorization", "Bearer loopback")
                .with_header("Cookie", "session=1"),
        )
        .expect("allowed cross-origin redirect is followed");

    assert_eq!(response.body, b"cross");
    assert_eq!(origin.hits(), 1);
    let seen = origin.first_request().expect("destination saw the hop");
    assert!(
        seen.starts_with("GET /landed "),
        "hop lands on the destination path, got: {seen:?}"
    );
    let lowered = seen.to_ascii_lowercase();
    assert!(
        !lowered.contains("authorization:"),
        "authorization stripped cross-origin, got: {seen:?}"
    );
    assert!(
        !lowered.contains("cookie:"),
        "cookie stripped cross-origin, got: {seen:?}"
    );

    redirector.stop_and_join();
    origin.stop_and_join();
}

/// A redirect hop outside the capability is denied and never sent
/// (issue #37).
///
/// The grant covers only the redirector's port, so the hop to the second
/// probe's port fails with the typed denial and the destination sees zero
/// connections.
#[test]
fn denied_second_hop_never_sends() {
    let origin = Probe::start(|_| ok_response(b"must not send"));
    let origin_url = origin.url("/landed");
    let redirector = Probe::start(move |_| redirect_response(&origin_url));
    let capped = HttpNetworkService::new(
        NetworkCapability::offline().with_domain_ports("127.0.0.1", [redirector.port]),
    );

    assert_eq!(
        capped.request(&Request::get(redirector.url("/start"))),
        Err(NetworkError::Denied {
            domain: "127.0.0.1".to_owned()
        })
    );

    assert_eq!(redirector.hits(), 1);
    thread::sleep(Duration::from_millis(150));
    assert_eq!(origin.hits(), 0);

    redirector.stop_and_join();
    origin.stop_and_join();
}

/// A redirect loop stops at the hop limit and fails closed (issue #37).
///
/// The probe redirects to itself forever; the client sends the first hop
/// plus [`MAX_REDIRECT_HOPS`] follow-ups, then reports unreachable.
#[test]
fn redirect_loop_stops_at_hop_limit() {
    let probe = Probe::start(|_| redirect_response("/loop"));
    let service = allow_loopback();

    assert_eq!(
        service.request(&Request::get(probe.url("/loop"))),
        Err(NetworkError::Offline)
    );
    assert_eq!(probe.hits(), MAX_REDIRECT_HOPS + 1);

    probe.stop_and_join();
}

/// Hops the shared-deadline chain below is built to need.
const CHAIN_HOPS: usize = 3;
/// Delay each hop of that chain spends before answering.
const CHAIN_HOP_DELAY: Duration = Duration::from_millis(550);
/// Caller deadline for the chain: under two hop delays, so the second hop
/// cannot finish even though every single hop stays inside its own budget.
const CHAIN_DEADLINE: Duration = Duration::from_millis(800);
/// Wall-clock ceiling for the chain: the shared deadline stops it near
/// [`CHAIN_DEADLINE`], while a per-hop reset needs three hop delays.
const CHAIN_ELAPSED_CEILING: Duration = Duration::from_millis(1300);

/// A redirect chain shares one request deadline.
///
/// The probe answers every hop only after [`CHAIN_HOP_DELAY`], so a
/// per-hop timeout reset would let all [`CHAIN_HOPS`] hops finish and the
/// request succeed after three delays. The shared deadline must instead
/// fail closed with the caller's deadline, having sent one hop fewer.
#[test]
fn redirect_chain_shares_one_request_deadline() {
    let served = Arc::new(AtomicUsize::new(0));
    let hop_count = Arc::clone(&served);
    let probe = Probe::start(move |head| {
        thread::sleep(CHAIN_HOP_DELAY);
        let hop = hop_count.fetch_add(1, Ordering::SeqCst);
        if head.starts_with("GET /final ") || hop + 1 == CHAIN_HOPS {
            ok_response(b"arrived")
        } else {
            redirect_response(&format!("/hop{hop}"))
        }
    });
    let service = allow_loopback();

    let started = Instant::now();
    let error = service
        .request(&Request::get(probe.url("/start")).with_timeout(CHAIN_DEADLINE))
        .expect_err("a slow hop chain must not outlive the request deadline");
    let elapsed = started.elapsed();

    assert_eq!(
        error,
        NetworkError::Timeout {
            after: CHAIN_DEADLINE
        }
    );
    assert_eq!(
        probe.hits(),
        CHAIN_HOPS - 1,
        "the chain must stop at the deadline, not run every hop"
    );
    assert!(
        elapsed < CHAIN_ELAPSED_CEILING,
        "the chain consumed {elapsed:?}, over the {CHAIN_ELAPSED_CEILING:?} bound"
    );

    probe.stop_and_join();
}

/// Every reqwest client in the crate carries the egress controls.
///
/// The pinned reqwest build omits its `system-proxy` feature, so
/// `.no_proxy()` has no observable runtime effect here and no behavioural
/// test can fail when it is dropped. This source-level assertion pins the
/// control instead: `http.rs` is the only module that builds clients, and
/// every `Client::builder()` chain in it must disable ambient proxy
/// discovery and redirect following, with no unconfigured client
/// constructor to bypass them.
#[test]
fn every_client_builder_disables_ambient_proxy_and_redirects() {
    let source = include_str!("../src/http.rs");
    let mut rest = source;
    let mut builders = 0;
    while let Some(start) = rest.find("Client::builder()") {
        builders += 1;
        let chain = &rest[start..];
        let end = chain
            .find(".build()")
            .expect("every client builder chain ends in .build()");
        let calls = &chain[..end];
        assert!(
            calls.contains(".no_proxy()"),
            "client builder {builders} omits .no_proxy()"
        );
        assert!(
            calls.contains("Policy::none()"),
            "client builder {builders} omits Policy::none()"
        );
        rest = &chain[end..];
    }
    assert!(builders > 0, "no client builder chain found in http.rs");
    for constructor in ["Client::new()", "Client::default()", "ClientBuilder::new()"] {
        assert!(
            !source.contains(constructor),
            "unconfigured client construction {constructor} bypasses the egress controls"
        );
    }
}
