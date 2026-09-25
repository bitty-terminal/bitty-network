//! Property pins for the authenticated-proxy credential decision (#25).
//!
//! `docs/decisions/25-proxy-auth.md` used to justify its control claims with
//! a hand-maintained table mapping each control to the commit that provides
//! it. That apparatus could not self-maintain, because the commit graph moves
//! every time anything merges or rebases, so three review rounds failed on
//! provenance alone. The claims it carried are restated here as executable
//! properties: a change that breaks one of these fails the suite instead of
//! silently invalidating a document.
//!
//! Every pin is scoped to the record's single base pin. When that base moves,
//! re-verify the base and revisit these tests; they are the mechanism that
//! keeps the record's code-level claims true between reviews, not a substitute
//! for re-verifying the base.
//!
//! Rules honoured here, so the pins do not violate the decision they protect:
//! no raw URL, header, request, response, connection, attachment, error, or
//! source chain is placed in an assertion message, a `dbg!`, a snapshot, or
//! captured child output. Credential-bearing values are compared with the `==`
//! operator rather than `assert_eq!`, which never formats either operand, and
//! every secret is an obvious non-secret canary named by a constant. Servers
//! are loopback `TcpListener`s on ephemeral ports and no port is hardcoded.

#![forbid(unsafe_code)]

use bitty_network::{Request, Response, WebSocketRequest};

#[cfg(feature = "http")]
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(feature = "http")]
use bitty_network::{HttpNetworkService, NetworkCapability, NetworkError, NetworkService};

/// Obvious non-secret canaries. Not a credential, and never a real one.
const CANARY_USER: &str = "pin-user";
const CANARY_PASSWORD: &str = "pin-pass";
const CANARY_TOKEN: &str = "pin-token";
const CANARY_COOKIE: &str = "pin-cookie";
const CANARY_ORIGIN_HOST: &str = "pin-origin.invalid";

/// The only address any server here binds or any client here dials.
#[cfg(feature = "http")]
const LOOPBACK: &str = "127.0.0.1";

/// Reserved, non-routable TLD: this host can never resolve, so a pin that let a
/// proxy URL through by mistake fails loudly instead of reaching an endpoint.
#[cfg(feature = "http")]
const CANARY_PROXY_HOST: &str = "pin-proxy.invalid";

/// A non-default but syntactically valid port, used only inside URL strings
/// that must be rejected before any socket is opened.
#[cfg(feature = "http")]
const CANARY_PROXY_PORT: &str = "8080";

/// Pins "Redaction and diagnostics" -> "Baseline `Debug` and API request
/// types": `HttpNetworkService` has a hand-written redacting `Debug`, and
/// formatting it with `{:?}` cannot emit a credential or the proxy URL.
///
/// Two halves, because either alone is weak. The source half fails the moment
/// the hand-written `impl` is replaced by a `#[derive(Debug)]`, including in
/// the case where the derive chain would not compile at all. The behavioural
/// half fails whenever a redaction is dropped from the hand-written `impl`,
/// because a proxy route carrying a distinctive canary host is configured
/// first and the formatted service is then scanned for it.
#[cfg(feature = "http")]
#[test]
fn http_network_service_debug_is_hand_written_and_cannot_emit_a_credential() {
    let source = include_str!("../src/http.rs");
    // The contiguous attribute/doc block directly above the declaration: any
    // other line clears it, so a `#[derive(...)]` further up cannot be
    // mistaken for one on this type.
    const DECLARATION: &str = "pub struct HttpNetworkService {";
    let mut above: Vec<&str> = Vec::new();
    let mut declared = false;
    let mut derived = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == DECLARATION {
            declared = true;
            derived = above
                .iter()
                .any(|attribute| attribute.starts_with("#[derive(") && attribute.contains("Debug"));
            break;
        }
        if trimmed.starts_with('#') || trimmed.starts_with("///") {
            above.push(trimmed);
        } else {
            above.clear();
        }
    }
    assert!(declared, "http.rs declares HttpNetworkService");
    assert!(
        !derived,
        "HttpNetworkService gained a Debug derive; the redacting hand-written impl is required"
    );
    assert!(
        source.contains("impl std::fmt::Debug for HttpNetworkService {"),
        "HttpNetworkService lost its hand-written redacting Debug impl"
    );

    let proxy_url = format!("http://{CANARY_PROXY_HOST}:{CANARY_PROXY_PORT}/");
    let service = HttpNetworkService::with_proxy(NetworkCapability::offline(), &proxy_url)
        .expect("a credential-free proxy URL is retained");
    let debug = format!("{service:?}");

    for (label, canary) in [
        ("proxy host", CANARY_PROXY_HOST),
        ("proxy port", CANARY_PROXY_PORT),
        ("proxy user", CANARY_USER),
        ("proxy password", CANARY_PASSWORD),
        ("proxy scheme", "http://"),
    ] {
        assert!(!debug.contains(canary), "service Debug emitted the {label}");
    }
    for field in [
        "HttpNetworkService",
        "capability",
        "proxy_configured",
        "proxy_rejected",
    ] {
        assert!(
            debug.contains(field),
            "service Debug lost the {field} field"
        );
    }
    assert!(
        debug.contains("proxy_configured: true"),
        "the redaction must still report that a proxy is configured"
    );
}

/// Pins "Redaction and diagnostics" -> "Serialization and equality": `Request`,
/// `WebSocketRequest`, and `Response` still derive `Debug` and `PartialEq`,
/// and the leak those derives cause is still there.
///
/// This is a tripwire, not an endorsement. Those derives are unchanged on
/// every baseline the decision reviews, so a failed equality assertion on a
/// credential-bearing value still prints it. The decision keeps flagging that
/// as an open, unmitigated state, and this test is what stops the flag from
/// going stale, because it fails in both directions:
///
/// - Remove a `Debug` derive and the `{:?}` lines stop compiling, so the
///   change cannot land unnoticed.
/// - Swap a derived `Debug` for a redacting hand-written one and the leak
///   assertions below fail, because a mitigation arrived without the decision
///   being revisited.
///
/// When the mitigation lands, this test goes with it and the decision is
/// updated in the same change. Do not weaken it to make it pass.
#[test]
fn api_vocabulary_types_still_derive_debug_and_equality_and_still_leak() {
    let credentialed_url =
        format!("https://{CANARY_USER}:{CANARY_PASSWORD}@{CANARY_ORIGIN_HOST}/p");
    let request = Request::get(credentialed_url.clone())
        .with_header("Authorization", format!("Bearer {CANARY_TOKEN}"));
    let request_twin = Request::get(credentialed_url)
        .with_header("Authorization", format!("Bearer {CANARY_TOKEN}"));
    // `==` proves `PartialEq` without formatting either operand, so no
    // credential can reach the assertion output.
    assert!(request == request_twin, "Request must stay PartialEq");
    let request_debug = format!("{request:?}");
    for (label, canary) in [
        ("request header value", CANARY_TOKEN),
        ("request url userinfo", CANARY_USER),
        ("request url password", CANARY_PASSWORD),
    ] {
        assert!(
            request_debug.contains(canary),
            "the derived Request Debug no longer emits the {label}; the decision's open item must be revisited"
        );
    }
    assert!(
        request_debug.contains("Authorization"),
        "the derived Request Debug must still print header names"
    );

    let response = Response {
        status: 401,
        headers: vec![("Set-Cookie".to_owned(), CANARY_COOKIE.to_owned())],
        body: Vec::new(),
    };
    assert!(response == response.clone(), "Response must stay PartialEq");
    assert!(
        format!("{response:?}").contains(CANARY_COOKIE),
        "the derived Response Debug no longer emits a header value; the decision's open item must be revisited"
    );

    let socket_url = format!("wss://{CANARY_USER}:{CANARY_PASSWORD}@{CANARY_ORIGIN_HOST}/socket");
    let socket = WebSocketRequest::new(socket_url.clone()).with_protocol(CANARY_TOKEN);
    assert!(
        socket == WebSocketRequest::new(socket_url).with_protocol(CANARY_TOKEN),
        "WebSocketRequest must stay PartialEq"
    );
    let socket_debug = format!("{socket:?}");
    for (label, canary) in [
        ("subprotocol", CANARY_TOKEN),
        ("socket url userinfo", CANARY_USER),
        ("socket url password", CANARY_PASSWORD),
    ] {
        assert!(
            socket_debug.contains(canary),
            "the derived WebSocketRequest Debug no longer emits the {label}; the decision's open item must be revisited"
        );
    }
}

/// Pins "Environment routing and fail-closed construction" and "Credential
/// source and scope snapshots": a credential-bearing proxy URL never reaches
/// `Proxy::all` or `.proxy()`, on the explicit path or the environment path.
///
/// The explicit half asserts the typed rejection, asserts that a loopback
/// proxy listener receives nothing, and refuses to be satisfied by refusing
/// every URL: a credential-free proxy URL must still be retained, so the
/// predicate cannot be neutered by always answering "yes".
///
/// The environment half runs in a child process, because proxy environment
/// variables are process-global. The child inherits a credentialed proxy URL,
/// must fail every request closed, must expose no canary on any observable
/// channel, and must leave both the origin and the proxy loopback probes
/// untouched. Had the credentialed URL reached a client, the proxy probe would
/// record a hit and the child would fail.
#[cfg(feature = "http")]
#[test]
fn credentialed_proxy_url_never_reaches_proxy_construction() {
    // Positive control first: refusing everything must not pass this pin.
    let clean_url = format!("http://{CANARY_PROXY_HOST}:{CANARY_PROXY_PORT}/");
    assert!(
        HttpNetworkService::with_proxy(NetworkCapability::offline(), &clean_url).is_ok(),
        "a credential-free proxy URL must still be retained"
    );

    // Explicit path. Plain userinfo, a bare user, percent-encoded userinfo, a
    // schemeless authority, and an `https` proxy scheme are all
    // credential-bearing and all rejected before retention.
    let rejected = [
        format!("http://{CANARY_USER}:{CANARY_PASSWORD}@{CANARY_PROXY_HOST}:{CANARY_PROXY_PORT}/"),
        format!("http://{CANARY_USER}@{CANARY_PROXY_HOST}:{CANARY_PROXY_PORT}/"),
        format!(
            "http://{CANARY_USER}%3A{CANARY_PASSWORD}@{CANARY_PROXY_HOST}:{CANARY_PROXY_PORT}/"
        ),
        format!("{CANARY_USER}:{CANARY_PASSWORD}@{CANARY_PROXY_HOST}:{CANARY_PROXY_PORT}"),
        format!("https://{CANARY_USER}:{CANARY_PASSWORD}@{CANARY_PROXY_HOST}/"),
    ];
    for proxy_url in &rejected {
        assert_eq!(
            HttpNetworkService::with_proxy(NetworkCapability::offline(), proxy_url).err(),
            Some(NetworkError::Offline),
            "a credential-bearing proxy URL must be rejected before retention"
        );
    }

    // Rejection happens before dialing: a credentialed proxy URL naming a
    // live loopback listener must not produce a single connection.
    let probe = LoopbackProbe::start();
    let proxy_url = format!(
        "http://{CANARY_USER}:{CANARY_PASSWORD}@{}",
        probe.authority()
    );
    assert_eq!(
        HttpNetworkService::with_proxy(
            NetworkCapability::offline().with_domain(LOOPBACK),
            &proxy_url
        )
        .err(),
        Some(NetworkError::Offline),
        "a credentialed proxy URL must be rejected before any client is built"
    );
    assert_eq!(
        probe.hits(),
        0,
        "a rejected credentialed proxy URL was dialed"
    );
    probe.stop_and_join();

    // Environment path, in a child process.
    if run_env_child() {
        return;
    }
    for variable in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        let origin = LoopbackProbe::start();
        let proxy = LoopbackProbe::start();
        let proxy_url = format!(
            "http://{CANARY_USER}:{CANARY_PASSWORD}@{}",
            proxy.authority()
        );
        let output = run_env_child_process(variable, &proxy_url, &origin.url());
        let origin_hits = origin.hits();
        let proxy_hits = proxy.hits();
        let captured = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for (label, canary) in [
            ("proxy user", CANARY_USER),
            ("proxy password", CANARY_PASSWORD),
            ("proxy url", proxy_url.as_str()),
        ] {
            assert!(
                !captured.contains(canary),
                "the {label} reached child output on the environment path"
            );
        }
        assert!(
            output.status.success(),
            "the environment-path child did not fail closed"
        );
        assert!(
            captured.contains(ENV_CHILD_SENTINEL),
            "the environment-path child ran no test; the pin proved nothing"
        );
        assert_eq!(
            proxy_hits, 0,
            "a credentialed environment proxy URL was dialed"
        );
        assert_eq!(
            origin_hits, 0,
            "a rejected credentialed environment proxy fell back to direct egress"
        );
        // Belt and braces: even if a connection had been made, no proxy
        // credential may appear in what the proxy actually received.
        assert!(
            !proxy.saw_any(&[CANARY_USER, CANARY_PASSWORD, CANARY_TOKEN]),
            "a proxy canary reached the wire on the environment path"
        );
        assert!(
            !origin.saw_any(&[CANARY_USER, CANARY_PASSWORD, CANARY_TOKEN]),
            "a proxy canary reached the origin on the environment path"
        );
        origin.stop_and_join();
        proxy.stop_and_join();
    }
}

/// Loopback probe: counts accepted connections, records each request head, and
/// answers every connection with a `200` so that a request which should never
/// have been sent would otherwise succeed loudly.
///
/// The accept loop is non-blocking, so [`LoopbackProbe::stop_and_join`] always
/// terminates, including when zero connections arrive.
#[cfg(feature = "http")]
struct LoopbackProbe {
    port: u16,
    hits: Arc<AtomicUsize>,
    first_request: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(feature = "http")]
impl LoopbackProbe {
    fn start() -> Self {
        let listener = TcpListener::bind((LOOPBACK, 0)).expect("bind loopback probe");
        listener.set_nonblocking(true).expect("probe non-blocking");
        let port = listener
            .local_addr()
            .expect("loopback probe address")
            .port();
        let hits = Arc::new(AtomicUsize::new(0));
        let first_request = Arc::new(Mutex::new(None::<String>));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_hits = Arc::clone(&hits);
        let thread_first = Arc::clone(&first_request);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets inherit the listener's non-blocking
                        // mode on Windows and macOS: restore blocking mode so the
                        // read below actually blocks.
                        stream
                            .set_nonblocking(false)
                            .expect("accepted stream blocking");
                        thread_hits.fetch_add(1, Ordering::SeqCst);
                        let head = read_head(&stream);
                        if let Ok(mut guard) = thread_first.lock() {
                            if guard.is_none() {
                                *guard = Some(head);
                            }
                        }
                        let body = b"probe-must-stay-unused";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.write_all(body);
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
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

    fn authority(&self) -> String {
        format!("{LOOPBACK}:{}", self.port)
    }

    fn url(&self) -> String {
        format!("http://{}/", self.authority())
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// True when any canary appears in the first request head this probe
    /// received. Used only to decide whether a canary reached the wire; the
    /// head itself is never printed.
    fn saw_any(&self, canaries: &[&str]) -> bool {
        self.first_request
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .is_some_and(|head| canaries.iter().any(|canary| head.contains(canary)))
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("loopback probe thread");
        }
    }
}

/// Read one HTTP request head, bounded, for the canary check only.
#[cfg(feature = "http")]
fn read_head(stream: &std::net::TcpStream) -> String {
    const MAX_HEAD: usize = 1024;
    const READ_SLICE: usize = 512;
    const HEAD_WAIT: Duration = Duration::from_millis(500);
    let mut stream = stream.try_clone().expect("clone probe stream");
    let _ = stream.set_read_timeout(Some(HEAD_WAIT));
    let mut head = Vec::new();
    let mut buffer = [0_u8; READ_SLICE];
    while head.len() < MAX_HEAD && !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                head.extend_from_slice(&buffer[..read]);
            }
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

#[cfg(feature = "http")]
const ENV_CHILD_MODE: &str = "BITTY_NETWORK_PIN_ENV_CHILD";
#[cfg(feature = "http")]
const ENV_CHILD_ORIGIN: &str = "BITTY_NETWORK_PIN_ENV_CHILD_ORIGIN";
#[cfg(feature = "http")]
const ENV_CHILD_TEST: &str = "credentialed_proxy_url_never_reaches_proxy_construction";
/// Printed by the child and required by the parent. Without it, a child whose
/// `--exact` filter matched nothing would exit `0` with an empty run and the
/// parent would read that as a pass.
#[cfg(feature = "http")]
const ENV_CHILD_SENTINEL: &str = "env-child-completed";
/// Every proxy variable, cleared in the child so the pin sees only the one it
/// sets.
#[cfg(feature = "http")]
const ENV_PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];
#[cfg(feature = "http")]
const ENV_BYPASS_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];
#[cfg(feature = "http")]
const ENV_CHILD_WAIT: Duration = Duration::from_secs(5);
#[cfg(feature = "http")]
const ENV_CHILD_POLL: Duration = Duration::from_millis(10);

/// Child half of the environment-path pin: build a service from the ambient
/// environment, require every request to fail closed, and require no canary on
/// any observable channel. Returns `true` in the child, so the parent half runs
/// in the parent only.
#[cfg(feature = "http")]
fn run_env_child() -> bool {
    if std::env::var(ENV_CHILD_MODE).is_err() {
        return false;
    }
    let origin = std::env::var(ENV_CHILD_ORIGIN).expect("environment child origin");
    let service = HttpNetworkService::new(NetworkCapability::offline().with_domain(LOOPBACK));
    let error = service
        .request(&Request::get(origin))
        .expect_err("a credentialed ambient proxy must fail closed");
    assert_eq!(error, NetworkError::Offline);
    for (channel, value) in [
        ("service Debug", format!("{service:?}")),
        ("error Display", format!("{error}")),
        ("error Debug", format!("{error:?}")),
    ] {
        for (secret, canary) in [("user", CANARY_USER), ("password", CANARY_PASSWORD)] {
            assert!(
                !value.contains(canary),
                "the {secret} reached the {channel} on the environment path"
            );
        }
    }
    println!("{ENV_CHILD_SENTINEL}");
    true
}

#[cfg(feature = "http")]
fn run_env_child_process(variable: &str, proxy_url: &str, origin_url: &str) -> Output {
    let mut command = Command::new(std::env::current_exe().expect("test binary"));
    command
        .arg(ENV_CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .env(ENV_CHILD_MODE, "1")
        .env(ENV_CHILD_ORIGIN, origin_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ENV_PROXY_VARS {
        command.env_remove(name);
    }
    for name in ENV_BYPASS_VARS {
        command.env_remove(name);
    }
    command.env(variable, proxy_url);
    let mut child = command.spawn().expect("environment child process");
    let deadline = Instant::now() + ENV_CHILD_WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                panic!("environment child process exceeded its wait bound");
            }
            Ok(None) => thread::sleep(ENV_CHILD_POLL),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                panic!("environment child process wait failed: {error}");
            }
        }
    }
    child.wait_with_output().expect("environment child output")
}
