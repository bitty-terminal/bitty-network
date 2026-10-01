//! `serve` engine tests over channel-backed pipes and a fake backend.

use super::*;

use std::io;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Instant;

use bitty_network_wire::GrantHost;

/// Bound on any single wait in these tests.
const WAIT: Duration = Duration::from_secs(10);

/// `Read` over chunks arriving on a channel; EOF once the sender drops.
struct ChanReader {
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// `Write` forwarding every write to a channel.
struct ChanWriter(Sender<Vec<u8>>);

impl Write for ChanWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0
            .send(data.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn chan_reader(rx: Receiver<Vec<u8>>) -> ChanReader {
    ChanReader {
        rx,
        buf: Vec::new(),
        pos: 0,
    }
}

/// What the fake backend does for one URL path.
#[derive(Clone)]
enum Behavior {
    /// `200` with a body of this many bytes (byte `i` = `i % 251`).
    Body(usize),
    /// Echo the request body back.
    Echo,
    /// Fail with this error.
    Fail(NetworkError),
    /// Block until released, then answer `200` with a short body.
    Block(Arc<(Mutex<bool>, Condvar)>),
    /// Panic inside the backend.
    Panic,
}

#[derive(Default)]
struct Fake {
    routes: Mutex<HashMap<String, Behavior>>,
    calls: Mutex<Vec<String>>,
}

impl Fake {
    fn route(self, path: &str, behavior: Behavior) -> Self {
        self.routes
            .lock()
            .expect("routes")
            .insert(path.to_owned(), behavior);
        self
    }
}

fn body_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("fits"))
        .collect()
}

impl Backend for Fake {
    fn execute(
        &self,
        capability: &NetworkCapability,
        request: &Request,
    ) -> Result<Response, NetworkError> {
        capability.check_request(request)?;
        let path = request
            .url
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_owned()))
            .unwrap_or_default();
        self.calls.lock().expect("calls").push(path.clone());
        let behavior = self.routes.lock().expect("routes").get(&path).cloned();
        let ok = |body: Vec<u8>| Response {
            status: 200,
            headers: vec![(
                "content-type".to_owned(),
                "application/octet-stream".to_owned(),
            )],
            body,
        };
        match behavior {
            Some(Behavior::Body(len)) => Ok(ok(body_bytes(len))),
            Some(Behavior::Echo) => Ok(ok(request.body.clone())),
            Some(Behavior::Fail(error)) => Err(error),
            Some(Behavior::Block(gate)) => {
                let (lock, cvar) = &*gate;
                let guard = lock.lock().expect("gate");
                let _guard = cvar
                    .wait_timeout_while(guard, WAIT, |open| !*open)
                    .expect("gate wait");
                Ok(ok(b"late".to_vec()))
            }
            Some(Behavior::Panic) => panic!("fake backend panic"),
            None => Ok(Response {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            }),
        }
    }
}

/// One running `serve` session driven from the test thread.
struct Harness {
    input: Option<Sender<Vec<u8>>>,
    output: FrameReader<ChanReader>,
    done: Receiver<ServeOutcome>,
}

impl Harness {
    fn start(backend: Fake, config: ServeConfig) -> (Self, Arc<Fake>) {
        let backend = Arc::new(backend);
        let (in_tx, in_rx) = channel();
        let (out_tx, out_rx) = channel();
        let (done_tx, done_rx) = channel();
        let serve_backend = Arc::clone(&backend);
        thread::spawn(move || {
            let outcome = serve(
                chan_reader(in_rx),
                ChanWriter(out_tx),
                serve_backend,
                &config,
            );
            let _ = done_tx.send(outcome);
        });
        (
            Self {
                input: Some(in_tx),
                output: FrameReader::new(chan_reader(out_rx)),
                done: done_rx,
            },
            backend,
        )
    }

    fn send(&self, message: &Message) {
        let frame = encode_frame(message).expect("encode");
        self.send_raw(frame);
    }

    fn send_raw(&self, bytes: Vec<u8>) {
        self.input
            .as_ref()
            .expect("input open")
            .send(bytes)
            .expect("serve alive");
    }

    fn recv(&mut self) -> Message {
        self.output
            .read_message()
            .expect("decode output")
            .expect("output frame")
    }

    fn close_input(&mut self) {
        self.input = None;
    }

    fn outcome(&self) -> ServeOutcome {
        self.done.recv_timeout(WAIT).expect("serve finished")
    }

    /// All remaining output frames after the session ends.
    fn rest(&mut self) -> Vec<Message> {
        let mut frames = Vec::new();
        while let Some(message) = self.output.read_message().expect("decode output") {
            frames.push(message);
        }
        frames
    }

    fn handshake(&mut self) {
        self.send(&hello(1, 1));
        assert_eq!(
            self.recv(),
            Message::HelloAck {
                protocol: PROTOCOL_VERSION,
                component: COMPONENT_NAME.to_owned(),
                version: COMPONENT_VERSION.to_owned(),
            }
        );
    }
}

fn hello(min: u16, max: u16) -> Message {
    Message::Hello {
        min,
        max,
        component: COMPONENT_NAME.to_owned(),
        version: "test".to_owned(),
    }
}

fn grant(host: &str, ports: &[u16]) -> Grant {
    Grant {
        hosts: vec![GrantHost {
            host: host.to_owned(),
            ports: ports.to_vec(),
        }],
        methods: None,
    }
}

fn get(id: u64, grant: Grant, url: &str) -> Message {
    Message::HttpRequest {
        id,
        plugin_id: "test-plugin".to_owned(),
        grant,
        method: Method::Get,
        url: url.to_owned(),
        headers: Vec::new(),
        timeout_ms: 0,
        max_body_bytes: 0,
        body_follows: false,
    }
}

const URL_OK: &str = "https://api.example/ok";

fn fast() -> ServeConfig {
    ServeConfig {
        shutdown_grace: Duration::from_millis(200),
        max_in_flight: MAX_IN_FLIGHT,
    }
}

/// Collect a complete response (head + body chunks) for `id`.
fn collect_response(h: &mut Harness, id: u64) -> (u16, Vec<u8>, usize) {
    let status = match h.recv() {
        Message::ResponseHead {
            id: got, status, ..
        } => {
            assert_eq!(got, id);
            status
        }
        other => panic!("expected head, got {other:?}"),
    };
    let mut body = Vec::new();
    let mut chunks = 0;
    loop {
        match h.recv() {
            Message::ResponseBody {
                id: got,
                data,
                last,
            } => {
                assert_eq!(got, id);
                assert!(data.len() <= MAX_BODY_CHUNK_BYTES);
                body.extend(data);
                chunks += 1;
                if last {
                    return (status, body, chunks);
                }
            }
            other => panic!("expected body, got {other:?}"),
        }
    }
}

#[test]
fn handshake_then_eof_exits_cleanly() {
    let (mut h, _) = Harness::start(Fake::default(), fast());
    h.handshake();
    h.close_input();
    assert_eq!(h.outcome(), ServeOutcome::Eof);
    assert_eq!(ServeOutcome::Eof.exit_code(), EXIT_OK);
    assert!(h.rest().is_empty());
}

#[test]
fn eof_before_handshake_is_clean() {
    let (mut h, _) = Harness::start(Fake::default(), fast());
    h.close_input();
    assert_eq!(h.outcome(), ServeOutcome::Eof);
}

#[test]
fn negotiation_picks_intersection() {
    assert_eq!(negotiate(1, 1), Some(1));
    assert_eq!(negotiate(0, 5), Some(1));
    assert_eq!(negotiate(2, 3), None);
    assert_eq!(negotiate(0, 0), None);
    assert_eq!(negotiate(1, 0), None);
}

fn expect_connection_error(h: &mut Harness) {
    match h.recv() {
        Message::Error { id, kind, .. } => {
            assert_eq!(id, CONNECTION_ID);
            assert_eq!(kind, ErrorKind::Protocol);
        }
        other => panic!("expected protocol error, got {other:?}"),
    }
    assert_eq!(h.outcome(), ServeOutcome::ProtocolError);
    assert_eq!(ServeOutcome::ProtocolError.exit_code(), EXIT_PROTOCOL);
}

#[test]
fn request_before_hello_is_a_protocol_error() {
    let (mut h, backend) = Harness::start(Fake::default(), fast());
    h.send(&get(1, grant("api.example", &[]), URL_OK));
    expect_connection_error(&mut h);
    assert!(backend.calls.lock().expect("calls").is_empty());
}

#[test]
fn unsupported_version_is_a_protocol_error() {
    let (mut h, _) = Harness::start(Fake::default(), fast());
    h.send(&hello(2, 4));
    expect_connection_error(&mut h);
}

#[test]
fn wrong_component_name_is_a_protocol_error() {
    let (mut h, _) = Harness::start(Fake::default(), fast());
    h.send(&Message::Hello {
        min: 1,
        max: 1,
        component: "ai".to_owned(),
        version: "x".to_owned(),
    });
    expect_connection_error(&mut h);
}

#[test]
fn garbage_after_handshake_is_a_protocol_error() {
    let (mut h, _) = Harness::start(Fake::default(), fast());
    h.handshake();
    h.send_raw(vec![0, 0, 0, 1, 0x7E]);
    expect_connection_error(&mut h);
}

#[test]
fn oversize_frame_is_a_protocol_error() {
    let (mut h, _) = Harness::start(Fake::default(), fast());
    h.handshake();
    h.send_raw(
        u32::try_from(bitty_network_wire::MAX_FRAME_BYTES + 1)
            .expect("fits")
            .to_be_bytes()
            .to_vec(),
    );
    expect_connection_error(&mut h);
}

#[test]
fn wrong_direction_message_is_a_protocol_error() {
    let (mut h, _) = Harness::start(Fake::default(), fast());
    h.handshake();
    h.send(&Message::ResponseBody {
        id: 1,
        data: Vec::new(),
        last: true,
    });
    expect_connection_error(&mut h);
}

#[test]
fn get_streams_large_body_in_bounded_chunks() {
    let len = 2 * MAX_BODY_CHUNK_BYTES + 17;
    let (mut h, _) = Harness::start(Fake::default().route("/ok", Behavior::Body(len)), fast());
    h.handshake();
    h.send(&get(1, grant("api.example", &[]), URL_OK));
    let (status, body, chunks) = collect_response(&mut h, 1);
    assert_eq!(status, 200);
    assert_eq!(chunks, 3);
    assert_eq!(body, body_bytes(len));
    h.close_input();
    assert_eq!(h.outcome(), ServeOutcome::Eof);
}

#[test]
fn empty_body_sends_single_last_chunk() {
    let (mut h, _) = Harness::start(Fake::default().route("/ok", Behavior::Body(0)), fast());
    h.handshake();
    h.send(&get(1, grant("api.example", &[]), URL_OK));
    let (status, body, chunks) = collect_response(&mut h, 1);
    assert_eq!((status, body.len(), chunks), (200, 0, 1));
}

#[test]
fn denied_and_offline_never_reach_the_backend() {
    let (mut h, backend) = Harness::start(Fake::default().route("/ok", Behavior::Body(1)), fast());
    h.handshake();
    // Host not in grant.
    h.send(&get(1, grant("other.example", &[]), URL_OK));
    // Empty grant = offline.
    h.send(&get(2, Grant::default(), URL_OK));
    // Port outside the grant.
    h.send(&get(3, grant("api.example", &[8443]), URL_OK));
    // Empty port list = scheme default only.
    h.send(&get(
        4,
        grant("api.example", &[]),
        "https://api.example:8443/ok",
    ));
    // Method outside the mask.
    let mut post_only = grant("api.example", &[]);
    post_only.methods = Some(Method::Post.bit());
    h.send(&get(5, post_only, URL_OK));
    let mut kinds = HashMap::new();
    for _ in 0..5 {
        match h.recv() {
            Message::Error { id, kind, .. } => {
                kinds.insert(id, kind);
            }
            other => panic!("expected error, got {other:?}"),
        }
    }
    assert_eq!(kinds[&1], ErrorKind::Denied);
    assert_eq!(kinds[&2], ErrorKind::Offline);
    assert_eq!(kinds[&3], ErrorKind::Denied);
    assert_eq!(kinds[&4], ErrorKind::Denied);
    assert_eq!(kinds[&5], ErrorKind::Denied);
    assert!(backend.calls.lock().expect("calls").is_empty());
}

#[test]
fn capability_from_grant_never_widens() {
    let empty = capability_from_grant(&Grant::default(), URL_OK);
    assert!(empty.is_offline());
    let cap = capability_from_grant(&grant("api.example", &[]), URL_OK);
    assert!(cap.allows_port("api.example", 443));
    assert!(!cap.allows_port("api.example", 80));
    assert!(!cap.allows("other.example"));
    let cap = capability_from_grant(&grant("api.example", &[]), "gopher://api.example/");
    assert!(!cap.allows_port("api.example", 70));
    let mut none = grant("api.example", &[]);
    none.methods = Some(0);
    let cap = capability_from_grant(&none, URL_OK);
    for method in Method::ALL {
        assert!(!cap.allows_method(api_method(method)));
    }
}

#[test]
fn backend_errors_map_to_kinds() {
    let cases = [
        (
            "/timeout",
            NetworkError::Timeout { after: WAIT },
            ErrorKind::Timeout,
        ),
        (
            "/budget",
            NetworkError::Budget { limit_bytes: 1 },
            ErrorKind::Budget,
        ),
        (
            "/count",
            NetworkError::CountBudget { limit_items: 1 },
            ErrorKind::Budget,
        ),
        ("/offline", NetworkError::Offline, ErrorKind::Offline),
    ];
    let mut fake = Fake::default();
    for (path, error, _) in &cases {
        fake = fake.route(path, Behavior::Fail(error.clone()));
    }
    let (mut h, _) = Harness::start(fake, fast());
    h.handshake();
    for (index, (path, _, kind)) in cases.iter().enumerate() {
        let id = u64::try_from(index + 1).expect("fits");
        h.send(&get(
            id,
            grant("api.example", &[]),
            &format!("https://api.example{path}"),
        ));
        match h.recv() {
            Message::Error {
                id: got, kind: k, ..
            } => assert_eq!((got, k), (id, *kind)),
            other => panic!("expected error, got {other:?}"),
        }
    }
}

#[test]
fn backend_panic_becomes_internal_error() {
    let (mut h, _) = Harness::start(Fake::default().route("/ok", Behavior::Panic), fast());
    h.handshake();
    h.send(&get(1, grant("api.example", &[]), URL_OK));
    match h.recv() {
        Message::Error { id, kind, .. } => assert_eq!((id, kind), (1, ErrorKind::Internal)),
        other => panic!("expected error, got {other:?}"),
    }
}

#[test]
fn request_body_chunks_are_accumulated() {
    let (mut h, _) = Harness::start(Fake::default().route("/ok", Behavior::Echo), fast());
    h.handshake();
    h.send(&Message::HttpRequest {
        id: 1,
        plugin_id: "p".to_owned(),
        grant: grant("api.example", &[]),
        method: Method::Post,
        url: URL_OK.to_owned(),
        headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
        timeout_ms: 1000,
        max_body_bytes: 0,
        body_follows: true,
    });
    h.send(&Message::RequestBody {
        id: 1,
        data: b"hello ".to_vec(),
        last: false,
    });
    h.send(&Message::RequestBody {
        id: 1,
        data: b"world".to_vec(),
        last: true,
    });
    let (status, body, _) = collect_response(&mut h, 1);
    assert_eq!((status, body.as_slice()), (200, &b"hello world"[..]));
}

#[test]
fn oversize_request_body_is_budget_error() {
    let (mut h, backend) = Harness::start(Fake::default().route("/ok", Behavior::Echo), fast());
    h.handshake();
    h.send(&Message::HttpRequest {
        id: 1,
        plugin_id: "p".to_owned(),
        grant: grant("api.example", &[]),
        method: Method::Post,
        url: URL_OK.to_owned(),
        headers: Vec::new(),
        timeout_ms: 0,
        max_body_bytes: 0,
        body_follows: true,
    });
    let chunk = vec![0u8; MAX_BODY_CHUNK_BYTES];
    let needed = usize::try_from(MAX_REQUEST_BODY_BYTES).expect("fits") / MAX_BODY_CHUNK_BYTES + 1;
    for _ in 0..needed {
        h.send(&Message::RequestBody {
            id: 1,
            data: chunk.clone(),
            last: false,
        });
    }
    match h.recv() {
        Message::Error { id, kind, .. } => assert_eq!((id, kind), (1, ErrorKind::Budget)),
        other => panic!("expected budget error, got {other:?}"),
    }
    assert!(backend.calls.lock().expect("calls").is_empty());
}

fn gate() -> Arc<(Mutex<bool>, Condvar)> {
    Arc::new((Mutex::new(false), Condvar::new()))
}

fn open(gate: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cvar) = &**gate;
    *lock.lock().expect("gate") = true;
    cvar.notify_all();
}

#[test]
fn duplicate_in_flight_id_is_protocol_error_for_that_id() {
    let blocker = gate();
    let (mut h, _) = Harness::start(
        Fake::default().route("/slow", Behavior::Block(Arc::clone(&blocker))),
        fast(),
    );
    h.handshake();
    let slow = "https://api.example/slow";
    h.send(&get(5, grant("api.example", &[]), slow));
    h.send(&get(5, grant("api.example", &[]), slow));
    match h.recv() {
        Message::Error { id, kind, .. } => assert_eq!((id, kind), (5, ErrorKind::Protocol)),
        other => panic!("expected duplicate error, got {other:?}"),
    }
    open(&blocker);
    let (status, body, _) = collect_response(&mut h, 5);
    assert_eq!((status, body.as_slice()), (200, &b"late"[..]));
}

#[test]
fn cancel_suppresses_the_response() {
    let blocker = gate();
    let (mut h, _) = Harness::start(
        Fake::default()
            .route("/slow", Behavior::Block(Arc::clone(&blocker)))
            .route("/ok", Behavior::Body(3)),
        fast(),
    );
    h.handshake();
    h.send(&get(
        1,
        grant("api.example", &[]),
        "https://api.example/slow",
    ));
    h.send(&Message::Cancel { id: 1 });
    // Unknown ids are ignored.
    h.send(&Message::Cancel { id: 99 });
    // A follow-up request proves the cancel was processed before release.
    h.send(&get(2, grant("api.example", &[]), URL_OK));
    let (status, _, _) = collect_response(&mut h, 2);
    assert_eq!(status, 200);
    open(&blocker);
    h.close_input();
    assert_eq!(h.outcome(), ServeOutcome::Eof);
    let rest = h.rest();
    assert!(
        rest.iter().all(|m| m.id() != Some(1)),
        "cancelled id leaked: {rest:?}"
    );
}

#[test]
fn in_flight_limit_answers_budget() {
    let blocker = gate();
    let config = ServeConfig {
        shutdown_grace: Duration::from_millis(200),
        max_in_flight: 2,
    };
    let (mut h, _) = Harness::start(
        Fake::default().route("/slow", Behavior::Block(Arc::clone(&blocker))),
        config,
    );
    h.handshake();
    for id in 1..=3 {
        h.send(&get(
            id,
            grant("api.example", &[]),
            "https://api.example/slow",
        ));
    }
    match h.recv() {
        Message::Error { id, kind, .. } => assert_eq!((id, kind), (3, ErrorKind::Budget)),
        other => panic!("expected budget error, got {other:?}"),
    }
    open(&blocker);
    let mut done = Vec::new();
    for _ in 0..4 {
        if let Message::ResponseHead { id, .. } = h.recv() {
            done.push(id);
        }
    }
    done.sort_unstable();
    assert_eq!(done, vec![1, 2]);
}

#[test]
fn shutdown_finishes_running_requests_within_grace() {
    let (mut h, _) = Harness::start(Fake::default().route("/ok", Behavior::Body(10)), fast());
    h.handshake();
    h.send(&get(1, grant("api.example", &[]), URL_OK));
    h.send(&Message::Shutdown);
    assert_eq!(h.outcome(), ServeOutcome::Shutdown);
    let rest = h.rest();
    assert!(
        rest.iter().any(|m| matches!(
            m,
            Message::ResponseBody {
                id: 1,
                last: true,
                ..
            }
        )),
        "running request should finish within grace: {rest:?}"
    );
}

#[test]
fn shutdown_abandons_stuck_requests_after_grace() {
    let blocker = gate();
    let (mut h, _) = Harness::start(
        Fake::default().route("/slow", Behavior::Block(Arc::clone(&blocker))),
        fast(),
    );
    h.handshake();
    h.send(&get(
        1,
        grant("api.example", &[]),
        "https://api.example/slow",
    ));
    let started = Instant::now();
    h.send(&Message::Shutdown);
    assert_eq!(h.outcome(), ServeOutcome::Shutdown);
    assert!(started.elapsed() < WAIT);
    let rest = h.rest();
    open(&blocker);
    assert!(rest.iter().all(|m| m.id() != Some(1)), "{rest:?}");
}

#[test]
fn closed_output_ends_the_session() {
    let backend = Arc::new(Fake::default().route("/ok", Behavior::Body(10)));
    let (in_tx, in_rx) = channel();
    let (out_tx, out_rx) = channel::<Vec<u8>>();
    drop(out_rx);
    in_tx
        .send(encode_frame(&hello(1, 1)).expect("hello"))
        .expect("send");
    in_tx
        .send(encode_frame(&get(1, grant("api.example", &[]), URL_OK)).expect("get"))
        .expect("send");
    drop(in_tx);
    let outcome = serve(chan_reader(in_rx), ChanWriter(out_tx), backend, &fast());
    assert_eq!(outcome, ServeOutcome::OutputClosed);
}
