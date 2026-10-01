//! End-to-end tests for the `bitty-net` executable over real stdio pipes.
//!
//! The success path runs against a loopback HTTP/1.1 stub on an ephemeral
//! `127.0.0.1` port (no external network, no hardcoded ports). The child is
//! spawned with a cleared environment, as the core broker does.

#![forbid(unsafe_code)]

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitty_network_wire::{
    CONNECTION_ID, ErrorKind, FrameReader, Grant, GrantHost, MAX_BODY_CHUNK_BYTES, Message, Method,
    PROTOCOL_VERSION, write_frame,
};

/// Upper bound on any wait for the child.
const WAIT: Duration = Duration::from_secs(20);

/// Size of the stub's large body: more than two wire chunks.
const LARGE_BODY_BYTES: usize = 2 * MAX_BODY_CHUNK_BYTES + 1234;

fn body_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("fits"))
        .collect()
}

/// Accept-loop poll interval of the stub (non-blocking accept).
const STUB_POLL: Duration = Duration::from_millis(10);

/// Delay the stub applies to `/slow` before answering.
const SLOW_DELAY: Duration = Duration::from_millis(500);

/// Loopback HTTP/1.1 stub answering each connection with one response.
///
/// The accept loop is non-blocking and stops on [`Stub::stop`], so a test
/// never hangs when a request is refused or cancelled before it connects.
struct Stub {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Stub {
    /// `/large` gets the large body, `/slow` answers after [`SLOW_DELAY`],
    /// anything else gets `404`.
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback stub");
        listener.set_nonblocking(true).expect("stub nonblocking");
        let port = listener.local_addr().expect("stub addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut workers = Vec::new();
            while !stop_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => workers.push(thread::spawn(move || answer(stream))),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(STUB_POLL);
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Self {
            port,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn grant(&self) -> Grant {
        Grant {
            hosts: vec![GrantHost {
                host: "127.0.0.1".to_owned(),
                ports: vec![self.port],
            }],
            methods: Some(Method::Get.bit()),
        }
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Serve one HTTP/1.1 exchange on `stream`.
fn answer(mut stream: TcpStream) {
    // Accepted sockets may inherit non-blocking mode on some platforms.
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let (status, body) = match path.as_str() {
        "/large" => ("200 OK", body_bytes(LARGE_BODY_BYTES)),
        "/slow" => {
            thread::sleep(SLOW_DELAY);
            ("200 OK", b"slow".to_vec())
        }
        _ => ("404 Not Found", Vec::new()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

/// One spawned `bitty-net` child.
struct Component {
    child: Child,
    stdin: Option<ChildStdin>,
    output: FrameReader<BufReader<ChildStdout>>,
}

impl Component {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bitty-net"))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitty-net");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Self {
            child,
            stdin: Some(stdin),
            output: FrameReader::new(BufReader::new(stdout)),
        }
    }

    fn send(&mut self, message: &Message) {
        write_frame(self.stdin.as_mut().expect("stdin open"), message).expect("write frame");
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        stdin.write_all(bytes).expect("write raw");
        stdin.flush().expect("flush");
    }

    fn recv(&mut self) -> Message {
        self.output
            .read_message()
            .expect("decode child output")
            .expect("child frame")
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Read frames until the child closes stdout.
    fn read_to_eof(&mut self) -> Vec<Message> {
        let mut frames = Vec::new();
        while let Some(message) = self.output.read_message().expect("decode child output") {
            frames.push(message);
        }
        frames
    }

    fn handshake(&mut self) {
        self.send(&Message::Hello {
            min: PROTOCOL_VERSION,
            max: PROTOCOL_VERSION,
            component: "net".to_owned(),
            version: "test".to_owned(),
        });
        match self.recv() {
            Message::HelloAck {
                protocol,
                component,
                ..
            } => {
                assert_eq!(protocol, PROTOCOL_VERSION);
                assert_eq!(component, "net");
            }
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    /// Wait for exit within [`WAIT`]; kills (only this child) on overrun.
    fn wait(mut self) -> ExitStatus {
        self.stdin = None;
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            if started.elapsed() > WAIT {
                let _ = self.child.kill();
                panic!("bitty-net did not exit within {WAIT:?}");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn get(id: u64, grant: Grant, url: String) -> Message {
    Message::HttpRequest {
        id,
        plugin_id: "test-plugin".to_owned(),
        grant,
        method: Method::Get,
        url,
        headers: vec![("accept".to_owned(), "*/*".to_owned())],
        timeout_ms: 10_000,
        max_body_bytes: 0,
        body_follows: false,
    }
}

#[test]
fn version_flag_prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_bitty-net"))
        .arg("--version")
        .env_clear()
        .output()
        .expect("run --version");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("utf-8");
    assert_eq!(
        text.trim(),
        format!("bitty-net {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_argument_is_refused() {
    let status = Command::new(env!("CARGO_BIN_EXE_bitty-net"))
        .arg("--serve-forever")
        .env_clear()
        .stderr(Stdio::null())
        .status()
        .expect("run");
    assert!(!status.success());
}

#[test]
fn handshake_then_eof_exits_zero() {
    let mut component = Component::spawn();
    component.handshake();
    component.close_stdin();
    assert_eq!(component.wait().code(), Some(0));
}

#[test]
fn eof_without_handshake_exits_zero() {
    assert_eq!(Component::spawn().wait().code(), Some(0));
}

#[test]
fn shutdown_exits_zero() {
    let mut component = Component::spawn();
    component.handshake();
    component.send(&Message::Shutdown);
    assert_eq!(component.wait().code(), Some(0));
}

#[test]
fn bad_first_message_is_protocol_error_and_exit() {
    let mut component = Component::spawn();
    component.send(&Message::Cancel { id: 1 });
    match component.recv() {
        Message::Error { id, kind, .. } => {
            assert_eq!(id, CONNECTION_ID);
            assert_eq!(kind, ErrorKind::Protocol);
        }
        other => panic!("expected protocol error, got {other:?}"),
    }
    let status = component.wait();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn garbage_frame_is_protocol_error_and_exit() {
    let mut component = Component::spawn();
    component.handshake();
    component.send_raw(&[0, 0, 0, 2, 0x41, 0x00]);
    match component.recv() {
        Message::Error { id, kind, .. } => {
            assert_eq!((id, kind), (CONNECTION_ID, ErrorKind::Protocol))
        }
        other => panic!("expected protocol error, got {other:?}"),
    }
    assert_eq!(component.wait().code(), Some(2));
}

/// Skipped on Windows: the default `HttpNetworkService::new()` may fail to
/// build a reqwest client in CI (native-tls backend cannot access the system
/// certificate store), falling back to an offline service. bitty-network's
/// own Windows CI skips HTTP tests for the same reason.
#[test]
#[cfg_attr(target_os = "windows", ignore = "HttpNetworkService may be offline")]
fn get_large_body_streams_in_chunks() {
    let stub = Stub::start();
    let mut component = Component::spawn();
    component.handshake();
    component.send(&get(1, stub.grant(), stub.url("/large")));
    let headers = match component.recv() {
        Message::ResponseHead {
            id,
            status,
            headers,
        } => {
            assert_eq!((id, status), (1, 200));
            headers
        }
        other => panic!("expected head, got {other:?}"),
    };
    assert!(
        headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    );
    let mut body = Vec::new();
    let mut chunks = 0;
    loop {
        match component.recv() {
            Message::ResponseBody { id, data, last } => {
                assert_eq!(id, 1);
                assert!(data.len() <= MAX_BODY_CHUNK_BYTES);
                body.extend(data);
                chunks += 1;
                if last {
                    break;
                }
            }
            other => panic!("expected body, got {other:?}"),
        }
    }
    assert_eq!(chunks, 3);
    assert_eq!(body, body_bytes(LARGE_BODY_BYTES));
    component.close_stdin();
    assert_eq!(component.wait().code(), Some(0));
    drop(stub);
}

#[test]
fn denied_host_and_offline_grant_never_connect() {
    // A stub that expects zero connections: the listener is only a port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let url = format!("http://127.0.0.1:{port}/large");

    let mut component = Component::spawn();
    component.handshake();
    let other_host = Grant {
        hosts: vec![GrantHost {
            host: "localhost.invalid".to_owned(),
            ports: vec![port],
        }],
        methods: None,
    };
    component.send(&get(1, other_host, url.clone()));
    match component.recv() {
        Message::Error { id, kind, .. } => assert_eq!((id, kind), (1, ErrorKind::Denied)),
        other => panic!("expected denied, got {other:?}"),
    }
    component.send(&get(2, Grant::default(), url));
    match component.recv() {
        Message::Error { id, kind, .. } => assert_eq!((id, kind), (2, ErrorKind::Offline)),
        other => panic!("expected offline, got {other:?}"),
    }
    assert!(
        listener.accept().is_err(),
        "a refused request reached the socket"
    );
    component.close_stdin();
    assert_eq!(component.wait().code(), Some(0));
}

/// Skipped on Windows: see `get_large_body_streams_in_chunks`.
#[test]
#[cfg_attr(target_os = "windows", ignore = "HttpNetworkService may be offline")]
fn cancel_suppresses_response_and_session_continues() {
    let stub = Stub::start();
    let mut component = Component::spawn();
    component.handshake();
    component.send(&get(1, stub.grant(), stub.url("/slow")));
    component.send(&Message::Cancel { id: 1 });
    // The session keeps serving: a second request answers 404 promptly.
    component.send(&get(2, stub.grant(), stub.url("/missing")));
    match component.recv() {
        Message::ResponseHead { id, status, .. } => assert_eq!((id, status), (2, 404)),
        other => panic!("expected head for id 2, got {other:?}"),
    }
    // End the session: the component's shutdown drain waits (bounded) for the
    // cancelled request if it already started; nothing for id 1 may leave.
    component.close_stdin();
    let frames = component.read_to_eof();
    assert!(
        frames.iter().all(|m| m.id() != Some(1)),
        "cancelled id leaked: {frames:?}"
    );
    assert_eq!(component.wait().code(), Some(0));
}
