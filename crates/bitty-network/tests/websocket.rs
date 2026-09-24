//! Acceptance tests for the capability-gated WebSocket backend (issue #7).
//!
//! All servers are loopback `TcpListener`s on ephemeral ports speaking real
//! WebSocket on the accept side: no external network, no hardcoded ports.
//! Coverage: connect + text/binary echo through the handshake,
//! capability-denied handshakes never touching a socket, deny-all offline,
//! refused-port fail-closed, handshake timeout with typed
//! [`NetworkError::Timeout`], `wss` against a plaintext speaker failing
//! closed, explicit-proxy `CONNECT` tunneling, and clean close.
//!
//! [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout

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

use bitty_network::{
    HttpNetworkService, NetworkCapability, NetworkError, NetworkService, WebSocketRequest,
    WsMessage,
};
use tungstenite::Message;

/// Loopback WebSocket echo server: accepts connections on an ephemeral
/// port, completes the handshake, and echoes text/binary messages back.
///
/// The accept loop is non-blocking so [`WsServer::stop_and_join`] always
/// terminates; each connection is served on a detached thread with read
/// timeouts so nothing lingers after a test ends.
struct WsServer {
    port: u16,
    tcp_hits: Arc<AtomicUsize>,
    echoed: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl WsServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback ws server");
        listener.set_nonblocking(true).expect("server nonblocking");
        let port = listener.local_addr().expect("server port").port();
        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let echoed = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_hits = Arc::clone(&tcp_hits);
        let thread_echoed = Arc::clone(&echoed);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Accepted sockets inherit the listener's
                        // non-blocking mode on Windows and macOS (Linux
                        // clears it): restore blocking mode so the read
                        // timeouts below actually block.
                        stream
                            .set_nonblocking(false)
                            .expect("accepted stream blocking");
                        thread_hits.fetch_add(1, Ordering::SeqCst);
                        let echoed = Arc::clone(&thread_echoed);
                        thread::spawn(move || serve_echo(stream, &echoed));
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
            echoed,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("ws://127.0.0.1:{}{path}", self.port)
    }

    fn tcp_hits(&self) -> usize {
        self.tcp_hits.load(Ordering::SeqCst)
    }

    fn echoed(&self) -> usize {
        self.echoed.load(Ordering::SeqCst)
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Serve one echo connection until the peer goes away or stalls.
fn serve_echo(stream: TcpStream, echoed: &AtomicUsize) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut socket = match tungstenite::accept(stream) {
        Ok(socket) => socket,
        Err(_) => return,
    };
    loop {
        match socket.read() {
            Ok(Message::Text(text)) => {
                echoed.fetch_add(1, Ordering::SeqCst);
                if socket.send(Message::Text(text)).is_err() {
                    break;
                }
            }
            Ok(Message::Binary(data)) => {
                echoed.fetch_add(1, Ordering::SeqCst);
                if socket.send(Message::Binary(data)).is_err() {
                    break;
                }
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
}

/// Loopback probe that accepts TCP and then holds the connection open in
/// silence: the client handshake read must expire against it.
struct SilentProbe {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SilentProbe {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent probe");
        listener.set_nonblocking(true).expect("probe nonblocking");
        let port = listener.local_addr().expect("probe port").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_hits = Arc::clone(&hits);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // See WsServer: accepted sockets inherit
                        // non-blocking mode on Windows and macOS.
                        stream
                            .set_nonblocking(false)
                            .expect("accepted stream blocking");
                        thread_hits.fetch_add(1, Ordering::SeqCst);
                        thread::spawn(move || {
                            thread::sleep(Duration::from_secs(2));
                            drop(stream);
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
            hits,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        format!("ws://127.0.0.1:{}/socket", self.port)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Minimal loopback `CONNECT` proxy: answers `200` to well-formed
/// `CONNECT host:port` lines and splices bytes to the origin, so the
/// handshake under test runs over a real tunnel.
struct ConnectProxy {
    port: u16,
    connect_line: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ConnectProxy {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind connect proxy");
        listener.set_nonblocking(true).expect("proxy nonblocking");
        let port = listener.local_addr().expect("proxy port").port();
        let connect_line = Arc::new(Mutex::new(None::<String>));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_line = Arc::clone(&connect_line);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // See WsServer: accepted sockets inherit
                        // non-blocking mode on Windows and macOS.
                        stream
                            .set_nonblocking(false)
                            .expect("accepted stream blocking");
                        let line = Arc::clone(&thread_line);
                        thread::spawn(move || serve_connect(stream, &line));
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
            connect_line,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn connect_line(&self) -> Option<String> {
        self.connect_line
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Serve one `CONNECT` exchange, then splice both directions.
fn serve_connect(client: TcpStream, line: &Mutex<Option<String>>) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
    let head = read_head(client.try_clone().expect("clone proxy stream"));
    let first_line = head.split("\r\n").next().unwrap_or("").to_owned();
    if let Ok(mut guard) = line.lock() {
        if guard.is_none() {
            *guard = Some(first_line.clone());
        }
    }
    let target = match first_line
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split_whitespace().next())
    {
        Some(target) => target.to_owned(),
        None => {
            let _ = client
                .try_clone()
                .expect("clone proxy stream")
                .write_all(b"HTTP/1.1 400 bad request\r\n\r\n");
            return;
        }
    };
    let origin = match TcpStream::connect(&target) {
        Ok(origin) => origin,
        Err(_) => {
            let _ = client
                .try_clone()
                .expect("clone proxy stream")
                .write_all(b"HTTP/1.1 502 bad gateway\r\n\r\n");
            return;
        }
    };
    if client
        .try_clone()
        .expect("clone proxy stream")
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let _ = origin.set_read_timeout(Some(Duration::from_secs(5)));
    let relay = client.try_clone().expect("clone proxy stream");
    let back = origin.try_clone().expect("clone origin stream");
    let first = thread::spawn(move || copy_until_end(relay, back));
    copy_until_end(origin, client);
    let _ = first.join();
}

/// Copy one direction until EOF or stall; timeouts keep this bounded.
fn copy_until_end(mut from: TcpStream, mut to: TcpStream) {
    let _ = from.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = to.flush();
}

/// Read one request head (up to the blank line).
fn read_head(stream: TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut stream = stream;
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

/// An ephemeral port with nothing listening: bind, read, drop.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind for closed port");
    let port = listener.local_addr().expect("closed port").port();
    drop(listener);
    port
}

fn allow_loopback() -> HttpNetworkService {
    HttpNetworkService::new(NetworkCapability::offline().with_domain("127.0.0.1"))
}

#[test]
fn connect_and_echo_text_and_binary() {
    let server = WsServer::start();
    let service = allow_loopback();

    let mut socket = service
        .websocket(&WebSocketRequest::new(server.url("/chat")))
        .expect("loopback handshake succeeds");
    assert_eq!(server.tcp_hits(), 1);

    socket
        .send(WsMessage::Text("hello".to_owned()))
        .expect("send text succeeds");
    assert_eq!(
        socket
            .recv_with_timeout(Duration::from_secs(5))
            .expect("recv text succeeds"),
        WsMessage::Text("hello".to_owned())
    );

    socket
        .send(WsMessage::Binary(vec![1, 2, 3]))
        .expect("send binary succeeds");
    assert_eq!(
        socket
            .recv_with_timeout(Duration::from_secs(5))
            .expect("recv binary succeeds"),
        WsMessage::Binary(vec![1, 2, 3])
    );
    assert_eq!(server.echoed(), 2);

    socket.close().expect("clean close succeeds");
    server.stop_and_join();
}

#[test]
fn capability_denied_never_connects() {
    let server = WsServer::start();
    let capped = HttpNetworkService::new(NetworkCapability::offline().with_domain("example.com"));

    assert_eq!(
        capped
            .websocket(&WebSocketRequest::new(server.url("/")))
            .err(),
        Some(NetworkError::Denied {
            domain: "127.0.0.1".to_owned()
        })
    );

    let deny_all = HttpNetworkService::default();
    assert_eq!(
        deny_all
            .websocket(&WebSocketRequest::new(server.url("/")))
            .err(),
        Some(NetworkError::Offline)
    );

    // The denial path performs zero I/O by construction; the pause only
    // guards against bizarre scheduling before asserting silence.
    thread::sleep(Duration::from_millis(150));
    assert_eq!(server.tcp_hits(), 0);

    server.stop_and_join();
}

#[test]
fn refused_port_fails_closed_offline() {
    let service = allow_loopback();
    let url = format!("ws://127.0.0.1:{}/socket", closed_port());

    assert_eq!(
        service.websocket(&WebSocketRequest::new(url)).err(),
        Some(NetworkError::Offline)
    );
}

#[test]
fn handshake_timeout_fails_closed_with_typed_error() {
    let probe = SilentProbe::start();
    let service = allow_loopback();
    let deadline = Duration::from_millis(150);

    let error = service
        .websocket(&WebSocketRequest::new(probe.url()).with_timeout(deadline))
        .expect_err("silent origin must fail closed");

    assert_eq!(error, NetworkError::Timeout { after: deadline });
    // The TCP connection WAS established (proving this is a handshake
    // timeout, not a denial) but no handshake completed.
    assert_eq!(probe.hits(), 1);

    probe.stop_and_join();
}

#[test]
fn wss_to_plaintext_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind plaintext probe");
    let port = listener.local_addr().expect("probe port").port();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi");
        }
    });
    let service = allow_loopback();

    // TLS against a plaintext speaker cannot complete: fail closed, never
    // a successful socket.
    assert_eq!(
        service
            .websocket(&WebSocketRequest::new(format!(
                "wss://127.0.0.1:{port}/socket"
            )))
            .err(),
        Some(NetworkError::Offline)
    );

    let _ = handle.join();
}

#[test]
fn explicit_proxy_tunnels_the_handshake() {
    let server = WsServer::start();
    let server_url = server.url("/via-proxy");
    let proxy = ConnectProxy::start();
    let service = HttpNetworkService::with_proxy(
        NetworkCapability::offline().with_domain("127.0.0.1"),
        &proxy.url(),
    )
    .expect("valid proxy url");

    let mut socket = service
        .websocket(&WebSocketRequest::new(server_url))
        .expect("proxied handshake succeeds");
    socket
        .send(WsMessage::Text("tunneled".to_owned()))
        .expect("send through tunnel succeeds");
    assert_eq!(
        socket
            .recv_with_timeout(Duration::from_secs(5))
            .expect("recv through tunnel succeeds"),
        WsMessage::Text("tunneled".to_owned())
    );
    socket.close().expect("close through tunnel succeeds");

    let seen = proxy.connect_line().expect("proxy saw the exchange");
    assert!(
        seen.starts_with("CONNECT 127.0.0.1:"),
        "CONNECT line at proxy, got: {seen:?}"
    );
    // The echo server saw exactly the tunneled connection.
    assert_eq!(server.echoed(), 1);

    proxy.stop_and_join();
    server.stop_and_join();
}
