//! Capability-gated WebSocket transport over a single sync stack.
//!
//! [`connect`] performs one handshake through tungstenite (the only
//! WebSocket dependency) and returns the open [`WebSocketSocket`]. The
//! handshake path, in order:
//!
//! 1. The caller ([`HttpNetworkService::websocket`]) checks the capability
//!    on [`WebSocketRequest::host`] FIRST: deny-all yields
//!    [`NetworkError::Offline`], an allowlist miss yields the typed
//!    [`NetworkError::Denied`], and no socket is touched in either case.
//! 2. The target is parsed from the URL (`ws`/`wss` only; anything else
//!    fails closed as [`NetworkError::Offline`]). The default ports are 80
//!    for `ws` and 443 for `wss`.
//! 3. Egress reuses the HTTP backend's proxy decision: when a proxy is
//!    configured (explicit [`HttpNetworkService::with_proxy`] or the
//!    environment) and the host is not bypassed, a `CONNECT` tunnel is
//!    opened to the proxy first and the handshake runs over it. Only HTTP
//!    proxies are supported; any other proxy scheme fails closed.
//! 4. `wss` (direct or tunneled) upgrades through rustls with native roots
//!    — the same trust approach as the HTTP backend: the platform root
//!    store, no custom CA, crypto from the shared rustls tree.
//! 5. Post-capability failures fail closed: refused/unreachable becomes
//!    [`NetworkError::Offline`], an expired handshake/read deadline becomes
//!    [`NetworkError::Timeout`].
//!
//! Timeouts: [`DEFAULT_WEBSOCKET_TIMEOUT`] bounds the handshake unless the
//! caller overrides it per request via [`WebSocketRequest::with_timeout`];
//! each [`WebSocketSocket::recv_with_timeout`] call carries its own read
//! deadline, and writes are bounded by the same default. Expired deadlines
//! always surface [`NetworkError::Timeout`].
//!
//! Out of scope (issue #7): subprotocol negotiation (offered
//! [`WebSocketRequest::protocols`] are not sent on the handshake; the server
//! proceeds with its default), custom CA / client certificates, message
//! size tuning (tungstenite defaults), and async I/O (the service stays
//! blocking).
//!
//! [`HttpNetworkService::websocket`]: crate::http::HttpNetworkService
//! [`HttpNetworkService::with_proxy`]: crate::http::HttpNetworkService::with_proxy
//! [`WebSocketRequest::host`]: bitty_network_api::WebSocketRequest::host
//! [`WebSocketRequest::with_timeout`]: bitty_network_api::WebSocketRequest::with_timeout
//! [`WebSocketRequest::protocols`]: bitty_network_api::WebSocketRequest::protocols
//! [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
//! [`NetworkError::Denied`]: bitty_network_api::NetworkError::Denied
//! [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use bitty_network_api::{NetworkError, WebSocketRequest};
use tungstenite::stream::MaybeTlsStream;

/// Default handshake deadline when the caller sets no
/// [`WebSocketRequest::timeout`], and the bound for writes on an open
/// socket.
///
/// Thirty seconds mirrors [`crate::http::DEFAULT_REQUEST_TIMEOUT`]: generous
/// for a loopback or nearby handshake, while interactive callers should set
/// tighter per-request deadlines via
/// [`WebSocketRequest::with_timeout`].
///
/// [`WebSocketRequest::timeout`]: bitty_network_api::WebSocketRequest::timeout
/// [`WebSocketRequest::with_timeout`]: bitty_network_api::WebSocketRequest::with_timeout
pub const DEFAULT_WEBSOCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// Smallest remaining slice still handed to a blocking call.
///
/// When a deadline is nearly exhausted the remaining time is clamped to this
/// floor instead of zero so the call fails with its own typed error rather
/// than returning immediately without trying.
const MIN_REMAINING: Duration = Duration::from_millis(1);

/// Cap for one `CONNECT` response head; a proxy answering with more is
/// treated as a failure (fail closed).
const MAX_CONNECT_HEAD: usize = 16_384;

/// One established WebSocket connection.
///
/// Returned by [`connect`]; owns the stream until [`WebSocketSocket::close`].
/// Ping/Pong control frames are answered by the stack and never surfaced:
/// [`WebSocketSocket::recv_with_timeout`] only returns data messages.
pub struct WebSocketSocket {
    inner: tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
}

impl std::fmt::Debug for WebSocketSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketSocket").finish_non_exhaustive()
    }
}

/// One incoming or outgoing data message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    /// UTF-8 text message.
    Text(String),
    /// Binary message.
    Binary(Vec<u8>),
}

impl WebSocketSocket {
    /// Send one data message, bounded by [`DEFAULT_WEBSOCKET_TIMEOUT`].
    pub fn send(&mut self, message: WsMessage) -> Result<(), NetworkError> {
        let outgoing = match message {
            WsMessage::Text(text) => tungstenite::Message::text(text),
            WsMessage::Binary(data) => tungstenite::Message::binary(data),
        };
        self.inner
            .send(outgoing)
            .map_err(|error| map_transport(&error, DEFAULT_WEBSOCKET_TIMEOUT))
    }

    /// Receive one data message, waiting at most `timeout`.
    ///
    /// Control frames never surface here; an expired deadline yields
    /// [`NetworkError::Timeout`], a dead connection yields
    /// [`NetworkError::Offline`].
    ///
    /// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
    /// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
    pub fn recv_with_timeout(&mut self, timeout: Duration) -> Result<WsMessage, NetworkError> {
        set_deadlines(self.inner.get_mut(), Some(timeout), None)?;
        loop {
            match self.inner.read() {
                Ok(message) => match message_to_data(message)? {
                    Some(data) => return Ok(data),
                    None => continue,
                },
                Err(error) => return Err(map_transport(&error, timeout)),
            }
        }
    }

    /// Close the connection cleanly (close frame, then drop the stream).
    ///
    /// An already-dead connection still reports success: the end state —
    /// no open socket — is what the caller asked for.
    pub fn close(mut self) -> Result<(), NetworkError> {
        match self.inner.close(None) {
            Ok(()) => Ok(()),
            Err(tungstenite::Error::ConnectionClosed) | Err(tungstenite::Error::AlreadyClosed) => {
                Ok(())
            }
            Err(error) => Err(map_transport(&error, DEFAULT_WEBSOCKET_TIMEOUT)),
        }
    }
}

/// Convert one message read by [`WebSocketSocket::recv_with_timeout`].
///
/// Returns `None` for control frames the stack already handled (Ping/Pong
/// are answered internally; a raw `Frame` never surfaces from `read`): the
/// receive loop skips them. A `Close` frame means the connection is gone
/// and fails closed as [`NetworkError::Offline`].
///
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
fn message_to_data(message: tungstenite::Message) -> Result<Option<WsMessage>, NetworkError> {
    match message {
        tungstenite::Message::Text(_) => {
            let bytes = message.into_data();
            String::from_utf8(bytes.to_vec())
                .map(WsMessage::Text)
                .map(Some)
                .map_err(|_| NetworkError::Offline)
        }
        tungstenite::Message::Binary(_) => {
            Ok(Some(WsMessage::Binary(message.into_data().to_vec())))
        }
        tungstenite::Message::Close(_) => Err(NetworkError::Offline),
        _ => Ok(None),
    }
}

/// Handshake target parsed from a `ws`/`wss` URL.
#[derive(Debug, PartialEq, Eq)]
struct WsTarget {
    /// Lowercased host without brackets or port (for dialing and the
    /// `Host`/`CONNECT` lines).
    host: String,
    /// Effective port (URL port or the scheme default).
    port: u16,
    /// True for `wss` (TLS upgrade after TCP, before the handshake).
    tls: bool,
}

/// Perform one capability-cleared handshake, returning the open socket.
///
/// The caller checks the capability on [`WebSocketRequest::host`] before
/// calling: this function performs I/O unconditionally. `proxy_url` is the
/// HTTP backend's proxy decision for the host (`Some` URL to tunnel
/// through, `None` for direct egress).
pub(crate) fn connect(
    request: &WebSocketRequest,
    proxy_url: Option<&str>,
) -> Result<WebSocketSocket, NetworkError> {
    let target = parse_target(&request.url)?;
    let deadline = request.timeout.unwrap_or(DEFAULT_WEBSOCKET_TIMEOUT);
    let started = Instant::now();
    let stream = match proxy_url {
        Some(proxy) => tunnel_via_proxy(proxy, &target, deadline, started)?,
        None => dial(&target, deadline, started)?,
    };
    // Bound the handshake itself; per-message deadlines are set on each
    // receive and writes keep the module default afterwards.
    set_timeouts(&stream, remaining(deadline, started))?;
    let url = request.url.as_str();
    // Plain and TLS handshakes unify as `WebSocket<MaybeTlsStream<_>>`:
    // `wss` upgrades inside `client_tls`, while `ws` handshakes over the
    // bare stream and is wrapped as `Plain` afterwards.
    let inner = if target.tls {
        let (socket, _) = drive(tungstenite::client_tls(url, stream), deadline, started)?;
        socket
    } else {
        let (socket, _) = drive(tungstenite::client(url, stream), deadline, started)?;
        tungstenite::WebSocket::from_raw_socket(
            MaybeTlsStream::Plain(socket.into_inner()),
            tungstenite::protocol::Role::Client,
            None,
        )
    };
    let mut socket = WebSocketSocket { inner };
    set_deadlines(
        socket.inner.get_mut(),
        None,
        Some(DEFAULT_WEBSOCKET_TIMEOUT),
    )?;
    Ok(socket)
}

/// Remaining handshake budget: the deadline minus elapsed, never below
/// [`MIN_REMAINING`] so a nearly-exhausted budget still produces the
/// call's own typed error.
fn remaining(deadline: Duration, started: Instant) -> Duration {
    deadline
        .checked_sub(started.elapsed())
        .unwrap_or(MIN_REMAINING)
        .max(MIN_REMAINING)
}

/// Parse a `ws`/`wss` URL into its dial target.
///
/// Best-effort splitting mirroring [`WebSocketRequest::host`]: strip the
/// scheme, take the authority, drop userinfo (same `rsplit('@')` rule so the
/// capability check and the dial target agree), honor IPv6 brackets. Any
/// shape that does not parse fails closed as [`NetworkError::Offline`].
///
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
fn parse_target(url: &str) -> Result<WsTarget, NetworkError> {
    let (scheme, rest) = url.split_once("://").ok_or(NetworkError::Offline)?;
    let tls = match scheme.to_lowercase().as_str() {
        "ws" => false,
        "wss" => true,
        _ => return Err(NetworkError::Offline),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
        let (host, rest) = bracketed.split_once(']').ok_or(NetworkError::Offline)?;
        let port = match rest.strip_prefix(':') {
            Some(port) => port,
            None if rest.is_empty() => "",
            None => return Err(NetworkError::Offline),
        };
        (host, port)
    } else {
        if hostport.contains(':') {
            let (host, port) = hostport.split_once(':').ok_or(NetworkError::Offline)?;
            (host, port)
        } else {
            (hostport, "")
        }
    };
    if host.is_empty() {
        return Err(NetworkError::Offline);
    }
    let port = if port.is_empty() {
        if tls { 443 } else { 80 }
    } else {
        port.parse::<u16>().map_err(|_| NetworkError::Offline)?
    };
    Ok(WsTarget {
        host: host.to_lowercase(),
        port,
        tls,
    })
}

/// Open a TCP connection to `target`, trying each resolved address in
/// order. Each attempt waits at most for the budget still left out of
/// `deadline` (tracked from `started`); the typed errors always carry the
/// configured `deadline`. Refused/unreachable/unresolvable targets fail
/// closed as [`NetworkError::Offline`].
///
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
fn dial(
    target: &WsTarget,
    deadline: Duration,
    started: Instant,
) -> Result<TcpStream, NetworkError> {
    let authority = if target.host.contains(':') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let addrs = authority
        .to_socket_addrs()
        .map_err(|_| NetworkError::Offline)?;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, remaining(deadline, started)) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return Err(NetworkError::Timeout { after: deadline });
            }
            Err(_) => continue,
        }
    }
    Err(NetworkError::Offline)
}

/// Open a `CONNECT` tunnel to `target` through the HTTP proxy at
/// `proxy_url`.
///
/// Only `http`/`https`-scheme proxies are supported (a plain TCP tunnel to
/// the proxy's host:port); anything else fails closed. A non-`200` proxy
/// answer or a stalled proxy fails closed as [`NetworkError::Offline`] /
/// [`NetworkError::Timeout`] respectively.
///
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
/// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
fn tunnel_via_proxy(
    proxy_url: &str,
    target: &WsTarget,
    deadline: Duration,
    started: Instant,
) -> Result<TcpStream, NetworkError> {
    let (scheme, rest) = proxy_url.split_once("://").ok_or(NetworkError::Offline)?;
    if !matches!(scheme.to_lowercase().as_str(), "http" | "https") {
        return Err(NetworkError::Offline);
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let (proxy_host, proxy_port) = if let Some(bracketed) = hostport.strip_prefix('[') {
        let (host, rest) = bracketed.split_once(']').ok_or(NetworkError::Offline)?;
        let port = rest.strip_prefix(':').unwrap_or("");
        (host, if port.is_empty() { "80" } else { port })
    } else if let Some((host, port)) = hostport.split_once(':') {
        (host, if port.is_empty() { "80" } else { port })
    } else {
        (hostport, "80")
    };
    if proxy_host.is_empty() {
        return Err(NetworkError::Offline);
    }
    let port: u16 = proxy_port.parse().map_err(|_| NetworkError::Offline)?;
    let proxy_target = WsTarget {
        host: proxy_host.to_lowercase(),
        port,
        tls: false,
    };
    let mut stream = dial(&proxy_target, deadline, started)?;
    set_timeouts(&stream, remaining(deadline, started))?;
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target.host, target.port, target.host, target.port
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| map_io(&error, deadline))?;
    let head = read_head(&stream, deadline)?;
    if !is_connect_success(&head) {
        return Err(NetworkError::Offline);
    }
    Ok(stream)
}

/// Read one response head (up to the blank line), capped at
/// [`MAX_CONNECT_HEAD`] bytes. The socket timeouts set by the caller bound
/// the wait; anything unreadable fails closed with `deadline` as the typed
/// timeout.
fn read_head(stream: &TcpStream, deadline: Duration) -> Result<String, NetworkError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut stream = stream;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_CONNECT_HEAD || buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(error) => return Err(map_io(&error, deadline)),
        }
    }
    String::from_utf8(buf).map_err(|_| NetworkError::Offline)
}

/// True when a proxy `CONNECT` response head carries a `200` status.
fn is_connect_success(head: &str) -> bool {
    let status_line = head.split("\r\n").next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(version), Some(status)) => {
            version.to_uppercase().starts_with("HTTP/") && status == "200"
        }
        _ => false,
    }
}

/// Set both directions' socket timeouts; local failures fail closed.
fn set_timeouts(stream: &TcpStream, timeout: Duration) -> Result<(), NetworkError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| NetworkError::Offline)
}

/// Set read/write deadlines on the stream inside an open socket (plain or
/// rustls-wrapped); local failures fail closed.
fn set_deadlines(
    stream: &mut MaybeTlsStream<TcpStream>,
    read: Option<Duration>,
    write: Option<Duration>,
) -> Result<(), NetworkError> {
    let socket: &TcpStream = match stream {
        MaybeTlsStream::Plain(socket) => socket,
        MaybeTlsStream::Rustls(tls) => tls.get_mut(),
        // `MaybeTlsStream` is non-exhaustive: any future variant fails
        // closed here rather than silently keeping stale deadlines.
        _ => return Err(NetworkError::Offline),
    };
    socket
        .set_read_timeout(read)
        .and_then(|()| socket.set_write_timeout(write))
        .map_err(|_| NetworkError::Offline)
}

/// Map a post-handshake transport failure to its typed error: expired
/// deadlines become [`NetworkError::Timeout`] carrying the effective
/// deadline; everything else fails closed as [`NetworkError::Offline`].
///
/// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
fn map_transport(error: &tungstenite::Error, after: Duration) -> NetworkError {
    match error {
        tungstenite::Error::Io(io)
            if io.kind() == std::io::ErrorKind::TimedOut
                || io.kind() == std::io::ErrorKind::WouldBlock =>
        {
            NetworkError::Timeout { after }
        }
        _ => NetworkError::Offline,
    }
}

/// Map a blocking I/O failure to its typed error (same rule as
/// [`map_transport`]).
fn map_io(error: &std::io::Error, after: Duration) -> NetworkError {
    if error.kind() == std::io::ErrorKind::TimedOut
        || error.kind() == std::io::ErrorKind::WouldBlock
    {
        NetworkError::Timeout { after }
    } else {
        NetworkError::Offline
    }
}

/// Streams a handshake can run over: expose deadline updates so every
/// resume round waits only for the budget still left.
trait HandshakeStream {
    /// Bound the next blocking round to `timeout`; local failures fail
    /// closed.
    fn set_round_timeout(&mut self, timeout: Duration) -> Result<(), NetworkError>;
}

impl HandshakeStream for TcpStream {
    fn set_round_timeout(&mut self, timeout: Duration) -> Result<(), NetworkError> {
        set_timeouts(self, timeout)
    }
}

impl HandshakeStream for MaybeTlsStream<TcpStream> {
    fn set_round_timeout(&mut self, timeout: Duration) -> Result<(), NetworkError> {
        set_deadlines(self, Some(timeout), Some(timeout))
    }
}

/// Drive a blocking handshake to completion within `deadline`.
///
/// Tungstenite reports a stalled-but-live socket as
/// [`HandshakeError::Interrupted`](tungstenite::HandshakeError::Interrupted)
/// instead of blocking: resume until the handshake completes, the socket
/// dies (typed by [`map_transport`]), or the overall `deadline` expires as
/// [`NetworkError::Timeout`]. Every resume round waits at most for the
/// budget still left, so the total never exceeds the deadline by more than
/// one final round.
///
/// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
fn drive<Role>(
    first: Result<Role::FinalResult, tungstenite::HandshakeError<Role>>,
    deadline: Duration,
    started: Instant,
) -> Result<Role::FinalResult, NetworkError>
where
    Role: tungstenite::handshake::HandshakeRole,
    Role::InternalStream: HandshakeStream,
{
    let mut pending = first;
    loop {
        match pending {
            Ok(done) => return Ok(done),
            Err(tungstenite::HandshakeError::Failure(error)) => {
                return Err(map_transport(&error, deadline));
            }
            Err(tungstenite::HandshakeError::Interrupted(mut stalled)) => {
                if started.elapsed() >= deadline {
                    return Err(NetworkError::Timeout { after: deadline });
                }
                stalled
                    .get_mut()
                    .get_mut()
                    .set_round_timeout(remaining(deadline, started))?;
                pending = stalled.handshake();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parses_ws_and_wss_defaults() {
        let plain = parse_target("ws://example.com/socket").expect("ws parses");
        assert!(!plain.tls);
        assert_eq!(plain.host, "example.com");
        assert_eq!(plain.port, 80);

        let secure = parse_target("wss://example.com:8443/s").expect("wss parses");
        assert!(secure.tls);
        assert_eq!(secure.port, 8443);

        let default_secure = parse_target("wss://example.com/").expect("wss default port");
        assert_eq!(default_secure.port, 443);
    }

    #[test]
    fn target_parsing_matches_host_extraction() {
        for url in [
            "ws://user@example.com/socket",
            "ws://example.com:8080/a?b#c",
            "WS://EXAMPLE.com/chat",
        ] {
            let request = WebSocketRequest::new(url);
            let target = parse_target(url).expect("parseable");
            assert_eq!(target.host, request.host().to_lowercase());
        }
    }

    #[test]
    fn target_parses_ipv6_userinfo_and_port() {
        let target = parse_target("ws://user@[::1]:9000/socket").expect("ipv6 parses");
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 9000);

        let bare = parse_target("ws://127.0.0.1/socket").expect("ipv4 parses");
        assert_eq!(bare.host, "127.0.0.1");
        assert_eq!(bare.port, 80);
    }

    #[test]
    fn target_rejects_non_ws_shapes() {
        for url in [
            "https://example.com/socket",
            "http://example.com/",
            "ws://",
            "ws:///no-host",
            "ws://example.com:notaport/",
            "not-a-url",
            "",
        ] {
            assert_eq!(
                parse_target(url),
                Err(NetworkError::Offline),
                "fail closed: {url}"
            );
        }
    }

    #[test]
    fn connect_success_parses_status_line() {
        assert!(is_connect_success(
            "HTTP/1.1 200 Connection Established\r\n\r\n"
        ));
        assert!(is_connect_success("http/1.0 200 ok\r\n\r\n"));
        assert!(!is_connect_success(
            "HTTP/1.1 407 Proxy Auth Required\r\n\r\n"
        ));
        assert!(!is_connect_success("HTTP/1.1 500 boom\r\n\r\n"));
        assert!(!is_connect_success("garbage"));
        assert!(!is_connect_success(""));
    }

    #[test]
    fn remaining_never_returns_zero() {
        let floor = remaining(Duration::from_secs(30), Instant::now());
        assert!(floor >= MIN_REMAINING);
        let exhausted = remaining(Duration::from_nanos(1), Instant::now());
        assert!(exhausted >= MIN_REMAINING);
    }
}
