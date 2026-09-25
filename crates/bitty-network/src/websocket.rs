//! Capability-gated WebSocket transport over a single sync stack.
//!
//! [`connect`] performs one handshake through tungstenite (the only
//! WebSocket dependency) and returns the open [`WebSocketSocket`]. The
//! handshake path, in order:
//!
//! 1. The caller ([`HttpNetworkService::websocket`]) runs
//!    `bitty_network_api::NetworkCapability::check_handshake` (host, then
//!    port) FIRST: deny-all yields [`NetworkError::Offline`], an allowlist
//!    miss yields the typed [`NetworkError::Denied`], and no socket is
//!    touched in either case. Portless handshakes fail closed.
//! 2. The target is parsed from the URL (`ws`/`wss` only; anything else
//!    fails closed as [`NetworkError::Offline`]). The default ports are 80
//!    for `ws` and 443 for `wss`.
//! 3. Egress reuses the HTTP backend's proxy decision: when a proxy is
//!    configured (explicit [`HttpNetworkService::with_proxy`] or the
//!    environment) and the host is not bypassed, a `CONNECT` tunnel is
//!    opened to the proxy first and the handshake runs over it. Only plain
//!    `http` proxies are supported: an `https` (or any other) proxy scheme
//!    fails closed as [`NetworkError::Offline`] rather than being dialed as
//!    plaintext TCP, so credentials and the handshake never travel
//!    unencrypted to a TLS-expecting proxy.
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
//! deadline, writes keep the socket's write deadline
//! ([`DEFAULT_WEBSOCKET_TIMEOUT`] unless a test narrows it), and
//! [`WebSocketSocket::close`] is bounded by
//! [`DEFAULT_WS_CLOSE_TIMEOUT`]. Deadlines live on the socket: a receive
//! re-applies the stored write deadline instead of clearing it, so a later
//! send or close after any number of receives stays bounded. Expired
//! deadlines always surface [`NetworkError::Timeout`].
//!
//! Budgets: [`MAX_WS_FRAME_BYTES`] caps one frame payload,
//! [`MAX_WS_MESSAGE_BYTES`] caps one assembled message (fragmented or not),
//! and [`MAX_WS_AGGREGATE_BYTES`] caps the cumulative payload one socket
//! delivers. All three are enforced Bitty-side before a message crosses
//! into Bitty code, and the same frame/message caps ride into the stack via
//! the handshake config so oversize wire traffic aborts early; every
//! crossing surfaces [`NetworkError::Budget`].
//!
//! Out of scope (issue #7): subprotocol negotiation (offered
//! [`WebSocketRequest::protocols`] are not sent on the handshake; the server
//! proceeds with its default), custom CA / client certificates, and async
//! I/O (the service stays blocking).
//!
//! [`HttpNetworkService::websocket`]: crate::http::HttpNetworkService
//! [`HttpNetworkService::with_proxy`]: crate::http::HttpNetworkService::with_proxy
//! [`WebSocketRequest::host`]: bitty_network_api::WebSocketRequest::host
//! [`WebSocketRequest::with_timeout`]: bitty_network_api::WebSocketRequest::with_timeout
//! [`WebSocketRequest::protocols`]: bitty_network_api::WebSocketRequest::protocols
//! [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
//! [`NetworkError::Denied`]: bitty_network_api::NetworkError::Denied
//! [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
//! [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget

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

/// Bound for [`WebSocketSocket::close`]: the close frame must leave within
/// this deadline, even when the peer stopped reading.
///
/// Ten seconds is generous for a single small frame on loopback or a nearby
/// link while still bounding a stalled peer; the value is intentionally
/// shorter than [`DEFAULT_WEBSOCKET_TIMEOUT`] because close carries no
/// payload and never needs the handshake's generosity.
pub const DEFAULT_WS_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest payload of one incoming WebSocket frame, in bytes.
///
/// Frames above this cap abort the read fail-closed with
/// [`NetworkError::Budget`] before any assembled message crosses into Bitty
/// code. One mebibyte fits generous control-adjacent traffic while keeping
/// a single frame's buffering bounded; larger payloads must fragment.
pub const MAX_WS_FRAME_BYTES: usize = 1_048_576;

/// Largest payload of one assembled WebSocket message, in bytes.
///
/// Bounds a single unfragmented message and, at the stack level, the running
/// total while fragments assemble, so a fragmented message can never exceed
/// this cap either. Crossings fail closed with [`NetworkError::Budget`].
/// Four mebibytes fits file-flavored sync traffic on an embedded client;
/// larger transfers must chunk into separate messages.
pub const MAX_WS_MESSAGE_BYTES: usize = 4_194_304;

/// Largest cumulative payload one socket delivers, in bytes.
///
/// [`WebSocketSocket`] counts every message it hands to Bitty code and fails
/// closed with [`NetworkError::Budget`] once the lifetime total would cross
/// this cap. Long-lived high-volume sockets reconnect instead of growing
/// without bound. Sixteen mebibytes is four full-size messages: enough for
/// bursty sync, tight enough to bound a runaway peer.
pub const MAX_WS_AGGREGATE_BYTES: u64 = 16_777_216;

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
///
/// The socket carries its own deadlines (`read_timeout` for the next
/// receive, `write_timeout` for sends, `close_timeout` for the close frame)
/// plus the lifetime delivery counter behind [`MAX_WS_AGGREGATE_BYTES`].
/// Every operation re-applies the stored deadlines to the stream first, so a
/// receive never clears the write deadline a later send or close needs.
pub struct WebSocketSocket {
    inner: tungstenite::WebSocket<MaybeTlsStream<TcpStream>>,
    /// Read deadline for the next receive (`None` means no bound yet).
    read_timeout: Option<Duration>,
    /// Write deadline for sends; always bounded.
    write_timeout: Duration,
    /// Write deadline for the close frame; always bounded.
    close_timeout: Duration,
    /// Cumulative payload bytes handed to Bitty code on this socket.
    received_bytes: u64,
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
    /// Send one data message, bounded by the socket's write deadline.
    ///
    /// Messages above [`MAX_WS_MESSAGE_BYTES`] fail closed with
    /// [`NetworkError::Budget`] before touching the stack, so an oversize
    /// send never moves a byte; an expired write deadline surfaces
    /// [`NetworkError::Timeout`].
    ///
    /// [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget
    /// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
    pub fn send(&mut self, message: WsMessage) -> Result<(), NetworkError> {
        let len = match &message {
            WsMessage::Text(text) => text.len(),
            WsMessage::Binary(data) => data.len(),
        } as u64;
        if len > MAX_WS_MESSAGE_BYTES as u64 {
            return Err(NetworkError::Budget {
                limit_bytes: MAX_WS_MESSAGE_BYTES as u64,
            });
        }
        self.apply_deadlines()?;
        let outgoing = match message {
            WsMessage::Text(text) => tungstenite::Message::text(text),
            WsMessage::Binary(data) => tungstenite::Message::binary(data),
        };
        self.inner
            .send(outgoing)
            .map_err(|error| map_transport(&error, self.write_timeout))
    }

    /// Receive one data message, waiting at most `timeout`.
    ///
    /// Control frames never surface here; an expired deadline yields
    /// [`NetworkError::Timeout`], a dead connection yields
    /// [`NetworkError::Offline`], and a message crossing
    /// [`MAX_WS_MESSAGE_BYTES`] or pushing the socket past
    /// [`MAX_WS_AGGREGATE_BYTES`] yields [`NetworkError::Budget`]. The
    /// socket's write deadline is re-applied alongside the new read
    /// deadline, so later sends and [`WebSocketSocket::close`] stay bounded.
    ///
    /// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
    /// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
    /// [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget
    pub fn recv_with_timeout(&mut self, timeout: Duration) -> Result<WsMessage, NetworkError> {
        self.read_timeout = Some(timeout);
        self.apply_deadlines()?;
        loop {
            match self.inner.read() {
                Ok(message) => match message_to_data(message)? {
                    Some(data) => {
                        self.check_inbound(&data)?;
                        return Ok(data);
                    }
                    None => continue,
                },
                Err(error) => return Err(map_transport(&error, timeout)),
            }
        }
    }

    /// Close the connection cleanly (close frame, then drop the stream),
    /// bounded by the socket's close deadline.
    ///
    /// The close frame carries the close deadline even when the peer stopped
    /// reading: a stalled peer surfaces [`NetworkError::Timeout`] instead of
    /// hanging. An already-dead connection still reports success: the end
    /// state — no open socket — is what the caller asked for.
    ///
    /// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
    pub fn close(mut self) -> Result<(), NetworkError> {
        let after = self.close_timeout;
        self.read_timeout = None;
        self.write_timeout = after;
        self.apply_deadlines()?;
        match self.inner.close(None) {
            Ok(()) => Ok(()),
            Err(tungstenite::Error::ConnectionClosed) | Err(tungstenite::Error::AlreadyClosed) => {
                Ok(())
            }
            Err(error) => Err(map_transport(&error, after)),
        }
    }

    /// Push the stored deadlines onto the stream.
    ///
    /// Every public operation calls this first; that is what keeps a receive
    /// from silently clearing the write deadline a later send or close
    /// relies on. Local failures fail closed.
    fn apply_deadlines(&mut self) -> Result<(), NetworkError> {
        set_deadlines(
            self.inner.get_mut(),
            self.read_timeout,
            Some(self.write_timeout),
        )
    }

    /// Enforce the inbound budgets on one assembled message before it
    /// crosses into Bitty code.
    ///
    /// A message above [`MAX_WS_MESSAGE_BYTES`] fails with that cap, and a
    /// message pushing the socket's lifetime total past
    /// [`MAX_WS_AGGREGATE_BYTES`] fails with the aggregate cap — both as
    /// [`NetworkError::Budget`]. Only delivered messages count.
    ///
    /// [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget
    fn check_inbound(&mut self, message: &WsMessage) -> Result<(), NetworkError> {
        let len = match message {
            WsMessage::Text(text) => text.len(),
            WsMessage::Binary(data) => data.len(),
        } as u64;
        if len > MAX_WS_MESSAGE_BYTES as u64 {
            return Err(NetworkError::Budget {
                limit_bytes: MAX_WS_MESSAGE_BYTES as u64,
            });
        }
        let next = self.received_bytes.saturating_add(len);
        if next > MAX_WS_AGGREGATE_BYTES {
            return Err(NetworkError::Budget {
                limit_bytes: MAX_WS_AGGREGATE_BYTES,
            });
        }
        self.received_bytes = next;
        Ok(())
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

/// Stack config carrying the Bitty budgets: one frame may hold
/// [`MAX_WS_FRAME_BYTES`], one assembled message [`MAX_WS_MESSAGE_BYTES`].
///
/// Passed to every handshake constructor below, so oversize wire traffic
/// aborts inside the stack with a capacity error (mapped to
/// [`NetworkError::Budget`] by [`map_transport`]) on top of the Bitty-side
/// checks in [`WebSocketSocket::send`] and
/// [`WebSocketSocket::check_inbound`].
///
/// [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget
fn ws_config() -> tungstenite::protocol::WebSocketConfig {
    tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WS_FRAME_BYTES))
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
    // `wss` upgrades inside `client_tls_with_config`, while `ws` handshakes
    // over the bare stream and is wrapped as `Plain` afterwards. Both carry
    // the Bitty frame/message budgets from `ws_config`.
    let inner = if target.tls {
        let (socket, _) = drive(
            tungstenite::client_tls_with_config(url, stream, Some(ws_config()), None),
            deadline,
            started,
        )?;
        socket
    } else {
        let (socket, _) = drive(
            tungstenite::client::client_with_config(url, stream, Some(ws_config())),
            deadline,
            started,
        )?;
        tungstenite::WebSocket::from_raw_socket(
            MaybeTlsStream::Plain(socket.into_inner()),
            tungstenite::protocol::Role::Client,
            Some(ws_config()),
        )
    };
    let mut socket = WebSocketSocket {
        inner,
        read_timeout: None,
        write_timeout: DEFAULT_WEBSOCKET_TIMEOUT,
        close_timeout: DEFAULT_WS_CLOSE_TIMEOUT,
        received_bytes: 0,
    };
    socket.apply_deadlines()?;
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

/// Open a `CONNECT` tunnel to `target` through the plain-HTTP proxy at
/// `proxy_url`.
///
/// Only `http`-scheme proxies are tunneled (a plain TCP connection to the
/// proxy's host:port carrying the `CONNECT` request). An `https`-scheme
/// proxy URL fails closed as [`NetworkError::Offline`]: dialing it as
/// plaintext TCP would send the `CONNECT` authority — and any proxy
/// credentials — unencrypted to a TLS-expecting endpoint, a silent
/// plaintext fallback this backend never performs. Correct TLS-then-`CONNECT`
/// proxying is follow-up scope; until then `https` proxy URLs stay rejected.
/// Any other scheme fails closed the same way. A non-`200` proxy answer or a
/// stalled proxy fails closed as [`NetworkError::Offline`] /
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
    if scheme.to_lowercase().as_str() != "http" {
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
/// deadline, capacity crossings become [`NetworkError::Budget`] carrying the
/// crossed cap, and everything else fails closed as
/// [`NetworkError::Offline`].
///
/// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
/// [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
fn map_transport(error: &tungstenite::Error, after: Duration) -> NetworkError {
    match error {
        tungstenite::Error::Io(io)
            if io.kind() == std::io::ErrorKind::TimedOut
                || io.kind() == std::io::ErrorKind::WouldBlock =>
        {
            NetworkError::Timeout { after }
        }
        tungstenite::Error::Capacity(tungstenite::error::CapacityError::MessageTooLong {
            max_size,
            ..
        }) => NetworkError::Budget {
            limit_bytes: *max_size as u64,
        },
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

    /// Write deadline narrowed for stall fixtures: short enough to keep the
    /// suite fast, long enough to stay clear of loopback jitter.
    const STALL_DEADLINE: Duration = Duration::from_millis(200);

    /// Read deadline for silent-peer fixtures.
    const SILENT_READ: Duration = Duration::from_millis(100);

    /// Bound for joining the stalled-send thread: proving the write deadline
    /// survived a receive must fail (not hang) if it regresses.
    const STALL_JOIN_BOUND: Duration = Duration::from_secs(10);

    /// Bound for a stalled close: the close deadline above is 200ms, so five
    /// seconds of grace still fails fast on a regression.
    const STALL_CLOSE_BOUND: Duration = Duration::from_secs(5);

    /// One-mebibyte chunk reused by the stall and aggregate fixtures.
    const ONE_MIB_CHUNK: usize = 1 << 20;

    /// Raw server-to-client frame opcodes for the fragmentation fixtures.
    const OPCODE_TEXT: u8 = 0x1;
    const OPCODE_BINARY: u8 = 0x2;
    const OPCODE_CONTINUE: u8 = 0x0;

    /// Bind an ephemeral loopback listener, returning it with its port.
    /// Never a fixed port; loopback only.
    fn bind_loopback() -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let port = listener.local_addr().expect("loopback addr").port();
        (listener, port)
    }

    /// Plain `ws` URL for a loopback port.
    fn loopback_url(port: u16) -> String {
        format!("ws://127.0.0.1:{port}/socket")
    }

    /// Open a client socket to a loopback port with no proxy.
    fn connect_loopback(port: u16) -> WebSocketSocket {
        let request = WebSocketRequest::new(loopback_url(port));
        connect(&request, None).expect("loopback handshake")
    }

    /// Spawn a loopback echo server (default stack config, so it accepts
    /// messages far above the Bitty caps) and return its port. Echoes
    /// `messages` data messages, then exits.
    fn spawn_echo_server(messages: usize) -> u16 {
        let (listener, port) = bind_loopback();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("loopback accept");
            let mut server = tungstenite::accept(stream).expect("server handshake");
            for _ in 0..messages {
                match server.read() {
                    Ok(message) => {
                        if server.send(message).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        port
    }

    /// Spawn a loopback peer that completes the handshake and then never
    /// reads or writes again, and return its port.
    fn spawn_stall_server() -> u16 {
        let (listener, port) = bind_loopback();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("loopback accept");
            let _server = tungstenite::accept(stream).expect("server handshake");
            std::thread::park();
        });
        port
    }

    /// Encode one server-to-client frame (never masked, per RFC 6455).
    fn encode_server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![(if fin { 0x80 } else { 0x00 }) | (opcode & 0x0F)];
        if payload.len() < 126 {
            frame.push(payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    /// Spawn a loopback peer that completes the handshake and then emits
    /// exactly `frames` as raw wire frames (`(fin, opcode, payload)`), and
    /// return its port. Bypasses the stack's own framing so the fixtures
    /// control fragmentation directly; the client must still assemble (or
    /// reject) per the budgets.
    fn spawn_raw_server(frames: Vec<(bool, u8, Vec<u8>)>) -> u16 {
        let (listener, port) = bind_loopback();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("loopback accept");
            let server = tungstenite::accept(stream).expect("server handshake");
            let mut raw = server.into_inner();
            for (fin, opcode, payload) in frames {
                let frame = encode_server_frame(fin, opcode, &payload);
                if raw.write_all(&frame).is_err() {
                    break;
                }
            }
        });
        port
    }

    /// Spawn a loopback plain-HTTP proxy: answers one `CONNECT` with 200,
    /// then speaks WebSocket on the tunneled stream (echoing `messages`),
    /// and return its port.
    fn spawn_plain_proxy(messages: usize) -> u16 {
        let (listener, port) = bind_loopback();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("proxy accept");
            let mut stream = stream;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("proxy timeout");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(1) = stream.read(&mut byte) {
                head.push(byte[0]);
                if head.len() > MAX_CONNECT_HEAD || head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
            let mut server = match tungstenite::accept(stream) {
                Ok(server) => server,
                Err(_) => return,
            };
            for _ in 0..messages {
                match server.read() {
                    Ok(message) => {
                        if server.send(message).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        port
    }

    #[test]
    fn capacity_errors_map_to_budget() {
        let error =
            tungstenite::Error::Capacity(tungstenite::error::CapacityError::MessageTooLong {
                size: 9,
                max_size: 7,
            });
        assert_eq!(
            map_transport(&error, Duration::from_secs(30)),
            NetworkError::Budget { limit_bytes: 7 }
        );
    }

    #[test]
    fn send_rejects_over_message_budget_before_wire() {
        let port = spawn_echo_server(1);
        let mut socket = connect_loopback(port);
        let over = "a".repeat(MAX_WS_MESSAGE_BYTES + 1);
        assert_eq!(
            socket.send(WsMessage::Text(over)),
            Err(NetworkError::Budget {
                limit_bytes: MAX_WS_MESSAGE_BYTES as u64
            })
        );
        // The rejected send moved no bytes: the socket still echoes.
        socket
            .send(WsMessage::Text("still-here".to_owned()))
            .expect("socket usable");
        assert_eq!(
            socket
                .recv_with_timeout(Duration::from_secs(5))
                .expect("echo"),
            WsMessage::Text("still-here".to_owned())
        );
    }

    #[test]
    fn recv_accepts_single_frame_at_frame_boundary() {
        let payload = vec![0xABu8; MAX_WS_FRAME_BYTES];
        let port = spawn_raw_server(vec![(true, OPCODE_BINARY, payload.clone())]);
        let mut socket = connect_loopback(port);
        assert_eq!(
            socket
                .recv_with_timeout(Duration::from_secs(10))
                .expect("boundary frame"),
            WsMessage::Binary(payload)
        );
    }

    #[test]
    fn recv_rejects_single_frame_over_frame_budget() {
        let payload = vec![0xABu8; MAX_WS_FRAME_BYTES + 1];
        let port = spawn_raw_server(vec![(true, OPCODE_BINARY, payload)]);
        let mut socket = connect_loopback(port);
        assert_eq!(
            socket.recv_with_timeout(Duration::from_secs(10)),
            Err(NetworkError::Budget {
                limit_bytes: MAX_WS_FRAME_BYTES as u64
            })
        );
    }

    #[test]
    fn recv_assembles_fragments_at_message_boundary() {
        // Four max-size frames assembling exactly MAX_WS_MESSAGE_BYTES.
        let chunk = vec![b'a'; MAX_WS_FRAME_BYTES];
        let frames = vec![
            (false, OPCODE_TEXT, chunk.clone()),
            (false, OPCODE_CONTINUE, chunk.clone()),
            (false, OPCODE_CONTINUE, chunk.clone()),
            (true, OPCODE_CONTINUE, chunk),
        ];
        let port = spawn_raw_server(frames);
        let mut socket = connect_loopback(port);
        assert_eq!(
            socket
                .recv_with_timeout(Duration::from_secs(15))
                .expect("assembled"),
            WsMessage::Text("a".repeat(MAX_WS_MESSAGE_BYTES))
        );
    }

    #[test]
    fn recv_rejects_fragments_over_message_budget() {
        // Five max-size frames: the fifth pushes the assembly past the cap.
        let chunk = vec![b'a'; MAX_WS_FRAME_BYTES];
        let frames = vec![
            (false, OPCODE_TEXT, chunk.clone()),
            (false, OPCODE_CONTINUE, chunk.clone()),
            (false, OPCODE_CONTINUE, chunk.clone()),
            (false, OPCODE_CONTINUE, chunk.clone()),
            (true, OPCODE_CONTINUE, chunk),
        ];
        let port = spawn_raw_server(frames);
        let mut socket = connect_loopback(port);
        assert_eq!(
            socket.recv_with_timeout(Duration::from_secs(15)),
            Err(NetworkError::Budget {
                limit_bytes: MAX_WS_MESSAGE_BYTES as u64
            })
        );
    }

    #[test]
    fn recv_rejects_lifetime_aggregate_over_budget() {
        // Sixteen frame-size messages total exactly the aggregate cap; the
        // seventeenth crossing fails. One-mebibyte messages stay single
        // frames so the frame cap never trips first.
        let port = spawn_echo_server(17);
        let mut socket = connect_loopback(port);
        let chunk = WsMessage::Binary(vec![0xCDu8; ONE_MIB_CHUNK]);
        for _ in 0..16 {
            socket.send(chunk.clone()).expect("send fits");
            let echoed = socket
                .recv_with_timeout(Duration::from_secs(15))
                .expect("echo fits");
            assert_eq!(echoed, chunk);
        }
        socket.send(chunk.clone()).expect("send still fits");
        assert_eq!(
            socket.recv_with_timeout(Duration::from_secs(15)),
            Err(NetworkError::Budget {
                limit_bytes: MAX_WS_AGGREGATE_BYTES
            })
        );
    }

    #[test]
    fn recv_timeout_leaves_socket_usable() {
        let port = spawn_echo_server(1);
        let mut socket = connect_loopback(port);
        assert_eq!(
            socket.recv_with_timeout(SILENT_READ),
            Err(NetworkError::Timeout { after: SILENT_READ })
        );
        socket
            .send(WsMessage::Text("after-timeout".to_owned()))
            .expect("send after timeout");
        assert_eq!(
            socket
                .recv_with_timeout(Duration::from_secs(5))
                .expect("echo"),
            WsMessage::Text("after-timeout".to_owned())
        );
    }

    #[test]
    fn recv_preserves_write_deadline_for_later_send() {
        let port = spawn_stall_server();
        let mut socket = connect_loopback(port);
        socket.write_timeout = STALL_DEADLINE;
        // A silent peer: the read deadline expires on its own...
        assert_eq!(
            socket.recv_with_timeout(SILENT_READ),
            Err(NetworkError::Timeout { after: SILENT_READ })
        );
        // ...and the write deadline survived it: filling the stalled peer's
        // buffers surfaces Timeout carried by the preserved write deadline.
        // Without the fix the write deadline is cleared and the send below
        // blocks forever, so the join bound turns the hang into a failure.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let chunk = WsMessage::Binary(vec![0xEFu8; ONE_MIB_CHUNK]);
            let result = loop {
                match socket.send(chunk.clone()) {
                    Err(error) => break error,
                    Ok(()) => continue,
                }
            };
            let _ = done_tx.send(result);
        });
        match done_rx.recv_timeout(STALL_JOIN_BOUND) {
            Ok(result) => assert_eq!(
                result,
                NetworkError::Timeout {
                    after: STALL_DEADLINE
                }
            ),
            Err(_) => panic!("write deadline lost across receive: stalled send never returned"),
        }
    }

    #[test]
    fn stalled_close_is_bounded_by_close_deadline() {
        let port = spawn_stall_server();
        let mut socket = connect_loopback(port);
        socket.write_timeout = STALL_DEADLINE;
        socket.close_timeout = STALL_DEADLINE;
        // Fill the peer's buffers so even the small close frame cannot leave.
        let chunk = WsMessage::Binary(vec![0xEFu8; ONE_MIB_CHUNK]);
        let fill = loop {
            match socket.send(chunk.clone()) {
                Err(error) => break error,
                Ok(()) => continue,
            }
        };
        assert_eq!(
            fill,
            NetworkError::Timeout {
                after: STALL_DEADLINE
            }
        );
        let started = Instant::now();
        assert_eq!(
            socket.close(),
            Err(NetworkError::Timeout {
                after: STALL_DEADLINE
            })
        );
        assert!(
            started.elapsed() < STALL_CLOSE_BOUND,
            "stalled close must stay bounded"
        );
    }

    #[test]
    fn https_proxy_scheme_never_dials_plaintext() {
        let (listener, port) = bind_loopback();
        let proxy_url = format!("https://127.0.0.1:{port}/");
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: 9,
            tls: false,
        };
        assert_eq!(
            tunnel_via_proxy(&proxy_url, &target, Duration::from_secs(2), Instant::now())
                .expect_err("https proxy must fail closed"),
            NetworkError::Offline
        );
        // No TCP connection may have reached the proxy: the rejection happens
        // before any dial, so nothing is pending on the listener.
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        match listener.accept() {
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
            Ok(_) => panic!("https proxy URL was dialed as plaintext TCP"),
        }
    }

    #[test]
    fn non_http_proxy_scheme_fails_closed() {
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: 9,
            tls: false,
        };
        for proxy_url in ["socks5://127.0.0.1:1080/", "ftp://127.0.0.1:21/", "://bad"] {
            assert_eq!(
                tunnel_via_proxy(proxy_url, &target, Duration::from_secs(2), Instant::now())
                    .expect_err("non-http proxy must fail closed"),
                NetworkError::Offline,
                "fail closed: {proxy_url}"
            );
        }
    }

    #[test]
    fn http_proxy_tunnel_carries_handshake() {
        let proxy = spawn_plain_proxy(1);
        let proxy_url = format!("http://127.0.0.1:{proxy}/");
        // The target port is unroutable on purpose: success proves the
        // handshake ran through the proxy tunnel, not direct.
        let request = WebSocketRequest::new("ws://127.0.0.1:9/socket");
        let mut socket = connect(&request, Some(&proxy_url)).expect("tunneled handshake");
        socket
            .send(WsMessage::Text("via-proxy".to_owned()))
            .expect("send through tunnel");
        assert_eq!(
            socket
                .recv_with_timeout(Duration::from_secs(10))
                .expect("echo through tunnel"),
            WsMessage::Text("via-proxy".to_owned())
        );
    }
}
