//! Capability-gated WebSocket transport over a single sync stack.
//!
//! `connect` performs one handshake through tungstenite (the only
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
//! Timeouts: [`DEFAULT_WEBSOCKET_TIMEOUT`] bounds DNS, TCP, proxy
//! `CONNECT`, and the WebSocket handshake unless the caller overrides it per
//! request via [`WebSocketRequest::with_timeout`]. DNS work uses a bounded
//! elastic permit pool: the caller always returns at its deadline, a timed-out
//! OS lookup may retain its permit until the OS returns, and permit exhaustion
//! surfaces [`NetworkError::Timeout`]. Each
//! [`WebSocketSocket::recv_with_timeout`] call temporarily installs one
//! absolute read/write deadline, covering automatic control-frame replies,
//! then restores the stored send deadline
//! ([`DEFAULT_WEBSOCKET_TIMEOUT`]) and close deadline
//! ([`DEFAULT_WS_CLOSE_TIMEOUT`]).
//! Expired deadlines always surface [`NetworkError::Timeout`].
//!
//! Budgets: [`MAX_WS_FRAME_BYTES`] caps one frame payload,
//! [`MAX_WS_MESSAGE_BYTES`] caps one assembled message (fragmented or not),
//! [`MAX_WS_AGGREGATE_BYTES`] caps cumulative delivered payload,
//! [`MAX_WS_FRAMES`] and [`MAX_WS_MESSAGES`] cap low-level frame and data
//! message counts, and [`MAX_WS_WRITE_BUFFER_BYTES`] caps pending outbound
//! data. All are enforced Bitty-side before a message crosses into Bitty
//! code, with matching stack frame/message/write-buffer caps where the
//! WebSocket implementation supports them. Byte crossings surface
//! [`NetworkError::Budget`]; count crossings surface
//! [`NetworkError::CountBudget`].
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
//! [`NetworkError::CountBudget`]: bitty_network_api::NetworkError::CountBudget

use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
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

/// Largest number of WebSocket frames one socket may read, including control
/// frames and continuation fragments.
///
/// Counting low-level frames keeps empty messages, empty fragments, and
/// ping/pong traffic from bypassing the byte budgets. Exceeding the cap
/// fails closed with [`NetworkError::CountBudget`].
pub const MAX_WS_FRAMES: u64 = 65_536;

/// Largest number of data messages one socket may read.
///
/// A message is counted when its final data frame arrives, so fragmented
/// messages consume one message-budget slot while every fragment remains
/// subject to [`MAX_WS_FRAMES`]. Exceeding the cap fails closed with
/// [`NetworkError::CountBudget`].
pub const MAX_WS_MESSAGES: u64 = 16_384;

/// Largest pending outbound WebSocket write buffer, in bytes.
///
/// This is a transport-level backstop in addition to the per-message byte
/// cap. A stalled peer cannot make repeated failed sends grow tungstenite's
/// buffer without limit; the next send fails closed with
/// [`NetworkError::Budget`].
pub const MAX_WS_WRITE_BUFFER_BYTES: usize = 2 * MAX_WS_MESSAGE_BYTES;

/// Smallest remaining slice still handed to a blocking call.
///
/// When a deadline is nearly exhausted the remaining time is clamped to this
/// floor instead of zero so the call fails with its own typed error rather
/// than returning immediately without trying.
const MIN_REMAINING: Duration = Duration::from_millis(1);

/// Target size at which tungstenite flushes ordinary writes.
const WS_WRITE_BUFFER_SIZE: usize = 128 * 1024;

/// Maximum buffered response head used while the WebSocket handshake is
/// being consumed by the stream wrapper.
const MAX_WS_HANDSHAKE_HEAD: usize = 65_536;

/// Maximum number of addresses retained from one DNS answer.
const MAX_DNS_ADDRS: usize = 16;

/// Polling interval used while waiting for a bounded DNS result.
const DNS_WAIT_POLL: Duration = Duration::from_millis(1);

const DNS_RESOLVER_CAPACITY: usize = 32;
#[cfg(test)]
const HUNG_RESOLVER_COUNT: usize = 4;

type ResolverResult = std::io::Result<Vec<SocketAddr>>;
type Resolver = Box<dyn FnOnce() -> ResolverResult + Send + 'static>;

static DNS_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

struct ResolverPermit;

impl ResolverPermit {
    fn acquire(after: Duration) -> Result<Self, NetworkError> {
        let mut current = DNS_IN_FLIGHT.load(Ordering::Acquire);
        loop {
            if current >= DNS_RESOLVER_CAPACITY {
                return Err(NetworkError::Timeout { after });
            }
            match DNS_IN_FLIGHT.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for ResolverPermit {
    fn drop(&mut self) {
        DNS_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ResolverJob {
    resolver: Resolver,
    result: mpsc::Sender<ResolverResult>,
    cancelled: Arc<AtomicBool>,
}

impl ResolverJob {
    fn run(self) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        let _ = self.result.send((self.resolver)());
    }

    fn spawn(self, after: Duration) -> Result<(), NetworkError> {
        let permit = ResolverPermit::acquire(after)?;
        std::thread::Builder::new()
            .name("bitty-dns".to_owned())
            .spawn(move || {
                let _permit = permit;
                self.run();
            })
            .map(|_| ())
            .map_err(|_| NetworkError::Offline)
    }
}

/// Maximum bytes retained after a `CONNECT` response terminator.
const MAX_CONNECT_LEFTOVER: usize = 65_536;

/// Cap for one `CONNECT` response head; a proxy answering with more is
/// treated as a failure (fail closed).
const MAX_CONNECT_HEAD: usize = 16_384;

struct DeadlineStream {
    inner: TcpStream,
    read_deadline: Option<Instant>,
    write_deadline: Option<Instant>,
    interrupt_next_io: bool,
}

impl DeadlineStream {
    fn new(inner: TcpStream, deadline: Instant) -> Self {
        Self {
            inner,
            read_deadline: Some(deadline),
            write_deadline: Some(deadline),
            interrupt_next_io: false,
        }
    }

    fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
            read_deadline: self.read_deadline,
            write_deadline: self.write_deadline,
            interrupt_next_io: false,
        })
    }

    fn interrupt_next_io(&mut self) {
        self.interrupt_next_io = true;
    }

    fn set_deadlines(
        &mut self,
        read: Option<Duration>,
        write: Option<Duration>,
        now: Instant,
    ) -> std::io::Result<()> {
        self.read_deadline = read.map(|duration| deadline_from(now, duration));
        self.write_deadline = write.map(|duration| deadline_from(now, duration));
        self.apply_read_timeout()?;
        self.apply_write_timeout()
    }

    fn set_deadline(&mut self, deadline: Instant) -> std::io::Result<()> {
        self.read_deadline = Some(deadline);
        self.write_deadline = Some(deadline);
        self.apply_read_timeout()?;
        self.apply_write_timeout()
    }

    fn apply_read_timeout(&mut self) -> std::io::Result<()> {
        let timeout = match self.read_deadline {
            Some(deadline) => Some(timeout_until(deadline)?),
            None => None,
        };
        self.inner.set_read_timeout(timeout)
    }

    fn apply_write_timeout(&mut self) -> std::io::Result<()> {
        let timeout = match self.write_deadline {
            Some(deadline) => Some(timeout_until(deadline)?),
            None => None,
        };
        self.inner.set_write_timeout(timeout)
    }

    fn read_expired(&self) -> bool {
        self.read_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn write_expired(&self) -> bool {
        self.write_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.interrupt_next_io {
            self.interrupt_next_io = false;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "websocket handshake interruption",
            ));
        }
        self.apply_read_timeout()?;
        let result = self.inner.read(buf);
        if self.read_expired() {
            return Err(timed_out());
        }
        result
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.interrupt_next_io {
            self.interrupt_next_io = false;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "websocket handshake interruption",
            ));
        }
        self.apply_write_timeout()?;
        let result = self.inner.write(buf);
        if self.write_expired() {
            return Err(timed_out());
        }
        result
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.apply_write_timeout()?;
        let result = self.inner.flush();
        if self.write_expired() {
            return Err(timed_out());
        }
        result
    }
}

struct BudgetedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    prefix_offset: usize,
    handshake_probe: Vec<u8>,
    handshake_complete: bool,
    count_frames: bool,
    frame_counter: FrameCounter,
}

impl<S> BudgetedStream<S> {
    fn new(inner: S, prefix: Vec<u8>, count_frames: bool) -> Self {
        Self {
            inner,
            prefix,
            prefix_offset: 0,
            handshake_probe: Vec::new(),
            handshake_complete: false,
            count_frames,
            frame_counter: FrameCounter::default(),
        }
    }

    fn finish_handshake(&mut self) {
        self.handshake_complete = true;
        self.handshake_probe.clear();
    }
}

trait DeadlineSetter {
    fn set_deadlines(
        &mut self,
        read: Option<Duration>,
        write: Option<Duration>,
        now: Instant,
    ) -> std::io::Result<()>;

    fn set_deadline(&mut self, deadline: Instant) -> std::io::Result<()>;
}

impl DeadlineSetter for DeadlineStream {
    fn set_deadlines(
        &mut self,
        read: Option<Duration>,
        write: Option<Duration>,
        now: Instant,
    ) -> std::io::Result<()> {
        DeadlineStream::set_deadlines(self, read, write, now)
    }

    fn set_deadline(&mut self, deadline: Instant) -> std::io::Result<()> {
        DeadlineStream::set_deadline(self, deadline)
    }
}

impl<S: DeadlineSetter> DeadlineSetter for BudgetedStream<S> {
    fn set_deadlines(
        &mut self,
        read: Option<Duration>,
        write: Option<Duration>,
        now: Instant,
    ) -> std::io::Result<()> {
        self.inner.set_deadlines(read, write, now)
    }

    fn set_deadline(&mut self, deadline: Instant) -> std::io::Result<()> {
        self.inner.set_deadline(deadline)
    }
}

impl DeadlineSetter for InnerTlsStream {
    fn set_deadlines(
        &mut self,
        read: Option<Duration>,
        write: Option<Duration>,
        now: Instant,
    ) -> std::io::Result<()> {
        match self {
            MaybeTlsStream::Plain(stream) => stream.set_deadlines(read, write, now),
            MaybeTlsStream::Rustls(tls) => tls.get_mut().set_deadlines(read, write, now),
            _ => Err(std::io::Error::other("unsupported websocket transport")),
        }
    }

    fn set_deadline(&mut self, deadline: Instant) -> std::io::Result<()> {
        match self {
            MaybeTlsStream::Plain(stream) => stream.set_deadline(deadline),
            MaybeTlsStream::Rustls(tls) => tls.get_mut().set_deadline(deadline),
            _ => Err(std::io::Error::other("unsupported websocket transport")),
        }
    }
}

impl<S: Read> Read for BudgetedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.prefix_offset < self.prefix.len() {
            let start = self.prefix_offset;
            let end = self.prefix.len();
            let source = self.prefix[start..end].to_vec();
            let consumed = self.deliver_bytes(&source, buf)?;
            self.prefix_offset += consumed;
            if self.prefix_offset == self.prefix.len() {
                self.prefix.clear();
                self.prefix_offset = 0;
            }
            return Ok(consumed);
        }
        let mut chunk = [0u8; 8192];
        let read = self.inner.read(&mut chunk)?;
        if read == 0 {
            return Ok(0);
        }
        let consumed = self.deliver_bytes(&chunk[..read], buf)?;
        if consumed < read {
            self.prefix.extend_from_slice(&chunk[consumed..read]);
        }
        Ok(consumed)
    }
}

impl<S> BudgetedStream<S> {
    fn deliver_bytes(&mut self, source: &[u8], destination: &mut [u8]) -> std::io::Result<usize> {
        if !self.count_frames {
            let consumed = source.len().min(destination.len());
            destination[..consumed].copy_from_slice(&source[..consumed]);
            return Ok(consumed);
        }
        if self.handshake_complete {
            let consumed = source.len().min(destination.len());
            self.frame_counter.feed(&source[..consumed])?;
            destination[..consumed].copy_from_slice(&source[..consumed]);
            return Ok(consumed);
        }
        let mut consumed = 0;
        for byte in source.iter().take(destination.len()) {
            self.handshake_probe.push(*byte);
            if self.handshake_probe.len() > MAX_WS_HANDSHAKE_HEAD {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "websocket handshake head exceeds budget",
                ));
            }
            destination[consumed] = *byte;
            consumed += 1;
            if self.handshake_probe.ends_with(b"\r\n\r\n") {
                self.handshake_complete = true;
                self.handshake_probe.clear();
                break;
            }
        }
        Ok(consumed)
    }
}

impl<S: Write> Write for BudgetedStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Default)]
struct FrameCounter {
    header: Vec<u8>,
    payload_remaining: u64,
    frames: u64,
    messages: u64,
}

impl FrameCounter {
    fn feed(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        for byte in bytes {
            if self.payload_remaining > 0 {
                self.payload_remaining -= 1;
                if self.payload_remaining == 0 {
                    self.header.clear();
                }
                continue;
            }
            self.header.push(*byte);
            if self.header.len() < 2 {
                continue;
            }
            let length_octets = match self.header[1] & 0x7f {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let mask_octets = if self.header[1] & 0x80 == 0 { 0 } else { 4 };
            let header_len = 2 + length_octets + mask_octets;
            if self.header.len() < header_len {
                continue;
            }
            self.admit_frame()?;
            let payload_len = match length_octets {
                0 => u64::from(self.header[1] & 0x7f),
                2 => u64::from(u16::from_be_bytes([self.header[2], self.header[3]])),
                _ => read_u64(&self.header[2..10]),
            };
            self.payload_remaining = payload_len;
            self.header.clear();
            if payload_len == 0 {
                continue;
            }
        }
        Ok(())
    }

    fn admit_frame(&mut self) -> std::io::Result<()> {
        self.frames = self.frames.saturating_add(1);
        if self.frames > MAX_WS_FRAMES {
            return Err(count_budget(MAX_WS_FRAMES));
        }
        let fin = self.header[0] & 0x80 != 0;
        let opcode = self.header[0] & 0x0f;
        if fin && opcode <= 2 {
            self.messages = self.messages.saturating_add(1);
            if self.messages > MAX_WS_MESSAGES {
                return Err(count_budget(MAX_WS_MESSAGES));
            }
        }
        Ok(())
    }
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(value)
}

#[derive(Debug)]
struct WsCountBudget {
    limit_items: u64,
}

impl std::fmt::Display for WsCountBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "websocket count budget exceeded: {} items",
            self.limit_items
        )
    }
}

impl std::error::Error for WsCountBudget {}

fn count_budget(limit_items: u64) -> std::io::Error {
    std::io::Error::other(WsCountBudget { limit_items })
}

fn deadline_from(start: Instant, duration: Duration) -> Instant {
    match start.checked_add(duration) {
        Some(deadline) => deadline,
        None => start,
    }
}

fn timeout_until(deadline: Instant) -> std::io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(timed_out())
    } else {
        Ok(remaining.max(MIN_REMAINING))
    }
}

fn timed_out() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "network operation deadline expired",
    )
}

type SocketStream = DeadlineStream;
type InnerTlsStream = MaybeTlsStream<BudgetedStream<SocketStream>>;
type WebSocketTransport = BudgetedStream<InnerTlsStream>;

/// One established WebSocket connection.
///
/// Returned by [`bitty_network_api::NetworkService::websocket`]; owns the stream until
/// [`WebSocketSocket::close`].
/// Ping/Pong control frames are answered by the stack and never surfaced:
/// [`WebSocketSocket::recv_with_timeout`] only returns data messages.
///
/// The socket carries its own deadlines (`read_timeout` for the next
/// receive, `write_timeout` for sends, `close_timeout` for the close frame)
/// plus frame/message counters and the lifetime delivery counter behind
/// [`MAX_WS_AGGREGATE_BYTES`]. A receive temporarily overrides both socket
/// deadlines, then restores the stored values so a later send or close never
/// loses its bound.
pub struct WebSocketSocket {
    inner: tungstenite::WebSocket<WebSocketTransport>,
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
    /// receive deadline covers both reads and any automatic control-frame
    /// reply write, so later sends and [`WebSocketSocket::close`] stay
    /// bounded.
    ///
    /// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
    /// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
    /// [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget
    pub fn recv_with_timeout(&mut self, timeout: Duration) -> Result<WsMessage, NetworkError> {
        let started = Instant::now();
        let deadline = deadline_from(started, timeout);
        self.read_timeout = Some(timeout);
        let result = self.recv_before_deadline(deadline, timeout);
        let restore = self.apply_deadlines();
        match (result, restore) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(message), Ok(())) => Ok(message),
        }
    }

    fn recv_before_deadline(
        &mut self,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<WsMessage, NetworkError> {
        loop {
            if Instant::now() >= deadline {
                return Err(NetworkError::Timeout { after: timeout });
            }
            self.inner
                .get_mut()
                .set_deadline(deadline)
                .map_err(|error| map_io(&error, timeout))?;
            match self.inner.read() {
                Ok(message) => {
                    let data = message_to_data(message)?;
                    if Instant::now() >= deadline {
                        return Err(NetworkError::Timeout { after: timeout });
                    }
                    match data {
                        Some(data) => {
                            self.check_inbound(&data)?;
                            if Instant::now() >= deadline {
                                return Err(NetworkError::Timeout { after: timeout });
                            }
                            return Ok(data);
                        }
                        None => continue,
                    }
                }
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
/// [`MAX_WS_FRAME_BYTES`], one assembled message [`MAX_WS_MESSAGE_BYTES`],
/// and pending writes may hold [`MAX_WS_WRITE_BUFFER_BYTES`].
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
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(MAX_WS_WRITE_BUFFER_BYTES)
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
    let (stream, prefix) = match proxy_url {
        Some(proxy) => tunnel_via_proxy(proxy, &target, deadline, started)?,
        None => (dial(&target, deadline, started)?, Vec::new()),
    };
    let url = request.url.as_str();
    let inner = if target.tls {
        let placeholder = stream.try_clone().map_err(|_| NetworkError::Offline)?;
        let mut tls_input = BudgetedStream::new(stream, Vec::new(), false);
        tls_input.inner.interrupt_next_io();
        let tls_stream =
            match tungstenite::client_tls_with_config(url, tls_input, Some(ws_config()), None) {
                Err(tungstenite::HandshakeError::Interrupted(mut stalled)) => {
                    let stream = stalled.get_mut().get_mut();
                    let placeholder =
                        MaybeTlsStream::Plain(BudgetedStream::new(placeholder, Vec::new(), false));
                    std::mem::replace(stream, placeholder)
                }
                Err(tungstenite::HandshakeError::Failure(error)) => {
                    return Err(map_transport(&error, deadline));
                }
                Ok(_) => return Err(NetworkError::Offline),
            };
        let outer = BudgetedStream::new(tls_stream, prefix, true);
        let (socket, _) = drive(
            tungstenite::client::client_with_config(url, outer, Some(ws_config())),
            deadline,
            started,
        )?;
        socket
    } else {
        let inner = BudgetedStream::new(stream, Vec::new(), false);
        let outer = BudgetedStream::new(MaybeTlsStream::Plain(inner), prefix, true);
        let (socket, _) = drive(
            tungstenite::client::client_with_config(url, outer, Some(ws_config())),
            deadline,
            started,
        )?;
        socket
    };
    let mut socket = WebSocketSocket {
        inner,
        read_timeout: None,
        write_timeout: DEFAULT_WEBSOCKET_TIMEOUT,
        close_timeout: DEFAULT_WS_CLOSE_TIMEOUT,
        received_bytes: 0,
    };
    finish_handshake(&mut socket.inner)?;
    socket.apply_deadlines()?;
    Ok(socket)
}

/// Remaining handshake budget: the deadline minus elapsed, never below
/// [`MIN_REMAINING`] so a nearly-exhausted budget still produces the
/// call's own typed error.
fn remaining(deadline: Duration, started: Instant) -> Duration {
    deadline_from(started, deadline)
        .saturating_duration_since(Instant::now())
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
    let (host, port) = parse_authority(hostport, if tls { 443 } else { 80 })?;
    Ok(WsTarget { host, port, tls })
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), NetworkError> {
    if authority.is_empty()
        || authority.contains('@')
        || authority
            .bytes()
            .any(|byte| byte <= b' ' || byte >= 0x7f || b"/?#".contains(&byte))
    {
        return Err(NetworkError::Offline);
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or(NetworkError::Offline)?;
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(NetworkError::Offline);
        }
        let port = match suffix {
            "" => default_port,
            _ => suffix
                .strip_prefix(':')
                .ok_or(NetworkError::Offline)?
                .parse::<u16>()
                .map_err(|_| NetworkError::Offline)?,
        };
        return Ok((host.to_lowercase(), port));
    }
    if authority.matches(':').count() > 1 {
        return Err(NetworkError::Offline);
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>().map_err(|_| NetworkError::Offline)?,
        ),
        None => (authority, default_port),
    };
    if host.is_empty() {
        return Err(NetworkError::Offline);
    }
    Ok((host.to_lowercase(), port))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
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
) -> Result<SocketStream, NetworkError> {
    let absolute_deadline = deadline_from(started, deadline);
    let authority = format_authority(&target.host, target.port);
    let addrs = resolve_with_deadline(deadline, started, move || {
        authority
            .to_socket_addrs()
            .map(|addresses| addresses.take(MAX_DNS_ADDRS).collect())
    })?;
    for addr in addrs {
        if Instant::now() >= absolute_deadline {
            return Err(NetworkError::Timeout { after: deadline });
        }
        match TcpStream::connect_timeout(&addr, remaining(deadline, started)) {
            Ok(stream) => {
                return Ok(DeadlineStream::new(stream, absolute_deadline));
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(NetworkError::Timeout { after: deadline });
            }
            Err(_) => continue,
        }
    }
    if Instant::now() >= absolute_deadline {
        Err(NetworkError::Timeout { after: deadline })
    } else {
        Err(NetworkError::Offline)
    }
}

fn resolve_with_deadline<F>(
    deadline: Duration,
    started: Instant,
    resolver: F,
) -> Result<Vec<SocketAddr>, NetworkError>
where
    F: FnOnce() -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let absolute_deadline = deadline_from(started, deadline);
    if Instant::now() >= absolute_deadline {
        return Err(NetworkError::Timeout { after: deadline });
    }
    let (sender, receiver) = mpsc::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let job = ResolverJob {
        resolver: Box::new(resolver),
        result: sender,
        cancelled: Arc::clone(&cancelled),
    };
    job.spawn(deadline)?;
    loop {
        if Instant::now() >= absolute_deadline {
            cancelled.store(true, Ordering::Release);
            return Err(NetworkError::Timeout { after: deadline });
        }
        let wait = remaining(deadline, started).min(DNS_WAIT_POLL);
        match receiver.recv_timeout(wait) {
            Ok(Ok(addresses)) => {
                if Instant::now() >= absolute_deadline {
                    return Err(NetworkError::Timeout { after: deadline });
                }
                if addresses.is_empty() {
                    return Err(NetworkError::Offline);
                }
                return Ok(addresses);
            }
            Ok(Err(_)) => {
                if Instant::now() >= absolute_deadline {
                    return Err(NetworkError::Timeout { after: deadline });
                }
                return Err(NetworkError::Offline);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if Instant::now() >= absolute_deadline {
                    return Err(NetworkError::Timeout { after: deadline });
                }
                return Err(NetworkError::Offline);
            }
        }
    }
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
) -> Result<(SocketStream, Vec<u8>), NetworkError> {
    let (scheme, rest) = proxy_url.split_once("://").ok_or(NetworkError::Offline)?;
    if scheme.to_lowercase().as_str() != "http" {
        return Err(NetworkError::Offline);
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (proxy_host, proxy_port) = parse_authority(authority, 80)?;
    let proxy_target = WsTarget {
        host: proxy_host,
        port: proxy_port,
        tls: false,
    };
    let mut stream = dial(&proxy_target, deadline, started)?;
    let authority = format_authority(&target.host, target.port);
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| map_io(&error, deadline))?;
    let head = read_head(&mut stream, deadline)?;
    if !is_connect_success(&head.head) {
        return Err(NetworkError::Offline);
    }
    Ok((stream, head.leftover))
}

struct ConnectHead {
    head: String,
    leftover: Vec<u8>,
}

/// Read one response head (up to the blank line), capped at
/// [`MAX_CONNECT_HEAD`] bytes. The deadline-aware stream bounds the wait;
/// incomplete, malformed, and oversized heads fail closed.
fn read_head(stream: &mut SocketStream, deadline: Duration) -> Result<ConnectHead, NetworkError> {
    let mut buf = Vec::with_capacity(MAX_CONNECT_HEAD.min(8192));
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| map_io(&error, deadline))?;
        if read == 0 {
            return Err(NetworkError::Offline);
        }
        let take = read.min(MAX_CONNECT_HEAD.saturating_add(1) - buf.len());
        buf.extend_from_slice(&chunk[..take]);
        if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            let head_len = end + 4;
            if head_len > MAX_CONNECT_HEAD {
                return Err(NetworkError::Budget {
                    limit_bytes: MAX_CONNECT_HEAD as u64,
                });
            }
            let leftover = buf[head_len..].to_vec();
            if leftover.len() > MAX_CONNECT_LEFTOVER {
                return Err(NetworkError::Budget {
                    limit_bytes: MAX_CONNECT_LEFTOVER as u64,
                });
            }
            let head =
                String::from_utf8(buf[..head_len].to_vec()).map_err(|_| NetworkError::Offline)?;
            return Ok(ConnectHead { head, leftover });
        }
        if buf.len() > MAX_CONNECT_HEAD {
            return Err(NetworkError::Budget {
                limit_bytes: MAX_CONNECT_HEAD as u64,
            });
        }
    }
}

/// True when a proxy `CONNECT` response has a valid `200` status line and
/// syntactically valid header block.
fn is_connect_success(head: &str) -> bool {
    let without_terminator = match head.strip_suffix("\r\n\r\n") {
        Some(value) => value,
        None => return false,
    };
    let mut lines = without_terminator.split("\r\n");
    let status_line = match lines.next() {
        Some(value) => value,
        None => return false,
    };
    let mut status_parts = status_line.splitn(3, ' ');
    let _version = match status_parts.next() {
        Some(value)
            if value.eq_ignore_ascii_case("HTTP/1.0") || value.eq_ignore_ascii_case("HTTP/1.1") =>
        {
            value
        }
        _ => return false,
    };
    if status_parts.next() != Some("200") {
        return false;
    }
    let reason = match status_parts.next() {
        Some(value) if !value.is_empty() => value,
        _ => return false,
    };
    if reason.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return false;
    }
    lines.all(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        !name.is_empty()
            && name.bytes().all(is_header_name_byte)
            && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
    })
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_!#$%&'*+.^`|~".contains(&byte)
}

fn finish_handshake(
    socket: &mut tungstenite::WebSocket<WebSocketTransport>,
) -> Result<(), NetworkError> {
    socket.get_mut().finish_handshake();
    Ok(())
}

/// Set read/write deadlines on the stream inside an open socket (plain or
/// rustls-wrapped); local failures fail closed.
fn set_deadlines(
    stream: &mut WebSocketTransport,
    read: Option<Duration>,
    write: Option<Duration>,
) -> Result<(), NetworkError> {
    let now = Instant::now();
    let after = write.or(read).unwrap_or(MIN_REMAINING);
    let result = stream.set_deadlines(read, write, now);
    result.map_err(|error| map_io(&error, after))
}

/// Map a post-handshake transport failure to its typed error: expired
/// deadlines become [`NetworkError::Timeout`] carrying the effective
/// deadline, capacity crossings become [`NetworkError::Budget`] carrying the
/// crossed cap, count crossings become [`NetworkError::CountBudget`], and
/// everything else fails closed as [`NetworkError::Offline`].
///
/// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
/// [`NetworkError::Budget`]: bitty_network_api::NetworkError::Budget
/// [`NetworkError::CountBudget`]: bitty_network_api::NetworkError::CountBudget
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
fn map_transport(error: &tungstenite::Error, after: Duration) -> NetworkError {
    match error {
        tungstenite::Error::Io(io) => map_io(io, after),
        tungstenite::Error::Capacity(tungstenite::error::CapacityError::MessageTooLong {
            max_size,
            ..
        }) => NetworkError::Budget {
            limit_bytes: *max_size as u64,
        },
        tungstenite::Error::WriteBufferFull(_) => NetworkError::Budget {
            limit_bytes: MAX_WS_WRITE_BUFFER_BYTES as u64,
        },
        _ => NetworkError::Offline,
    }
}

/// Map a blocking I/O failure to its typed error (same rule as
/// [`map_transport`]).
fn map_io(error: &std::io::Error, after: Duration) -> NetworkError {
    if let Some(limit) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<WsCountBudget>())
    {
        return NetworkError::CountBudget {
            limit_items: limit.limit_items,
        };
    }
    if error.kind() == std::io::ErrorKind::TimedOut
        || error.kind() == std::io::ErrorKind::WouldBlock
    {
        NetworkError::Timeout { after }
    } else {
        NetworkError::Offline
    }
}

/// Streams a handshake can run over: expose absolute deadline updates so
/// every resume round uses the same operation budget.
trait HandshakeStream {
    fn set_round_deadline(
        &mut self,
        deadline: Instant,
        after: Duration,
    ) -> Result<(), NetworkError>;
}

impl HandshakeStream for WebSocketTransport {
    fn set_round_deadline(
        &mut self,
        deadline: Instant,
        after: Duration,
    ) -> Result<(), NetworkError> {
        self.set_deadline(deadline)
            .map_err(|error| map_io(&error, after))
    }
}

/// Drive a blocking handshake to completion within one absolute `deadline`.
///
/// Tungstenite reports a stalled-but-live socket as
/// [`HandshakeError::Interrupted`](tungstenite::HandshakeError::Interrupted)
/// instead of blocking: resume until the handshake completes, the socket
/// dies (typed by [`map_transport`]), or the overall `deadline` expires as
/// [`NetworkError::Timeout`]. Every stream round is given the same absolute
/// deadline, so trickling I/O cannot extend the operation budget.
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
    let absolute_deadline = deadline_from(started, deadline);
    let mut pending = first;
    loop {
        match pending {
            Ok(done) => {
                if Instant::now() >= absolute_deadline {
                    return Err(NetworkError::Timeout { after: deadline });
                }
                return Ok(done);
            }
            Err(tungstenite::HandshakeError::Failure(error)) => {
                return Err(map_transport(&error, deadline));
            }
            Err(tungstenite::HandshakeError::Interrupted(mut stalled)) => {
                if Instant::now() >= absolute_deadline {
                    return Err(NetworkError::Timeout { after: deadline });
                }
                stalled
                    .get_mut()
                    .get_mut()
                    .set_round_deadline(absolute_deadline, deadline)?;
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
            "ws://example.com\r\nbad",
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

    #[test]
    fn resolver_wait_is_bounded_without_waiting_for_completion() {
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let started = Instant::now();
        let resolver = std::thread::spawn(move || {
            let result = resolve_with_deadline(SILENT_READ, started, move || {
                let _ = gate_rx.recv();
                Ok(Vec::new())
            });
            let _ = done_tx.send(result);
        });
        let result = done_rx.recv_timeout(OPERATION_DEADLINE_BOUND);
        drop(gate_tx);
        let _ = resolver.join();
        assert_eq!(
            result.expect("resolver wait exceeded its bound"),
            Err(NetworkError::Timeout { after: SILENT_READ })
        );
    }

    /// Write deadline narrowed for stall fixtures: short enough to keep the
    /// suite fast, long enough to stay clear of loopback jitter.
    const STALL_DEADLINE: Duration = Duration::from_millis(200);
    const CONTROL_REPLY_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn resolver_saturation_preserves_capacity_for_healthy_lookup() {
        let calls = HUNG_RESOLVER_COUNT;
        let barrier = Arc::new(std::sync::Barrier::new(calls));
        let release = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = mpsc::channel();
        let mut callers = Vec::with_capacity(calls);
        for _ in 0..calls {
            let barrier = Arc::clone(&barrier);
            let release = Arc::clone(&release);
            let started_tx = started_tx.clone();
            callers.push(std::thread::spawn(move || {
                barrier.wait();
                resolve_with_deadline(SILENT_READ, Instant::now(), move || {
                    let _ = started_tx.send(());
                    while !release.load(Ordering::Acquire) {
                        std::thread::sleep(TRICKLE_INTERVAL);
                    }
                    Ok(Vec::new())
                })
            }));
        }
        drop(started_tx);
        let mut all_started = true;
        for _ in 0..calls {
            if started_rx.recv_timeout(OPERATION_DEADLINE_BOUND).is_err() {
                all_started = false;
                break;
            }
        }
        let caller_results = callers
            .into_iter()
            .map(|caller| caller.join().unwrap_or(Err(NetworkError::Offline)))
            .collect::<Vec<_>>();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("healthy address");
        let healthy = listener.local_addr().expect("healthy address");
        let healthy_result =
            resolve_with_deadline(Duration::from_secs(1), Instant::now(), move || {
                Ok(vec![healthy])
            });
        release.store(true, Ordering::Release);
        assert!(
            all_started,
            "hung resolvers did not occupy the original pool"
        );
        assert!(
            caller_results
                .iter()
                .all(|result| { *result == Err(NetworkError::Timeout { after: SILENT_READ }) })
        );
        assert_eq!(healthy_result, Ok(vec![healthy]));
    }

    /// Read deadline for silent-peer fixtures.
    const SILENT_READ: Duration = Duration::from_millis(100);

    /// Bound for joining the stalled-send thread: proving the write deadline
    /// survived a receive must fail (not hang) if it regresses.
    const STALL_JOIN_BOUND: Duration = Duration::from_secs(10);

    /// Bound for a stalled close: the close deadline above is 200ms, so five
    /// seconds of grace still fails fast on a regression.
    const STALL_CLOSE_BOUND: Duration = Duration::from_secs(5);

    /// Upper bound for an operation that must honor its absolute deadline.
    const OPERATION_DEADLINE_BOUND: Duration = Duration::from_millis(500);

    /// Interval used by trickle fixtures that otherwise keep I/O active.
    const TRICKLE_INTERVAL: Duration = Duration::from_millis(10);

    /// One-mebibyte chunk reused by the stall and aggregate fixtures.
    const ONE_MIB_CHUNK: usize = 1 << 20;

    /// Raw server-to-client frame opcodes for the fragmentation fixtures.
    const OPCODE_TEXT: u8 = 0x1;
    const OPCODE_BINARY: u8 = 0x2;
    const OPCODE_CONTINUE: u8 = 0x0;
    const OPCODE_PING: u8 = 0x9;

    /// Bind an ephemeral loopback listener, returning it with its port.
    /// Never a fixed port; loopback only.
    fn bind_loopback() -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let port = listener.local_addr().expect("loopback addr").port();
        (listener, port)
    }

    struct FixtureProcess {
        port: u16,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl FixtureProcess {
        fn stop_and_join(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    impl Drop for FixtureProcess {
        fn drop(&mut self) {
            self.stop_and_join();
        }
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
    /// reads or writes again, with an explicit shutdown path.
    fn spawn_stall_server() -> FixtureProcess {
        let (listener, port) = bind_loopback();
        listener
            .set_nonblocking(true)
            .expect("stall listener nonblocking");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            loop {
                if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("stall stream blocking");
                        let _server = tungstenite::accept(stream).expect("server handshake");
                        while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                            std::thread::sleep(TRICKLE_INTERVAL);
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TRICKLE_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });
        FixtureProcess {
            port,
            stop,
            handle: Some(handle),
        }
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

    fn spawn_draining_raw_server(frames: Vec<(bool, u8, Vec<u8>)>) -> FixtureProcess {
        let (listener, port) = bind_loopback();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("loopback accept");
            let mut reader = stream.try_clone().expect("raw reader clone");
            let server = tungstenite::accept(stream).expect("server handshake");
            let mut raw = server.into_inner();
            let drain = std::thread::spawn(move || {
                let mut buffer = [0u8; 8192];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
            for (fin, opcode, payload) in frames {
                let frame = encode_server_frame(fin, opcode, &payload);
                if raw.write_all(&frame).is_err() {
                    break;
                }
            }
            while !thread_stop.load(Ordering::SeqCst) {
                std::thread::sleep(TRICKLE_INTERVAL);
            }
            let _ = raw.shutdown(std::net::Shutdown::Both);
            let _ = drain.join();
        });
        FixtureProcess {
            port,
            stop,
            handle: Some(handle),
        }
    }

    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("closed-port bind");
        let port = listener.local_addr().expect("closed-port addr").port();
        drop(listener);
        port
    }

    fn fragmented_frames(
        total: usize,
        opcode: u8,
        fill: u8,
        empty_fragments: bool,
    ) -> Vec<(bool, u8, Vec<u8>)> {
        if total == 0 {
            return vec![(true, opcode, Vec::new())];
        }
        let mut frames = Vec::new();
        let mut remaining = total;
        let mut first = true;
        while remaining > 0 {
            let take = remaining.min(MAX_WS_FRAME_BYTES);
            let final_frame = take == remaining;
            let frame_opcode = if first { opcode } else { OPCODE_CONTINUE };
            frames.push((final_frame, frame_opcode, vec![fill; take]));
            remaining -= take;
            first = false;
            if empty_fragments && !final_frame {
                frames.push((false, OPCODE_CONTINUE, Vec::new()));
            }
        }
        frames
    }

    fn assert_message_boundary(opcode: u8, fill: u8, empty_fragments: bool) {
        for (size, accepted) in [
            (MAX_WS_MESSAGE_BYTES - 1, true),
            (MAX_WS_MESSAGE_BYTES, true),
            (MAX_WS_MESSAGE_BYTES + 1, false),
        ] {
            let frames = fragmented_frames(size, opcode, fill, empty_fragments);
            let port = spawn_raw_server(frames);
            let mut socket = connect_loopback(port);
            let result = socket.recv_with_timeout(Duration::from_secs(15));
            if accepted {
                let expected = match opcode {
                    OPCODE_TEXT => WsMessage::Text(vec![fill as char; size].into_iter().collect()),
                    _ => WsMessage::Binary(vec![fill; size]),
                };
                assert_eq!(result.expect("message at accepted boundary"), expected);
            } else {
                assert_eq!(
                    result,
                    Err(NetworkError::Budget {
                        limit_bytes: MAX_WS_MESSAGE_BYTES as u64,
                    })
                );
            }
        }
    }

    fn spawn_ping_server(frames: usize, interval: Duration) -> FixtureProcess {
        let (listener, port) = bind_loopback();
        listener
            .set_nonblocking(true)
            .expect("ping listener nonblocking");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            loop {
                if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("ping stream blocking");
                        let server = tungstenite::accept(stream).expect("ping server handshake");
                        let mut raw = server.into_inner();
                        let ping = encode_server_frame(true, OPCODE_PING, b"p");
                        for _ in 0..frames {
                            if thread_stop.load(std::sync::atomic::Ordering::SeqCst)
                                || raw.write_all(&ping).is_err()
                            {
                                break;
                            }
                            std::thread::sleep(interval);
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TRICKLE_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });
        FixtureProcess {
            port,
            stop,
            handle: Some(handle),
        }
    }

    fn spawn_stall_ping_server(
        signal: Arc<AtomicBool>,
        pinged: mpsc::Sender<()>,
    ) -> FixtureProcess {
        let (listener, port) = bind_loopback();
        listener
            .set_nonblocking(true)
            .expect("stall ping listener nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_signal = Arc::clone(&signal);
        let handle = std::thread::spawn(move || {
            loop {
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("stall ping stream blocking");
                        let server = tungstenite::accept(stream).expect("stall ping handshake");
                        let mut raw = server.into_inner();
                        while !thread_signal.load(Ordering::Acquire)
                            && !thread_stop.load(Ordering::SeqCst)
                        {
                            std::thread::sleep(TRICKLE_INTERVAL);
                        }
                        if !thread_stop.load(Ordering::SeqCst) {
                            let ping = encode_server_frame(true, OPCODE_PING, b"p");
                            if raw.write_all(&ping).is_ok() {
                                let _ = pinged.send(());
                            }
                        }
                        while !thread_stop.load(Ordering::SeqCst) {
                            std::thread::sleep(TRICKLE_INTERVAL);
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TRICKLE_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });
        FixtureProcess {
            port,
            stop,
            handle: Some(handle),
        }
    }

    fn spawn_connect_response(response: Vec<u8>) -> FixtureProcess {
        let (listener, port) = bind_loopback();
        listener
            .set_nonblocking(true)
            .expect("proxy listener nonblocking");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            loop {
                if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("proxy stream blocking");
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut request = Vec::new();
                        let mut byte = [0u8; 1];
                        while request.len() <= MAX_CONNECT_HEAD {
                            match stream.read(&mut byte) {
                                Ok(1) => {
                                    request.push(byte[0]);
                                    if request.ends_with(b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                        let _ = stream.write_all(&response);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TRICKLE_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });
        FixtureProcess {
            port,
            stop,
            handle: Some(handle),
        }
    }

    fn spawn_stalled_connect() -> FixtureProcess {
        let (listener, port) = bind_loopback();
        listener
            .set_nonblocking(true)
            .expect("stalled proxy listener nonblocking");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            loop {
                if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("stalled proxy stream blocking");
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut request = Vec::new();
                        let mut byte = [0u8; 1];
                        while request.len() <= MAX_CONNECT_HEAD {
                            match stream.read(&mut byte) {
                                Ok(1) => {
                                    request.push(byte[0]);
                                    if request.ends_with(b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                        while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                            std::thread::sleep(TRICKLE_INTERVAL);
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TRICKLE_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });
        FixtureProcess {
            port,
            stop,
            handle: Some(handle),
        }
    }

    fn spawn_trickle_handshake() -> FixtureProcess {
        let (listener, port) = bind_loopback();
        listener
            .set_nonblocking(true)
            .expect("handshake listener nonblocking");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            loop {
                if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("handshake stream blocking");
                        let response = b"HTTP/1.1 101 Switching Protocols\r\n";
                        for byte in response {
                            if thread_stop.load(std::sync::atomic::Ordering::SeqCst)
                                || stream.write_all(&[*byte]).is_err()
                            {
                                break;
                            }
                            std::thread::sleep(TRICKLE_INTERVAL);
                        }
                        while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                            std::thread::sleep(TRICKLE_INTERVAL);
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TRICKLE_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });
        FixtureProcess {
            port,
            stop,
            handle: Some(handle),
        }
    }

    fn spawn_coalesced_ws_server() -> FixtureProcess {
        let (listener, port) = bind_loopback();
        listener
            .set_nonblocking(true)
            .expect("coalesced listener nonblocking");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            loop {
                if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("coalesced stream blocking");
                        let mut request = Vec::new();
                        let mut byte = [0u8; 1];
                        while request.len() <= MAX_CONNECT_HEAD {
                            match stream.read(&mut byte) {
                                Ok(1) => {
                                    request.push(byte[0]);
                                    if request.ends_with(b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                        let request = match String::from_utf8(request) {
                            Ok(value) => value,
                            Err(_) => break,
                        };
                        let key = request.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("sec-websocket-key")
                                .then(|| value.trim().to_owned())
                        });
                        let key = match key {
                            Some(value) => value,
                            None => break,
                        };
                        let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
                        let mut response = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                        )
                        .into_bytes();
                        response.extend_from_slice(&encode_server_frame(
                            true,
                            OPCODE_TEXT,
                            b"tail",
                        ));
                        if stream.write_all(&response).is_err() {
                            break;
                        }
                        while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                            std::thread::sleep(TRICKLE_INTERVAL);
                        }
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TRICKLE_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });
        FixtureProcess {
            port,
            stop,
            handle: Some(handle),
        }
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
    fn coalesced_handshake_tail_is_preserved() {
        let mut server = spawn_coalesced_ws_server();
        let mut socket = connect_loopback(server.port);
        assert_eq!(
            socket
                .recv_with_timeout(Duration::from_secs(5))
                .expect("coalesced frame"),
            WsMessage::Text("tail".to_owned())
        );
        server.stop_and_join();
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
    fn recv_accepts_single_frame_below_frame_budget() {
        let payload = vec![0xABu8; MAX_WS_FRAME_BYTES - 1];
        let port = spawn_raw_server(vec![(true, OPCODE_BINARY, payload.clone())]);
        let mut socket = connect_loopback(port);
        assert_eq!(
            socket
                .recv_with_timeout(Duration::from_secs(10))
                .expect("below-boundary frame"),
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
    fn recv_text_message_boundaries_are_pinned() {
        assert_message_boundary(OPCODE_TEXT, b'a', false);
    }

    #[test]
    fn recv_binary_message_boundaries_are_pinned() {
        assert_message_boundary(OPCODE_BINARY, 0xA5, false);
    }

    #[test]
    fn recv_fragmented_message_boundaries_are_pinned() {
        assert_message_boundary(OPCODE_TEXT, b'b', true);
    }

    #[test]
    fn recv_binary_fragmented_message_boundaries_are_pinned() {
        assert_message_boundary(OPCODE_BINARY, 0xA5, true);
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
    fn recv_deadline_is_not_reset_by_pings() {
        let mut server = spawn_ping_server(100, TRICKLE_INTERVAL);
        let mut socket = connect_loopback(server.port);
        let started = Instant::now();
        assert_eq!(
            socket.recv_with_timeout(SILENT_READ),
            Err(NetworkError::Timeout { after: SILENT_READ })
        );
        assert!(started.elapsed() < OPERATION_DEADLINE_BOUND);
        server.stop_and_join();
    }

    #[test]
    fn recv_deadline_covers_stalled_control_reply() {
        let signal = Arc::new(AtomicBool::new(false));
        let (pinged_tx, pinged_rx) = mpsc::channel();
        let mut server = spawn_stall_ping_server(Arc::clone(&signal), pinged_tx);
        let mut socket = connect_loopback(server.port);
        socket.write_timeout = STALL_DEADLINE;
        let chunk = WsMessage::Binary(vec![0xC3u8; ONE_MIB_CHUNK]);
        let mut write_full = None;
        for _ in 0..(MAX_WS_WRITE_BUFFER_BYTES / ONE_MIB_CHUNK + 8) {
            match socket.send(chunk.clone()) {
                Ok(()) => {}
                Err(NetworkError::Timeout { .. }) => {}
                Err(error @ NetworkError::Budget { .. }) => {
                    write_full = Some(error);
                    break;
                }
                Err(error) => panic!("unexpected stalled-write error: {error:?}"),
            }
        }
        assert_eq!(
            write_full,
            Some(NetworkError::Budget {
                limit_bytes: MAX_WS_WRITE_BUFFER_BYTES as u64,
            })
        );
        socket.write_timeout = CONTROL_REPLY_WRITE_TIMEOUT;
        socket
            .apply_deadlines()
            .expect("long control-reply write deadline");
        signal.store(true, Ordering::Release);
        pinged_rx
            .recv_timeout(OPERATION_DEADLINE_BOUND)
            .expect("stalled control frame reached the client");
        let started = Instant::now();
        assert_eq!(
            socket.recv_with_timeout(SILENT_READ),
            Err(NetworkError::Timeout { after: SILENT_READ })
        );
        assert!(started.elapsed() < OPERATION_DEADLINE_BOUND);
        server.stop_and_join();
    }

    #[test]
    fn recv_rejects_frame_flood_including_empty_fragments() {
        let mut frames = Vec::with_capacity(MAX_WS_FRAMES as usize + 1);
        frames.push((false, OPCODE_TEXT, Vec::new()));
        frames.extend(std::iter::repeat_n(
            (false, OPCODE_CONTINUE, Vec::new()),
            MAX_WS_FRAMES as usize,
        ));
        let port = spawn_raw_server(frames);
        let mut socket = connect_loopback(port);
        assert_eq!(
            socket.recv_with_timeout(Duration::from_secs(10)),
            Err(NetworkError::CountBudget {
                limit_items: MAX_WS_FRAMES,
            })
        );
    }

    #[test]
    fn recv_rejects_empty_message_flood() {
        let frames = std::iter::repeat_n(
            (true, OPCODE_TEXT, Vec::new()),
            MAX_WS_MESSAGES as usize + 1,
        )
        .collect();
        let port = spawn_raw_server(frames);
        let mut socket = connect_loopback(port);
        let mut result = Ok(WsMessage::Text(String::new()));
        for _ in 0..=MAX_WS_MESSAGES as usize {
            match socket.recv_with_timeout(Duration::from_secs(10)) {
                Ok(_) => {}
                Err(error) => {
                    result = Err(error);
                    break;
                }
            }
        }
        assert_eq!(
            result,
            Err(NetworkError::CountBudget {
                limit_items: MAX_WS_MESSAGES,
            })
        );
    }

    #[test]
    fn recv_accepts_frame_count_minus_one() {
        let mut frames = Vec::with_capacity(MAX_WS_FRAMES as usize - 1);
        frames.push((false, OPCODE_TEXT, Vec::new()));
        frames.extend(std::iter::repeat_n(
            (false, OPCODE_CONTINUE, Vec::new()),
            MAX_WS_FRAMES as usize - 2,
        ));
        frames.push((true, OPCODE_CONTINUE, Vec::new()));
        let port = spawn_raw_server(frames);
        let mut socket = connect_loopback(port);
        assert_eq!(
            socket
                .recv_with_timeout(Duration::from_secs(10))
                .expect("frame-count boundary"),
            WsMessage::Text(String::new())
        );
    }

    #[test]
    fn recv_accepts_message_count_minus_one() {
        let frames = std::iter::repeat_n(
            (true, OPCODE_TEXT, Vec::new()),
            MAX_WS_MESSAGES as usize - 1,
        )
        .collect();
        let port = spawn_raw_server(frames);
        let mut socket = connect_loopback(port);
        for _ in 0..(MAX_WS_MESSAGES as usize - 1) {
            assert_eq!(
                socket
                    .recv_with_timeout(Duration::from_secs(10))
                    .expect("message-count boundary"),
                WsMessage::Text(String::new())
            );
        }
    }

    #[test]
    fn recv_rejects_control_frame_flood() {
        let frames =
            std::iter::repeat_n((true, OPCODE_PING, vec![b'p']), MAX_WS_FRAMES as usize + 1)
                .collect();
        let mut server = spawn_draining_raw_server(frames);
        let mut socket = connect_loopback(server.port);
        assert_eq!(
            socket.recv_with_timeout(Duration::from_secs(10)),
            Err(NetworkError::CountBudget {
                limit_items: MAX_WS_FRAMES,
            })
        );
        server.stop_and_join();
    }

    #[test]
    fn stalled_write_buffer_has_a_bitty_owned_cap() {
        let mut server = spawn_stall_server();
        let mut socket = connect_loopback(server.port);
        assert_eq!(
            socket.inner.get_config().max_write_buffer_size,
            MAX_WS_WRITE_BUFFER_BYTES
        );
        socket.write_timeout = STALL_DEADLINE;
        let chunk = WsMessage::Binary(vec![0x5Au8; ONE_MIB_CHUNK]);
        let mut budget = None;
        for _ in 0..(MAX_WS_WRITE_BUFFER_BYTES / ONE_MIB_CHUNK + 8) {
            match socket.send(chunk.clone()) {
                Ok(()) => {}
                Err(NetworkError::Timeout { .. }) => {}
                Err(error @ NetworkError::Budget { .. }) => {
                    budget = Some(error);
                    break;
                }
                Err(error) => panic!("unexpected stalled-write error: {error:?}"),
            }
        }
        assert_eq!(
            budget,
            Some(NetworkError::Budget {
                limit_bytes: MAX_WS_WRITE_BUFFER_BYTES as u64,
            })
        );
        server.stop_and_join();
    }

    #[test]
    fn recv_preserves_write_deadline_for_later_send() {
        let mut server = spawn_stall_server();
        let mut socket = connect_loopback(server.port);
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
        server.stop_and_join();
    }

    #[test]
    fn stalled_close_is_bounded_by_close_deadline() {
        let mut server = spawn_stall_server();
        let mut socket = connect_loopback(server.port);
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
        server.stop_and_join();
    }

    #[test]
    fn connect_parser_rejects_malformed_headers() {
        assert!(is_connect_success(
            "HTTP/1.1 200 Connection Established\r\nX-Test: yes\r\n\r\n"
        ));
        assert!(!is_connect_success(
            "HTTP/1.1 200 Connection Established\r\nMalformed\r\n\r\n"
        ));
        assert!(!is_connect_success(
            "HTTP/1.1 200 Connection Established\r\n\r\nHTTP/1.1 407 denied\r\n\r\n"
        ));
        assert!(!is_connect_success("HTTP/1.1 200\r\n\r\n"));
        assert!(!is_connect_success("HTTP/... 200 bad\r\n\r\n"));
        assert!(!is_connect_success("HTTP/1.1 200 ok\0bad\r\n\r\n"));
        assert!(!is_connect_success("HTTP/1.1 200 ok\x7f\r\n\r\n"));
        assert!(!is_connect_success("HTTP/999.999 200 ok\r\n\r\n"));
    }

    #[test]
    fn connect_preserves_coalesced_tunnel_bytes() {
        let marker = b"coalesced-tunnel-bytes".to_vec();
        let mut response = b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec();
        response.extend_from_slice(&marker);
        let mut proxy = spawn_connect_response(response);
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: closed_port(),
            tls: false,
        };
        let proxy_url = format!("http://127.0.0.1:{}/", proxy.port);
        let result = tunnel_via_proxy(&proxy_url, &target, Duration::from_secs(2), Instant::now());
        match result {
            Ok((_stream, leftover)) => assert_eq!(leftover, marker),
            Err(error) => panic!("valid CONNECT failed: {error:?}"),
        }
        proxy.stop_and_join();
    }

    #[test]
    fn connect_oversize_head_fails_closed() {
        let mut proxy = spawn_connect_response(vec![b'A'; MAX_CONNECT_HEAD + 1]);
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: closed_port(),
            tls: false,
        };
        let proxy_url = format!("http://127.0.0.1:{}/", proxy.port);
        assert_eq!(
            tunnel_via_proxy(&proxy_url, &target, Duration::from_secs(2), Instant::now(),).err(),
            Some(NetworkError::Budget {
                limit_bytes: MAX_CONNECT_HEAD as u64,
            })
        );
        proxy.stop_and_join();
    }

    #[test]
    fn incomplete_connect_head_fails_closed() {
        let mut proxy = spawn_connect_response(b"HTTP/1.1 200 OK\r\n".to_vec());
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: closed_port(),
            tls: false,
        };
        let proxy_url = format!("http://127.0.0.1:{}/", proxy.port);
        assert_eq!(
            tunnel_via_proxy(&proxy_url, &target, Duration::from_secs(2), Instant::now()).err(),
            Some(NetworkError::Offline)
        );
        proxy.stop_and_join();
    }

    #[test]
    fn stalled_connect_is_bounded_by_total_deadline() {
        let mut proxy = spawn_stalled_connect();
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: closed_port(),
            tls: false,
        };
        let proxy_url = format!("http://127.0.0.1:{}/", proxy.port);
        let started = Instant::now();
        assert_eq!(
            tunnel_via_proxy(&proxy_url, &target, SILENT_READ, Instant::now(),).err(),
            Some(NetworkError::Timeout { after: SILENT_READ })
        );
        assert!(started.elapsed() < OPERATION_DEADLINE_BOUND);
        proxy.stop_and_join();
    }

    #[test]
    fn authenticated_proxy_is_rejected_before_dial() {
        let (listener, port) = bind_loopback();
        let proxy_url = format!("http://fixture-user:fixture-pass@127.0.0.1:{port}/");
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: closed_port(),
            tls: false,
        };
        assert_eq!(
            tunnel_via_proxy(&proxy_url, &target, Duration::from_secs(2), Instant::now()).err(),
            Some(NetworkError::Offline)
        );
        listener
            .set_nonblocking(true)
            .expect("auth listener nonblocking");
        match listener.accept() {
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
            Ok(_) => panic!("authenticated proxy URL was dialed"),
        }
    }

    #[test]
    fn ipv6_proxy_authority_requires_brackets() {
        assert_eq!(format_authority("::1", 443), "[::1]:443");
        assert_eq!(
            parse_authority("[::1]", 80).expect("bracketed IPv6 parses"),
            ("::1".to_owned(), 80)
        );
        assert_eq!(
            parse_authority("[::1]garbage", 80),
            Err(NetworkError::Offline)
        );
        assert_eq!(parse_authority("::1:443", 80), Err(NetworkError::Offline));
    }

    #[test]
    fn trickle_handshake_is_bounded_by_total_deadline() {
        let mut server = spawn_trickle_handshake();
        let request = WebSocketRequest::new(loopback_url(server.port)).with_timeout(SILENT_READ);
        let started = Instant::now();
        assert_eq!(
            connect(&request, None).err(),
            Some(NetworkError::Timeout { after: SILENT_READ })
        );
        assert!(started.elapsed() < OPERATION_DEADLINE_BOUND);
        server.stop_and_join();
    }

    #[test]
    fn https_proxy_scheme_never_dials_plaintext() {
        let (listener, port) = bind_loopback();
        let proxy_url = format!("https://127.0.0.1:{port}/");
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: closed_port(),
            tls: false,
        };
        assert_eq!(
            tunnel_via_proxy(&proxy_url, &target, Duration::from_secs(2), Instant::now()).err(),
            Some(NetworkError::Offline)
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
        let unavailable = closed_port();
        let target = WsTarget {
            host: "127.0.0.1".to_owned(),
            port: unavailable,
            tls: false,
        };
        for proxy_url in [
            format!("socks5://127.0.0.1:{unavailable}/"),
            format!("ftp://127.0.0.1:{unavailable}/"),
            "://bad".to_owned(),
        ] {
            assert_eq!(
                tunnel_via_proxy(&proxy_url, &target, Duration::from_secs(2), Instant::now()).err(),
                Some(NetworkError::Offline),
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
        let request = WebSocketRequest::new(format!("ws://127.0.0.1:{}/socket", closed_port()));
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
