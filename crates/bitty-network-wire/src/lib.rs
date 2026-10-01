//! `bitty-network-wire`: native-component wire protocol v1 codec.
//!
//! The Bitty core broker and native components (first: `bitty-net`) talk
//! over the component's stdin/stdout with this protocol. The crate is a
//! hand-written codec with no dependencies (`std` only), no serde, no
//! `unsafe`, and no panics in non-test code. It carries no TLS material.
//!
//! # Framing
//!
//! ```text
//! frame   = length:u32be payload[length]
//! payload = tag:u8 fields...
//! ```
//!
//! `length` is at most [`MAX_FRAME_BYTES`] and at least 1 (the tag). A frame
//! longer than the limit is rejected before any payload byte is read.
//!
//! # Field encoding
//!
//! - Integers are big-endian fixed width (`u8`, `u16`, `u32`, `u64`).
//! - `bool` is one byte, `0x00` or `0x01`; any other value is rejected.
//! - `str` is `len:u32be` + UTF-8 bytes (validated); `bytes` is `len:u32be` +
//!   raw bytes. Every length has a per-field bound checked before the data
//!   is taken.
//! - Lists are `count:u32be` followed by `count` elements, each bounded.
//! - `headers` is a list of `(name:str, value:str)`; at most [`MAX_HEADERS`]
//!   entries and [`MAX_HEADER_BYTES`] of names plus values. Names are RFC 9110
//!   tokens; values carry no CR, LF, or NUL.
//! - `Grant` is `hosts:list<GrantHost>` + `has_methods:bool` +
//!   `methods:u8` (the bitmask byte is always present; it must be `0` when
//!   `has_methods` is false). `GrantHost` is `host:str` + `ports:list<u16>`.
//!
//! # Messages (tag values are fixed)
//!
//! | Tag    | Message        | Fields                                                                                                   | Direction  |
//! |--------|----------------|----------------------------------------------------------------------------------------------------------|------------|
//! | `0x01` | `Hello`        | `min:u16 max:u16 component:str version:str`                                                              | core->comp |
//! | `0x02` | `HelloAck`     | `protocol:u16 component:str version:str`                                                                 | comp->core |
//! | `0x10` | `HttpRequest`  | `id:u64 plugin_id:str grant:Grant method:u8 url:str headers timeout_ms:u32 max_body_bytes:u64 body_follows:bool` | core->comp |
//! | `0x11` | `RequestBody`  | `id:u64 data:bytes last:bool`                                                                            | core->comp |
//! | `0x20` | `ResponseHead` | `id:u64 status:u16 headers`                                                                              | comp->core |
//! | `0x21` | `ResponseBody` | `id:u64 data:bytes last:bool`                                                                            | comp->core |
//! | `0x2F` | `Error`        | `id:u64 kind:u8 message:str`                                                                             | comp->core |
//! | `0x30` | `Cancel`       | `id:u64`                                                                                                 | core->comp |
//! | `0x3F` | `Shutdown`     | (none)                                                                                                   | core->comp |
//!
//! Tags `0x40..=0x4F` are reserved for WebSocket and currently decode as
//! [`WireError::UnknownTag`], like every other unassigned tag.
//!
//! Request ids are non-zero; [`CONNECTION_ID`] (`0`) is reserved for
//! connection-level [`Message::Error`] frames (handshake or framing
//! failures). `timeout_ms = 0` and `max_body_bytes = 0` mean "component
//! default" ([`DEFAULT_MAX_BODY_BYTES`] for the body cap).
//!
//! # Decoding is fail-closed
//!
//! [`decode`] rejects truncated payloads, trailing bytes, invalid UTF-8,
//! oversize fields, unknown tags, unknown enum codes, invalid booleans,
//! zero request ids, and zero ports, each with a typed [`WireError`].
//! [`encode`] applies the same bounds, so a peer can never emit a frame the
//! other side would refuse.
//!
//! # Example
//!
//! ```
//! use bitty_network_wire::{FrameReader, Message, PROTOCOL_VERSION, write_frame};
//!
//! let mut stream = Vec::new();
//! write_frame(
//!     &mut stream,
//!     &Message::Hello {
//!         min: PROTOCOL_VERSION,
//!         max: PROTOCOL_VERSION,
//!         component: "net".to_owned(),
//!         version: "0.1.0".to_owned(),
//!     },
//! )?;
//! let mut reader = FrameReader::new(stream.as_slice());
//! assert!(matches!(reader.read_message()?, Some(Message::Hello { .. })));
//! assert_eq!(reader.read_message()?, None); // clean EOF at a frame boundary
//! # Ok::<(), bitty_network_wire::WireError>(())
//! ```

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read, Write};

/// Wire protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

/// Size of the big-endian `u32` length prefix in front of every payload.
pub const FRAME_HEADER_BYTES: usize = 4;

/// Maximum payload length of one frame (256 KiB, same as `bitty-ipc`).
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Maximum number of requests in flight on one component connection.
pub const MAX_IN_FLIGHT: usize = 64;

/// Maximum number of headers in one request or response head.
pub const MAX_HEADERS: usize = 64;

/// Maximum combined byte length of all header names plus values.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Maximum byte length of a request URL.
pub const MAX_URL_BYTES: usize = 8 * 1024;

/// Maximum data bytes carried by one `RequestBody` or `ResponseBody` frame.
pub const MAX_BODY_CHUNK_BYTES: usize = 192 * 1024;

/// Default response body cap when `max_body_bytes` is `0` (8 MiB, the
/// `bitty-network` HTTP backend ceiling).
pub const DEFAULT_MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum total request body a component accepts across `RequestBody`
/// chunks for one request (8 MiB).
pub const MAX_REQUEST_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum byte length of a component name (`[a-z][a-z0-9-]{0,31}`).
pub const MAX_COMPONENT_NAME_BYTES: usize = 32;

/// Maximum byte length of a version string in `Hello` / `HelloAck`.
pub const MAX_VERSION_BYTES: usize = 64;

/// Maximum byte length of a plugin id in `HttpRequest`.
pub const MAX_PLUGIN_ID_BYTES: usize = 128;

/// Maximum byte length of the human-readable message in `Error`.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 1024;

/// Maximum number of hosts in one [`Grant`].
pub const MAX_GRANT_HOSTS: usize = 64;

/// Maximum byte length of one grant host name (DNS name limit).
pub const MAX_GRANT_HOST_BYTES: usize = 253;

/// Maximum number of ports listed for one [`GrantHost`].
pub const MAX_GRANT_PORTS: usize = 16;

/// Request id reserved for connection-level `Error` frames.
pub const CONNECTION_ID: u64 = 0;

/// Message tag: [`Message::Hello`].
pub const TAG_HELLO: u8 = 0x01;
/// Message tag: [`Message::HelloAck`].
pub const TAG_HELLO_ACK: u8 = 0x02;
/// Message tag: [`Message::HttpRequest`].
pub const TAG_HTTP_REQUEST: u8 = 0x10;
/// Message tag: [`Message::RequestBody`].
pub const TAG_REQUEST_BODY: u8 = 0x11;
/// Message tag: [`Message::ResponseHead`].
pub const TAG_RESPONSE_HEAD: u8 = 0x20;
/// Message tag: [`Message::ResponseBody`].
pub const TAG_RESPONSE_BODY: u8 = 0x21;
/// Message tag: [`Message::Error`].
pub const TAG_ERROR: u8 = 0x2F;
/// Message tag: [`Message::Cancel`].
pub const TAG_CANCEL: u8 = 0x30;
/// Message tag: [`Message::Shutdown`].
pub const TAG_SHUTDOWN: u8 = 0x3F;
/// First tag of the range reserved for WebSocket messages (follow-up).
pub const TAG_RESERVED_WEBSOCKET_FIRST: u8 = 0x40;
/// Last tag of the range reserved for WebSocket messages (follow-up).
pub const TAG_RESERVED_WEBSOCKET_LAST: u8 = 0x4F;

/// HTTP method on the wire (`u8` code; bit `1 << code` in a method mask).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`, code 0.
    Get,
    /// `POST`, code 1.
    Post,
    /// `PUT`, code 2.
    Put,
    /// `DELETE`, code 3.
    Delete,
    /// `HEAD`, code 4.
    Head,
    /// `OPTIONS`, code 5.
    Options,
    /// `PATCH`, code 6.
    Patch,
}

impl Method {
    /// Every method, in code order.
    pub const ALL: [Method; 7] = [
        Method::Get,
        Method::Post,
        Method::Put,
        Method::Delete,
        Method::Head,
        Method::Options,
        Method::Patch,
    ];

    /// Bitmask with every defined method bit set (`0x7F`).
    pub const MASK_ALL: u8 = 0x7F;

    /// Wire code of this method.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Method::Get => 0,
            Method::Post => 1,
            Method::Put => 2,
            Method::Delete => 3,
            Method::Head => 4,
            Method::Options => 5,
            Method::Patch => 6,
        }
    }

    /// Method for a wire code, or `None` for an unknown code.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Method::ALL.into_iter().find(|method| method.code() == code)
    }

    /// Bit of this method inside a [`Grant::methods`] mask.
    #[must_use]
    pub fn bit(self) -> u8 {
        1 << self.code()
    }

    /// Methods whose bits are set in `mask` (unknown bits are ignored here;
    /// [`decode`] already rejects them).
    pub fn in_mask(mask: u8) -> impl Iterator<Item = Method> {
        Method::ALL
            .into_iter()
            .filter(move |method| mask & method.bit() != 0)
    }

    /// Mask with the bits of every method in `methods` set.
    #[must_use]
    pub fn mask_of(methods: impl IntoIterator<Item = Method>) -> u8 {
        methods
            .into_iter()
            .fold(0, |mask, method| mask | method.bit())
    }
}

/// One host entry of a [`Grant`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantHost {
    /// Exact host name (non-empty, at most [`MAX_GRANT_HOST_BYTES`]).
    pub host: String,
    /// Allowed ports (non-zero, at most [`MAX_GRANT_PORTS`]). Empty means the
    /// default port of the request URL's scheme only.
    pub ports: Vec<u16>,
}

/// Capability grant the core hands a component for one request.
///
/// The component enforces exactly this grant and never widens it: no hosts
/// means offline. Maps onto `bitty_network_api::NetworkCapability`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Grant {
    /// Allowed hosts (at most [`MAX_GRANT_HOSTS`]).
    pub hosts: Vec<GrantHost>,
    /// Optional method restriction as a [`Method::bit`] mask; `None` allows
    /// every method, `Some(0)` allows none.
    pub methods: Option<u8>,
}

/// Error category carried by [`Message::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The grant does not cover the host, port, or method (code 1).
    Denied,
    /// The grant is empty or the destination is unreachable (code 2).
    Offline,
    /// The request deadline expired (code 3).
    Timeout,
    /// A byte or count budget was exceeded (code 4).
    Budget,
    /// TLS refused the connection (code 5).
    Tls,
    /// The peer violated the protocol (code 6).
    Protocol,
    /// The component process was lost (code 7; produced by the core).
    ComponentLost,
    /// Internal component failure (code 8).
    Internal,
}

impl ErrorKind {
    /// Every kind, in code order.
    pub const ALL: [ErrorKind; 8] = [
        ErrorKind::Denied,
        ErrorKind::Offline,
        ErrorKind::Timeout,
        ErrorKind::Budget,
        ErrorKind::Tls,
        ErrorKind::Protocol,
        ErrorKind::ComponentLost,
        ErrorKind::Internal,
    ];

    /// Wire code of this kind.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            ErrorKind::Denied => 1,
            ErrorKind::Offline => 2,
            ErrorKind::Timeout => 3,
            ErrorKind::Budget => 4,
            ErrorKind::Tls => 5,
            ErrorKind::Protocol => 6,
            ErrorKind::ComponentLost => 7,
            ErrorKind::Internal => 8,
        }
    }

    /// Kind for a wire code, or `None` for an unknown code.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        ErrorKind::ALL.into_iter().find(|kind| kind.code() == code)
    }

    /// Stable snake_case name (`denied`, `component_lost`, ...).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Denied => "denied",
            ErrorKind::Offline => "offline",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Budget => "budget",
            ErrorKind::Tls => "tls",
            ErrorKind::Protocol => "protocol",
            ErrorKind::ComponentLost => "component_lost",
            ErrorKind::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One protocol v1 message.
#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    /// Handshake offer (core -> component); must be the first message.
    Hello {
        /// Lowest protocol version the core supports.
        min: u16,
        /// Highest protocol version the core supports.
        max: u16,
        /// Component name the core expects (for example `net`).
        component: String,
        /// Core version string.
        version: String,
    },
    /// Handshake answer (component -> core).
    HelloAck {
        /// Negotiated protocol version.
        protocol: u16,
        /// Component name.
        component: String,
        /// Component version string.
        version: String,
    },
    /// Start one HTTP request (core -> component).
    HttpRequest {
        /// Non-zero request id, unique among in-flight requests.
        id: u64,
        /// Requesting plugin id (attribution only).
        plugin_id: String,
        /// Capability grant for this request.
        grant: Grant,
        /// Request method.
        method: Method,
        /// Absolute request URL.
        url: String,
        /// Request headers.
        headers: Vec<(String, String)>,
        /// Deadline in milliseconds; `0` = component default.
        timeout_ms: u32,
        /// Response body cap; `0` = [`DEFAULT_MAX_BODY_BYTES`].
        max_body_bytes: u64,
        /// When true, the body follows in `RequestBody` frames.
        body_follows: bool,
    },
    /// One request body chunk (core -> component).
    RequestBody {
        /// Request id.
        id: u64,
        /// Chunk data (at most [`MAX_BODY_CHUNK_BYTES`]).
        data: Vec<u8>,
        /// True on the final chunk.
        last: bool,
    },
    /// Response status and headers (component -> core).
    ResponseHead {
        /// Request id.
        id: u64,
        /// HTTP status code.
        status: u16,
        /// Response headers.
        headers: Vec<(String, String)>,
    },
    /// One response body chunk (component -> core).
    ResponseBody {
        /// Request id.
        id: u64,
        /// Chunk data (at most [`MAX_BODY_CHUNK_BYTES`]).
        data: Vec<u8>,
        /// True on the final chunk; ends the request.
        last: bool,
    },
    /// Terminal failure for one request, or the connection when `id` is
    /// [`CONNECTION_ID`] (component -> core).
    Error {
        /// Request id or [`CONNECTION_ID`].
        id: u64,
        /// Error category.
        kind: ErrorKind,
        /// Redacted human-readable detail.
        message: String,
    },
    /// Abandon one request; the component sends nothing more for it
    /// (core -> component).
    Cancel {
        /// Request id.
        id: u64,
    },
    /// Stop accepting requests and exit after a bounded grace
    /// (core -> component).
    Shutdown,
}

impl Message {
    /// Tag byte of this message.
    #[must_use]
    pub fn tag(&self) -> u8 {
        match self {
            Message::Hello { .. } => TAG_HELLO,
            Message::HelloAck { .. } => TAG_HELLO_ACK,
            Message::HttpRequest { .. } => TAG_HTTP_REQUEST,
            Message::RequestBody { .. } => TAG_REQUEST_BODY,
            Message::ResponseHead { .. } => TAG_RESPONSE_HEAD,
            Message::ResponseBody { .. } => TAG_RESPONSE_BODY,
            Message::Error { .. } => TAG_ERROR,
            Message::Cancel { .. } => TAG_CANCEL,
            Message::Shutdown => TAG_SHUTDOWN,
        }
    }

    /// Request id carried by this message, if any.
    #[must_use]
    pub fn id(&self) -> Option<u64> {
        match self {
            Message::HttpRequest { id, .. }
            | Message::RequestBody { id, .. }
            | Message::ResponseHead { id, .. }
            | Message::ResponseBody { id, .. }
            | Message::Error { id, .. }
            | Message::Cancel { id } => Some(*id),
            Message::Hello { .. } | Message::HelloAck { .. } | Message::Shutdown => None,
        }
    }
}

/// Redacting `Debug`: URLs, header values, and body bytes never appear.
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Hello {
                min,
                max,
                component,
                version,
            } => f
                .debug_struct("Hello")
                .field("min", min)
                .field("max", max)
                .field("component", component)
                .field("version", version)
                .finish(),
            Message::HelloAck {
                protocol,
                component,
                version,
            } => f
                .debug_struct("HelloAck")
                .field("protocol", protocol)
                .field("component", component)
                .field("version", version)
                .finish(),
            Message::HttpRequest {
                id,
                plugin_id,
                grant,
                method,
                url,
                headers,
                timeout_ms,
                max_body_bytes,
                body_follows,
            } => f
                .debug_struct("HttpRequest")
                .field("id", id)
                .field("plugin_id", plugin_id)
                .field("grant_hosts", &grant.hosts.len())
                .field("method", method)
                .field("url_len", &url.len())
                .field("header_count", &headers.len())
                .field("timeout_ms", timeout_ms)
                .field("max_body_bytes", max_body_bytes)
                .field("body_follows", body_follows)
                .finish(),
            Message::RequestBody { id, data, last } => f
                .debug_struct("RequestBody")
                .field("id", id)
                .field("data_len", &data.len())
                .field("last", last)
                .finish(),
            Message::ResponseHead {
                id,
                status,
                headers,
            } => f
                .debug_struct("ResponseHead")
                .field("id", id)
                .field("status", status)
                .field("header_count", &headers.len())
                .finish(),
            Message::ResponseBody { id, data, last } => f
                .debug_struct("ResponseBody")
                .field("id", id)
                .field("data_len", &data.len())
                .field("last", last)
                .finish(),
            Message::Error { id, kind, message } => f
                .debug_struct("Error")
                .field("id", id)
                .field("kind", kind)
                .field("message", message)
                .finish(),
            Message::Cancel { id } => f.debug_struct("Cancel").field("id", id).finish(),
            Message::Shutdown => f.write_str("Shutdown"),
        }
    }
}

/// Typed codec failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The payload or stream ended before a complete value.
    Truncated,
    /// Bytes remained after the last field of a message.
    TrailingBytes {
        /// Number of unread bytes.
        remaining: usize,
    },
    /// A frame length exceeds [`MAX_FRAME_BYTES`].
    FrameTooLarge {
        /// Declared or encoded payload length.
        len: usize,
    },
    /// The frame payload is empty (no tag byte).
    EmptyFrame,
    /// The tag byte names no v1 message.
    UnknownTag(u8),
    /// A string field is not valid UTF-8.
    InvalidUtf8 {
        /// Field name.
        field: &'static str,
    },
    /// A length or count exceeds its bound.
    LimitExceeded {
        /// Field name.
        field: &'static str,
        /// The bound that was exceeded.
        limit: usize,
    },
    /// A field holds a value outside its domain (unknown code, bad bool,
    /// zero id or port, malformed header).
    InvalidValue {
        /// Field name.
        field: &'static str,
    },
    /// The underlying reader or writer failed.
    Io(io::ErrorKind),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => f.write_str("wire: truncated input"),
            WireError::TrailingBytes { remaining } => {
                write!(f, "wire: {remaining} trailing bytes")
            }
            WireError::FrameTooLarge { len } => {
                write!(f, "wire: frame of {len} bytes exceeds {MAX_FRAME_BYTES}")
            }
            WireError::EmptyFrame => f.write_str("wire: empty frame"),
            WireError::UnknownTag(tag) => write!(f, "wire: unknown tag 0x{tag:02x}"),
            WireError::InvalidUtf8 { field } => write!(f, "wire: invalid utf-8 in {field}"),
            WireError::LimitExceeded { field, limit } => {
                write!(f, "wire: {field} exceeds limit {limit}")
            }
            WireError::InvalidValue { field } => write!(f, "wire: invalid value in {field}"),
            WireError::Io(kind) => write!(f, "wire: i/o error: {kind}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<io::Error> for WireError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            WireError::Truncated
        } else {
            WireError::Io(error.kind())
        }
    }
}

// --- encoding ---------------------------------------------------------------

/// Encoding cursor; every variable-length write checks its bound.
struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn len(&mut self, len: usize, limit: usize, field: &'static str) -> Result<(), WireError> {
        if len > limit {
            return Err(WireError::LimitExceeded { field, limit });
        }
        let len = u32::try_from(len).map_err(|_| WireError::LimitExceeded { field, limit })?;
        self.u32(len);
        Ok(())
    }

    fn bytes(&mut self, data: &[u8], limit: usize, field: &'static str) -> Result<(), WireError> {
        self.len(data.len(), limit, field)?;
        self.buf.extend_from_slice(data);
        Ok(())
    }

    fn str(&mut self, value: &str, limit: usize, field: &'static str) -> Result<(), WireError> {
        self.bytes(value.as_bytes(), limit, field)
    }

    fn id(&mut self, id: u64, field: &'static str) -> Result<(), WireError> {
        if id == CONNECTION_ID {
            return Err(WireError::InvalidValue { field });
        }
        self.u64(id);
        Ok(())
    }

    fn headers(&mut self, headers: &[(String, String)]) -> Result<(), WireError> {
        check_headers(headers.iter().map(|(n, v)| (n.as_str(), v.as_str())))?;
        self.len(headers.len(), MAX_HEADERS, "headers")?;
        for (name, value) in headers {
            self.str(name, MAX_HEADER_BYTES, "header name")?;
            self.str(value, MAX_HEADER_BYTES, "header value")?;
        }
        Ok(())
    }

    fn grant(&mut self, grant: &Grant) -> Result<(), WireError> {
        self.len(grant.hosts.len(), MAX_GRANT_HOSTS, "grant hosts")?;
        for entry in &grant.hosts {
            check_grant_host(&entry.host)?;
            self.str(&entry.host, MAX_GRANT_HOST_BYTES, "grant host")?;
            self.len(entry.ports.len(), MAX_GRANT_PORTS, "grant ports")?;
            for port in &entry.ports {
                if *port == 0 {
                    return Err(WireError::InvalidValue {
                        field: "grant port",
                    });
                }
                self.u16(*port);
            }
        }
        match grant.methods {
            Some(mask) => {
                check_method_mask(mask)?;
                self.bool(true);
                self.u8(mask);
            }
            None => {
                self.bool(false);
                self.u8(0);
            }
        }
        Ok(())
    }
}

/// Encode `message` into one payload (tag + fields, no length prefix).
///
/// Applies every decode bound, so a payload that encodes always decodes.
pub fn encode(message: &Message) -> Result<Vec<u8>, WireError> {
    let mut enc = Enc { buf: Vec::new() };
    enc.u8(message.tag());
    match message {
        Message::Hello {
            min,
            max,
            component,
            version,
        } => {
            enc.u16(*min);
            enc.u16(*max);
            enc.str(component, MAX_COMPONENT_NAME_BYTES, "component")?;
            enc.str(version, MAX_VERSION_BYTES, "version")?;
        }
        Message::HelloAck {
            protocol,
            component,
            version,
        } => {
            enc.u16(*protocol);
            enc.str(component, MAX_COMPONENT_NAME_BYTES, "component")?;
            enc.str(version, MAX_VERSION_BYTES, "version")?;
        }
        Message::HttpRequest {
            id,
            plugin_id,
            grant,
            method,
            url,
            headers,
            timeout_ms,
            max_body_bytes,
            body_follows,
        } => {
            enc.id(*id, "id")?;
            enc.str(plugin_id, MAX_PLUGIN_ID_BYTES, "plugin_id")?;
            enc.grant(grant)?;
            enc.u8(method.code());
            enc.str(url, MAX_URL_BYTES, "url")?;
            enc.headers(headers)?;
            enc.u32(*timeout_ms);
            enc.u64(*max_body_bytes);
            enc.bool(*body_follows);
        }
        Message::RequestBody { id, data, last } | Message::ResponseBody { id, data, last } => {
            enc.id(*id, "id")?;
            enc.bytes(data, MAX_BODY_CHUNK_BYTES, "data")?;
            enc.bool(*last);
        }
        Message::ResponseHead {
            id,
            status,
            headers,
        } => {
            enc.id(*id, "id")?;
            enc.u16(*status);
            enc.headers(headers)?;
        }
        Message::Error { id, kind, message } => {
            enc.u64(*id);
            enc.u8(kind.code());
            enc.str(message, MAX_ERROR_MESSAGE_BYTES, "message")?;
        }
        Message::Cancel { id } => enc.id(*id, "id")?,
        Message::Shutdown => {}
    }
    if enc.buf.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge { len: enc.buf.len() });
    }
    Ok(enc.buf)
}

/// Encode `message` into one complete frame (length prefix + payload).
pub fn encode_frame(message: &Message) -> Result<Vec<u8>, WireError> {
    let payload = encode(message)?;
    let len = u32::try_from(payload.len())
        .map_err(|_| WireError::FrameTooLarge { len: payload.len() })?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Encode `message` and write it to `writer` as one frame, then flush.
///
/// The frame is fully encoded before the first byte is written, so an
/// encoding failure never leaves a partial frame on the stream.
pub fn write_frame<W: Write + ?Sized>(writer: &mut W, message: &Message) -> Result<(), WireError> {
    let frame = encode_frame(message)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

// --- decoding ---------------------------------------------------------------

/// Decoding cursor; every read is bounds-checked.
struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidValue { field }),
        }
    }

    fn len(&mut self, limit: usize, field: &'static str) -> Result<usize, WireError> {
        let len =
            usize::try_from(self.u32()?).map_err(|_| WireError::LimitExceeded { field, limit })?;
        if len > limit {
            return Err(WireError::LimitExceeded { field, limit });
        }
        Ok(len)
    }

    fn bytes(&mut self, limit: usize, field: &'static str) -> Result<Vec<u8>, WireError> {
        let len = self.len(limit, field)?;
        Ok(self.take(len)?.to_vec())
    }

    fn str(&mut self, limit: usize, field: &'static str) -> Result<String, WireError> {
        let len = self.len(limit, field)?;
        let raw = self.take(len)?;
        std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| WireError::InvalidUtf8 { field })
    }

    fn id(&mut self) -> Result<u64, WireError> {
        let id = self.u64()?;
        if id == CONNECTION_ID {
            return Err(WireError::InvalidValue { field: "id" });
        }
        Ok(id)
    }

    fn headers(&mut self) -> Result<Vec<(String, String)>, WireError> {
        let count = self.len(MAX_HEADERS, "headers")?;
        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            let name = self.str(MAX_HEADER_BYTES, "header name")?;
            let value = self.str(MAX_HEADER_BYTES, "header value")?;
            headers.push((name, value));
        }
        check_headers(headers.iter().map(|(n, v)| (n.as_str(), v.as_str())))?;
        Ok(headers)
    }

    fn grant(&mut self) -> Result<Grant, WireError> {
        let host_count = self.len(MAX_GRANT_HOSTS, "grant hosts")?;
        let mut hosts = Vec::with_capacity(host_count);
        for _ in 0..host_count {
            let host = self.str(MAX_GRANT_HOST_BYTES, "grant host")?;
            check_grant_host(&host)?;
            let port_count = self.len(MAX_GRANT_PORTS, "grant ports")?;
            let mut ports = Vec::with_capacity(port_count);
            for _ in 0..port_count {
                let port = self.u16()?;
                if port == 0 {
                    return Err(WireError::InvalidValue {
                        field: "grant port",
                    });
                }
                ports.push(port);
            }
            hosts.push(GrantHost { host, ports });
        }
        let has_methods = self.bool("grant has_methods")?;
        let mask = self.u8()?;
        let methods = if has_methods {
            check_method_mask(mask)?;
            Some(mask)
        } else if mask == 0 {
            None
        } else {
            return Err(WireError::InvalidValue {
                field: "grant methods",
            });
        };
        Ok(Grant { hosts, methods })
    }

    fn finish(&self) -> Result<(), WireError> {
        let remaining = self.buf.len().saturating_sub(self.pos);
        if remaining == 0 {
            Ok(())
        } else {
            Err(WireError::TrailingBytes { remaining })
        }
    }
}

/// Decode one payload (tag + fields, no length prefix) into a [`Message`].
///
/// Fails closed on every malformed input; see the [crate docs](crate).
pub fn decode(payload: &[u8]) -> Result<Message, WireError> {
    if payload.is_empty() {
        return Err(WireError::EmptyFrame);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge { len: payload.len() });
    }
    let mut dec = Dec {
        buf: payload,
        pos: 0,
    };
    let tag = dec.u8()?;
    let message = match tag {
        TAG_HELLO => Message::Hello {
            min: dec.u16()?,
            max: dec.u16()?,
            component: dec.str(MAX_COMPONENT_NAME_BYTES, "component")?,
            version: dec.str(MAX_VERSION_BYTES, "version")?,
        },
        TAG_HELLO_ACK => Message::HelloAck {
            protocol: dec.u16()?,
            component: dec.str(MAX_COMPONENT_NAME_BYTES, "component")?,
            version: dec.str(MAX_VERSION_BYTES, "version")?,
        },
        TAG_HTTP_REQUEST => {
            let id = dec.id()?;
            let plugin_id = dec.str(MAX_PLUGIN_ID_BYTES, "plugin_id")?;
            let grant = dec.grant()?;
            let method =
                Method::from_code(dec.u8()?).ok_or(WireError::InvalidValue { field: "method" })?;
            let url = dec.str(MAX_URL_BYTES, "url")?;
            let headers = dec.headers()?;
            let timeout_ms = dec.u32()?;
            let max_body_bytes = dec.u64()?;
            let body_follows = dec.bool("body_follows")?;
            Message::HttpRequest {
                id,
                plugin_id,
                grant,
                method,
                url,
                headers,
                timeout_ms,
                max_body_bytes,
                body_follows,
            }
        }
        TAG_REQUEST_BODY => Message::RequestBody {
            id: dec.id()?,
            data: dec.bytes(MAX_BODY_CHUNK_BYTES, "data")?,
            last: dec.bool("last")?,
        },
        TAG_RESPONSE_HEAD => Message::ResponseHead {
            id: dec.id()?,
            status: dec.u16()?,
            headers: dec.headers()?,
        },
        TAG_RESPONSE_BODY => Message::ResponseBody {
            id: dec.id()?,
            data: dec.bytes(MAX_BODY_CHUNK_BYTES, "data")?,
            last: dec.bool("last")?,
        },
        TAG_ERROR => {
            let id = dec.u64()?;
            let kind =
                ErrorKind::from_code(dec.u8()?).ok_or(WireError::InvalidValue { field: "kind" })?;
            let message = dec.str(MAX_ERROR_MESSAGE_BYTES, "message")?;
            Message::Error { id, kind, message }
        }
        TAG_CANCEL => Message::Cancel { id: dec.id()? },
        TAG_SHUTDOWN => Message::Shutdown,
        other => return Err(WireError::UnknownTag(other)),
    };
    dec.finish()?;
    Ok(message)
}

/// Decode one frame from the front of `buf` without blocking.
///
/// Returns `Ok(None)` while `buf` holds less than one complete frame,
/// `Ok(Some((message, consumed)))` once it does (`consumed` = prefix +
/// payload bytes), and an error as soon as the length prefix exceeds
/// [`MAX_FRAME_BYTES`] or the payload is malformed.
pub fn try_decode_frame(buf: &[u8]) -> Result<Option<(Message, usize)>, WireError> {
    let Some(header) = buf.get(..FRAME_HEADER_BYTES) else {
        return Ok(None);
    };
    let len = frame_len(header)?;
    let end = FRAME_HEADER_BYTES + len;
    match buf.get(FRAME_HEADER_BYTES..end) {
        Some(payload) => Ok(Some((decode(payload)?, end))),
        None => Ok(None),
    }
}

/// Validate one length prefix and return the payload length.
fn frame_len(header: &[u8]) -> Result<usize, WireError> {
    let mut raw = [0u8; FRAME_HEADER_BYTES];
    raw.copy_from_slice(header);
    let len = usize::try_from(u32::from_be_bytes(raw))
        .map_err(|_| WireError::FrameTooLarge { len: usize::MAX })?;
    if len > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge { len });
    }
    if len == 0 {
        return Err(WireError::EmptyFrame);
    }
    Ok(len)
}

/// Incremental frame reader over any [`Read`].
///
/// Reads exactly one frame per call and never past it, so the underlying
/// stream stays positioned at the next frame. The length prefix is checked
/// before the payload buffer is allocated. Wrap unbuffered handles (pipes)
/// in [`std::io::BufReader`] for fewer syscalls.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
}

impl<R: Read> FrameReader<R> {
    /// Wrap `inner`.
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Read one raw payload.
    ///
    /// Returns `Ok(None)` on a clean EOF at a frame boundary and
    /// [`WireError::Truncated`] on EOF inside a frame.
    pub fn read_frame(&mut self) -> Result<Option<Vec<u8>>, WireError> {
        let mut header = [0u8; FRAME_HEADER_BYTES];
        let mut filled = 0;
        while filled < FRAME_HEADER_BYTES {
            match self.inner.read(&mut header[filled..]) {
                Ok(0) if filled == 0 => return Ok(None),
                Ok(0) => return Err(WireError::Truncated),
                Ok(n) => filled += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        let len = frame_len(&header)?;
        let mut payload = vec![0u8; len];
        self.inner.read_exact(&mut payload)?;
        Ok(Some(payload))
    }

    /// Read and decode one message (`Ok(None)` on clean EOF).
    pub fn read_message(&mut self) -> Result<Option<Message>, WireError> {
        match self.read_frame()? {
            Some(payload) => decode(&payload).map(Some),
            None => Ok(None),
        }
    }

    /// Unwrap the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

// --- validation -------------------------------------------------------------

/// Header list bounds plus RFC 9110 token names and CR/LF/NUL-free values.
fn check_headers<'a>(
    headers: impl ExactSizeIterator<Item = (&'a str, &'a str)>,
) -> Result<(), WireError> {
    if headers.len() > MAX_HEADERS {
        return Err(WireError::LimitExceeded {
            field: "headers",
            limit: MAX_HEADERS,
        });
    }
    let mut total: usize = 0;
    for (name, value) in headers {
        total = total.saturating_add(name.len()).saturating_add(value.len());
        if total > MAX_HEADER_BYTES {
            return Err(WireError::LimitExceeded {
                field: "header bytes",
                limit: MAX_HEADER_BYTES,
            });
        }
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(WireError::InvalidValue {
                field: "header name",
            });
        }
        if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
            return Err(WireError::InvalidValue {
                field: "header value",
            });
        }
    }
    Ok(())
}

/// RFC 9110 `tchar`.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Grant hosts are non-empty and free of whitespace and control bytes.
fn check_grant_host(host: &str) -> Result<(), WireError> {
    if host.is_empty()
        || host
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(WireError::InvalidValue {
            field: "grant host",
        });
    }
    Ok(())
}

/// A method mask may only set defined method bits.
fn check_method_mask(mask: u8) -> Result<(), WireError> {
    if mask & !Method::MASK_ALL != 0 {
        return Err(WireError::InvalidValue {
            field: "grant methods",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
