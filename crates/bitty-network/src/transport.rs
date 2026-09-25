//! Transport shell: TCP/UDP/QUIC markers (no sockets yet).
//!
//! Sealed: real transports arrive in a follow-up task. This module performs
//! no I/O and opens no sockets; the markers below reserve the variants
//! follow-ups will implement behind the `client`/`server`/`quic` features.
//!
//! The `CONNECT` helpers are pure and dependency-free: they split one
//! already-read proxy response head from the tunnel bytes pipelined after it
//! so a follow-up can replay the exact leftovers into the tunneled handshake
//! instead of dropping them. Wiring them into the handshake path's
//! `read_head`/`tunnel_via_proxy` is a follow-up merge (that file is owned
//! by the sibling websocket lane); [`MAX_CONNECT_HEAD`] mirrors the bound
//! there and the two must be unified then.

use std::fmt;

/// Marker reserving the TCP transport shape (no sockets yet).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Tcp {
    _private: (),
}

/// Marker reserving the UDP transport shape (no sockets yet).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Udp {
    _private: (),
}

/// Marker reserving the QUIC transport shape (no sockets yet).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Quic {
    _private: (),
}

/// Cap for one `CONNECT` response head, in bytes.
///
/// Mirrors the proxy-tunnel bound in the WebSocket handshake path; the
/// follow-up that wires [`split_connect_head`] in must unify the two instead
/// of keeping parallel constants.
pub const MAX_CONNECT_HEAD: usize = 16_384;

/// Cap for tunnel bytes preserved past one `CONNECT` head, in bytes.
///
/// Leftovers are normally a few hundred bytes (a pipelined TLS greeting);
/// anything past this bound fails closed instead of being buffered.
pub const MAX_CONNECT_LEFTOVER: usize = 65_536;

/// Exact byte sequence ending one `CONNECT` response head.
const HEADER_END: &[u8] = b"\r\n\r\n";

/// One split `CONNECT` response: the head through the blank line plus the
/// exact tunnel bytes already read past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectHead {
    /// Response head through the blank line, as text.
    pub head: String,
    /// Bytes read past the head, preserved verbatim (binary-safe: tunnel
    /// bytes are usually a TLS greeting, not text).
    pub leftover: Vec<u8>,
}

/// Typed `CONNECT` split failure (fail closed, no partial state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The head already exceeds [`MAX_CONNECT_HEAD`] (or the buffered bytes
    /// do with no head in sight yet).
    HeadTooLong {
        /// Bound that was exceeded, in bytes.
        limit_bytes: usize,
    },
    /// Tunnel bytes past the head exceed [`MAX_CONNECT_LEFTOVER`].
    LeftoverTooLong {
        /// Bound that was exceeded, in bytes.
        limit_bytes: usize,
    },
    /// Head bytes are not valid text (heads are ASCII status lines).
    InvalidHead,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadTooLong { limit_bytes } => {
                write!(f, "connect head exceeds {limit_bytes} bytes")
            }
            Self::LeftoverTooLong { limit_bytes } => {
                write!(f, "connect leftover exceeds {limit_bytes} bytes")
            }
            Self::InvalidHead => write!(f, "connect head is not valid text"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Split one buffered `CONNECT` response into its head and exact leftovers.
///
/// Returns `Ok(None)` when `buffer` holds no head terminator yet and still
/// fits the head bound (feed more bytes); `Ok(Some(_))` once the blank line
/// is present, with every byte past it preserved verbatim in
/// [`ConnectHead::leftover`]. Oversized heads or leftovers fail closed with
/// [`ConnectError`].
#[must_use]
pub fn split_connect_head(buffer: &[u8]) -> Option<Result<ConnectHead, ConnectError>> {
    match find_header_end(buffer) {
        Some(end) => {
            let head_len = end + HEADER_END.len();
            if head_len > MAX_CONNECT_HEAD {
                return Some(Err(ConnectError::HeadTooLong {
                    limit_bytes: MAX_CONNECT_HEAD,
                }));
            }
            let leftover = buffer[head_len..].to_vec();
            if leftover.len() > MAX_CONNECT_LEFTOVER {
                return Some(Err(ConnectError::LeftoverTooLong {
                    limit_bytes: MAX_CONNECT_LEFTOVER,
                }));
            }
            match std::str::from_utf8(&buffer[..head_len]) {
                Ok(head) => Some(Ok(ConnectHead {
                    head: head.to_owned(),
                    leftover,
                })),
                Err(_) => Some(Err(ConnectError::InvalidHead)),
            }
        }
        None => {
            if buffer.len() > MAX_CONNECT_HEAD {
                return Some(Err(ConnectError::HeadTooLong {
                    limit_bytes: MAX_CONNECT_HEAD,
                }));
            }
            None
        }
    }
}

/// Offset of the head terminator in `buffer`, if present.
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(HEADER_END.len())
        .position(|window| window == HEADER_END)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table-driven split fixtures: chunked proxy bytes plus the exact head
    /// and leftover the final split must produce.
    struct SplitFixture {
        name: &'static str,
        chunks: &'static [&'static [u8]],
        head: &'static str,
        leftover: &'static [u8],
    }

    /// Binary TLS-greeting-shaped leftover (not valid UTF-8 on purpose: the
    /// split must preserve it byte-exact without text conversion).
    const TLS_GREETING: &[u8] = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03";

    const FIXTURES: &[SplitFixture] = &[
        SplitFixture {
            name: "head only, no leftover",
            chunks: &[b"HTTP/1.1 200 Connection Established\r\n\r\n"],
            head: "HTTP/1.1 200 Connection Established\r\n\r\n",
            leftover: b"",
        },
        SplitFixture {
            name: "head with headers plus text leftover, one read",
            chunks: &[b"HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\nTUNNELED"],
            head: "HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\n",
            leftover: b"TUNNELED",
        },
        SplitFixture {
            name: "binary leftover preserved byte-exact",
            chunks: &[b"HTTP/1.1 200 Connection Established\r\n\r\n\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"],
            head: "HTTP/1.1 200 Connection Established\r\n\r\n",
            leftover: TLS_GREETING,
        },
        SplitFixture {
            name: "terminator split across reads",
            chunks: &[b"HTTP/1.1 200 OK\r\n", b"\r", b"\nTUNNELED"],
            head: "HTTP/1.1 200 OK\r\n\r\n",
            leftover: b"TUNNELED",
        },
        SplitFixture {
            name: "byte-at-a-time arrival",
            chunks: &[b"H", b"T", b"T", b"P", b"/1.1 200 OK\r\n\r\n", b"X"],
            head: "HTTP/1.1 200 OK\r\n\r\n",
            leftover: b"X",
        },
        SplitFixture {
            name: "leftover resembling another response stays verbatim",
            chunks: &[b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 404 nope\r\n\r\n"],
            head: "HTTP/1.1 200 OK\r\n\r\n",
            leftover: b"HTTP/1.1 404 nope\r\n\r\n",
        },
    ];

    #[test]
    fn table_splits_preserve_exact_leftovers() {
        for fixture in FIXTURES {
            let mut buffered = Vec::new();
            let last = fixture.chunks.len() - 1;
            for (index, chunk) in fixture.chunks.iter().enumerate() {
                buffered.extend_from_slice(chunk);
                let split = split_connect_head(&buffered);
                if index == last {
                    let expected = ConnectHead {
                        head: fixture.head.to_owned(),
                        leftover: fixture.leftover.to_vec(),
                    };
                    assert_eq!(split, Some(Ok(expected)), "fixture: {}", fixture.name);
                } else {
                    match split {
                        None => {}
                        Some(Ok(partial)) => {
                            assert_eq!(partial.head, fixture.head, "fixture: {}", fixture.name);
                            assert!(
                                fixture.leftover.starts_with(&partial.leftover),
                                "fixture: {}",
                                fixture.name
                            );
                        }
                        Some(Err(error)) => {
                            panic!("fixture {} failed early: {error}", fixture.name);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn incomplete_head_needs_more_bytes() {
        assert_eq!(split_connect_head(b""), None);
        assert_eq!(split_connect_head(b"HTTP/1.1 200 OK\r\n"), None);
        assert_eq!(split_connect_head(b"HTTP/1.1 200 OK\r\n\r"), None);
    }

    #[test]
    fn head_past_the_cap_fails_closed() {
        let mut oversized = vec![b'A'; MAX_CONNECT_HEAD + 1];
        assert_eq!(
            split_connect_head(&oversized),
            Some(Err(ConnectError::HeadTooLong {
                limit_bytes: MAX_CONNECT_HEAD
            }))
        );
        oversized.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            split_connect_head(&oversized),
            Some(Err(ConnectError::HeadTooLong {
                limit_bytes: MAX_CONNECT_HEAD
            }))
        );
    }

    #[test]
    fn head_exactly_at_the_cap_still_splits() {
        let pad = MAX_CONNECT_HEAD - b"\r\n\r\n".len();
        let mut exact = vec![b'A'; pad];
        exact.extend_from_slice(b"\r\n\r\n");
        let split = split_connect_head(&exact);
        match split {
            Some(Ok(head)) => assert!(head.leftover.is_empty()),
            other => panic!("boundary head must split, got {other:?}"),
        }
    }

    #[test]
    fn leftover_past_the_cap_fails_closed() {
        let mut buffered = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        buffered.extend(std::iter::repeat_n(b'B', MAX_CONNECT_LEFTOVER + 1));
        assert_eq!(
            split_connect_head(&buffered),
            Some(Err(ConnectError::LeftoverTooLong {
                limit_bytes: MAX_CONNECT_LEFTOVER
            }))
        );
    }

    #[test]
    fn non_text_head_fails_closed() {
        assert_eq!(
            split_connect_head(b"HTTP/1.1 200 \xff\r\n\r\n"),
            Some(Err(ConnectError::InvalidHead))
        );
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            ConnectError::HeadTooLong { limit_bytes: 8 }.to_string(),
            "connect head exceeds 8 bytes"
        );
        assert_eq!(
            ConnectError::LeftoverTooLong { limit_bytes: 8 }.to_string(),
            "connect leftover exceeds 8 bytes"
        );
        assert_eq!(
            ConnectError::InvalidHead.to_string(),
            "connect head is not valid text"
        );
    }
}
