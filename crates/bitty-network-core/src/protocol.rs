//! Protocol shell: HTTP/WS markers plus bounded subprotocol negotiation.
//!
//! Sealed: framing and wire behavior arrive in a follow-up task behind the
//! `http`/`websocket` features. This module performs no I/O; the markers
//! below reserve the protocols follow-ups will implement.
//!
//! The subprotocol helpers are pure and dependency-free: they validate one
//! client's offers against strict bounds and pick the first overlap with the
//! server's supported set. Sending the negotiated offer on the handshake
//! (today the handshake ignores [`WebSocketRequest::protocols`]) is a
//! follow-up merge owned by the sibling websocket lane.
//!
//! [`WebSocketRequest::protocols`]: bitty_network_api::WebSocketRequest::protocols

use std::fmt;

/// Marker reserving the HTTP protocol shape (no wire code yet).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Http {
    _private: (),
}

/// Marker reserving the WebSocket protocol shape (no wire code yet).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct WebSocket {
    _private: (),
}

/// Cap for offered subprotocols per handshake, in entries.
///
/// Eight covers real negotiations (clients usually offer one or two) while
/// keeping the handshake header bounded; more fails closed.
pub const MAX_SUBPROTOCOLS: usize = 8;

/// Cap for one subprotocol name, in bytes.
///
/// Names are ASCII tokens (so bytes equal characters); sixty-four fits every
/// registered name with room while keeping the header bounded.
pub const MAX_SUBPROTOCOL_LEN: usize = 64;

/// Typed subprotocol negotiation failure.
///
/// Carries positions and lengths only — never the offered bytes — so the
/// error stays safe to log (see `crate::diagnostics`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// More offers than [`MAX_SUBPROTOCOLS`].
    TooManyOffers {
        /// Offers received, in entries.
        count: usize,
    },
    /// One offer exceeds [`MAX_SUBPROTOCOL_LEN`].
    OfferTooLong {
        /// Position of the offer in the offer list.
        index: usize,
        /// Length of the offer, in bytes.
        len: usize,
    },
    /// One offer is not a valid subprotocol token (empty or carrying a
    /// separator, whitespace, control, or non-ASCII byte).
    InvalidOffer {
        /// Position of the offer in the offer list.
        index: usize,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyOffers { count } => {
                write!(f, "too many subprotocol offers: {count}")
            }
            Self::OfferTooLong { index, len } => {
                write!(f, "subprotocol offer {index} too long: {len} bytes")
            }
            Self::InvalidOffer { index } => {
                write!(f, "invalid subprotocol offer at index {index}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Validate one client's subprotocol offers against the negotiation bounds.
///
/// Checks the offer count, then each offer's length and token shape (RFC 6455
/// tokens: one or more `tchar` bytes). Reports the first violation by
/// position; errors never echo the offered bytes.
pub fn validate_offers(offers: &[String]) -> Result<(), ProtocolError> {
    if offers.len() > MAX_SUBPROTOCOLS {
        return Err(ProtocolError::TooManyOffers {
            count: offers.len(),
        });
    }
    for (index, offer) in offers.iter().enumerate() {
        if offer.len() > MAX_SUBPROTOCOL_LEN {
            return Err(ProtocolError::OfferTooLong {
                index,
                len: offer.len(),
            });
        }
        if !is_subprotocol_token(offer) {
            return Err(ProtocolError::InvalidOffer { index });
        }
    }
    Ok(())
}

/// Pick the negotiated subprotocol for validated offers.
///
/// Returns the first offer (client preference order) the server also
/// supports, or `Ok(None)` on mismatch — the handshake then proceeds with
/// its default, matching current behavior. Offer matching is exact
/// (case-sensitive); invalid or over-bound offers fail closed first via
/// [`validate_offers`].
pub fn select_protocol<'a>(
    offers: &[String],
    supported: &[&'a str],
) -> Result<Option<&'a str>, ProtocolError> {
    validate_offers(offers)?;
    for offer in offers {
        for candidate in supported {
            if offer.as_str() == *candidate {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(None)
}

/// True when `offer` is a valid subprotocol token: non-empty ASCII of
/// `tchar` bytes only (RFC 2616 token shape, reused by RFC 6455).
fn is_subprotocol_token(offer: &str) -> bool {
    !offer.is_empty() && offer.bytes().all(is_token_char)
}

/// True for one `tchar` byte: alphanumerics plus the token symbols.
/// Separators (`()<>@,;:\"/[]?={}`, space, tab), controls, and non-ASCII
/// bytes are all rejected.
fn is_token_char(byte: u8) -> bool {
    if byte.is_ascii_alphanumeric() {
        return true;
    }
    matches!(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn offers(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn valid_tokens_pass_validation() {
        assert_eq!(
            validate_offers(&offers(&["chat", "mqtt", "a-b_c.d~e!f"])),
            Ok(())
        );
        assert_eq!(validate_offers(&[]), Ok(()));
    }

    #[test]
    fn offer_count_boundary_is_exact() {
        let at_cap: Vec<String> = (0..MAX_SUBPROTOCOLS)
            .map(|n| format!("proto-{n}"))
            .collect();
        assert_eq!(validate_offers(&at_cap), Ok(()));
        let mut over_cap = at_cap.clone();
        over_cap.push("one-too-many".to_owned());
        assert_eq!(
            validate_offers(&over_cap),
            Err(ProtocolError::TooManyOffers {
                count: MAX_SUBPROTOCOLS + 1
            })
        );
    }

    #[test]
    fn offer_length_boundary_is_exact() {
        let at_cap = "p".repeat(MAX_SUBPROTOCOL_LEN);
        assert_eq!(validate_offers(&offers(&[&at_cap])), Ok(()));
        let over_cap = "p".repeat(MAX_SUBPROTOCOL_LEN + 1);
        assert_eq!(
            validate_offers(&offers(&[&over_cap])),
            Err(ProtocolError::OfferTooLong {
                index: 0,
                len: MAX_SUBPROTOCOL_LEN + 1
            })
        );
        // Length is checked before shape: the over-long offer reports its
        // position even with later offers also invalid.
        let both_bad = vec!["p".repeat(MAX_SUBPROTOCOL_LEN + 1), "has space".to_owned()];
        assert_eq!(
            validate_offers(&both_bad),
            Err(ProtocolError::OfferTooLong {
                index: 0,
                len: MAX_SUBPROTOCOL_LEN + 1
            })
        );
    }

    #[test]
    fn non_token_offers_fail_by_position() {
        for bad in [
            "",
            "has space",
            "comma,separated",
            "semi;colon",
            "quote\"d",
            "slash/d",
            "back\\slash",
            "tab\there",
            "newline\nhere",
            "non-ascii-ü",
            "@at",
            "[bracket]",
            "paren(s)",
            "colon:proto",
        ] {
            let mut names = vec!["chat".to_owned()];
            names.push(bad.to_owned());
            assert_eq!(
                validate_offers(&names),
                Err(ProtocolError::InvalidOffer { index: 1 }),
                "offer must be rejected: {bad:?}"
            );
        }
    }

    #[test]
    fn selection_follows_offer_preference_order() {
        let picked = select_protocol(&offers(&["second", "first"]), &["first", "second"]);
        assert_eq!(picked, Ok(Some("second")));
    }

    #[test]
    fn selection_is_case_sensitive() {
        assert_eq!(select_protocol(&offers(&["Chat"]), &["chat"]), Ok(None));
    }

    #[test]
    fn mismatch_yields_none_not_an_error() {
        assert_eq!(
            select_protocol(&offers(&["chat", "mqtt"]), &["graphql-ws"]),
            Ok(None)
        );
        assert_eq!(select_protocol(&[], &["chat"]), Ok(None));
        assert_eq!(select_protocol(&offers(&["chat"]), &[]), Ok(None));
    }

    #[test]
    fn selection_validates_before_matching() {
        let too_many: Vec<String> = (0..=MAX_SUBPROTOCOLS)
            .map(|n| format!("proto-{n}"))
            .collect();
        assert_eq!(
            select_protocol(&too_many, &["proto-0"]),
            Err(ProtocolError::TooManyOffers {
                count: MAX_SUBPROTOCOLS + 1
            })
        );
        assert_eq!(
            select_protocol(&offers(&["has space"]), &["has space"]),
            Err(ProtocolError::InvalidOffer { index: 0 })
        );
    }

    #[test]
    fn error_display_is_stable_and_echo_free() {
        assert_eq!(
            ProtocolError::TooManyOffers { count: 9 }.to_string(),
            "too many subprotocol offers: 9"
        );
        assert_eq!(
            ProtocolError::OfferTooLong { index: 1, len: 65 }.to_string(),
            "subprotocol offer 1 too long: 65 bytes"
        );
        assert_eq!(
            ProtocolError::InvalidOffer { index: 2 }.to_string(),
            "invalid subprotocol offer at index 2"
        );
    }
}
