//! `bitty-network`: network implementation with an embedded offline backend
//! and, behind the default-off `http` and `websocket` features, real HTTP
//! and WebSocket transports.
//!
//! This crate owns the modules behind [`NetworkService`]: [`offline`],
//! [`http`] (only with the `http` feature), [`websocket`] (only with the
//! `websocket` feature, which implies `http`), [`runtime`], [`transport`],
//! [`protocol`], [`tls`], [`dns`], and [`policy`]. [`offline`] serves the
//! trait with a capability-first, fail-closed backend (no sockets);
//! [`http`] serves it with a shared-client HTTP backend (capability-first,
//! explicit proxy override plus environment-proxy inheritance behind the
//! `proxy` feature, per-request timeouts) and, with `websocket`,
//! with a capability-gated handshake returning an open socket. The
//! remaining modules hold the offline-first shell vocabulary plus the
//! connection-hardening helpers: [`transport`] (bounded `CONNECT` splits),
//! [`protocol`] (bounded subprotocol negotiation), [`dns`] (explicit
//! resolver deadlines and cancellation), [`diagnostics`] (redacted log and
//! error snapshots), and the [`runtime`], [`tls`], and [`policy`] markers
//! follow-up tasks will fill.
//!
//! The stable vocabulary (`Request`, `WebSocketRequest`, `NetworkCapability`,
//! `NetworkError`, [`NetworkService`] itself) lives in `bitty-network-api`
//! and is re-exported here for convenience; implementations serve the trait,
//! consumers depend on the `-api` crate.
//!
//! [`NetworkService`]: bitty_network_api::NetworkService
//!
//! # Sealing note
//!
//! Sockets arrive through the `http` and `websocket` features. The
//! [`offline`] backend performs no I/O, opens no sockets, spawns no
//! background tasks, and takes no network dependencies (its only dependency
//! is the path-local `bitty-network-api` vocabulary): every allowed request
//! fails closed with [`NetworkError::Offline`], and capability misses
//! surface the typed denial. The feature-gated [`http`] and [`websocket`]
//! backends are the modules that move bytes; the remaining marker modules
//! keep the offline promise. Anything that needs the network today must
//! still go through its existing path unless it opts into the `http` (or
//! `websocket`) feature explicitly.
//!
//! # Example
//!
//! ```
//! use bitty_network::{NetworkCapability, NetworkError};
//!
//! let offline = NetworkCapability::offline();
//! assert!(offline.is_offline());
//! assert_eq!(
//!     offline.check("example.com"),
//!     Err(NetworkError::Offline)
//! );
//! ```

#![forbid(unsafe_code)]

#[cfg(feature = "http")]
pub mod dns;
#[cfg(feature = "http")]
pub mod http;
pub mod offline;
pub mod proxy;
pub mod tls;
pub mod transport;
#[cfg(feature = "websocket")]
pub mod websocket;

// Re-export core modules from bitty-network-core
pub use bitty_network_core::{diagnostics, policy, protocol, runtime};

#[cfg(feature = "http")]
pub use crate::http::HttpNetworkService;
pub use crate::offline::{OfflineNetworkService, OfflineSocket};
#[cfg(feature = "websocket")]
pub use crate::websocket::{WebSocketSocket, WsMessage};
pub use bitty_network_api::{
    HttpMethod, NetworkCapability, NetworkError, NetworkService, OfflineFirst, Request, Response,
    WebSocketRequest,
};
