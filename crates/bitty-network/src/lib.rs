//! `bitty-network`: network implementation with an embedded offline backend
//! and, behind the default-off `http` feature, a first real HTTP transport.
//!
//! This crate owns the modules behind [`NetworkService`]: [`offline`],
//! [`http`] (only with the `http` feature), [`runtime`], [`transport`],
//! [`protocol`], [`tls`], [`dns`], and [`policy`]. [`offline`] serves the
//! trait with a capability-first, fail-closed backend (no sockets);
//! [`http`] serves it with a shared-client HTTP backend (capability-first,
//! proxy from the environment, per-request timeouts). The remaining modules
//! hold marker types so follow-up tasks have a stable place to land
//! transports, TLS, DNS, and runtime ownership without reshaping the tree.
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
//! Sockets beyond plain HTTP arrive in a follow-up task. The [`offline`]
//! backend performs no I/O, opens no sockets, spawns no background tasks,
//! and takes no network dependencies (its only dependency is the path-local
//! `bitty-network-api` vocabulary): every allowed request fails closed with
//! [`NetworkError::Offline`], and capability misses surface the typed
//! denial. The [`http`] backend (feature-gated, default-off) is the only
//! module that moves bytes; everything else keeps the offline promise.
//! Anything that needs the network today must still go through its existing
//! path unless it opts into the `http` feature explicitly.
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

pub mod dns;
#[cfg(feature = "http")]
pub mod http;
pub mod offline;
pub mod policy;
pub mod protocol;
pub mod runtime;
pub mod tls;
pub mod transport;

#[cfg(feature = "http")]
pub use crate::http::HttpNetworkService;
pub use crate::offline::{OfflineNetworkService, OfflineSocket};
pub use bitty_network_api::{
    HttpMethod, NetworkCapability, NetworkError, NetworkService, OfflineFirst, Request, Response,
    WebSocketRequest,
};
