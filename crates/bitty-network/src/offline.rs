//! Embedded offline backend: capability-first [`NetworkService`] with no sockets.
//!
//! [`OfflineNetworkService`] is the first consumable [`NetworkService`]
//! implementation: it holds a [`NetworkCapability`] and checks it FIRST on
//! every call. Deny-all stays [`NetworkError::Offline`], an allowlist miss
//! becomes the typed [`NetworkError::Denied`], and even an allowlist hit
//! fails closed with [`NetworkError::Offline`] because this backend moves no
//! bytes. Sockets, transports, and wire code arrive in a follow-up task.
//!
//! Feature gates: `client` resolves to this backend through the
//! [`OfflineNetworkService::client`] constructor when that feature is
//! enabled. The `http` gate keeps its [`OfflineNetworkService::http`]
//! constructor for the fail-closed resolution, and additionally enables the
//! real transport in `crate::http`: prefer
//! `crate::http::HttpNetworkService` when the `http` feature is on and
//! moving bytes is intended. The `websocket` gate (which implies `http`)
//! enables the handshake on that same backend; every other gate (`server`,
//! `quic`, `proxy`, `oauth`) stays fail-closed: the embedded backend is the
//! only resolution and it performs no I/O under any of them.
//!
//! [`NetworkService`]: bitty_network_api::NetworkService
//! [`NetworkCapability`]: bitty_network_api::NetworkCapability
//! [`NetworkError`]: bitty_network_api::NetworkError
//! [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
//! [`NetworkError::Denied`]: bitty_network_api::NetworkError::Denied
//!
//! # Example
//!
//! ```
//! use bitty_network::{
//!     NetworkCapability, NetworkError, NetworkService, OfflineNetworkService,
//!     Request,
//! };
//!
//! let service = OfflineNetworkService::offline();
//! assert_eq!(
//!     service.request(&Request::get("https://example.com/")),
//!     Err(NetworkError::Offline)
//! );
//!
//! let capped = OfflineNetworkService::new(
//!     NetworkCapability::offline().with_domain("example.com"),
//! );
//! assert_eq!(
//!     capped.request(&Request::get("https://other.example/")),
//!     Err(NetworkError::Denied {
//!         domain: "other.example".to_owned()
//!     })
//! );
//! ```

use bitty_network_api::{
    NetworkCapability, NetworkError, NetworkService, Request, Response, WebSocketRequest,
};

/// Never-connected socket placeholder for the offline backend.
///
/// [`NetworkService::websocket`] always fails, so this type is never
/// constructed outside this module; the private field keeps it that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OfflineSocket {
    _private: (),
}

/// Embedded offline [`NetworkService`] with capability-first enforcement.
///
/// Holds the caller's [`NetworkCapability`] and rejects before anything else:
/// deny-all yields [`NetworkError::Offline`], an allowlist miss yields the
/// typed [`NetworkError::Denied`], and an allowlist hit still yields
/// [`NetworkError::Offline`] because the backend owns no sockets. The default
/// is deny-all ([`OfflineNetworkService::offline`]).
///
/// [`NetworkService`]: bitty_network_api::NetworkService
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
/// [`NetworkError::Denied`]: bitty_network_api::NetworkError::Denied
#[derive(Debug, Clone, Default)]
pub struct OfflineNetworkService {
    capability: NetworkCapability,
}

impl OfflineNetworkService {
    /// Serve the offline backend under `capability`.
    #[must_use]
    pub fn new(capability: NetworkCapability) -> Self {
        Self { capability }
    }

    /// Deny-all backend: every host is unreachable.
    #[must_use]
    pub fn offline() -> Self {
        Self::new(NetworkCapability::offline())
    }

    /// Resolve the offline backend as the `client` initiator role.
    ///
    /// Only available with the `client` feature; behavior is identical to
    /// [`OfflineNetworkService::new`] (fail-closed, no sockets).
    #[cfg(feature = "client")]
    #[must_use]
    pub fn client(capability: NetworkCapability) -> Self {
        Self::new(capability)
    }

    /// Resolve the offline backend for the `http` protocol.
    ///
    /// Only available with the `http` feature; behavior is identical to
    /// [`OfflineNetworkService::new`] (fail-closed, no wire code). This is
    /// the stay-offline resolution — for the real transport behind the same
    /// gate see `crate::http::HttpNetworkService`.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn http(capability: NetworkCapability) -> Self {
        Self::new(capability)
    }

    /// The capability this backend enforces.
    #[must_use]
    pub fn capability(&self) -> &NetworkCapability {
        &self.capability
    }

    /// Capability-first rejection for `domain`: deny-all and allowlist misses
    /// surface the checker's typed error, allowlist hits fail closed with
    /// [`NetworkError::Offline`] (no sockets yet).
    ///
    /// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
    fn reject(&self, domain: &str) -> NetworkError {
        match self.capability.check(domain) {
            Ok(()) => NetworkError::Offline,
            Err(error) => error,
        }
    }
}

impl NetworkService for OfflineNetworkService {
    type Socket = OfflineSocket;

    fn request(&self, request: &Request) -> Result<Response, NetworkError> {
        Err(self.reject(request.host()))
    }

    fn websocket(&self, request: &WebSocketRequest) -> Result<Self::Socket, NetworkError> {
        Err(self.reject(request.host()))
    }
}
