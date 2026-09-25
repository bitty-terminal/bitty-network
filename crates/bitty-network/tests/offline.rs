//! Acceptance tests for the embedded offline backend (issue #2).
//!
//! Covers deny-all default, allowlist hit/miss, the fail-closed offline
//! response for every request, service-boundary consumption through the
//! [`NetworkService`] trait, and feature-gate presence (`client`/`http`
//! resolve, every other gate stays fail-closed).
//!
//! [`NetworkService`]: bitty_network_api::NetworkService

#![forbid(unsafe_code)]

use bitty_network::{
    NetworkCapability, NetworkError, NetworkService, OfflineNetworkService, OfflineSocket, Request,
    WebSocketRequest,
};

fn allow_example() -> OfflineNetworkService {
    OfflineNetworkService::new(NetworkCapability::offline().with_domain("example.com"))
}

#[test]
fn deny_all_by_default() {
    let service = OfflineNetworkService::offline();
    assert!(service.capability().is_offline());
    assert_eq!(
        service.capability().check("example.com"),
        Err(NetworkError::Offline)
    );
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
    assert_eq!(
        service.websocket(&WebSocketRequest::new("wss://example.com/socket")),
        Err(NetworkError::Offline)
    );
}

#[test]
fn default_is_deny_all() {
    let service = OfflineNetworkService::default();
    assert!(service.capability().is_offline());
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
}

#[test]
fn allowlist_hit_still_fails_closed() {
    let service = allow_example();
    assert_eq!(service.capability().check("example.com"), Ok(()));
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
    assert_eq!(
        service.websocket(&WebSocketRequest::new("wss://example.com/socket")),
        Err(NetworkError::Offline)
    );
}

#[test]
fn allowlist_miss_is_typed_denied() {
    let service = allow_example();
    assert_eq!(
        service.capability().check("other.example"),
        Err(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
    assert_eq!(
        service.request(&Request::get("https://other.example/")),
        Err(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
    assert_eq!(
        service.websocket(&WebSocketRequest::new("wss://other.example/socket")),
        Err(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
}

#[test]
fn every_request_returns_offline_when_not_denied() {
    let deny_all = OfflineNetworkService::offline();
    let allowed = allow_example();

    for url in [
        "https://example.com/",
        "http://example.com:8080/submit",
        "wss://example.com/socket",
        "https://user@example.com./path?a=b#c",
        "",
    ] {
        assert_eq!(
            deny_all.request(&Request::get(url)),
            Err(NetworkError::Offline),
            "deny-all must stay Offline for {url:?}"
        );
    }

    assert_eq!(
        allowed.request(&Request::post("https://example.com/submit", vec![1, 2])),
        Err(NetworkError::Offline)
    );
    assert_eq!(
        allowed.websocket(&WebSocketRequest::new("wss://example.com/socket")),
        Err(NetworkError::Offline)
    );
}

#[test]
fn serves_the_network_service_boundary() {
    fn fetch(
        service: &dyn NetworkService<Socket = OfflineSocket>,
        url: &str,
    ) -> Result<(), NetworkError> {
        service.request(&Request::get(url)).map(|_| ())
    }

    let service = allow_example();
    assert_eq!(
        fetch(&service, "https://example.com/"),
        Err(NetworkError::Offline)
    );
    assert_eq!(
        fetch(&service, "https://other.example/"),
        Err(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
}

#[test]
fn proxy_gate_meaning_is_pinned() {
    // Issue #29 (CTX-0015): the `proxy` gate enables environment-proxy
    // inheritance and nothing else. This single assertion pins both sides:
    // the CI feature matrix runs this target once per gate, so the `proxy`
    // leg asserts `true` and every other leg asserts `false`.
    assert_eq!(
        bitty_network::proxy::env_proxy_enabled(),
        cfg!(feature = "proxy")
    );
}

#[test]
fn feature_gates_resolve_or_fail_closed() {
    // `client` / `http` resolve to the offline backend when enabled.
    #[cfg(feature = "client")]
    {
        let service =
            OfflineNetworkService::client(NetworkCapability::offline().with_domain("example.com"));
        assert_eq!(
            service.request(&Request::get("https://example.com/")),
            Err(NetworkError::Offline)
        );
        assert_eq!(
            service.request(&Request::get("https://other.example/")),
            Err(NetworkError::Denied {
                domain: "other.example".to_owned()
            })
        );
    }
    #[cfg(feature = "http")]
    {
        let service =
            OfflineNetworkService::http(NetworkCapability::offline().with_domain("example.com"));
        assert_eq!(
            service.request(&Request::get("https://example.com/")),
            Err(NetworkError::Offline)
        );
    }

    // Every other gate stays fail-closed: the embedded backend is the only
    // resolution and it moves no bytes, with or without the gate.
    let service = OfflineNetworkService::offline();
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
    #[cfg(feature = "server")]
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
    #[cfg(feature = "websocket")]
    assert_eq!(
        service.websocket(&WebSocketRequest::new("wss://example.com/socket")),
        Err(NetworkError::Offline)
    );
    #[cfg(feature = "quic")]
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
    #[cfg(feature = "proxy")]
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
    #[cfg(feature = "oauth")]
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
}
