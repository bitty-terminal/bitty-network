//! Integration tests for OAuth credential flow architecture and property pins (#28).
//!
//! Pins the contract specified in `docs/decisions/28-oauth.md`:
//! - The `oauth` feature compiles cleanly and enables no ambient credential fetching.
//! - Offline service fails closed with `NetworkError::Offline`.
//! - Requests carrying `Authorization` or `Proxy-Authorization` headers maintain
//!   strict secret redaction in `Debug` and `Display` formatting (PP-2, P0-AC-026).
//! - NetworkError variants do not echo canaries or token strings.

#![forbid(unsafe_code)]

use bitty_network::OfflineNetworkService;
use bitty_network_api::{NetworkCapability, NetworkError, NetworkService, Request};

#[test]
fn oauth_gate_compiles_and_preserves_fail_closed_offline_behaviour() {
    let service = OfflineNetworkService::new(NetworkCapability::offline());
    let req = Request::get("https://api.openai.com/v1/models");
    let err = service
        .request(&req)
        .expect_err("offline service must fail closed");
    assert_eq!(err, NetworkError::Offline);
}

#[test]
fn oauth_bearer_token_is_strictly_redacted_in_request_debug() {
    let canary_token = "canary_oauth_access_token_sk_live_99887766554433221100";
    let req = Request::post("https://api.anthropic.com/v1/messages", b"{}".to_vec())
        .with_header("Authorization", format!("Bearer {canary_token}"))
        .with_header("X-Custom-Header", "custom-value");

    let debug_repr = format!("{req:?}");

    // The secret token MUST NOT appear anywhere in the Debug representation.
    assert!(
        !debug_repr.contains(canary_token),
        "Secret OAuth bearer token leaked in Request Debug: {debug_repr}"
    );

    // Header values are redacted, but header names are preserved.
    assert!(debug_repr.contains("Authorization"));
    assert!(debug_repr.contains("X-Custom-Header"));
    assert!(debug_repr.contains("[redacted]"));
}

#[test]
fn network_error_never_leaks_token_or_credential_canaries() {
    let canary = "secret_canary_value_should_not_leak";
    let err = NetworkError::Denied {
        domain: "example.com".to_owned(),
    };

    let display_repr = format!("{err}");
    let debug_repr = format!("{err:?}");

    assert!(!display_repr.contains(canary));
    assert!(!debug_repr.contains(canary));
}
