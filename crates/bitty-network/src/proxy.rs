//! Proxy-gate policy: the one meaning of the `proxy` feature.
//!
//! Decided in CTX-0015 (issue #29): the `proxy` feature gates
//! *environment-proxy inheritance* and nothing else. With the feature,
//! backends may inherit `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and
//! `NO_PROXY` (including each lowercase spelling) from the environment;
//! without it, the environment is ignored and egress is direct-only unless
//! the caller passes an explicit proxy. Explicit proxies (for example
//! [`HttpNetworkService::with_proxy`]) stay always-on in both cases:
//! explicit construction is a deliberate operator act, not ambient
//! authority, so the gate must not disable it.
//!
//! Sealed like the rest of the shell: this module performs no I/O, reads
//! no environment, opens no sockets, and takes no dependencies. It names
//! the gate policy as one predicate so backends and tests share it. The
//! `HttpNetworkService::new` integration is recorded in
//! `docs/decisions/29-proxy.md` (owned by a sibling lane this slice) and
//! is the only remaining wiring step.
//!
//! [`HttpNetworkService::with_proxy`]: crate::http::HttpNetworkService::with_proxy

/// True exactly when environment-proxy inheritance is enabled: on with
/// the `proxy` feature, off without it (direct-only default).
#[must_use]
pub fn env_proxy_enabled() -> bool {
    cfg!(feature = "proxy")
}

use bitty_network_api::NetworkError;
use bitty_network_core::origin::CanonicalOrigin;

/// Immutable provider record snapshot containing non-secret routing metadata
/// and opaque credential state.
///
/// A provider record contains only non-secret routing metadata and opaque secret
/// material:
/// - a stable, non-secret credential identifier;
/// - one `CanonicalOrigin` for the proxy to which the credential may authenticate;
/// - an immutable snapshot of the exact `CanonicalOrigin` destinations for which
///   the credential may be used;
/// - a monotonically increasing credential generation; and
/// - a monotonically increasing scope epoch.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCredentialRecord {
    pub id: String,
    pub proxy_origin: CanonicalOrigin,
    pub allowed_destinations: Vec<CanonicalOrigin>,
    pub generation: u64,
    pub scope_epoch: u64,
}

impl std::fmt::Debug for ProxyCredentialRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacting Debug: structurally descriptive without emitting secret or canary material
        f.debug_struct("ProxyCredentialRecord")
            .finish_non_exhaustive()
    }
}

/// The single credential source for authenticated proxies.
///
/// Installed on [`HttpNetworkService`](crate::http::HttpNetworkService) at construction.
/// The provider owns lookup, remote lifecycle operations, and rotation;
/// `bitty-network` owns no second credential source and performs no implicit
/// environment-variable, keyring, secret-file, or configuration-file lookup.
/// The HTTP and WebSocket paths share that one provider handle.
pub trait ProxyCredentialProvider: Send + Sync + std::fmt::Debug {
    /// Resolve a credential record snapshot for the given proxy origin and destination origin.
    ///
    /// Non-bypass resolution reads the provider exactly once per hop and selects
    /// exactly one current record.
    fn resolve(
        &self,
        proxy_origin: &CanonicalOrigin,
        destination_origin: &CanonicalOrigin,
    ) -> Result<Option<ProxyCredentialRecord>, NetworkError>;
}

/// Validate bindings and resolve a credential record from the provider for the
/// given proxy and destination origins.
///
/// Both bindings must match the same current record snapshot:
/// 1. The actual proxy `CanonicalOrigin` exactly matches the record's proxy origin.
/// 2. The effective destination `CanonicalOrigin` exactly matches one member of
///    that snapshot's allowed destination set.
///
/// Wildcards, suffix matching, ambient defaults, and "same host as the request"
/// shortcuts are prohibited. A malformed route, missing record, stale generation,
/// stale scope epoch, or mismatch fails closed as [`NetworkError::Offline`].
/// It never falls back to an older record, an unauthenticated proxy, or direct egress.
pub fn resolve_proxy_record(
    provider: &dyn ProxyCredentialProvider,
    proxy_origin: &CanonicalOrigin,
    destination_origin: &CanonicalOrigin,
) -> Result<ProxyCredentialRecord, NetworkError> {
    let Some(record) = provider.resolve(proxy_origin, destination_origin)? else {
        return Err(NetworkError::Offline);
    };
    if &record.proxy_origin != proxy_origin {
        return Err(NetworkError::Offline);
    }
    if !record.allowed_destinations.contains(destination_origin) {
        return Err(NetworkError::Offline);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_matches_the_gate() {
        assert_eq!(env_proxy_enabled(), cfg!(feature = "proxy"));
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn gate_on_enables_env_inheritance() {
        assert!(env_proxy_enabled());
    }

    #[cfg(not(feature = "proxy"))]
    #[test]
    fn gate_off_disables_env_inheritance() {
        assert!(!env_proxy_enabled());
    }

    #[test]
    fn record_debug_is_redacting_and_emits_no_canary() {
        let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
        let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();
        let record = ProxyCredentialRecord {
            id: "CANARY_SECRET_ID_12345".to_owned(),
            proxy_origin: proxy,
            allowed_destinations: vec![dest],
            generation: 42,
            scope_epoch: 99,
        };
        let formatted = format!("{record:?}");
        assert!(!formatted.contains("CANARY_SECRET_ID_12345"));
        assert!(!formatted.contains("proxy.test"));
        assert!(!formatted.contains("api.test"));
        assert!(!formatted.contains("42"));
        assert!(!formatted.contains("99"));
        assert!(formatted.contains("ProxyCredentialRecord"));
    }

    #[derive(Debug)]
    struct MockProvider {
        result: Option<ProxyCredentialRecord>,
    }

    impl ProxyCredentialProvider for MockProvider {
        fn resolve(
            &self,
            _proxy_origin: &CanonicalOrigin,
            _destination_origin: &CanonicalOrigin,
        ) -> Result<Option<ProxyCredentialRecord>, NetworkError> {
            Ok(self.result.clone())
        }
    }

    #[test]
    fn resolve_proxy_record_enforces_both_bindings() {
        let proxy1 = CanonicalOrigin::parse("http://proxy1.test:8080").unwrap();
        let proxy2 = CanonicalOrigin::parse("http://proxy2.test:8080").unwrap();
        let dest1 = CanonicalOrigin::parse("https://api1.test:443").unwrap();
        let dest2 = CanonicalOrigin::parse("https://api2.test:443").unwrap();

        // 1. Valid matching record succeeds
        let valid_record = ProxyCredentialRecord {
            id: "rec-1".to_owned(),
            proxy_origin: proxy1.clone(),
            allowed_destinations: vec![dest1.clone()],
            generation: 1,
            scope_epoch: 1,
        };
        let provider = MockProvider {
            result: Some(valid_record.clone()),
        };
        let resolved = resolve_proxy_record(&provider, &proxy1, &dest1);
        assert_eq!(resolved.as_ref(), Ok(&valid_record));

        // 2. Mismatched proxy origin fails closed
        let mismatch_proxy = resolve_proxy_record(&provider, &proxy2, &dest1);
        assert_eq!(mismatch_proxy, Err(NetworkError::Offline));

        // 3. Mismatched destination origin fails closed
        let mismatch_dest = resolve_proxy_record(&provider, &proxy1, &dest2);
        assert_eq!(mismatch_dest, Err(NetworkError::Offline));

        // 4. Missing record fails closed
        let empty_provider = MockProvider { result: None };
        assert_eq!(
            resolve_proxy_record(&empty_provider, &proxy1, &dest1),
            Err(NetworkError::Offline)
        );
    }
}
