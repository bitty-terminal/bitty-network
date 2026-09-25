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
}
