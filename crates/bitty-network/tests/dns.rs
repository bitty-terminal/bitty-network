//! Acceptance tests for the shared DNS cache (issue #23).
//!
//! The unit pins in `src/dns.rs` reach into the store to drive a fake clock.
//! This file pins what a consumer outside the module can actually observe
//! about the cache, which is the property the issue asks for: one shared
//! store, reachable from every backend, with the bounds and the authority
//! rules holding at the public seam.
//!
//! No network and no resolver: every resolver here is an in-memory fixture
//! answering loopback literals, and nothing is ever dialled.
//!
//! [`NetworkCapability::check_handshake`]: bitty_network_api::NetworkCapability::check_handshake

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bitty_network::dns::{
    DEFAULT_DNS_TIMEOUT, DNS_CACHE_MAX_ENTRIES, DnsCache, DnsError, DnsResolver, resolve_cached,
    resolve_shared, shared,
};

/// Loopback literals for the in-memory fixtures: never dialled, never
/// reached, and protocol constants rather than host values.
const LOOPBACK_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const LOOPBACK_V6: Ipv6Addr = Ipv6Addr::LOCALHOST;

/// Fixture port for the in-memory answers; resolution never leaves the
/// process, so the value is arbitrary and never a live service.
const FIXTURE_PORT: u16 = 18_101;

/// Second fixture port, so no test can pass by answering one port's lookup
/// with another's entry.
const OTHER_FIXTURE_PORT: u16 = 18_102;

/// Resolver answering loopback literals and counting its invocations.
#[derive(Clone)]
struct CountingResolver {
    calls: Arc<AtomicUsize>,
}

impl CountingResolver {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl DnsResolver for CountingResolver {
    fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![
            SocketAddr::from((LOOPBACK_V4, port)),
            SocketAddr::from((LOOPBACK_V6, port)),
        ])
    }
}

/// The address list the fixture answers with.
fn answer(port: u16) -> Vec<SocketAddr> {
    vec![
        SocketAddr::from((LOOPBACK_V4, port)),
        SocketAddr::from((LOOPBACK_V6, port)),
    ]
}

#[test]
fn a_second_lookup_is_served_without_the_resolver() {
    let cache = DnsCache::new();
    let (resolver, calls) = CountingResolver::new();
    let cancel = AtomicBool::new(false);
    for _ in 0..3 {
        let resolved = resolve_cached(
            &cache,
            resolver.clone(),
            "cacheable.test",
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only the first lookup may reach the resolver"
    );
    assert_eq!(cache.len(), 1);
}

#[test]
fn two_backends_share_one_bounded_store() {
    let (resolver, calls) = CountingResolver::new();
    let cancel = AtomicBool::new(false);
    // Two independent callers, as two backends would be, going through the
    // process-wide instance rather than a private one.
    for _ in 0..2 {
        let resolved = resolve_shared(
            resolver.clone(),
            "shared-across-backends.test",
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the shared cache is what makes the bound mean anything"
    );
    assert!(std::ptr::eq(shared(), shared()));
    // Overflowing the shared store must still respect the bound. This shares
    // the process-wide instance with the test above, so it runs in the same
    // test rather than in a second one racing it for the same entries.
    for index in 0..DNS_CACHE_MAX_ENTRIES + 16 {
        let host = format!("bounded-{index}.test");
        let resolved = resolve_shared(
            resolver.clone(),
            &host,
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
        assert!(
            shared().len() <= DNS_CACHE_MAX_ENTRIES,
            "the shared store grew past its bound: {}",
            shared().len()
        );
    }
    assert_eq!(shared().len(), DNS_CACHE_MAX_ENTRIES);
}

#[test]
fn a_cached_answer_never_crosses_the_authorized_query() {
    let cache = DnsCache::new();
    let (resolver, calls) = CountingResolver::new();
    let cancel = AtomicBool::new(false);
    // The allowlist is per (host, port): an answer resolved for one granted
    // query must not be handed to a different one.
    for (host, port) in [
        ("granted.test", FIXTURE_PORT),
        ("granted.test", OTHER_FIXTURE_PORT),
        ("other-granted.test", FIXTURE_PORT),
    ] {
        let resolved = resolve_cached(
            &cache,
            resolver.clone(),
            host,
            port,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        assert_eq!(
            resolved,
            Ok(answer(port)),
            "each query must be answered for itself"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(cache.len(), 3);
}

#[test]
fn a_cache_hit_cannot_outlive_the_callers_deadline() {
    let cache = DnsCache::new();
    let (resolver, _calls) = CountingResolver::new();
    let cancel = AtomicBool::new(false);
    let resolved = resolve_cached(
        &cache,
        resolver.clone(),
        "deadline-bounded.test",
        FIXTURE_PORT,
        DEFAULT_DNS_TIMEOUT,
        &cancel,
    );
    assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
    // A live entry plus a caller whose budget is already spent: the entry is
    // free to serve, so serving it would hand a timed-out caller an answer.
    let spent = std::time::Duration::ZERO;
    let resolved = resolve_cached(
        &cache,
        resolver.clone(),
        "deadline-bounded.test",
        FIXTURE_PORT,
        spent,
        &cancel,
    );
    assert_eq!(resolved, Err(DnsError::Timeout { after: spent }));
}

#[test]
fn a_cache_hit_cannot_outlive_cancellation() {
    let cache = DnsCache::new();
    let (resolver, calls) = CountingResolver::new();
    let cancel = AtomicBool::new(false);
    let resolved = resolve_cached(
        &cache,
        resolver.clone(),
        "cancelled-hit.test",
        FIXTURE_PORT,
        DEFAULT_DNS_TIMEOUT,
        &cancel,
    );
    assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    cancel.store(true, Ordering::SeqCst);
    let resolved = resolve_cached(
        &cache,
        resolver.clone(),
        "cancelled-hit.test",
        FIXTURE_PORT,
        DEFAULT_DNS_TIMEOUT,
        &cancel,
    );
    assert_eq!(resolved, Err(DnsError::Cancelled));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a cancelled call must not reach the resolver even on a hit"
    );
}
