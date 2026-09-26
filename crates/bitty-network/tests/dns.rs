//! Acceptance tests for the shared DNS cache (issue #23).
//!
//! The unit pins in `src/dns.rs` reach into the store to drive a fake clock.
//! This file pins what a consumer outside the module can actually observe
//! about the cache: one shared store, with the bounds and the authority
//! rules holding at the public seam.
//!
//! No backend reaches the cache yet. `crate::http` and `crate::websocket` are
//! owned by other lanes, and nothing in this crate calls [`resolve_shared`]
//! outside a test — so "used by every backend" is a wiring state this file
//! neither claims nor tests, and issue #23 stays open for it. What this file
//! can pin is the half of the adopter obligation that is observable from out
//! here: that the cache's key granularity and the capability allowlist's
//! decision granularity are the same relation, asserted against the real
//! [`NetworkCapability`] rather than against a restatement of the key. The
//! other half — that a future adapter hands over the check's own host string
//! and the request's port, neither of which reqwest's resolver hook can
//! supply on its own — is documented in `src/dns.rs` and is not observable
//! until that adapter exists.
//!
//! No network and no resolver: every resolver here is an in-memory fixture
//! answering loopback literals, and nothing is ever dialled.
//!
//! [`NetworkCapability`]: bitty_network_api::NetworkCapability
//! [`resolve_shared`]: bitty_network::dns::resolve_shared

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bitty_network::dns::{
    DEFAULT_DNS_TIMEOUT, DNS_CACHE_MAX_ENTRIES, DnsCache, DnsError, DnsResolver, resolve_cached,
    resolve_shared, shared,
};
use bitty_network_api::NetworkCapability;

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

/// The cache's host equivalence class is the allowlist's, verified against the
/// real [`NetworkCapability`] rather than against a restatement of the key.
///
/// This is the observable half of the adopter obligation in `src/dns.rs`: it
/// is what makes handing the cache the check's own unmodified host string
/// *sufficient*. The allowlist is the independent oracle, so a change to
/// either side's normalization fails here — including a coarsening of the
/// cache key, which would merge two classes the allowlist still separates.
#[test]
fn the_cache_key_class_is_exactly_the_allowlist_class() {
    // One host, granted on exactly one port. Every spelling below is the
    // same host to the allowlist, and must be the same key to the cache.
    let capability =
        NetworkCapability::offline().with_domain_ports("Granted.Test.", [FIXTURE_PORT]);
    let cache = DnsCache::new();
    let (resolver, calls) = CountingResolver::new();
    let cancel = AtomicBool::new(false);

    for host in ["granted.test", "GRANTED.test.", "  granted.test  "] {
        assert!(
            capability.allows(host),
            "the allowlist must treat {host:?} as the granted host"
        );
        let resolved = resolve_cached(
            &cache,
            resolver.clone(),
            host,
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        assert_eq!(
            resolved,
            Ok(answer(FIXTURE_PORT)),
            "the cache must answer {host:?} from the one entry"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "three spellings of one allowlist class are one cache key, so the resolver is asked once"
    );
    assert_eq!(cache.len(), 1, "one class, one entry");

    // A host the allowlist does not know is a different class, so it is a
    // different key: resolved for itself, never answered from the granted
    // host's entry.
    assert!(!capability.allows("other-granted.test"));
    let resolved = resolve_cached(
        &cache,
        resolver.clone(),
        "other-granted.test",
        FIXTURE_PORT,
        DEFAULT_DNS_TIMEOUT,
        &cancel,
    );
    assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an ungranted host must reach the resolver, not inherit the granted host's answer"
    );
    assert_eq!(cache.len(), 2, "two classes, two entries");

    // Two separately authorized hosts under one registrable domain are the
    // case a re-deriving adopter actually gets wrong. Folding
    // "api.granted.test" down to "granted.test" would merge two hosts the
    // allowlist authorizes independently into a single entry, and would
    // merge a granted host with a refused sibling just as readily. Both must
    // stay distinct here.
    let siblings = NetworkCapability::offline()
        .with_domain_ports("api.granted.test.", [FIXTURE_PORT])
        .with_domain_ports("www.granted.test", [FIXTURE_PORT]);
    let sibling_cache = DnsCache::new();
    for host in ["api.granted.test", "www.granted.test"] {
        assert!(
            siblings.allows_port(host, FIXTURE_PORT),
            "the allowlist must authorize {host:?} for itself"
        );
        let resolved = resolve_cached(
            &sibling_cache,
            resolver.clone(),
            host,
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "one registrable domain, two independently authorized hosts, two resolver calls and two keys"
    );
    assert_eq!(sibling_cache.len(), 2);

    // The refused sibling under the same registrable domain reaches the
    // resolver rather than being answered from either authorized host.
    assert!(!siblings.allows("cdn.granted.test"));
    let resolved = resolve_cached(
        &sibling_cache,
        resolver.clone(),
        "cdn.granted.test",
        FIXTURE_PORT,
        DEFAULT_DNS_TIMEOUT,
        &cancel,
    );
    assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "a refused sibling must not be answered from a sibling host's entry"
    );
    assert_eq!(sibling_cache.len(), 3);
}

/// The port half of the key is what keeps the cache as fine as the
/// allowlist's per-host port set, again checked against the real
/// [`NetworkCapability`] as an independent oracle.
///
/// An adopter that cannot source the port from reqwest's resolver hook —
/// that hook's `Name` is a host with no port — and folds the port away would
/// make the cache coarser than the allowlist. This is the pin that says so:
/// the allowlist denies the ungranted port while the cache must already
/// refuse to have an answer for it, and if the key ever lost its port half
/// these two would disagree.
#[test]
fn the_cache_key_is_as_fine_as_the_allowlist_port_set() {
    let capability =
        NetworkCapability::offline().with_domain_ports("one-port.test", [FIXTURE_PORT]);
    let cache = DnsCache::new();
    let (resolver, calls) = CountingResolver::new();
    let cancel = AtomicBool::new(false);

    // The granted query.
    assert!(capability.allows_port("one-port.test", FIXTURE_PORT));
    let resolved = resolve_cached(
        &cache,
        resolver.clone(),
        "one-port.test",
        FIXTURE_PORT,
        DEFAULT_DNS_TIMEOUT,
        &cancel,
    );
    assert_eq!(resolved, Ok(answer(FIXTURE_PORT)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The same host on a port the allowlist refuses. The allowlist is the
    // oracle: it denies this query, so a cache that had an entry here would
    // be coarser than the authority it sits below. The port in the key is
    // what makes it miss instead.
    assert!(
        !capability.allows_port("one-port.test", OTHER_FIXTURE_PORT),
        "the allowlist must refuse the ungranted port for this host"
    );
    let resolved = resolve_cached(
        &cache,
        resolver.clone(),
        "one-port.test",
        OTHER_FIXTURE_PORT,
        DEFAULT_DNS_TIMEOUT,
        &cancel,
    );
    assert_eq!(resolved, Ok(answer(OTHER_FIXTURE_PORT)));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the ungranted port must reach the resolver, not be served the granted port's answer"
    );
    assert_eq!(
        cache.len(),
        2,
        "two ports on one host are two keys, matching the allowlist's port set"
    );
}
