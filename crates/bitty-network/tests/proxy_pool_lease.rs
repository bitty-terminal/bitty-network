//! Integration tests for #25 (Criterion 7):
//! - Authenticated Connection/Client Pool Lease and Checkout Protocol:
//!   1. A connection is unusable without an active lease;
//!   2. Pools never reuse across differing pool-key fields;
//!   3. Two distinct records with equal generation and scope epoch get distinct pools;
//!   4. Checkout failure never falls back to another pool;
//!   5. Threads waiting in checkout either take a lease on the new key or fail closed;
//!   6. HttpNetworkService scope registry tracks and invalidates authenticated egress.

#![cfg(all(feature = "http", feature = "websocket"))]
#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bitty_network::origin::CanonicalOrigin;
use bitty_network::proxy::{
    PoolKey, ProxyCredentialProvider, ProxyCredentialRecord, ScopeRegistry,
};
use bitty_network::{HttpNetworkService, NetworkCapability, NetworkError, NetworkService, Request};

/// Loopback HTTP probe server for testing proxied hops.
struct Probe {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Probe {
    fn start(handler: impl Fn(&str) -> Vec<u8> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback probe");
        listener.set_nonblocking(true).expect("probe nonblocking");
        let port = listener.local_addr().expect("probe port").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_hits = Arc::clone(&hits);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("accepted stream blocking");
                        thread_hits.fetch_add(1, Ordering::SeqCst);
                        let head = read_head(stream.try_clone().expect("clone probe stream"));
                        let response = handler(&head);
                        if let Ok(mut stream) = stream.try_clone() {
                            let _ = stream.write_all(&response);
                            let _ = stream.flush();
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            hits,
            stop,
            handle: Some(handle),
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_head(mut stream: TcpStream) -> String {
    let mut buf = [0u8; 1024];
    let mut collected = Vec::new();
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break;
        }
        collected.extend_from_slice(&buf[..n]);
        if collected.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
}

#[derive(Debug)]
struct MockProvider {
    record: Option<ProxyCredentialRecord>,
    calls: Arc<AtomicUsize>,
}

impl MockProvider {
    fn new(record: Option<ProxyCredentialRecord>) -> (Arc<Self>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                record,
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }
}

impl ProxyCredentialProvider for MockProvider {
    fn resolve(
        &self,
        _proxy_origin: &CanonicalOrigin,
        _destination_origin: &CanonicalOrigin,
    ) -> Result<Option<ProxyCredentialRecord>, NetworkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.record.clone())
    }
}

// -----------------------------------------------------------------------------
// Test 1: connection_is_unusable_without_current_lease
// -----------------------------------------------------------------------------
#[test]
fn connection_is_unusable_without_current_lease() {
    let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
    let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();
    let key = PoolKey::new(proxy, dest, "cred-lease-1", 1, 1);

    let registry = ScopeRegistry::<String>::new();
    let lease = registry
        .register(key.clone(), "pooled-client".to_owned())
        .expect("register entry");
    assert!(lease.is_active());
    assert_eq!(registry.active_entry_count(), 1);
    assert_eq!(registry.active_lease_count(&key), 1);

    // Explicit lease cancellation makes connection unusable
    lease.cancel();
    assert!(!lease.is_active());

    // Invalidation removes key and cancels any new checkouts
    drop(lease);
    registry
        .invalidate(&key, Duration::from_millis(100))
        .expect("invalidate key");
    assert_eq!(registry.active_entry_count(), 0);
    assert!(matches!(
        registry.checkout(&key),
        Err(NetworkError::Offline)
    ));
}

// -----------------------------------------------------------------------------
// Test 2: pools_never_reuse_across_differing_pool_key_fields
// -----------------------------------------------------------------------------
#[test]
fn pools_never_reuse_across_differing_pool_key_fields() {
    let proxy1 = CanonicalOrigin::parse("http://proxy1.test:8080").unwrap();
    let proxy2 = CanonicalOrigin::parse("http://proxy2.test:8080").unwrap();
    let dest1 = CanonicalOrigin::parse("https://api1.test:443").unwrap();
    let dest2 = CanonicalOrigin::parse("https://api2.test:443").unwrap();

    let registry = ScopeRegistry::<String>::new();

    let base_key = PoolKey::new(proxy1.clone(), dest1.clone(), "cred-1", 10, 20);
    let diff_proxy = PoolKey::new(proxy2, dest1.clone(), "cred-1", 10, 20);
    let diff_dest = PoolKey::new(proxy1.clone(), dest2, "cred-1", 10, 20);
    let diff_cred = PoolKey::new(proxy1.clone(), dest1.clone(), "cred-2", 10, 20);
    let diff_gen = PoolKey::new(proxy1.clone(), dest1.clone(), "cred-1", 11, 20);
    let diff_epoch = PoolKey::new(proxy1, dest1, "cred-1", 10, 21);

    let keys = vec![
        (base_key.clone(), "base"),
        (diff_proxy.clone(), "diff_proxy"),
        (diff_dest.clone(), "diff_dest"),
        (diff_cred.clone(), "diff_cred"),
        (diff_gen.clone(), "diff_gen"),
        (diff_epoch.clone(), "diff_epoch"),
    ];

    for (k, val) in &keys {
        let _ = registry.register(k.clone(), (*val).to_owned()).unwrap();
    }

    assert_eq!(registry.active_entry_count(), 6);

    for (k, expected_val) in &keys {
        let (val, lease) = registry.checkout(k).unwrap();
        assert_eq!(&val, expected_val);
        assert!(lease.is_active());
        assert_eq!(lease.key(), k);
    }
}

// -----------------------------------------------------------------------------
// Test 3: distinct_records_with_equal_generation_and_scope_epoch_get_distinct_pools
// -----------------------------------------------------------------------------
#[test]
fn distinct_records_with_equal_generation_and_scope_epoch_get_distinct_pools() {
    let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
    let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();

    // Two distinct records with equal generation (42) and equal scope epoch (7)
    let key_alpha = PoolKey::new(proxy.clone(), dest.clone(), "record-alpha", 42, 7);
    let key_beta = PoolKey::new(proxy, dest, "record-beta", 42, 7);

    let registry = ScopeRegistry::<String>::new();
    let lease_alpha = registry
        .register(key_alpha.clone(), "client-alpha".to_owned())
        .unwrap();
    let lease_beta = registry
        .register(key_beta.clone(), "client-beta".to_owned())
        .unwrap();

    assert_eq!(registry.active_entry_count(), 2);

    let (item_alpha, _) = registry.checkout(&key_alpha).unwrap();
    let (item_beta, _) = registry.checkout(&key_beta).unwrap();
    assert_eq!(item_alpha, "client-alpha");
    assert_eq!(item_beta, "client-beta");

    // Invalidation of alpha does not invalidate beta
    drop(lease_alpha);
    registry
        .invalidate(&key_alpha, Duration::from_millis(50))
        .unwrap();

    assert_eq!(registry.active_entry_count(), 1);
    assert!(matches!(
        registry.checkout(&key_alpha),
        Err(NetworkError::Offline)
    ));
    assert!(registry.checkout(&key_beta).is_ok());

    drop(lease_beta);
}

// -----------------------------------------------------------------------------
// Test 4: checkout_failure_never_falls_back_to_another_pool
// -----------------------------------------------------------------------------
#[test]
fn checkout_failure_never_falls_back_to_another_pool() {
    let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
    let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();

    let key_existing = PoolKey::new(proxy.clone(), dest.clone(), "cred-existing", 1, 1);
    let key_missing = PoolKey::new(proxy, dest, "cred-missing", 1, 1);

    let registry = ScopeRegistry::<String>::new();
    let _lease = registry
        .register(key_existing.clone(), "valid-client".to_owned())
        .unwrap();

    // Missing key fails closed; never returns key_existing's client
    assert!(matches!(
        registry.checkout(&key_missing),
        Err(NetworkError::Offline)
    ));

    // Invalidate existing key
    drop(_lease);
    registry
        .invalidate(&key_existing, Duration::from_millis(50))
        .unwrap();
    assert!(matches!(
        registry.checkout(&key_existing),
        Err(NetworkError::Offline)
    ));
}

// -----------------------------------------------------------------------------
// Test 5: thread_waiting_in_checkout_takes_lease_on_new_key_or_fails_closed
// -----------------------------------------------------------------------------
#[test]
fn thread_waiting_in_checkout_takes_lease_on_new_key_or_fails_closed() {
    let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
    let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();
    let registry = Arc::new(ScopeRegistry::<usize>::new());

    let stop = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();

    // Spawn 8 worker threads attempting checkout_or_create
    for thread_idx in 0..8 {
        let reg = Arc::clone(&registry);
        let st = Arc::clone(&stop);
        let p = proxy.clone();
        let d = dest.clone();

        workers.push(thread::spawn(move || {
            let mut iter = 0;
            while !st.load(Ordering::SeqCst) && iter < 100 {
                iter += 1;
                let epoch = (iter % 3) as u64 + 1;
                let key = PoolKey::new(p.clone(), d.clone(), "cred-concurrent", 1, epoch);
                match reg.checkout_or_create(&key, || Ok(thread_idx)) {
                    Ok((_val, lease)) => {
                        assert!(lease.is_active());
                        thread::sleep(Duration::from_micros(200));
                        drop(lease);
                    }
                    Err(e) => {
                        assert_eq!(e, NetworkError::Offline);
                    }
                }
            }
        }));
    }

    // Invalidator thread invalidating epochs concurrently
    let reg_inv = Arc::clone(&registry);
    let p_inv = proxy.clone();
    let inv_thread = thread::spawn(move || {
        for epoch in 1..=3 {
            thread::sleep(Duration::from_millis(5));
            let _ = reg_inv.invalidate_scope_epoch(
                &p_inv,
                "cred-concurrent",
                epoch,
                Duration::from_millis(20),
            );
        }
    });

    for w in workers {
        w.join().unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    inv_thread.join().unwrap();
}

// -----------------------------------------------------------------------------
// Test 6: service_scope_registry_tracks_and_invalidates_authenticated_egress
// -----------------------------------------------------------------------------
#[test]
fn service_scope_registry_tracks_and_invalidates_authenticated_egress() {
    let proxy_probe =
        Probe::start(|_head| b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nproxy".to_vec());

    let proxy_url = format!("http://127.0.0.1:{}", proxy_probe.port);
    let proxy_origin = CanonicalOrigin::parse(&proxy_url).unwrap();
    let dest_url = "http://api.authenticated.service/v1";
    let dest_origin = CanonicalOrigin::parse(dest_url).unwrap();

    let record = ProxyCredentialRecord {
        id: "cred-service-1".to_owned(),
        proxy_origin: proxy_origin.clone(),
        allowed_destinations: vec![dest_origin.clone()],
        generation: 1,
        scope_epoch: 1,
    };

    let (provider, calls) = MockProvider::new(Some(record.clone()));

    let service = HttpNetworkService::with_proxy_bypass_and_provider(
        NetworkCapability::offline().with_domain("api.authenticated.service"),
        &proxy_url,
        "127.0.0.1",
        provider,
    )
    .expect("build service");

    // Before any request, registry is empty
    assert_eq!(service.scope_registry().active_entry_count(), 0);

    // Make an egress request
    let resp = service
        .request(&Request::get(dest_url))
        .expect("request succeeds");
    assert_eq!(resp.status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(proxy_probe.hits(), 1);

    // Registry now owns exactly one entry for the pool key
    assert_eq!(service.scope_registry().active_entry_count(), 1);
    let pool_key = PoolKey::from_record(&record, &dest_origin);
    assert!(service.scope_registry().checkout(&pool_key).is_ok());

    // Invalidate the pool key in the service's scope registry
    service
        .scope_registry()
        .invalidate(&pool_key, Duration::from_millis(50))
        .expect("invalidate service pool key");

    assert_eq!(service.scope_registry().active_entry_count(), 0);
    assert!(matches!(
        service.scope_registry().checkout(&pool_key),
        Err(NetworkError::Offline)
    ));

    proxy_probe.stop_and_join();
}
