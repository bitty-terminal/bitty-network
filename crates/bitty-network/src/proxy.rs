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

use std::collections::HashMap;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

/// Five-field key uniquely identifying an authenticated connection pool entry.
///
/// A pool key is a structured value containing at least:
/// - canonical proxy origin;
/// - canonical destination origin;
/// - the stable, non-secret credential-record identity;
/// - credential generation; and
/// - scope epoch.
///
/// Two different records with equal generation and scope epoch still have
/// different pool keys and can never share a pool.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub proxy_origin: CanonicalOrigin,
    pub destination_origin: CanonicalOrigin,
    pub credential_id: String,
    pub generation: u64,
    pub scope_epoch: u64,
}

impl PoolKey {
    /// Construct a new pool key from explicit fields.
    pub fn new(
        proxy_origin: CanonicalOrigin,
        destination_origin: CanonicalOrigin,
        credential_id: impl Into<String>,
        generation: u64,
        scope_epoch: u64,
    ) -> Self {
        Self {
            proxy_origin,
            destination_origin,
            credential_id: credential_id.into(),
            generation,
            scope_epoch,
        }
    }

    /// Construct a pool key bound to `record` and `destination`.
    pub fn from_record(record: &ProxyCredentialRecord, destination: &CanonicalOrigin) -> Self {
        Self {
            proxy_origin: record.proxy_origin.clone(),
            destination_origin: destination.clone(),
            credential_id: record.id.clone(),
            generation: record.generation,
            scope_epoch: record.scope_epoch,
        }
    }
}

impl std::fmt::Debug for PoolKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacting Debug: structurally descriptive without emitting secret or canary material
        f.debug_struct("PoolKey").finish_non_exhaustive()
    }
}

/// Internal RAII guard to decrement active leases on drop.
struct LeaseGuard {
    active_leases: Arc<AtomicUsize>,
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        self.active_leases.fetch_sub(1, Ordering::SeqCst);
    }
}

/// An authorization lease tying a checked-out connection or client to a specific
/// pool key, credential generation, and scope epoch.
///
/// A connection is unusable without an active lease. Invalidation of the pool
/// entry marks the lease inactive, cancels it, and waits for outstanding leases
/// to be released before destroying resources.
#[derive(Clone)]
pub struct AuthorizationLease {
    key: PoolKey,
    active: Arc<AtomicBool>,
    _guard: Arc<LeaseGuard>,
}

impl AuthorizationLease {
    /// True when the lease remains active.
    ///
    /// An invalidated or cancelled lease returns false, failing any attempted
    /// connection use closed.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// The pool key this lease is bound to.
    #[must_use]
    pub fn key(&self) -> &PoolKey {
        &self.key
    }

    /// Cancel this lease, marking it permanently inactive.
    pub fn cancel(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for AuthorizationLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacting Debug: reports active status without emitting secret or canary material
        f.debug_struct("AuthorizationLease")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

struct RegistryEntry<T> {
    key: PoolKey,
    active: Arc<AtomicBool>,
    active_leases: Arc<AtomicUsize>,
    item: T,
}

/// Scope registry owning authenticated clients, connection pools, and leases.
///
/// Every authenticated client and connection pool has one scope registry owner.
/// Checkouts revalidate every pool-key field and take an active lease under the
/// read-side guard. Invalidation under the exclusive guard marks the key inactive,
/// removes it from lookup, cancels leases, and waits for active leases to drain.
pub struct ScopeRegistry<T> {
    entries: RwLock<HashMap<PoolKey, Arc<RegistryEntry<T>>>>,
}

impl<T: Clone + Send + Sync + 'static> Default for ScopeRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> std::fmt::Debug for ScopeRegistry<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.entries.read().map(|e| e.len()).unwrap_or(0);
        f.debug_struct("ScopeRegistry")
            .field("active_entries", &count)
            .finish_non_exhaustive()
    }
}

impl<T: Clone + Send + Sync + 'static> ScopeRegistry<T> {
    /// Create a new empty scope registry.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Check out an item from the pool under the given key while holding an active lease.
    ///
    /// Checkout occurs under the registry synchronization protocol:
    /// - Revalidates all 5 pool key fields against the active entry.
    /// - Confirms that the entry is active (not invalidated).
    /// - Increments the in-flight lease count and returns the item + AuthorizationLease.
    /// - Every checkout failure fails closed; it never searches another pool as fallback.
    pub fn checkout(&self, key: &PoolKey) -> Result<(T, AuthorizationLease), NetworkError> {
        let entries = self.entries.read().map_err(|_| NetworkError::Offline)?;
        let entry = entries.get(key).ok_or(NetworkError::Offline)?;

        // Revalidate every key field
        if &entry.key != key {
            return Err(NetworkError::Offline);
        }

        // Confirm active status
        if !entry.active.load(Ordering::SeqCst) {
            return Err(NetworkError::Offline);
        }

        // Increment in-flight lease count
        entry.active_leases.fetch_add(1, Ordering::SeqCst);
        let guard = Arc::new(LeaseGuard {
            active_leases: Arc::clone(&entry.active_leases),
        });

        let lease = AuthorizationLease {
            key: key.clone(),
            active: Arc::clone(&entry.active),
            _guard: guard,
        };

        Ok((entry.item.clone(), lease))
    }

    /// Register or update an active pool entry for the given pool key.
    pub fn register(&self, key: PoolKey, item: T) -> Result<AuthorizationLease, NetworkError> {
        let mut entries = self.entries.write().map_err(|_| NetworkError::Offline)?;
        let active = Arc::new(AtomicBool::new(true));
        let active_leases = Arc::new(AtomicUsize::new(1));
        let guard = Arc::new(LeaseGuard {
            active_leases: Arc::clone(&active_leases),
        });
        let lease = AuthorizationLease {
            key: key.clone(),
            active: Arc::clone(&active),
            _guard: guard,
        };
        let entry = Arc::new(RegistryEntry {
            key: key.clone(),
            active,
            active_leases,
            item,
        });
        entries.insert(key, entry);
        Ok(lease)
    }

    /// Check out an existing entry for `key`, or initialize one with `builder` if absent.
    pub fn checkout_or_create<F>(
        &self,
        key: &PoolKey,
        builder: F,
    ) -> Result<(T, AuthorizationLease), NetworkError>
    where
        F: FnOnce() -> Result<T, NetworkError>,
    {
        // 1. Fast read path: if active entry exists, check it out
        if let Ok(result) = self.checkout(key) {
            return Ok(result);
        }

        // 2. Write path: register and return lease
        let mut entries = self.entries.write().map_err(|_| NetworkError::Offline)?;
        if let Some(entry) = entries.get(key) {
            if entry.active.load(Ordering::SeqCst) && &entry.key == key {
                entry.active_leases.fetch_add(1, Ordering::SeqCst);
                let guard = Arc::new(LeaseGuard {
                    active_leases: Arc::clone(&entry.active_leases),
                });
                let lease = AuthorizationLease {
                    key: key.clone(),
                    active: Arc::clone(&entry.active),
                    _guard: guard,
                };
                return Ok((entry.item.clone(), lease));
            }
        }

        let item = builder()?;
        let active = Arc::new(AtomicBool::new(true));
        let active_leases = Arc::new(AtomicUsize::new(1));
        let guard = Arc::new(LeaseGuard {
            active_leases: Arc::clone(&active_leases),
        });
        let lease = AuthorizationLease {
            key: key.clone(),
            active: Arc::clone(&active),
            _guard: guard,
        };
        let entry = Arc::new(RegistryEntry {
            key: key.clone(),
            active,
            active_leases,
            item: item.clone(),
        });
        entries.insert(key.clone(), entry);
        Ok((item, lease))
    }

    /// Invalidate the entry for `key`: marks it inactive, removes from lookup,
    /// cancels existing leases, and waits up to `timeout` for active leases to drain.
    pub fn invalidate(&self, key: &PoolKey, timeout: Duration) -> Result<(), NetworkError> {
        let entry = {
            let mut entries = self.entries.write().map_err(|_| NetworkError::Offline)?;
            entries.remove(key)
        };

        if let Some(entry) = entry {
            entry.active.store(false, Ordering::SeqCst);
            // Wait for active leases to drain
            let start = Instant::now();
            while entry.active_leases.load(Ordering::SeqCst) > 0 {
                if start.elapsed() >= timeout {
                    return Err(NetworkError::Offline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }

    /// Invalidate all entries for a given proxy and credential where scope_epoch < new_epoch.
    pub fn invalidate_scope_epoch(
        &self,
        proxy_origin: &CanonicalOrigin,
        credential_id: &str,
        new_epoch: u64,
        timeout: Duration,
    ) -> Result<(), NetworkError> {
        let matching_keys: Vec<PoolKey> = {
            let entries = self.entries.read().map_err(|_| NetworkError::Offline)?;
            entries
                .keys()
                .filter(|k| {
                    &k.proxy_origin == proxy_origin
                        && k.credential_id == credential_id
                        && k.scope_epoch < new_epoch
                })
                .cloned()
                .collect()
        };

        for key in matching_keys {
            self.invalidate(&key, timeout)?;
        }
        Ok(())
    }

    /// Invalidate all entries for a given proxy and credential where generation < new_generation.
    pub fn invalidate_generation(
        &self,
        proxy_origin: &CanonicalOrigin,
        credential_id: &str,
        new_generation: u64,
        timeout: Duration,
    ) -> Result<(), NetworkError> {
        let matching_keys: Vec<PoolKey> = {
            let entries = self.entries.read().map_err(|_| NetworkError::Offline)?;
            entries
                .keys()
                .filter(|k| {
                    &k.proxy_origin == proxy_origin
                        && k.credential_id == credential_id
                        && k.generation < new_generation
                })
                .cloned()
                .collect()
        };

        for key in matching_keys {
            self.invalidate(&key, timeout)?;
        }
        Ok(())
    }

    /// Count of active entries currently in the lookup table.
    pub fn active_entry_count(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    /// In-flight active lease count for a specific pool key.
    pub fn active_lease_count(&self, key: &PoolKey) -> usize {
        self.entries
            .read()
            .ok()
            .and_then(|entries| {
                entries
                    .get(key)
                    .map(|e| e.active_leases.load(Ordering::SeqCst))
            })
            .unwrap_or(0)
    }
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

    #[test]
    fn pool_key_debug_is_redacting_and_emits_no_canary() {
        let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
        let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();
        let key = PoolKey::new(proxy, dest, "SECRET_CRED_CANARY", 1, 1);
        let debug_str = format!("{key:?}");
        assert!(!debug_str.contains("SECRET_CRED_CANARY"));
        assert!(!debug_str.contains("proxy.test"));
        assert!(!debug_str.contains("api.test"));
        assert!(debug_str.contains("PoolKey"));
    }

    #[test]
    fn authorization_lease_lifecycle_and_debug() {
        let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
        let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();
        let key = PoolKey::new(proxy, dest, "cred-1", 1, 1);

        let registry = ScopeRegistry::<String>::new();
        let lease = registry
            .register(key.clone(), "client-item".to_owned())
            .unwrap();
        assert!(lease.is_active());
        assert_eq!(lease.key(), &key);

        let debug_str = format!("{lease:?}");
        assert!(debug_str.contains("AuthorizationLease"));
        assert!(debug_str.contains("active: true"));
        assert!(!debug_str.contains("cred-1"));

        lease.cancel();
        assert!(!lease.is_active());
        let debug_after = format!("{lease:?}");
        assert!(debug_after.contains("active: false"));
    }

    #[test]
    fn scope_registry_checkout_invalidation_and_draining() {
        let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
        let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();
        let key = PoolKey::new(proxy, dest, "cred-1", 1, 1);

        let registry = ScopeRegistry::<String>::new();
        assert_eq!(registry.active_entry_count(), 0);

        // Register initial entry
        let lease1 = registry
            .register(key.clone(), "client-1".to_owned())
            .unwrap();
        assert_eq!(registry.active_entry_count(), 1);
        assert_eq!(registry.active_lease_count(&key), 1);

        // Checkout second lease
        let (item, lease2) = registry.checkout(&key).unwrap();
        assert_eq!(item, "client-1");
        assert_eq!(registry.active_lease_count(&key), 2);

        // Drop lease2 -> active lease count decreases
        drop(lease2);
        assert_eq!(registry.active_lease_count(&key), 1);

        // Invalidate key with timeout
        // In another thread, drop lease1 after a brief delay
        let lease1_holder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            drop(lease1);
        });

        registry.invalidate(&key, Duration::from_secs(1)).unwrap();
        lease1_holder.join().unwrap();

        assert_eq!(registry.active_entry_count(), 0);
        assert_eq!(registry.active_lease_count(&key), 0);

        // Subsequent checkout fails closed
        assert!(matches!(
            registry.checkout(&key),
            Err(NetworkError::Offline)
        ));
    }

    #[test]
    fn scope_registry_distinct_records_get_distinct_pools() {
        let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
        let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();

        // Two distinct records with equal generation (1) and scope epoch (1)
        let key1 = PoolKey::new(proxy.clone(), dest.clone(), "record-A", 1, 1);
        let key2 = PoolKey::new(proxy, dest, "record-B", 1, 1);

        let registry = ScopeRegistry::<String>::new();
        let _lease1 = registry
            .register(key1.clone(), "client-A".to_owned())
            .unwrap();
        let _lease2 = registry
            .register(key2.clone(), "client-B".to_owned())
            .unwrap();

        assert_eq!(registry.active_entry_count(), 2);
        let (item1, _) = registry.checkout(&key1).unwrap();
        let (item2, _) = registry.checkout(&key2).unwrap();
        assert_eq!(item1, "client-A");
        assert_eq!(item2, "client-B");
    }

    #[test]
    fn scope_registry_epoch_and_generation_invalidation() {
        let proxy = CanonicalOrigin::parse("http://proxy.test:8080").unwrap();
        let dest = CanonicalOrigin::parse("https://api.test:443").unwrap();

        let key_old_gen = PoolKey::new(proxy.clone(), dest.clone(), "cred-1", 1, 5);
        let key_new_gen = PoolKey::new(proxy.clone(), dest.clone(), "cred-1", 2, 5);

        let registry = ScopeRegistry::<String>::new();
        let lease_old = registry
            .register(key_old_gen.clone(), "old-gen".to_owned())
            .unwrap();
        let lease_new = registry
            .register(key_new_gen.clone(), "new-gen".to_owned())
            .unwrap();
        drop(lease_new);

        drop(lease_old);
        // Invalidate generation < 2
        registry
            .invalidate_generation(&proxy, "cred-1", 2, Duration::from_millis(50))
            .unwrap();

        assert!(matches!(
            registry.checkout(&key_old_gen),
            Err(NetworkError::Offline)
        ));
        assert!(registry.checkout(&key_new_gen).is_ok());

        // Invalidate scope epoch < 10
        let (_item, lease_new) = registry.checkout(&key_new_gen).unwrap();
        drop(lease_new);
        registry
            .invalidate_scope_epoch(&proxy, "cred-1", 10, Duration::from_millis(50))
            .unwrap();
        assert!(matches!(
            registry.checkout(&key_new_gen),
            Err(NetworkError::Offline)
        ));
        assert_eq!(registry.active_entry_count(), 0);
    }
}
