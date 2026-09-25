//! DNS shell: explicit resolver seam with cancellation and deadlines, plus
//! the shared answer cache in front of it.
//!
//! This module performs no I/O and issues no DNS queries itself: it defines
//! the [`DnsResolver`] seam, [`resolve_with_deadline`] (which bounds any
//! blocking resolver with an explicit deadline and an explicit cancellation
//! flag), and [`resolve_cached`] / [`resolve_shared`], which put one shared
//! [`DnsCache`] in front of that seam. Wiring the dial path
//! (`crate::websocket`'s `dial`, owned by the sibling websocket lane) through
//! this seam is a follow-up merge — and the HTTP backend is deliberately
//! untouched here: reqwest owns its resolver internals and exposes no hook
//! to replace them, so the HTTP backend cannot share this cache without
//! dropping reqwest for a hand-rolled transport. Until the dial path adopts
//! the seam, this cache is reached only through [`resolve_shared`].
//!
//! Cancellation stops the *wait*, not the in-flight lookup: a resolver
//! blocked inside a syscall cannot be preempted without an async runtime,
//! so the worker thread is detached and its late answer is dropped while the
//! caller already holds [`DnsError::Cancelled`] or [`DnsError::Timeout`].
//!
//! # Where the cache sits, and why that side
//!
//! The cache sits **below the capability check**, inside the resolution
//! seam, and that is the only safe side. Enforcement happens in
//! `bitty_network_api::NetworkCapability` on the *request*: a
//! case-insensitive, trailing-dot-insensitive allowlist keyed on the host
//! plus a per-host port set, evaluated against the request's own host and
//! port strings (`check_request`, `check_handshake`) before any backend
//! touches a socket. Resolution happens after that, and the resolved
//! addresses are never an input to the check.
//!
//! Two consequences pin the placement:
//!
//! * **A hit is not an authorization.** Because the authority decision is
//!   made on the string query, a cached answer can only ever be reached by
//!   a caller that has already passed the check for that same query — the
//!   cache is downstream of the decision, so it cannot stand in for it. The
//!   reverse placement (a cache consulted *before* the check) would let a
//!   name that was never authorized inherit an answer resolved for a name
//!   that was.
//! * **The key is never coarser than the authorized query.** A [`CacheKey`]
//!   is `(normalized host, port)` where the host normalization is
//!   deliberately the *same* equivalence class the allowlist uses (trim,
//!   strip trailing dots, lowercase), and the port is part of the key. So
//!   two requests share a cache entry exactly when the allowlist treats them
//!   as the same host *and* port: no cross-port reuse, no cross-host reuse,
//!   and no answer can redirect a lookup to an address whose own query was
//!   refused. Poisoning a key therefore requires poisoning the resolver
//!   itself, which is the pre-existing exposure, not a new one.
//!
//! Reuse never extends a deadline either. An entry's own expiry is
//! [`DNS_CACHE_TTL`] (or [`DNS_NEGATIVE_CACHE_TTL`]) *capped by the absolute
//! deadline of the lookup that produced it*, an entry is written only by the
//! caller that actually received the answer inside its own deadline (never
//! by the detached worker, whose late answer arrives after that deadline has
//! been charged and abandoned), and a probe whose own caller deadline has
//! already passed misses rather than serving for free.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

/// Default bound for one resolution when the caller sets no deadline.
///
/// Five seconds keeps an offline-first client responsive while tolerating a
/// slow local resolver; interactive callers pass tighter per-call deadlines.
pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap for resolved addresses kept per lookup, in entries.
///
/// A lookup returning more is truncated (fail closed on abundance, not on
/// absence): callers dial in order and never need an unbounded list.
pub const MAX_DNS_ADDRS: usize = 16;

/// Largest number of answers one [`DnsCache`] holds, in entries.
///
/// The bound is what makes the cache safe to share process-wide: an unbounded
/// cache is a memory-growth vector reachable by anyone who can make the host
/// resolve names, and a terminal that is long-lived by design would hold
/// every name it ever saw. Insertion past the bound evicts the
/// oldest-inserted entry (first in, first out — not least-recently-used, so
/// a refreshed entry keeps its original position).
///
/// 128 entries covers a handful of services re-resolved across a session
/// while staying small enough that the linear eviction bookkeeping is free.
pub const DNS_CACHE_MAX_ENTRIES: usize = 128;

/// How long one successful answer stays servable, before its own deadline cap.
///
/// Deliberately short: a cached address is a statement about the past, and a
/// long-lived terminal must not keep dialing an address the network has since
/// reassigned. Callers that need a longer-lived answer re-resolve.
pub const DNS_CACHE_TTL: Duration = Duration::from_secs(30);

/// How long one *negative* answer stays servable, before its own deadline cap.
///
/// Shorter than [`DNS_CACHE_TTL`] because a negative entry is the sticky
/// case: while it lives, every lookup for that name is answered from the
/// cache and the resolver is not consulted, so a transient failure would
/// otherwise harden into a permanent answer. Capping it well below the
/// positive TTL keeps a failed lookup from suppressing real resolution for
/// long.
pub const DNS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);

/// Poll cadence while waiting for the worker: the granularity at which
/// cancellation and the deadline are noticed.
const DNS_WAIT_POLL: Duration = Duration::from_millis(1);

/// Typed DNS failure (fail closed; the host value never echoes back — see
/// `crate::diagnostics` for why raw request data stays out of errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Nothing to resolve (empty host) or the lookup itself failed.
    Offline,
    /// The deadline expired before the resolver answered.
    Timeout {
        /// Deadline that expired.
        after: Duration,
    },
    /// The caller cancelled the wait via the cancellation flag.
    Cancelled,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => write!(f, "dns offline"),
            Self::Timeout { after } => {
                write!(f, "dns timeout after {}ms", after.as_millis())
            }
            Self::Cancelled => write!(f, "dns cancelled"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Blocking resolver seam: one synchronous lookup, no deadline of its own.
///
/// Implementations must be pure lookups (loopback fixtures or the real
/// resolver follow-up); the deadline and cancellation live in
/// [`resolve_with_deadline`], never inside the resolver.
pub trait DnsResolver {
    /// Resolve `host` for `port` into dialable addresses, in dial order.
    ///
    /// Returns [`DnsError::Offline`] when the name does not resolve; the
    /// caller truncates over-long lists to [`MAX_DNS_ADDRS`].
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError>;
}

/// Resolve through `resolver`, bounded by `deadline` and `cancel`.
///
/// Checks cancellation before starting (an already-cancelled call never
/// touches the resolver), runs the blocking lookup on a detached worker, and
/// waits at most `deadline`, polling `cancel` every [`DNS_WAIT_POLL`].
/// Cancellation wins over a simultaneously arriving answer; an expired
/// deadline yields [`DnsError::Timeout`] carrying the configured `deadline`.
/// Empty hosts fail closed without touching the resolver. The worker is
/// detached on purpose (see the module docs): a late answer is dropped.
pub fn resolve_with_deadline<R>(
    resolver: R,
    host: &str,
    port: u16,
    deadline: Duration,
    cancel: &AtomicBool,
) -> Result<Vec<SocketAddr>, DnsError>
where
    R: DnsResolver + Send + 'static,
{
    if cancel.load(Ordering::SeqCst) {
        return Err(DnsError::Cancelled);
    }
    if host.trim().is_empty() {
        return Err(DnsError::Offline);
    }
    let (tx, rx) = mpsc::channel();
    let owned_host = host.to_owned();
    // Detached on purpose: dropping the handle leaves a cancelled worker to
    // finish (and drop its late answer) instead of blocking the caller.
    let _worker = std::thread::spawn(move || {
        let outcome = resolver.resolve(&owned_host, port);
        let _ = tx.send(outcome);
    });
    let started = Instant::now();
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(DnsError::Cancelled);
        }
        if started.elapsed() >= deadline {
            return Err(DnsError::Timeout { after: deadline });
        }
        match rx.recv_timeout(DNS_WAIT_POLL) {
            Ok(Ok(mut addrs)) => {
                if cancel.load(Ordering::SeqCst) {
                    return Err(DnsError::Cancelled);
                }
                addrs.truncate(MAX_DNS_ADDRS);
                return Ok(addrs);
            }
            Ok(Err(error)) => {
                if cancel.load(Ordering::SeqCst) {
                    return Err(DnsError::Cancelled);
                }
                return Err(error);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(DnsError::Offline),
        }
    }
}

/// Per-record expiry for an entry stored at `now`: the earlier of the entry's
/// own ttl and the producing caller's `horizon`.
///
/// An unrepresentable `now + ttl` (an instant already at the platform's
/// ceiling) yields `now` itself, so the entry is born unservable rather than
/// panicking.
fn expiry_from(now: Instant, ttl: Duration, horizon: Option<Instant>) -> Instant {
    let ttl_expiry = now.checked_add(ttl).unwrap_or(now);
    match horizon {
        Some(horizon) => ttl_expiry.min(horizon),
        None => ttl_expiry,
    }
}

/// Absolute deadline for a caller-supplied budget, saturating at the start.
///
/// An unrepresentable budget (`Duration::MAX`, or a `started` already near
/// the platform's ceiling) yields the start instant itself, which every
/// comparison treats as already expired: the caller's budget is then never
/// reusable, never cacheable, and the lookup below still runs under its own
/// `elapsed` comparison. Fail closed on an unrepresentable deadline, never
/// panic.
fn deadline_from(start: Instant, duration: Duration) -> Instant {
    start.checked_add(duration).unwrap_or(start)
}

/// One cache key: the authorized query, and nothing coarser.
///
/// The host is normalized exactly as `bitty_network_api` normalizes a domain
/// for its allowlist (trim, strip trailing dots, lowercase) so the cache's
/// equivalence classes are the allowlist's equivalence classes and no finer:
/// two requests share a key only when the capability check treated them as
/// the same host. The port is part of the key, so an answer resolved for one
/// port can never be handed to a lookup for another — the per-host port set
/// would otherwise be re-decided against an address it never approved.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    host: String,
    port: u16,
}

impl CacheKey {
    /// Build the key for `host`/`port`, normalizing the host the way the
    /// capability allowlist does.
    fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.trim().trim_end_matches('.').to_lowercase(),
            port,
        }
    }
}

/// What one entry holds.
///
/// [`CachedAnswer::Negative`] is a *recorded* refusal, not an absence: a
/// caller can tell "we looked and it does not resolve" from "we have not
/// looked", which is what keeps a transient failure from being silently
/// promoted into a permanent answer. A resolver that answers with an empty
/// list is recorded as negative too — no addresses means nothing dialable,
/// so it is the same fact expressed the other way round.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CachedAnswer {
    /// A usable, non-empty address list in dial order.
    Addresses(Vec<SocketAddr>),
    /// Recorded: this name did not resolve.
    Negative,
}

/// One stored answer plus its own per-record deadline.
#[derive(Debug, Clone)]
struct CacheEntry {
    answer: CachedAnswer,
    /// Absolute instant the entry stops being servable.
    ///
    /// `min(stored_at + ttl, the producing caller's deadline)`. The ttl caps
    /// staleness; the caller's deadline caps authority — a lookup bounded by
    /// a short deadline may not mint an answer that stays usable for a
    /// longer one, so a later caller with a tighter budget can never inherit
    /// a longer-lived answer than its own budget could have produced.
    expires_at: Instant,
}

/// Result of probing the cache for one key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CacheProbe {
    /// Nothing servable: absent, expired, or the caller's own deadline has
    /// already passed. All three mean "resolve".
    Miss,
    /// A recorded refusal is servable.
    Negative,
    /// A usable address list is servable, in dial order.
    Addresses(Vec<SocketAddr>),
}

/// Backing store: a map plus the insertion order that bounds it.
///
/// A `HashMap` keyed by [`CacheKey`] with a `VecDeque` of keys in insertion
/// order: probe and insert are O(1) amortized, eviction pops the front until
/// the map is back under [`DNS_CACHE_MAX_ENTRIES`]. A key is in the deque
/// exactly while it is in the map — a refresh updates the map in place and
/// leaves the order untouched, so the deque never holds a duplicate or a
/// ghost.
#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<CacheKey, CacheEntry>,
    order: VecDeque<CacheKey>,
}

/// Shared answer cache in front of the resolution seam.
///
/// Bounded twice over: at most [`DNS_CACHE_MAX_ENTRIES`] entries, each
/// servable for at most its own ttl and never past the deadline of the
/// lookup that produced it. Concurrency follows the crate's existing
/// resolver pattern — one `Mutex` over plain data, no lock held across
/// resolution, and no lock held across I/O: a probe takes the lock, reads,
/// and drops it before the caller spawns its worker.
///
/// [`DnsCache`] is a handle, not a resource: cloning shares the same store,
/// which is what "one shared cache" means here.
#[derive(Debug)]
pub struct DnsCache {
    state: Mutex<CacheState>,
}

impl DnsCache {
    /// An empty cache with the default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CacheState::default()),
        }
    }

    /// Number of entries currently held, expired ones included.
    ///
    /// Never exceeds [`DNS_CACHE_MAX_ENTRIES`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// True when no entry is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }

    /// Take the store lock, recovering from a poisoned mutex.
    ///
    /// A panic while the lock was held cannot leave the store inconsistent —
    /// every mutation is a single `insert`/`remove` under the same guard — so
    /// the data is sound and refusing to serve it would be a fail-*closed*
    /// lie about a cache miss. The lock is released by the `PoisonError`'s
    /// guard, so the store is not left locked.
    fn lock(&self) -> std::sync::MutexGuard<'_, CacheState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Probe `key` at `now`, refusing to serve past the caller's own
    /// `horizon`.
    ///
    /// Every store operation goes through here so the entry count stays
    /// bounded no matter which path inserts.
    fn probe(&self, key: &CacheKey, now: Instant, horizon: Option<Instant>) -> CacheProbe {
        if let Some(horizon) = horizon {
            if now >= horizon {
                return CacheProbe::Miss;
            }
        }
        let state = self.lock();
        let servable = state
            .entries
            .get(key)
            .is_some_and(|entry| now < entry.expires_at);
        if !servable {
            return CacheProbe::Miss;
        }
        match state.entries.get(key).map(|entry| &entry.answer) {
            Some(CachedAnswer::Addresses(addrs)) => CacheProbe::Addresses(addrs.clone()),
            Some(CachedAnswer::Negative) => CacheProbe::Negative,
            None => CacheProbe::Miss,
        }
    }

    /// Store `answer` for `key`, expiring at the earlier of the ttl and the
    /// producing caller's `horizon`, and enforce the entry bound.
    fn store(&self, key: CacheKey, answer: CachedAnswer, now: Instant, horizon: Option<Instant>) {
        let ttl = match answer {
            CachedAnswer::Addresses(_) => DNS_CACHE_TTL,
            CachedAnswer::Negative => DNS_NEGATIVE_CACHE_TTL,
        };
        let expiry = expiry_from(now, ttl, horizon);
        let mut state = self.lock();
        if state
            .entries
            .insert(
                key.clone(),
                CacheEntry {
                    answer,
                    expires_at: expiry,
                },
            )
            .is_none()
        {
            state.order.push_back(key);
        }
        while state.entries.len() > DNS_CACHE_MAX_ENTRIES {
            match state.order.pop_front() {
                Some(evicted) => {
                    state.entries.remove(&evicted);
                }
                None => break,
            }
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// The process-wide shared cache, created on first use.
///
/// One cache for the whole process is the point: the memory bound is
/// meaningful only against a single shared store, and two stores would halve
/// the effective bound while multiplying the hit rate's cost.
static SHARED_CACHE: OnceLock<DnsCache> = OnceLock::new();

/// The process-wide shared [`DnsCache`].
///
/// Every caller that goes through [`resolve_shared`] reads and writes this
/// one instance, so the entry bound and the TTLs are enforced once for the
/// process rather than per service.
#[must_use]
pub fn shared() -> &'static DnsCache {
    SHARED_CACHE.get_or_init(DnsCache::new)
}

/// Resolve `host`/`port` through `cache`, reusing a servable answer when one
/// exists and resolving otherwise.
///
/// Order of operations, each step load-bearing:
///
/// 1. An already-cancelled call and an empty host fail closed without
///    touching the cache or the resolver.
/// 2. The caller's absolute deadline is computed once. Every probe is made
///    against it, so a caller whose budget is already spent cannot be handed
///    a cached answer for free — it misses and resolves, and the resolver
///    answers [`DnsError::Timeout`].
/// 3. A hit is served only if `cancel` is still clear: cancellation outranks
///    a cache hit exactly as it outranks a live answer.
/// 4. A miss resolves through [`resolve_with_deadline`], which keeps the
///    blocking lookup off the caller's thread. Only the caller that actually
///    received the answer stores it — never the detached worker, whose late
///    answer arrives after this caller's deadline was charged and abandoned.
/// 5. A successful non-empty answer is stored as a positive entry; a
///    recorded refusal — and an empty answer, which is nothing dialable — is
///    stored as a *negative* entry; [`DnsError::Timeout`] and
///    [`DnsError::Cancelled`] are never stored, so a transient failure can
///    never be replayed as an answer.
///
/// Either way the stored expiry is capped by this caller's own deadline, so
/// reuse cannot outlive the budget that produced it.
pub fn resolve_cached<R>(
    cache: &DnsCache,
    resolver: R,
    host: &str,
    port: u16,
    deadline: Duration,
    cancel: &AtomicBool,
) -> Result<Vec<SocketAddr>, DnsError>
where
    R: DnsResolver + Send + 'static,
{
    if cancel.load(Ordering::SeqCst) {
        return Err(DnsError::Cancelled);
    }
    if host.trim().is_empty() {
        return Err(DnsError::Offline);
    }
    let key = CacheKey::new(host, port);
    let started = Instant::now();
    let horizon = deadline_from(started, deadline);
    match cache.probe(&key, started, Some(horizon)) {
        CacheProbe::Addresses(addrs) => {
            if cancel.load(Ordering::SeqCst) {
                return Err(DnsError::Cancelled);
            }
            return Ok(addrs);
        }
        CacheProbe::Negative => {
            if cancel.load(Ordering::SeqCst) {
                return Err(DnsError::Cancelled);
            }
            return Err(DnsError::Offline);
        }
        CacheProbe::Miss => {}
    }
    let outcome = resolve_with_deadline(resolver, host, port, deadline, cancel);
    let stored_at = Instant::now();
    match outcome {
        Ok(addrs) if !addrs.is_empty() => {
            cache.store(
                key,
                CachedAnswer::Addresses(addrs.clone()),
                stored_at,
                Some(horizon),
            );
            Ok(addrs)
        }
        // An empty answer is nothing dialable: record it as the negative it
        // is and fail closed rather than handing back a list that cannot be
        // connected to.
        Ok(_) => {
            cache.store(key, CachedAnswer::Negative, stored_at, Some(horizon));
            Err(DnsError::Offline)
        }
        // A recorded refusal is cacheable; a timeout or a cancellation is
        // this caller's own outcome, never an answer about the name.
        Err(DnsError::Offline) => {
            cache.store(key, CachedAnswer::Negative, stored_at, Some(horizon));
            Err(DnsError::Offline)
        }
        Err(error) => Err(error),
    }
}

/// Resolve `host`/`port` through the process-wide [`shared`] cache.
///
/// The adoption point for a dial path: one call, the shared bounds, the same
/// authority and deadline rules as [`resolve_cached`].
pub fn resolve_shared<R>(
    resolver: R,
    host: &str,
    port: u16,
    deadline: Duration,
    cancel: &AtomicBool,
) -> Result<Vec<SocketAddr>, DnsError>
where
    R: DnsResolver + Send + 'static,
{
    resolve_cached(shared(), resolver, host, port, deadline, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Resolver answering loopback addresses for any host (in-memory only).
    struct LoopbackResolver;

    impl DnsResolver for LoopbackResolver {
        fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            let mut addrs = Vec::new();
            for ip in ["127.0.0.1", "[::1]"] {
                if let Ok(addr) = format!("{ip}:{port}").parse() {
                    addrs.push(addr);
                }
            }
            Ok(addrs)
        }
    }

    /// Resolver returning more addresses than the cap keeps.
    struct FloodResolver;

    impl DnsResolver for FloodResolver {
        fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            let mut addrs = Vec::new();
            for last in 1..=MAX_DNS_ADDRS + 4 {
                let text = format!("127.0.0.{last}:{port}");
                if let Ok(addr) = text.parse() {
                    addrs.push(addr);
                }
            }
            Ok(addrs)
        }
    }

    /// Resolver failing closed for any host.
    struct FailingResolver;

    impl DnsResolver for FailingResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            Err(DnsError::Offline)
        }
    }

    /// Blocked-resolver seam: stalls until the test releases (or drops) the
    /// gate, proving the wait honors cancellation and deadlines while the
    /// resolver itself never answers.
    struct BlockedResolver {
        gate: Mutex<mpsc::Receiver<()>>,
    }

    impl BlockedResolver {
        fn new() -> (Self, mpsc::Sender<()>) {
            let (tx, rx) = mpsc::channel();
            (
                Self {
                    gate: Mutex::new(rx),
                },
                tx,
            )
        }
    }

    impl DnsResolver for BlockedResolver {
        fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            if let Ok(gate) = self.gate.lock() {
                let _ = gate.recv();
            }
            LoopbackResolver.resolve("localhost", port)
        }
    }

    /// Resolver counting its invocations (proves short-circuits).
    ///
    /// Cloneable so one instance's counter can be observed across several
    /// lookups; each lookup takes the resolver by value.
    #[derive(Clone)]
    struct CountingResolver {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingResolver {
        fn new() -> (Self, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            (
                Self {
                    calls: std::sync::Arc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl DnsResolver for CountingResolver {
        fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            LoopbackResolver.resolve("localhost", port)
        }
    }

    /// Counting resolver that can also be told to fail, so one fixture
    /// proves both "the resolver was consulted again" and "it failed again".
    #[derive(Clone)]
    struct SwitchableResolver {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl SwitchableResolver {
        fn new() -> (Self, CallCount, FailSwitch) {
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let fail = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            (
                Self {
                    calls: std::sync::Arc::clone(&calls),
                    fail: std::sync::Arc::clone(&fail),
                },
                CallCount(std::sync::Arc::clone(&calls)),
                FailSwitch(fail),
            )
        }
    }

    impl DnsResolver for SwitchableResolver {
        fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(DnsError::Offline);
            }
            LoopbackResolver.resolve("localhost", port)
        }
    }

    /// Shared handle on a [`SwitchableResolver`]'s call counter.
    struct CallCount(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl CallCount {
        fn get(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Shared switch making a [`SwitchableResolver`] fail closed.
    struct FailSwitch(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl FailSwitch {
        fn set(&self, fail: bool) {
            self.0.store(fail, Ordering::SeqCst);
        }
    }

    /// Resolver whose answer carries the requested port, so an answer that
    /// leaked across keys is visible as the wrong port in the address.
    struct PortEchoResolver;

    impl DnsResolver for PortEchoResolver {
        fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            Ok(vec![SocketAddr::from((LOOPBACK_ADDRESS, port))])
        }
    }

    /// Resolver answering successfully with nothing dialable.
    struct EmptyResolver;

    impl DnsResolver for EmptyResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            Ok(Vec::new())
        }
    }

    /// Loopback address literal for in-memory fixtures: never dialled, never
    /// reached, and a protocol constant rather than a host value.
    const LOOPBACK_ADDRESS: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127, 0, 0, 1);

    /// Loopback port for deadline fixtures (ephemeral scratch only; the
    /// value never leaves the test — resolution here is in-memory).
    const FIXTURE_PORT: u16 = 18_001;

    /// Second fixture port, used to prove a cache key never folds two ports
    /// into one entry.
    const OTHER_FIXTURE_PORT: u16 = 18_002;

    /// Deadline tight enough that its own cap is the binding expiry, used by
    /// the deadline-authority pins.
    const TIGHT_DEADLINE: Duration = Duration::from_millis(50);

    /// Step taken past a tight deadline when probing. Must stay well inside
    /// [`DNS_CACHE_TTL`], or the deadline-cap pins could pass vacuously
    /// because the ttl had expired on its own; every pin using it asserts
    /// that relation.
    const PROBE_SLACK: Duration = Duration::from_secs(1);

    /// Settle time after releasing a detached worker, so a late answer would
    /// have landed before the assertion.
    const LATE_ANSWER_SETTLE: Duration = Duration::from_millis(50);

    /// The list [`LoopbackResolver`] answers with for `port`.
    fn loopback_answer(port: u16) -> Vec<SocketAddr> {
        vec![
            SocketAddr::from((LOOPBACK_ADDRESS, port)),
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        ]
    }

    /// Cache key for `host`/`port` (the authorized query, nothing coarser).
    fn key(host: &str, port: u16) -> CacheKey {
        CacheKey::new(host, port)
    }

    /// A servable positive entry for `host`/`port`, stored at `now`.
    fn seed_positive(cache: &DnsCache, host: &str, port: u16, now: Instant) {
        cache.store(
            key(host, port),
            CachedAnswer::Addresses(vec![SocketAddr::from((LOOPBACK_ADDRESS, port))]),
            now,
            None,
        );
    }

    #[test]
    fn success_returns_loopback_addrs_in_order() {
        let cancel = AtomicBool::new(false);
        let addrs = resolve_with_deadline(
            LoopbackResolver,
            "localhost",
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        match addrs {
            Ok(addrs) => {
                assert_eq!(addrs.len(), 2);
                for addr in &addrs {
                    assert!(addr.ip().is_loopback());
                    assert_eq!(addr.port(), FIXTURE_PORT);
                }
            }
            Err(error) => panic!("loopback must resolve, got {error}"),
        }
    }

    #[test]
    fn over_long_lists_truncate_to_the_cap() {
        let cancel = AtomicBool::new(false);
        let addrs = resolve_with_deadline(
            FloodResolver,
            "localhost",
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        match addrs {
            Ok(addrs) => assert_eq!(addrs.len(), MAX_DNS_ADDRS),
            Err(error) => panic!("flood must truncate, got {error}"),
        }
    }

    #[test]
    fn resolver_failure_forwards_offline() {
        let cancel = AtomicBool::new(false);
        assert_eq!(
            resolve_with_deadline(
                FailingResolver,
                "localhost",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel
            ),
            Err(DnsError::Offline)
        );
    }

    #[test]
    fn empty_host_never_touches_the_resolver() {
        let cancel = AtomicBool::new(false);
        let (resolver, calls) = CountingResolver::new();
        assert_eq!(
            resolve_with_deadline(resolver, "   ", FIXTURE_PORT, DEFAULT_DNS_TIMEOUT, &cancel),
            Err(DnsError::Offline)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn preset_cancel_never_touches_the_resolver() {
        let cancel = AtomicBool::new(true);
        let (resolver, calls) = CountingResolver::new();
        assert_eq!(
            resolve_with_deadline(
                resolver,
                "localhost",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel
            ),
            Err(DnsError::Cancelled)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn blocked_resolver_cancel_midflight_yields_cancelled() {
        let (resolver, gate) = BlockedResolver::new();
        let cancel = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                resolve_with_deadline(
                    resolver,
                    "localhost",
                    FIXTURE_PORT,
                    Duration::from_secs(30),
                    &cancel,
                )
            });
            std::thread::sleep(Duration::from_millis(20));
            cancel.store(true, Ordering::SeqCst);
            match worker.join() {
                Ok(outcome) => assert_eq!(outcome, Err(DnsError::Cancelled)),
                Err(_) => panic!("wait thread panicked"),
            }
        });
        drop(gate);
    }

    #[test]
    fn blocked_resolver_short_deadline_yields_timeout() {
        let (resolver, gate) = BlockedResolver::new();
        let cancel = AtomicBool::new(false);
        let deadline = Duration::from_millis(50);
        assert_eq!(
            resolve_with_deadline(resolver, "localhost", FIXTURE_PORT, deadline, &cancel),
            Err(DnsError::Timeout { after: deadline })
        );
        drop(gate);
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(DnsError::Offline.to_string(), "dns offline");
        assert_eq!(
            DnsError::Timeout {
                after: Duration::from_secs(2)
            }
            .to_string(),
            "dns timeout after 2000ms"
        );
        assert_eq!(DnsError::Cancelled.to_string(), "dns cancelled");
    }

    // -- cache: bounded entries ------------------------------------------------

    #[test]
    fn entry_count_never_exceeds_the_bound() {
        let cache = DnsCache::new();
        let now = Instant::now();
        let overflow = 8;
        for index in 0..DNS_CACHE_MAX_ENTRIES + overflow {
            seed_positive(&cache, &format!("host-{index}.test"), FIXTURE_PORT, now);
            assert!(
                cache.len() <= DNS_CACHE_MAX_ENTRIES,
                "entry count {} exceeded the bound {DNS_CACHE_MAX_ENTRIES}",
                cache.len()
            );
        }
        assert_eq!(cache.len(), DNS_CACHE_MAX_ENTRIES);
    }

    #[test]
    fn oldest_entry_is_evicted_first() {
        let cache = DnsCache::new();
        let now = Instant::now();
        seed_positive(&cache, "oldest.test", FIXTURE_PORT, now);
        for index in 0..DNS_CACHE_MAX_ENTRIES {
            seed_positive(&cache, &format!("newer-{index}.test"), FIXTURE_PORT, now);
        }
        assert_eq!(
            cache.probe(&key("oldest.test", FIXTURE_PORT), now, None),
            CacheProbe::Miss,
            "the oldest-inserted key must be the one evicted"
        );
        assert_eq!(
            cache.probe(&key("newer-0.test", FIXTURE_PORT), now, None),
            CacheProbe::Addresses(vec![SocketAddr::from((LOOPBACK_ADDRESS, FIXTURE_PORT))])
        );
    }

    #[test]
    fn refreshed_entry_keeps_one_position_and_one_copy() {
        let cache = DnsCache::new();
        let now = Instant::now();
        seed_positive(&cache, "kept.test", FIXTURE_PORT, now);
        for index in 0..DNS_CACHE_MAX_ENTRIES - 1 {
            seed_positive(&cache, &format!("filler-{index}.test"), FIXTURE_PORT, now);
        }
        // Re-storing the oldest key must not append a second deque entry: the
        // store is still bounded and nothing is double-counted.
        seed_positive(&cache, "kept.test", FIXTURE_PORT, now);
        assert_eq!(cache.len(), DNS_CACHE_MAX_ENTRIES);
        assert_eq!(
            cache.probe(&key("kept.test", FIXTURE_PORT), now, None),
            CacheProbe::Addresses(vec![SocketAddr::from((LOOPBACK_ADDRESS, FIXTURE_PORT))])
        );
    }

    // -- cache: bounded ttl ----------------------------------------------------

    #[test]
    fn an_entry_survives_until_its_own_expiry() {
        let cache = DnsCache::new();
        let now = Instant::now();
        seed_positive(&cache, "fresh.test", FIXTURE_PORT, now);
        let just_before = now + DNS_CACHE_TTL - Duration::from_millis(1);
        assert_eq!(
            cache.probe(&key("fresh.test", FIXTURE_PORT), just_before, None),
            CacheProbe::Addresses(vec![SocketAddr::from((LOOPBACK_ADDRESS, FIXTURE_PORT))]),
            "an entry must be servable right up to its own expiry"
        );
    }

    #[test]
    fn an_expired_entry_is_not_servable() {
        let cache = DnsCache::new();
        let now = Instant::now();
        seed_positive(&cache, "stale.test", FIXTURE_PORT, now);
        assert_eq!(
            cache.probe(&key("stale.test", FIXTURE_PORT), now + DNS_CACHE_TTL, None),
            CacheProbe::Miss,
            "an entry must not be servable at or past its own expiry"
        );
    }

    #[test]
    fn a_negative_entry_expires_so_a_transient_failure_is_not_sticky() {
        let cache = DnsCache::new();
        let now = Instant::now();
        cache.store(
            key("absent.test", FIXTURE_PORT),
            CachedAnswer::Negative,
            now,
            None,
        );
        assert_eq!(
            cache.probe(&key("absent.test", FIXTURE_PORT), now, None),
            CacheProbe::Negative
        );
        assert!(
            DNS_NEGATIVE_CACHE_TTL < DNS_CACHE_TTL,
            "the negative ttl must be the shorter of the two"
        );
        assert_eq!(
            cache.probe(
                &key("absent.test", FIXTURE_PORT),
                now + DNS_NEGATIVE_CACHE_TTL,
                None
            ),
            CacheProbe::Miss,
            "a recorded refusal must expire well before a positive answer would"
        );
    }

    #[test]
    fn a_live_entry_never_answers_past_the_negative_ttl_of_a_negative_one() {
        // Guards the ttl choice itself: a negative entry must not outlive the
        // positive one, or a failed lookup would suppress real resolution for
        // longer than a good answer stays usable.
        let cache = DnsCache::new();
        let now = Instant::now();
        cache.store(
            key("negative.test", FIXTURE_PORT),
            CachedAnswer::Negative,
            now,
            None,
        );
        seed_positive(&cache, "positive.test", FIXTURE_PORT, now);
        let probe_at = now + DNS_NEGATIVE_CACHE_TTL;
        assert_eq!(
            cache.probe(&key("negative.test", FIXTURE_PORT), probe_at, None),
            CacheProbe::Miss
        );
        assert_eq!(
            cache.probe(&key("positive.test", FIXTURE_PORT), probe_at, None),
            CacheProbe::Addresses(vec![SocketAddr::from((LOOPBACK_ADDRESS, FIXTURE_PORT))])
        );
    }

    // -- cache: negative is not absence, failure is not success ---------------

    #[test]
    fn a_failed_resolution_is_recorded_as_a_negative_entry() {
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            resolve_cached(
                &cache,
                FailingResolver,
                "failing.test",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel
            ),
            Err(DnsError::Offline)
        );
        assert_eq!(cache.len(), 1, "the refusal must be recorded, not dropped");
        assert_eq!(
            cache.probe(&key("failing.test", FIXTURE_PORT), Instant::now(), None),
            CacheProbe::Negative,
            "a recorded refusal must be distinguishable from an absence"
        );
    }

    #[test]
    fn a_negative_entry_never_yields_an_address_list() {
        let (resolver, calls, fail) = SwitchableResolver::new();
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        fail.set(true);
        assert_eq!(
            resolve_cached(
                &cache,
                resolver.clone(),
                "recorded.test",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel
            ),
            Err(DnsError::Offline)
        );
        assert_eq!(calls.get(), 1);
        // Second call is answered from the recorded refusal: still
        // `Offline`, never `Ok`, and the resolver is not consulted again.
        assert_eq!(
            resolve_cached(
                &cache,
                resolver.clone(),
                "recorded.test",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel
            ),
            Err(DnsError::Offline)
        );
        assert_eq!(
            calls.get(),
            1,
            "a recorded refusal must be reused, not re-resolved"
        );
    }

    #[test]
    fn an_empty_answer_is_recorded_as_a_negative_entry() {
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            resolve_cached(
                &cache,
                EmptyResolver,
                "empty.test",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel
            ),
            Err(DnsError::Offline),
            "an empty answer is nothing dialable and must fail closed"
        );
        assert_eq!(
            cache.probe(&key("empty.test", FIXTURE_PORT), Instant::now(), None),
            CacheProbe::Negative
        );
    }

    #[test]
    fn a_timeout_is_never_cached() {
        let (resolver, gate) = BlockedResolver::new();
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            resolve_cached(
                &cache,
                resolver,
                "hung.test",
                FIXTURE_PORT,
                TIGHT_DEADLINE,
                &cancel
            ),
            Err(DnsError::Timeout {
                after: TIGHT_DEADLINE
            })
        );
        assert!(
            cache.is_empty(),
            "a timeout is this caller's outcome, never an answer about the name"
        );
        drop(gate);
    }

    #[test]
    fn a_cancellation_is_never_cached() {
        let (resolver, gate) = BlockedResolver::new();
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                resolve_cached(
                    &cache,
                    resolver,
                    "cancelled.test",
                    FIXTURE_PORT,
                    DEFAULT_DNS_TIMEOUT,
                    &cancel,
                )
            });
            std::thread::sleep(Duration::from_millis(20));
            cancel.store(true, Ordering::SeqCst);
            match worker.join() {
                Ok(outcome) => assert_eq!(outcome, Err(DnsError::Cancelled)),
                Err(_) => panic!("wait thread panicked"),
            }
        });
        assert!(cache.is_empty(), "a cancellation must not be cached");
        drop(gate);
    }

    #[test]
    fn a_detached_workers_late_answer_never_reaches_the_cache() {
        let (resolver, gate) = BlockedResolver::new();
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            resolve_cached(
                &cache,
                resolver,
                "late.test",
                FIXTURE_PORT,
                TIGHT_DEADLINE,
                &cancel
            ),
            Err(DnsError::Timeout {
                after: TIGHT_DEADLINE
            })
        );
        // The caller has already been charged its deadline and given up; the
        // worker is still blocked. Release it and let its answer arrive late.
        drop(gate);
        std::thread::sleep(LATE_ANSWER_SETTLE);
        assert_eq!(
            cache.len(),
            0,
            "a late answer must not be minted into an entry"
        );
        // And the next lookup for that name must still reach the resolver:
        // the abandoned lookup's answer is not an answer for anyone.
        let (resolver, calls) = CountingResolver::new();
        match resolve_cached(
            &cache,
            resolver,
            "late.test",
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        ) {
            Ok(_) => {}
            Err(error) => panic!("loopback must resolve, got {error}"),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the abandoned answer must not be reused"
        );
    }

    // -- cache: reuse must not extend a deadline -------------------------------

    #[test]
    fn an_entry_expires_with_the_deadline_of_the_lookup_that_produced_it() {
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        let base = Instant::now();
        match resolve_cached(
            &cache,
            LoopbackResolver,
            "tight.test",
            FIXTURE_PORT,
            TIGHT_DEADLINE,
            &cancel,
        ) {
            Ok(_) => {}
            Err(error) => panic!("loopback must resolve, got {error}"),
        }
        assert!(
            PROBE_SLACK < DNS_CACHE_TTL,
            "the probe step must stay inside the ttl, or this pin passes vacuously"
        );
        assert_eq!(
            cache.probe(&key("tight.test", FIXTURE_PORT), base, None),
            CacheProbe::Addresses(loopback_answer(FIXTURE_PORT)),
            "the entry must exist: the miss below is the deadline cap, not absence"
        );
        assert_eq!(
            cache.probe(
                &key("tight.test", FIXTURE_PORT),
                base + TIGHT_DEADLINE + PROBE_SLACK,
                None
            ),
            CacheProbe::Miss,
            "an entry resolved under a tight deadline must not outlive it while the \
             ttl would still allow it"
        );
    }

    #[test]
    fn an_expired_caller_deadline_is_never_served_from_the_cache() {
        let cache = DnsCache::new();
        let (resolver, _calls) = CountingResolver::new();
        let cancel = AtomicBool::new(false);
        match resolve_cached(
            &cache,
            resolver.clone(),
            "generous.test",
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        ) {
            Ok(_) => {}
            Err(error) => panic!("loopback must resolve, got {error}"),
        }
        assert_eq!(cache.len(), 1);
        // A live entry, and a caller whose budget is already spent. The hit is
        // free, so serving it would hand a deadline-expired caller an answer
        // the cache happened to be holding.
        let spent = Duration::ZERO;
        assert_eq!(
            resolve_cached(
                &cache,
                resolver.clone(),
                "generous.test",
                FIXTURE_PORT,
                spent,
                &cancel
            ),
            Err(DnsError::Timeout { after: spent }),
            "reuse must never turn an expired deadline into a free answer"
        );
        assert_eq!(cache.len(), 1, "the miss must not disturb the live entry");
    }

    #[test]
    fn a_probe_past_the_caller_horizon_always_misses() {
        let cache = DnsCache::new();
        let now = Instant::now();
        seed_positive(&cache, "horizon.test", FIXTURE_PORT, now);
        let horizon = now + TIGHT_DEADLINE;
        assert_eq!(
            cache.probe(
                &key("horizon.test", FIXTURE_PORT),
                horizon - PROBE_SLACK,
                Some(horizon)
            ),
            CacheProbe::Addresses(vec![SocketAddr::from((LOOPBACK_ADDRESS, FIXTURE_PORT))])
        );
        assert_eq!(
            cache.probe(&key("horizon.test", FIXTURE_PORT), horizon, Some(horizon)),
            CacheProbe::Miss,
            "an answer must not be served at the caller's own deadline"
        );
        assert_eq!(
            cache.probe(
                &key("horizon.test", FIXTURE_PORT),
                horizon + PROBE_SLACK,
                Some(horizon)
            ),
            CacheProbe::Miss
        );
    }

    // -- cache: key granularity (the poisoning property) -----------------------

    #[test]
    fn a_servable_entry_is_reused_without_the_resolver() {
        let cache = DnsCache::new();
        let (resolver, calls) = CountingResolver::new();
        let cancel = AtomicBool::new(false);
        for _ in 0..2 {
            match resolve_cached(
                &cache,
                resolver.clone(),
                "reused.test",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel,
            ) {
                Ok(_) => {}
                Err(error) => panic!("loopback must resolve, got {error}"),
            }
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second lookup must be answered from the cache"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_cache_key_never_folds_two_ports_into_one_entry() {
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        match resolve_cached(
            &cache,
            PortEchoResolver,
            "ports.test",
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        ) {
            Ok(_) => {}
            Err(error) => panic!("loopback must resolve, got {error}"),
        }
        let other = resolve_cached(
            &cache,
            PortEchoResolver,
            "ports.test",
            OTHER_FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        );
        match other {
            Ok(addrs) => {
                assert_eq!(addrs.len(), 1);
                assert_eq!(
                    addrs[0].port(),
                    OTHER_FIXTURE_PORT,
                    "a second port must never be handed the first port's answer"
                );
            }
            Err(error) => panic!("loopback must resolve, got {error}"),
        }
        assert_eq!(cache.len(), 2, "each authorized query is its own entry");
    }

    #[test]
    fn a_cache_key_never_folds_two_hosts_into_one_entry() {
        let cache = DnsCache::new();
        let (resolver, calls) = CountingResolver::new();
        let cancel = AtomicBool::new(false);
        for host in ["first.test", "second.test"] {
            match resolve_cached(
                &cache,
                resolver.clone(),
                host,
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel,
            ) {
                Ok(_) => {}
                Err(error) => panic!("loopback must resolve, got {error}"),
            }
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "each host must be resolved for itself"
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn host_normalization_is_exactly_the_capability_allowlists() {
        let cache = DnsCache::new();
        let (resolver, calls) = CountingResolver::new();
        let cancel = AtomicBool::new(false);
        for host in ["Mixed.Case.Test", "  mixed.case.test.  "] {
            match resolve_cached(
                &cache,
                resolver.clone(),
                host,
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel,
            ) {
                Ok(_) => {}
                Err(error) => panic!("loopback must resolve, got {error}"),
            }
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "cache granularity must match the allowlist's, not be finer"
        );
        assert_eq!(
            key("Mixed.Case.Test.", FIXTURE_PORT),
            key("  mixed.case.test  ", FIXTURE_PORT)
        );
    }

    #[test]
    fn a_cached_answer_still_honours_cancellation() {
        let cache = DnsCache::new();
        let (resolver, calls) = CountingResolver::new();
        let cancel = AtomicBool::new(false);
        match resolve_cached(
            &cache,
            resolver.clone(),
            "cancel-hit.test",
            FIXTURE_PORT,
            DEFAULT_DNS_TIMEOUT,
            &cancel,
        ) {
            Ok(_) => {}
            Err(error) => panic!("loopback must resolve, got {error}"),
        }
        assert_eq!(cache.len(), 1);
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(
            resolve_cached(
                &cache,
                resolver.clone(),
                "cancel-hit.test",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel
            ),
            Err(DnsError::Cancelled),
            "a cache hit must not become a way past the cancellation gate"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a cancelled call must not resolve"
        );
    }

    #[test]
    fn an_empty_host_never_touches_the_cache_or_the_resolver() {
        let cache = DnsCache::new();
        seed_positive(&cache, "blank.test", FIXTURE_PORT, Instant::now());
        let (resolver, calls) = CountingResolver::new();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            resolve_cached(
                &cache,
                resolver.clone(),
                "   ",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel
            ),
            Err(DnsError::Offline)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            cache.probe(&key("blank.test", FIXTURE_PORT), Instant::now(), None),
            CacheProbe::Addresses(vec![SocketAddr::from((LOOPBACK_ADDRESS, FIXTURE_PORT))]),
            "a fail-closed empty host must not evict or overwrite anything"
        );
    }

    // -- cache: the shared instance -------------------------------------------

    #[test]
    fn the_shared_cache_is_one_instance_for_the_process() {
        assert!(
            std::ptr::eq(shared(), shared()),
            "every backend must reach the same bounded store"
        );
    }

    #[test]
    fn resolve_shared_uses_the_shared_cache() {
        let (resolver, calls) = CountingResolver::new();
        let cancel = AtomicBool::new(false);
        for _ in 0..2 {
            match resolve_shared(
                resolver.clone(),
                "shared-seam.test",
                FIXTURE_PORT,
                DEFAULT_DNS_TIMEOUT,
                &cancel,
            ) {
                Ok(_) => {}
                Err(error) => panic!("loopback must resolve, got {error}"),
            }
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the shared seam must cache like any other"
        );
        assert_eq!(
            shared().probe(&key("shared-seam.test", FIXTURE_PORT), Instant::now(), None),
            CacheProbe::Addresses(loopback_answer(FIXTURE_PORT)),
            "the entry must live in the process-wide instance"
        );
    }

    #[test]
    fn an_unrepresentable_deadline_stays_fail_closed() {
        let cache = DnsCache::new();
        let cancel = AtomicBool::new(false);
        // A budget past the platform's instant ceiling cannot be represented;
        // it must neither panic nor produce a reusable entry.
        match resolve_cached(
            &cache,
            LoopbackResolver,
            "huge-budget.test",
            FIXTURE_PORT,
            Duration::MAX,
            &cancel,
        ) {
            Ok(_) => {}
            Err(error) => panic!("loopback must resolve, got {error}"),
        }
        let now = Instant::now();
        assert_eq!(
            cache.probe(&key("huge-budget.test", FIXTURE_PORT), now, None),
            CacheProbe::Miss,
            "an unrepresentable deadline must not mint a reusable entry"
        );
    }
}
