//! DNS shell: explicit resolver seam with cancellation and deadlines.
//!
//! This module performs no I/O and issues no DNS queries itself: it defines
//! the [`DnsResolver`] seam plus [`resolve_with_deadline`], which bounds any
//! blocking resolver with an explicit deadline and an explicit cancellation
//! flag. Wiring the dial path (`crate::websocket`'s `dial`, owned by the
//! sibling websocket lane) through this seam is a follow-up merge — and the
//! HTTP backend is deliberately untouched here: reqwest owns its resolver
//! internals, so this seam covers only the code that dials directly.
//!
//! Cancellation stops the *wait*, not the in-flight lookup: a resolver
//! blocked inside a syscall cannot be preempted without an async runtime,
//! so the worker thread is detached and its late answer is dropped while the
//! caller already holds [`DnsError::Cancelled`] or [`DnsError::Timeout`].

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
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
    struct CountingResolver {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl DnsResolver for CountingResolver {
        fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            LoopbackResolver.resolve("localhost", port)
        }
    }

    /// Loopback port for deadline fixtures (ephemeral scratch only; the
    /// value never leaves the test — resolution here is in-memory).
    const FIXTURE_PORT: u16 = 18_001;

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
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resolver = CountingResolver {
            calls: std::sync::Arc::clone(&calls),
        };
        assert_eq!(
            resolve_with_deadline(resolver, "   ", FIXTURE_PORT, DEFAULT_DNS_TIMEOUT, &cancel),
            Err(DnsError::Offline)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn preset_cancel_never_touches_the_resolver() {
        let cancel = AtomicBool::new(true);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let resolver = CountingResolver {
            calls: std::sync::Arc::clone(&calls),
        };
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
}
