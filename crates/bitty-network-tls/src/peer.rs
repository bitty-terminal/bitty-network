//! Peer leaf `SubjectPublicKeyInfo` accessor for SPKI-pin consumers.
//!
//! [`peer_leaf_spki_der`] opens one direct TLS connection to a host and
//! returns the DER bytes of the peer leaf certificate's
//! `subjectPublicKeyInfo`, which the caller hashes into an SPKI pin.
//! Hashing stays consumer-side: this module slices bytes, it never hashes.
//!
//! The fetch path, in order:
//!
//! 1. Capability first: [`NetworkCapability::check_host_port`] runs before
//!    anything else is touched. Deny-all yields [`NetworkError::Offline`], an
//!    allowlist miss yields the typed [`NetworkError::Denied`], and no socket
//!    is opened in either case.
//! 2. Trust and identity resolve through the provider
//!    ([`TlsProvider::peer_client_config`](crate::TlsProvider)), so the
//!    handshake verifies exactly what a backend handshake would verify,
//!    including the custom-root validity re-check. A policy refusal is a
//!    typed [`NetworkError::Tls`].
//! 3. One DNS resolution, one TCP connect to the first resolved address, one
//!    TLS handshake with the provider's `ClientConfig`. No HTTP bytes are
//!    sent after the handshake, and nothing is retried: any failure fails
//!    closed instead of being attempted again.
//! 4. The leaf certificate (the first peer certificate) is sliced with the
//!    existing X.509 DER reader ([`x509::leaf_spki_der`]), the socket is
//!    closed, and the bytes are returned.
//!
//! Timeouts: `timeout` bounds DNS, TCP, and the handshake together, mirroring
//! `DEFAULT_REQUEST_TIMEOUT` of the http backend; [`DEFAULT_PEER_TIMEOUT`] applies
//! when the caller passes `None`. An expired deadline always surfaces
//! [`NetworkError::Timeout`]. Post-capability transport failures fail closed
//! as [`NetworkError::Offline`], mirroring the backends, which cannot vouch
//! for reachability and so report unreachable.
//!
//! [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
//! [`NetworkError::Denied`]: bitty_network_api::NetworkError::Denied
//! [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
//! [`NetworkError::Tls`]: bitty_network_api::NetworkError::Tls

use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bitty_network_api::{NetworkCapability, NetworkError};
use rustls::pki_types::ServerName;
use rustls::ClientConnection;

use super::provider::TlsProvider;
use super::x509;

/// Default bound for one peer fetch (DNS, TCP, and TLS handshake together)
/// when the caller passes no timeout.
///
/// Thirty seconds mirrors `DEFAULT_REQUEST_TIMEOUT` of the http backend and the
/// WebSocket handshake bound: generous for a loopback or nearby fetch, while
/// callers with a tighter budget pass their own deadline.
pub const DEFAULT_PEER_TIMEOUT: Duration = Duration::from_secs(30);

/// Smallest remaining budget any step still waits for, so a nearly-exhausted
/// deadline still produces this call's own typed error instead of a zero wait.
const MIN_REMAINING: Duration = Duration::from_millis(1);

/// Poll interval while waiting for the resolver thread, so an expired
/// deadline is noticed promptly without busy-waiting.
const DNS_WAIT_POLL: Duration = Duration::from_millis(1);

/// Bound for the best-effort `close_notify` flush after a successful fetch.
///
/// The fetch already succeeded when this applies, so the flush must stay
/// short: long enough for a loopback or nearby peer, never a second budget.
const PEER_CLOSE_FLUSH: Duration = Duration::from_secs(2);

/// Fetch one peer's leaf `SubjectPublicKeyInfo` DER for SPKI-pin consumers.
///
/// Opens a direct TLS connection to `host:port`, completes exactly one
/// handshake with the provider's client configuration, and returns the leaf
/// certificate's `subjectPublicKeyInfo` bytes. The caller hashes them; no
/// hash is computed here and no new dependency is introduced.
///
/// Capability gating runs before any socket work; DNS resolves once, TCP
/// connects once to the first resolved address, and the handshake runs once.
/// No HTTP bytes follow the handshake and nothing is retried. `timeout`
/// bounds the whole fetch, or [`DEFAULT_PEER_TIMEOUT`] when `None`.
pub fn peer_leaf_spki_der(
    host: &str,
    port: u16,
    capability: &NetworkCapability,
    provider: &TlsProvider,
    timeout: Option<Duration>,
) -> Result<Vec<u8>, NetworkError> {
    // Capability first: no resolve, no provider selection, and no socket when
    // the grant does not cover this host and port.
    capability.check_host_port(host, port)?;
    let after = timeout.unwrap_or(DEFAULT_PEER_TIMEOUT);
    let started = Instant::now();
    let absolute = deadline_from(started, after);
    let config = provider
        .peer_client_config(host)
        .map_err(|reason| NetworkError::Tls { reason })?;
    let name = server_name(host)?;
    let address = resolve_first(host, port, after, started)?;
    if Instant::now() >= absolute {
        return Err(NetworkError::Timeout { after });
    }
    let mut stream = TcpStream::connect_timeout(&address, remaining(after, started))
        .map_err(|error| map_io(&error, after))?;
    // One handshake, driven to completion inside the same budget. Socket
    // timeouts are refreshed every round so trickling records cannot extend
    // the operation past its deadline.
    let mut connection = ClientConnection::new(config, name).map_err(|_| NetworkError::Offline)?;
    while connection.is_handshaking() {
        if Instant::now() >= absolute {
            return Err(NetworkError::Timeout { after });
        }
        let round = remaining(after, started);
        stream
            .set_read_timeout(Some(round))
            .map_err(|_| NetworkError::Offline)?;
        stream
            .set_write_timeout(Some(round))
            .map_err(|_| NetworkError::Offline)?;
        connection
            .complete_io(&mut stream)
            .map_err(|error| map_io(&error, after))?;
    }
    let leaf = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or(NetworkError::Offline)?;
    let spki = x509::leaf_spki_der(leaf).map_err(|_| NetworkError::Offline)?;
    close_quietly(&mut connection, &stream);
    Ok(spki)
}

/// TLS server name for `host`: an IP literal stays an IP, anything else is
/// canonicalized exactly the way identity selection canonicalizes it, so SNI
/// and selection can never disagree about what "the same host" means.
///
/// A host with no canonical form fails closed as
/// [`NetworkError::Offline`], mirroring how the backends treat a target they
/// cannot parse: there is no name to offer and no trust decision to report.
fn server_name(host: &str) -> Result<ServerName<'static>, NetworkError> {
    let canonical = super::provider::canonical_host(host).map_err(|_| NetworkError::Offline)?;
    if let Ok(address) = std::net::IpAddr::from_str(&canonical) {
        return Ok(ServerName::IpAddress(address.into()));
    }
    ServerName::try_from(canonical).map_err(|_| NetworkError::Offline)
}

/// Resolve `host:port` to its first address, waiting at most for the budget
/// still left out of `after`.
///
/// Resolution runs on a helper thread because the OS lookup has no deadline
/// of its own; a timed-out lookup may linger on that thread until the OS
/// returns, exactly like the WebSocket dial path, while this call already
/// reports [`NetworkError::Timeout`]. An unresolvable target fails closed as
/// [`NetworkError::Offline`].
///
/// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
fn resolve_first(
    host: &str,
    port: u16,
    after: Duration,
    started: Instant,
) -> Result<SocketAddr, NetworkError> {
    let absolute = deadline_from(started, after);
    if Instant::now() >= absolute {
        return Err(NetworkError::Timeout { after });
    }
    let authority = format_authority(host, port);
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result: std::io::Result<Vec<SocketAddr>> = authority
            .as_str()
            .to_socket_addrs()
            .map(|addresses| addresses.collect());
        let _ = sender.send(result);
    });
    loop {
        if Instant::now() >= absolute {
            return Err(NetworkError::Timeout { after });
        }
        match receiver.recv_timeout(remaining(after, started).min(DNS_WAIT_POLL)) {
            Ok(Ok(addresses)) => {
                if let Some(address) = addresses.into_iter().next() {
                    return Ok(address);
                }
                return Err(NetworkError::Offline);
            }
            Ok(Err(_)) => return Err(NetworkError::Offline),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(NetworkError::Offline),
        }
    }
}

/// `host:port` authority text, bracketing IPv6 literals so the resolver and
/// the capability check split the same authority.
fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Absolute instant `duration` after `start`, never panicking: an
/// unrepresentable sum clamps to a far-future instant, and a still-failing
/// fallback expires immediately (fail-closed) instead of hanging.
fn deadline_from(start: Instant, duration: Duration) -> Instant {
    start
        .checked_add(duration)
        .or_else(|| start.checked_add(Duration::from_secs(u64::from(u32::MAX))))
        .unwrap_or(start)
}

/// Remaining fetch budget: the deadline minus elapsed, never below
/// [`MIN_REMAINING`] so a nearly-exhausted budget still produces the call's
/// own typed error.
fn remaining(after: Duration, started: Instant) -> Duration {
    deadline_from(started, after)
        .saturating_duration_since(Instant::now())
        .max(MIN_REMAINING)
}

/// Map a blocking I/O failure to its typed error: expired deadlines become
/// [`NetworkError::Timeout`] carrying the effective deadline, everything else
/// fails closed as [`NetworkError::Offline`].
///
/// [`NetworkError::Timeout`]: bitty_network_api::NetworkError::Timeout
/// [`NetworkError::Offline`]: bitty_network_api::NetworkError::Offline
fn map_io(error: &std::io::Error, after: Duration) -> NetworkError {
    if error.kind() == std::io::ErrorKind::TimedOut
        || error.kind() == std::io::ErrorKind::WouldBlock
    {
        NetworkError::Timeout { after }
    } else {
        NetworkError::Offline
    }
}

/// Best-effort TLS shutdown after a successful fetch.
///
/// The fetch already succeeded, so no failure here may fail the call: every
/// error is ignored. The `close_notify` flush is bounded by
/// [`PEER_CLOSE_FLUSH`], then the socket is shut down and dropped by the
/// caller. Skipping the flush on error still closes the TCP connection; the
/// peer observes a normal teardown either way.
fn close_quietly(connection: &mut ClientConnection, stream: &TcpStream) {
    connection.send_close_notify();
    let _ = stream.set_read_timeout(Some(PEER_CLOSE_FLUSH));
    let _ = stream.set_write_timeout(Some(PEER_CLOSE_FLUSH));
    // The buffered alert either leaves within the flush bound or it does not;
    // both outcomes close the socket below.
    if let Ok(mut owned) = stream.try_clone() {
        let _ = connection.complete_io(&mut owned);
    }
    let _ = stream.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Short bound for fail-closed tests: long enough for loopback, short
    /// enough that a broken gate (one that dials) cannot stall the suite.
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// A loopback listener that is never accepted from: any accepted
    /// connection would prove a socket was opened.
    fn unaccepted_listener() -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking test listener");
        listener
    }

    /// True when the listener holds a pending (abandoned) connection, which
    /// proves a socket was opened despite the denial.
    fn connection_attempted(listener: &TcpListener) -> bool {
        listener.accept().is_ok()
    }

    /// A denied fetch opens no socket: the capability gate runs before any
    /// resolve, selection, or connect, so a deny-all grant leaves the
    /// listener's backlog empty.
    #[test]
    fn gate_denies_before_connect() {
        let listener = unaccepted_listener();
        let port = listener.local_addr().expect("listener port").port();
        let error = peer_leaf_spki_der(
            "127.0.0.1",
            port,
            &NetworkCapability::offline(),
            &TlsProvider::native_only(),
            Some(TEST_TIMEOUT),
        )
        .expect_err("deny-all denies the fetch");
        assert_eq!(error, NetworkError::Offline);
        assert!(
            !connection_attempted(&listener),
            "no socket may be opened after a capability denial"
        );
    }

    /// An allowlist miss on the host denies before connect, even for an
    /// unroutable documentation address that no socket could reach: the typed
    /// denial (not a timeout or unreachable) proves no dial was attempted.
    #[test]
    fn gate_denies_an_unlisted_host_before_connect() {
        let error = peer_leaf_spki_der(
            "192.0.2.1",
            443,
            &NetworkCapability::offline().with_domain("allowed.example"),
            &TlsProvider::native_only(),
            Some(TEST_TIMEOUT),
        )
        .expect_err("an unlisted host is denied");
        assert_eq!(
            error,
            NetworkError::Denied {
                domain: "192.0.2.1".to_owned(),
            }
        );
    }

    /// An allowlist miss on the port denies before connect: the domain is
    /// allowed but only on another port, so the fetch fails with the typed
    /// denial and the listener sees no connection.
    #[test]
    fn gate_denies_an_unlisted_port_before_connect() {
        let listener = unaccepted_listener();
        let port = listener.local_addr().expect("listener port").port();
        let other_port = if port == 1 { 2 } else { 1 };
        let error = peer_leaf_spki_der(
            "127.0.0.1",
            port,
            &NetworkCapability::offline().with_domain_ports("127.0.0.1", [other_port]),
            &TlsProvider::native_only(),
            Some(TEST_TIMEOUT),
        )
        .expect_err("an unlisted port is denied");
        assert_eq!(
            error,
            NetworkError::Denied {
                domain: "127.0.0.1".to_owned(),
            }
        );
        assert!(
            !connection_attempted(&listener),
            "no socket may be opened after a capability denial"
        );
    }

    /// An allowed fetch to a refused port fails closed as unreachable, not as
    /// a timeout and never with a trust category: the gate passed, the dial
    /// did not.
    #[test]
    fn refused_port_fails_closed_as_offline() {
        let port = {
            let held = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
            held.local_addr().expect("listener port").port()
        };
        let error = peer_leaf_spki_der(
            "127.0.0.1",
            port,
            &NetworkCapability::offline().with_domain("127.0.0.1"),
            &TlsProvider::native_only(),
            Some(TEST_TIMEOUT),
        )
        .expect_err("a refused port fails the fetch");
        assert_eq!(error, NetworkError::Offline);
    }

    /// The remaining-budget floor never returns zero, so a nearly-exhausted
    /// deadline still produces this call's own typed error.
    #[test]
    fn remaining_never_returns_zero() {
        let floor = remaining(Duration::from_nanos(1), Instant::now());
        assert!(floor >= MIN_REMAINING);
    }

    /// A very large timeout never panics: the deadline clamps instead of
    /// overflowing `Instant` addition (CodeRabbit Minor on PR #89).
    #[test]
    fn huge_timeout_never_panics_the_deadline() {
        let start = Instant::now();
        let far = deadline_from(start, Duration::MAX);
        assert!(far >= start);
        let floored = remaining(Duration::MAX, start);
        assert!(floored >= MIN_REMAINING);
    }

    /// Manual-only live handshake: one real TLS handshake against a loopback
    /// rustls server, asserting the fetched SPKI equals the server leaf's
    /// SPKI and that the server observed zero application bytes (no HTTP).
    ///
    /// Never runs in CI (`#[ignore]`): it binds loopback sockets and depends
    /// on the platform root store loading for the custom-CA probe, so it is
    /// for operator verification only. No secrets: the CA and leaf are minted
    /// in memory at runtime and never committed.
    #[test]
    #[ignore = "manual-only live TLS handshake against a loopback server; never run in CI"]
    fn live_handshake_returns_the_server_leaf_spki() {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        };
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::ServerConnection;
        use std::net::IpAddr;

        const LIVE_TIMEOUT: Duration = Duration::from_secs(10);

        // A runtime CA admitted as a custom anchor, valid across any manual
        // run date in the next two decades.
        let mut ca_params = CertificateParams::new(Vec::new()).expect("CA parameters");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = {
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, "loopback peer-fetch CA");
            name
        };
        ca_params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        ca_params.not_after = rcgen::date_time_ymd(2046, 1, 1);
        let ca_key = KeyPair::generate().expect("a runtime CA key");
        let ca_certificate = ca_params
            .self_signed(&ca_key)
            .expect("a self-signed runtime CA");

        // A leaf for the loopback address, signed by the runtime CA.
        let mut leaf_params = CertificateParams::new(Vec::new()).expect("leaf parameters");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.subject_alt_names = vec![rcgen::SanType::IpAddress(
            IpAddr::from_str("127.0.0.1").expect("loopback IP"),
        )];
        leaf_params.distinguished_name = {
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, "loopback peer");
            name
        };
        leaf_params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2046, 1, 1);
        let leaf_key = KeyPair::generate().expect("a runtime leaf key");
        let leaf_certificate = leaf_params
            .signed_by(&leaf_key, &ca_certificate, &ca_key)
            .expect("a CA-signed loopback leaf");
        let leaf_der: Vec<u8> = leaf_certificate.der().to_vec();
        let expected_spki = x509::leaf_spki_der(&leaf_der).expect("the runtime leaf slices");

        // A loopback TLS server speaking this leaf, recording any application
        // bytes the client sends after the handshake.
        let server_config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .expect("server identity"),
        );
        let server_listener = TcpListener::bind("127.0.0.1:0").expect("a loopback TLS listener");
        let server_port = server_listener.local_addr().expect("listener port").port();
        let app_bytes = Arc::new(AtomicBool::new(false));
        let app_seen = Arc::clone(&app_bytes);
        let server = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().expect("one client");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            let mut connection = ServerConnection::new(server_config).expect("server connection");
            while connection.is_handshaking() {
                connection
                    .complete_io(&mut stream)
                    .expect("server handshake I/O");
            }
            // After the handshake the client must send no application bytes:
            // absorb its `close_notify` flight, then drain *decrypted* data
            // until its FIN. A raw-socket read would mistake the alert record
            // itself for application data, so the drain runs through TLS. Any
            // decrypted byte here is an HTTP (or other) violation.
            let _ = connection.complete_io(&mut stream);
            let mut app_data = Vec::new();
            {
                use std::io::Read;
                let mut tls = rustls::Stream::new(&mut connection, &mut stream);
                let _ = tls.read_to_end(&mut app_data);
            }
            if !app_data.is_empty() {
                app_seen.store(true, Ordering::Release);
            }
        });

        let provider = TlsProvider::build(bitty_network_api::TlsConfig::new().with_ca(
            bitty_network_api::PemSource::inline(ca_certificate.pem().into_bytes()),
        ))
        .expect("the runtime CA is admitted");
        let fetched = peer_leaf_spki_der(
            "127.0.0.1",
            server_port,
            &NetworkCapability::offline().with_domain("127.0.0.1"),
            &provider,
            Some(LIVE_TIMEOUT),
        )
        .expect("the loopback handshake fetches the leaf SPKI");
        server.join().expect("the server thread finishes");

        assert_eq!(
            fetched, expected_spki,
            "the fetched SPKI is the server leaf's SPKI"
        );
        assert!(
            !app_bytes.load(Ordering::Acquire),
            "the fetch sends no application bytes after the handshake"
        );
    }
}
