//! Control-client TLS tests over the deterministic in-memory peer.

mod support;

use std::time::{Duration, Instant};

use bitty_network_publication::{CONTROL_ALPN, ControlClient, ControlError, LaunchMaterial};
use support::{InMemoryPeer, hex, server_config, server_config_with_chain};

fn peer(material: &LaunchMaterial, alpn: &[u8], tls13_only: bool) -> InMemoryPeer {
    let config = server_config(material, material.core_cert_sha256(), alpn, tls13_only);
    InMemoryPeer::new(config).expect("in-memory server")
}

#[test]
fn mutual_handshake_establishes_with_the_pinned_helper_leaf() {
    let material = LaunchMaterial::generate().expect("launch material");
    let expected_peer = material.helper_cert_der().clone();
    let mut peer = peer(&material, CONTROL_ALPN, true);
    let client = ControlClient::new(material).expect("control client");

    let session = client.establish(&mut peer).expect("mutual TLS handshake");

    assert!(!session.is_handshaking());
    assert_eq!(session.alpn_protocol(), Some(CONTROL_ALPN));
    assert_eq!(session.peer_certificate(), &expected_peer);
    assert_eq!(
        session.connection().protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(peer.server_alpn(), Some(CONTROL_ALPN));
    peer.drive()
        .expect("server processes the client's final flight");
    assert!(!peer.server_is_handshaking());
}

#[test]
fn pin_mismatch_fails_the_handshake() {
    let material = LaunchMaterial::generate().expect("launch material");
    let mut peer = peer(&material, CONTROL_ALPN, true);
    let client = ControlClient::new_with_expected_pin(material, [0u8; 32])
        .expect("control client with a deliberately wrong pin");

    let error = client
        .establish(&mut peer)
        .expect_err("wrong helper pin must fail");
    assert!(
        matches!(error, ControlError::Io(_) | ControlError::HandshakeStalled),
        "unexpected error: {error:?}"
    );
}

#[test]
fn extra_intermediate_certificate_is_refused() {
    let material = LaunchMaterial::generate().expect("launch material");
    let extra = material.core_cert_der().clone();
    let config = server_config_with_chain(
        &material,
        material.core_cert_sha256(),
        CONTROL_ALPN,
        true,
        Some(extra),
    );
    let mut peer = InMemoryPeer::new(config).expect("in-memory server");
    let client = ControlClient::new(material).expect("control client");

    let error = client
        .establish(&mut peer)
        .expect_err("an extra certificate in the chain must fail");
    assert!(
        matches!(error, ControlError::Io(_) | ControlError::HandshakeStalled),
        "unexpected error: {error:?}"
    );
}

#[test]
fn missing_alpn_is_refused_after_the_handshake() {
    let material = LaunchMaterial::generate().expect("launch material");
    let mut peer = peer(&material, &[], true);
    let client = ControlClient::new(material).expect("control client");

    let error = client
        .establish(&mut peer)
        .expect_err("missing ALPN must fail");
    assert!(matches!(error, ControlError::AlpnMismatch));
}

#[test]
fn tls12_only_server_is_refused() {
    let material = LaunchMaterial::generate().expect("launch material");
    let mut peer = peer(&material, CONTROL_ALPN, false);
    let client = ControlClient::new(material).expect("control client");

    let error = client
        .establish(&mut peer)
        .expect_err("TLS 1.2-only server must fail");
    assert!(
        matches!(error, ControlError::Io(_) | ControlError::HandshakeStalled),
        "unexpected error: {error:?}"
    );
}

#[test]
fn debug_and_handshake_errors_do_not_expose_key_material() {
    let material = LaunchMaterial::generate().expect("launch material");
    let core_key = hex(material.core_key_der());
    let helper_key = hex(material.helper_key_der());
    let material_debug = format!("{material:?}");
    assert!(!material_debug.contains(&core_key));
    assert!(!material_debug.contains(&helper_key));

    let mut peer = peer(&material, CONTROL_ALPN, true);
    let client = ControlClient::new_with_expected_pin(material, [0u8; 32])
        .expect("control client with a deliberately wrong pin");
    let client_debug = format!("{client:?}");
    assert!(!client_debug.contains("PRIVATE KEY"));

    let error = client
        .establish(&mut peer)
        .expect_err("wrong helper pin must fail");
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(&core_key));
    assert!(!rendered.contains(&helper_key));
    assert!(!rendered.contains("PRIVATE KEY"));
}

#[test]
fn handshake_cost_stays_under_a_generous_bound() {
    let material = LaunchMaterial::generate().expect("launch material");
    let mut peer = peer(&material, CONTROL_ALPN, true);
    let client = ControlClient::new(material).expect("control client");

    let started = Instant::now();
    let session = client.establish(&mut peer).expect("handshake");
    let elapsed = started.elapsed();
    eprintln!("in-memory mutual TLS handshake completed in {elapsed:?}");
    assert!(!session.is_handshaking());
    assert!(
        elapsed < Duration::from_secs(30),
        "handshake took {elapsed:?}"
    );
}
