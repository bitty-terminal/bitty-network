//! TLS 1.3 mutual-certificate control client.
//!
//! The client authenticates exactly one server leaf by SHA-256 certificate
//! digest, presents the Core leaf as its client certificate, and requires ALPN
//! `provider-publication-control/1`. There is no PKI, chain building, name
//! check, resumption, ticket storage, or early data.
//!
//! I/O is injected: [`ControlClient::establish`] drives a blocking
//! [`Read`] + [`Write`] stream supplied by the caller. This crate never opens
//! a socket or spawns a thread.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError,
    SignatureScheme,
};

use crate::sha256::sha256;
use crate::{CONTROL_ALPN, LaunchMaterial};

/// Verification-neutral server name for the rustls connection API.
///
/// The control channel has no DNS identity: the certificate pin is the only
/// server identity, and SNI is disabled. rustls nevertheless requires a
/// [`ServerName`] when constructing a client connection, so this reserved
/// `.invalid` name is supplied and ignored by the custom verifier. It is never
/// resolved, sent on the wire, or used as a host.
const TLS_SERVER_NAME: &str = "provider-publication.invalid";

/// A configured control client, ready to handshake on the dedicated stream.
///
/// Construction consumes [`LaunchMaterial`]: the Core private-key buffer is
/// zeroized once the rustls configuration has copied what it needs, and the
/// helper key never enters the client configuration at all.
pub struct ControlClient {
    connection: ClientConnection,
}

impl ControlClient {
    /// Build a client that accepts the helper pin carried by `material`.
    pub fn new(material: LaunchMaterial) -> Result<Self, ControlError> {
        let expected = material.helper_cert_sha256();
        Self::new_with_expected_pin(material, expected)
    }

    /// Build a client with an explicitly supplied helper certificate pin.
    ///
    /// The pin must be SHA-256 over the helper leaf certificate DER. Passing a
    /// pin that does not match the helper's leaf makes the handshake fail at
    /// the verifier; there is no fallback identity.
    pub fn new_with_expected_pin(
        material: LaunchMaterial,
        expected_helper_pin: [u8; 32],
    ) -> Result<Self, ControlError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let supported = provider.signature_verification_algorithms;
        let verifier = Arc::new(PinnedServerVerifier {
            expected: expected_helper_pin,
            supported,
        });

        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(ControlError::Configuration)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(
                vec![material.core_cert_der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.core_key_der().to_vec())),
            )
            .map_err(ControlError::ClientIdentity)?;

        config.alpn_protocols = vec![CONTROL_ALPN.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        config.enable_sni = false;
        config.enable_secret_extraction = false;
        config.send_ticket_request = Some(rustls::client::TicketRequest {
            new_session_count: 0,
            resumption_count: 0,
        });

        let name = ServerName::try_from(TLS_SERVER_NAME).map_err(|_| ControlError::ServerName)?;
        let connection =
            ClientConnection::new(Arc::new(config), name).map_err(ControlError::Configuration)?;

        // `material` is dropped here; its private-key buffers are zeroized.
        Ok(Self { connection })
    }

    /// Drive the TLS handshake to completion over `stream`.
    ///
    /// On success the connection is fully established, ALPN is the control
    /// protocol, and exactly one pinned peer certificate was presented. On any
    /// failure the launch must be revoked; this method never retries with a
    /// weaker identity.
    pub fn establish<S>(self, stream: &mut S) -> Result<ControlSession, ControlError>
    where
        S: Read + Write,
    {
        let mut connection = self.connection;
        while connection.is_handshaking() {
            let (read, written) = connection.complete_io(stream).map_err(ControlError::Io)?;
            if read == 0 && written == 0 && connection.is_handshaking() {
                return Err(ControlError::HandshakeStalled);
            }
        }

        if connection.alpn_protocol() != Some(CONTROL_ALPN) {
            return Err(ControlError::AlpnMismatch);
        }

        let certificates = connection
            .peer_certificates()
            .ok_or(ControlError::NoPeerCertificate)?;
        if certificates.len() != 1 {
            return Err(ControlError::UnexpectedPeerCertificateCount {
                count: certificates.len(),
            });
        }
        let peer_certificate = certificates[0].clone();

        Ok(ControlSession {
            connection,
            peer_certificate,
        })
    }
}

impl fmt::Debug for ControlClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlClient")
            .field("handshaking", &self.connection.is_handshaking())
            .finish()
    }
}

/// A completed control-client TLS session.
///
/// Slice 1 stops at establishment. The underlying connection is exposed so the
/// next slice can carry the bounded control records on the same stream.
pub struct ControlSession {
    connection: ClientConnection,
    peer_certificate: CertificateDer<'static>,
}

impl ControlSession {
    /// The single peer leaf certificate that matched the helper pin.
    pub fn peer_certificate(&self) -> &CertificateDer<'static> {
        &self.peer_certificate
    }

    /// The negotiated ALPN protocol, always [`CONTROL_ALPN`] on success.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.connection.alpn_protocol()
    }

    /// Whether the connection is still handshaking; always `false` here.
    pub fn is_handshaking(&self) -> bool {
        self.connection.is_handshaking()
    }

    /// Borrow the established rustls connection.
    pub fn connection(&self) -> &ClientConnection {
        &self.connection
    }

    /// Mutably borrow the established rustls connection.
    pub fn connection_mut(&mut self) -> &mut ClientConnection {
        &mut self.connection
    }

    /// Take ownership of the established rustls connection.
    pub fn into_connection(self) -> ClientConnection {
        self.connection
    }
}

impl fmt::Debug for ControlSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlSession")
            .field("handshaking", &self.connection.is_handshaking())
            .field("alpn_protocol", &self.connection.alpn_protocol())
            .field(
                "peer_certificate_len",
                &self.peer_certificate.as_ref().len(),
            )
            .finish()
    }
}

/// Why the control client could not be built or established.
///
/// Errors carry no key material. A verifier refusal surfaces as
/// [`ControlError::Io`] with the rustls alert, exactly like any other fatal
/// handshake failure, so callers must treat every error as launch-fatal.
#[derive(Debug)]
pub enum ControlError {
    /// The rustls configuration or connection could not be built.
    Configuration(RustlsError),
    /// The Core client certificate and private key were rejected.
    ClientIdentity(RustlsError),
    /// The fixed verification-neutral server name could not be represented.
    ServerName,
    /// The injected stream failed or TLS aborted the handshake.
    Io(io::Error),
    /// The handshake made no progress while still incomplete.
    HandshakeStalled,
    /// The peer did not negotiate the control ALPN.
    AlpnMismatch,
    /// The connection completed without a peer certificate.
    NoPeerCertificate,
    /// The peer presented more than the one accepted end-entity certificate.
    UnexpectedPeerCertificateCount {
        /// Number of certificates presented.
        count: usize,
    },
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => {
                write!(formatter, "control TLS configuration failed: {error}")
            }
            Self::ClientIdentity(error) => {
                write!(formatter, "control client identity failed: {error}")
            }
            Self::ServerName => formatter.write_str("control TLS server name is invalid"),
            Self::Io(error) => write!(formatter, "control TLS stream failed: {error}"),
            Self::HandshakeStalled => formatter.write_str("control TLS handshake stalled"),
            Self::AlpnMismatch => formatter.write_str("control TLS ALPN mismatch"),
            Self::NoPeerCertificate => formatter.write_str("control TLS peer sent no certificate"),
            Self::UnexpectedPeerCertificateCount { count } => write!(
                formatter,
                "control TLS peer sent {count} certificates, expected exactly one"
            ),
        }
    }
}

impl std::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(error) | Self::ClientIdentity(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Server verifier that accepts exactly one pinned end-entity certificate.
struct PinnedServerVerifier {
    expected: [u8; 32],
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if !intermediates.is_empty() {
            return Err(pin_rejection());
        }
        if sha256(end_entity.as_ref()) != self.expected {
            return Err(pin_rejection());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, certificate, signature, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, certificate, signature, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

impl fmt::Debug for PinnedServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedServerVerifier")
            .field("expected", &"<sha256 pin>")
            .finish()
    }
}

fn pin_rejection() -> RustlsError {
    RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}
