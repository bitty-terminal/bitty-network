//! Shared integration-test helpers: DER inspection, pins, and an in-memory TLS
//! peer. Nothing here opens a socket, starts a thread, or writes the
//! filesystem.

#![allow(dead_code)]

use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;

use bitty_network_publication::LaunchMaterial;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as RustlsError, ServerConfig,
    ServerConnection, SignatureScheme, SupportedProtocolVersion,
};

pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
pub const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
pub const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
pub const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
pub const OID_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
pub const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    output
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// One DER tag-length-value.
#[derive(Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

pub fn parse_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), &'static str> {
    let tag = *input.first().ok_or("truncated tag")?;
    if tag & 0x1f == 0x1f {
        return Err("high-tag-number form is not expected");
    }
    let first_length = *input.get(1).ok_or("truncated length")?;
    let (length, header) = if first_length < 0x80 {
        (first_length as usize, 2)
    } else {
        let width = (first_length & 0x7f) as usize;
        if width == 0 || width > 4 {
            return Err("unsupported length width");
        }
        if input.len() < 2 + width {
            return Err("truncated long length");
        }
        if input[2] == 0 {
            return Err("non-minimal long length");
        }
        let mut length = 0usize;
        for byte in &input[2..2 + width] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(*byte as usize))
                .ok_or("length overflow")?;
        }
        if length < 0x80 {
            return Err("long form used for a short length");
        }
        (length, 2 + width)
    };
    let end = header.checked_add(length).ok_or("length overflow")?;
    if end > input.len() {
        return Err("truncated value");
    }
    Ok((
        Tlv {
            tag,
            value: &input[header..end],
        },
        &input[end..],
    ))
}

pub fn children(value: &[u8]) -> Result<Vec<Tlv<'_>>, &'static str> {
    let mut values = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (tlv, next) = parse_tlv(rest)?;
        values.push(tlv);
        rest = next;
    }
    Ok(values)
}

/// Certificate fields this crate's tests care about.
pub struct CertInfo {
    pub serial: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub basic_constraints: Option<Vec<u8>>,
    pub key_usage: Option<Vec<u8>>,
    pub extended_key_usage: Option<Vec<u8>>,
    pub subject_alt_name: Option<Vec<u8>>,
}

pub fn parse_certificate(der: &[u8]) -> Result<CertInfo, &'static str> {
    let (outer, rest) = parse_tlv(der)?;
    if outer.tag != 0x30 || !rest.is_empty() {
        return Err("certificate is not one SEQUENCE");
    }
    let fields = children(outer.value)?;
    if fields.len() != 3 || fields[0].tag != 0x30 {
        return Err("certificate fields");
    }
    let mut tbs = children(fields[0].value)?.into_iter();
    let first = tbs.next().ok_or("empty tbsCertificate")?;
    let serial_tlv = if first.tag == 0xa0 {
        tbs.next().ok_or("missing serial")?
    } else {
        first
    };
    if serial_tlv.tag != 0x02 {
        return Err("serial is not an INTEGER");
    }
    let signature = tbs.next().ok_or("missing signature algorithm")?;
    if signature.tag != 0x30 {
        return Err("signature algorithm is not a SEQUENCE");
    }
    let issuer = tbs.next().ok_or("missing issuer")?;
    if issuer.tag != 0x30 {
        return Err("issuer is not a SEQUENCE");
    }
    let validity = tbs.next().ok_or("missing validity")?;
    if validity.tag != 0x30 {
        return Err("validity is not a SEQUENCE");
    }
    let subject = tbs.next().ok_or("missing subject")?;
    if subject.tag != 0x30 {
        return Err("subject is not a SEQUENCE");
    }
    let spki = tbs.next().ok_or("missing subjectPublicKeyInfo")?;
    if spki.tag != 0x30 {
        return Err("subjectPublicKeyInfo is not a SEQUENCE");
    }

    let validity_fields = children(validity.value)?;
    if validity_fields.len() != 2 {
        return Err("validity fields");
    }
    let not_before = parse_time(&validity_fields[0])?;
    let not_after = parse_time(&validity_fields[1])?;

    let mut basic_constraints = None;
    let mut key_usage = None;
    let mut extended_key_usage = None;
    let mut subject_alt_name = None;
    for field in tbs {
        match field.tag {
            0xa3 => {
                let (extensions, rest) = parse_tlv(field.value)?;
                if extensions.tag != 0x30 || !rest.is_empty() {
                    return Err("extensions wrapper");
                }
                for extension in children(extensions.value)? {
                    let parts = children(extension.value)?;
                    if parts.len() < 2 || parts[0].tag != 0x06 {
                        return Err("extension fields");
                    }
                    let value = parts
                        .last()
                        .filter(|part| part.tag == 0x04)
                        .ok_or("extension value")?
                        .value
                        .to_vec();
                    match parts[0].value {
                        value_oid if value_oid == OID_BASIC_CONSTRAINTS => {
                            basic_constraints = Some(value);
                        }
                        value_oid if value_oid == OID_KEY_USAGE => {
                            key_usage = Some(value);
                        }
                        value_oid if value_oid == OID_EXTENDED_KEY_USAGE => {
                            extended_key_usage = Some(value);
                        }
                        value_oid if value_oid == OID_SUBJECT_ALT_NAME => {
                            subject_alt_name = Some(value);
                        }
                        _ => {}
                    }
                }
            }
            0x81 | 0x82 => {}
            _ => return Err("unexpected tbsCertificate field"),
        }
    }

    Ok(CertInfo {
        serial: serial_tlv.value.to_vec(),
        not_before,
        not_after,
        basic_constraints,
        key_usage,
        extended_key_usage,
        subject_alt_name,
    })
}

pub fn basic_constraints_ca_false(value: &[u8]) -> bool {
    let Ok((sequence, rest)) = parse_tlv(value) else {
        return false;
    };
    if sequence.tag != 0x30 || !rest.is_empty() {
        return false;
    }
    let Ok(fields) = children(sequence.value) else {
        return false;
    };
    match fields.first() {
        None => true,
        Some(boolean) => boolean.tag == 0x01 && boolean.value == [0x00],
    }
}

pub fn key_usage_digital_signature_only(value: &[u8]) -> bool {
    let Ok((bits, rest)) = parse_tlv(value) else {
        return false;
    };
    // rcgen emits all nine RFC 5280 key-usage bits: seven unused bits, then
    // `digitalSignature` (bit 0) and a zero second content octet.
    bits.tag == 0x03 && rest.is_empty() && bits.value == [0x07, 0x80, 0x00]
}

pub fn extended_key_usage_is(value: &[u8], expected_oid: &[u8]) -> bool {
    let Ok((sequence, rest)) = parse_tlv(value) else {
        return false;
    };
    if sequence.tag != 0x30 || !rest.is_empty() {
        return false;
    }
    let Ok(fields) = children(sequence.value) else {
        return false;
    };
    fields.len() == 1 && fields[0].tag == 0x06 && fields[0].value == expected_oid
}

fn parse_time(tlv: &Tlv<'_>) -> Result<i64, &'static str> {
    let text = std::str::from_utf8(tlv.value).map_err(|_| "time is not ASCII")?;
    let (year, rest) = match tlv.tag {
        0x17 => {
            if text.len() != 13 {
                return Err("UTCTime length");
            }
            let short_year: i64 = text[0..2].parse().map_err(|_| "UTCTime year")?;
            let year = if short_year < 50 {
                2000 + short_year
            } else {
                1900 + short_year
            };
            (year, &text[2..])
        }
        0x18 => {
            if text.len() != 15 {
                return Err("GeneralizedTime length");
            }
            let year: i64 = text[0..4].parse().map_err(|_| "GeneralizedTime year")?;
            (year, &text[4..])
        }
        _ => return Err("unsupported time tag"),
    };
    if !rest.ends_with('Z') {
        return Err("time is not UTC");
    }
    let rest = &rest[..rest.len() - 1];
    let month: i64 = rest[0..2].parse().map_err(|_| "month")?;
    let day: i64 = rest[2..4].parse().map_err(|_| "day")?;
    let hour: i64 = rest[4..6].parse().map_err(|_| "hour")?;
    let minute: i64 = rest[6..8].parse().map_err(|_| "minute")?;
    let second: i64 = rest[8..10].parse().map_err(|_| "second")?;
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Sequential reader for the documented manifest envelope.
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn take(&mut self, length: usize) -> &'a [u8] {
        let end = self.position + length;
        assert!(end <= self.bytes.len(), "manifest is truncated");
        let slice = &self.bytes[self.position..end];
        self.position = end;
        slice
    }

    pub fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().expect("two bytes"))
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().expect("four bytes"))
    }

    pub fn len_prefixed(&mut self) -> &'a [u8] {
        let length = self.u32() as usize;
        self.take(length)
    }

    pub fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

/// Server verifier used by the in-test helper side.
struct PinnedClientVerifier {
    expected: [u8; 32],
    supported: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if !intermediates.is_empty() || sha256(end_entity.as_ref()) != self.expected {
            return Err(pin_rejection());
        }
        Ok(ClientCertVerified::assertion())
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

impl std::fmt::Debug for PinnedClientVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedClientVerifier")
            .field("expected", &"<sha256 pin>")
            .finish()
    }
}

fn pin_rejection() -> RustlsError {
    RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

/// Build the helper-side server configuration from generated launch material.
///
/// `tls13_only = false` builds a TLS 1.2-only server for the refusal test; the
/// dev-dependency feature enables that protocol in test builds only.
pub fn server_config(
    material: &LaunchMaterial,
    expected_core_pin: [u8; 32],
    alpn: &[u8],
    tls13_only: bool,
) -> ServerConfig {
    server_config_with_chain(material, expected_core_pin, alpn, tls13_only, None)
}

/// Build the helper-side configuration with an optional extra certificate in
/// the presented chain, to prove the client rejects intermediates.
pub fn server_config_with_chain(
    material: &LaunchMaterial,
    expected_core_pin: [u8; 32],
    alpn: &[u8],
    tls13_only: bool,
    extra_certificate: Option<CertificateDer<'static>>,
) -> ServerConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let supported = provider.signature_verification_algorithms;
    let verifier = Arc::new(PinnedClientVerifier {
        expected: expected_core_pin,
        supported,
    });
    let versions: &[&'static SupportedProtocolVersion] = if tls13_only {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS12]
    };
    let mut chain = vec![material.helper_cert_der().clone()];
    if let Some(extra_certificate) = extra_certificate {
        chain.push(extra_certificate);
    }
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("test protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            chain,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.helper_key_der().to_vec())),
        )
        .expect("test helper certificate and key");
    if !alpn.is_empty() {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config
}

/// An in-memory server endpoint that drives rustls whenever the client reads.
///
/// This is deterministic and single-threaded: bytes written by the client are
/// fed to [`ServerConnection::read_tls`] on the next read, and server output is
/// returned to the client. No socket, thread, or timer is involved.
pub struct InMemoryPeer {
    server: ServerConnection,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
    outbound_position: usize,
}

impl InMemoryPeer {
    pub fn new(config: ServerConfig) -> io::Result<Self> {
        Ok(Self {
            server: ServerConnection::new(Arc::new(config))
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            inbound: Vec::new(),
            outbound: Vec::new(),
            outbound_position: 0,
        })
    }

    pub fn server_alpn(&self) -> Option<&[u8]> {
        self.server.alpn_protocol()
    }

    pub fn server_is_handshaking(&self) -> bool {
        self.server.is_handshaking()
    }

    /// Feed any bytes the client already wrote and process the server side.
    ///
    /// The client can finish its handshake before the server has processed the
    /// client's final flight; this drives the remaining in-memory work.
    pub fn drive(&mut self) -> io::Result<()> {
        self.pump()
    }

    fn pump(&mut self) -> io::Result<()> {
        if !self.inbound.is_empty() {
            let input = std::mem::take(&mut self.inbound);
            let mut cursor = Cursor::new(input.as_slice());
            while cursor.position() < input.len() as u64 {
                let read = self.server.read_tls(&mut cursor)?;
                if read == 0 {
                    break;
                }
                self.server
                    .process_new_packets()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            }
        }
        if self.outbound_position == self.outbound.len() {
            self.outbound.clear();
            self.outbound_position = 0;
        }
        while self.server.wants_write() {
            self.server.write_tls(&mut self.outbound)?;
        }
        Ok(())
    }
}

impl Read for InMemoryPeer {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.outbound_position < self.outbound.len() {
                let available = self.outbound.len() - self.outbound_position;
                let length = available.min(buffer.len());
                buffer[..length]
                    .copy_from_slice(&self.outbound[self.outbound_position..][..length]);
                self.outbound_position += length;
                return Ok(length);
            }
            self.pump()?;
            if self.outbound_position < self.outbound.len() {
                continue;
            }
            if !self.server.is_handshaking() {
                return Ok(0);
            }
            if self.inbound.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "in-memory TLS peer stalled",
                ));
            }
        }
    }
}

impl Write for InMemoryPeer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inbound.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
