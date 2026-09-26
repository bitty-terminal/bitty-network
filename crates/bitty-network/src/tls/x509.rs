//! Minimal X.509 attribute reader for TLS trust-anchor admission.
//!
//! # Scope, and why it is this small
//!
//! The provider has to answer one question about every certificate a caller
//! supplies as an extra trust anchor: *may this certificate be an explicit
//! trust anchor at all?* The answer needs four fixed fields, and this module
//! reads exactly those:
//!
//! - `basicConstraints` — present, and `CA=TRUE`;
//! - `keyUsage` — when present, includes `keyCertSign`;
//! - the validity window — `notBefore <= now < notAfter`;
//! - the public-key algorithm and key size, and the signature algorithm.
//!
//! Subject and issuer names are walked to prove they parse, because a
//! certificate whose names do not parse cannot be a usable anchor.
//!
//! **Nothing here verifies a signature.** Path building, path length, name
//! constraints, leaf key usage, and every cryptographic decision stay inside
//! `rustls`/`rustls-webpki`; this module only decides whether a certificate is
//! *admissible* as an anchor. Keeping that split sharp is the point: the
//! cryptographic authority is a reviewed library, and the part written here is
//! a bounded, read-only field extractor over caller-supplied **public**
//! certificates. No private key, no network, and no I/O is reachable from here.
//!
//! # Shape of the reader
//!
//! [`Der`] walks DER tag-length-value triples over a borrowed slice. It is
//! deliberately strict, because a permissive reader is how a trust decision
//! gets faked:
//!
//! - long-form lengths must be minimally encoded and must fit in the slice, so
//!   a length can never be re-interpreted at two widths;
//! - the indefinite form is rejected outright;
//! - high-tag-number form is rejected (no field read here needs it);
//! - a constructed value is walked to its exact end, so trailing garbage
//!   inside a structure is a rejection rather than a silently ignored tail.
//!
//! [`admit_root`] is total: it returns a typed reason for every refusal and
//! never panics, whatever the input bytes are. The truncation sweep in
//! `tests/tls_trust_anchor_admission.rs` reads every prefix of a real
//! certificate to keep that true.

use std::fmt;
use std::time::{Duration, SystemTime};

/// Seconds in one day; the unit for the civil-date conversion.
const SECONDS_PER_DAY: i64 = 86_400;

/// Tag: `BOOLEAN`.
const TAG_BOOLEAN: u8 = 0x01;
/// Tag: `INTEGER`.
const TAG_INTEGER: u8 = 0x02;
/// Tag: `BIT STRING`.
const TAG_BIT_STRING: u8 = 0x03;
/// Tag: `OCTET STRING`.
const TAG_OCTET_STRING: u8 = 0x04;
/// Tag: `OBJECT IDENTIFIER`.
const TAG_OID: u8 = 0x06;
/// Tag: `UTCTime`.
const TAG_UTC_TIME: u8 = 0x17;
/// Tag: `GeneralizedTime`.
const TAG_GENERALIZED_TIME: u8 = 0x18;
/// Tag: constructed `SEQUENCE`.
const TAG_SEQUENCE: u8 = 0x30;
/// Tag: constructed `SET`.
const TAG_SET: u8 = 0x31;
/// Tag: constructed, context-specific 0 (`version`).
const TAG_CONTEXT_0: u8 = 0xa0;
/// Tag: constructed, context-specific 3 (`extensions`).
const TAG_CONTEXT_3: u8 = 0xa3;

/// Bit mask of `keyCertSign` inside the first `KeyUsage` content octet:
/// `KeyUsage ::= BIT STRING { ..., keyCertSign (5), ... }`, and bit 5 is
/// `0b0000_0100` counting from the most significant bit.
const KEY_CERT_SIGN_BIT: u8 = 0b0000_0100;

/// Bit index of `keyCertSign` counted from the most significant bit.
const KEY_CERT_SIGN_INDEX: u32 = 5;

/// Smallest RSA modulus this crate admits as a trust-anchor public key, in
/// bits.
///
/// Below this the anchor is not a meaningful barrier. This is a policy floor,
/// not an intrinsic constant: raising it narrows trust, so it lives here with
/// the rest of the algorithm policy rather than inline at the check.
pub const MIN_RSA_MODULUS_BITS: u32 = 2048;

/// Smallest elliptic-curve order this crate admits as a trust-anchor public
/// key, in bits.
///
/// Matches the NIST P-256 curve, the smallest curve `rustls` verifies with.
pub const MIN_ECDSA_CURVE_BITS: u32 = 256;

/// Named elliptic curves a trust-anchor public key may use, with the curve
/// order in bits.
///
/// Only the three NIST curves `rustls` verifies with appear here, so a curve
/// this crate admits is a curve the backends can actually verify with.
const SUPPORTED_ECDSA_CURVES: [(&[u8], u32); 3] = [
    // P-256 (secp256r1 / prime256v1).
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], 256),
    // P-384 (secp384r1).
    (&[0x2b, 0x81, 0x04, 0x00, 0x22], 384),
    // P-521 (secp521r1).
    (&[0x2b, 0x81, 0x04, 0x00, 0x23], 521),
];

/// `id-ecPublicKey` (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `rsaEncryption` (1.2.840.113549.1.1.1).
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `Ed25519` (1.3.101.112).
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// `id-ce-basicConstraints` (2.5.29.19).
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// `id-ce-keyUsage` (2.5.29.15).
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

/// Signature algorithms this crate admits for a trust anchor, by OID.
///
/// SHA-256 and stronger only. SHA-1 appears in RFC 5280 for legacy
/// certificates and is absent here on purpose: a trust anchor signed with
/// SHA-1 is not a control worth keeping, and refusing it fails closed.
const ADMITTED_SIGNATURE_ALGORITHMS: [&[u8]; 8] = [
    // sha256WithRSAEncryption (1.2.840.113549.1.1.11).
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
    // sha384WithRSAEncryption (1.2.840.113549.1.1.12).
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c],
    // sha512WithRSAEncryption (1.2.840.113549.1.1.13).
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d],
    // ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    // ecdsa-with-SHA384 (1.2.840.10045.4.3.3).
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03],
    // ecdsa-with-SHA512 (1.2.840.10045.4.3.4).
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04],
    // Ed25519 (1.3.101.112).
    OID_ED25519,
    // RSASSA-PSS (1.2.840.113549.1.1.10), gated on its hash parameters.
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a],
];

/// `sha1WithRSAEncryption` (1.2.840.113549.1.1.5): named by RFC 5280 for
/// legacy certificates and absent from the admitted set, so it is a policy
/// decision rather than an oversight. Nothing in the reader has to recognize
/// it: a certificate that names it fails
/// [`RootRejection::UnsupportedSignatureAlgorithm`] by falling out of
/// [`ADMITTED_SIGNATURE_ALGORITHMS`]. The constant exists so the test that pins
/// the exclusion names the OID rather than a literal.
#[cfg(test)]
const OID_SHA1_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];

/// `id-sha256` (2.16.840.1.101.3.4.2.1).
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `id-sha384` (2.16.840.1.101.3.4.2.2).
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// `id-sha512` (2.16.840.1.101.3.4.2.3).
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// Length of an RFC 5280 `UTCTime` value: `YYMMDDHHMMSSZ`.
const TIME_UTC_LEN: usize = 13;
/// Length of an RFC 5280 `GeneralizedTime` value: `YYYYMMDDHHMMSSZ`.
const TIME_GENERALIZED_LEN: usize = 15;

/// Why a certificate is not admissible as an explicit trust anchor.
///
/// Every refusal maps to exactly one stable reason, and the reasons are the
/// policy requirements rather than parser trivia: a caller who supplied a
/// bundle can tell "that certificate is not a CA" from "that certificate is
/// expired" from "that certificate uses a key I will not anchor on".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootRejection {
    /// The bytes are not a well-formed certificate structure.
    Malformed,
    /// The certificate declares no `basicConstraints`, so it never claims to be
    /// a CA.
    NotCaConstrained,
    /// The certificate declares `basicConstraints` with `CA=FALSE`.
    NotCa,
    /// `keyUsage` is present but does not include `keyCertSign`.
    NoKeyCertSign,
    /// The signature algorithm is not one this crate admits.
    UnsupportedSignatureAlgorithm,
    /// The inner and outer `signatureAlgorithm` fields disagree.
    SignatureAlgorithmMismatch,
    /// The public-key algorithm is not one this crate admits.
    UnsupportedPublicKeyAlgorithm,
    /// The public key is smaller than this crate admits.
    WeakPublicKey,
    /// `notBefore` or `notAfter` is missing or unparseable.
    UnparseableValidity,
}

impl fmt::Display for RootRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Malformed => "malformed certificate",
            Self::NotCaConstrained => "no basicConstraints extension",
            Self::NotCa => "basicConstraints CA=FALSE",
            Self::NoKeyCertSign => "keyUsage without keyCertSign",
            Self::UnsupportedSignatureAlgorithm => "unsupported signature algorithm",
            Self::SignatureAlgorithmMismatch => "signatureAlgorithm fields disagree",
            Self::UnsupportedPublicKeyAlgorithm => "unsupported public key algorithm",
            Self::WeakPublicKey => "public key below the admitted size",
            Self::UnparseableValidity => "unparseable validity window",
        };
        f.write_str(text)
    }
}

/// One admitted trust anchor: the fields the provider re-checks later.
///
/// The certificate DER itself is *not* retained here. The provider hands the
/// original bytes to `rustls` (which owns path building) and keeps only what it
/// needs to re-run its own admission checks before each new TLS destination:
/// the validity window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedRoot {
    not_before: SystemTime,
    not_after: SystemTime,
}

impl AdmittedRoot {
    /// The instant from which this anchor is valid, inclusive.
    #[cfg(test)]
    pub fn not_before(&self) -> SystemTime {
        self.not_before
    }

    /// The instant at which this anchor stops being valid, exclusive.
    #[cfg(test)]
    pub fn not_after(&self) -> SystemTime {
        self.not_after
    }

    /// True when `now` is inside the validity window, with no grace period:
    /// `notBefore <= now < notAfter`.
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

/// A strict, read-only DER tag-length-value reader over a borrowed slice.
///
/// Construction is private to this module; the only way to make one is
/// [`Der::read`], which fails rather than guessing.
#[derive(Debug, Clone, Copy)]
struct Der<'a> {
    input: &'a [u8],
}

impl<'a> Der<'a> {
    /// A reader over `input`.
    fn read(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// True when no bytes remain.
    fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Read one tag-length-value triple, advancing past it.
    ///
    /// Returns the tag and the value contents. The reader is left positioned at
    /// the next element, so a caller that wants to walk a constructed value
    /// keeps reading from `self` — a third return value would be a second,
    /// silently different notion of "what is left", which is how a walker ends
    /// up reading a sibling's bytes as its own.
    ///
    /// Fails on a truncated element, the indefinite length form, a non-minimal
    /// long-form length, a long form wider than the value can allow, and
    /// high-tag-number form.
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        let (tag, after_tag) = self.input.split_first()?;
        // High-tag-number form (low five tag bits all set) encodes a tag number
        // of 31 or more. No field this module reads uses it, so refusing it
        // keeps the reader from decoding a tag it would never match.
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (length, after_length) = read_length(after_tag)?;
        if length > after_length.len() {
            return None;
        }
        let (contents, rest) = after_length.split_at(length);
        self.input = rest;
        Some((*tag, contents))
    }

    /// Read one triple, require `tag`, and return a reader over its contents.
    ///
    /// This is how a constructed value is entered: the returned reader walks
    /// exactly that value's bytes, and the caller is responsible for consuming
    /// all of them (or for rejecting a non-empty tail explicitly).
    fn expect_value(&mut self, tag: u8) -> Result<Der<'a>, RootRejection> {
        match self.next() {
            Some((found, contents)) if found == tag => Ok(Der::read(contents)),
            _ => Err(RootRejection::Malformed),
        }
    }

    /// Skip one triple of any tag, used where a field's tag carries no
    /// admission decision (such as a `Name` attribute value).
    fn skip(&mut self) -> Result<(), RootRejection> {
        match self.next() {
            Some(_) => Ok(()),
            None => Err(RootRejection::Malformed),
        }
    }
}

/// Read one DER definite length, returning it with the bytes that follow.
///
/// Rejects the indefinite form (`0x80`), a zero long-form length byte (a
/// non-minimal encoding), and a long form wider than `usize`, so a length is
/// read at exactly one width or not at all.
fn read_length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = input.split_first()?;
    match *first {
        // Short form: the low seven bits are the length.
        0x00..=0x7f => Some((usize::from(*first), rest)),
        // Indefinite form: not valid DER.
        0x80 => None,
        // Long form: the low seven bits count the length-of-length bytes.
        _ => {
            let count = usize::from(first & 0x7f);
            if count == 0
                || count > std::mem::size_of::<usize>()
                || rest.len() < count
                // A leading zero byte would make the encoding non-minimal.
                || rest.first() == Some(&0)
            {
                return None;
            }
            let (width, tail) = rest.split_at(count);
            let mut length = 0usize;
            for byte in width {
                length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
            }
            Some((length, tail))
        }
    }
}

/// Decide whether `der` is admissible as an explicit TLS trust anchor.
///
/// Returns the fields the provider re-checks before each handshake. Every
/// refusal is a typed [`RootRejection`]; nothing here panics, whatever the
/// input bytes are.
pub fn admit_root(der: &[u8]) -> Result<AdmittedRoot, RootRejection> {
    let mut certificate = Der::read(der);
    let mut body = certificate.expect_value(TAG_SEQUENCE)?;
    // A certificate is exactly one SEQUENCE and nothing after it: trailing
    // bytes are a malformed certificate, not a certificate whose tail is
    // quietly ignored.
    if !certificate.is_empty() {
        return Err(RootRejection::Malformed);
    }
    let mut tbs = body.expect_value(TAG_SEQUENCE)?;
    let outer_algorithm = body.expect_value(TAG_SEQUENCE)?;
    body.skip()?; // signatureValue BIT STRING
    if !body.is_empty() {
        return Err(RootRejection::Malformed);
    }

    // version [0] EXPLICIT Version DEFAULT v1
    if let Some((tag, _)) = tbs.next() {
        if tag != TAG_CONTEXT_0 {
            return Err(RootRejection::Malformed);
        }
    }
    tbs.skip()?; // serialNumber INTEGER
    let inner_algorithm = tbs.expect_value(TAG_SEQUENCE)?;
    skip_name(&mut tbs)?; // issuer Name
    let validity = read_validity(&mut tbs)?;
    skip_name(&mut tbs)?; // subject Name
    read_public_key(&mut tbs)?;
    let extensions = read_optional_extensions(&mut tbs)?;

    // RFC 5280 4.1.1.2: the two signatureAlgorithm fields must carry the same
    // algorithm, so a reader that checked only one of them could be shown a
    // different algorithm than the one verified.
    if !algorithms_agree(&inner_algorithm, &outer_algorithm) {
        return Err(RootRejection::SignatureAlgorithmMismatch);
    }
    if !signature_algorithm_admitted(&inner_algorithm) {
        return Err(RootRejection::UnsupportedSignatureAlgorithm);
    }
    let constraints = read_extensions(extensions)?;

    if !constraints.is_ca {
        return Err(if constraints.saw_basic_constraints {
            RootRejection::NotCa
        } else {
            RootRejection::NotCaConstrained
        });
    }
    if constraints.saw_key_usage && !constraints.key_cert_sign {
        return Err(RootRejection::NoKeyCertSign);
    }
    Ok(AdmittedRoot {
        not_before: validity.0,
        not_after: validity.1,
    })
}

/// The `basicConstraints` / `keyUsage` decisions read out of a certificate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Constraints {
    saw_basic_constraints: bool,
    is_ca: bool,
    saw_key_usage: bool,
    key_cert_sign: bool,
}

/// Collect the `[3] extensions` field, or an empty reader when absent.
///
/// `issuerUniqueID [1]` and `subjectUniqueID [2]` are legacy and carry no
/// admission decision, so they are skipped. A second `[3]` is malformed.
fn read_optional_extensions<'a>(tbs: &mut Der<'a>) -> Result<Der<'a>, RootRejection> {
    let mut extensions = Der::read(&[]);
    let mut saw_extensions = false;
    while !tbs.is_empty() {
        let (tag, wrapper) = tbs.next().ok_or(RootRejection::Malformed)?;
        if tag != TAG_CONTEXT_3 {
            continue;
        }
        if saw_extensions {
            return Err(RootRejection::Malformed);
        }
        saw_extensions = true;
        let mut wrapper = Der::read(wrapper);
        extensions = wrapper.expect_value(TAG_SEQUENCE)?;
        if !wrapper.is_empty() {
            return Err(RootRejection::Malformed);
        }
    }
    Ok(extensions)
}

/// Walk every `Extension` and record the two the decision depends on.
///
/// A repeated `basicConstraints` or `keyUsage` is rejected: RFC 5280 allows an
/// extension at most once, and a second copy is a way to make a reader and a
/// verifier disagree about the same certificate.
fn read_extensions(mut extensions: Der<'_>) -> Result<Constraints, RootRejection> {
    let mut constraints = Constraints::default();
    while !extensions.is_empty() {
        let mut extension = extensions.expect_value(TAG_SEQUENCE)?;
        let oid = read_oid(&mut extension)?;
        // `critical BOOLEAN DEFAULT FALSE` then `extnValue OCTET STRING`. The
        // boolean is optional, so the element after the OID is either that
        // boolean or already the value; nothing else is a well-formed extension.
        let (tag, contents) = extension.next().ok_or(RootRejection::Malformed)?;
        let value = match tag {
            TAG_BOOLEAN => {
                let (tag, value) = extension.next().ok_or(RootRejection::Malformed)?;
                if tag != TAG_OCTET_STRING {
                    return Err(RootRejection::Malformed);
                }
                value
            }
            TAG_OCTET_STRING => contents,
            _ => return Err(RootRejection::Malformed),
        };
        if !extension.is_empty() {
            return Err(RootRejection::Malformed);
        }
        if oid == OID_BASIC_CONSTRAINTS {
            if constraints.saw_basic_constraints {
                return Err(RootRejection::Malformed);
            }
            constraints.saw_basic_constraints = true;
            constraints.is_ca = read_basic_constraints(value)?;
        } else if oid == OID_KEY_USAGE {
            if constraints.saw_key_usage {
                return Err(RootRejection::Malformed);
            }
            constraints.saw_key_usage = true;
            constraints.key_cert_sign = read_key_usage(value)?;
        }
    }
    Ok(constraints)
}

/// Read an `OBJECT IDENTIFIER` as its raw content octets.
///
/// The content octets are the only form compared in this module: two OIDs are
/// equal exactly when their encodings are byte-equal, because DER mandates the
/// minimal base-128 encoding, so there is no alternative spelling of the same
/// OID left to normalize away.
fn read_oid<'a>(reader: &mut Der<'a>) -> Result<&'a [u8], RootRejection> {
    match reader.next() {
        Some((TAG_OID, contents)) if !contents.is_empty() => Ok(contents),
        _ => Err(RootRejection::Malformed),
    }
}

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint
/// INTEGER OPTIONAL }`; the answer is whether `cA` is present and TRUE.
///
/// `pathLenConstraint` is deliberately not interpreted here: the path it
/// limits is enforced during path building, which is `rustls-webpki`'s job.
fn read_basic_constraints(value: &[u8]) -> Result<bool, RootRejection> {
    let mut wrapper = Der::read(value);
    let mut body = wrapper.expect_value(TAG_SEQUENCE)?;
    if !wrapper.is_empty() {
        return Err(RootRejection::Malformed);
    }
    if body.is_empty() {
        // An empty SEQUENCE leaves `cA` at its default, so the certificate
        // never claims to be a CA.
        return Ok(false);
    }
    let (tag, contents) = body.next().ok_or(RootRejection::Malformed)?;
    let is_ca = match tag {
        TAG_BOOLEAN => {
            // DER encodes TRUE as exactly one octet, 0xff.
            if contents != [0xff] && contents != [0x00] {
                return Err(RootRejection::Malformed);
            }
            contents == [0xff]
        }
        // pathLenConstraint with `cA` left at its default.
        TAG_INTEGER => false,
        _ => return Err(RootRejection::Malformed),
    };
    // pathLenConstraint INTEGER OPTIONAL, and nothing after it.
    if let Some((tag, _)) = body.next() {
        if tag != TAG_INTEGER {
            return Err(RootRejection::Malformed);
        }
    }
    if !body.is_empty() {
        return Err(RootRejection::Malformed);
    }
    Ok(is_ca)
}

/// `KeyUsage ::= BIT STRING { ..., keyCertSign (5), ... }`; the answer is
/// whether bit 5 is set.
///
/// DER BIT STRING content is a count of unused bits in the *last* octet
/// followed by the octets, so the significant bits are the leading
/// `8 * octets - unused` of them. `keyCertSign` is bit 5 counted from the most
/// significant bit of the first octet, so it is set only when the string is
/// long enough to hold it and that octet's mask is present. A set bit in the
/// padding is malformed rather than a usage.
fn read_key_usage(value: &[u8]) -> Result<bool, RootRejection> {
    let mut reader = Der::read(value);
    let (tag, contents) = reader.next().ok_or(RootRejection::Malformed)?;
    if tag != TAG_BIT_STRING || !reader.is_empty() || contents.is_empty() {
        return Err(RootRejection::Malformed);
    }
    let unused_bits = u32::from(contents[0]);
    if unused_bits > 7 {
        return Err(RootRejection::Malformed);
    }
    let octets = &contents[1..];
    if octets.is_empty() {
        // A bit string with no octets holds no bits, so it permits nothing.
        return Ok(false);
    }
    // DER requires the padding bits to be zero; a set one would let two readers
    // disagree about the same extension.
    if unused_bits > 0 {
        let padding_mask = (1u8 << unused_bits) - 1;
        if octets[octets.len() - 1] & padding_mask != 0 {
            return Err(RootRejection::Malformed);
        }
    }
    let significant_bits = u32::try_from(octets.len())
        .ok()
        .and_then(|octets| octets.checked_mul(8))
        .and_then(|bits| bits.checked_sub(unused_bits))
        .unwrap_or(0);
    if significant_bits <= KEY_CERT_SIGN_INDEX {
        return Ok(false);
    }
    Ok(octets[0] & KEY_CERT_SIGN_BIT != 0)
}

/// The validity window as a `(notBefore, notAfter)` pair.
type Validity = (SystemTime, SystemTime);

/// Read `validity ::= SEQUENCE { notBefore Time, notAfter Time }`.
///
/// A structural problem anywhere in `validity` is reported as
/// [`RootRejection::UnparseableValidity`]: a window this reader cannot state
/// exactly is a window it must not anchor on.
fn read_validity(tbs: &mut Der<'_>) -> Result<Validity, RootRejection> {
    let malformed = RootRejection::UnparseableValidity;
    let mut validity = tbs.expect_value(TAG_SEQUENCE).map_err(|_| malformed)?;
    let (tag, contents) = validity.next().ok_or(malformed)?;
    let not_before = read_time(tag, contents).ok_or(malformed)?;
    let (tag, contents) = validity.next().ok_or(malformed)?;
    let not_after = read_time(tag, contents).ok_or(malformed)?;
    if !validity.is_empty() {
        return Err(malformed);
    }
    Ok((not_before, not_after))
}

/// Parse an X.509 `Time` as a UTC instant.
///
/// RFC 5280 pins the profile: `UTCTime` is `YYMMDDHHMMSSZ`, `GeneralizedTime`
/// is `YYYYMMDDHHMMSSZ`, and neither carries fractional seconds or a non-`Z`
/// offset. Anything else is refused rather than interpreted, so a certificate
/// cannot smuggle in a local-time window this crate would silently shift.
fn read_time(tag: u8, contents: &[u8]) -> Option<SystemTime> {
    let text = std::str::from_utf8(contents).ok()?;
    if !text.ends_with('Z') {
        return None;
    }
    let (year, rest) = match tag {
        TAG_UTC_TIME if text.len() == TIME_UTC_LEN => {
            let short_year = two_digits(&text[0..2])?;
            // RFC 5280 4.1.2.5.1: 00..49 is 20xx, 50..99 is 19xx.
            let year = if short_year < 50 {
                2000 + short_year
            } else {
                1900 + short_year
            };
            (year, &text[2..])
        }
        TAG_GENERALIZED_TIME if text.len() == TIME_GENERALIZED_LEN => {
            (four_digits(&text[0..4])?, &text[4..])
        }
        _ => return None,
    };
    let month = two_digits(&rest[0..2])?;
    let day = two_digits(&rest[2..4])?;
    let hour = two_digits(&rest[4..6])?;
    let minute = two_digits(&rest[6..8])?;
    let second = two_digits(&rest[8..10])?;
    // A leap second is legal in ASN.1 `Time` but has no POSIX instant, and
    // RFC 5280 forbids it, so a certificate carrying one is refused.
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let seconds = days_from_civil(year, month, day)?
        .checked_mul(SECONDS_PER_DAY)?
        .checked_add(i64::from(hour) * 3600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    let seconds = u64::try_from(seconds).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}

/// Two ASCII decimal digits as a number.
fn two_digits(text: &str) -> Option<u32> {
    match text.as_bytes() {
        [high, low] => Some(char::from(*high).to_digit(10)? * 10 + char::from(*low).to_digit(10)?),
        _ => None,
    }
}

/// ASCII decimal digits as a number, rejecting anything that is not one.
fn four_digits(text: &str) -> Option<u32> {
    let mut value: u32 = 0;
    for byte in text.bytes() {
        value = value
            .checked_mul(10)?
            .checked_add(char::from(byte).to_digit(10)?)?;
    }
    Some(value)
}

/// Days from 1970-01-01 to `year-month-day` in the proleptic Gregorian
/// calendar, or `None` for a date the calendar does not have.
///
/// This is Howard Hinnant's `days_from_civil`: an exact integer algorithm with
/// no lookup table and no floating point. Rejecting impossible dates (a
/// February 30th) is what keeps a validity window from silently rolling over
/// into the next month.
fn days_from_civil(year: u32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) {
        return None;
    }
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    // Shift the year so March starts it, which moves the leap day to the end
    // of the count instead of the middle.
    let shifted = year - i64::from(month <= 2);
    let era = if shifted >= 0 { shifted } else { shifted - 399 } / 400;
    let year_of_era = shifted - era * 400;
    let month_of_year = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_of_year + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// Days in `month` of `year`.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        // Unreachable: `month` is range-checked by the caller.
        _ => 0,
    }
}

/// True when `year` is a leap year in the proleptic Gregorian calendar.
fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Skip one X.509 `Name` (an `RDNSequence`), proving it parses.
///
/// `Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName`, and a
/// `RelativeDistinguishedName` is a `SET OF AttributeTypeAndValue`, which is a
/// `SEQUENCE` of an OID and a value. Walking the whole structure is the check:
/// a name this reader cannot walk is a name no conforming verifier can match
/// against, so admitting the anchor would be admitting something unusable.
fn skip_name(reader: &mut Der<'_>) -> Result<(), RootRejection> {
    let mut rdns = reader.expect_value(TAG_SEQUENCE)?;
    while !rdns.is_empty() {
        let mut set = rdns.expect_value(TAG_SET)?;
        while !set.is_empty() {
            let mut attribute = set.expect_value(TAG_SEQUENCE)?;
            read_oid(&mut attribute)?;
            attribute.skip()?;
            if !attribute.is_empty() {
                return Err(RootRejection::Malformed);
            }
        }
    }
    Ok(())
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }`, read far enough to admit or refuse the key.
fn read_public_key(tbs: &mut Der<'_>) -> Result<(), RootRejection> {
    let mut spki = tbs.expect_value(TAG_SEQUENCE)?;
    let mut algorithm = spki.expect_value(TAG_SEQUENCE)?;
    let oid = read_oid(&mut algorithm)?;
    let parameters = algorithm.next().map(|(_, contents)| contents);
    if !algorithm.is_empty() {
        return Err(RootRejection::Malformed);
    }
    let (tag, key) = spki.next().ok_or(RootRejection::Malformed)?;
    if tag != TAG_BIT_STRING || key.is_empty() || !spki.is_empty() {
        return Err(RootRejection::Malformed);
    }
    // The first content octet counts unused trailing bits; a public key uses
    // whole octets, so anything but zero here is malformed.
    if key[0] != 0 {
        return Err(RootRejection::Malformed);
    }
    let key = &key[1..];

    if oid == OID_RSA_ENCRYPTION {
        // rsaEncryption parameters are NULL when present; any other parameter
        // is a different algorithm wearing the same OID.
        if parameters.is_some_and(|value| value != [0x05, 0x00]) {
            return Err(RootRejection::UnsupportedPublicKeyAlgorithm);
        }
        return match rsa_modulus_bits(key) {
            Some(bits) if bits >= MIN_RSA_MODULUS_BITS => Ok(()),
            Some(_) => Err(RootRejection::WeakPublicKey),
            None => Err(RootRejection::UnsupportedPublicKeyAlgorithm),
        };
    }
    if oid == OID_EC_PUBLIC_KEY {
        // `id-ecPublicKey` names its curve *in* the parameters field, as the
        // named-curve OID's own content octets rather than a nested TLV, so the
        // comparison is against those octets directly.
        let curve = parameters.ok_or(RootRejection::UnsupportedPublicKeyAlgorithm)?;
        return match SUPPORTED_ECDSA_CURVES.iter().find(|(oid, _)| *oid == curve) {
            Some((_, bits)) if *bits >= MIN_ECDSA_CURVE_BITS => Ok(()),
            Some(_) => Err(RootRejection::WeakPublicKey),
            None => Err(RootRejection::UnsupportedPublicKeyAlgorithm),
        };
    }
    if oid == OID_ED25519 {
        // Ed25519 keys have a fixed width and take no parameters.
        return if parameters.is_some() {
            Err(RootRejection::UnsupportedPublicKeyAlgorithm)
        } else {
            Ok(())
        };
    }
    Err(RootRejection::UnsupportedPublicKeyAlgorithm)
}

/// Significant bit length of the modulus in a DER `RSAPublicKey`.
///
/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`. The
/// bit length is the modulus's octet length less eight when the leading octet
/// is a sign pad, which is why a 256-octet modulus holding 2047 significant
/// bits is refused while one holding 2048 is not.
fn rsa_modulus_bits(key: &[u8]) -> Option<u32> {
    let mut wrapper = Der::read(key);
    let mut body = wrapper.expect_value(TAG_SEQUENCE).ok()?;
    if !wrapper.is_empty() {
        return None;
    }
    let (tag, modulus) = body.next()?;
    if tag != TAG_INTEGER || modulus.is_empty() {
        return None;
    }
    // The exponent is a positive INTEGER; it carries no admission decision, but
    // it has to be there and the sequence has to end after it.
    let (tag, _) = body.next()?;
    if tag != TAG_INTEGER || !body.is_empty() {
        return None;
    }
    let octets = u32::try_from(modulus.len()).ok()?;
    // A DER INTEGER is minimally encoded and non-negative, so a leading 0x00 is
    // a sign pad; any other leading octet has its top bit set by definition.
    Some(match modulus.first() {
        Some(0x00) => octets * 8 - 8,
        _ => octets * 8,
    })
}

/// Whether the two `signatureAlgorithm` fields carry byte-identical content.
///
/// Only the algorithm OID is compared, because that is what a verifier acts on
/// and what the admission decision depends on. RFC 5280 requires the two
/// fields to match; a difference is refused rather than resolved in favour of
/// either one.
fn algorithms_agree(inner: &Der<'_>, outer: &Der<'_>) -> bool {
    match (algorithm_oid(inner), algorithm_oid(outer)) {
        (Some((inner, _)), Some((outer, _))) => inner == outer,
        _ => false,
    }
}

/// The algorithm OID of one `AlgorithmIdentifier`, with its parameters.
fn algorithm_oid<'a>(algorithm: &Der<'a>) -> Option<(&'a [u8], Option<&'a [u8]>)> {
    let mut body = Der::read(algorithm.input);
    let oid = read_oid(&mut body).ok()?;
    let parameters = body.next().map(|(_, contents)| contents);
    body.is_empty().then_some((oid, parameters))
}

/// Whether `algorithm` is a signature algorithm this crate admits.
///
/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`.
/// The admitted set is SHA-256 and stronger with RSA, ECDSA, and Ed25519, plus
/// RSASSA-PSS when its parameters name an admitted hash. SHA-1 is named in
/// RFC 5280 for legacy certificates and is refused here: a trust anchor signed
/// with SHA-1 is not a control worth keeping, and refusing it fails closed.
fn signature_algorithm_admitted(algorithm: &Der<'_>) -> bool {
    let Some((oid, parameters)) = algorithm_oid(algorithm) else {
        return false;
    };
    if !ADMITTED_SIGNATURE_ALGORITHMS.contains(&oid) {
        return false;
    }
    match parameters {
        // Every other admitted OID takes no parameters that change the
        // decision, and an unexpected parameter shape is caught by
        // `algorithm_oid` refusing a trailing element.
        None => true,
        Some(parameters) => pss_hash_admitted(parameters),
    }
}

/// Whether `RSASSA-PSS-params` name an admitted hash.
///
/// `RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0] HashAlgorithm DEFAULT
/// sha1, ... }`, so the hash is the first, explicitly tagged field. Absent
/// parameters mean SHA-1, so they are not admitted.
fn pss_hash_admitted(parameters: &[u8]) -> bool {
    let mut params = Der::read(parameters);
    let Some((_, hash)) = params.next() else {
        return false;
    };
    // [0] EXPLICIT, so the hash follows as its own AlgorithmIdentifier.
    let mut hash = Der::read(hash);
    match hash.next() {
        Some((TAG_OID, contents)) => {
            hash.is_empty() && [OID_SHA256, OID_SHA384, OID_SHA512].contains(&contents)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose, date_time_ymd,
    };
    use time::OffsetDateTime;

    /// Validity windows used by the tests, as UTC midnight dates.
    ///
    /// Fixed dates rather than offsets from the clock: the assertions are about
    /// how the window is *read*, and a fixed window makes an already-expired or
    /// not-yet-valid certificate expressible without sleeping or racing.
    const WINDOW_FROM: fn() -> OffsetDateTime = || date_time_ymd(2000, 1, 1);
    const WINDOW_UNTIL: fn() -> OffsetDateTime = || date_time_ymd(2100, 1, 1);
    const EXPIRED_FROM: fn() -> OffsetDateTime = || date_time_ymd(1975, 1, 1);
    const EXPIRED_UNTIL: fn() -> OffsetDateTime = || date_time_ymd(1980, 1, 1);
    const FUTURE_FROM: fn() -> OffsetDateTime = || date_time_ymd(4000, 1, 1);
    const FUTURE_UNTIL: fn() -> OffsetDateTime = || date_time_ymd(4090, 1, 1);

    /// The `SystemTime` a test treats as "now", inside the good window.
    fn inside_window() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800)
    }

    /// Certificate parameters with the requested CA constraints and window.
    fn params(
        is_ca: IsCa,
        key_usages: Vec<KeyUsagePurpose>,
        from: OffsetDateTime,
        until: OffsetDateTime,
    ) -> CertificateParams {
        let mut params = CertificateParams::default();
        params.is_ca = is_ca;
        params.key_usages = key_usages;
        params.not_before = from;
        params.not_after = until;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "bitty test anchor");
        params.distinguished_name = name;
        params
    }

    /// A CA certificate in DER with the requested constraints and window.
    fn ca_der(is_ca: IsCa, key_usages: Vec<KeyUsagePurpose>) -> Vec<u8> {
        ca_der_in(params(is_ca, key_usages, WINDOW_FROM(), WINDOW_UNTIL()))
    }

    /// A CA certificate in DER from ready-made parameters.
    fn ca_der_in(params: CertificateParams) -> Vec<u8> {
        let key = KeyPair::generate().expect("runtime test key");
        params
            .self_signed(&key)
            .expect("self-signed test certificate")
            .der()
            .to_vec()
    }

    /// A usable CA certificate: `CA=TRUE` with `keyCertSign`.
    fn good_ca() -> Vec<u8> {
        ca_der(
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        )
    }

    /// One DER triple, with the length computed rather than hand-counted.
    ///
    /// The hand-built fixtures below are only trustworthy if their lengths are
    /// right, and a miscounted length fails as `Malformed` for the wrong reason
    /// — which would make a negative test pass without testing anything. Every
    /// length in these fixtures is therefore derived from the contents.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        assert!(
            contents.len() < 0x80,
            "these fixtures stay in the short-form length range"
        );
        let mut out = vec![tag, contents.len() as u8];
        out.extend_from_slice(contents);
        out
    }

    /// A `Name` (`RDNSequence`) holding exactly one RDN with one attribute.
    fn name(oid: &[u8], value: &[u8]) -> Vec<u8> {
        let attribute = tlv(
            TAG_SEQUENCE,
            &[tlv(TAG_OID, oid), tlv(TAG_OCTET_STRING, value)].concat(),
        );
        tlv(TAG_SEQUENCE, &tlv(TAG_SET, &attribute))
    }

    /// Walk `bytes` as a `Name`, for the strictness cases below.
    fn walk_name(bytes: &[u8]) -> Result<(), RootRejection> {
        let mut reader = Der::read(bytes);
        skip_name(&mut reader)
    }

    /// An OID that is legal to carry in a name; the tests vary the *structure*
    /// around it rather than the identifier itself.
    const NAME_OID: &[u8] = &[0x2a, 0x03, 0x04];

    /// `basicConstraints` must *say* `CA=TRUE`, and every other conforming
    /// encoding of the same field says it does not.
    ///
    /// The case the primary `a_root_must_declare_itself_a_ca` pin cannot reach
    /// is the empty `SEQUENCE`. DER encodes a defaulted `cA` by *omitting* it,
    /// so `basicConstraints` with no members at all is a conforming way to say
    /// `CA=FALSE` — the same claim as an explicit `BOOLEAN FALSE`, reached
    /// through a different arm of the reader. Both must answer "not a CA", and
    /// neither may be mistaken for the absent-extension case, which is a
    /// different refusal reason.
    ///
    /// The `pathLenConstraint`-only form is here for the same reason: it also
    /// leaves `cA` at its default while being a non-empty `SEQUENCE`.
    #[test]
    fn basic_constraints_reads_every_non_true_encoding_as_not_a_ca() {
        // `SEQUENCE {}` — `cA` omitted, left at its DEFAULT FALSE.
        assert_eq!(
            read_basic_constraints(&tlv(TAG_SEQUENCE, &[])),
            Ok(false),
            "an empty basicConstraints is a conforming CA=FALSE and must not read as a CA"
        );
        // `SEQUENCE { BOOLEAN FALSE }` — the explicit spelling of the same claim.
        assert_eq!(
            read_basic_constraints(&tlv(TAG_SEQUENCE, &tlv(TAG_BOOLEAN, &[0x00]))),
            Ok(false)
        );
        // `SEQUENCE { pathLenConstraint INTEGER }` with `cA` still defaulted.
        assert_eq!(
            read_basic_constraints(&tlv(TAG_SEQUENCE, &tlv(TAG_INTEGER, &[0x01]))),
            Ok(false)
        );
        // `SEQUENCE { BOOLEAN TRUE, pathLenConstraint INTEGER }` is the only
        // form that reads as a CA, so the negatives above are not vacuous.
        assert_eq!(
            read_basic_constraints(&tlv(
                TAG_SEQUENCE,
                &[tlv(TAG_BOOLEAN, &[0xff]), tlv(TAG_INTEGER, &[0x01])].concat()
            )),
            Ok(true)
        );
        // Not a `SEQUENCE` at all, and a `SEQUENCE` with a field this reader
        // does not know: both malformed, never silently "not a CA".
        assert_eq!(
            read_basic_constraints(&tlv(TAG_SET, &tlv(TAG_BOOLEAN, &[0xff]))),
            Err(RootRejection::Malformed)
        );
        assert_eq!(
            read_basic_constraints(&tlv(TAG_SEQUENCE, &tlv(TAG_OCTET_STRING, &[0x00]))),
            Err(RootRejection::Malformed)
        );
        // Trailing bytes after the `SEQUENCE`: a value that is not exactly one
        // element, which is the shape a hostile bundle uses to append a second
        // object past a reader that stops at the first.
        let mut trailing = tlv(TAG_SEQUENCE, &tlv(TAG_BOOLEAN, &[0xff]));
        trailing.extend_from_slice(&tlv(TAG_BOOLEAN, &[0xff]));
        assert_eq!(
            read_basic_constraints(&trailing),
            Err(RootRejection::Malformed)
        );
        // A non-minimal boolean encoding: DER admits TRUE as exactly `0xff`.
        assert_eq!(
            read_basic_constraints(&tlv(TAG_SEQUENCE, &tlv(TAG_BOOLEAN, &[0x01]))),
            Err(RootRejection::Malformed)
        );
    }

    /// `keyCertSign` is bit 5, so a bit string too short to *hold* bit 5 cannot
    /// assert it. The boundary is pinned from both sides: a string ending one
    /// bit short must not report the usage, and one bit longer must.
    ///
    /// A set bit in the DER padding is malformed rather than a usage, so a
    /// string that would otherwise answer "yes" by reading padding is refused
    /// instead.
    ///
    /// **The length arm is covered but not load-bearing, and no test can make it
    /// so.** The `significant_bits <= KEY_CERT_SIGN_INDEX` guard is redundant
    /// with the padding check above it, and the redundancy is provable rather
    /// than incidental:
    ///
    /// - A bit string long enough to reach `significant_bits <= 5` with more
    ///   than one octet cannot exist: `significant_bits >= 8 * (len - 1)`, so
    ///   `len >= 2` already implies `significant_bits >= 8`.
    /// - At `len == 1` the guard fires only when `unused >= 3`, and the padding
    ///   mask `(1 << unused) - 1` then covers the `keyCertSign` bit, so a set
    ///   one is already `Malformed` before the guard is reached.
    ///
    /// So every input that reaches the guard answers "no" with or without it.
    /// Dropping it is a green mutation, and that is a property of the reader
    /// rather than a gap in this test. The guard is kept anyway: it is the
    /// statement of intent that the *length* is what bounds the read, and
    /// removing a correct safety net to make a mutation matrix tidier is the
    /// wrong trade. The claim is recorded here so the next reader does not
    /// mistake redundancy for coverage.
    #[test]
    fn key_usage_needs_a_long_enough_bit_string_and_zero_padding() {
        // BIT STRING contents are `<unused-bits> <octets...>`.
        let bit_string = |unused: u8, octets: &[u8]| {
            let mut contents = vec![unused];
            contents.extend_from_slice(octets);
            tlv(TAG_BIT_STRING, &contents)
        };

        // Five significant bits: the highest numbered bit is 4, so bit 5 is not
        // present and the answer is "no".
        assert_eq!(read_key_usage(&bit_string(3, &[0x00])), Ok(false));
        // Six significant bits: bit 5 is the last one, and it is set.
        assert_eq!(read_key_usage(&bit_string(2, &[0b0000_0100])), Ok(true));
        // The same length with the bit clear.
        assert_eq!(read_key_usage(&bit_string(2, &[0b0000_0000])), Ok(false));
        // Only a padding octet: no significant bits at all.
        assert_eq!(read_key_usage(&bit_string(7, &[0x00])), Ok(false));
        // No octets: holds no bits, so it permits nothing.
        assert_eq!(read_key_usage(&bit_string(0, &[])), Ok(false));
        // A set bit in the padding of an otherwise-answering string is malformed
        // rather than a usage: two readers could disagree about the same bytes.
        assert_eq!(
            read_key_usage(&bit_string(3, &[0b0000_0100])),
            Err(RootRejection::Malformed)
        );
        // More than seven unused bits, and a value that is not a BIT STRING.
        assert_eq!(
            read_key_usage(&bit_string(8, &[0x00])),
            Err(RootRejection::Malformed)
        );
        assert_eq!(
            read_key_usage(&tlv(TAG_OCTET_STRING, &[0x04])),
            Err(RootRejection::Malformed)
        );
    }

    /// A `Name` is walked to its last octet, and every level of the walk is
    /// strict.
    ///
    /// The walk is three deep — `RDNSequence` → `SET` → `SEQUENCE { OID, value }`
    /// — and each level can be wrong in a way the levels above cannot detect. A
    /// reader that stopped early, or that trusted a length, would accept a name
    /// no conforming verifier can match against, which is exactly the anchor
    /// this module is supposed to refuse. Each negative below breaks one level,
    /// and the positives show the walk is not refusing everything.
    #[test]
    fn a_name_is_walked_to_its_last_octet_or_refused() {
        // Well-formed: one RDN, one attribute, OID plus a value of any tag.
        assert_eq!(walk_name(&name(NAME_OID, b"anchor")), Ok(()));
        // An empty RDNSequence is a legal (if useless) name: nothing to walk,
        // nothing malformed.
        assert_eq!(walk_name(&tlv(TAG_SEQUENCE, &[])), Ok(()));
        // Two attributes in one RDN, and two RDNs, both walk.
        let two_attributes = tlv(
            TAG_SET,
            &[
                tlv(
                    TAG_SEQUENCE,
                    &[tlv(TAG_OID, NAME_OID), tlv(TAG_OCTET_STRING, b"a")].concat(),
                ),
                tlv(
                    TAG_SEQUENCE,
                    &[tlv(TAG_OID, NAME_OID), tlv(TAG_OCTET_STRING, b"b")].concat(),
                ),
            ]
            .concat(),
        );
        assert_eq!(
            walk_name(&tlv(TAG_SEQUENCE, &two_attributes)),
            Ok(()),
            "a multi-valued RDN is legal and must still be walked"
        );

        for (bytes, why) in [
            (tlv(TAG_SET, &[]), "the RDNSequence is not a SEQUENCE"),
            (
                tlv(TAG_SEQUENCE, &tlv(TAG_OCTET_STRING, b"")),
                "an RDN is not a SET",
            ),
            (
                tlv(TAG_SEQUENCE, &tlv(TAG_SET, &tlv(TAG_OCTET_STRING, b""))),
                "an attribute is not a SEQUENCE",
            ),
            (
                tlv(
                    TAG_SEQUENCE,
                    &tlv(TAG_SET, &tlv(TAG_SEQUENCE, &tlv(TAG_OCTET_STRING, b""))),
                ),
                "an attribute does not start with an OID",
            ),
            (
                // A third element after the OID and the value: the walk must
                // consume the attribute, not stop once it has what it needs.
                tlv(
                    TAG_SEQUENCE,
                    &tlv(
                        TAG_SET,
                        &tlv(
                            TAG_SEQUENCE,
                            &[
                                tlv(TAG_OID, NAME_OID),
                                tlv(TAG_OCTET_STRING, b"a"),
                                tlv(TAG_OCTET_STRING, b"b"),
                            ]
                            .concat(),
                        ),
                    ),
                ),
                "an attribute carries a third element",
            ),
            (
                // A value whose declared length runs past the attribute.
                tlv(
                    TAG_SEQUENCE,
                    &tlv(
                        TAG_SET,
                        &[tlv(TAG_OID, NAME_OID), vec![TAG_OCTET_STRING, 0x05]].concat(),
                    ),
                ),
                "an attribute value is truncated",
            ),
        ] {
            assert_eq!(
                walk_name(&bytes),
                Err(RootRejection::Malformed),
                "{why} must be refused"
            );
        }
    }

    #[test]
    fn a_ca_certificate_is_admitted_with_its_window() {
        let admitted =
            admit_root(&good_ca()).expect("a CA certificate with keyCertSign is admitted");
        assert_eq!(
            admitted.not_before(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800),
            "notBefore is read as UTC midnight on the certificate date"
        );
        assert!(admitted.is_valid_at(inside_window()));
        assert_eq!(
            admitted.not_after(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_800),
            "notAfter is read as UTC midnight on the certificate date"
        );
    }

    /// The window is `notBefore <= now < notAfter`, with no grace period at
    /// either end.
    ///
    /// Both boundaries are pinned from both sides: making `notAfter` inclusive,
    /// making `notBefore` strict, or widening the window all have to go red.
    #[test]
    fn validity_window_has_no_grace_period() {
        let admitted =
            admit_root(&good_ca()).expect("a CA certificate with keyCertSign is admitted");
        let not_before = WINDOW_FROM().unix_timestamp().unsigned_abs();
        let not_after = WINDOW_UNTIL().unix_timestamp().unsigned_abs();
        let at =
            |seconds: i64| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds.unsigned_abs());
        assert!(
            !admitted.is_valid_at(at(not_before as i64 - 1)),
            "before notBefore"
        );
        assert!(
            admitted.is_valid_at(at(not_before as i64)),
            "notBefore is inclusive"
        );
        assert!(
            !admitted.is_valid_at(at(not_after as i64)),
            "notAfter is exclusive"
        );
    }

    /// `basicConstraints` is required, and it has to say `CA=TRUE`.
    ///
    /// The two refusals are distinct reasons, so a caller can tell "not a CA"
    /// from "never claimed to be one".
    #[test]
    fn a_root_must_declare_itself_a_ca() {
        let absent = ca_der(IsCa::NoCa, vec![KeyUsagePurpose::KeyCertSign]);
        assert_eq!(admit_root(&absent), Err(RootRejection::NotCaConstrained));
        let explicit_false = ca_der(IsCa::ExplicitNoCa, vec![KeyUsagePurpose::KeyCertSign]);
        assert_eq!(admit_root(&explicit_false), Err(RootRejection::NotCa));
    }

    /// `keyUsage` is optional, but when present it has to allow certificate
    /// signing. Dropping `keyCertSign` from the policy, or ignoring `keyUsage`
    /// altogether, has to go red.
    #[test]
    fn key_usage_must_allow_certificate_signing_when_present() {
        let without = ca_der(
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature],
        );
        assert_eq!(admit_root(&without), Err(RootRejection::NoKeyCertSign));
        assert!(admit_root(&good_ca()).is_ok());
    }

    /// A window that does not contain now is read correctly and reported as
    /// such, whichever side it falls on.
    ///
    /// Dropping the window entirely, or comparing only one edge, has to go red.
    #[test]
    fn a_window_outside_now_is_reported_as_invalid() {
        let expired = ca_der_in(params(
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign],
            EXPIRED_FROM(),
            EXPIRED_UNTIL(),
        ));
        let admitted = admit_root(&expired).expect("a CA certificate with keyCertSign is admitted");
        assert!(
            !admitted.is_valid_at(inside_window()),
            "an expired anchor must not be valid now"
        );
        assert!(
            admitted.is_valid_at(SystemTime::UNIX_EPOCH + Duration::from_secs(220_924_800)),
            "the same anchor was valid at 1977-01-01, inside its own window"
        );

        let future = ca_der_in(params(
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![KeyUsagePurpose::KeyCertSign],
            FUTURE_FROM(),
            FUTURE_UNTIL(),
        ));
        assert!(
            !admit_root(&future)
                .expect("a CA certificate with keyCertSign is admitted")
                .is_valid_at(inside_window())
        );
    }

    /// Bytes that are not a certificate are refused, and refused the same way
    /// whatever they contain.
    #[test]
    fn malformed_input_is_refused_and_never_panics() {
        for input in [
            Vec::new(),
            b"not a certificate".to_vec(),
            b"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n".to_vec(),
            vec![0x30, 0x00],
            // Indefinite length: not valid DER.
            vec![0x30, 0x80, 0x00, 0x00],
            // A long-form length wider than a `usize` can hold.
            vec![0x30, 0x88, 0x01, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(admit_root(&input), Err(RootRejection::Malformed));
        }
    }

    /// Every prefix of a real certificate is refused, and none of them panics.
    ///
    /// This is the totality property the reader's strictness exists to provide:
    /// a truncated certificate from an unreadable file, a partial write, or a
    /// hostile bundle must produce a typed refusal, never a panic and never a
    /// partial parse accepted as a whole.
    #[test]
    fn no_truncation_of_a_real_certificate_is_accepted() {
        let certificate = good_ca();
        let cert_len = certificate.len();
        for cut in 0..cert_len {
            assert!(
                admit_root(&certificate[..cut]).is_err(),
                "a {cut}-byte prefix of a {cert_len}-byte certificate must be refused"
            );
        }
        assert!(admit_root(&certificate).is_ok());
    }

    /// Flipping any single bit of a real certificate either leaves it admitted
    /// or turns it into a typed refusal; it never panics.
    #[test]
    fn no_single_bit_corruption_panics() {
        let certificate = good_ca();
        for index in 0..certificate.len() {
            for bit in 0..8u8 {
                let mut corrupted = certificate.clone();
                corrupted[index] ^= 1 << bit;
                let _ = admit_root(&corrupted);
            }
        }
    }

    /// A DER length is read at exactly one width, or not at all.
    ///
    /// A long-form length with a leading zero byte is a second spelling of a
    /// short-form length. Accepting it means the same certificate has two
    /// encodings and two readers can disagree about where a value ends, which is
    /// the shape a hostile bundle uses to smuggle a second object past a lenient
    /// reader. So the non-minimal form is refused, as are the indefinite form and
    /// a long form wider than a `usize`.
    #[test]
    fn a_length_is_read_at_one_width_or_not_at_all() {
        // `read_length` takes the bytes after the tag, so the first byte here is
        // the length octet and the rest is the value.
        let short = [0x03u8, b'a', b'b', b'c'];
        assert_eq!(read_length(&short), Some((3, &short[1..])));
        // The equivalent minimal long form reads the same.
        let long = [0x81u8, 0x03, b'a', b'b', b'c'];
        assert_eq!(read_length(&long), Some((3, &long[2..])));
        // The indefinite form is not valid DER.
        let indefinite = [0x80u8, 0x00, 0x00];
        assert_eq!(read_length(&indefinite), None);
        // A leading zero byte makes the long form non-minimal, so the same
        // length has to be refused rather than read at a second width.
        let non_minimal = [0x82u8, 0x00, 0x03, b'a'];
        assert_eq!(read_length(&non_minimal), None);
        // A long form wider than a `usize` can address.
        let too_wide = [0x89u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(read_length(&too_wide), None);
        // A length wider than the remaining input is reported as read and then
        // refused by the caller, never silently shortened.
        let overrunning = [0x05u8, b'a'];
        assert_eq!(read_length(&overrunning), Some((5, &overrunning[1..])));
    }

    /// Trailing bytes after the certificate make it malformed rather than
    /// "a certificate with junk after it", which is the shape a hostile bundle
    /// would use to smuggle a second object past a lenient reader.
    #[test]
    fn trailing_bytes_after_a_certificate_are_refused() {
        let mut certificate = good_ca();
        certificate.push(0x00);
        assert_eq!(admit_root(&certificate), Err(RootRejection::Malformed));
    }

    /// The civil-date conversion is exact at the points a validity window can
    /// land on, including both leap-year rules and the epoch itself.
    #[test]
    fn civil_dates_convert_exactly() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(1970, 1, 2), Some(1));
        // 2000 is a leap year (divisible by 400); 1900 is not.
        // 30 years of 365 days plus the 7 leap days: 10957 to 2000-01-01.
        assert_eq!(days_from_civil(2000, 1, 1), Some(10_957));
        // 2000 is a leap year (divisible by 400), so March gains 29 days.
        assert_eq!(days_from_civil(2000, 3, 1), Some(10_957 + 31 + 29));
        // 1900 is not (divisible by 100 but not 400), so February has 28.
        assert_eq!(days_from_civil(1900, 3, 1), Some(-25_567 + 31 + 28));
        // 24 years from 2000-01-01 with 6 leap days.
        assert_eq!(days_from_civil(2024, 1, 1), Some(10_957 + 24 * 365 + 6));
        assert_eq!(
            days_from_civil(2024, 3, 1),
            Some(10_957 + 24 * 365 + 6 + 31 + 29)
        );
        // A date the calendar does not have is refused, never rolled over.
        assert_eq!(days_from_civil(2023, 2, 29), None);
        assert_eq!(days_from_civil(2023, 13, 1), None);
        assert_eq!(days_from_civil(2023, 4, 31), None);
        assert_eq!(days_from_civil(2023, 1, 0), None);
    }

    /// The signature-algorithm policy is SHA-256 and stronger, and SHA-1 with
    /// RSA is recognized only so it can be refused.
    #[test]
    fn signature_algorithm_policy_excludes_sha1() {
        // SHA-256 and stronger with RSA, plus Ed25519.
        for oid in [
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b][..],
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c][..],
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d][..],
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02][..],
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03][..],
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04][..],
            OID_ED25519,
        ] {
            assert!(
                ADMITTED_SIGNATURE_ALGORITHMS.contains(&oid),
                "{oid:02x?} must be admitted"
            );
        }
        // SHA-1 with RSA is the one named in RFC 5280 that is refused.
        assert!(!ADMITTED_SIGNATURE_ALGORITHMS.contains(&OID_SHA1_RSA));
        // The PSS hash OIDs are not signature OIDs; they gate PSS parameters.
        assert!(!ADMITTED_SIGNATURE_ALGORITHMS.contains(&OID_SHA256));
    }

    /// The admitted signature algorithms are exactly the set the module
    /// documents, so a new entry cannot be added without a decision.
    #[test]
    fn admitted_signature_algorithm_set_is_exactly_the_documented_one() {
        assert_eq!(ADMITTED_SIGNATURE_ALGORITHMS.len(), 8);
        for oid in ADMITTED_SIGNATURE_ALGORITHMS {
            assert!(!oid.is_empty(), "every admitted OID has content octets");
            assert_ne!(oid, OID_SHA1_RSA);
        }
    }
}
