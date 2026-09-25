//! TLS trust and client-identity provider (CTX-0021, issues #21 and #22).
//!
//! One vocabulary for both transports. [`TlsProvider`] is built once from a
//! [`TlsConfig`] and produces the single `rustls` configuration each backend
//! consumes, so HTTP and WebSocket share one trust model and one identity
//! selection rule by construction rather than by convention.
//!
//! # Trust model
//!
//! **Additive, and only additive.** A supplied CA bundle *adds* anchors to the
//! platform's native roots. It never replaces, shadows, or disables a native
//! root, and this module defines no custom-only mode — so **supplying a bundle
//! does not restrict native trust**. An operator who expects a bundle to
//! narrow what is trusted is mistaken: a host the platform trusts stays
//! trusted. Narrowing native trust would need a new decision recording the
//! narrower model and its compatibility impact.
//!
//! Native roots come from `rustls-platform-verifier`, which loads the platform
//! store and *adds* the supplied certificates to it, forwarding parse errors to
//! this module. Its own emptiness check cannot be relied on for the second half
//! of the model: in 0.7.0 the extra roots enter the store *before* the platform
//! store is read, so a platform store that yields nothing raises no error once a
//! bundle is configured and would leave a verifier trusting the custom roots
//! alone. [`provider`] therefore proves the native load separately and refuses
//! with [`TlsFailure::NativeRootsUnavailable`], so there is no code path here in
//! which a custom root is trusted while the native store failed to load. That
//! refusal is what makes "additive only" mechanical rather than a convention.
//!
//! **No partial fallback.** An empty path, an empty byte string, an unreadable
//! path, a bundle with no certificate, a malformed certificate, a
//! non-certificate PEM object, or a certificate that is not usable as a trust
//! anchor fails the whole load. The provider never skips the bad entry, never
//! falls back to another source, and never continues with a partial trust set.
//!
//! **Parse once at construction.** A bundle path is read and parsed once here,
//! not per handshake, and a file source is read only while the provider is
//! built. **No ambient discovery:** a CA source is whatever the caller passed —
//! never an environment variable, a default filesystem location, or a
//! platform-specific search path.
//!
//! **Admitted roots are anchors, never leaf exemptions.** Each supplied
//! certificate must carry `basicConstraints` with `CA=TRUE` and, when
//! `keyUsage` is present, `keyCertSign`; it must use a signature algorithm and
//! a public-key algorithm and key size this crate admits; and its subject and
//! issuer names must parse (see [`x509`]). A peer leaf is still accepted only
//! when its chain verifies — issuer, signature, intermediates, path length, and
//! name constraints — to a native root or to one of these anchors, and passes
//! the backend's SAN-based name check. That verification is `rustls-webpki`'s,
//! not this module's, and no unavailable required check downgrades trust.
//!
//! **Validity twice.** A root is admitted only when `notBefore <= now <
//! notAfter`, and the same window is re-checked before every new TLS
//! destination ([`TlsProvider::select`]). There is no grace period and no
//! stale-cache reuse. A pooled connection that is reused performs no new
//! handshake and so consumes no root again; the re-check is on the path that
//! starts a handshake, which is the path that reads the store.
//!
//! # Client identity
//!
//! Off by default, and indivisible: one identity is a certificate chain *and*
//! its matching private key, both from an explicit path or inline bytes. There
//! is no default identity, no environment lookup, no directory search, and no
//! URL source.
//!
//! Selection is exact and case-insensitive on the canonical host of the final
//! TLS target after URL parsing and IDNA normalization ([`canonical_host`]).
//! No wildcard, no suffix match, no default: a host with no exact rule receives
//! no client certificate, and an identity configured for one host is never
//! selected because another host is a parent, a subdomain, a redirect target,
//! or shares a suffix. Two rules naming the same host are refused rather than
//! resolved.
//!
//! Selection happens for **every new TLS destination**. The HTTP backend
//! resolves a client per redirect hop, so a redirect reselects from its own
//! target; the WebSocket handshake resolves one per handshake. The proxy
//! authority is never the selector. Cross-host reuse is structurally
//! impossible: each identity gets its own client with its own pool, and a pool
//! entry is only ever reused for the origin it was opened for, so a connection
//! authenticated with one identity cannot be presented to a different host.
//!
//! A rule selects an identity; it never waives a check. The selected
//! certificate still has to pass SAN-based name verification, chain building,
//! validity, and key use for the target it is presented to, and a load, parse,
//! or pairing failure is a typed [`TlsFailure`] at construction — never a
//! silent downgrade of that connection to "no client certificate".
//!
//! # Secret handling
//!
//! The policy vocabulary ([`bitty_network_api::TlsConfig`] and everything it
//! reaches) uses hand-written redacting `Debug`, hand-written zeroing drops,
//! and derives no serialization trait. This module adds no derived `Debug` to
//! anything that holds key material: [`TlsProvider`]'s own `Debug` is
//! hand-written and reports configuration shape and rule hosts only.
//!
//! Retained copies of a key are minimized rather than eliminated. An inline
//! source is parsed in place out of the policy's own buffer, and a file source
//! is read into a buffer that is zeroized ([`zeroize`]) as soon as the key has
//! been parsed out of it, so this crate keeps no second copy. The copy that
//! remains is the one inside the `rustls` configuration, which owns the parsed
//! key for as long as the configuration lives: `rustls` 0.23.45 zeroizes its
//! record buffers, ciphers, and HMACs, but it does **not** wipe a client's
//! signing key when a configuration is dropped. That is a property of the
//! pinned stack rather than of this policy, it cannot be tightened from here
//! without replacing the provider, and it is recorded here rather than papered
//! over.
//!
//! [`PemSource`]: bitty_network_api::PemSource

#[cfg(any(feature = "http", feature = "websocket"))]
mod provider;
#[cfg(any(feature = "http", feature = "websocket"))]
pub use provider::{TlsProvider, TlsSelection, TlsTransport, canonical_host};

#[cfg(any(feature = "http", feature = "websocket"))]
mod x509;
