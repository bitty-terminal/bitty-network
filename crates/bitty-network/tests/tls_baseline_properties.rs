//! Property pins for the current-state claims of `docs/decisions/21-tls-policy.md`.
//!
//! **Re-verified by CTX-0021 (issues #21 and #22).** Two pins changed state
//! when the TLS provider landed, and both changes are the record's own
//! designed-for outcome rather than drift:
//!
//! - `tls_module_is_no_longer_a_sealed_marker` replaces
//!   `tls_module_remains_a_sealed_marker`. The record's foundational
//!   current-state claim ("`src/tls.rs` is only a sealed marker: it has no
//!   policy type, certificate data, crypto, or I/O") is now false, which is
//!   the point of CTX-0021. The replacement pin states the new current state
//!   and, more usefully, pins the *properties* the record's contracts rest on
//!   so the next change that weakens one is loud.
//! - `proxy_gate_is_consulted_before_any_environment_read` replaces
//!   `proxy_gate_is_a_predicate_without_construction_wiring`. That pin existed
//!   to fail "the day the gap closes"; the gap closed when CTX-0034 landed the
//!   call-site wiring, so the pin now asserts the wired state instead, and
//!   strengthens it to the ordering property: the gate is consulted *before*
//!   either environment reader runs, not merely somewhere in `new`.
//!
//! The record itself is not edited here: it is owned by the decision lane, and
//! this suite reports which of its sentences no longer describe the code.
//!
//! Decision 21 fixes a future TLS-provider contract but also states what the
//! code looks like at the base it was verified against. Those current-state
//! statements used to be justified by a per-control table mapping each
//! control to a providing commit, which no one could keep true: the commit
//! graph moves with every merge and rebase, so the table was wrong again by
//! the next commit. It also went stale in the other direction, because a
//! table cannot be checked by a machine.
//!
//! This file is the replacement. Every property the record's current-state
//! section relies on is pinned here as an assertion, so a change that breaks
//! the property fails the suite instead of quietly invalidating the record.
//! The record keeps one base pin and the rule that its current-state claims
//! are scoped to that base. This suite is not what makes a moved base loud,
//! and it does not claim to be: the pins read the working tree through
//! `include_str!` and never observe a commit, so moving the base ref on its
//! own, without merging it here, leaves every pin green. The two cases are
//! the ones the record states. A base move merged here that *changes* a
//! pinned property turns this suite red, and one that leaves every pinned
//! property intact leaves it green. Re-verification after a base move is
//! therefore a human obligation that no assertion in this file discharges.
//!
//! Two deliberate asymmetries:
//!
//! - Properties that name a commit are *absent by design*. What is pinned is
//!   the behavior or manifest fact the record depends on, never the SHA that
//!   once provided it, so a merge or rebase cannot invalidate the pins. It can
//!   still invalidate a current-state sentence, because a sentence no pin
//!   backs is exactly what a merge can move; that case is the obligation the
//!   record leaves with a human, not one this suite can close.
//! - Two properties pin a *gap* (the `proxy` gate predicate is merged but its
//!   `HttpNetworkService::new` call-site wiring is not). Pinning a gap means
//!   the assertion fails the day the gap closes, which is the intended
//!   signal: the record must be re-verified, not silently left behind.
//!
//! Everything here is loopback-only or filesystem-only. No test in this file
//! opens an outbound socket or touches the network.

#![forbid(unsafe_code)]

use std::time::Duration;

use bitty_network::{
    HttpMethod, NetworkCapability, NetworkError, NetworkService, OfflineNetworkService, Request,
    WebSocketRequest,
};
use bitty_network_api::TlsFailure;

/// Implementation manifest: the pinned TLS stacks and their features.
const IMPL_MANIFEST: &str = include_str!("../Cargo.toml");
/// Vocabulary manifest: must stay implementation-free.
const API_MANIFEST: &str = include_str!("../../bitty-network-api/Cargo.toml");
/// Resolved dependency graph: which root store the TLS stacks actually pull.
const WORKSPACE_LOCK: &str = include_str!("../../../Cargo.lock");
/// The TLS provider module and the two files under it.
const TLS_SOURCE: &str = include_str!("../src/tls.rs");
/// The provider implementation (trust composition, identity loading, selection).
const TLS_PROVIDER_SOURCE: &str = include_str!("../src/tls/provider.rs");
/// The X.509 attribute reader that admits a trust anchor.
const TLS_X509_SOURCE: &str = include_str!("../src/tls/x509.rs");
/// The WebSocket handshake path, which selects a TLS configuration per handshake.
const WEBSOCKET_SOURCE: &str = include_str!("../src/websocket.rs");
/// The HTTP backend source (feature-gated; still readable without it).
const HTTP_SOURCE: &str = include_str!("../src/http.rs");
/// The proxy gate policy module.
const PROXY_SOURCE: &str = include_str!("../src/proxy.rs");
/// The vocabulary crate the record's contracts are defined in.
const API_SOURCE: &str = include_str!("../../bitty-network-api/src/lib.rs");

/// Drop Rust comments so a property scan reads code, not prose.
///
/// Every claim below is a claim about code. Scanning the raw text instead
/// would make the module docs satisfy the pins they are supposed to be
/// checked against (the `tls.rs` docs mention certificates and crypto in
/// order to say the module has neither), so the scan must not see them.
///
/// Line-based and whole-line only: a line whose first non-whitespace characters
/// open a comment is emptied, `/* */` carries across lines, and the remaining
/// code keeps its original line numbering so a failure names the right line.
/// Because it is whole-line only, it has one limit in each direction, and both
/// are stated here rather than assumed:
///
/// - **Over-stripping** can only remove text, so it can turn a `require` into a
///   failure and a `forbid` into a silent pass. It needs a line that opens with
///   a string or char literal whose contents begin `//` or `/*`, or a
///   continuation line inside a multi-line string literal that itself begins
///   with one of those. No line in any of the four sources scanned below is
///   shaped like that.
/// - **Under-stripping** keeps a `//` comment that trails code on its line.
///   Nothing is hidden by that, but something can be faked: a trailing comment
///   quoting a needle verbatim, or carrying a `#[derive(`, would satisfy a
///   check reading it. Every needle checked in stripped source below is a
///   code-shaped token, and no line in any of those four sources carries a
///   trailing comment, so no pin here is reading prose today. A source that
///   grows one must have this helper taught about it before the pin it feeds
///   can be trusted.
fn code_only(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut in_block_comment = false;
    for line in source.lines() {
        let trimmed = line.trim_start();
        let code = if in_block_comment {
            match trimmed.find("*/") {
                Some(end) => {
                    in_block_comment = false;
                    &trimmed[end + 2..]
                }
                None => "",
            }
        } else if let Some(rest) = trimmed.strip_prefix("/*") {
            in_block_comment = true;
            match rest.find("*/") {
                Some(end) => &rest[end + 2..],
                None => "",
            }
        } else if trimmed.starts_with("//") {
            ""
        } else {
            line
        };
        out.push_str(code);
        out.push('\n');
    }
    out
}

/// Trimmed first line of a manifest starting with `prefix`, if any.
fn manifest_line<'a>(manifest: &'a str, prefix: &str) -> &'a str {
    manifest
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .unwrap_or_else(|| panic!("{prefix} dependency is absent from the manifest"))
}

/// The `[[package]]` block of one crate in the resolved lockfile.
fn lock_package<'a>(lock: &'a str, name: &str) -> Option<&'a str> {
    let header = format!("name = \"{name}\"");
    let start = lock.find(&header)? + header.len();
    let rest = &lock[start..];
    let end = rest.find("[[package]]").unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The declaration of one item: its leading attribute run plus its body, from
/// the attribute directly above `header` to the line closing its brace.
///
/// Comments are stripped first, so prose inside the window can never satisfy a
/// `require`. All three properties pinned through this helper — the declared
/// failure categories, their per-category `Display` arms, and the absence of
/// `env_proxy_enabled` in `HttpNetworkService::new` — are claims about code, and
/// a doc comment naming a variant or a function would otherwise pass for one.
///
/// The window opens at the *attribute run*, not at the `header` token, because
/// the properties that only an attribute can violate sit above the item they
/// apply to. `#[non_exhaustive]` on the failure taxonomy is the load-bearing
/// one: a window starting at `pub enum NetworkError` could not see it, which
/// would leave that assertion permanently green and therefore worthless.
///
/// The run therefore only reaches an attribute that stays contiguous with the
/// item, and the formatter does not guarantee that: `rustfmt` keeps a blank
/// line or a comment between an attribute and the item it applies to, and
/// either one ends [`attribute_run_start`]'s run. That would put the attribute
/// outside the window and turn the `non_exhaustive` pin green on a taxonomy
/// that is no longer closed, so the pin holds for the shapes rustfmt emits
/// today and a source that separates the two must have this helper taught
/// about it before that pin can be trusted.
fn function_body(source: &str, header: &str) -> String {
    let stripped = code_only(source);
    let header_at = stripped.find(header).unwrap_or_else(|| {
        panic!("`{header}` is absent, so the pinned property cannot be checked");
    });
    let declaration = &stripped[attribute_run_start(&stripped, header_at)..];
    let end = declaration
        .find("\n}")
        .unwrap_or_else(|| panic!("`{header}` has no closing brace"));
    declaration[..end].to_owned()
}

/// Byte offset where the contiguous run of `#[..]` attribute lines directly
/// above `offset` begins.
///
/// Only attribute lines are absorbed, and the run ends at the first line above
/// the item that is not one — a doc comment has already been emptied by
/// [`code_only`], so it ends the run. A wrapped attribute (`#[cfg_attr(` on one
/// line, `)]` on another) is not part of the run; no property pinned through
/// [`function_body`] depends on one.
fn attribute_run_start(source: &str, offset: usize) -> usize {
    let mut run_start = offset;
    let mut below = offset;
    // `below` starts inside the header's own line, so the first `rfind` lands
    // on the newline that closes the line above it.
    while let Some(newline) = source[..below].rfind('\n') {
        let start = match source[..newline].rfind('\n') {
            Some(index) => index + 1,
            None => 0,
        };
        if !source[start..newline].trim_start().starts_with("#[") {
            break;
        }
        run_start = start;
        below = start;
    }
    run_start
}

/// Every macro named by a `#[derive(..)]` attribute, with its source line.
///
/// A `derive(Serialize)` substring test is not enough: the usual shape is
/// `#[derive(Clone, Serialize, Deserialize)]`, where the bare substring
/// never appears. Splitting the list is what makes the check able to fail.
///
/// The list is read as one span from `#[derive(` to its closing paren rather
/// than one line at a time, because rustfmt wraps a long list and a wrapped
/// list is the same declaration:
///
/// ```text
/// #[derive(
///     Debug,
///     Serialize,
/// )]
/// ```
///
/// Scanning line by line would skip a wrapped list whole, which is one of the
/// two ways this check can miss a forbidden trait. The other is the `break`
/// below: a `#[derive(` with no closing paren anywhere after it abandons the
/// rest of the file, so every later list goes unread. That path fails open and
/// silently rather than loudly, so a source that grows an unterminated
/// `#[derive(` must have this helper taught about it before the pin it feeds
/// can be trusted.
fn derived_traits(source: &str) -> Vec<(usize, String)> {
    const OPEN: &str = "#[derive(";
    let stripped = code_only(source);
    let mut derived = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = stripped[cursor..].find(OPEN) {
        let start = cursor + offset + OPEN.len();
        let Some(span) = stripped[start..].find(')') else {
            break;
        };
        let end = start + span;
        let line = stripped[..start].matches('\n').count() + 1;
        for item in stripped[start..end].split(',') {
            let item = item.trim();
            if !item.is_empty() {
                derived.push((line, item.to_owned()));
            }
        }
        cursor = end;
    }
    derived
}

/// Assert `haystack` carries `needle`, naming the property in the failure.
fn require(haystack: &str, needle: &str, property: &str) {
    assert!(
        haystack.contains(needle),
        "{property}: expected to find `{needle}`"
    );
}

/// Collapse every run of whitespace to one space, so a property can name a
/// multi-line expression without the pin going red on a `rustfmt` line break.
///
/// A source pin that has to reproduce the formatter's wrapping is a pin that
/// will fail on a reformat rather than on a behavior change, which trains
/// everyone to re-run it without reading it.
fn unwrapped(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Assert `unwrapped(haystack)` carries `unwrapped(needle)`.
fn require_unwrapped(haystack: &str, needle: &str, property: &str) {
    let haystack = unwrapped(haystack);
    let needle = unwrapped(needle);
    assert!(
        haystack.contains(&needle),
        "{property}: expected to find `{needle}`"
    );
}

/// Assert `haystack` does not carry `needle`, naming the property.
fn forbid(haystack: &str, needle: &str, property: &str) {
    assert!(
        !haystack.contains(needle),
        "{property}: `{needle}` must not appear"
    );
}

/// How many times `needle` occurs in `haystack`.
///
/// A name-based check cannot carry this property on its own: a custom-only mode
/// spelled anything other than the one name a pin happens to forbid would walk
/// straight past it. Counting the *composition sites* is what makes the property
/// hold whatever the mode is called.
fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

// --- Trust model: the HTTP native-root path -----------------------------
//
// Round 3 found the record attributing HTTP native-root behavior to the
// `tls.rs` marker and to the WebSocket-only path, with no entry for the HTTP
// path at all. The real provider is the reqwest dependency itself, so the
// property is pinned where it lives: the manifest and the resolved graph.

/// The HTTP backend gets native roots from reqwest's rustls stack, with
/// default features off so no ambient TLS behavior is inherited.
#[test]
fn http_backend_pins_native_roots_through_rustls() {
    let dependency = manifest_line(IMPL_MANIFEST, "reqwest = ");
    require(
        dependency,
        "version = \"=0.13.5\"",
        "the HTTP TLS stack stays pinned to one exact version",
    );
    require(
        dependency,
        "default-features = false",
        "reqwest default features stay off so no ambient TLS behavior is inherited",
    );
    require(
        dependency,
        "features = [\"blocking\", \"rustls\"]",
        "the HTTP backend adds only `blocking` and `rustls`; a new feature (for \
         example a bundled root store) must be a deliberate, reviewable edit",
    );
}

/// The WebSocket backend pins the same native-root approach, so HTTP and
/// WebSocket parity in the record rests on two real paths, not one.
#[test]
fn websocket_backend_pins_native_roots_through_rustls() {
    let dependency = manifest_line(IMPL_MANIFEST, "tungstenite = ");
    require(
        dependency,
        "version = \"=0.30.0\"",
        "the WebSocket TLS stack stays pinned to one exact version",
    );
    require(
        dependency,
        "default-features = false",
        "tungstenite default features stay off",
    );
    require(
        dependency,
        "features = [\"handshake\", \"rustls-tls-native-roots\"]",
        "the WebSocket handshake keeps the native-roots TLS feature; switching to a \
         bundled store must be a deliberate, reviewable edit",
    );
}

/// The resolved graph wires reqwest to the platform verifier over the platform
/// root store, and no bundled root store is in the graph at all.
///
/// The absence half is the load-bearing part. `rustls-platform-verifier`
/// reaches a Mozilla CA bundle through `webpki-root-certs`, but only as a
/// `wasm32`-target dependency and a dev-dependency, never as a desktop trust
/// source. The crate that *would* change the trust model is `webpki-roots`,
/// and its absence is pinned here: if a future change adds it, the record's
/// "native roots as the backends use them" statement is no longer true and
/// the suite must say so.
#[test]
fn resolved_graph_has_native_roots_and_no_bundle_root_store() {
    for provider in ["rustls", "rustls-native-certs", "rustls-platform-verifier"] {
        require(
            WORKSPACE_LOCK,
            &format!("name = \"{provider}\""),
            "the native-root providers stay in the resolved graph",
        );
    }
    forbid(
        WORKSPACE_LOCK,
        "name = \"webpki-roots\"",
        "no bundled root store enters the graph; native roots come from the platform",
    );
    let reqwest = lock_package(WORKSPACE_LOCK, "reqwest").expect("reqwest is locked");
    require(
        reqwest,
        "\"rustls-platform-verifier\"",
        "reqwest itself depends on the platform verifier, so the trust path is wired, \
         not merely present in the graph",
    );
    forbid(
        reqwest,
        "\"webpki-roots\"",
        "reqwest must not depend on a bundled root store",
    );
}

// --- The sealed marker ----------------------------------------------------

/// The record's foundational current-state claim is now false, and the new
/// current state is pinned in its place.
///
/// The old pin asserted that `src/tls.rs` was four lines of code. CTX-0021
/// makes that claim false on purpose, so what is pinned now is the set of
/// properties the record's *contracts* rest on, which is what a later change
/// could actually weaken:
///
/// - the provider is the only place a root set or a client identity is built;
/// - the trust set comes from the additive platform verifier, so there is no
///   code path that could replace or disable native roots;
/// - no CA source is discovered from the environment or a default location;
/// - a key source is an explicit path or inline bytes, never a URL;
/// - a key-bearing type derives neither `Debug` nor a serialization trait.
#[test]
fn tls_module_is_no_longer_a_sealed_marker() {
    // The marker type is gone, so nothing can still be a zero-sized stand-in
    // for the policy.
    forbid(
        &code_only(TLS_SOURCE),
        "pub struct Tls {",
        "the zero-sized `Tls` marker is gone; the policy type replaced it",
    );
    require(
        &code_only(TLS_SOURCE),
        "pub use provider::",
        "the module re-exports the provider, so it is reachable vocabulary",
    );
    let provider = code_only(TLS_PROVIDER_SOURCE);
    for needle in [
        "pub struct TlsProvider",
        "pub fn build(",
        "pub fn select(",
        "pub fn canonical_host(",
    ] {
        require(&provider, needle, "the provider carries the policy surface");
    }

    // The trust set has exactly one source, and it is the additive one.
    require(
        &provider,
        "Verifier::new_with_extra_roots(",
        "custom roots are ADDED to the platform store, which is the whole \
         additive guarantee",
    );
    for forbidden in [
        "RootCertStore",
        "webpki",
        "add_parsable_certificates",
        "with_native_roots",
    ] {
        forbid(
            &provider,
            forbidden,
            "no second root source exists, so native roots can never be \
             replaced, shadowed, or disabled by a bundle",
        );
    }
    // A custom-only mode is the one addition the record defers to a future
    // decision, so it is pinned by the *shape* of the composition rather than by
    // a name. There is exactly one site that builds a trust set from the supplied
    // roots, it is the additive one, and the only other verifier this crate
    // builds is the independent read that proves the platform store loaded. A
    // second composition site is a custom-only mode whatever it is called, and a
    // caller-reachable flag that skips the probe is one too, so both spellings
    // are named as well as counted.
    assert_eq!(
        occurrences(&provider, "Verifier::new_with_extra_roots("),
        1,
        "exactly one site may compose a trust set from supplied roots; a second one is a \
         custom-only mode, which needs a new decision and a security review"
    );
    assert_eq!(
        occurrences(&provider, "Verifier::new("),
        1,
        "the platform store is read exactly once, by the probe that proves it loaded"
    );
    for forbidden in [
        "custom_only",
        "supplied_roots_only",
        "without_native",
        "no_native",
        "skip_native",
        "ignore_native",
        "replace_roots",
        "disable_native",
    ] {
        forbid(
            &provider,
            forbidden,
            "there is no custom-only mode and no way to skip the native load; adding one \
             needs a new decision",
        );
    }
    // The probe cannot be turned off by configuration either: the only thing
    // that varies it is whether custom roots were supplied at all.
    assert_eq!(
        occurrences(&provider, "native_roots_loadable"),
        4,
        "the probe is defined, taken as a parameter, and called once on each of the two \
         paths that reach it; a caller-supplied switch in that chain would be a custom-only \
         mode"
    );

    // No ambient discovery: a source is whatever the caller passed.
    for source in [TLS_PROVIDER_SOURCE, TLS_X509_SOURCE] {
        let code = code_only(source);
        for forbidden in ["env::var", "var_os", "SSL_CERT_FILE", "CURL_CA_BUNDLE"] {
            forbid(
                &code,
                forbidden,
                "no CA source is discovered from the environment or a default \
                 filesystem location",
            );
        }
    }

    // A key source is a path or inline bytes; a URL is not a source.
    forbid(
        &code_only(include_str!("../../bitty-network-api/src/lib.rs")),
        "PemSource::Url",
        "a key or certificate source is never a fetched URL",
    );
}

/// The provider is reached from both transports, and each one resolves it per
/// destination rather than once for the whole service.
#[cfg(any(feature = "http", feature = "websocket"))]
#[test]
fn both_transports_resolve_the_provider_per_destination() {
    let http = code_only(HTTP_SOURCE);
    require(
        &http,
        "crate::tls::{TlsProvider, TlsTransport}",
        "the HTTP backend consumes the shared provider",
    );
    require_unwrapped(
        &function_body(&http, "fn client_for("),
        ".provider .select(TlsTransport::Http, host)",
        "the HTTP client for a hop is chosen from that hop's own host, so a \
         redirect reselects from its target",
    );
    // The proxy decision and the identity decision are separate reads of `host`;
    // the proxy URL is never the identity selector.
    let selection = unwrapped(&function_body(&http, "fn client_for("));
    let proxy_arm = selection.find("Some(_) => &self.egress.proxied");
    let identity_read = selection.find("select(TlsTransport::Http, host)");
    assert!(
        proxy_arm.is_some() && identity_read.is_some() && identity_read < proxy_arm,
        "the identity is selected from the request host before the proxy route \
         is consulted, so the proxy authority can never be the selector"
    );

    let websocket = code_only(WEBSOCKET_SOURCE);
    require_unwrapped(
        &function_body(&websocket, "pub(crate) fn connect("),
        "TlsTransport::WebSocket, &target.host",
        "the WebSocket handshake selects from its own target host",
    );
    require(
        &websocket,
        "tungstenite::Connector::Rustls",
        "the selected configuration reaches the handshake through the connector",
    );
}

// --- Capability-first and typed-error contracts ---------------------------

/// The capability gate is deny-all, exact-match, and fail-closed, in the
/// order the record relies on: host, then port, then method.
#[test]
fn capability_gate_is_deny_all_exact_and_fail_closed() {
    let offline = NetworkCapability::offline();
    assert!(offline.is_offline());
    assert_eq!(offline.check("example.com"), Err(NetworkError::Offline));

    let allowed = NetworkCapability::offline().with_domain("Example.COM.");
    assert!(allowed.allows("example.com"));
    assert!(
        !allowed.allows("sub.example.com"),
        "an exact-domain grant must not cover a subdomain"
    );
    assert_eq!(
        allowed.check("other.example"),
        Err(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
    assert_eq!(
        allowed.check("*.example.com"),
        Err(NetworkError::Denied {
            domain: "*.example.com".to_owned()
        }),
        "no wildcard grant exists"
    );

    let capped = allowed
        .clone()
        .with_domain_ports("example.com", [443])
        .restrict_methods([HttpMethod::Get]);
    assert_eq!(
        capped.check_request(&Request::get("https://example.com/")),
        Ok(())
    );
    assert_eq!(
        capped.check_request(&Request::get("http://example.com:8080/")),
        Err(NetworkError::Denied {
            domain: "example.com".to_owned()
        }),
        "an unlisted port is denied"
    );
    assert_eq!(
        capped.check_request(&Request::post("https://example.com/", vec![1])),
        Err(NetworkError::Denied {
            domain: "example.com".to_owned()
        }),
        "an unlisted method is denied"
    );
    assert_eq!(
        capped.check_request(&Request::get("https://other.example/")),
        Err(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
    assert_eq!(
        capped.check_request(&Request::get("example.com")),
        Err(NetworkError::Denied {
            domain: "example.com".to_owned()
        }),
        "a request with no determinable port is denied fail closed"
    );
    assert_eq!(
        NetworkCapability::offline().check_request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline),
        "deny-all is distinguishable from an allowlist miss"
    );

    assert_eq!(
        capped.check_handshake(&WebSocketRequest::new("wss://example.com/socket")),
        Ok(())
    );
    assert_eq!(
        capped.check_handshake(&WebSocketRequest::new("wss://example.com:9443/socket")),
        Err(NetworkError::Denied {
            domain: "example.com".to_owned()
        }),
        "an unlisted handshake port is denied"
    );
    assert_eq!(
        capped.check_handshake(&WebSocketRequest::new("wss://example.com")),
        Ok(()),
        "a wss handshake defaults to 443, which the grant lists"
    );
    assert_eq!(
        capped.check_handshake(&WebSocketRequest::new("example.com/socket")),
        Err(NetworkError::Denied {
            domain: "example.com".to_owned()
        }),
        "a portless handshake fails closed"
    );
}

/// Failures stay typed: a real `Error` with stable, exhaustive categories and
/// no catch-all arm that would let a new failure hide behind a generic one.
#[test]
fn failures_are_typed_with_stable_exhaustive_categories() {
    fn assert_typed_error<E: std::error::Error + Send + Sync + 'static>() {}
    assert_typed_error::<NetworkError>();

    let timeout = NetworkError::Timeout {
        after: Duration::from_secs(2),
    };
    let cases: Vec<(NetworkError, &str)> = vec![
        (NetworkError::Offline, "network offline"),
        (
            NetworkError::Denied {
                domain: "other.example".to_owned(),
            },
            "network denied: other.example",
        ),
        (timeout.clone(), "network timeout after 2000ms"),
        (
            NetworkError::Budget { limit_bytes: 8 },
            "network budget exceeded: 8 bytes",
        ),
        (
            NetworkError::CountBudget { limit_items: 3 },
            "network count budget exceeded: 3 items",
        ),
        (
            NetworkError::Tls {
                reason: TlsFailure::CaRootNotValid,
            },
            "network tls refused: ca root not valid",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.clone(), error, "failures stay comparable");
    }

    let variants = [
        "Denied",
        "Offline",
        "Timeout",
        "Budget",
        "CountBudget",
        "Tls",
    ];
    let declaration = function_body(API_SOURCE, "pub enum NetworkError");
    for variant in variants {
        require(
            &declaration,
            variant,
            "every typed failure category stays declared",
        );
    }
    let display = function_body(API_SOURCE, "impl fmt::Display for NetworkError");
    for variant in variants {
        require(
            &display,
            &format!("Self::{variant}"),
            "every category has its own stable display string",
        );
    }
    forbid(
        &display,
        "_ =>",
        "the display implementation has no catch-all arm, so a new category cannot \
         hide behind a generic message",
    );
    forbid(
        &declaration,
        "non_exhaustive",
        "the failure taxonomy is not open-ended for downstream consumers: no attribute \
         contiguous with it, in any spelling, marks it `non_exhaustive`",
    );
}

/// The vocabulary crate stays implementation-free, so no key-bearing type can
/// reach a derived serde surface: the record's `Serialize`/`Deserialize`
/// prohibition has no dependency to violate.
#[test]
fn no_key_bearing_type_can_derive_serde() {
    forbid(
        API_MANIFEST,
        "serde",
        "the vocabulary crate takes no serde dependency, ever",
    );
    forbid(
        IMPL_MANIFEST,
        "serde",
        "the implementation crate takes no serde dependency",
    );
    for (label, source) in [
        ("bitty-network-api/src/lib.rs", API_SOURCE),
        ("bitty-network/src/tls.rs", TLS_SOURCE),
        ("bitty-network/src/tls/provider.rs", TLS_PROVIDER_SOURCE),
        ("bitty-network/src/tls/x509.rs", TLS_X509_SOURCE),
        ("bitty-network/src/http.rs", HTTP_SOURCE),
        ("bitty-network/src/websocket.rs", WEBSOCKET_SOURCE),
        ("bitty-network/src/proxy.rs", PROXY_SOURCE),
    ] {
        for (line, derived) in derived_traits(source) {
            let leaf = derived.rsplit("::").next().unwrap_or(&derived);
            assert!(
                leaf != "Serialize" && leaf != "Deserialize",
                "{label}:{line} derives {derived}; a key-bearing type must use a \
                 hand-written redacted representation instead"
            );
        }
    }
}

// --- The proxy gate gap the record states --------------------------------

/// The `proxy` gate is a merged predicate, and CTX-0034's call-site wiring has
/// landed, so construction consults it.
///
/// This replaces `proxy_gate_is_a_predicate_without_construction_wiring`, which
/// pinned the *gap* on purpose: the record says that assertion "is expected to
/// fail when CTX-0034's call-site wiring lands, at which point this record is
/// re-verified". The gap is closed, so the pin now asserts the closed state —
/// the same predicate over the same feature, now consulted by `new`. The record
/// sentence describing the gap is the decision lane's to update; this suite
/// reports the code's actual state.
#[test]
fn proxy_gate_is_consulted_before_any_environment_read() {
    assert_eq!(
        bitty_network::proxy::env_proxy_enabled(),
        cfg!(feature = "proxy"),
        "the gate stays one predicate over the `proxy` feature"
    );
    require(
        &code_only(PROXY_SOURCE),
        "cfg!(feature = \"proxy\")",
        "the gate is decided by the feature alone",
    );
    let new = function_body(HTTP_SOURCE, "pub fn new(capability: NetworkCapability)");
    require(
        &new,
        "env_proxy_enabled",
        "the constructor consults the gate predicate",
    );
    // The gate must short-circuit *before* either environment reader runs, so
    // a build without `proxy` reads no proxy variable at all rather than
    // discarding one after reading it.
    let gate = new
        .find("env_proxy_enabled")
        .expect("the gate is consulted above");
    for reader in ["no_proxy_from_env()", "ProxyRoute::from_env()"] {
        let at = new
            .find(reader)
            .unwrap_or_else(|| panic!("{reader} must still be called on the gated path"));
        assert!(
            gate < at,
            "the gate is consulted at offset {gate} but {reader} runs at {at}; \
             the gate must short-circuit before any environment read, otherwise a \
             build without `proxy` reads a proxy variable and only then discards it"
        );
    }
}

// --- Credential handling (HTTP backend) -----------------------------------

/// A credential-bearing proxy URL is rejected before any client is built, and
/// the accepted proxy URL never reaches `Debug`. Both are behavior, not
/// provenance, so they are pinned behaviorally.
#[cfg(feature = "http")]
#[test]
fn credential_bearing_proxy_urls_are_rejected_and_never_rendered() {
    use std::net::TcpListener;

    use bitty_network::HttpNetworkService;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let authority = listener.local_addr().expect("loopback address").to_string();
    drop(listener);

    let credentialed = format!("http://operator:{authority}@127.0.0.1:1/");
    let clean = format!("http://{authority}");

    let error = HttpNetworkService::with_proxy(
        NetworkCapability::offline().with_domain("example.com"),
        &credentialed,
    )
    .expect_err("a credential-bearing proxy URL must be rejected");
    assert_eq!(error, NetworkError::Offline);

    let service = HttpNetworkService::with_proxy(
        NetworkCapability::offline().with_domain("example.com"),
        &clean,
    )
    .expect("a credential-free proxy URL is accepted");
    let rendered = format!("{service:?}");
    require(
        &rendered,
        "proxy_configured",
        "the redacting debug still reports non-secret proxy facts",
    );
    forbid(
        &rendered,
        &authority,
        "debug output never carries the accepted proxy URL",
    );
    forbid(&rendered, "operator", "debug output never carries userinfo");
}

/// The deny-all fallback is fail-closed *and* says so.
///
/// `HttpNetworkService::new` is infallible, so a client that cannot be built has
/// nowhere to return an error and the service falls back to refusing everything.
/// That is the right failure direction, but silently it is
/// indistinguishable from a service built during an outage, so the fallback
/// records `deny_all` and the redacting `Debug` reports it.
///
/// The flag is pinned from both sides. A normally-constructed service must not
/// claim to be deny-all, or the signal is worthless; and the flag must not
/// become a channel for the cause, which is why only the boolean is stored and
/// the cause is bound and dropped at the construction site.
#[cfg(feature = "http")]
#[test]
fn the_deny_all_fallback_is_reported_and_carries_no_cause() {
    use bitty_network::{HttpNetworkService, NetworkCapability};

    let service = HttpNetworkService::new(NetworkCapability::offline().with_domain("example.com"));
    let rendered = format!("{service:?}");
    require(
        &rendered,
        "deny_all",
        "the redacting debug must report whether the deny-all fallback was taken",
    );
    require_unwrapped(
        &rendered,
        "deny_all: false",
        "a service that built its clients normally must not claim to be deny-all",
    );

    // The cause is bound and dropped, not stored: the only construction outcome
    // the service carries is the boolean, so there is no field a future change
    // could widen into a leak without this turning red. The parameter itself
    // legitimately names `cause`, so the check is on the struct literal.
    let http = code_only(HTTP_SOURCE);
    let fallback = function_body(&http, "fn offline(");
    require(
        &fallback,
        "cause: NetworkError",
        "the deny-all constructor is told why it was reached, so the swallow is a \
         named decision rather than a wildcard",
    );
    let built = fallback
        .find("Self {")
        .expect("the deny-all constructor must build a service");
    // Field-shaped needles, not the bare word: this window is the rest of the
    // `impl` block, whose prose is full of "because".
    for stored in ["cause:", "cause,", "cause)"] {
        forbid(
            &fallback[built..],
            stored,
            "the cause must not be stored on the service, where it could reach Debug",
        );
    }
    require(
        &fallback[built..],
        "deny_all: true",
        "the stored outcome is the boolean, which is the whole diagnostic",
    );
}

/// The "no client in this slot" refusal is not a TLS failure.
///
/// The egress set is built with one client per identity slot, so a slot miss
/// cannot happen; the arm exists so a miss is a typed refusal rather than a
/// fall back to another slot's client, which would present a certificate the
/// destination never selected. Reporting it as `Tls { IdentityInvalid }` named a
/// client-identity problem an operator would go looking for in a policy that is
/// perfectly fine — the slot is empty because the service holds no client at
/// all, not because any identity is bad.
///
/// Pinned textually, and honestly: the arm is unreachable through the public API
/// by construction, so there is no behaviour to assert. A reorder that kept the
/// `Offline` mapping would pass, which is the accepted cost of pinning shape.
#[cfg(feature = "http")]
#[test]
fn an_empty_identity_slot_is_not_reported_as_a_tls_failure() {
    let body = function_body(&code_only(HTTP_SOURCE), "fn client_for(");
    let miss = unwrapped(&body);
    let refusal = miss
        .rfind("ok_or(")
        .expect("the slot lookup must refuse rather than fall back to another slot");
    let tail = &miss[refusal..];
    require(
        tail,
        "ok_or(NetworkError::Offline)",
        "a missing client in an identity slot is a no-egress refusal, not a client-identity \
         failure",
    );
    forbid(
        tail,
        "TlsFailure",
        "the slot-miss arm must not report a Tls category: the slot is empty because the \
         service holds no client, so no identity is at fault",
    );
}

/// The offline backend stays fail-closed with the same typed taxonomy the
/// record relies on for a denied or unreachable destination.
#[test]
fn offline_backend_fails_closed_with_typed_errors() {
    let service =
        OfflineNetworkService::new(NetworkCapability::offline().with_domain("example.com"));
    assert_eq!(
        service.request(&Request::get("https://example.com/")),
        Err(NetworkError::Offline)
    );
    assert_eq!(
        service.request(&Request::get("https://other.example/")),
        Err(NetworkError::Denied {
            domain: "other.example".to_owned()
        })
    );
    assert_eq!(
        service.websocket(&WebSocketRequest::new("wss://example.com/socket")),
        Err(NetworkError::Offline)
    );
}

// --- Trust composition: the additive guarantee is the provider's --------
//
// The record's trust model is additive with no custom-only mode: "If native
// roots cannot be loaded, construction or the handshake fails rather than
// silently continuing with custom-only trust."
//
// That guarantee cannot be delegated to `rustls-platform-verifier`. In 0.7.0
// `new_with_extra_roots` adds the extra roots to the root store *before* the
// platform store is read, and its only refusal is `root_store.is_empty()` — so
// with a bundle configured, a platform store that yields nothing raises nothing
// and the verifier comes back holding the custom roots alone. The library
// documents that as deliberate. The provider therefore proves the native load
// itself, and this property is that proof.

/// The provider proves the native root load instead of inferring it from the
/// composed store.
///
/// The behavioral half lives in the provider's own unit tests, which drive the
/// probe to `false`; this is the structural half, so deleting the guard cannot
/// leave the suite green by removing the only place the decision is made.
///
/// **What this pin does and does not catch, stated rather than implied.** It
/// matches the guard's *text*, so it proves the guard is present and shaped as
/// intended. It does not prove the guard is *reached* before the composition
/// call, and a behaviour-preserving reorder — moving the `if` below
/// `Verifier::new_with_extra_roots` while keeping it textually identical —
/// would leave this pin green. That is an accepted cost, not an oversight: a
/// textual pin cannot observe control flow, and the alternative is a refactor
/// that makes the order observable at the cost of the shape the record's own
/// reasoning is about. The behavioural tests in `provider.rs` cover the
/// *outcome*; this covers the *shape*; neither claims the other's coverage.
///
/// **The probe is only a probe on Linux.** `Verifier::new` returns `Ok`
/// unconditionally on macOS and Windows, where the platform verifier composes
/// additively by construction, so the guard cannot fire there. The record states
/// this limit; the property under test is the fail-closed decision, which is
/// real where the store can fail to load and vacuous where it cannot.
#[test]
fn a_missing_platform_root_store_is_refused_rather_than_trusted_around() {
    let build = function_body(TLS_PROVIDER_SOURCE, "fn build_verifier_with(");
    require_unwrapped(
        &build,
        "if !extra_roots.is_empty() && !native_roots_loadable() { return \
         Err(TlsFailure::NativeRootsUnavailable); }",
        "custom roots plus an unloadable platform store must fail closed; the guard is the \
         only thing standing between a bundle and a custom-only trust set",
    );
    // The probe has to be a separate read of the store, before anything this
    // crate supplies can fill it, and not the composed verifier's own verdict.
    let compose = function_body(TLS_PROVIDER_SOURCE, "fn native_roots_loadable(");
    require(
        &compose,
        "Verifier::new(crypto_provider()).is_ok()",
        "the native load is proved by an independent read with no extra roots",
    );
    forbid(
        &compose,
        "new_with_extra_roots",
        "the probe must not be the composed verifier, whose verdict is exactly what cannot \
         be trusted here",
    );
    // And the composition itself must stay additive: a root store this crate
    // builds from scratch would be the custom-only mode the record refuses.
    let entry = function_body(TLS_PROVIDER_SOURCE, "fn build_verifier(");
    require(
        &entry,
        "build_verifier_with(extra_roots, native_roots_loadable)",
        "the production path goes through the checked builder, not around it",
    );
}

/// A plaintext WebSocket target never consults the trust store.
///
/// A `ws://` handshake negotiates no certificate and reads no trust anchor, so
/// evaluating the policy for it would let an anchor that has expired since
/// construction refuse a connection that never used one. Fail-closed is right
/// for a destination that does use the anchor, and wrong for one that does not.
#[test]
fn a_plaintext_websocket_target_does_not_consult_the_trust_store() {
    let connect = function_body(WEBSOCKET_SOURCE, "pub(crate) fn connect(");
    require_unwrapped(
        &connect,
        "let tls = if target.tls {",
        "the per-handshake selection is reached only for a TLS destination",
    );
    let flat = unwrapped(&connect);
    let selection = flat
        .find("provider .select(")
        .unwrap_or_else(|| panic!("the handshake must still select a TLS configuration"));
    let guard = flat.find("if target.tls").expect("the TLS guard");
    assert!(
        selection > guard,
        "the selection must sit inside the `target.tls` branch, not before it: a policy \
         evaluated for a plaintext destination can refuse a connection that never reads a \
         trust anchor"
    );
}

/// An inline key source is parsed where it already lives.
///
/// The record requires the implementation to "minimize retained byte copies" of
/// key material. A copy of an inline private key is a second heap buffer of
/// secret bytes whose lifetime this crate then has to reason about, so the
/// inline arm borrows and only a path read allocates.
#[test]
fn an_inline_key_source_is_parsed_in_place_and_never_copied() {
    let read = function_body(TLS_PROVIDER_SOURCE, "fn read_pem(");
    require_unwrapped(
        &read,
        "PemSource::Inline { pem } => Ok(PemBytes::Borrowed(pem.as_slice()))",
        "an inline source is parsed in place out of the policy's own buffer",
    );
    forbid(
        &read,
        ".clone()",
        "the reader must not copy inline key bytes into a second buffer; only a path read \
         allocates, and that buffer is zeroized",
    );
}

/// The key-size and public-key-algorithm policy is enforced, not just declared.
///
/// The record admits a custom root only when "its signature algorithm,
/// public-key algorithm, and key size are supported by both backends", and the
/// reader states that policy in named constants. Nothing can mint a *weak* key
/// at runtime — every key `rcgen` generates is already at or above these
/// minimums — so the reader's own tests cannot drive the refusal the way they
/// drive `CA=FALSE` or a missing `keyCertSign`. Without this property the
/// constants could stop being consulted and no test would notice, which is a
/// weaker anchor than the rest of the admission policy and is pinned as the
/// structural check it has to be.
#[test]
fn the_key_size_and_public_key_algorithm_policy_is_consulted() {
    let reader = TLS_X509_SOURCE;
    require(
        reader,
        "pub const MIN_RSA_MODULUS_BITS: u32 = 2048;",
        "the RSA floor is a named policy constant, not a literal at the comparison",
    );
    require(
        reader,
        "pub const MIN_ECDSA_CURVE_BITS: u32 = 256;",
        "the ECDSA floor is a named policy constant, not a literal at the comparison",
    );
    require(
        reader,
        "Some(bits) if bits >= MIN_RSA_MODULUS_BITS => Ok(()),",
        "an RSA key below the floor is refused, so the constant is load-bearing",
    );
    require(
        reader,
        "Some((_, bits)) if *bits >= MIN_ECDSA_CURVE_BITS => Ok(()),",
        "an ECDSA curve below the floor is refused, so the constant is load-bearing",
    );
    require(
        reader,
        "OID_RSA_ENCRYPTION",
        "the RSA public-key algorithm is recognised by OID, not by key length alone",
    );
    require(
        reader,
        "OID_EC_PUBLIC_KEY",
        "the EC public-key algorithm is recognised by OID",
    );
    require(
        reader,
        "OID_ED25519",
        "Ed25519 is a recognised public-key algorithm",
    );
    // The curve list is the allowlist: an EC key on a curve this crate does not
    // admit is refused, which is the "supported by both backends" half.
    require(
        reader,
        "const SUPPORTED_ECDSA_CURVES: [(&[u8], u32); 3] = [",
        "the admitted EC curves are an explicit allowlist, not an open-ended match",
    );
}
