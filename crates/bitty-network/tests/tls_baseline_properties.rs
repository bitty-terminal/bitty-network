//! Property pins for the current-state claims of `docs/decisions/21-tls-policy.md`.
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
    WebSocketRequest, tls::Tls,
};

/// Implementation manifest: the pinned TLS stacks and their features.
const IMPL_MANIFEST: &str = include_str!("../Cargo.toml");
/// Vocabulary manifest: must stay implementation-free.
const API_MANIFEST: &str = include_str!("../../bitty-network-api/Cargo.toml");
/// Resolved dependency graph: which root store the TLS stacks actually pull.
const WORKSPACE_LOCK: &str = include_str!("../../../Cargo.lock");
/// The sealed marker module the record calls its foundational claim.
const TLS_SOURCE: &str = include_str!("../src/tls.rs");
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

/// Assert `haystack` does not carry `needle`, naming the property.
fn forbid(haystack: &str, needle: &str, property: &str) {
    assert!(
        !haystack.contains(needle),
        "{property}: `{needle}` must not appear"
    );
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

/// `tls.rs` is still a marker: a zero-sized type and no policy, certificate,
/// crypto, or I/O surface. This is the record's foundational current-state
/// claim, so it is pinned at both the type level and the source level.
///
/// The source half pins the module's exact code shape rather than a list of
/// forbidden words. A word list is easy to defeat by accident — a new field
/// named for neither "cert" nor "key", or a `#[derive(..)] pub struct` on one
/// line, would slip through — while "this module is four lines of code" fails
/// on any addition at all, which is the property the record actually needs.
#[test]
fn tls_module_remains_a_sealed_marker() {
    assert_eq!(
        std::mem::size_of::<Tls>(),
        0,
        "Tls is no longer a zero-sized marker"
    );
    let stripped = code_only(TLS_SOURCE);
    let code: Vec<&str> = stripped
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let expected = [
        "#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]",
        "pub struct Tls {",
        "_private: (),",
        "}",
    ];
    assert_eq!(
        code, expected,
        "tls.rs is no longer a bare marker: it carries a policy type, certificate data, \
         crypto, or I/O. The record's current-state section must be re-verified against \
         the base that introduces it."
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
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.clone(), error, "failures stay comparable");
    }

    let variants = ["Denied", "Offline", "Timeout", "Budget", "CountBudget"];
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
        ("bitty-network/src/http.rs", HTTP_SOURCE),
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

/// The `proxy` gate is a merged predicate, and at this base it is not wired
/// into `HttpNetworkService::new`: construction reads the environment
/// unconditionally. Both halves are pinned, so the record's statement about
/// the gap cannot quietly become true or quietly stop being true.
#[test]
fn proxy_gate_is_a_predicate_without_construction_wiring() {
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
    forbid(
        &function_body(HTTP_SOURCE, "pub fn new(capability: NetworkCapability)"),
        "env_proxy_enabled",
        "at this base `new` does not consult the gate predicate; when the call-site \
         wiring lands this assertion fails and the record must be re-verified",
    );
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
