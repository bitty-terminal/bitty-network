//! Property pins for the security claims in `docs/decisions/24-pac.md`.
//!
//! The decision record used to justify its control claims with a
//! hand-maintained table mapping each control to a providing commit. That
//! table could not self-maintain: the commit graph moves on every merge and
//! rebase, so each fix round made it briefly correct and the next commit made
//! it wrong again. The record now carries one base pin, and the properties
//! below carry the rest — a change that breaks one of them fails this suite
//! instead of silently invalidating a document.
//!
//! Scope and limits, so a future reader does not over-read these pins:
//!
//! - These tests pin **requirements**, not history. A control that does not
//!   exist yet fails here, which is the point: the record's controls are
//!   unmerged work and a silently dropped control is a security defect.
//! - Seven of the eight pins are deliberately **not** behind
//!   `#![cfg(feature = "http")]`, even though most of them read `src/http.rs`.
//!   The `http` feature is default-off, and a pin that only runs in one CI leg
//!   is a pin that can quietly stop running. The scan reads the file as text
//!   through `CARGO_MANIFEST_DIR`, and `src/http.rs` is on disk whatever the
//!   feature gate says, so the property is checkable in every leg. The eighth,
//!   `credential_bearing_explicit_proxy_fails_closed_without_dialing`, cannot
//!   follow: it constructs `HttpNetworkService`, whose re-export in
//!   `src/lib.rs` is itself behind the same feature. It runs in two legs of
//!   three, and the record says so rather than claiming otherwise.
//! - `tests/http.rs` still exercises the ambient rejection end to end
//!   (`ambient_proxy_environment_is_explicit_and_credential_safe`, which
//!   spawns a child process because mutating the environment is `unsafe` in
//!   edition 2024). That pin is **referenced, not duplicated**. It used to be
//!   joined by a second, narrower source scanner for the same egress controls
//!   (`every_client_builder_disables_ambient_proxy_and_redirects`, scoped to
//!   `src/http.rs` and behind the `http` feature); that one is deleted, because
//!   `every_client_construction_site_disables_ambient_discovery` below is a
//!   strict superset of it and two scanners for one property drift apart.
//!   What this file adds that no `http.rs` test can reach is the
//!   `unwrap_or_else` fallback ban, the single-injection-point rule, and the
//!   *ordering* of the credential check against proxy injection — which no
//!   behavioural test can distinguish, because "validated before injecting"
//!   and "validated, and injected anyway" produce the same observable
//!   outcome.
//! - Source-level pins read text, so they constrain shape, not types. A
//!   refactor that moves a call between functions will fail them; that is a
//!   false positive to fix in the test, not a security hole, and the failure
//!   message names the property so the fix is obvious.
//!
//! Crate layout assertions use `CARGO_MANIFEST_DIR` and a directory read, so
//! a new module cannot slip in unscanned: the scan is over every `.rs` file
//! under `src/`, not over a hardcoded module list.

#![forbid(unsafe_code)]

use std::path::PathBuf;

/// Display text the offline error must keep, unchanged.
const OFFLINE_DISPLAY: &str = "network offline";

/// Every `.rs` file in `src/`, sorted, so scan order is deterministic.
fn crate_source_files() -> Vec<(String, String)> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files: Vec<(String, String)> = std::fs::read_dir(&src)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", src.display()))
        .map(|entry| {
            let path = entry
                .unwrap_or_else(|error| panic!("cannot read a {} entry: {error}", src.display()))
                .path();
            let name = path
                .file_name()
                .unwrap_or_else(|| panic!("no file name in {}", src.display()))
                .to_string_lossy()
                .into_owned();
            assert_eq!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("rs"),
                "{name} is not a Rust source file"
            );
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            (name, text)
        })
        .collect();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(!files.is_empty(), "no crate source files found");
    files
}

/// Text of `src/http.rs`, the only module that builds reqwest clients.
fn http_source() -> String {
    crate_source_files()
        .into_iter()
        .find(|(name, _)| name == "http.rs")
        .map(|(_, text)| text)
        .expect("src/http.rs is a module of this crate")
}

/// Absolute byte range of `fn <name>`'s body in `source`, opening brace
/// through the matching close.
///
/// Brace counting is exact for this crate's sources: the scanned functions
/// contain no string or char literal with an unbalanced brace. A future
/// function that breaks the assumption fails loudly here rather than
/// returning a silently truncated slice.
fn function_body_span(source: &str, name: &str) -> (usize, usize) {
    let signature = format!("fn {name}(");
    let start = source
        .find(&signature)
        .unwrap_or_else(|| panic!("no `{signature}` in the scanned source"));
    let mut depth = 0_i32;
    let mut chars = source[start..].char_indices();
    let body_start = loop {
        let (offset, ch) = chars
            .next()
            .unwrap_or_else(|| panic!("`{signature}` has no body"));
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '{' if depth == 0 => break start + offset,
            _ => {}
        }
    };
    let mut braces = 0_i32;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => braces += 1,
            '}' => {
                braces -= 1;
                if braces == 0 {
                    return (body_start, body_start + offset);
                }
            }
            _ => {}
        }
    }
    panic!("`{signature}` body is not brace-balanced");
}

/// Body of `fn <name>` in `source`, from its opening brace to the match.
fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let (start, end) = function_body_span(source, name);
    &source[start..=end]
}

/// Signature of every `fn` in `source`: from `fn` to the opening brace of its
/// body, so a multi-line signature is captured whole.
///
/// Walks parentheses and brackets the way [`function_body_span`] does and
/// carries the same assumption — no unbalanced brace inside a signature — so a
/// signature that breaks it is truncated rather than silently reinterpreted.
/// Reading headers instead of bodies is what lets a uniqueness check survive a
/// rename: a function can be identified by its shape rather than by the name it
/// happens to carry today.
fn function_headers(source: &str) -> Vec<&str> {
    let mut headers = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("fn ") {
        let tail = &rest[start..];
        let mut depth = 0_i32;
        let end = tail.char_indices().find_map(|(offset, ch)| match ch {
            '(' | '[' => {
                depth += 1;
                None
            }
            ')' | ']' => {
                depth -= 1;
                None
            }
            '{' if depth == 0 => Some(offset),
            _ => None,
        });
        // A `fn` with no readable body ends the scan: nothing past it can be a
        // declaration whose header we could take.
        let Some(end) = end else {
            break;
        };
        headers.push(&tail[..end]);
        rest = &tail[end..];
    }
    headers
}

/// Index of `needle` in `haystack`, or a panic naming the property.
fn require_index(haystack: &str, needle: &str, what: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("{what}: expected {needle:?} in:\n{haystack}"))
}

/// Ambient discovery is off at every client construction site in the crate.
///
/// The record's "discovery stays off" rule is that **every** client builder
/// calls `.no_proxy()` before a selected route is added, and that no
/// unconfigured client can be constructed to bypass it. This test is the only
/// pin of that rule. It walks every `src/*.rs` module, so a new module cannot
/// open a construction path unscanned, and additionally bans an
/// `unwrap_or_else` fallback, which the record forbids because a silent
/// fallback client would restore reqwest's default `auto_sys_proxy = true`
/// while still looking fail-closed. It is not feature-gated, so it holds in
/// the default leg too, where `src/http.rs` is on disk but not compiled.
/// `tests/http.rs` used to carry a narrower copy of the same two assertions,
/// scoped to `src/http.rs` and behind `#![cfg(feature = "http")]`; it was
/// deleted rather than kept in parallel.
#[test]
fn every_client_construction_site_disables_ambient_discovery() {
    const BANNED_CONSTRUCTORS: [&str; 3] =
        ["Client::new()", "Client::default()", "ClientBuilder::new()"];

    let mut builders = 0_usize;
    for (module, source) in crate_source_files() {
        let mut rest = source.as_str();
        while let Some(start) = rest.find("Client::builder()") {
            builders += 1;
            let chain = &rest[start..];
            let end = chain
                .find(".build()")
                .unwrap_or_else(|| panic!("{module}: a client builder chain has no .build()"));
            let calls = &chain[..end];
            assert!(
                calls.contains(".no_proxy()"),
                "{module}: client builder {builders} omits .no_proxy(), so ambient proxy \
                 discovery stays enabled on that client"
            );
            assert!(
                calls.contains("Policy::none()"),
                "{module}: client builder {builders} omits Policy::none(), so reqwest \
                 follows redirects without re-authorizing each hop"
            );
            rest = &chain[end..];
        }
        for constructor in BANNED_CONSTRUCTORS {
            assert!(
                !source.contains(constructor),
                "{module}: unconfigured client construction {constructor} bypasses the \
                 egress controls"
            );
        }
        assert!(
            !source.contains("unwrap_or_else"),
            "{module}: an unwrap_or_else fallback can produce a client without the egress \
             controls; fail closed with an explicit Result instead"
        );
    }
    assert!(builders > 0, "no client builder chain found in the crate");
}

/// `http.rs` is the only module that can construct a reqwest client.
///
/// The record states there is no second construction path to cover, and
/// therefore that a PAC evaluator cannot slip in an unreviewed client by
/// living in another module. A new module that builds a correctly configured
/// client still fails here, on purpose: the record's claim must be revisited
/// rather than left standing.
#[test]
fn http_is_the_only_reqwest_client_construction_site() {
    for (module, source) in crate_source_files() {
        let builds_client = source.contains("Client::builder()")
            || source.contains("Client::new()")
            || source.contains("Client::default()")
            || source.contains("ClientBuilder::new()");
        assert!(
            !builds_client || module == "http.rs",
            "{module} builds a reqwest client; the record names http.rs as the only \
             construction site, so either the client moves or the record changes"
        );
    }
}

/// The explicit path reaches the credential check before injecting a proxy.
///
/// `with_proxy` is the deliberate-operator path, and the record requires it
/// to be rejected before a client is built — never "build a client first to
/// validate later". `ProxyRoute::explicit` must therefore validate before it
/// calls `proxy_client`, which is the function that injects.
#[test]
fn credential_check_precedes_proxy_injection_on_the_explicit_path() {
    let source = http_source();
    let body = function_body(&source, "explicit");
    let checked = require_index(body, "validated_proxy_url(", "explicit path");
    let injected = require_index(body, "proxy_client(", "explicit path");
    assert!(
        checked < injected,
        "the explicit path injects a proxy before the credential check; a \
         credential-bearing URL must be rejected before a client is built"
    );
}

/// The environment path reaches the credential check before injecting a proxy.
///
/// Same rule for the ambient path, and it is the one the record leans on
/// hardest: an unusable environment proxy must set `proxy_rejected` and fail
/// every request closed, not degrade to direct egress. `ProxyRoute::from_env`
/// must validate each variable before `proxy_route_client` injects any of
/// them.
///
/// `tests/http.rs::ambient_proxy_environment_is_explicit_and_credential_safe`
/// already proves the ambient rejection end to end, in a child process. This
/// pin covers what that test cannot see: the check has to be *reached before*
/// the injection, and a rejected value that still reached a client would look
/// identical from the outside.
#[test]
fn credential_check_precedes_proxy_injection_on_the_environment_path() {
    let source = http_source();
    let body = function_body(&source, "from_env");
    let checked = require_index(body, "validated_proxy_url(", "environment path");
    let injected = require_index(body, "proxy_route_client(", "environment path");
    assert!(
        checked < injected,
        "the environment path injects a proxy before the credential check; a rejected \
         value must set proxy_rejected instead of reaching a client"
    );
}

/// The shared validator is the only credential check, and it guards its own
/// injection site too.
///
/// This is the record's one-injection-point rule: every proxy URL, whatever
/// its source, passes one shared validation function, and a future PAC
/// evaluator must call that same function rather than get a second path.
///
/// Three things hold it, and each closes a hole the others leave:
///
/// - The injection sites are pinned by *call*, not by name: every
///   `reqwest::Proxy`/`.proxy(` in the crate must sit inside one of the four
///   named construction functions. This is the name-independent half, and it is
///   what catches a second validator that is actually used — a rename, a new
///   module, or a copy of the helper.
/// - The two helpers are counted by name, which confines them to `http.rs` and
///   pins the spelling the record cites.
/// - The validator is counted again by *shape*, so a renamed drop-in duplicate
///   is caught even though it matches no pinned spelling. A duplicate whose
///   return type differs is not drop-in, and then the two ordering pins —
///   `credential_check_precedes_proxy_injection_on_the_explicit_path` and
///   `credential_check_precedes_proxy_injection_on_the_environment_path`, which
///   require the call by name in `explicit` and `from_env` — fail instead.
///   Between them there is no rename that passes silently.
#[test]
fn proxy_injection_stays_inside_the_named_construction_paths() {
    /// The only functions allowed to touch `reqwest::Proxy` or `.proxy(`.
    const INJECTION_SITES: [&str; 4] = [
        "client_with",
        "proxy_client",
        "reqwest_proxy",
        "proxy_route_client",
    ];
    /// Every injection call the record's rules cover.
    const INJECTION_CALLS: [&str; 4] = [
        "reqwest::Proxy::all(",
        "reqwest::Proxy::http(",
        "reqwest::Proxy::https(",
        ".proxy(",
    ];
    /// The one signature a shared proxy-URL validator can have: it takes the
    /// scope it will build a `reqwest::Proxy` for and returns the validated
    /// URL or the typed error. `reqwest_proxy` shares the parameter and not the
    /// error, so the shape separates them.
    const VALIDATOR_SHAPE: [&str; 3] = ["ProxyScope", "-> Result<", "NetworkError"];

    for (module, source) in crate_source_files() {
        for call in INJECTION_CALLS {
            let found = source.match_indices(call).count();
            if module != "http.rs" {
                assert_eq!(
                    found, 0,
                    "{module}: {call:?} is outside http.rs, so it is a second injection \
                     path; a new proxy source must call validated_proxy_url, not build its \
                     own reqwest::Proxy"
                );
                continue;
            }

            // Absolute ranges of the only functions allowed to inject.
            let allowed: Vec<(usize, usize)> = INJECTION_SITES
                .iter()
                .map(|site| function_body_span(&source, site))
                .collect();
            for (nth, (at, _)) in source.match_indices(call).enumerate() {
                assert!(
                    allowed.iter().any(|(start, end)| *start <= at && at < *end),
                    "{module}: {call:?} (occurrence {}) is not inside any of {INJECTION_SITES:?}; \
                     a new injection point must go through validated_proxy_url, not around it",
                    nth + 1
                );
            }
        }
        for helper in ["fn validated_proxy_url(", "fn proxy_url_has_credentials("] {
            assert_eq!(
                source.matches(helper).count(),
                usize::from(module == "http.rs"),
                "{module}: {helper} must be defined exactly once in the crate; a second \
                 definition is a second injection path"
            );
        }
    }

    // The same validator counted by shape instead of by name, so a renamed
    // drop-in duplicate fails here rather than passing a check that only knows
    // one spelling. Zero matches fails too: if `ProxyScope` or the error type
    // is ever renamed this pin must redden, not go quietly vacuous.
    let sources = crate_source_files();
    let validators: Vec<(&str, &str)> = sources
        .iter()
        .flat_map(|(module, source)| {
            function_headers(source)
                .into_iter()
                .filter(|header| VALIDATOR_SHAPE.iter().all(|part| header.contains(part)))
                .map(move |header| (module.as_str(), header))
        })
        .collect();
    let mut shapes = validators.iter();
    let Some((module, header)) = shapes.next() else {
        panic!("no function in the crate has the shared proxy-URL validator signature")
    };
    assert!(
        header.contains("fn validated_proxy_url("),
        "the crate's only proxy-URL validator is {header} in {module}, not \
         validated_proxy_url; either the rename is recorded in the decision or the \
         shared validator is split, which is a second injection path"
    );
    assert!(
        shapes.next().is_none(),
        "a second proxy-URL validator exists besides the one in {module}: a second \
         validator is a second injection path, and a new proxy source must call \
         validated_proxy_url instead of getting a path of its own"
    );

    let source = http_source();
    let body = function_body(&source, "proxy_client");
    let checked = require_index(body, "proxy_url_has_credentials(", "proxy_client");
    let injected = require_index(body, "reqwest::Proxy::all(", "proxy_client");
    assert!(
        checked < injected,
        "proxy_client builds a reqwest::Proxy before checking for userinfo; the shared \
         validator cannot be the only guard if the injection site is unguarded"
    );
}

/// A credential-bearing explicit proxy URL fails closed without dialing.
///
/// The behavioural half of the same rule the two source pins above assert by
/// ordering. `with_proxy` must return the typed error and touch no socket:
/// the rejection precedes client construction, so both the proxy and the
/// origin must see zero connections.
///
/// Deliberately narrow: the credential check must also run for the
/// credential-*free* URLs the other tests route through, but those need a
/// real proxy that answers, which `tests/http.rs` already covers. This test
/// exists to prove the rejection is reached before any client is built.
#[cfg(feature = "http")]
#[test]
fn credential_bearing_explicit_proxy_fails_closed_without_dialing() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use bitty_network::{HttpNetworkService, NetworkCapability, NetworkError};

    /// Userinfo component of the credential-bearing proxy fixture.
    const PROXY_USER_FIXTURE: &str = "fixture-user";
    /// Password component of the credential-bearing proxy fixture.
    const PROXY_PASSWORD_FIXTURE: &str = "fixture-pass";
    /// How long to wait before asserting that no connection arrived. The
    /// rejection under test happens before any dial, so a short pause is
    /// generous; it only guards against a late connection.
    const NO_DIAL_SETTLE: Duration = Duration::from_millis(150);

    // A loopback listener that only counts accepts; it never has to answer,
    // because a correct rejection never dials it.
    let counting_listener = || -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("loopback addr").port();
        listener
            .set_nonblocking(true)
            .expect("non-blocking accept loop");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        thread::spawn(move || {
            let mut probe = [0_u8; 1];
            while let Ok((mut socket, _)) = listener.accept() {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = socket.read(&mut probe);
            }
        });
        (port, hits)
    };

    let (proxy_port, proxy_hits) = counting_listener();
    let proxy_url =
        format!("http://{PROXY_USER_FIXTURE}:{PROXY_PASSWORD_FIXTURE}@127.0.0.1:{proxy_port}");

    let error = HttpNetworkService::with_proxy(
        NetworkCapability::offline().with_domain("127.0.0.1"),
        &proxy_url,
    )
    .expect_err("a credential-bearing proxy url must be rejected before any client is built");

    assert_eq!(error, NetworkError::Offline);
    assert!(
        !error.to_string().contains(PROXY_USER_FIXTURE)
            && !error.to_string().contains(PROXY_PASSWORD_FIXTURE),
        "the rejection must not echo the rejected credential"
    );

    // Rejection precedes client construction, so the one socket this could
    // possibly have dialed is the proxy, and it must be untouched.
    thread::sleep(NO_DIAL_SETTLE);
    assert_eq!(proxy_hits.load(Ordering::SeqCst), 0, "the proxy was dialed");
}

/// `NetworkError::Offline` stays a unit variant with a constant display.
///
/// The record's diagnostic-carrier open point (owned by CTX-0022) rests on
/// exactly this: unit `Offline` plus the public taxonomy cannot carry the
/// four post-source PAC reasons plus `pac-url-userinfo`, so those cases are
/// indistinguishable today. If this test stops compiling or fails, `Offline`
/// gained a payload or its text became dynamic — the open point must be
/// revisited before any PAC slice relies on it.
///
/// This pin deliberately does **not** assert the variant count. The count is
/// a fact about a tree, not a requirement, and pinning it here would rebuild
/// the stale-table problem this file exists to remove.
#[test]
fn offline_stays_a_unit_variant_with_a_constant_display() {
    use bitty_network::NetworkError;

    // Compiles only while `Offline` carries no fields: adding a `reason` to
    // it turns this binding into a missing-field error.
    let offline: NetworkError = NetworkError::Offline;
    assert_eq!(offline, NetworkError::Offline);
    assert_eq!(NetworkError::Offline.to_string(), OFFLINE_DISPLAY);
}

/// Only the HTTP backend reads the proxy environment.
///
/// Tier 2 is HTTP-only in the record: the WebSocket backend inherits no proxy
/// environment, so the tier-2 rules are scoped to `http.rs`. A new `env::var`
/// in another module — or a second reader in `http.rs` that changes which
/// variables are honored — would silently falsify that, so the confinement is
/// pinned instead of asserted in prose.
#[test]
fn proxy_environment_is_read_only_by_the_http_backend() {
    const ENV_READ: &str = "env::var";

    let mut readers: Vec<String> = Vec::new();
    for (module, source) in crate_source_files() {
        if source.contains(ENV_READ) {
            readers.push(module);
        }
    }
    assert_eq!(
        readers,
        ["http.rs"],
        "only http.rs may read the environment; tier 2 is HTTP-only and another \
         reader would inherit proxy authority the record does not describe"
    );
}
