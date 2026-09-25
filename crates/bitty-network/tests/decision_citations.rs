//! Citation pin for the authenticated-proxy credential decision (#25).
//!
//! `docs/decisions/25-proxy-auth.md` locates every control it claims on the
//! base pin. Those locators were line numbers, and line numbers kept being
//! wrong: a rename, or an insertion above a cited function, silently
//! invalidated a locator while the sentence around it stayed true-looking, and
//! nothing noticed until a reviewer counted lines by hand.
//!
//! This pin replaces that failure mode. The record's locators are now written
//! as `path::anchor`, and this test resolves every one of them: the file must
//! exist, the anchor must occur in it, and an `[absent]` anchor must occur
//! nowhere in it. A rename now fails the suite instead of drifting.
//!
//! What this pin does not do, deliberately:
//!
//! - It does not check that a cited symbol still says what the record claims
//!   about it. The claims that carry weight are the property pins in
//!   `proxy_credential_policy.rs`, which fail on behaviour. This one only
//!   guarantees that the record points at something that exists.
//! - It does not check the prose markers that distinguish **[specified, not
//!   implemented]** from implemented. A `grep`-shaped check of those would be
//!   unsound — a count is satisfied by one marker anywhere, and a context
//!   window by any marker near any heading, so it would report green while the
//!   defect recurred — and it would reward adding markers to implemented
//!   requirements, turning a judgement into a checkbox. Those markers stay
//!   review-enforced.
//!
//! A locator this test cannot classify is itself the failure it is here to
//! catch, so the classifier is strict: a backticked token is a citation when
//! its prefix ends in `.rs` or `.toml`, or is the pseudo-path `tree`. Anything
//! else containing `::` is a Rust path in prose (`Self::read`,
//! `HttpNetworkService::with_proxy`) and is skipped. A citation must also name
//! a full repository-relative path, so a mistyped or abbreviated locator is
//! rejected rather than quietly skipped — the unsound path this pin exists to
//! close.
//!
//! Nothing in this file may quote a string the record cites as absent, because
//! this file is itself one of the sources the `tree` pseudo-path ranges over.
//! The first draft of this comment did exactly that and the pin caught it.
//!
//! No credential, URL, header, or request value is read or printed here. The
//! only inputs are the record and the repository's own source files, and a
//! failure message names a locator, never file content.

#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

/// The decision record this pin checks.
const RECORD: &str = "docs/decisions/25-proxy-auth.md";

/// The pseudo-path standing for every Rust source file under `crates/`.
const TREE: &str = "tree";

/// The prefix that marks a negative claim: the anchor must occur nowhere.
const ABSENT: &str = "[absent]";

/// Repository root, derived from this crate's manifest directory so the pin
/// never depends on the working directory a test happens to run in.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate manifest directory has a repository root above it")
        .to_path_buf()
}

/// Every backticked span in `text`, in order.
fn backticked_spans(text: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        rest = &rest[open + 1..];
        match rest.find('`') {
            Some(close) => {
                spans.push(&rest[..close]);
                rest = &rest[close + 1..];
            }
            None => break,
        }
    }
    spans
}

/// True when `token` is a locator rather than a Rust path in prose.
fn is_citation(token: &str) -> bool {
    let Some((prefix, _)) = token.split_once("::") else {
        return false;
    };
    prefix == TREE || prefix.ends_with(".rs") || prefix.ends_with(".toml")
}

/// Every `.rs` file under `directory`, recursively.
fn rust_sources(directory: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("the source tree must be readable: {error}"));
    for entry in entries {
        let path = entry.expect("a readable source-tree entry").path();
        if path.is_dir() {
            rust_sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()))
}

/// One locator, resolved against the repository.
struct Citation {
    token: String,
    path: String,
    absent: bool,
    anchor: String,
}

#[test]
fn every_citation_in_the_record_names_a_symbol_that_exists() {
    let root = workspace_root();
    let record_path = root.join(RECORD);
    let record = read(&record_path);

    let mut sources = Vec::new();
    rust_sources(&root.join("crates"), &mut sources);
    sources.sort();
    assert!(
        !sources.is_empty(),
        "the tree pseudo-path must resolve to at least one Rust source file"
    );
    let tree = sources
        .iter()
        .map(|path| read(path))
        .collect::<Vec<String>>()
        .join("\n");

    let mut citations: Vec<Citation> = Vec::new();
    for token in backticked_spans(&record) {
        if !is_citation(token) {
            continue;
        }
        let (path, rest) = token.split_once("::").expect("a classified citation");
        let (absent, anchor) = match rest.strip_prefix(ABSENT) {
            Some(anchor) => (true, anchor.trim()),
            None => (false, rest),
        };
        assert!(
            !anchor.is_empty(),
            "a locator in {RECORD} names no anchor: {token}"
        );
        assert!(
            path == TREE || path.starts_with("crates/"),
            "a locator in {RECORD} must name a full repository-relative path, \
             not {path}; an abbreviated or mistyped locator would be skipped \
             instead of checked: {token}"
        );
        citations.push(Citation {
            token: (*token).to_owned(),
            path: (*path).to_owned(),
            absent,
            anchor: (*anchor).to_owned(),
        });
    }

    assert!(
        !citations.is_empty(),
        "{RECORD} must carry at least one locator, or this pin proves nothing"
    );

    for citation in &citations {
        let file;
        let haystack = if citation.path == TREE {
            assert!(
                citation.absent,
                "the tree pseudo-path is only valid with {ABSENT}: {}",
                citation.token
            );
            tree.as_str()
        } else {
            file = read(&root.join(&citation.path));
            file.as_str()
        };
        if citation.absent {
            assert!(
                !haystack.contains(&citation.anchor),
                "{} cites {ABSENT} {}, but that text is present; the record's \
                 negative claim is stale",
                citation.token,
                citation.anchor
            );
        } else {
            assert!(
                haystack.contains(&citation.anchor),
                "{} names {}, which is not present; the record's locator is stale",
                citation.token,
                citation.anchor
            );
        }
    }
}
