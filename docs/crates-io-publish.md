# crates.io publish runbook: registry-ready network crates

Priority: P2 | Area: area:packaging | Labels: feat,P2,area:packaging
| Milestone: v0.1.0 | Issue: bitty-network#90
| Upstream: bitty-terminal/bitty#1512

Scope is this repository only. This note records the first publish of the
two registry-ready crates at version `0.0.2`, so the owner can execute it
after the registry token rotation lands (see the Blockers section).

## Readiness (verified)

- Both crate names return "does not exist" on the crates.io API: free.
- `cargo publish --dry-run -p bitty-network-api` is green.
- `cargo publish --dry-run -p bitty-network-wire` is green.
- Both crates are dependency-free (`bitty-network-api` is the
  implementation-free vocabulary; `bitty-network-wire` is std-only with no
  serde), so ordering between them does not matter and no manifest change
  is needed.

## Out of scope

`bitty-network-core`, `-dns`, `-tls`, `bitty-network`, `bitty-net`, and the
deprecated `bitty-network-lua` stay `publish = false`. They follow only when
Core actually needs them from the registry; this runbook must not be read as
approval to flip those flags.

## Prerequisites

- The registry token rotation recorded upstream is complete. Never publish
  with a token that may have been exposed; each publish is permanent
  (yank is the only undo).
- Immediately before publishing, re-check that both crate names are still
  free on the crates.io API. Names are first-come-first-served; the readiness
  check above is point-in-time and the publish may run days after this note.
- The working tree is clean and on `main`; the crates to publish are
  unchanged since the dry-run verification above.

## Publish commands

Run from the repository root. Either order works; wait until the first crate
is visible in the crates.io index before the second if published back to
back.

```sh
cargo publish -p bitty-network-api
cargo publish -p bitty-network-wire
```

## Verification

- After each step, confirm the just-published crate is visible in the index
  (`cargo search <crate> --limit 1` for `bitty-network-api` and
  `bitty-network-wire` respectively).
- From a clean consumer project outside this workspace, declare
  `bitty-network-api = "=0.0.2"` and `bitty-network-wire = "=0.0.2"` under
  `[dependencies]`, then run `cargo check`.
- Every crate page on crates.io shows "Builds on docs.rs" once the docs
  build finishes.
