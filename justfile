# bitty-network quality gates (run via justfile, never bare).
check:
    just fmt-check
    just clippy
    just test
    just component-dist-test

component-dist-test:
    bash scripts/tests/package-component.test.sh

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test:
    cargo test --workspace --all-targets --locked

typecheck:
    cargo check --workspace --all-targets --locked

check-http:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked --features http -- -D warnings
    cargo test --workspace --all-targets --locked --features http

check-websocket:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked --features http,websocket -- -D warnings
    cargo test --workspace --all-targets --locked --features http,websocket

actionlint:
    actionlint -color
