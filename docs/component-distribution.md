# Native Component Distribution

Status: **implemented packaging slice**.

This repository packages the `net` native component, whose executable is
`bitty-net`. The package is a DIR-030 stdio component and is not a plugin or a
registry entry. Registry integration and user-facing install resolution remain
outside this repository.

## Package Shape

The root `bitty-component.toml` is a parser-compatible template for version
`0.0.1`. Its all-zero SHA-256 value is a packaging sentinel. The pack command
replaces that value with the digest of the selected target binary before it
writes an archive.

Each target archive contains exactly these two members at its root:

```text
bitty-component.toml
bitty-net                 # bitty-net.exe on Windows targets
```

The output directory contains one archive per target, one `.sha256` sidecar
per archive, and the aggregate `SHA256SUMS` file. No wrapper directory or
other package member is permitted.

```text
extensions/net/<version>/<target>.tar.gz
extensions/net/<version>/<target>.tar.gz.sha256
extensions/net/<version>/SHA256SUMS
```

The corresponding public URLs are:

```text
https://cdn.bitty.run/extensions/net/<version>/<target>.tar.gz
https://cdn.bitty.run/extensions/net/<version>/SHA256SUMS
```

## Local Packaging

Build a target binary with the repository's pinned Rust toolchain, then run:

```sh
cargo build --release --locked -p bitty-net --target x86_64-unknown-linux-gnu
scripts/package-component.sh \
  --version 0.0.1 \
  --target x86_64-unknown-linux-gnu \
  --binary target/x86_64-unknown-linux-gnu/release/bitty-net \
  --output dist/x86_64-unknown-linux-gnu.tar.gz
```

The script validates the strict version, component name, protocol range,
executable name, binary size, and digest before creating output. It also
verifies the archive member list and regenerates `SHA256SUMS` over every target
archive already in the output directory.

The pure URL mapping is available without a build or filesystem write:

```sh
scripts/package-component.sh --print-url --version 0.0.1 \
  --target x86_64-unknown-linux-gnu
```

## Tag Publication

The component distribution workflow runs only for strict `vX.Y.Z` tag pushes.
It builds the current `bitty-net`, packages the target artifact, and publishes
the package directory to the configured R2 bucket under `extensions/net/`.
The publisher requires `R2_BUCKET`, `CLOUDFLARE_ACCOUNT_ID`, and
`CLOUDFLARE_API_TOKEN` from the workflow environment.

Before every put it fetches the existing object. An identical object is left
untouched; a different object or an indeterminate get failure aborts the job.
Every new put is fetched again and compared byte-for-byte. Versioned objects
use immutable cache headers and are never overwritten.

No tag is created or uploaded by local packaging commands. The fixture gate
is available as `just component-dist-test` and uses no network access.
