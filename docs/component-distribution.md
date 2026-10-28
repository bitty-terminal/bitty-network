# Native Component Distribution

Status: **implemented packaging slice**.

This repository packages the `net` native component, whose executable is
`bitty-net`. The package is a DIR-030 stdio component and is not a plugin or a
registry entry. Registry integration and user-facing install resolution remain
outside this repository.

The supported target set, per-target CI evidence, documented exclusions, and
the `extensions/catalog.v1` row contract are defined in
[component-release-matrix.md](component-release-matrix.md) and
`component-targets.toml`.

## Package Shape

The root `bitty-component.toml` is a parser-compatible template for version
`0.0.2`. Its all-zero SHA-256 value is a packaging sentinel. The pack command
replaces that value with the digest of the selected target binary before it
writes an archive. Component artifacts are immutable per version, so a matrix
change always ships under a new version; `0.0.1` was published with a
Linux-only payload.

Each target archive contains exactly these two members at its root:

```text
bitty-component.toml
bitty-net                 # bitty-net.exe on Windows targets
```

The output directory contains one archive per supported target, one `.sha256`
sidecar per archive, and the aggregate `SHA256SUMS` file. No wrapper directory
or other package member is permitted. Only targets declared
`supported = true` in `component-targets.toml` can appear; an archive for an
unsupported triple fails the manifest and catalog gates.

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
  --version 0.0.2 \
  --target x86_64-unknown-linux-gnu \
  --binary target/x86_64-unknown-linux-gnu/release/bitty-net \
  --output dist/x86_64-unknown-linux-gnu.tar.gz
```

The script validates the strict version, component name, protocol range,
executable name, binary size, and digest before creating output. It also
verifies the archive member list, rejects pre-existing archives whose embedded
descriptor version differs, and regenerates `SHA256SUMS` over every target
archive in the output directory. Checksum lines are always written as
`<sha256>  <name>`, including under Git-Bash/MSYS `sha256sum` binary mode, so
the manifest the publisher reads is the manifest the verifier checked. The
publisher rejects extra files, requires an exact archive-to-manifest set, and
verifies every archive sidecar.

The pure URL mapping is available without a build or filesystem write:

```sh
scripts/package-component.sh --print-url --version 0.0.2 \
  --target x86_64-unknown-linux-gnu
```

## Tag Publication

The component distribution workflow runs only for strict `vX.Y.Z` tag pushes.
It first runs the repository gates, then packages every supported target on
its native runner (`cargo check`, `cargo test -p bitty-net`, pack, protocol
smoke against the extracted tarball, catalog row), and only after every leg
succeeds does the aggregate job regenerate `SHA256SUMS`, write and verify
`release/component-digests.toml`, and run the full-matrix verifier. A partial
or unverified target set never reaches the publisher.
The publisher requires `R2_BUCKET`, `CLOUDFLARE_ACCOUNT_ID`, and
`CLOUDFLARE_API_TOKEN` from the workflow environment.

Before every put it fetches the existing object. An identical object is left
untouched; a different object or an indeterminate get failure aborts the job.
Every new put is fetched again and compared byte-for-byte. Versioned objects
use immutable cache headers and are never overwritten.

The publisher uploads payloads only (tarballs, sidecars, `SHA256SUMS`). The
verified `catalog.v1` row fragment and digest record are not uploaded here:
`extensions/catalog.v1` is a single shared object across components, so a
per-component fragment would clobber other rows, and the digest record is a
release-candidate artifact. A future catalog merge job owns that key.

No tag is created or uploaded by local packaging commands. The package,
release, smoke, and publisher fixture gates are available as
`just component-dist-test`, `just component-release-test`,
`just component-smoke-test`, and `just component-dist-publish-test`; all use
no network access.
