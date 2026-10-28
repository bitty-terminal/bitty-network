# Component Release Matrix

Status: **implemented** for the `net` component (issue
`bitty-terminal/bitty#2491`, component version `0.0.2`).

This page is the release contract for the native `net` component. The
machine-readable source of truth is `component-targets.toml`; this document
explains what it means, how CI proves each target, which targets are
deliberately excluded, and what evidence a published artifact carries.

## Purpose and scope

`bitty-net` is a host executable (DIR-030 stdio component), not a Lua plugin.
A single tarball cannot run on every host, so each supported Rust target
produces its own tarball, its own `SHA256SUMS` entry, and its own
`extensions/catalog.v1` row keyed by the target triple. The Core installer
resolves the host triple (`component_seed::host_target_triple`) and requests
exactly that artifact.

The matrix covers Linux glibc x86_64/aarch64, macOS arm64/x86_64, and Windows
x86_64. Anything not listed as supported publishes no bytes: a missing row is
an explicit "not installable yet", never a silent fallback to another target.

## Supported targets

| Target triple               | OS      | Arch    | Native CI runner   | Evidence                                                 |
| --------------------------- | ------- | ------- | ------------------ | -------------------------------------------------------- |
| `x86_64-unknown-linux-gnu`  | linux   | x86_64  | `ubuntu-24.04`     | check, component tests, clippy, smoke, pack, catalog row |
| `aarch64-unknown-linux-gnu` | linux   | aarch64 | `ubuntu-24.04-arm` | check, component tests, clippy, smoke, pack, catalog row |
| `aarch64-apple-darwin`      | macos   | aarch64 | `macos-15`         | check, component tests, clippy, smoke, pack, catalog row |
| `x86_64-apple-darwin`       | macos   | x86_64  | `macos-15-intel`   | check, component tests, clippy, smoke, pack, catalog row |
| `x86_64-pc-windows-msvc`    | windows | x86_64  | `windows-2025`     | check, component tests, clippy, smoke, pack, catalog row |

Every row runs on a native GitHub-hosted runner. `cargo check --workspace
--all-targets` proves the workspace compiles on that platform, `cargo test -p
bitty-net` proves the component's lib and integration tests, clippy denies
warnings for the component, the packed tarball is unpacked and the packaged
executable passes the protocol smoke, and only then is the tarball uploaded and
its catalog row emitted. The HTTP backend's `aws-lc-sys` C dependency builds
with each runner's native toolchain; cross-compiling it from a Linux host is
not evidence and is not used.

## Documented exclusions

These triples are host triples the Core installer can request, but this
repository publishes nothing for them. They are recorded with a `reason` in
`component-targets.toml`; the verifier refuses any tarball or catalog row for
an unsupported triple.

| Target triple               | Why excluded                                                                                                                                                                                                                                                                                                    |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `x86_64-unknown-linux-musl` | The shipped graph is not pure Rust: `bitty-network-tls` enables rustls' `aws-lc-rs` provider, so `aws-lc-sys` compiles C/assembly through cmake, and `rustls-platform-verifier` reads the platform trust store at runtime. A static musl artifact needs an Alpine toolchain build plus a native musl run first. |
| `aarch64-pc-windows-msvc`   | `aws-lc-sys` needs a clang/LLVM plus cmake assembler path for its Windows ARM64 crypto code, and the MSVC arm64 CRT and `rustls-platform-verifier` Windows arm64 backend are separate ABI targets. This repository has no native arm64 Windows runner, so the target is unproven.                               |

Both exclusions are dependency constraints, not policy preferences: neither
target has native build-and-run evidence in this repository, so no bytes are
published for them.

## Artifacts and catalog rows

For version `X.Y.Z` and a supported target `T`:

```text
https://cdn.bitty.run/extensions/net/X.Y.Z/T.tar.gz
https://cdn.bitty.run/extensions/net/X.Y.Z/SHA256SUMS
```

Each tarball contains exactly two members at the archive root: the logical
descriptor `bitty-component.toml` (with the target binary digest) and the
executable `bitty-net` (`bitty-net.exe` on Windows targets). The canonical root
`bitty-component.toml` keeps its zero-digest placeholder; the packer replaces
only that line, and install-time verification refuses any descriptor whose
digest does not match the executable, so the sentinel can never be installed.

`scripts/component-release.sh catalog` emits the registry fragment:

```text
schema 1
extension net X.Y.Z aarch64-apple-darwin <tarball sha256>
extension net X.Y.Z aarch64-unknown-linux-gnu <tarball sha256>
extension net X.Y.Z x86_64-apple-darwin <tarball sha256>
extension net X.Y.Z x86_64-pc-windows-msvc <tarball sha256>
extension net X.Y.Z x86_64-unknown-linux-gnu <tarball sha256>
```

Rows are sorted by target and their digest is the tarball digest, byte-equal to
that release's `SHA256SUMS` entry. The fragment is verified but **not uploaded**
by this repository: `extensions/catalog.v1` is one shared object across
components, so a single-component fragment would clobber other components'
rows. The future catalog merge job owns that key; until it exists, installs use
the pinned-version fallback described in `component-distribution.md`.

## Digest record

The release also writes `release/component-digests.toml`, a generated record
with one row per supported target:

```toml
schema = 1
name = "net"
version = "X.Y.Z"
protocol = [1, 1]

[[target]]
triple = "x86_64-unknown-linux-gnu"
tarball = "x86_64-unknown-linux-gnu.tar.gz"
tarball_sha256 = "<tarball sha256>"
executable = "bitty-net"
executable_sha256 = "<executable sha256>"
```

`scripts/component-release.sh verify --record release/component-digests.toml`
requires the record to name exactly the supported matrix and every digest to
match the verified artifacts. The record is a release-candidate artifact, not
an R2 object; it is written outside `dist/` so the publisher's exact file-set
gate stays intact. CI regenerates it on every run and never commits a stale
copy.

## Protocol smoke

`scripts/component_smoke.py` (through `scripts/component-release.sh smoke`) is
the native-host check that the artifact actually runs, not just that it has a
plausible name. It spawns the unpacked executable, verifies `--version`, then
speaks wire protocol v1 (`bitty-network-wire`) over stdin/stdout:

1. `Hello { min: 1, max: 1, component: "net", version: <descriptor> }` →
   `HelloAck { protocol: 1, component: "net", version: <descriptor> }`.
2. One `HttpRequest` with an **empty grant** → `Error { id, kind: offline }`
   with the same request id.
3. `Shutdown` → no further frame and process exit code `0`.

The empty grant is deliberate. A real fetch would need DNS and network egress,
which a sandboxed or offline runner cannot guarantee and which the smoke must
not perform; the grant check refuses the request before a worker, socket, or
resolver is touched, so the `Error` frame proves the request path with zero
external I/O. The URL uses the reserved `.invalid` TLD (RFC 6761), so even a
regression that skipped the grant check could not reach a real host.

Protocol v1 has no `ShutdownAck`: `Shutdown` (or stdin EOF) ends the session,
and the process exits `0` within the configured grace. The smoke requires
silence plus that exit code, so an extra frame or a hung process fails the leg.

Every native CI and release matrix leg runs this against the extracted tarball
before uploading it. A component that starts but cannot handshake, refuse the
ungranted request with the documented kind, or exit cleanly fails the leg, so no
artifact is advertised without native protocol evidence.
`just component-smoke path/to/bitty-net` runs the same check locally.

## Verification gate

`scripts/component-release.sh verify` fails when:

- a supported target has no tarball, no sidecar, or no `SHA256SUMS` entry;
- an unsupported target appears in the manifest or dist;
- the archive is not exactly the descriptor plus the expected executable;
- the embedded descriptor identity/version/protocol or executable digest
  drifts;
- the executable is empty, lacks an execute bit (non-Windows targets), or its
  first bytes are not the expected ELF/Mach-O/PE magic for that target;
- a tarball digest changes between manifest and verification.

`--record` adds the per-target digest-record check. The tag path runs the same
gate after every matrix leg, so a partial or unverified set can never reach R2.

## CI evidence

`.github/workflows/ci.yml`:

- `component-targets` validates the descriptor, the matrix, the
  at-least-one-supported-target gate, and the CDN URL mapping for every
  supported target, then emits the matrix.
- `component` runs once per supported target on its native runner: workspace
  compile, `bitty-net` tests, clippy with `-D warnings`, packaging, the
  protocol smoke against the extracted tarball, and the per-target catalog row.
- `component-aggregate` merges the target artifacts, regenerates
  `SHA256SUMS`, writes and verifies `release/component-digests.toml`, runs the
  full-matrix verifier (all supported targets present, every archive member,
  digest, mode, and magic checked), and prints the catalog fragment.

`.github/workflows/component-release.yml` repeats the same per-target proof on
the tag path, then aggregates before the publish job. The tag `verify` job runs
the full `just check` gate (fmt, clippy, workspace tests, fixture gates) once,
and each `package` leg runs `cargo check --workspace --all-targets`,
`cargo test -p bitty-net`, pack, smoke, and its catalog row; the legs do not
repeat clippy. A publish job can only run after every matrix leg succeeded, so
a partial or unverified target set can never reach R2. The publish job uploads
payloads only; the catalog fragment and digest record are not uploaded (see
above). Local packaging never uploads.

## Local commands

```sh
# Gate: descriptor + release matrix (fails with zero supported targets)
scripts/component-release.sh check

# Supported targets, plain or GitHub Actions matrix JSON
scripts/component-release.sh targets
scripts/component-release.sh targets --format json

# Build and pack one target (native build required), then verify and emit rows
cargo build --release --locked -p bitty-net --target x86_64-unknown-linux-gnu
scripts/package-component.sh --version X.Y.Z \
  --target x86_64-unknown-linux-gnu \
  --binary target/x86_64-unknown-linux-gnu/release/bitty-net \
  --output dist/x86_64-unknown-linux-gnu.tar.gz
scripts/component-release.sh manifest --dist dist
scripts/component-release.sh catalog --dist dist --output catalog/catalog.v1

# Native-host protocol smoke against the unpacked executable
scripts/component-release.sh smoke --binary path/to/unpacked/bitty-net

# Aggregate-only: collect every supported target's tarball into dist first
# (native builds on their own runners), then record and verify the full matrix.
scripts/component-release.sh record --dist dist --output release/component-digests.toml
scripts/component-release.sh verify \
  --dist dist --record release/component-digests.toml
```

The tooling is Python 3.11+ (`tomllib`) behind `scripts/component-release.sh`,
which resolves `python3` or `python` so the same command works on Linux, macOS,
and Windows runners. `scripts/component_release.py` is shared verbatim with
`bitty-graphics` and contains no repository-specific literal: the component
name comes from `bitty-component.toml`, the version from that descriptor plus
`Cargo.toml`, and the target set from `component-targets.toml`.

## Security and portability

- No host paths, usernames, credentials, bucket names, or CDN hosts are
  hardcoded in the matrix or the tooling. The CDN URL template is the one
  already owned by `scripts/package-component.sh`.
- Unsupported targets are refused before any manifest or catalog output is
  written; the verifier also refuses wrapper directories, extra members,
  symlinks, stale descriptor versions, digest mismatches, wrong-platform
  executable magic, and non-executable Linux/macOS members.
- The protocol smoke only spawns the artifact it was given, never a shell or an
  interpreter, bounds every response frame to the protocol's 256 KiB limit, and
  stops that child on any failure.
- The packer writes canonical `<sha256>  <name>` checksum lines on every host
  (including Git-Bash/MSYS binary mode), so the manifest the publisher reads is
  the manifest the verifier checked.
- Publication remains tag-only and read-back verified in
  `scripts/publish-component.sh`; this change does not tag, upload, or mutate
  R2 state.

## Open points

- `x86_64-unknown-linux-musl`: needs a static musl build plus a native Alpine
  test leg covering `aws-lc-sys` and the platform trust store.
- `aarch64-pc-windows-msvc`: needs a native Windows arm64 runner and ABI proof.
- The `extensions/catalog.v1` merge job (multi-component) remains a follow-up;
  this repository only proves its own row fragment.
