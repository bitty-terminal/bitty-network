#!/usr/bin/env bash
# component-release.test.sh — fixture gates for the reusable release tooling.
#
# No Rust build, no network, no R2 access. Covers the release-matrix gate
# (including "every bitty-component.toml repo publishes at least one
# supported target"), manifest regeneration, the catalog.v1 row fragment
# with its digest/archive verification, the generated per-target digest
# record, and the executable mode/magic gate.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ROOT
readonly SCRIPT="$ROOT/scripts/component-release.sh"
scratch_root="${TMPDIR:-/tmp/bitty}"
mkdir -p -- "$scratch_root"
TMP_BASE="$(mktemp -d "$scratch_root/component-release-test.XXXXXX")"
readonly TMP_BASE
cleanup() { rm -rf -- "$TMP_BASE"; }
trap cleanup EXIT

pass() { printf 'ok: %s\n' "$1"; }

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}

# sha256 <file>... — GNU sha256sum when present, otherwise the BSD-compatible
# shasum shipped with macOS. Mirrors the fallback in scripts/package-component.sh.
sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

# sed_inplace <expr> <file> — BSD sed requires an explicit -i suffix, GNU sed
# does not, so edit through a temporary file instead.
sed_inplace() {
	local expr="$1"
	local file="$2"
	sed "$expr" "$file" >"$file.tmp"
	command mv "$file.tmp" "$file"
}

expect_failure() {
	local name="$1"
	shift
	if "$@" >"$TMP_BASE/last-output" 2>&1; then
		printf 'unexpected output:\n' >&2
		cat "$TMP_BASE/last-output" >&2 || true
		fail "$name unexpectedly passed"
	fi
	pass "$name rejected"
}

# new_repo <name> — write a valid two-target fixture repository and print its
# path. Callers mutate one file to exercise a specific gate.
new_repo() {
	local name="$1"
	local dir="$TMP_BASE/$name"
	mkdir -p "$dir"
	cat >"$dir/bitty-component.toml" <<'EOF'
[component]
name = "demo"
version = "1.2.3"
protocol = [1, 1]
executable = "bitty-demo"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
EOF
	cat >"$dir/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "1.2.3"
EOF
	cat >"$dir/component-targets.toml" <<'EOF'
schema = 1

[[target]]
triple = "x86_64-unknown-linux-gnu"
os = "linux"
arch = "x86_64"
runner = "ubuntu-24.04"
supported = true

[[target]]
triple = "x86_64-pc-windows-msvc"
os = "windows"
arch = "x86_64"
runner = "windows-2025"
supported = true

[[target]]
triple = "aarch64-pc-windows-msvc"
os = "windows"
arch = "aarch64"
supported = false
reason = "deferred until a Windows arm64 runner and ABI proof exist"
EOF
	printf '%s\n' "$dir"
}

# write_fake_executable <path> <target> — a plausible native payload so the
# verifier's executable-magic gate sees the platform it expects. The bytes
# are not executed; fixture tests never spawn them.
write_fake_executable() {
	local path="$1"
	local target="$2"
	case "$target" in
	*-linux-*) printf '\177ELF\002\001\001\000fixture\n' >"$path" ;;
	*-apple-*) printf '\317\372\355\376fixture\n' >"$path" ;;
	*-windows-*) printf 'MZfixture\n' >"$path" ;;
	*) fail "no fake executable magic for target $target" ;;
	esac
	chmod 755 "$path"
}

# make_tarball <repo> <dist> <target> <windows:0|1> <extra:0|1>
# Stages the fake executable plus a descriptor carrying its digest, then
# packs the exact two-member archive shape.
make_tarball() {
	local repo="$1"
	local dist="$2"
	local target="$3"
	local windows="$4"
	local extra="$5"
	local stage="$TMP_BASE/stage-$target-$extra"
	local executable="bitty-demo"
	if [[ "$windows" -eq 1 ]]; then
		executable="bitty-demo.exe"
	fi
	mkdir -p "$stage" "$dist"
	write_fake_executable "$stage/$executable" "$target"
	local digest
	digest="$(sha256 "$stage/$executable" | cut -d' ' -f1)"
	sed "s/^sha256 = \".*\"$/sha256 = \"$digest\"/" "$repo/bitty-component.toml" >"$stage/bitty-component.toml"
	if [[ "$extra" -eq 1 ]]; then
		printf 'stray\n' >"$stage/README.md"
		tar -czf "$dist/$target.tar.gz" -C "$stage" bitty-component.toml "$executable" README.md
	else
		tar -czf "$dist/$target.tar.gz" -C "$stage" bitty-component.toml "$executable"
	fi
}

# --- 1. the real repository passes the release gate ---
"$SCRIPT" check >/dev/null || fail "current repository failed the release gate"
pass "current repository passes the release gate"

# --- 2. valid fixture: check, list, and JSON matrix ---
repo="$(new_repo valid)"
"$SCRIPT" check --root "$repo" >/dev/null || fail "valid fixture failed check"
pass "valid fixture passes check"

list="$("$SCRIPT" targets --root "$repo")"
expected_list=$'x86_64-pc-windows-msvc\nx86_64-unknown-linux-gnu'
[[ "$list" == "$expected_list" ]] || fail "supported target list is not the pinned pair: $list"
pass "supported target list is stable and sorted"

matrix_json="$("$SCRIPT" targets --root "$repo" --format json)"
expected_json='{"include":[{"target":"x86_64-pc-windows-msvc","os":"windows","runner":"windows-2025"},{"target":"x86_64-unknown-linux-gnu","os":"linux","runner":"ubuntu-24.04"}]}'
[[ "$matrix_json" == "$expected_json" ]] || fail "matrix JSON drifted: $matrix_json"
pass "GitHub Actions matrix JSON is stable"

# --- 3. gate rejections ---
repo="$(new_repo no-supported)"
cat >"$repo/component-targets.toml" <<'EOF'
schema = 1

[[target]]
triple = "aarch64-pc-windows-msvc"
os = "windows"
arch = "aarch64"
supported = false
reason = "no runner"
EOF
expect_failure "matrix with zero supported targets" "$SCRIPT" check --root "$repo"

repo="$(new_repo duplicate)"
cat >>"$repo/component-targets.toml" <<'EOF'

[[target]]
triple = "x86_64-unknown-linux-gnu"
os = "linux"
arch = "x86_64"
runner = "ubuntu-24.04"
supported = true
EOF
expect_failure "duplicate target triple" "$SCRIPT" check --root "$repo"

repo="$(new_repo unknown)"
cat >>"$repo/component-targets.toml" <<'EOF'

[[target]]
triple = "mips-unknown-linux-gnu"
os = "linux"
arch = "x86_64"
runner = "ubuntu-24.04"
supported = true
EOF
expect_failure "target the Core installer never requests" "$SCRIPT" check --root "$repo"

repo="$(new_repo no-runner)"
sed_inplace '/^runner = "ubuntu-24.04"$/d' "$repo/component-targets.toml"
expect_failure "supported target without a runner" "$SCRIPT" check --root "$repo"

repo="$(new_repo no-reason)"
cat >"$repo/component-targets.toml" <<'EOF'
schema = 1

[[target]]
triple = "x86_64-unknown-linux-gnu"
os = "linux"
arch = "x86_64"
runner = "ubuntu-24.04"
supported = true

[[target]]
triple = "aarch64-pc-windows-msvc"
os = "windows"
arch = "aarch64"
supported = false
EOF
expect_failure "unsupported target without a documented reason" "$SCRIPT" check --root "$repo"

repo="$(new_repo unsupported-runner)"
cat >>"$repo/component-targets.toml" <<'EOF'
runner = "windows-2025"
EOF
expect_failure "unsupported target declaring a runner" "$SCRIPT" check --root "$repo"

repo="$(new_repo os-arch-mismatch)"
sed_inplace 's/^os = "linux"$/os = "macos"/' "$repo/component-targets.toml"
expect_failure "os/arch mismatch for a known triple" "$SCRIPT" check --root "$repo"

repo="$(new_repo version-drift)"
sed_inplace 's/^version = "1\.2\.3"$/version = "1.2.4"/' "$repo/Cargo.toml"
expect_failure "Cargo/descriptor version drift" "$SCRIPT" check --root "$repo"

# --- 3b. Cargo version inherited from [workspace.package] ---
# `version.workspace = true` is a TOML table, not a string: the resolver must
# fall through to [workspace.package].version instead of rejecting it.
repo="$(new_repo inherited-version)"
cat >"$repo/Cargo.toml" <<'EOF'
[package]
name = "demo"
version.workspace = true

[workspace.package]
version = "1.2.3"
EOF
"$SCRIPT" check --root "$repo" >/dev/null ||
	fail "workspace-inherited Cargo version failed check"
pass "workspace-inherited Cargo version resolves through [workspace.package]"

repo="$(new_repo inherited-drift)"
cat >"$repo/Cargo.toml" <<'EOF'
[package]
name = "demo"
version.workspace = true

[workspace.package]
version = "9.9.9"
EOF
expect_failure "workspace-inherited Cargo version drift" "$SCRIPT" check --root "$repo"

repo="$(new_repo executable-drift)"
sed_inplace 's/^executable = "bitty-demo"$/executable = "bitty-other"/' "$repo/bitty-component.toml"
expect_failure "descriptor executable mismatch" "$SCRIPT" check --root "$repo"

repo="$(new_repo missing-matrix)"
rm -f "$repo/component-targets.toml"
expect_failure "component descriptor without a release matrix" "$SCRIPT" check --root "$repo"

repo="$(new_repo missing-descriptor)"
rm -f "$repo/bitty-component.toml"
expect_failure "release matrix without a component descriptor" "$SCRIPT" check --root "$repo"

# --- 4. manifest, catalog rows, and full-matrix verification ---
repo="$(new_repo catalog-repo)"
dist="$TMP_BASE/dist-output"
catalog_dir="$TMP_BASE/catalog"
make_tarball "$repo" "$dist" x86_64-unknown-linux-gnu 0 0
make_tarball "$repo" "$dist" x86_64-pc-windows-msvc 1 0

"$SCRIPT" manifest --root "$repo" --dist "$dist" >/dev/null || fail "manifest generation failed"
pass "manifest regenerates sidecars and SHA256SUMS"

grep -Eq '^[0-9a-f]{64}  x86_64-unknown-linux-gnu\.tar\.gz$' "$dist/SHA256SUMS" ||
	fail "SHA256SUMS is missing the Linux target"
grep -Eq '^[0-9a-f]{64}  x86_64-pc-windows-msvc\.tar\.gz$' "$dist/SHA256SUMS" ||
	fail "SHA256SUMS is missing the Windows target"
(cd "$dist" && sha256 -c SHA256SUMS >/dev/null) || fail "SHA256SUMS does not verify"
pass "SHA256SUMS covers every packaged target and verifies"

# --- 4a. GNU binary-mode markers are not canonical checksum lines ---
# Git-Bash/MSYS sha256sum writes "<hex> *<name>". The packer normalizes that
# marker (see 4b); the verifier must reject it, so a platform-specific line
# can never be read as release proof.
binary_marker="$TMP_BASE/binary-marker"
mkdir -p "$binary_marker"
cp "$dist"/*.tar.gz "$dist"/*.sha256 "$dist/SHA256SUMS" "$binary_marker/"
sed 's/^\([0-9a-f]\{64\}\)  /\1 */' "$dist/SHA256SUMS" >"$binary_marker/SHA256SUMS"
expect_failure "SHA256SUMS with GNU binary-mode markers" \
	"$SCRIPT" catalog --root "$repo" --dist "$binary_marker"

marker_sidecar="$TMP_BASE/marker-sidecar"
mkdir -p "$marker_sidecar"
cp "$dist"/*.tar.gz "$dist"/*.sha256 "$dist/SHA256SUMS" "$marker_sidecar/"
sed 's/^\([0-9a-f]\{64\}\)  /\1 */' \
	"$dist/x86_64-unknown-linux-gnu.tar.gz.sha256" \
	>"$marker_sidecar/x86_64-unknown-linux-gnu.tar.gz.sha256"
expect_failure "sidecar with a GNU binary-mode marker" \
	"$SCRIPT" catalog --root "$repo" --dist "$marker_sidecar"

"$SCRIPT" catalog --root "$repo" --dist "$dist" --output "$catalog_dir/catalog.v1" >/dev/null ||
	fail "catalog generation failed"
row() {
	local target="$1"
	local digest
	digest="$(cd "$dist" && sha256 "$target.tar.gz" | cut -d' ' -f1)"
	printf 'extension demo 1.2.3 %s %s\n' "$target" "$digest"
}
expected_catalog="schema 1
$(row x86_64-pc-windows-msvc)
$(row x86_64-unknown-linux-gnu)"
[[ "$(cat "$catalog_dir/catalog.v1")" == "$expected_catalog" ]] ||
	fail "catalog rows drifted from SHA256SUMS: $(cat "$catalog_dir/catalog.v1")"
pass "catalog rows are keyed by target and match SHA256SUMS"

"$SCRIPT" verify --root "$repo" --dist "$dist" >/dev/null || fail "full-matrix verify failed"
pass "full-matrix verify accepts the complete supported set"

# --- 4a. release digest record (root descriptor keeps its placeholder) ---
record_dir="$TMP_BASE/release"
record_file="$record_dir/component-digests.toml"
"$SCRIPT" record --root "$repo" --dist "$dist" --output "$record_file" >/dev/null ||
	fail "release digest record generation failed"
grep -Fx 'schema = 1' "$record_file" >/dev/null || fail "record schema drifted"
grep -Fx 'name = "demo"' "$record_file" >/dev/null || fail "record name drifted"
grep -Fx 'version = "1.2.3"' "$record_file" >/dev/null || fail "record version drifted"
grep -Fx 'protocol = [1, 1]' "$record_file" >/dev/null || fail "record protocol drifted"
[[ "$(grep -c '^\[\[target\]\]$' "$record_file")" == "2" ]] ||
	fail "record does not cover both supported targets"
linux_tarball_digest="$(cd "$dist" && sha256 x86_64-unknown-linux-gnu.tar.gz | cut -d' ' -f1)"
grep -Fx "tarball_sha256 = \"$linux_tarball_digest\"" "$record_file" >/dev/null ||
	fail "record does not carry the Linux tarball digest"
grep -Fx 'triple = "x86_64-pc-windows-msvc"' "$record_file" >/dev/null ||
	fail "record is missing the Windows target"
"$SCRIPT" verify --root "$repo" --dist "$dist" --record "$record_file" >/dev/null ||
	fail "verify rejected the matching release digest record"
pass "release digest record covers every target and verifies"

expect_failure "record written inside dist" \
	"$SCRIPT" record --root "$repo" --dist "$dist" --output "$dist/component-digests.toml"

tampered_record="$TMP_BASE/release/tampered.toml"
awk '
	BEGIN { done = 0 }
	!done && /^tarball_sha256 = / {
		print "tarball_sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\""
		done = 1
		next
	}
	{ print }
' "$record_file" >"$tampered_record"
expect_failure "record with a drifted digest" \
	"$SCRIPT" verify --root "$repo" --dist "$dist" --record "$tampered_record"

missing_record_target="$TMP_BASE/release/missing-target.toml"
sed 's/^triple = "x86_64-pc-windows-msvc"$/triple = "aarch64-pc-windows-msvc"/' \
	"$record_file" >"$missing_record_target"
expect_failure "record missing a supported target" \
	"$SCRIPT" verify --root "$repo" --dist "$dist" --record "$missing_record_target"

wrong_record_name="$TMP_BASE/release/wrong-name.toml"
sed 's/^name = "demo"$/name = "other"/' "$record_file" >"$wrong_record_name"
expect_failure "record with the wrong component name" \
	"$SCRIPT" verify --root "$repo" --dist "$dist" --record "$wrong_record_name"

# --- 4b. the packer normalizes Git-Bash/MSYS binary-mode checksum output ---
# Git-Bash/MSYS sha256sum defaults to binary mode and prints "<hex> *<name>".
# Shadow sha256sum with a shim that reproduces that marker, then require the
# repository packer to emit canonical "<hex>  <name>" lines for the sidecar
# and the aggregate manifest, and the verifier to accept the result. The
# packer always validates the real repository descriptor, so this fixture
# packs the real component name against a fake ELF payload.
msys_shim="$TMP_BASE/msys-shim"
mkdir -p "$msys_shim"
cat >"$msys_shim/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# `command -p -v` resolves through the default PATH without executing the
# tool: a bare `sha256sum` with no argument would read stdin and block.
if command -p -v sha256sum >/dev/null 2>&1; then
	digest="$(command -p sha256sum "$@" </dev/null | cut -d' ' -f1)"
else
	digest="$(command -p shasum -a 256 "$@" </dev/null | cut -d' ' -f1)"
fi
printf '%s *%s\n' "$digest" "$(basename "${@: -1}")"
EOF
chmod 755 "$msys_shim/sha256sum"

writer_dist="$TMP_BASE/writer-dist"
writer_stage="$TMP_BASE/writer-stage"
mkdir -p "$writer_dist" "$writer_stage"
write_fake_executable "$writer_stage/bitty-net" x86_64-unknown-linux-gnu
repo_version="$(awk -F'"' '$1 ~ /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }' \
	"$ROOT/bitty-component.toml")"
PATH="$msys_shim:$PATH" "$ROOT/scripts/package-component.sh" \
	--version "$repo_version" --target x86_64-unknown-linux-gnu \
	--binary "$writer_stage/bitty-net" \
	--output "$writer_dist/x86_64-unknown-linux-gnu.tar.gz" >/dev/null ||
	fail "package-component rejected MSYS-style sha256sum output"
grep -Eq '^[0-9a-f]{64}  x86_64-unknown-linux-gnu\.tar\.gz$' "$writer_dist/SHA256SUMS" ||
	fail "SHA256SUMS kept a binary-mode marker: $(cat "$writer_dist/SHA256SUMS")"
grep -Eq '^[0-9a-f]{64}  x86_64-unknown-linux-gnu\.tar\.gz$' \
	"$writer_dist/x86_64-unknown-linux-gnu.tar.gz.sha256" ||
	fail "sidecar kept a binary-mode marker: $(cat "$writer_dist/x86_64-unknown-linux-gnu.tar.gz.sha256")"
"$SCRIPT" catalog --dist "$writer_dist" >/dev/null ||
	fail "catalog rejected the packer's canonical checksum lines"
pass "package-component normalizes binary-mode checksum markers"

# --- 4c. a target's payload must be a plausible native executable ---
# A tarball named for Linux must not carry a PE payload, and a Linux
# executable must keep its execute bit. Both are checked before cataloging.
bad_magic="$TMP_BASE/bad-magic"
bad_magic_stage="$TMP_BASE/bad-magic-stage"
mkdir -p "$bad_magic" "$bad_magic_stage"
cp "$dist"/x86_64-pc-windows-msvc.tar.gz* "$bad_magic/"
printf 'MZnot-a-linux-executable\n' >"$bad_magic_stage/bitty-demo"
chmod 755 "$bad_magic_stage/bitty-demo"
digest="$(sha256 "$bad_magic_stage/bitty-demo" | cut -d' ' -f1)"
sed "s/^sha256 = \".*\"$/sha256 = \"$digest\"/" \
	"$repo/bitty-component.toml" >"$bad_magic_stage/bitty-component.toml"
tar -czf "$bad_magic/x86_64-unknown-linux-gnu.tar.gz" \
	-C "$bad_magic_stage" bitty-component.toml bitty-demo
"$SCRIPT" manifest --root "$repo" --dist "$bad_magic" >/dev/null
expect_failure "Linux artifact carrying a PE payload" \
	"$SCRIPT" catalog --root "$repo" --dist "$bad_magic"

not_executable="$TMP_BASE/not-executable"
not_executable_stage="$TMP_BASE/not-executable-stage"
mkdir -p "$not_executable" "$not_executable_stage"
cp "$dist"/x86_64-pc-windows-msvc.tar.gz* "$not_executable/"
write_fake_executable "$not_executable_stage/bitty-demo" x86_64-unknown-linux-gnu
chmod 644 "$not_executable_stage/bitty-demo"
digest="$(sha256 "$not_executable_stage/bitty-demo" | cut -d' ' -f1)"
sed "s/^sha256 = \".*\"$/sha256 = \"$digest\"/" \
	"$repo/bitty-component.toml" >"$not_executable_stage/bitty-component.toml"
tar -czf "$not_executable/x86_64-unknown-linux-gnu.tar.gz" \
	-C "$not_executable_stage" bitty-component.toml bitty-demo
"$SCRIPT" manifest --root "$repo" --dist "$not_executable" >/dev/null
expect_failure "Linux artifact without an execute bit" \
	"$SCRIPT" catalog --root "$repo" --dist "$not_executable"

protocol_drift="$TMP_BASE/protocol-drift"
protocol_drift_stage="$TMP_BASE/protocol-drift-stage"
mkdir -p "$protocol_drift" "$protocol_drift_stage"
cp "$dist"/x86_64-pc-windows-msvc.tar.gz* "$protocol_drift/"
write_fake_executable "$protocol_drift_stage/bitty-demo" x86_64-unknown-linux-gnu
digest="$(sha256 "$protocol_drift_stage/bitty-demo" | cut -d' ' -f1)"
sed -e 's/^protocol = \[1, 1\]$/protocol = [1, 2]/' \
	-e "s/^sha256 = \".*\"$/sha256 = \"$digest\"/" \
	"$repo/bitty-component.toml" >"$protocol_drift_stage/bitty-component.toml"
tar -czf "$protocol_drift/x86_64-unknown-linux-gnu.tar.gz" \
	-C "$protocol_drift_stage" bitty-component.toml bitty-demo
"$SCRIPT" manifest --root "$repo" --dist "$protocol_drift" >/dev/null
expect_failure "archive descriptor with drifted protocol bounds" \
	"$SCRIPT" catalog --root "$repo" --dist "$protocol_drift"

# --- 5. unsupported or unverified bytes never reach the catalog ---
partial="$TMP_BASE/partial"
mkdir -p "$partial"
cp "$dist"/x86_64-unknown-linux-gnu.tar.gz* "$partial/"
"$SCRIPT" manifest --root "$repo" --dist "$partial" >/dev/null
expect_failure "verify on a partial matrix" "$SCRIPT" verify --root "$repo" --dist "$partial"
"$SCRIPT" catalog --root "$repo" --dist "$partial" >/dev/null ||
	fail "per-target catalog failed on a partial dist"
pass "per-target catalog accepts one verified target"

unsupported_dist="$TMP_BASE/unsupported-dist"
mkdir -p "$unsupported_dist"
cp "$dist"/x86_64-unknown-linux-gnu.tar.gz* "$unsupported_dist/"
make_tarball "$repo" "$unsupported_dist" aarch64-pc-windows-msvc 1 0
expect_failure "manifest with an unsupported target tarball" \
	"$SCRIPT" manifest --root "$repo" --dist "$unsupported_dist"

wrapped="$TMP_BASE/wrapped"
mkdir -p "$wrapped"
stage="$TMP_BASE/wrapped-stage"
mkdir -p "$stage/pkg"
make_tarball "$repo" "$TMP_BASE/wrapped-source" x86_64-unknown-linux-gnu 0 0
tar -xzf "$TMP_BASE/wrapped-source/x86_64-unknown-linux-gnu.tar.gz" -C "$stage/pkg"
tar -czf "$wrapped/x86_64-unknown-linux-gnu.tar.gz" -C "$stage" pkg
"$SCRIPT" manifest --root "$repo" --dist "$wrapped" >/dev/null
expect_failure "archive with a wrapper directory" \
	"$SCRIPT" catalog --root "$repo" --dist "$wrapped"

tampered="$TMP_BASE/tampered"
mkdir -p "$tampered"
cp "$dist"/x86_64-unknown-linux-gnu.tar.gz* "$tampered/"
"$SCRIPT" manifest --root "$repo" --dist "$tampered" >/dev/null
printf 'tamper' >>"$tampered/x86_64-unknown-linux-gnu.tar.gz"
expect_failure "tarball digest drift after manifest" \
	"$SCRIPT" catalog --root "$repo" --dist "$tampered"

missing_sidecar="$TMP_BASE/missing-sidecar"
mkdir -p "$missing_sidecar"
cp "$dist"/x86_64-unknown-linux-gnu.tar.gz "$missing_sidecar/"
cp "$dist/SHA256SUMS" "$missing_sidecar/"
expect_failure "missing per-target sidecar" \
	"$SCRIPT" catalog --root "$repo" --dist "$missing_sidecar"

stale_descriptor="$TMP_BASE/stale-descriptor"
stage="$TMP_BASE/stale-stage"
mkdir -p "$stale_descriptor" "$stage"
write_fake_executable "$stage/bitty-demo" x86_64-unknown-linux-gnu
digest="$(sha256 "$stage/bitty-demo" | cut -d' ' -f1)"
cat >"$stage/bitty-component.toml" <<EOF
[component]
name = "demo"
version = "9.9.9"
protocol = [1, 1]
executable = "bitty-demo"
sha256 = "$digest"
EOF
tar -czf "$stale_descriptor/x86_64-unknown-linux-gnu.tar.gz" -C "$stage" bitty-component.toml bitty-demo
"$SCRIPT" manifest --root "$repo" --dist "$stale_descriptor" >/dev/null
expect_failure "stale descriptor version inside the archive" \
	"$SCRIPT" catalog --root "$repo" --dist "$stale_descriptor"

bad_digest="$TMP_BASE/bad-digest"
stage="$TMP_BASE/bad-digest-stage"
mkdir -p "$bad_digest" "$stage"
write_fake_executable "$stage/bitty-demo" x86_64-unknown-linux-gnu
sed 's/^sha256 = ".*"$/sha256 = "1111111111111111111111111111111111111111111111111111111111111111"/' \
	"$repo/bitty-component.toml" >"$stage/bitty-component.toml"
tar -czf "$bad_digest/x86_64-unknown-linux-gnu.tar.gz" -C "$stage" bitty-component.toml bitty-demo
"$SCRIPT" manifest --root "$repo" --dist "$bad_digest" >/dev/null
expect_failure "descriptor digest mismatch inside the archive" \
	"$SCRIPT" catalog --root "$repo" --dist "$bad_digest"

printf 'component-release.test: PASS\n'
