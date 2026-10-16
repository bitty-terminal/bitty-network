#!/usr/bin/env bash
# Package one bitty-net target using the DIR-030 component layout.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly REPO_ROOT
readonly DESCRIPTOR_TEMPLATE="$REPO_ROOT/bitty-component.toml"
readonly DESCRIPTOR_FILE="bitty-component.toml"
readonly EXECUTABLE="bitty-net"
readonly ZERO_DIGEST="0000000000000000000000000000000000000000000000000000000000000000"
readonly DEFAULT_CDN_BASE="https://cdn.bitty.run"
readonly MAX_DESCRIPTOR_BYTES=4096
readonly MAX_BINARY_BYTES=268435456

VERSION=""
TARGET=""
BINARY=""
OUTPUT=""
PRINT_URL=0
CDN_BASE="${BITTY_CDN_BASE:-$DEFAULT_CDN_BASE}"

die() {
	printf 'package-component: ERROR: %s\n' "$1" >&2
	exit 1
}

usage() {
	cat <<'EOF'
Usage: scripts/package-component.sh --target TRIPLE --binary PATH --output PATH [--version X.Y.Z]
       scripts/package-component.sh --print-url --target TRIPLE [--version X.Y.Z]

  --target TRIPLE  Rust target triple; output basename must be TRIPLE.tar.gz
  --binary PATH    bitty-net executable built for TRIPLE
  --output PATH    output archive path
  --version X.Y.Z  descriptor version (defaults to bitty-component.toml)
  --print-url      print the archive URL and SHA256SUMS URL without writing
  --cdn-base URL   CDN base for --print-url (default: BITTY_CDN_BASE or public CDN)
EOF
}

valid_version() {
	[[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

valid_target() {
	[[ "$1" =~ ^[a-z0-9_]+(-[a-z0-9_]+)+$ ]]
}

valid_cdn_base() {
	[[ "$1" =~ ^https://[A-Za-z0-9.-]+$ ]]
}

validate_archive_version() {
	local archive="$1"
	local archive_descriptor archive_version
	archive_descriptor="$(tar -xOzf "$archive" "$DESCRIPTOR_FILE" 2>/dev/null)" || die "archive has no readable $DESCRIPTOR_FILE: $archive"
	archive_version="$(awk -F'"' '$1 ~ /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }' <<<"$archive_descriptor")"
	valid_version "$archive_version" || die "archive has an invalid descriptor version: $archive"
	[[ "$archive_version" == "$VERSION" ]] || die "archive version $archive_version differs from requested version $VERSION: $archive"
}

if command -v sha256sum >/dev/null 2>&1; then
	SHA256SUM=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
	SHA256SUM=(shasum -a 256)
else
	die "sha256sum or shasum is required"
fi
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v gzip >/dev/null 2>&1 || die "gzip is required"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--target)
		TARGET="${2:-}"
		shift 2
		;;
	--binary)
		BINARY="${2:-}"
		shift 2
		;;
	--output)
		OUTPUT="${2:-}"
		shift 2
		;;
	--version)
		VERSION="${2:-}"
		shift 2
		;;
	--print-url)
		PRINT_URL=1
		shift
		;;
	--cdn-base)
		CDN_BASE="${2:-}"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		die "unknown argument: $1"
		;;
	esac
done

[[ -f "$DESCRIPTOR_TEMPLATE" && ! -L "$DESCRIPTOR_TEMPLATE" ]] || die "root descriptor is missing"
descriptor_size="$(wc -c <"$DESCRIPTOR_TEMPLATE" | tr -d ' ')"
[[ "$descriptor_size" -le "$MAX_DESCRIPTOR_BYTES" ]] || die "root descriptor exceeds $MAX_DESCRIPTOR_BYTES bytes"

template_version="$(awk -F'"' '$1 ~ /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }' "$DESCRIPTOR_TEMPLATE")"
[[ -n "$VERSION" ]] || VERSION="$template_version"
valid_version "$VERSION" || die "version must be strict X.Y.Z: $VERSION"
[[ "$template_version" == "$VERSION" ]] || die "version $VERSION differs from root descriptor $template_version"

grep -Fx '[component]' "$DESCRIPTOR_TEMPLATE" >/dev/null || die "root descriptor must contain [component]"
grep -Fx 'name = "net"' "$DESCRIPTOR_TEMPLATE" >/dev/null || die "root descriptor name must be net"
grep -Fx 'protocol = [1, 1]' "$DESCRIPTOR_TEMPLATE" >/dev/null || die "root descriptor protocol must be [1, 1]"
grep -Fx 'executable = "bitty-net"' "$DESCRIPTOR_TEMPLATE" >/dev/null || die "root descriptor executable must be bitty-net"
grep -Fx "sha256 = \"$ZERO_DIGEST\"" "$DESCRIPTOR_TEMPLATE" >/dev/null || die "root descriptor must use the zero digest sentinel"

valid_target "$TARGET" || die "target must look like a Rust target triple: $TARGET"
if [[ "$PRINT_URL" -eq 1 ]]; then
	valid_cdn_base "$CDN_BASE" || die "CDN base must be an HTTPS host without a path"
	printf '%s/extensions/net/%s/%s.tar.gz\n' "$CDN_BASE" "$VERSION" "$TARGET"
	printf '%s/extensions/net/%s/SHA256SUMS\n' "$CDN_BASE" "$VERSION"
	exit 0
fi

[[ -n "$BINARY" ]] || die "--binary is required"
[[ -f "$BINARY" && ! -L "$BINARY" ]] || die "binary is missing or is a symlink: $BINARY"
[[ -n "$OUTPUT" ]] || die "--output is required"
[[ "$(basename -- "$OUTPUT")" == "$TARGET.tar.gz" ]] || die "output basename must be $TARGET.tar.gz"
binary_size="$(wc -c <"$BINARY" | tr -d ' ')"
[[ "$binary_size" -gt 0 ]] || die "binary is empty"
[[ "$binary_size" -le "$MAX_BINARY_BYTES" ]] || die "binary exceeds $MAX_BINARY_BYTES bytes"

binary_digest="$("${SHA256SUM[@]}" "$BINARY" | awk '{print $1}')"
[[ "$binary_digest" =~ ^[0-9a-f]{64}$ ]] || die "digest tool returned invalid SHA-256"
if [[ "$OUTPUT" != /* ]]; then
	OUTPUT="$PWD/${OUTPUT#./}"
fi
output_dir="$(dirname -- "$OUTPUT")"
mkdir -p -- "$output_dir"
shopt -s nullglob
existing_tarballs=("$output_dir"/*.tar.gz)
shopt -u nullglob
for candidate in "${existing_tarballs[@]}"; do
	[[ -f "$candidate" && ! -L "$candidate" ]] || die "archive is not a regular file: $candidate"
	candidate_name="$(basename -- "$candidate")"
	valid_target "${candidate_name%.tar.gz}" || die "archive basename is not a target triple: $candidate_name"
	[[ "$candidate" == "$OUTPUT" ]] || validate_archive_version "$candidate"
done
scratch_root="${TMPDIR:-/tmp/bitty}"
mkdir -p -- "$scratch_root"
stage_dir="$(mktemp -d "$scratch_root/component-package.XXXXXX")"
cleanup() { rm -rf -- "$stage_dir"; }
trap cleanup EXIT

awk -v digest="$binary_digest" '
  /^[[:space:]]*sha256[[:space:]]*=/ { print "sha256 = \"" digest "\""; next }
  { print }
' "$DESCRIPTOR_TEMPLATE" >"$stage_dir/$DESCRIPTOR_FILE"

archive_executable="$EXECUTABLE"
if [[ "$TARGET" == *-windows-* ]]; then
	archive_executable="$EXECUTABLE.exe"
fi
cp -- "$BINARY" "$stage_dir/$archive_executable"
chmod 755 "$stage_dir/$archive_executable"

rm -f -- "$OUTPUT"
tar -czf "$OUTPUT" -C "$stage_dir" "$DESCRIPTOR_FILE" "$archive_executable"
expected_members="$(printf '%s\n%s\n' "$DESCRIPTOR_FILE" "$archive_executable" | LC_ALL=C sort)"
actual_members="$(tar -tzf "$OUTPUT" | LC_ALL=C sort)"
[[ "$actual_members" == "$expected_members" ]] || die "archive members are not exactly descriptor plus executable"

shopt -s nullglob
tarballs=()
for candidate in "$output_dir"/*.tar.gz; do
	candidate_name="$(basename -- "$candidate")"
	candidate_target="${candidate_name%.tar.gz}"
	if valid_target "$candidate_target"; then
		tarballs+=("$candidate_name")
	fi
done
shopt -u nullglob
[[ "${#tarballs[@]}" -gt 0 ]] || die "no target archives found in $output_dir"
printf '%s\n' "${tarballs[@]}" | LC_ALL=C sort >"$output_dir/.component-targets"
mapfile -t archive_names <"$output_dir/.component-targets"
(cd -- "$output_dir" && for archive_name in "${archive_names[@]}"; do
	"${SHA256SUM[@]}" "$archive_name" >"$archive_name.sha256"
done)
for archive_name in "${archive_names[@]}"; do
	validate_archive_version "$output_dir/$archive_name"
done
(cd -- "$output_dir" && "${SHA256SUM[@]}" "${archive_names[@]}" | LC_ALL=C sort -k2 >SHA256SUMS)
rm -f -- "$output_dir/.component-targets"
(cd -- "$output_dir" && "${SHA256SUM[@]}" -c SHA256SUMS >/dev/null) || die "SHA256SUMS verification failed"

printf 'package-component: PASS (target=%s, version=%s, output=%s)\n' "$TARGET" "$VERSION" "$OUTPUT"
