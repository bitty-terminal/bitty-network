#!/usr/bin/env bash
# Publish an already validated net component directory to immutable R2 keys.
# This script is intentionally tag-only and never overwrites an existing key.
set -euo pipefail

PACKAGE_DIR="${1:-}"
VERSION="${2:-${COMPONENT_VERSION:-}}"
R2_BUCKET="${R2_BUCKET:-}"
R2_PREFIX="${R2_PREFIX:-extensions}"
WRANGLER_BIN="${WRANGLER_BIN:-wrangler}"

die() {
	printf 'publish-component: ERROR: %s\n' "$1" >&2
	exit 1
}

[[ -n "$PACKAGE_DIR" && -d "$PACKAGE_DIR" ]] || die "package directory is required"
[[ -n "$VERSION" && "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die "version must be strict X.Y.Z"
[[ "${GITHUB_REF_TYPE:-}" == "tag" ]] || die "publication is allowed only for a tag ref"
[[ -z "${GITHUB_REF_NAME:-}" || "${GITHUB_REF_NAME#v}" == "$VERSION" ]] || die "tag version does not match package version"
[[ -n "$R2_BUCKET" ]] || die "R2_BUCKET is required"
[[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || die "CLOUDFLARE_API_TOKEN is required"
[[ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ]] || die "CLOUDFLARE_ACCOUNT_ID is required"
command -v "$WRANGLER_BIN" >/dev/null 2>&1 || die "wrangler is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v cmp >/dev/null 2>&1 || die "cmp is required"

valid_target() {
	[[ "$1" =~ ^[a-z0-9_]+(-[a-z0-9_]+)+$ ]]
}

mapfile -t files < <(find "$PACKAGE_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
[[ "${#files[@]}" -gt 1 ]] || die "package directory is empty"
for file in "${files[@]}"; do
	[[ -f "$PACKAGE_DIR/$file" && ! -L "$PACKAGE_DIR/$file" ]] || die "package entry is not a regular file: $file"
done
[[ -f "$PACKAGE_DIR/SHA256SUMS" ]] || die "package is missing SHA256SUMS"

archive_names=()
sidecar_names=()
for file in "${files[@]}"; do
	case "$file" in
	SHA256SUMS) ;;
	*.tar.gz)
		valid_target "${file%.tar.gz}" || die "archive basename is not a target triple: $file"
		archive_names+=("$file")
		;;
	*.tar.gz.sha256)
		valid_target "${file%.tar.gz.sha256}" || die "sidecar basename is not a target triple: $file"
		sidecar_names+=("$file")
		;;
	*) die "unexpected package file: $file" ;;
	esac
done
[[ "${#archive_names[@]}" -gt 0 ]] || die "package contains no archives"
[[ "${#archive_names[@]}" == "${#sidecar_names[@]}" ]] || die "every archive must have one sidecar"

expected_files=(SHA256SUMS)
for archive in "${archive_names[@]}"; do
	expected_files+=("$archive" "$archive.sha256")
done
expected_file_list="$(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)"
actual_file_list="$(printf '%s\n' "${files[@]}")"
[[ "$actual_file_list" == "$expected_file_list" ]] || die "package file set is not exactly archives, sidecars, and SHA256SUMS"

manifest_names=()
while IFS= read -r line; do
	[[ "$line" =~ ^[0-9a-f]{64}[[:space:]]{2}([^[:space:]]+)$ ]] || die "SHA256SUMS contains a malformed line"
	manifest_name="${BASH_REMATCH[1]}"
	[[ "$manifest_name" == *.tar.gz ]] || die "SHA256SUMS lists a non-archive: $manifest_name"
	valid_target "${manifest_name%.tar.gz}" || die "SHA256SUMS lists an invalid archive: $manifest_name"
	[[ -f "$PACKAGE_DIR/$manifest_name" ]] || die "SHA256SUMS lists a missing archive: $manifest_name"
	for existing in "${manifest_names[@]}"; do
		[[ "$existing" != "$manifest_name" ]] || die "SHA256SUMS lists an archive more than once: $manifest_name"
	done
	manifest_names+=("$manifest_name")
done <"$PACKAGE_DIR/SHA256SUMS"
[[ "${#manifest_names[@]}" == "${#archive_names[@]}" ]] || die "SHA256SUMS does not list exactly every archive"
expected_manifest="$(printf '%s\n' "${archive_names[@]}" | LC_ALL=C sort)"
actual_manifest="$(printf '%s\n' "${manifest_names[@]}" | LC_ALL=C sort)"
[[ "$actual_manifest" == "$expected_manifest" ]] || die "SHA256SUMS archive set is incomplete or has extras"
(cd "$PACKAGE_DIR" && sha256sum -c SHA256SUMS >/dev/null) || die "SHA256SUMS does not verify"

for archive in "${archive_names[@]}"; do
	cmp -s <(cd "$PACKAGE_DIR" && sha256sum "$archive") "$PACKAGE_DIR/$archive.sha256" || die "sidecar digest does not match archive: $archive.sha256"
done

scratch_root="${TMPDIR:-/tmp/bitty}"
mkdir -p -- "$scratch_root"
temporary_dir="$(mktemp -d "$scratch_root/component-publish.XXXXXX")"
cleanup() { rm -rf -- "$temporary_dir"; }
trap cleanup EXIT

for file in "${files[@]}"; do
	key="$R2_BUCKET/$R2_PREFIX/net/$VERSION/$file"
	remote="$temporary_dir/remote"
	error_file="$temporary_dir/error"
	if "$WRANGLER_BIN" r2 object get "$key" --remote --pipe >"$remote" 2>"$error_file"; then
		cmp -s "$PACKAGE_DIR/$file" "$remote" || die "immutable R2 object differs: $key"
		printf 'skip %s: immutable object already matches\n' "$key"
		continue
	else
		status=$?
	fi
	if ! grep -qiE 'not[ _-]?found|NoSuchKey|404|does not exist' "$error_file"; then
		die "R2 get-before-put failed for $key (exit $status): $(tr '\n' ' ' <"$error_file")"
	fi
	"$WRANGLER_BIN" r2 object put "$key" --file "$PACKAGE_DIR/$file" --remote --cache-control 'public, max-age=31536000, immutable' -y
	"$WRANGLER_BIN" r2 object get "$key" --remote --pipe >"$remote"
	cmp -s "$PACKAGE_DIR/$file" "$remote" || die "R2 read-back differs: $key"
	printf 'uploaded and verified %s\n' "$key"
done
