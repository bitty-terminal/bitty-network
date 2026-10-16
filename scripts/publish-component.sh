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

mapfile -t files < <(find "$PACKAGE_DIR" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
[[ "${#files[@]}" -gt 1 ]] || die "package directory is empty"
[[ " ${files[*]} " == *" SHA256SUMS "* ]] || die "package is missing SHA256SUMS"
(cd "$PACKAGE_DIR" && sha256sum -c SHA256SUMS >/dev/null) || die "SHA256SUMS does not verify"

for file in "${files[@]}"; do
	case "$file" in
	SHA256SUMS | *.tar.gz | *.tar.gz.sha256) ;;
	*) die "unexpected package file: $file" ;;
	esac
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
