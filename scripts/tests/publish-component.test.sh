#!/usr/bin/env bash
# Publisher validation test: fake R2, no network access.
set -euo pipefail

cd -- "$(dirname -- "$0")/../.."
readonly PACKAGE_SCRIPT=./scripts/package-component.sh
readonly PUBLISH_SCRIPT=./scripts/publish-component.sh
scratch_root="${TMPDIR:-/tmp/bitty}"
mkdir -p -- "$scratch_root"
TMP_BASE="$(mktemp -d "$scratch_root/publish-component-test.XXXXXX")"
readonly TMP_BASE
cleanup() { rm -rf -- "$TMP_BASE"; }
trap cleanup EXIT

version="$(awk -F'"' '$1 ~ /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }' bitty-component.toml)"
[[ -n "$version" ]] || {
	printf 'root descriptor version is missing\n' >&2
	exit 1
}
source_dir="$TMP_BASE/source"
package_dir="$TMP_BASE/package"
mkdir -p -- "$source_dir" "$package_dir"
printf '#!/bin/sh\necho bitty-net %s\n' "$version" >"$source_dir/bitty-net"
chmod 755 "$source_dir/bitty-net"
"$PACKAGE_SCRIPT" --version "$version" --target x86_64-unknown-linux-gnu \
	--binary "$source_dir/bitty-net" --output "$package_dir/x86_64-unknown-linux-gnu.tar.gz" >/dev/null

wrangler_bin="$TMP_BASE/wrangler"
storage_dir="$TMP_BASE/storage"
operation_log="$TMP_BASE/operations"
mkdir -p -- "$storage_dir"
cat >"$wrangler_bin" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

storage_dir="${FAKE_R2_STORAGE:?}"
operation_log="${FAKE_R2_LOG:?}"
operation="${3:-}"
key="${4:-}"
printf '%s %s\n' "$operation" "$key" >>"$operation_log"
object="$storage_dir/$key"
case "$operation" in
get)
	if [[ -f "$object" ]]; then
		cat "$object"
	else
		printf 'not found\n' >&2
		exit 1
	fi
	;;
put)
	file=""
	for ((index = 1; index <= $#; index++)); do
		if [[ "${!index}" == "--file" ]]; then
			next=$((index + 1))
			file="${!next}"
		fi
	done
	mkdir -p -- "$(dirname -- "$object")"
	cp -- "$file" "$object"
	;;
*)
	printf 'unexpected fake wrangler operation\n' >&2
	exit 1
	;;
esac
EOF
chmod 755 "$wrangler_bin"

run_publisher() {
	FAKE_R2_STORAGE="$storage_dir" FAKE_R2_LOG="$operation_log" \
		CLOUDFLARE_API_TOKEN=test-token CLOUDFLARE_ACCOUNT_ID=test-account \
		R2_BUCKET=test-bucket R2_PREFIX=extensions WRANGLER_BIN="$wrangler_bin" \
		GITHUB_REF_TYPE=tag GITHUB_REF_NAME="v$version" \
		"$PUBLISH_SCRIPT" "$1" "$version" >/dev/null
}

run_publisher "$package_dir"
stored_files="$(find "$storage_dir" -type f -printf '%P\n' | LC_ALL=C sort)"
expected_stored="$(printf 'test-bucket/extensions/net/%s/SHA256SUMS\ntest-bucket/extensions/net/%s/x86_64-unknown-linux-gnu.tar.gz\ntest-bucket/extensions/net/%s/x86_64-unknown-linux-gnu.tar.gz.sha256' "$version" "$version" "$version")"
[[ "$stored_files" == "$expected_stored" ]] || {
	printf 'unexpected stored files:\n%s\n' "$stored_files" >&2
	exit 1
}
operation_count="$(wc -l <"$operation_log" | tr -d ' ')"
[[ "$operation_count" == 9 ]] || {
	printf 'expected get, put, get for three files, got %s operations\n' "$operation_count" >&2
	exit 1
}

expect_rejected() {
	local invalid_dir="$1"
	if run_publisher "$invalid_dir"; then
		printf 'publisher accepted invalid package: %s\n' "$invalid_dir" >&2
		exit 1
	fi
}

extra_dir="$TMP_BASE/extra"
cp -a -- "$package_dir" "$extra_dir"
printf 'extra\n' >"$extra_dir/unlisted.txt"
expect_rejected "$extra_dir"

manifest_dir="$TMP_BASE/manifest"
cp -a -- "$package_dir" "$manifest_dir"
printf '%064d  extra.tar.gz\n' 0 >>"$manifest_dir/SHA256SUMS"
expect_rejected "$manifest_dir"

sidecar_dir="$TMP_BASE/sidecar"
cp -a -- "$package_dir" "$sidecar_dir"
printf '%064d  x86_64-unknown-linux-gnu.tar.gz\n' 0 >"$sidecar_dir/x86_64-unknown-linux-gnu.tar.gz.sha256"
expect_rejected "$sidecar_dir"

printf 'publish-component.test: PASS\n'
