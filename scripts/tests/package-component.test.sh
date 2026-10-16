#!/usr/bin/env bash
# Package shape test: no Rust build, network, or R2 access.
set -euo pipefail

cd -- "$(dirname -- "$0")/../.."
readonly SCRIPT=./scripts/package-component.sh
scratch_root="${TMPDIR:-/tmp/bitty}"
mkdir -p -- "$scratch_root"
TMP_BASE="$(mktemp -d "$scratch_root/package-component-test.XXXXXX")"
readonly TMP_BASE
cleanup() { rm -rf -- "$TMP_BASE"; }
trap cleanup EXIT

source_dir="$TMP_BASE/source"
output_dir="$TMP_BASE/output"
mkdir -p -- "$source_dir" "$output_dir"
printf '#!/bin/sh\necho bitty-net 0.0.1\n' >"$source_dir/bitty-net"
chmod 755 "$source_dir/bitty-net"

"$SCRIPT" --version 0.0.1 --target x86_64-unknown-linux-gnu \
	--binary "$source_dir/bitty-net" --output "$output_dir/x86_64-unknown-linux-gnu.tar.gz"
printf '#!/bin/sh\necho bitty-net 0.0.1 arm\n' >"$source_dir/bitty-net-arm"
chmod 755 "$source_dir/bitty-net-arm"
"$SCRIPT" --version 0.0.1 --target aarch64-unknown-linux-gnu \
	--binary "$source_dir/bitty-net-arm" --output "$output_dir/aarch64-unknown-linux-gnu.tar.gz"

expected_files=$'SHA256SUMS\naarch64-unknown-linux-gnu.tar.gz\naarch64-unknown-linux-gnu.tar.gz.sha256\nx86_64-unknown-linux-gnu.tar.gz\nx86_64-unknown-linux-gnu.tar.gz.sha256'
actual_files="$(find "$output_dir" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)"
[[ "$actual_files" == "$expected_files" ]] || {
	printf 'unexpected package files:\n%s\n' "$actual_files" >&2
	exit 1
}

(cd "$output_dir" && sha256sum -c SHA256SUMS >/dev/null)
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
	archive="$output_dir/$target.tar.gz"
	members="$(tar -tzf "$archive" | LC_ALL=C sort)"
	[[ "$members" == $'bitty-component.toml\nbitty-net' ]] || {
		printf 'unexpected archive members for %s:\n%s\n' "$target" "$members" >&2
		exit 1
	}
	extract="$TMP_BASE/$target"
	mkdir -p "$extract"
	tar -xzf "$archive" -C "$extract"
	grep -Fx 'name = "net"' "$extract/bitty-component.toml" >/dev/null
	grep -Fx 'version = "0.0.1"' "$extract/bitty-component.toml" >/dev/null
	grep -Fx 'protocol = [1, 1]' "$extract/bitty-component.toml" >/dev/null
	grep -Fx 'executable = "bitty-net"' "$extract/bitty-component.toml" >/dev/null
	digest="$(sha256sum "$extract/bitty-net" | awk '{print $1}')"
	grep -Fx "sha256 = \"$digest\"" "$extract/bitty-component.toml" >/dev/null
done

urls="$(BITTY_CDN_BASE=https://cdn.bitty.run "$SCRIPT" --print-url --version 0.0.1 --target x86_64-unknown-linux-gnu)"
[[ "$urls" == $'https://cdn.bitty.run/extensions/net/0.0.1/x86_64-unknown-linux-gnu.tar.gz\nhttps://cdn.bitty.run/extensions/net/0.0.1/SHA256SUMS' ]]

if GITHUB_REF_TYPE=branch R2_BUCKET=unused "$PWD/scripts/publish-component.sh" "$output_dir" 0.0.1 >/dev/null 2>&1; then
	printf 'publisher accepted a non-tag ref\n' >&2
	exit 1
fi
printf 'package-component.test: PASS\n'
