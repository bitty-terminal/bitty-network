#!/usr/bin/env bash
# component-smoke.test.sh — fixture gates for the packaged-binary protocol
# smoke. No Rust build, no network: a small Python coprocess speaks enough of
# wire protocol v1 to exercise the smoke client, including its failure paths.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ROOT
scratch_root="${TMPDIR:-/tmp/bitty}"
mkdir -p -- "$scratch_root"
TMP_BASE="$(mktemp -d "$scratch_root/component-smoke-test.XXXXXX")"
readonly TMP_BASE
cleanup() { rm -rf -- "$TMP_BASE"; }
trap cleanup EXIT

pass() { printf 'ok: %s\n' "$1"; }

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
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

fixture="$TMP_BASE/fixture"
mkdir -p "$fixture"
cat >"$fixture/bitty-component.toml" <<'EOF'
[component]
name = "demo"
version = "1.2.3"
protocol = [1, 1]
executable = "bitty-demo"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
EOF

fake="$fixture/bitty-demo"
cat >"$fake" <<'EOF'
#!/usr/bin/env python3
"""Minimal wire protocol v1 responder for the net smoke fixture."""
import os
import struct
import sys
import time

MODE = os.environ.get("FAKE_MODE", "ok")


def take(stream, length):
    data = b""
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise SystemExit(0)
        data += chunk
    return data


def frame(stream):
    length = struct.unpack(">I", take(stream, 4))[0]
    return take(stream, length)


def text(value):
    raw = value.encode()
    return struct.pack(">I", len(raw)) + raw


def send(payload):
    sys.stdout.buffer.write(struct.pack(">I", len(payload)) + payload)
    sys.stdout.buffer.flush()


if "--version" in sys.argv:
    print("bitty-demo 9.9.9" if MODE == "bad-version" else "bitty-demo 1.2.3")
    raise SystemExit(0)

if MODE == "hang":
    time.sleep(60)
    raise SystemExit(0)

if MODE == "oversize-frame":
    sys.stdout.buffer.write(struct.pack(">I", 256 * 1024 + 1))
    sys.stdout.buffer.flush()
    time.sleep(60)
    raise SystemExit(0)

hello = frame(sys.stdin.buffer)
if not hello or hello[0] != 0x01:
    raise SystemExit(3)
name = "other" if MODE == "bad-component" else "demo"
send(b"\x02" + struct.pack(">H", 1) + text(name) + text("1.2.3"))

request = frame(sys.stdin.buffer)
if not request or request[0] != 0x10:
    raise SystemExit(3)
request_id = struct.unpack(">Q", request[1:9])[0]
kind = 3 if MODE == "bad-kind" else 2
send(b"\x2f" + struct.pack(">Q", request_id) + bytes([kind]) + text("offline"))

shutdown = frame(sys.stdin.buffer)
if not shutdown or shutdown[0] != 0x3F:
    raise SystemExit(3)
if MODE == "frame-after-shutdown":
    send(b"\x02" + struct.pack(">H", 1) + text("demo") + text("1.2.3"))
    raise SystemExit(0)
if MODE == "no-exit":
    time.sleep(60)
raise SystemExit(0)
EOF
chmod 755 "$fake"

smoke() {
	"$ROOT/scripts/component-release.sh" smoke \
		--binary "$fake" --root "$fixture" --timeout 3
}

smoke >"$TMP_BASE/pass-output" || fail "valid fixture failed the protocol smoke"
grep -F 'component-smoke: PASS' "$TMP_BASE/pass-output" >/dev/null ||
	fail "smoke did not report PASS"
pass "valid fixture passes Hello/offline HttpRequest/Shutdown smoke"

expect_failure "version mismatch" \
	env FAKE_MODE=bad-version "$ROOT/scripts/component-release.sh" smoke \
	--binary "$fake" --root "$fixture" --timeout 3

expect_failure "HelloAck component mismatch" \
	env FAKE_MODE=bad-component "$ROOT/scripts/component-release.sh" smoke \
	--binary "$fake" --root "$fixture" --timeout 3

expect_failure "component that never replies" \
	env FAKE_MODE=hang "$ROOT/scripts/component-release.sh" smoke \
	--binary "$fake" --root "$fixture" --timeout 1

expect_failure "oversized response frame" \
	env FAKE_MODE=oversize-frame "$ROOT/scripts/component-release.sh" smoke \
	--binary "$fake" --root "$fixture" --timeout 3

expect_failure "grant-refused request answered with the wrong error kind" \
	env FAKE_MODE=bad-kind "$ROOT/scripts/component-release.sh" smoke \
	--binary "$fake" --root "$fixture" --timeout 3

expect_failure "frame emitted after Shutdown" \
	env FAKE_MODE=frame-after-shutdown "$ROOT/scripts/component-release.sh" smoke \
	--binary "$fake" --root "$fixture" --timeout 3

expect_failure "component that does not exit after Shutdown" \
	env FAKE_MODE=no-exit "$ROOT/scripts/component-release.sh" smoke \
	--binary "$fake" --root "$fixture" --timeout 1

expect_failure "missing binary" \
	"$ROOT/scripts/component-release.sh" smoke \
	--binary "$TMP_BASE/missing" --root "$fixture" --timeout 3

printf 'component-smoke.test: PASS\n'
