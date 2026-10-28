#!/usr/bin/env python3
"""Spawn the packaged `bitty-net` binary and exercise wire protocol v1.

The smoke is deliberately small and standard-library only so the same check
runs on every native runner (Linux, macOS, Windows) after the target tarball
is unpacked:

1. ``<binary> --version`` reports ``<executable> <version>``.
2. ``Hello`` is answered by ``HelloAck`` with protocol 1, the descriptor
   component name, and the exact descriptor version.
3. One ``HttpRequest`` with an **empty** grant is answered by a request-level
   ``Error`` with kind ``offline`` (2) and the same request id.
4. ``Shutdown`` is answered by no frame at all and a clean exit code 0
   (protocol v1 has no ``ShutdownAck``; ``Shutdown`` or stdin EOF ends the
   session and ``ServeOutcome::exit_code`` returns ``EXIT_OK``).

Why no real fetch: a request that resolves a host would need DNS and network
egress, which this smoke must not perform and which a sandboxed or offline
runner cannot guarantee. The empty grant proves the same wire path without any
external I/O: ``bitty-net`` refuses the request in ``capability.check_request``
before a worker, socket, or resolver is touched, and answers the documented
``Error { kind: offline }`` frame. The URL uses the reserved ``.invalid`` TLD
(RFC 6761) so a regression that skipped the grant check still could not reach
a real host.

The script never reads a path, environment variable, URL, or command from the
wire; it only drives the public v1 framing. Response frames are bounded to the
protocol's ``MAX_FRAME_BYTES`` (256 KiB) so a malformed child cannot make the
smoke allocate more. On any failure it stops the child it started and exits 1
with a bounded diagnostic.

Usage:
    scripts/component_smoke.py --binary PATH [--root DIR] [--timeout SECONDS]
    scripts/component-release.sh smoke --binary PATH
"""

from __future__ import annotations

import argparse
import queue
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import tomllib

DESCRIPTOR_FILE = "bitty-component.toml"

PROTOCOL_VERSION = 1
TAG_HELLO = 0x01
TAG_HELLO_ACK = 0x02
TAG_HTTP_REQUEST = 0x10
TAG_ERROR = 0x2F
TAG_SHUTDOWN = 0x3F

# Wire codes from bitty-network-wire.
METHOD_GET = 0
ERROR_KIND_OFFLINE = 2

# Mirrors MAX_FRAME_BYTES in crates/bitty-network-wire/src/lib.rs (256 KiB).
# A malformed child cannot make the smoke allocate more than one bounded
# frame per read.
MAX_RESPONSE_FRAME_BYTES = 256 * 1024
FRAME_QUEUE_DEPTH = 8

REQUEST_ID = 1
PLUGIN_ID = "component-smoke"
# RFC 6761 reserved TLD: never resolves, so even a broken grant check cannot
# turn this smoke into real network traffic.
SMOKE_URL = "https://component-smoke.invalid/"
REQUEST_TIMEOUT_MS = 5_000


class SmokeFailure(Exception):
    """One operator-facing protocol smoke failure."""


def read_descriptor(root: Path) -> tuple[str, str, str]:
    path = root / DESCRIPTOR_FILE
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise SmokeFailure(f"cannot read descriptor {path}: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise SmokeFailure(f"descriptor {path} is not valid TOML: {error}") from error
    section = data.get("component")
    if not isinstance(section, dict):
        raise SmokeFailure(f"descriptor {path} is missing [component]")
    values = []
    for key in ("name", "version", "executable"):
        value = section.get(key)
        if not isinstance(value, str) or not value:
            raise SmokeFailure(f"descriptor {path} is missing a valid {key}")
        values.append(value)
    return values[0], values[1], values[2]


def encode_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def encode_hello(component: str, version: str) -> bytes:
    payload = (
        bytes([TAG_HELLO])
        + struct.pack(">HH", PROTOCOL_VERSION, PROTOCOL_VERSION)
        + encode_string(component)
        + encode_string(version)
    )
    return struct.pack(">I", len(payload)) + payload


def encode_offline_request() -> bytes:
    """One GET with an empty grant: refused before any socket work."""
    empty_grant = (
        struct.pack(">I", 0)  # hosts
        + bytes([0x00])  # has_methods = false
        + bytes([0x00])  # methods mask (must be zero without a restriction)
    )
    payload = (
        bytes([TAG_HTTP_REQUEST])
        + struct.pack(">Q", REQUEST_ID)
        + encode_string(PLUGIN_ID)
        + empty_grant
        + bytes([METHOD_GET])
        + encode_string(SMOKE_URL)
        + struct.pack(">I", 0)  # headers
        + struct.pack(">I", REQUEST_TIMEOUT_MS)
        + struct.pack(">Q", 0)  # max_body_bytes: component default
        + bytes([0x00])  # body_follows = false
    )
    return struct.pack(">I", len(payload)) + payload


def encode_shutdown() -> bytes:
    payload = bytes([TAG_SHUTDOWN])
    return struct.pack(">I", len(payload)) + payload


def take(payload: bytes, offset: int, length: int) -> tuple[bytes, int]:
    end = offset + length
    if end > len(payload):
        raise SmokeFailure("truncated component frame")
    return payload[offset:end], end


def take_u16(payload: bytes, offset: int) -> tuple[int, int]:
    raw, offset = take(payload, offset, 2)
    return struct.unpack(">H", raw)[0], offset


def take_u64(payload: bytes, offset: int) -> tuple[int, int]:
    raw, offset = take(payload, offset, 8)
    return struct.unpack(">Q", raw)[0], offset


def take_string(payload: bytes, offset: int) -> tuple[str, int]:
    raw, offset = take(payload, offset, 4)
    length = struct.unpack(">I", raw)[0]
    value, offset = take(payload, offset, length)
    try:
        return value.decode("utf-8"), offset
    except UnicodeDecodeError as error:
        raise SmokeFailure("component frame carries a non-UTF-8 string") from error


def parse_hello_ack(payload: bytes, expected_name: str, expected_version: str) -> None:
    if not payload or payload[0] != TAG_HELLO_ACK:
        raise SmokeFailure(f"expected HelloAck, got {describe(payload)}")
    protocol, offset = take_u16(payload, 1)
    component, offset = take_string(payload, offset)
    version, offset = take_string(payload, offset)
    if offset != len(payload):
        raise SmokeFailure("HelloAck has trailing bytes")
    if protocol != PROTOCOL_VERSION:
        raise SmokeFailure(f"HelloAck protocol {protocol} != {PROTOCOL_VERSION}")
    if component != expected_name:
        raise SmokeFailure(
            f"HelloAck component {component!r} != descriptor {expected_name!r}"
        )
    if version != expected_version:
        raise SmokeFailure(
            f"HelloAck version {version!r} != descriptor {expected_version!r}"
        )


def parse_offline_error(payload: bytes) -> None:
    if not payload or payload[0] != TAG_ERROR:
        raise SmokeFailure(f"expected Error, got {describe(payload)}")
    request, offset = take_u64(payload, 1)
    kind, offset = take(payload, offset, 1)
    message, offset = take_string(payload, offset)
    if offset != len(payload):
        raise SmokeFailure("Error has trailing bytes")
    if request != REQUEST_ID:
        raise SmokeFailure(f"Error request {request} != {REQUEST_ID}")
    if kind[0] != ERROR_KIND_OFFLINE:
        raise SmokeFailure(
            f"Error kind {kind[0]} != {ERROR_KIND_OFFLINE} (offline); "
            f"message={message!r}"
        )


def read_exact(stream, length: int) -> bytes:
    """Read up to ``length`` bytes; a short result means EOF or truncation."""
    data = bytearray()
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def describe(payload: bytes) -> str:
    if not payload:
        return "an empty frame"
    if payload[0] == TAG_ERROR:
        try:
            request, offset = take_u64(payload, 1)
            kind, offset = take(payload, offset, 1)
            message, offset = take_string(payload, offset)
        except SmokeFailure:
            return "a malformed Error frame"
        return f"Error(request={request}, kind={kind[0]}, message={message!r})"
    return f"tag 0x{payload[0]:02x}"


class Component:
    """One spawned component process plus its decoded frame stream."""

    def __init__(self, binary: Path, timeout: float) -> None:
        self.binary = binary
        self.timeout = timeout
        self.child = subprocess.Popen(
            [str(binary)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.frames: queue.Queue[tuple[str, object]] = queue.Queue(
            maxsize=FRAME_QUEUE_DEPTH
        )
        self.reader = threading.Thread(
            target=self._read_frames, name="component-smoke-reader", daemon=True
        )
        self.reader.start()

    def _read_frames(self) -> None:
        assert self.child.stdout is not None
        stream = self.child.stdout
        try:
            while True:
                header = read_exact(stream, 4)
                if not header:
                    self.frames.put(("eof", None))
                    return
                if len(header) != 4:
                    self.frames.put(("error", "truncated frame header"))
                    return
                length = struct.unpack(">I", header)[0]
                if length == 0 or length > MAX_RESPONSE_FRAME_BYTES:
                    self.frames.put(
                        (
                            "error",
                            (
                                f"component frame length {length} outside "
                                f"1..{MAX_RESPONSE_FRAME_BYTES}"
                            ),
                        )
                    )
                    return
                payload = read_exact(stream, length)
                if len(payload) != length:
                    self.frames.put(("error", "truncated frame payload"))
                    return
                self.frames.put(("frame", payload))
        except OSError as error:
            self.frames.put(("error", f"stream failure: {error}"))

    def send(self, frame: bytes) -> None:
        assert self.child.stdin is not None
        try:
            self.child.stdin.write(frame)
            self.child.stdin.flush()
        except OSError as error:
            raise SmokeFailure(f"cannot write to component: {error}") from error

    def recv(self) -> bytes:
        try:
            kind, payload = self.frames.get(timeout=self.timeout)
        except queue.Empty as error:
            raise SmokeFailure(
                f"component produced no frame within {self.timeout:g}s"
            ) from error
        if kind == "eof":
            raise SmokeFailure("component closed stdout before replying")
        if kind == "error":
            raise SmokeFailure(str(payload))
        assert isinstance(payload, bytes)
        return payload

    def expect_silent_close(self) -> None:
        """Require EOF with no further frame after ``Shutdown``."""
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeFailure("component kept stdout open after Shutdown")
            try:
                kind, payload = self.frames.get(timeout=remaining)
            except queue.Empty as error:
                raise SmokeFailure(
                    "component kept stdout open after Shutdown"
                ) from error
            if kind == "eof":
                return
            if kind == "error":
                raise SmokeFailure(str(payload))
            raise SmokeFailure(
                f"component emitted a frame after Shutdown: {describe(payload)}"
            )

    def stop(self) -> None:
        if self.child.poll() is not None:
            return
        self.child.terminate()
        try:
            self.child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait(timeout=5)


def check_version(binary: Path, expected: str, timeout: float) -> None:
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeFailure(f"cannot run {binary} --version: {error}") from error
    if result.returncode != 0:
        raise SmokeFailure(
            f"{binary} --version exited {result.returncode}: {result.stderr.strip()}"
        )
    if result.stdout.strip() != expected:
        raise SmokeFailure(
            f"{binary} --version reported {result.stdout.strip()!r}, expected {expected!r}"
        )


def run(binary: Path, root: Path, timeout: float) -> None:
    name, version, executable = read_descriptor(root)
    if not binary.is_file():
        raise SmokeFailure(f"component binary is missing: {binary}")
    check_version(binary, f"{executable} {version}", timeout)

    component = Component(binary, timeout)
    try:
        component.send(encode_hello(name, version))
        parse_hello_ack(component.recv(), name, version)
        component.send(encode_offline_request())
        parse_offline_error(component.recv())
        component.send(encode_shutdown())
        component.expect_silent_close()
        try:
            code = component.child.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise SmokeFailure("component did not exit after Shutdown") from error
        if code != 0:
            raise SmokeFailure(f"component exited {code} after Shutdown")
    finally:
        component.stop()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="component-release.sh smoke",
        description=(
            "Spawn the packaged bitty-net binary and verify Hello/offline "
            "HttpRequest/Shutdown against wire protocol v1."
        ),
    )
    parser.add_argument("--binary", required=True, help="component executable to run")
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parent.parent),
        help="component repository root holding bitty-component.toml",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="seconds allowed for one frame or process transition (default: 20)",
    )
    args = parser.parse_args(argv)

    binary = Path(args.binary).resolve()
    root = Path(args.root).resolve()
    started = time.monotonic()
    try:
        if args.timeout <= 0:
            raise SmokeFailure("--timeout must be positive")
        run(binary, root, args.timeout)
    except SmokeFailure as error:
        print(f"component-smoke: ERROR: {error}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started
    print(
        f"component-smoke: PASS (binary={binary}, root={root}, elapsed={elapsed:.2f}s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
