#!/usr/bin/env python3
"""Reusable component release matrix, manifest, catalog, and verification.

This module is shared verbatim by the extension component repositories
(``bitty-graphics`` ships ``graphics``, ``bitty-network`` ships ``net``). It
contains no repository-specific literal: the component name comes from the
canonical ``bitty-component.toml`` descriptor, the version from that
descriptor plus the workspace ``Cargo.toml``, and the supported target set
from ``component-targets.toml``.

Subcommands:

``check``     Validate the descriptor, the Cargo version, and the release
              matrix. Fails when the matrix publishes no supported target,
              which is the gate that keeps a ``bitty-component.toml``
              repository from existing without at least one shippable
              target.
``targets``   Print the supported targets as a plain list or as a GitHub
              Actions matrix JSON document.
``manifest``  Regenerate per-target ``.sha256`` sidecars and the aggregate
              ``SHA256SUMS`` over the target tarballs in a dist directory.
``catalog``   Emit the ``extensions/catalog.v1`` row fragment for the
              verified tarballs in a dist directory, keyed by target.
``record``    Write the release digest record: one row per supported target
              with the tarball and executable SHA-256 values the release
              produced. The canonical root descriptor keeps its placeholder
              sentinel; each archive carries that target's real digest.
``verify``    Require the dist directory to hold exactly the supported
              target set and verify the descriptor/digest chain inside every
              archive. Nothing unpublished or unverified can pass this gate.
              With ``--record`` the generated digest record must match too.

Only supported targets ever produce a manifest entry or a catalog row. An
unsupported target in the matrix is documentation, never a publishable row.

Exit codes: 0 success, 1 gate failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - guarded by the shell wrapper
    sys.exit("component-release: ERROR: Python 3.11+ with tomllib is required")

DESCRIPTOR_FILE = "bitty-component.toml"
MATRIX_FILE = "component-targets.toml"
MANIFEST_FILE = "SHA256SUMS"
CATALOG_FILE = "catalog.v1"
CATALOG_SCHEMA_LINE = "schema 1"
RECORD_SCHEMA = 1
EXECUTABLE_PREFIX = "bitty-"

DESCRIPTOR_MAX_BYTES = 4096
EXECUTABLE_MAX_BYTES = 268435456  # mirrors COMPONENT_EXECUTABLE_MAX_BYTES

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
TARGET_RE = re.compile(r"^[a-z0-9_]+(-[a-z0-9_]+)+$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
RUNNER_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Mirrors `host_target_triple` in the Core installer
# (`bitty/crates/bitty-terminal/src/component_seed.rs`). Keep in sync: a
# supported triple the installer never requests would ship bytes nobody can
# install, and a missing triple makes a supported host uninstallable.
# Triple -> (OS, ARCH) as reported by `std::env::consts`.
HOST_TARGETS: dict[str, tuple[str, str]] = {
    "x86_64-unknown-linux-gnu": ("linux", "x86_64"),
    "x86_64-unknown-linux-musl": ("linux", "x86_64"),
    "aarch64-unknown-linux-gnu": ("linux", "aarch64"),
    "aarch64-apple-darwin": ("macos", "aarch64"),
    "x86_64-apple-darwin": ("macos", "x86_64"),
    "x86_64-pc-windows-msvc": ("windows", "x86_64"),
    "aarch64-pc-windows-msvc": ("windows", "aarch64"),
}

DESCRIPTOR_KEYS = {"name", "version", "protocol", "executable", "sha256"}
MATRIX_KEYS = {"schema", "target"}
TARGET_ROW_KEYS = {"triple", "os", "arch", "runner", "supported", "reason"}
RECORD_KEYS = {"schema", "name", "version", "protocol", "target"}
RECORD_TARGET_KEYS = {
    "triple",
    "tarball",
    "tarball_sha256",
    "executable",
    "executable_sha256",
}

# First bytes of a native executable for each supported OS. A tarball named
# for a target must not carry another platform's payload (for example a PE
# file in a Linux artifact); the magic is checked before anything is
# published. Mach-O covers both thin (32/64-bit, either endianness) and fat
# containers because a macOS runner may emit any of them.
EXECUTABLE_MAGIC = {
    "linux": (b"\x7fELF",),
    "macos": (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    ),
    "windows": (b"MZ",),
}


class GateError(Exception):
    """A release gate failed; the message is operator-facing."""


@dataclass(frozen=True)
class Target:
    triple: str
    os: str
    arch: str
    runner: str | None
    supported: bool
    reason: str | None


@dataclass(frozen=True)
class Matrix:
    targets: tuple[Target, ...]

    @property
    def supported(self) -> tuple[Target, ...]:
        return tuple(
            sorted((t for t in self.targets if t.supported), key=lambda t: t.triple)
        )

    @property
    def unsupported(self) -> tuple[Target, ...]:
        return tuple(
            sorted((t for t in self.targets if not t.supported), key=lambda t: t.triple)
        )


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    executable: str
    sha256: str
    protocol_min: int
    protocol_max: int


@dataclass(frozen=True)
class ArchiveInfo:
    """Verified facts about one target tarball."""

    tarball_sha256: str
    executable: str
    executable_sha256: str
    executable_size: int
    executable_mode: int


def fail(message: str) -> NoReturn:
    raise GateError(message)


def read_toml(path: Path, label: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {label} {path}: {error}")
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        fail(f"{label} {path} is not valid TOML: {error}")


def strict_version(value: object, label: str) -> str:
    if not isinstance(value, str) or not VERSION_RE.match(value):
        fail(f"{label} must be a strict X.Y.Z version, got: {value!r}")
    for part in value.split("."):
        if int(part) > 4294967295:
            fail(f"{label} component exceeds the u32 range: {value}")
    return value


def parse_component_descriptor(path: Path, label: str = "descriptor") -> Component:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is missing or is not a regular file: {path}")
    if path.stat().st_size > DESCRIPTOR_MAX_BYTES:
        fail(f"{label} exceeds {DESCRIPTOR_MAX_BYTES} bytes: {path}")
    data = read_toml(path, label)
    return validate_component_data(data, label)


def validate_component_data(data: dict, label: str) -> Component:
    extra_tables = sorted(set(data) - {"component"})
    if extra_tables:
        fail(f"{label} has unknown tables: {', '.join(extra_tables)}")
    section = data.get("component")
    if not isinstance(section, dict):
        fail(f"{label} is missing the [component] table")
    extra_keys = sorted(set(section) - DESCRIPTOR_KEYS)
    if extra_keys:
        fail(f"{label} has unknown [component] keys: {', '.join(extra_keys)}")
    missing = sorted(DESCRIPTOR_KEYS - set(section))
    if missing:
        fail(f"{label} is missing [component] keys: {', '.join(missing)}")

    name = section["name"]
    if not isinstance(name, str) or not NAME_RE.match(name):
        fail(f"{label} name must match [a-z][a-z0-9-]{{0,31}}, got: {name!r}")
    version = strict_version(section["version"], f"{label} version")

    executable = section["executable"]
    expected_executable = f"{EXECUTABLE_PREFIX}{name}"
    if executable != expected_executable:
        fail(f"{label} executable must be {expected_executable}, got: {executable!r}")

    protocol = section["protocol"]
    if (
        not isinstance(protocol, list)
        or len(protocol) != 2
        or any(not isinstance(part, int) or isinstance(part, bool) for part in protocol)
    ):
        fail(f"{label} protocol must be [min, max] integers")
    protocol_min, protocol_max = protocol
    if not (1 <= protocol_min <= protocol_max <= 65535):
        fail(f"{label} protocol must satisfy 1 <= min <= max <= 65535, got: {protocol}")

    sha256 = section["sha256"]
    if not isinstance(sha256, str) or not DIGEST_RE.match(sha256):
        fail(f"{label} sha256 must be 64 lowercase hex characters")

    return Component(
        name=name,
        version=version,
        executable=executable,
        sha256=sha256,
        protocol_min=protocol_min,
        protocol_max=protocol_max,
    )


def cargo_version(root: Path) -> str:
    path = root / "Cargo.toml"
    data = read_toml(path, "Cargo.toml")
    package = data.get("package")
    if isinstance(package, dict):
        version = package.get("version")
        # `version.workspace = true` inherits [workspace.package].version;
        # let the workspace lookup below resolve it instead of handing the
        # TOML table to strict_version.
        inherited = isinstance(version, dict) and version.get("workspace") is True
        if version is not None and not inherited:
            return strict_version(version, "Cargo.toml [package] version")
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        workspace_package = workspace.get("package")
        if isinstance(workspace_package, dict) and "version" in workspace_package:
            return strict_version(
                workspace_package["version"], "Cargo.toml [workspace.package] version"
            )
    fail("Cargo.toml has neither [package].version nor [workspace.package].version")


def parse_matrix(root: Path) -> Matrix:
    path = root / MATRIX_FILE
    if path.is_symlink() or not path.is_file():
        fail(f"release matrix is missing or is not a regular file: {path}")
    data = read_toml(path, "release matrix")
    extra = sorted(set(data) - MATRIX_KEYS)
    if extra:
        fail(f"release matrix has unknown top-level keys: {', '.join(extra)}")
    if data.get("schema") != 1:
        fail(f"release matrix schema must be 1, got: {data.get('schema')!r}")
    rows = data.get("target")
    if not isinstance(rows, list) or not rows:
        fail("release matrix must define at least one [[target]] row")

    targets: list[Target] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        label = f"release matrix target[{index}]"
        if not isinstance(row, dict):
            fail(f"{label} must be a table")
        unknown = sorted(set(row) - TARGET_ROW_KEYS)
        if unknown:
            fail(f"{label} has unknown keys: {', '.join(unknown)}")
        for key in ("triple", "os", "arch", "supported"):
            if key not in row:
                fail(f"{label} is missing '{key}'")

        triple = row["triple"]
        if not isinstance(triple, str) or not TARGET_RE.match(triple):
            fail(f"{label} triple must look like a Rust target triple, got: {triple!r}")
        if triple not in HOST_TARGETS:
            fail(
                f"{label} triple {triple} is not a host triple the Core installer "
                "requests (see HOST_TARGETS)"
            )
        if triple in seen:
            fail(f"{label} duplicates triple {triple}")
        seen.add(triple)

        expected_os, expected_arch = HOST_TARGETS[triple]
        if row["os"] != expected_os or row["arch"] != expected_arch:
            fail(
                f"{label} {triple} must declare os={expected_os} arch={expected_arch}, "
                f"got os={row['os']!r} arch={row['arch']!r}"
            )

        supported = row["supported"]
        if not isinstance(supported, bool):
            fail(f"{label} 'supported' must be a boolean")

        runner = row.get("runner")
        reason = row.get("reason")
        if supported:
            if not isinstance(runner, str) or not RUNNER_RE.match(runner):
                fail(f"{label} {triple} is supported and needs a valid 'runner' label")
            if reason is not None:
                fail(
                    f"{label} {triple} is supported; use a TOML comment for context "
                    "instead of a 'reason' (reserved for unsupported targets)"
                )
        else:
            if not isinstance(reason, str) or not reason.strip():
                fail(f"{label} {triple} is unsupported and needs a non-empty 'reason'")
            if runner is not None:
                fail(f"{label} {triple} is unsupported and must not declare a 'runner'")

        targets.append(
            Target(
                triple=triple,
                os=expected_os,
                arch=expected_arch,
                runner=runner,
                supported=supported,
                reason=reason,
            )
        )

    matrix = Matrix(targets=tuple(targets))
    if not matrix.supported:
        fail(
            "release matrix publishes no supported target; every bitty-component.toml "
            "repository must ship at least one installable host target"
        )
    return matrix


def load_repo(root: Path) -> tuple[Component, Matrix]:
    component = parse_component_descriptor(root / DESCRIPTOR_FILE)
    manifest_version = cargo_version(root)
    if manifest_version != component.version:
        fail(
            f"Cargo.toml version {manifest_version} differs from descriptor version "
            f"{component.version}"
        )
    matrix = parse_matrix(root)
    return component, matrix


def archive_executable(component: Component, target: str) -> str:
    suffix = ".exe" if "-windows-" in target else ""
    return f"{component.executable}{suffix}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_stream(handle, limit: int, label: str) -> tuple[str, int, bytes]:
    digest = hashlib.sha256()
    size = 0
    prefix = bytearray()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        size += len(chunk)
        if size > limit:
            fail(f"{label} exceeds {limit} bytes")
        digest.update(chunk)
        if len(prefix) < 8:
            prefix.extend(chunk[: 8 - len(prefix)])
    return digest.hexdigest(), size, bytes(prefix)


def inspect_archive(path: Path, component: Component, target: Target) -> ArchiveInfo:
    """Verify one tarball's members, descriptor, digest, and executable shape."""
    expected_executable = archive_executable(component, target.triple)
    expected_members = sorted([DESCRIPTOR_FILE, expected_executable])
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if sorted(member.name for member in members) != expected_members:
                fail(
                    f"{path} must hold exactly {DESCRIPTOR_FILE} and "
                    f"{expected_executable} at the archive root"
                )
            for member in members:
                if not member.isfile():
                    fail(f"{path} member is not a regular file: {member.name}")

            descriptor_member = archive.getmember(DESCRIPTOR_FILE)
            if descriptor_member.size > DESCRIPTOR_MAX_BYTES:
                fail(f"{path} descriptor exceeds {DESCRIPTOR_MAX_BYTES} bytes")
            descriptor_handle = archive.extractfile(descriptor_member)
            if descriptor_handle is None:
                fail(f"{path} descriptor is not readable")
            descriptor_bytes = descriptor_handle.read()
            try:
                descriptor_data = tomllib.loads(descriptor_bytes.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
                fail(f"{path} descriptor is not valid UTF-8 TOML: {error}")
            embedded = validate_component_data(descriptor_data, f"{path} descriptor")
            if embedded.name != component.name:
                fail(
                    f"{path} descriptor name {embedded.name} differs from {component.name}"
                )
            if embedded.version != component.version:
                fail(
                    f"{path} descriptor version {embedded.version} differs from "
                    f"{component.version}"
                )
            if embedded.executable != component.executable:
                fail(
                    f"{path} descriptor executable {embedded.executable} differs from "
                    f"{component.executable}"
                )
            if (embedded.protocol_min, embedded.protocol_max) != (
                component.protocol_min,
                component.protocol_max,
            ):
                fail(
                    f"{path} descriptor protocol "
                    f"[{embedded.protocol_min}, {embedded.protocol_max}] differs from "
                    f"the canonical [{component.protocol_min}, {component.protocol_max}]"
                )

            executable_member = archive.getmember(expected_executable)
            executable_handle = archive.extractfile(executable_member)
            if executable_handle is None:
                fail(f"{path} executable {expected_executable} is not readable")
            digest, size, prefix = sha256_stream(
                executable_handle, EXECUTABLE_MAX_BYTES, f"{path} executable"
            )
            if size == 0:
                fail(f"{path} executable {expected_executable} is empty")
            if embedded.sha256 != digest:
                fail(
                    f"{path} descriptor sha256 {embedded.sha256} does not match the "
                    f"executable digest {digest}"
                )
            expected_magic = EXECUTABLE_MAGIC.get(target.os)
            if expected_magic is None:
                fail(f"{path} target {target.triple} has no executable magic rule")
            if not any(prefix.startswith(magic) for magic in expected_magic):
                fail(
                    f"{path} executable {expected_executable} does not look like a "
                    f"{target.os} executable (first bytes {prefix.hex()})"
                )
            if target.os != "windows" and executable_member.mode & 0o111 == 0:
                fail(
                    f"{path} executable {expected_executable} is not marked executable"
                )
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot read component archive {path}: {error}")
    return ArchiveInfo(
        tarball_sha256=sha256_file(path),
        executable=expected_executable,
        executable_sha256=digest,
        executable_size=size,
        executable_mode=executable_member.mode,
    )


def dist_entries(dist: Path) -> list[Path]:
    if not dist.is_dir():
        fail(f"dist directory is missing: {dist}")
    entries: list[Path] = []
    for entry in sorted(dist.iterdir(), key=lambda item: item.name):
        if entry.is_symlink():
            fail(f"dist entry is a symlink: {entry}")
        if entry.is_dir():
            fail(f"dist entry is a directory: {entry}")
        if not entry.is_file():
            fail(f"dist entry is not a regular file: {entry}")
        entries.append(entry)
    return entries


def target_tarballs(dist: Path, matrix: Matrix) -> dict[str, Path]:
    supported = {target.triple for target in matrix.supported}
    tarballs: dict[str, Path] = {}
    for entry in dist_entries(dist):
        name = entry.name
        if name in {MANIFEST_FILE, CATALOG_FILE}:
            continue
        if name.endswith(".tar.gz.sha256"):
            continue
        if not name.endswith(".tar.gz"):
            fail(f"unexpected dist entry: {name}")
        target = name[: -len(".tar.gz")]
        if not TARGET_RE.match(target):
            fail(f"tarball basename is not a target triple: {name}")
        if target not in supported:
            fail(
                f"tarball {name} is not a supported target; unsupported targets never "
                "produce publishable bytes"
            )
        if target in tarballs:
            fail(f"duplicate tarball for target {target}")
        tarballs[target] = entry
    if not tarballs:
        fail(f"no target tarballs in {dist}")
    return tarballs


def write_sidecar(tarball: Path, digest: str) -> None:
    sidecar = tarball.with_name(f"{tarball.name}.sha256")
    sidecar.write_text(f"{digest}  {tarball.name}\n", encoding="utf-8")


def read_manifest(dist: Path, matrix: Matrix) -> dict[str, str]:
    path = dist / MANIFEST_FILE
    if path.is_symlink() or not path.is_file():
        fail(f"aggregate manifest is missing: {path}")
    supported = {target.triple for target in matrix.supported}
    digests: dict[str, str] = {}
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw:
            fail(f"{MANIFEST_FILE} line {line_number} is blank")
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+\.tar\.gz)", raw)
        if not match:
            fail(f"{MANIFEST_FILE} line {line_number} is malformed: {raw!r}")
        digest, name = match.groups()
        target = name[: -len(".tar.gz")]
        if target not in supported:
            fail(f"{MANIFEST_FILE} lists unsupported target {target}")
        if target in digests:
            fail(f"{MANIFEST_FILE} lists target {target} more than once")
        digests[target] = digest
    return digests


def verify_dist(
    dist: Path, root: Path, *, require_full_matrix: bool
) -> tuple[Component, dict]:
    component, matrix = load_repo(root)
    tarballs = target_tarballs(dist, matrix)
    digests = read_manifest(dist, matrix)

    if set(digests) != set(tarballs):
        missing = sorted(set(tarballs) - set(digests))
        extra = sorted(set(digests) - set(tarballs))
        detail = []
        if missing:
            detail.append(f"missing from {MANIFEST_FILE}: {', '.join(missing)}")
        if extra:
            detail.append(f"listed but absent: {', '.join(extra)}")
        fail("; ".join(detail))

    if require_full_matrix:
        expected = {target.triple for target in matrix.supported}
        missing = sorted(expected - set(tarballs))
        if missing:
            fail(
                "dist is incomplete for the supported matrix; missing: "
                + ", ".join(missing)
            )

    target_rows = {target.triple: target for target in matrix.targets}
    infos: dict[str, ArchiveInfo] = {}
    for target, tarball in tarballs.items():
        digest = sha256_file(tarball)
        if digests[target] != digest:
            fail(
                f"{MANIFEST_FILE} digest for {target} is {digests[target]}, "
                f"computed {digest}"
            )
        sidecar = tarball.with_name(f"{tarball.name}.sha256")
        if sidecar.is_symlink() or not sidecar.is_file():
            fail(f"sidecar is missing: {sidecar}")
        if sidecar.read_text(encoding="utf-8") != f"{digest}  {tarball.name}\n":
            fail(f"sidecar does not match {tarball.name}: {sidecar.name}")
        info = inspect_archive(tarball, component, target_rows[target])
        if info.tarball_sha256 != digest:
            fail(f"archive digest changed while verifying {tarball}")
        infos[target] = info

    sidecars = {
        entry.name[: -len(".sha256")]
        for entry in dist_entries(dist)
        if entry.name.endswith(".tar.gz.sha256")
    }
    expected_sidecars = {tarball.name for tarball in tarballs.values()}
    if sidecars != expected_sidecars:
        fail(
            "sidecar set does not match the tarball set: "
            f"expected {sorted(expected_sidecars)}, found {sorted(sidecars)}"
        )

    return component, {
        "matrix": matrix,
        "tarballs": tarballs,
        "digests": digests,
        "infos": infos,
    }


def rows(component: Component, digests: dict[str, str]) -> list[str]:
    return [
        f"extension {component.name} {component.version} {target} {digests[target]}"
        for target in sorted(digests)
    ]


def render_record(
    component: Component, matrix: Matrix, infos: dict[str, ArchiveInfo]
) -> str:
    """Render the release digest record as deterministic TOML.

    The canonical root descriptor keeps its zero placeholder; this record is
    the release output that names each target's real tarball and executable
    digests. It is written outside ``dist`` so it can never be mistaken for a
    publishable R2 object.
    """
    lines = [
        "# Generated by scripts/component-release.sh record. Do not edit by hand.",
        "# The canonical bitty-component.toml keeps the zero-digest placeholder;",
        "# each archive's embedded descriptor carries that target's real digest.",
        f"schema = {RECORD_SCHEMA}",
        f'name = "{component.name}"',
        f'version = "{component.version}"',
        f"protocol = [{component.protocol_min}, {component.protocol_max}]",
    ]
    for target in matrix.supported:
        info = infos[target.triple]
        lines.extend(
            [
                "",
                "[[target]]",
                f'triple = "{target.triple}"',
                f'tarball = "{target.triple}.tar.gz"',
                f'tarball_sha256 = "{info.tarball_sha256}"',
                f'executable = "{info.executable}"',
                f'executable_sha256 = "{info.executable_sha256}"',
            ]
        )
    return "\n".join(lines) + "\n"


def verify_record(
    path: Path,
    component: Component,
    matrix: Matrix,
    infos: dict[str, ArchiveInfo],
) -> None:
    """Require a generated record to match the verified dist byte-for-byte."""
    if path.is_symlink() or not path.is_file():
        fail(f"release digest record is missing or not a regular file: {path}")
    data = read_toml(path, "release digest record")
    extra = sorted(set(data) - RECORD_KEYS)
    if extra:
        fail(f"release digest record has unknown keys: {', '.join(extra)}")
    if data.get("schema") != RECORD_SCHEMA:
        fail(
            f"release digest record schema must be {RECORD_SCHEMA}, "
            f"got: {data.get('schema')!r}"
        )
    if data.get("name") != component.name:
        fail(
            f"release digest record name {data.get('name')!r} differs from "
            f"{component.name!r}"
        )
    if data.get("version") != component.version:
        fail(
            f"release digest record version {data.get('version')!r} differs from "
            f"{component.version!r}"
        )
    if data.get("protocol") != [component.protocol_min, component.protocol_max]:
        fail(
            "release digest record protocol differs from the descriptor: "
            f"{data.get('protocol')!r}"
        )
    rows_data = data.get("target")
    if not isinstance(rows_data, list) or not rows_data:
        fail("release digest record must define at least one [[target]] row")

    seen: set[str] = set()
    for index, row in enumerate(rows_data):
        label = f"release digest record target[{index}]"
        if not isinstance(row, dict):
            fail(f"{label} must be a table")
        unknown = sorted(set(row) - RECORD_TARGET_KEYS)
        if unknown:
            fail(f"{label} has unknown keys: {', '.join(unknown)}")
        missing = sorted(RECORD_TARGET_KEYS - set(row))
        if missing:
            fail(f"{label} is missing keys: {', '.join(missing)}")
        triple = row["triple"]
        if not isinstance(triple, str) or triple not in infos:
            fail(f"{label} triple {triple!r} is not a supported packaged target")
        if triple in seen:
            fail(f"{label} duplicates triple {triple}")
        seen.add(triple)
        info = infos[triple]
        expected = {
            "tarball": f"{triple}.tar.gz",
            "tarball_sha256": info.tarball_sha256,
            "executable": info.executable,
            "executable_sha256": info.executable_sha256,
        }
        for key, value in expected.items():
            if row[key] != value:
                fail(
                    f"{label} {triple} {key} {row[key]!r} differs from the "
                    f"verified artifact {value!r}"
                )
    expected_targets = {target.triple for target in matrix.supported}
    if seen != expected_targets:
        missing = sorted(expected_targets - seen)
        extra = sorted(seen - expected_targets)
        detail = []
        if missing:
            detail.append(f"missing targets: {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected targets: {', '.join(extra)}")
        fail(
            "release digest record does not cover the supported matrix: "
            + "; ".join(detail)
        )


def cmd_check(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    component, matrix = load_repo(root)
    supported = ", ".join(target.triple for target in matrix.supported)
    unsupported = ", ".join(target.triple for target in matrix.unsupported) or "none"
    print(
        f"component-release: PASS (check: {component.name} {component.version}; "
        f"supported: {supported}; unsupported: {unsupported})"
    )
    return 0


def cmd_targets(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    _, matrix = load_repo(root)
    if args.format == "list":
        for target in matrix.supported:
            print(target.triple)
        return 0
    document = {
        "include": [
            {"target": target.triple, "os": target.os, "runner": target.runner}
            for target in matrix.supported
        ]
    }
    print(json.dumps(document, separators=(",", ":"), sort_keys=False))
    return 0


def cmd_manifest(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    component, matrix = load_repo(root)
    dist = Path(args.dist).resolve()
    tarballs = target_tarballs(dist, matrix)
    for target, tarball in sorted(tarballs.items()):
        write_sidecar(tarball, sha256_file(tarball))
    lines = [
        f"{sha256_file(tarballs[target])}  {tarballs[target].name}"
        for target in sorted(tarballs)
    ]
    (dist / MANIFEST_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")
    supported = {target.triple for target in matrix.supported}
    missing = sorted(supported - set(tarballs))
    note = "" if not missing else f"; targets still to package: {', '.join(missing)}"
    print(
        f"component-release: PASS (manifest: {component.name} {component.version}; "
        f"{len(tarballs)} target(s){note})"
    )
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    component, _ = load_repo(root)
    dist = Path(args.dist).resolve()
    _, verified = verify_dist(dist, root, require_full_matrix=False)
    catalog_rows = rows(component, verified["digests"])
    document = "\n".join([CATALOG_SCHEMA_LINE, *catalog_rows]) + "\n"
    if args.output:
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(document, encoding="utf-8")
        print(
            f"component-release: PASS (catalog: {len(catalog_rows)} row(s) -> {output})"
        )
    else:
        sys.stdout.write(document)
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    component, matrix = load_repo(root)
    dist = Path(args.dist).resolve()
    output = Path(args.output).resolve()
    if output == dist or dist in output.parents:
        fail("release digest record must be written outside --dist")
    _, verified = verify_dist(dist, root, require_full_matrix=True)
    document = render_record(component, matrix, verified["infos"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    print(
        f"component-release: PASS (record: {component.name} {component.version}; "
        f"{len(matrix.supported)} target(s) -> {output})"
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    component, matrix = load_repo(root)
    dist = Path(args.dist).resolve()
    _, verified = verify_dist(dist, root, require_full_matrix=True)
    if args.record:
        verify_record(
            Path(args.record).resolve(),
            component,
            matrix,
            verified["infos"],
        )
    print(
        f"component-release: PASS (verify: {component.name} {component.version}; "
        f"{len(matrix.supported)} supported target(s))"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="component-release.sh",
        description="Reusable component release matrix, manifest, catalog, and verification.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_root(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument(
            "--root",
            default=str(Path(__file__).resolve().parent.parent),
            help="component repository root (default: this checkout)",
        )

    check = subparsers.add_parser(
        "check", help="validate descriptor, version, and release matrix"
    )
    add_root(check)
    check.set_defaults(func=cmd_check)

    targets = subparsers.add_parser("targets", help="print supported release targets")
    add_root(targets)
    targets.add_argument(
        "--format", choices=("list", "json"), default="list", help="output format"
    )
    targets.set_defaults(func=cmd_targets)

    manifest = subparsers.add_parser(
        "manifest", help="regenerate sidecars and SHA256SUMS"
    )
    add_root(manifest)
    manifest.add_argument("--dist", required=True, help="packaged dist directory")
    manifest.set_defaults(func=cmd_manifest)

    catalog = subparsers.add_parser("catalog", help="emit extensions/catalog.v1 rows")
    add_root(catalog)
    catalog.add_argument("--dist", required=True, help="packaged dist directory")
    catalog.add_argument("--output", help="write the fragment here (default: stdout)")
    catalog.set_defaults(func=cmd_catalog)

    record = subparsers.add_parser(
        "record", help="write the per-target release digest record"
    )
    add_root(record)
    record.add_argument("--dist", required=True, help="packaged dist directory")
    record.add_argument(
        "--output", required=True, help="record path outside the dist directory"
    )
    record.set_defaults(func=cmd_record)

    verify = subparsers.add_parser(
        "verify", help="require the full supported matrix and verify every archive"
    )
    add_root(verify)
    verify.add_argument("--dist", required=True, help="packaged dist directory")
    verify.add_argument(
        "--record",
        help="release digest record that must match the verified artifacts",
    )
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GateError as error:
        print(f"component-release: ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
