#!/usr/bin/env bash
# component-release.sh — thin cross-platform entry point for the reusable
# component release matrix tooling (component_release.py).
#
# Shared verbatim by the extension component repositories. Call sites use
# this wrapper so Linux, macOS, and Windows runners all resolve a working
# Python 3.11+ interpreter (tomllib) without repeating the probe:
#
#   scripts/component-release.sh check
#   scripts/component-release.sh targets --format json
#   scripts/component-release.sh manifest --dist dist
#   scripts/component-release.sh catalog --dist dist --output catalog/catalog.v1
#   scripts/component-release.sh verify --dist dist [--record release/component-digests.toml]
#   scripts/component-release.sh record --dist dist --output release/component-digests.toml
#   scripts/component-release.sh smoke --binary PATH
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

python_bin=""
for candidate in python3 python; do
	if ! command -v "$candidate" >/dev/null 2>&1; then
		continue
	fi
	if "$candidate" -c 'import sys, tomllib; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
		python_bin="$candidate"
		break
	fi
done

if [[ -z "$python_bin" ]]; then
	printf '%s\n' \
		'component-release: ERROR: Python 3.11+ with tomllib is required (python3 or python)' >&2
	exit 1
fi

if [[ "${1:-}" == "smoke" ]]; then
	shift
	exec "$python_bin" "$SCRIPT_DIR/component_smoke.py" "$@"
fi

exec "$python_bin" "$SCRIPT_DIR/component_release.py" "$@"
