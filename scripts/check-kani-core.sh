#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! cargo kani --version >/dev/null 2>&1; then
  echo "Kani core check requires cargo-kani" >&2
  exit 1
fi

cargo kani -p chio-kernel-core --lib --default-unwind 8 --no-unwinding-checks --fail-fast

echo "Kani core harnesses passed"
