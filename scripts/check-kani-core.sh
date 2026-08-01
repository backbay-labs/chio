#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! cargo kani --version >/dev/null 2>&1; then
  echo "Kani core check requires cargo-kani" >&2
  exit 1
fi

cargo kani -p chio-kernel-core --lib --default-unwind 8 --no-unwinding-checks --fail-fast

# The bounded inclusion walk is the only loop-bearing refinement harness in
# this aggregate whose sufficiency is part of its evidence claim. Re-run it
# with CBMC's unwinding assertions enabled so the aggregate cannot silently
# inherit the legacy no-check posture above.
cargo kani -p chio-kernel-core --lib \
  --harness verify_oracle_inclusion_walk_parity --default-unwind 8

echo "Kani core harnesses passed"
