#!/usr/bin/env bash
# mutants-baseline-kernel.sh - Run cargo-mutants baseline on chio-kernel.
#
# Behavior:
#   - If cargo-mutants is not installed locally, soft-skip with exit 0
#     and emit an install hint. CI runs the baseline on a beefy runner
#     and uploads the report; the audit doc records "TBD until CI runs"
#     until then.
#   - If cargo-mutants is available, run it scoped to the chio-kernel
#     package with a tight per-mutant timeout and write the JSON report
#     to .planning/audits/mutants-baseline-kernel.txt.
#   - Print the kill rate (caught / total) as a percentage to stdout.
#
# Environment (informational; not required):
#   MUTANTS_TIMEOUT  : per-mutant timeout in seconds (default 60).
#   MUTANTS_PACKAGE  : crate name (default chio-kernel).

set -euo pipefail

OUT_FILE=".planning/audits/mutants-baseline-kernel.txt"
PACKAGE="${MUTANTS_PACKAGE:-chio-kernel}"
TIMEOUT="${MUTANTS_TIMEOUT:-60}"

if ! command -v cargo-mutants >/dev/null 2>&1; then
  echo "WARN: cargo-mutants not installed. Install with:" >&2
  echo "  cargo install cargo-mutants --version '^25'" >&2
  echo "Skipping baseline; CI will run it." >&2
  exit 0
fi

mkdir -p "$(dirname "$OUT_FILE")"

# Run with a tight timeout to keep the baseline reproducible. Tolerate a
# non-zero exit (surviving mutants); the kill-rate calculation below is
# what we care about for the baseline snapshot.
cargo mutants \
  --package "$PACKAGE" \
  --json \
  --output "$OUT_FILE" \
  --timeout "$TIMEOUT" \
  || true

# Extract kill rate from the JSON output. cargo-mutants emits one JSON
# object per mutant with an "outcome" field; "missed" means the test
# suite did not catch the mutation. "caught" / "timeout" / "unviable"
# are the kill / quarantine outcomes.
if [ ! -f "$OUT_FILE" ]; then
  echo "ERROR: cargo-mutants produced no report at $OUT_FILE" >&2
  exit 1
fi

missed=$(grep -c '"outcome":"missed"' "$OUT_FILE" || true)
total=$(grep -c '"mutant"' "$OUT_FILE" || true)
missed=${missed:-0}
total=${total:-0}

if [ "$total" -eq 0 ]; then
  echo "ERROR: no mutants reported in $OUT_FILE; check cargo-mutants run" >&2
  exit 1
fi

# Kill rate = (total - missed) / total * 100, rounded to 2 decimals via bc.
rate=$(echo "scale=2; (1 - $missed / $total) * 100" | bc -l)
echo "${rate}%"
