#!/usr/bin/env bash
# Regression test for mutation aggregate summary selection.
#
# A newer PENDING-RERUN summary must not mask an older measured baseline
# for the same crate. The pending file is an instruction to rerun, not a
# baseline.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

work="$(mktemp -d -t chio-mut-aggregate-XXXXXX)"
trap 'rm -rf "$work"' EXIT

mkdir -p \
  "$work/audits/mutation" \
  "$work/audits/evidence/mutants/chio-attest-verify/mutants.out"

cp "$REPO_ROOT/audits/mutation/aggregate.sh" "$work/audits/mutation/aggregate.sh"
git -C "$work" init -q

out_dir="$work/audits/evidence/mutants/chio-attest-verify/mutants.out"
seq 1 30 | sed 's/^/caught-/' > "$out_dir/caught.txt"
seq 1 38 | sed 's/^/missed-/' > "$out_dir/missed.txt"
: > "$out_dir/timeout.txt"
seq 1 18 | sed 's/^/unviable-/' > "$out_dir/unviable.txt"

evidence_dir="$work/audits/evidence/mutants/chio-attest-verify"
cat > "$evidence_dir/2026-05-08.json" <<'JSON'
{
  "crate": "chio-attest-verify",
  "result_label": "FULL-BELOW-TARGET",
  "test_scope": "package-only (--test-package chio-attest-verify)",
  "target_met": false,
  "evaluated": 68,
  "total_discovered": 86
}
JSON

cat > "$evidence_dir/2026-05-08-post-gap-closure.json" <<'JSON'
{
  "crate": "chio-attest-verify",
  "result_label": "PENDING-RERUN",
  "test_scope": "package-only (--test-package chio-attest-verify)",
  "examine_scope": "full-crate (crates/chio-attest-verify/src/**)",
  "target_met": null
}
JSON

output="$(cd "$work" && bash audits/mutation/aggregate.sh chio-attest-verify)"

if ! grep -Fq '| `chio-attest-verify` | `full-package-only` | 86 (BELOW-TARGET) | 30 | 38 | 0 | 18 | **44.1%** |' <<< "$output"; then
  echo "FAIL: aggregate did not select the measured baseline over PENDING-RERUN" >&2
  echo "$output" >&2
  exit 1
fi

if grep -Fq 'PENDING-RERUN' <<< "$output"; then
  echo "FAIL: aggregate output used PENDING-RERUN despite measured baseline" >&2
  echo "$output" >&2
  exit 1
fi

echo "mutation-aggregate-pending-rerun.test.sh: all assertions passed"
