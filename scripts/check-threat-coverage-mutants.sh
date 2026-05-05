#!/usr/bin/env bash
# Per-row cargo-mutants gate for threat coverage.
#
# Owner: trajectory-4 wave-0 / E0.4.
#
# The trajectory-4 closeout audit found that the existing
# `check-threat-coverage.sh` only enforces "the threat-stub file
# exists and does not call unimplemented!()", so a one-line
# `assert!(true)` body satisfies the 20/0/0 gate without exercising
# any real defensive logic. This script is the per-row mutation-
# testing backstop.
#
# For each threat in `spec/security/chio-threat-model.v1.json`
# whose `coverage_state` is `covered` (or absent, which defaults to
# covered):
#
#   1. Read the threat's `coveredBy` (preferred) or
#      `covered_by_tests` cross-link list. If both are missing or
#      empty, emit a downgrade hint with reason `no_coveredby` and
#      exit 1 (or, in `--dry-run` mode, continue).
#
#   2. Look up the evidence file at
#      `audits/evidence/threats/<threat_id>.json`. The file is
#      expected to record the most recent mutation-testing run with
#      shape:
#
#          {
#            "caught": <int>,
#            "survivors": [<string>, ...],
#            "ran_at": "<iso8601>",
#            "needs_real_run": <bool, optional>
#          }
#
#      A row with `needs_real_run: true` is treated as
#      `weak_coverage` regardless of `caught`, and a downgrade hint
#      is emitted with reason `bootstrap_placeholder`. The script
#      does NOT exit 1 on bootstrap placeholders (this is the
#      temporary scaffolding accommodation that lets the PR land
#      while wave 4 backfills real evidence).
#
#   3. If the evidence file is missing, emit a downgrade hint with
#      reason `missing_evidence` and exit 1 (unless `--dry-run`).
#
#   4. If `caught == 0` and `needs_real_run` is not true, emit a
#      downgrade hint with reason `zero_kills` and exit 1 (unless
#      `--dry-run`).
#
#   5. If `caught >= 1`, the row passes.
#
# Downgrade hint format (single line, machine-grep-able):
#
#     WEAK: <threat_id> should be marked weak_coverage; reason=<reason>
#
# Where `<reason>` is one of:
#   - `missing_evidence` - audits/evidence/threats/<id>.json is missing
#   - `zero_kills`       - the evidence file records caught == 0
#   - `no_coveredby`     - no coveredBy / covered_by_tests cross-link
#   - `bootstrap_placeholder` - needs_real_run is true (informational)
#
# Modes:
#   - default: any non-bootstrap downgrade hint causes exit 1.
#   - --dry-run: every downgrade hint is reported but exit code is 0,
#     so authors can iterate locally before wiring evidence.
#
# Exit codes:
#   0 - all covered rows have caught >= 1 evidence (or every offending
#       row is a bootstrap placeholder, or --dry-run).
#   1 - one or more covered rows are missing real evidence and we are
#       not in --dry-run.

set -euo pipefail

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            sed -n '1,80p' "$0"
            exit 0
            ;;
        *)
            echo "error: unknown argument $arg" >&2
            echo "usage: $(basename "$0") [--dry-run]" >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

THREAT_MODEL="${CHIO_THREAT_MODEL_PATH:-$REPO_ROOT/spec/security/chio-threat-model.v1.json}"
EVIDENCE_DIR="${CHIO_THREAT_EVIDENCE_DIR:-$REPO_ROOT/audits/evidence/threats}"

if [[ ! -f "$THREAT_MODEL" ]]; then
    echo "error: threat model not found at $THREAT_MODEL" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to parse threat-model JSON" >&2
    exit 1
fi

# Emit one tab-separated record per row needing classification:
#   <threat_id>\t<state>\t<has_coveredby>
# where state is whatever appears in the JSON (default 'covered').
classify_threats() {
    python3 - "$THREAT_MODEL" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    doc = json.load(fh)

for t in doc.get("threats", []):
    tid = (t.get("id") or "").strip()
    if not tid:
        continue
    state = (t.get("coverage_state") or "covered").strip() or "covered"
    coveredby = t.get("coveredBy") or t.get("covered_by_tests") or []
    has_coveredby = "1" if coveredby else "0"
    print(f"{tid}\t{state}\t{has_coveredby}")
PY
}

# Read the evidence file and emit `<caught>\t<needs_real_run>` where
# needs_real_run is "1" or "0". Returns nonzero exit if file missing.
read_evidence() {
    local evidence_file="$1"
    if [[ ! -f "$evidence_file" ]]; then
        return 1
    fi
    python3 - "$evidence_file" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    data = json.load(fh)

caught = int(data.get("caught", 0))
needs_real_run = bool(data.get("needs_real_run", False))
print(f"{caught}\t{1 if needs_real_run else 0}")
PY
}

passed=()
weak_hints=()
bootstrap_hints=()
fail=0

while IFS=$'\t' read -r tid state has_coveredby; do
    [[ -z "$tid" ]] && continue

    # Only `covered` rows are gated by mutants evidence. Rows that
    # are explicitly partial / pending / weak_coverage are handled
    # by the file-existence gate (`check-threat-coverage.sh`).
    if [[ "$state" != "covered" ]]; then
        continue
    fi

    if [[ "$has_coveredby" != "1" ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=no_coveredby")
        fail=1
        continue
    fi

    evidence_file="$EVIDENCE_DIR/$tid.json"
    if ! evidence_record="$(read_evidence "$evidence_file" 2>/dev/null)"; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=missing_evidence")
        fail=1
        continue
    fi

    caught="$(printf '%s' "$evidence_record" | cut -f1)"
    needs_real_run="$(printf '%s' "$evidence_record" | cut -f2)"

    if [[ "$needs_real_run" == "1" ]]; then
        # Bootstrap placeholder. Emit hint but DO NOT raise fail.
        bootstrap_hints+=("WEAK: $tid should be marked weak_coverage; reason=bootstrap_placeholder")
        continue
    fi

    if [[ "${caught:-0}" -lt 1 ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=zero_kills")
        fail=1
        continue
    fi

    passed+=("$tid")
done < <(classify_threats)

echo "threat-model mutants gate:"
echo "  passed: ${#passed[@]}"
echo "  weak (real failures): ${#weak_hints[@]}"
echo "  bootstrap placeholders: ${#bootstrap_hints[@]}"

# Always print every hint so authors see the full picture.
for h in "${bootstrap_hints[@]}"; do
    echo "$h"
done
for h in "${weak_hints[@]}"; do
    echo "$h" >&2
done

if [[ "$fail" -eq 1 && "$DRY_RUN" -ne 1 ]]; then
    echo "" >&2
    echo "FAIL: per-row mutants evidence is missing or empty for one or more covered threats." >&2
    echo "hint: re-run cargo-mutants for the listed rows and update audits/evidence/threats/<id>.json," >&2
    echo "       or downgrade the row to coverage_state=weak_coverage in $THREAT_MODEL." >&2
    exit 1
fi

if [[ "$fail" -eq 1 ]]; then
    echo ""
    echo "DRY-RUN: ${#weak_hints[@]} row(s) would fail the mutants gate; not exiting non-zero."
fi

echo "PASS: per-row mutants evidence gate"
