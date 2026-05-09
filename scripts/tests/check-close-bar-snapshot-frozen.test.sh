#!/usr/bin/env bash
# Integration tests for scripts/check-close-bar-snapshot-frozen.sh.
#
# Exercises:
#   1. baseline tracker matches base snapshot, gate passes;
#   2. tracker downgrades a base-DONE row to PARTIAL even though the head
#      snapshot would not catch it, gate fails;
#   3. tracker downgrades a base-PARTIAL row to NONE, gate fails;
#   4. tracker upgrades a row (allowed), gate passes.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GATE="$REPO_ROOT/scripts/check-close-bar-snapshot-frozen.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

OUT="$TMP_DIR/out"
ERR="$TMP_DIR/err"

write_tracker() {
    # write_tracker <path> <row1> [<row2> ...]
    # Each row is a pipe-separated 8-cell string.
    local path="$1"
    shift
    {
        echo "# close-bar tracker (test fixture)"
        echo
        echo "| ID | Title | Bucket | Wired runtime path | Negative conformance test | Theorem status | Wave | Notes |"
        echo "|----|-------|--------|--------------------|---------------------------|----------------|------|-------|"
        for row in "$@"; do
            echo "| $row |"
        done
    } > "$path"
}

write_snapshot() {
    local path="$1"
    shift
    python3 - "$path" "$@" <<'PY'
import json
import sys

path = sys.argv[1]
rows = []
for raw in sys.argv[2:]:
    cells = [c.strip() for c in raw.split("|")]
    rows.append({
        "id": cells[0],
        "title": cells[1],
        "bucket": cells[2],
        "wired_runtime_path": cells[3],
        "negative_conformance_test": cells[4],
        "theorem_status": cells[5],
        "wave": cells[6],
        "notes": cells[7],
    })

with open(path, "w") as fh:
    json.dump({"schema": "chio.close-bar-snapshot.v1", "rows": rows}, fh)
    fh.write("\n")
PY
}

run_gate() {
    local tracker="$1"
    local base_snapshot="$2"
    CHIO_CLOSE_BAR_TRACKER="$tracker" \
    CHIO_CLOSE_BAR_BASE_SNAPSHOT="$base_snapshot" \
        bash "$GATE" >"$OUT" 2>"$ERR"
}

assert_passes() {
    local label="$1"
    if ! run_gate "$2" "$3"; then
        echo "FAIL ($label): expected pass" >&2
        cat "$OUT" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

assert_fails() {
    local label="$1"
    if run_gate "$2" "$3"; then
        echo "FAIL ($label): expected failure" >&2
        cat "$OUT" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

# ---- Case 1: baseline pass ----------------------------------------------
T1="$TMP_DIR/baseline.md"
B1="$TMP_DIR/baseline.snapshot.json"
write_tracker "$T1" \
    "row-1 | t1 | DONE | y | scripts/check-close-bar-tracker.sh | n-a | 01 | match"
write_snapshot "$B1" \
    "row-1 | t1 | DONE | y | scripts/check-close-bar-tracker.sh | n-a | 01 | match"
assert_passes "baseline (no regression)" "$T1" "$B1"

# ---- Case 2: DONE -> PARTIAL regression (the snapshot-edit bypass) ------
# This is the key bypass: even if a hypothetical head snapshot was edited to
# match the downgrade, this gate compares the head TRACKER directly against
# the base SNAPSHOT, so the regression is visible.
T2="$TMP_DIR/regress.md"
B2="$TMP_DIR/regress.snapshot.json"
write_tracker "$T2" \
    "c-3 | x | PARTIAL | n | NONE | n-a | 02 | downgraded from DONE"
write_snapshot "$B2" \
    "c-3 | x | DONE | y | scripts/check-close-bar-tracker.sh | n-a | 02 | base says DONE"
assert_fails "DONE -> PARTIAL regression vs base snapshot" "$T2" "$B2"
grep -q "regresses against" "$ERR" \
    || { echo "FAIL: missing regression diagnostic"; cat "$ERR"; exit 1; }

# ---- Case 3: PARTIAL -> NONE regression --------------------------------
T3="$TMP_DIR/regress2.md"
B3="$TMP_DIR/regress2.snapshot.json"
write_tracker "$T3" \
    "c-3 | x | NONE | n | NONE | n-a | 02 | downgraded from PARTIAL"
write_snapshot "$B3" \
    "c-3 | x | PARTIAL | n | NONE | n-a | 02 | base says PARTIAL"
assert_fails "PARTIAL -> NONE regression vs base snapshot" "$T3" "$B3"

# ---- Case 4: upgrade is allowed -----------------------------------------
T4="$TMP_DIR/upgrade.md"
B4="$TMP_DIR/upgrade.snapshot.json"
write_tracker "$T4" \
    "c-3 | x | DONE | y | scripts/check-close-bar-tracker.sh | n-a | 02 | upgraded"
write_snapshot "$B4" \
    "c-3 | x | PARTIAL | n | NONE | n-a | 02 | base says PARTIAL"
assert_passes "upgrade NONE -> DONE allowed" "$T4" "$B4"

echo "PASS: check-close-bar-snapshot-frozen integration test"
