#!/usr/bin/env bash
# Integration tests for scripts/check-close-bar-tracker.sh.
#
# Exercises:
#   1. DONE row with no negative test fails the gate.
#   2. DONE + Wired runtime path=n fails the gate (audit's "types-only" pattern).
#   3. Theorem-proven row with a missing .lean file fails the gate.
#   4. Snapshot regression (snapshot DONE -> tracker PARTIAL) fails the gate.
#   5. Baseline tracker passes the gate.
#
# Each case writes a tracker + snapshot pair into a temp dir and points the
# gate at them via the CHIO_CLOSE_BAR_* env overrides.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GATE="$REPO_ROOT/scripts/check-close-bar-tracker.sh"

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
        echo "# Trj4 close-bar tracker (test fixture)"
        echo
        echo "| ID | Title | Bucket | Wired runtime path | Negative conformance test | Theorem status | Wave | Notes |"
        echo "|----|-------|--------|--------------------|---------------------------|----------------|------|-------|"
        for row in "$@"; do
            echo "| $row |"
        done
    } > "$path"
}

write_snapshot() {
    # write_snapshot <path> <row1> [<row2> ...]
    # Each row is a pipe-separated 8-cell string (same shape as tracker).
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
    local snapshot="$2"
    local min_rows="${3:-1}"
    CHIO_CLOSE_BAR_TRACKER="$tracker" \
    CHIO_CLOSE_BAR_SNAPSHOT="$snapshot" \
    CHIO_CLOSE_BAR_CURRENT_OUT="$TMP_DIR/current.json" \
    CHIO_CLOSE_BAR_MIN_ROWS="$min_rows" \
        bash "$GATE" >"$OUT" 2>"$ERR"
}

assert_passes() {
    local label="$1"
    if ! run_gate "$2" "$3" "${4:-1}"; then
        echo "FAIL ($label): expected gate to pass, got non-zero" >&2
        cat "$OUT" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

assert_fails() {
    local label="$1"
    if run_gate "$2" "$3" "${4:-1}"; then
        echo "FAIL ($label): expected gate to fail, got 0" >&2
        cat "$OUT" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

# ---- Baseline: minimal tracker passes -------------------------------------
T1="$TMP_DIR/baseline.md"
S1="$TMP_DIR/baseline.snapshot.json"
write_tracker "$T1" \
    "row-1 | t1 | NONE | n | NONE | n-a | 02 | placeholder"
write_snapshot "$S1" \
    "row-1 | t1 | NONE | n | NONE | n-a | 02 | placeholder"
assert_passes "baseline" "$T1" "$S1" 1

# ---- Case 1: DONE row with no negative test fails -------------------------
T2="$TMP_DIR/done-no-test.md"
S2="$TMP_DIR/done-no-test.snapshot.json"
write_tracker "$T2" \
    "row-1 | t1 | DONE | y | NONE | n-a | 01 | DONE without test"
write_snapshot "$S2" \
    "row-1 | t1 | NONE | n | NONE | n-a | 01 | placeholder"
assert_fails "DONE without negative test" "$T2" "$S2" 1
grep -q "Bucket=DONE but Negative conformance test=NONE" "$ERR" \
    || { echo "FAIL: missing diagnostic for DONE-without-test"; cat "$ERR"; exit 1; }

# ---- Case 2: DONE + wired=n fails -----------------------------------------
T3="$TMP_DIR/done-not-wired.md"
S3="$TMP_DIR/done-not-wired.snapshot.json"
write_tracker "$T3" \
    "row-1 | t1 | DONE | n | scripts/trj4-preflight.sh | n-a | 01 | DONE but not wired"
write_snapshot "$S3" \
    "row-1 | t1 | NONE | n | NONE | n-a | 01 | placeholder"
assert_fails "DONE not wired (types-only pattern)" "$T3" "$S3" 1
grep -q "audit's types-only pattern" "$ERR" \
    || { echo "FAIL: missing diagnostic for DONE+not-wired"; cat "$ERR"; exit 1; }

# ---- Case 3: theorem-proven with missing .lean file fails -----------------
T4="$TMP_DIR/proven-missing.md"
S4="$TMP_DIR/proven-missing.snapshot.json"
write_tracker "$T4" \
    "row-1 | t1 | NONE | n | NONE | proven | 04 | claims formal/lean/does/not/exist.lean is proven"
write_snapshot "$S4" \
    "row-1 | t1 | NONE | n | NONE | proposed | 04 | placeholder"
assert_fails "theorem proven with missing .lean file" "$T4" "$S4" 1
grep -q "Theorem status=proven but no referenced .lean file exists" "$ERR" \
    || { echo "FAIL: missing diagnostic for theorem-proven missing file"; cat "$ERR"; exit 1; }

# ---- Case 4: snapshot regression (snapshot DONE -> tracker PARTIAL) fails -
T5="$TMP_DIR/regression.md"
S5="$TMP_DIR/regression.snapshot.json"
write_tracker "$T5" \
    "row-1 | t1 | PARTIAL | n | NONE | n-a | 04 | regressed from DONE"
write_snapshot "$S5" \
    "row-1 | t1 | DONE | y | scripts/trj4-preflight.sh | n-a | 04 | snapshot says DONE"
assert_fails "regression DONE -> PARTIAL" "$T5" "$S5" 1
grep -q "regressed DONE -> PARTIAL" "$ERR" \
    || { echo "FAIL: missing diagnostic for DONE -> PARTIAL regression"; cat "$ERR"; exit 1; }

# ---- Case 5: regression PARTIAL -> NONE fails ------------------------------
T6="$TMP_DIR/regression-pn.md"
S6="$TMP_DIR/regression-pn.snapshot.json"
write_tracker "$T6" \
    "row-1 | t1 | NONE | n | NONE | n-a | 04 | regressed from PARTIAL"
write_snapshot "$S6" \
    "row-1 | t1 | PARTIAL | n | NONE | n-a | 04 | snapshot says PARTIAL"
assert_fails "regression PARTIAL -> NONE" "$T6" "$S6" 1
grep -q "regressed PARTIAL -> NONE" "$ERR" \
    || { echo "FAIL: missing diagnostic for PARTIAL -> NONE regression"; cat "$ERR"; exit 1; }

# ---- Case 6: row count below threshold fails -------------------------------
T7="$TMP_DIR/short.md"
S7="$TMP_DIR/short.snapshot.json"
write_tracker "$T7" \
    "row-1 | t1 | NONE | n | NONE | n-a | 04 | placeholder"
write_snapshot "$S7" \
    "row-1 | t1 | NONE | n | NONE | n-a | 04 | placeholder"
assert_fails "row count below threshold" "$T7" "$S7" 145
grep -q "expected >= 145" "$ERR" \
    || { echo "FAIL: missing diagnostic for short tracker"; cat "$ERR"; exit 1; }

# ---- Case 7: DONE + Cargo.toml as test path fails (path allowlist) ---------
# A row pointing at Cargo.toml or any other non-test/evidence path must be
# rejected as "not a recognised test/evidence path", even when the file
# exists on disk.
T8="$TMP_DIR/done-cargo-toml.md"
S8="$TMP_DIR/done-cargo-toml.snapshot.json"
write_tracker "$T8" \
    "row-1 | t1 | DONE | y | Cargo.toml | n-a | 04 | DONE pointing at Cargo.toml"
write_snapshot "$S8" \
    "row-1 | t1 | NONE | n | NONE | n-a | 04 | placeholder"
assert_fails "DONE + Cargo.toml as test path" "$T8" "$S8" 1
grep -q "not a recognised test/evidence path" "$ERR" \
    || { echo "FAIL: missing diagnostic for Cargo.toml as test"; cat "$ERR"; exit 1; }

# ---- Case 8: DONE + README.md as test path fails (path allowlist) ----------
T9="$TMP_DIR/done-readme.md"
S9="$TMP_DIR/done-readme.snapshot.json"
write_tracker "$T9" \
    "row-1 | t1 | DONE | y | README.md | n-a | 04 | DONE pointing at README.md"
write_snapshot "$S9" \
    "row-1 | t1 | NONE | n | NONE | n-a | 04 | placeholder"
assert_fails "DONE + README.md as test path" "$T9" "$S9" 1
grep -q "not a recognised test/evidence path" "$ERR" \
    || { echo "FAIL: missing diagnostic for README.md as test"; cat "$ERR"; exit 1; }

# ---- Case 9: DONE + recognised scripts/*.sh path passes --------------------
# The path allowlist accepts scripts/*.sh; pointing at the gate script itself
# is a real on-disk file and matches the allowlist, so this row should pass.
T10="$TMP_DIR/done-allowed.md"
S10="$TMP_DIR/done-allowed.snapshot.json"
write_tracker "$T10" \
    "row-1 | t1 | DONE | y | scripts/check-close-bar-tracker.sh | n-a | 04 | DONE with allowlisted test"
write_snapshot "$S10" \
    "row-1 | t1 | NONE | n | NONE | n-a | 04 | placeholder"
assert_passes "DONE + allowlisted scripts/*.sh path" "$T10" "$S10" 1

echo "PASS: check-close-bar-tracker integration test"
