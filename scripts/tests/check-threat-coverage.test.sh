#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

MODEL="$TMP_DIR/threat-model.json"
STUBS="$TMP_DIR/stubs"
EVIDENCE_DIR="$TMP_DIR/evidence"
OUT="$TMP_DIR/out"
ERR="$TMP_DIR/err"

reset_fixture() {
    rm -rf "$STUBS" "$EVIDENCE_DIR"
    mkdir -p "$STUBS" "$EVIDENCE_DIR"
}

write_model() {
    local id="$1"
    local state="$2"
    local deferred_to="${3:-}"
    python3 - "$MODEL" "$id" "$state" "$deferred_to" <<'PY'
import json
import sys

path, threat_id, state, deferred_to = sys.argv[1:5]
threat = {
    "id": threat_id,
    "name": threat_id.replace("_", " ").title(),
    "surfaces": ["native_chio"],
    "coverage_state": state,
}
if deferred_to:
    threat["deferred_to"] = deferred_to

with open(path, "w") as fh:
    json.dump({"threats": [threat]}, fh)
    fh.write("\n")
PY
}

write_stub() {
    local id="$1"
    local body="$2"
    printf '%s\n' '#[test]' "fn ${id}_stub() {" "    ${body}" '}' > "$STUBS/$id.rs"
}

write_partial_evidence() {
    local id="$1"
    local status="${2:-partial}"
    local caught="${3:-1}"
    local closure_scope="${4:-closed-sub-vector}"
    local follow_up="${5:-future sub-vector}"
    local needs_real_run="${6:-false}"
    python3 - "$EVIDENCE_DIR/$id.json" "$status" "$caught" "$closure_scope" "$follow_up" "$needs_real_run" <<'PY'
import json
import sys

path, status, caught, closure_scope, follow_up, needs_real_run = sys.argv[1:7]
with open(path, "w") as fh:
    json.dump({
        "status": status,
        "caught": int(caught),
        "needs_real_run": needs_real_run == "true",
        "closure_scope": closure_scope,
        "deferred_follow_up": follow_up,
        "ran_at": "2026-05-05T12:34:56Z",
        "timestamp_kind": "command-wall-clock",
    }, fh)
    fh.write("\n")
PY
}

run_gate() {
    CHIO_THREAT_MODEL_PATH="$MODEL" \
    CHIO_THREAT_STUBS_DIR="$STUBS" \
    CHIO_THREAT_EVIDENCE_DIR="$EVIDENCE_DIR" \
        bash "$REPO_ROOT/scripts/check-threat-coverage.sh" >"$OUT" 2>"$ERR"
}

assert_passes() {
    local label="$1"
    if ! run_gate; then
        echo "FAIL: expected pass for $label" >&2
        cat "$OUT" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

assert_fails() {
    local label="$1"
    if run_gate; then
        echo "FAIL: expected failure for $label" >&2
        cat "$OUT" >&2
        exit 1
    fi
}

reset_fixture
write_model "covered_threat" "covered"
write_stub "covered_threat" "assert!(true);"
assert_passes "covered populated stub"

# `partial` requires BOTH a non-empty deferred_to AND a populated test
# body (so the closed sub-vector is exercised). These three fixtures
# cover the failure modes and the positive accept path.

# Failure: partial without deferred_to is rejected.
reset_fixture
write_model "partial_no_deferred" "partial"
write_stub "partial_no_deferred" "assert!(true);"
assert_fails "partial state without deferred_to"
grep -q "coverage_state partial requires a non-empty deferred_to" "$ERR"

# Failure: partial with deferred_to but no in-tree stub is rejected.
reset_fixture
write_model "partial_no_stub" "partial" "future-closure"
assert_fails "partial state without in-tree stub"
grep -q "coverage_state partial requires the closed sub-vector to be exercised by an in-tree test" "$ERR"

# Failure: partial with deferred_to and stub but stub still calls
# unimplemented!() (the closed sub-vector is not actually exercised).
reset_fixture
write_model "partial_unimplemented" "partial" "future-closure"
write_stub "partial_unimplemented" 'unimplemented!("deferred sub-vector");'
write_partial_evidence "partial_unimplemented"
assert_fails "partial state with unimplemented stub"
grep -q "coverage_state partial requires the closed sub-vector test body to be populated" "$ERR"

# Failure: partial with deferred_to and populated stub but no evidence
# file is still rejected, because partial rows must prove the closed
# sub-vector rather than only name a future deferral.
reset_fixture
write_model "partial_no_evidence" "partial" "future-closure"
write_stub "partial_no_evidence" "assert!(true);"
assert_fails "partial state without evidence file"
grep -q "coverage_state partial requires an evidence file" "$ERR"

# Failure: partial evidence file must identify itself as partial.
reset_fixture
write_model "partial_bad_status" "partial" "future-closure"
write_stub "partial_bad_status" "assert!(true);"
write_partial_evidence "partial_bad_status" "covered"
assert_fails "partial state with non-partial evidence status"
grep -q "coverage_state partial requires status=partial" "$ERR"

# Failure: partial evidence must record at least one caught mutant for
# the closed sub-vector.
reset_fixture
write_model "partial_zero_caught" "partial" "future-closure"
write_stub "partial_zero_caught" "assert!(true);"
write_partial_evidence "partial_zero_caught" "partial" 0
assert_fails "partial state with zero caught evidence"
grep -q "coverage_state partial requires caught >= 1" "$ERR"

# Failure: partial rows cannot pass on bootstrap placeholders.
reset_fixture
write_model "partial_bootstrap" "partial" "future-closure"
write_stub "partial_bootstrap" "assert!(true);"
write_partial_evidence "partial_bootstrap" "partial" 1 "closed-sub-vector" "future sub-vector" true
assert_fails "partial state with bootstrap evidence"
grep -q "coverage_state partial cannot use a bootstrap placeholder" "$ERR"

# Positive: partial with deferred_to, a populated test body, and a
# partial evidence file for the closed sub-vector passes.
reset_fixture
write_model "partial_complete" "partial" "future-closure"
write_stub "partial_complete" "assert!(true);"
write_partial_evidence "partial_complete"
assert_passes "partial with deferred_to, populated stub, and evidence"

reset_fixture
write_model "pending_deferred_threat" "pending" "future-follow-up"
write_stub "pending_deferred_threat" 'unimplemented!("deferred");'
assert_passes "pending with deferred_to"

reset_fixture
write_model "pending_missing_deferred_threat" "pending"
write_stub "pending_missing_deferred_threat" 'unimplemented!("missing deferred_to");'
assert_fails "pending without deferred_to"
grep -q "pending without deferred_to" "$ERR"

# Edge case: whitespace-only deferred_to must be rejected; the schema
# enforces minLength=1 but this runtime gate is the second backstop.
reset_fixture
python3 - "$MODEL" <<'PY'
import json, sys
with open(sys.argv[1], "w") as fh:
    json.dump({"threats": [{
        "id": "pending_whitespace_deferred",
        "name": "Pending Whitespace Deferred",
        "surfaces": ["native_chio"],
        "coverage_state": "pending",
        "deferred_to": "   ",
    }]}, fh)
    fh.write("\n")
PY
write_stub "pending_whitespace_deferred" 'unimplemented!("whitespace deferred_to");'
assert_fails "pending with whitespace-only deferred_to"
grep -q "pending without deferred_to" "$ERR"

# Edge case: JSON null deferred_to must be rejected the same as missing.
reset_fixture
python3 - "$MODEL" <<'PY'
import json, sys
with open(sys.argv[1], "w") as fh:
    json.dump({"threats": [{
        "id": "pending_null_deferred",
        "name": "Pending Null Deferred",
        "surfaces": ["native_chio"],
        "coverage_state": "pending",
        "deferred_to": None,
    }]}, fh)
    fh.write("\n")
PY
write_stub "pending_null_deferred" 'unimplemented!("null deferred_to");'
assert_fails "pending with null deferred_to"
grep -q "pending without deferred_to" "$ERR"

echo "PASS: check-threat-coverage state matrix"
