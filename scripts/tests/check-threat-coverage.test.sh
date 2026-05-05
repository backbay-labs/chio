#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

MODEL="$TMP_DIR/threat-model.json"
STUBS="$TMP_DIR/stubs"
OUT="$TMP_DIR/out"
ERR="$TMP_DIR/err"

reset_fixture() {
    rm -rf "$STUBS"
    mkdir -p "$STUBS"
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

run_gate() {
    CHIO_THREAT_MODEL_PATH="$MODEL" \
    CHIO_THREAT_STUBS_DIR="$STUBS" \
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

reset_fixture
write_model "partial_threat" "partial"
write_stub "partial_threat" "assert!(true);"
assert_fails "partial state"
grep -q "coverage_state partial is not allowed" "$ERR"

reset_fixture
write_model "pending_deferred_threat" "pending" "trajectory-4.follow-up"
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
