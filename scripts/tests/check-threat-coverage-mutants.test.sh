#!/usr/bin/env bash
# Self-test for scripts/check-threat-coverage-mutants.sh.
#
# Owner: threat-coverage evidence gate.
#
# Exercises the core threat-coverage evidence scenarios:
#
#   1. A row with valid evidence (caught >= 1) PASSES.
#   2. A row with `needs_real_run: true` produces a downgrade hint
#      (`bootstrap_placeholder`) and fails by default.
#   3. A row with `coverage_state: weak_coverage` in the JSON
#      causes `check-threat-coverage.sh` (the file-existence gate
#      that owns enum policy) to FAIL with a clear message naming
#      the row.
#   4. A missing evidence file produces a downgrade hint
#      (`missing_evidence`) and FAILS the gate (without --dry-run)
#      while passing under --dry-run.
#
# We also lock in two extra invariants:
#   - `caught: 0` without `needs_real_run` produces `zero_kills`
#     and FAILS.
#   - A covered row with no `coveredBy`/`covered_by_tests` produces
#     `no_coveredby` and FAILS.
#   - Generated or conformance-only metadata cannot pass as real
#     cargo-mutants evidence by setting `needs_real_run=false`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Each case below sets CI explicitly when it needs it (case 9 opts into
# CI=true to assert the dry-run refusal). Neutralize any ambient CI value so
# the local-mode dry-run pass-cases are not tripped by the runner's CI=true.
unset CI

MODEL="$TMP_DIR/threat-model.json"
EVIDENCE_DIR="$TMP_DIR/evidence"
STUBS="$TMP_DIR/stubs"
OUT="$TMP_DIR/out"
ERR="$TMP_DIR/err"

reset_fixture() {
    rm -rf "$EVIDENCE_DIR" "$STUBS"
    mkdir -p "$EVIDENCE_DIR" "$STUBS"
}

write_model_single() {
    # write_model_single <id> <state> [<has_coveredby>=1]
    local id="$1"
    local state="$2"
    local has_coveredby="${3:-1}"
    python3 - "$MODEL" "$id" "$state" "$has_coveredby" <<'PY'
import json
import sys

path, threat_id, state, has_coveredby = sys.argv[1:5]
threat = {
    "id": threat_id,
    "name": threat_id.replace("_", " ").title(),
    "surfaces": ["native_chio"],
    "coverage_state": state,
}
if has_coveredby == "1":
    threat["coveredBy"] = [f"crates/chio-conformance/tests/threats/{threat_id}.rs"]

with open(path, "w") as fh:
    json.dump({"threats": [threat]}, fh)
    fh.write("\n")
PY
}

write_evidence() {
    # write_evidence <id> <caught> [<needs_real_run>=false] [<ran_at_override>]
    #                [<timestamp_kind>] [<evidence_status>]
    #                [<mutation_evidence_status>] [<promotion_status>]
    # Bootstrap placeholders (needs_real_run=true) require ran_at to be the
    # 1970 epoch sentinel; real-run rows record the actual timestamp.
    local id="$1"
    local caught="$2"
    local needs_real_run="${3:-false}"
    local ran_at_override="${4:-}"
    local timestamp_kind="${5:-}"
    local evidence_status="${6:-}"
    local mutation_evidence_status="${7:-}"
    local promotion_status="${8:-}"
    local ran_at
    if [[ -n "$ran_at_override" ]]; then
        ran_at="$ran_at_override"
    elif [[ "$needs_real_run" == "true" ]]; then
        ran_at="1970-01-01T00:00:00Z"
    else
        ran_at="2026-05-05T00:00:00Z"
    fi
    if [[ -z "$timestamp_kind" ]]; then
        if [[ "$needs_real_run" == "true" ]]; then
            timestamp_kind="bootstrap-placeholder"
        else
            timestamp_kind="cargo-mutants-run"
        fi
    fi
    if [[ -z "$evidence_status" ]]; then
        if [[ "$needs_real_run" == "true" ]]; then
            evidence_status="conformance-only"
        else
            evidence_status="cargo-mutants-run"
        fi
    fi
    if [[ -z "$mutation_evidence_status" ]]; then
        if [[ "$needs_real_run" == "true" ]]; then
            mutation_evidence_status="not-run"
        else
            mutation_evidence_status="complete"
        fi
    fi
    if [[ -z "$promotion_status" ]]; then
        if [[ "$needs_real_run" == "true" ]]; then
            promotion_status="not-promoted"
        else
            promotion_status="promoted"
        fi
    fi
    cat > "$EVIDENCE_DIR/$id.json" <<JSON
{
  "caught": $caught,
  "survivors": [],
  "ran_at": "$ran_at",
  "timestamp_kind": "$timestamp_kind",
  "evidence_status": "$evidence_status",
  "mutation_evidence_status": "$mutation_evidence_status",
  "promotion_status": "$promotion_status",
  "needs_real_run": $needs_real_run
}
JSON
}

write_stub() {
    local id="$1"
    local body="$2"
    printf '%s\n' '#[test]' "fn ${id}_stub() {" "    ${body}" '}' > "$STUBS/$id.rs"
}

run_mutants_gate() {
    local extra_args=("$@")
    CHIO_THREAT_MODEL_PATH="$MODEL" \
    CHIO_THREAT_EVIDENCE_DIR="$EVIDENCE_DIR" \
        bash "$REPO_ROOT/scripts/check-threat-coverage-mutants.sh" ${extra_args[@]+"${extra_args[@]}"} \
        >"$OUT" 2>"$ERR"
}

run_file_gate() {
    CHIO_THREAT_MODEL_PATH="$MODEL" \
    CHIO_THREAT_STUBS_DIR="$STUBS" \
        bash "$REPO_ROOT/scripts/check-threat-coverage.sh" >"$OUT" 2>"$ERR"
}

assert_passes() {
    local label="$1"; shift
    if ! "$@"; then
        echo "FAIL: expected pass for $label" >&2
        echo "--- stdout ---" >&2
        cat "$OUT" >&2
        echo "--- stderr ---" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

assert_fails() {
    local label="$1"; shift
    if "$@"; then
        echo "FAIL: expected failure for $label" >&2
        echo "--- stdout ---" >&2
        cat "$OUT" >&2
        echo "--- stderr ---" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

# Case 1: valid evidence (caught >= 1) PASSES.
reset_fixture
write_model_single "valid_threat" "covered"
write_evidence "valid_threat" 7 false
assert_passes "valid evidence passes" run_mutants_gate
grep -q "passed: 1" "$OUT"

# Case 2: bootstrap placeholder produces hint and fails by default because
# placeholders are not release-covered evidence.
reset_fixture
write_model_single "bootstrap_threat" "covered"
write_evidence "bootstrap_threat" 0 true
assert_fails "bootstrap placeholder fails by default" run_mutants_gate
grep -q "bootstrap placeholders: 1" "$OUT"
grep -q "WEAK: bootstrap_threat should be marked weak_coverage; reason=bootstrap_placeholder" "$OUT"

# Case 2b: same input passes only under the explicit placeholder fixture mode
# or dry-run. Release/preflight callers do not use this flag.
assert_passes "bootstrap placeholder passes under explicit fixture mode" \
    run_mutants_gate --allow-bootstrap-placeholders
grep -q "bootstrap placeholders: 1" "$OUT"

# Case 2c: same input, dry-run, also passes.
assert_passes "bootstrap placeholder passes under --dry-run" run_mutants_gate --dry-run
grep -q "bootstrap placeholders: 1" "$OUT"

# Case 3: weak_coverage in JSON FAILS the file-existence gate with a
# clear message naming the row.
reset_fixture
write_model_single "weak_threat" "weak_coverage"
write_stub "weak_threat" "assert!(true);"
assert_fails "weak_coverage state fails the file-existence gate" run_file_gate
grep -q "weak_threat (coverage_state weak_coverage" "$ERR"

# Case 4: missing evidence file produces hint and FAILS by default,
# but PASSES under --dry-run.
reset_fixture
write_model_single "missing_evidence_threat" "covered"
# Intentionally do NOT write evidence file.
assert_fails "missing evidence fails by default" run_mutants_gate
grep -q "WEAK: missing_evidence_threat should be marked weak_coverage; reason=missing_evidence" "$ERR"

assert_passes "missing evidence passes under --dry-run" run_mutants_gate --dry-run
grep -q "WEAK: missing_evidence_threat should be marked weak_coverage; reason=missing_evidence" "$ERR"

# Case 5 (extra): caught: 0 without needs_real_run FAILS with zero_kills.
reset_fixture
write_model_single "zero_kills_threat" "covered"
write_evidence "zero_kills_threat" 0 false
assert_fails "zero kills fails the gate" run_mutants_gate
grep -q "WEAK: zero_kills_threat should be marked weak_coverage; reason=zero_kills" "$ERR"

# Case 6 (extra): no coveredBy/covered_by_tests FAILS with no_coveredby.
reset_fixture
write_model_single "no_coveredby_threat" "covered" 0
# Even with valid evidence, missing coveredBy should still flag.
write_evidence "no_coveredby_threat" 5 false
assert_fails "no coveredBy fails the gate" run_mutants_gate
grep -q "WEAK: no_coveredby_threat should be marked weak_coverage; reason=no_coveredby" "$ERR"

# Case 7: bootstrap placeholder AFTER expiry FAILS with
# reason=bootstrap_expired. CHIO_BOOTSTRAP_EXPIRY=1970-01-01 forces the
# accommodation to be expired regardless of today's date.
reset_fixture
write_model_single "expired_bootstrap_threat" "covered"
write_evidence "expired_bootstrap_threat" 0 true
CHIO_BOOTSTRAP_EXPIRY="1970-01-01" \
    assert_fails "bootstrap_expired fails after expiry date" run_mutants_gate
grep -q "WEAK: expired_bootstrap_threat should be marked weak_coverage; reason=bootstrap_expired" "$ERR" \
    || { echo "FAIL: missing bootstrap_expired diagnostic"; cat "$ERR"; exit 1; }

# Case 7b: same input WITHOUT the expiry override still fails by default.
CHIO_BOOTSTRAP_EXPIRY="2099-01-01" \
    assert_fails "bootstrap placeholder fails before expiry by default" run_mutants_gate

# Case 7c: explicit fixture mode can still admit the pre-expiry placeholder.
CHIO_BOOTSTRAP_EXPIRY="2099-01-01" \
    assert_passes "bootstrap placeholder fixture mode before expiry" \
    run_mutants_gate --allow-bootstrap-placeholders

# Case 8: needs_real_run=true with non-1970 ran_at is
# rejected as inconsistent_bootstrap.
reset_fixture
write_model_single "inconsistent_bootstrap_threat" "covered"
write_evidence "inconsistent_bootstrap_threat" 0 true "2026-05-05T12:00:00Z"
assert_fails "inconsistent bootstrap (real ran_at + needs_real_run) fails" run_mutants_gate
grep -q "WEAK: inconsistent_bootstrap_threat should be marked weak_coverage; reason=inconsistent_bootstrap" "$ERR" \
    || { echo "FAIL: missing inconsistent_bootstrap diagnostic"; cat "$ERR"; exit 1; }

# Case 9: CI=true + --dry-run is rejected (exit 2).
reset_fixture
write_model_single "ci_dryrun_threat" "covered"
write_evidence "ci_dryrun_threat" 1 false
CI=true assert_fails "CI=true forbids --dry-run" run_mutants_gate --dry-run
grep -q "dry-run is not allowed in CI" "$ERR" \
    || { echo "FAIL: missing CI dry-run diagnostic"; cat "$ERR"; exit 1; }

# Case 10: partial rows are still gated by per-row mutants
# evidence. The row can remain partial, but the defended sub-vector must
# have present, non-placeholder evidence with caught >= 1.
reset_fixture
python3 - "$MODEL" <<'PY'
import json, sys
with open(sys.argv[1], "w") as fh:
    json.dump({"threats": [{
        "id": "partial_with_deferred",
        "name": "Partial With Deferred",
        "surfaces": ["native_chio"],
        "coverage_state": "partial",
        "deferred_to": "future-threat-coverage-closure",
        "coveredBy": ["crates/chio-conformance/tests/threats/partial_with_deferred.rs"],
    }]}, fh)
    fh.write("\n")
PY
# Intentionally no evidence file: partial rows now fail the mutants gate.
assert_fails "partial-with-deferred row without evidence fails" run_mutants_gate
grep -q "WEAK: partial_with_deferred should be marked weak_coverage; reason=missing_evidence" "$ERR"

write_evidence "partial_with_deferred" 2 false "2026-05-05T12:34:56Z"
assert_passes "partial-with-deferred row with evidence passes" run_mutants_gate
grep -q "passed: 1" "$OUT" \
    || { echo "FAIL: partial row with evidence should be counted as passed"; cat "$OUT"; exit 1; }

# Case 11: generated conformance metadata cannot be promoted as cargo-mutants
# evidence just by flipping needs_real_run=false and caught>=1. Exact-midnight
# timestamps are valid only when they are honestly labeled as generated
# metadata, not command wall-clock evidence.
reset_fixture
write_model_single "generated_metadata_threat" "covered"
write_evidence \
    "generated_metadata_threat" \
    1 \
    false \
    "2026-05-08T00:00:00Z" \
    "generated-metadata" \
    "conformance-only" \
    "not-run" \
    "not-promoted"
assert_fails "generated metadata cannot pass as mutants evidence" run_mutants_gate
grep -q "WEAK: generated_metadata_threat should be marked weak_coverage; reason=non_mutants_metadata" "$ERR" \
    || { echo "FAIL: missing non_mutants_metadata diagnostic"; cat "$ERR"; exit 1; }

echo "PASS: check-threat-coverage-mutants evidence matrix"
