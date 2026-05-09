#!/usr/bin/env bash
# Threat-model coverage CI gate.
#
# Owner: M05.P5.T4.
#
# Reads spec/security/chio-threat-model.v1.json and asserts that
# every threat ID either:
#
#   1. has a populated test body at
#      crates/chio-conformance/tests/threats/<id>.rs
#      (a file that exists and does NOT contain `unimplemented!`),
#      OR
#
#   2. carries `coverage_state: pending` plus a non-empty
#      `deferred_to` reference in the threat-model JSON, OR
#
#   3. carries `coverage_state: partial` plus a non-empty
#      `deferred_to` reference AND a populated test body at
#      `crates/chio-conformance/tests/threats/<id>.rs`, plus a
#      companion evidence file at
#      `audits/evidence/threats/<id>.json` recording
#      `status: "partial"`, `closure_scope: "<scope>"`,
#      `deferred_follow_up: "<rationale>"`, `caught >= 1`, and
#      `needs_real_run: false`. A partial row is honest reporting
#      that one sub-vector of the threat is closed by evidence today
#      while another sub-vector is deferred.
#
# Fails closed: `weak_coverage` is never accepted (the row must
# either be raised to `covered` with real mutation-testing
# evidence under `audits/evidence/threats/<id>.json` or downgraded
# to `pending` with a `deferred_to` reference), `pending` without
# `deferred_to` exits non-zero with a clear hint, and `partial`
# without both a `deferred_to` reference and an in-tree test body
# also exits non-zero. Auto-promoted pending corpus seeds (D14)
# are excluded from coverage by construction since they live in
# the corpus, not the threat list.
#
# This script handles the file-existence check only. The companion
# `check-threat-coverage-mutants.sh` enforces the per-row mutation-
# testing evidence requirement and is the gate that catches the
# `assert!(true)` failure mode flagged by the prior closeout review.

set -euo pipefail

# Find repo root (script lives at <root>/scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

THREAT_MODEL="${CHIO_THREAT_MODEL_PATH:-$REPO_ROOT/spec/security/chio-threat-model.v1.json}"
STUBS_DIR="${CHIO_THREAT_STUBS_DIR:-$REPO_ROOT/crates/chio-conformance/tests/threats}"
EVIDENCE_DIR="${CHIO_THREAT_EVIDENCE_DIR:-$REPO_ROOT/audits/evidence/threats}"

if [[ ! -f "$THREAT_MODEL" ]]; then
    echo "error: threat model not found at $THREAT_MODEL" >&2
    exit 1
fi
if [[ ! -d "$STUBS_DIR" ]]; then
    echo "error: threat-stub directory not found at $STUBS_DIR" >&2
    echo "hint: run 'cargo run -p chio-spec-codegen -- --threat-model $THREAT_MODEL --out $STUBS_DIR'" >&2
    exit 1
fi

# Pick a JSON parser. Prefer python3; fall back to jq if available.
parse_threats() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$THREAT_MODEL" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    doc = json.load(fh)
for t in doc.get("threats", []):
    tid = (t.get("id") or "").strip()
    state = (t.get("coverage_state") or "").strip()
    # Treat JSON null and whitespace-only strings as missing; the
    # schema also enforces minLength=1, this is the runtime backstop.
    deferred_to = (t.get("deferred_to") or "").strip()
    print(f"{tid}\t{state}\t{deferred_to}")
PY
    elif command -v jq >/dev/null 2>&1; then
        # `// ""` collapses null AND missing into empty string; the
        # gsub then strips leading/trailing whitespace so a
        # whitespace-only deferred_to still fails the gate.
        jq -r '.threats[] | "\(.id // "" | gsub("^\\s+|\\s+$"; ""))\t\(.coverage_state // "" | gsub("^\\s+|\\s+$"; ""))\t\(.deferred_to // "" | gsub("^\\s+|\\s+$"; ""))"' "$THREAT_MODEL"
    else
        echo "error: need python3 or jq to parse threat-model JSON" >&2
        exit 1
    fi
}

read_partial_evidence() {
    local evidence_file="$1"
    if [[ ! -f "$evidence_file" ]]; then
        return 1
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$evidence_file" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    data = json.load(fh)

print(
    "\t".join([
        str(data.get("status") or "").strip(),
        str(data.get("closure_scope") or "").strip(),
        str(data.get("deferred_follow_up") or "").strip(),
        str(int(data.get("caught", 0))),
        "1" if bool(data.get("needs_real_run", False)) else "0",
    ])
)
PY
    elif command -v jq >/dev/null 2>&1; then
        jq -r '[
          (.status // "" | gsub("^\\s+|\\s+$"; "")),
          (.closure_scope // "" | gsub("^\\s+|\\s+$"; "")),
          (.deferred_follow_up // "" | gsub("^\\s+|\\s+$"; "")),
          ((.caught // 0) | tostring),
          (if (.needs_real_run // false) then "1" else "0" end)
        ] | @tsv' "$evidence_file"
    else
        echo "error: need python3 or jq to parse partial evidence JSON" >&2
        exit 1
    fi
}

uncovered=()
covered=()
pending=()
partial=()
weak=()

while IFS=$'\t' read -r id state deferred_to; do
    [[ -z "$id" ]] && continue

    case "$state" in
        pending)
            if [[ -n "${deferred_to:-}" ]]; then
                pending+=("$id -> $deferred_to")
            else
                uncovered+=("$id (coverage_state pending without deferred_to)")
            fi
            continue
            ;;
        partial)
            # Partial is the honest signal that one sub-vector of the
            # threat is closed by a real test today and the other is
            # deferred. Accept it iff a deferred_to reference is
            # populated AND the test body exists (so the closed
            # sub-vector is actually exercised). Otherwise treat it as
            # uncovered with a clear remediation hint.
            stub_partial="$STUBS_DIR/$id.rs"
            if [[ -z "${deferred_to:-}" ]]; then
                uncovered+=("$id (coverage_state partial requires a non-empty deferred_to in $THREAT_MODEL naming the future-milestone work that closes the deferred sub-vector)")
                continue
            fi
            if [[ ! -f "$stub_partial" ]]; then
                uncovered+=("$id (coverage_state partial requires the closed sub-vector to be exercised by an in-tree test at $stub_partial)")
                continue
            fi
            if sed 's://.*::' "$stub_partial" | grep -q 'unimplemented!'; then
                uncovered+=("$id (coverage_state partial requires the closed sub-vector test body to be populated; $stub_partial still calls unimplemented!())")
                continue
            fi
            evidence_partial="$EVIDENCE_DIR/$id.json"
            if ! partial_record="$(read_partial_evidence "$evidence_partial" 2>/dev/null)"; then
                uncovered+=("$id (coverage_state partial requires an evidence file at $evidence_partial)")
                continue
            fi
            partial_status="$(printf '%s' "$partial_record" | cut -f1)"
            partial_scope="$(printf '%s' "$partial_record" | cut -f2)"
            partial_follow_up="$(printf '%s' "$partial_record" | cut -f3)"
            partial_caught="$(printf '%s' "$partial_record" | cut -f4)"
            partial_needs_real_run="$(printf '%s' "$partial_record" | cut -f5)"
            if [[ "$partial_status" != "partial" ]]; then
                uncovered+=("$id (coverage_state partial requires status=partial in $evidence_partial)")
                continue
            fi
            if [[ -z "$partial_scope" ]]; then
                uncovered+=("$id (coverage_state partial requires a non-empty closure_scope in $evidence_partial)")
                continue
            fi
            if [[ -z "$partial_follow_up" ]]; then
                uncovered+=("$id (coverage_state partial requires a non-empty deferred_follow_up in $evidence_partial)")
                continue
            fi
            if [[ "${partial_caught:-0}" -lt 1 ]]; then
                uncovered+=("$id (coverage_state partial requires caught >= 1 in $evidence_partial for the closed sub-vector)")
                continue
            fi
            if [[ "$partial_needs_real_run" == "1" ]]; then
                uncovered+=("$id (coverage_state partial cannot use a bootstrap placeholder; $evidence_partial has needs_real_run=true)")
                continue
            fi
            partial+=("$id -> $deferred_to")
            continue
            ;;
        weak_coverage)
            weak+=("$id")
            uncovered+=("$id (coverage_state weak_coverage: mutation-testing evidence is missing or shows zero kills; raise to covered with real evidence under audits/evidence/threats/<id>.json)")
            continue
            ;;
        ""|covered)
            ;;
        *)
            echo "error: threat $id has unknown coverage_state '$state' (expected covered|partial|pending|weak_coverage)" >&2
            exit 1
            ;;
    esac

    stub="$STUBS_DIR/$id.rs"
    if [[ ! -f "$stub" ]]; then
        uncovered+=("$id (missing $stub)")
        continue
    fi
    # Only treat the file as not-yet-covered when `unimplemented!`
    # appears as an actual call (not inside a `//` line comment).
    # The grep below strips line comments before matching.
    if sed 's://.*::' "$stub" | grep -q 'unimplemented!'; then
        uncovered+=("$id ($stub still calls unimplemented!())")
        continue
    fi
    covered+=("$id")
done < <(parse_threats)

echo "threat-model coverage:"
echo "  covered: ${#covered[@]}"
echo "  partial: ${#partial[@]}"
echo "  pending: ${#pending[@]}"
echo "  weak_coverage: ${#weak[@]}"
echo "  uncovered: ${#uncovered[@]}"

if [[ ${#uncovered[@]} -gt 0 ]]; then
    echo "" >&2
    echo "FAIL: threat-model coverage gate" >&2
    for u in "${uncovered[@]}"; do
        echo "  - $u" >&2
    done
    echo "" >&2
    echo "hint: either populate the test body (replace unimplemented!() with a real assertion)" >&2
    echo "       or mark the threat ID as coverage_state: pending with a non-empty deferred_to in $THREAT_MODEL" >&2
    exit 1
fi

echo "PASS: every threat ID is covered or explicitly pending with deferred_to."
