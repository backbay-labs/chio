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
#      `deferred_to` reference in the threat-model JSON.
#
# Fails closed: `partial` is never accepted, and `pending` without
# `deferred_to` exits non-zero with a clear hint. Auto-promoted
# pending corpus seeds (D14) are excluded from coverage by
# construction since they live in the corpus, not the threat list.

set -euo pipefail

# Find repo root (script lives at <root>/scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

THREAT_MODEL="${CHIO_THREAT_MODEL_PATH:-$REPO_ROOT/spec/security/chio-threat-model.v1.json}"
STUBS_DIR="${CHIO_THREAT_STUBS_DIR:-$REPO_ROOT/crates/chio-conformance/tests/threats}"

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

uncovered=()
covered=()
pending=()
partial=()

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
            partial+=("$id")
            uncovered+=("$id (coverage_state partial is not allowed after M05.P4)")
            continue
            ;;
        ""|covered)
            ;;
        *)
            echo "error: threat $id has unknown coverage_state '$state' (expected covered|partial|pending)" >&2
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
