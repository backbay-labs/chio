#!/usr/bin/env bash
# Per-row cargo-mutants gate for threat coverage.
#
# Owner: threat-coverage evidence gate.
#
# Mutation-testing backstop for threat coverage: the threat-stub
# existence gate accepts a one-line `assert!(true)` body that exercises
# no defensive logic, so this gate verifies each row's tests actually
# kill mutants.
#
# For each threat in `spec/security/chio-threat-model.v1.json`
# whose `coverage_state` is `covered` (or absent, which defaults to
# covered) or `partial`:
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
#            "needs_real_run": <bool, optional>,
#            "timestamp_kind": "cargo-mutants-run" | "command-wall-clock"
#                | "bootstrap-placeholder" | "generated-metadata" (optional),
#            "evidence_status": "cargo-mutants-run" | "conformance-only"
#                (optional),
#            "mutation_evidence_status": "complete" | "not-run" (optional),
#            "promotion_status": "promoted" | "not-promoted" (optional)
#          }
#
#      A row with `needs_real_run: true` is treated as
#      `weak_coverage` regardless of `caught`, and a downgrade hint
#      is emitted with reason `bootstrap_placeholder`. By default
#      bootstrap placeholders are hard failures: they are not release
#      evidence and must not count as covered.
#
#      Generated conformance metadata is not mutation evidence. A row
#      whose metadata says `generated-metadata`, `conformance-only`,
#      `not-run`, or `not-promoted` cannot pass the mutants evidence
#      gate by flipping `needs_real_run` to false and `caught` to a
#      positive number.
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
# Partial rows are still required to carry evidence. The row can remain
# `partial` in the threat model, but the defended sub-vector must have
# a present evidence file, a non-placeholder run status, and caught >= 1.
#
# Downgrade hint format (single line, machine-grep-able):
#
#     WEAK: <threat_id> should be marked weak_coverage; reason=<reason>
#
# Where `<reason>` is one of:
#   - `missing_evidence` - audits/evidence/threats/<id>.json is missing
#   - `zero_kills`       - the evidence file records caught == 0
#   - `no_coveredby`     - no coveredBy / covered_by_tests cross-link
#   - `bootstrap_placeholder` - needs_real_run is true before expiry; still a
#     normal failure unless --allow-bootstrap-placeholders is explicitly set
#   - `bootstrap_expired` - needs_real_run is true but today >=
#     BOOTSTRAP_EXPIRES_DATE; the accommodation has expired and the
#     row is now a real failure
#   - `inconsistent_bootstrap` - needs_real_run is true with a non-1970
#     `ran_at` timestamp (the stale-timestamp check); a real timestamp
#     contradicts the placeholder claim
#   - `non_mutants_metadata` - the row tries to pass with generated,
#     conformance-only, not-run, bootstrap, or not-promoted metadata
#
# Modes:
#   - default: any downgrade hint causes exit 1, including
#     bootstrap_placeholder.
#   - --dry-run: every downgrade hint is reported but exit code is 0,
#     so authors can iterate locally before wiring evidence. NOTE:
#     --dry-run is refused when CI=true so a CI run cannot land a PR
#     by relying on the lenient mode.
#   - --allow-bootstrap-placeholders: bootstrap placeholders are
#     reported but do not fail. This exists only for non-release
#     scaffolding fixtures; release and preflight callers must not use it.
#
# Bootstrap expiry:
#   The `needs_real_run: true` accommodation is bounded by
#   BOOTSTRAP_EXPIRES_DATE (default 2026-08-01). After that date the
#   script treats every `needs_real_run: true` evidence file as a
#   bootstrap_expired failure. CHIO_BOOTSTRAP_EXPIRY=YYYY-MM-DD
#   overrides for local development and tests.
#
# Exit codes:
#   0 - all covered rows have caught >= 1 evidence (or --dry-run, or
#       --allow-bootstrap-placeholders for bootstrap-only fixtures).
#   1 - one or more covered rows are missing real evidence and we are
#       not in --dry-run.
#   2 - argument or config error (unknown flag, --dry-run in CI,
#       invalid CHIO_BOOTSTRAP_EXPIRY, or missing python3).

set -euo pipefail

# Hard expiry for the bootstrap-placeholder accommodation. After this date,
# `needs_real_run: true` evidence files are treated as a HARD FAIL (reason
# `bootstrap_expired`) rather than an informational hint, so a slipped evidence backfill
# cannot leave 20 covered threats green forever.
#
# Local development can override this via the CHIO_BOOTSTRAP_EXPIRY env var
# (ISO-8601 date, YYYY-MM-DD).
BOOTSTRAP_EXPIRES_DATE="2026-08-01"
BOOTSTRAP_EXPIRES_DATE="${CHIO_BOOTSTRAP_EXPIRY:-$BOOTSTRAP_EXPIRES_DATE}"

DRY_RUN=0
ALLOW_BOOTSTRAP_PLACEHOLDERS=0
for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        --allow-bootstrap-placeholders)
            ALLOW_BOOTSTRAP_PLACEHOLDERS=1
            ;;
        -h|--help)
            sed -n '1,80p' "$0"
            exit 0
            ;;
        *)
            echo "error: unknown argument $arg" >&2
            echo "usage: $(basename "$0") [--dry-run] [--allow-bootstrap-placeholders]" >&2
            exit 2
            ;;
    esac
done

# Refuse --dry-run in CI: a CI run cannot rely on the lenient mode to land a
# PR. Local iteration is fine; CI is fail-closed.
if [[ "${CI:-}" == "true" && "$DRY_RUN" == "1" ]]; then
    echo "error: --dry-run is not allowed in CI" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

THREAT_MODEL="${CHIO_THREAT_MODEL_PATH:-$REPO_ROOT/spec/security/chio-threat-model.v1.json}"
EVIDENCE_DIR="${CHIO_THREAT_EVIDENCE_DIR:-$REPO_ROOT/audits/evidence/threats}"

# Decide whether the bootstrap-placeholder accommodation has expired. Use
# python3 to compare ISO-8601 dates portably (date-only, no clock-skew
# math).
BOOTSTRAP_EXPIRED=0
if ! BOOTSTRAP_EXPIRED="$(python3 - "$BOOTSTRAP_EXPIRES_DATE" <<'PY'
import datetime
import sys

expiry_str = sys.argv[1]
try:
    expiry = datetime.date.fromisoformat(expiry_str)
except ValueError:
    print(f"error: invalid CHIO_BOOTSTRAP_EXPIRY {expiry_str!r}; expected YYYY-MM-DD", file=sys.stderr)
    sys.exit(2)
print(1 if datetime.date.today() >= expiry else 0)
PY
)"; then
    echo "error: could not evaluate bootstrap expiry" >&2
    exit 2
fi

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

# Read the evidence file and emit a tab-separated record:
#   <caught> <needs_real_run> <ran_at> <survivor_count> <timestamp_kind>
#   <evidence_status> <mutation_evidence_status> <promotion_status>
# where needs_real_run is "1" or "0". Returns nonzero exit if file missing.
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
ran_at = (data.get("ran_at") or "").strip()
timestamp_kind = (data.get("timestamp_kind") or data.get("timestamp_source") or "").strip()
survivors = data.get("survivors") or []
if not isinstance(survivors, list):
    survivors = [str(survivors)]
evidence_status = (data.get("evidence_status") or "").strip()
mutation_evidence_status = (data.get("mutation_evidence_status") or "").strip()
promotion_status = (data.get("promotion_status") or "").strip()
print(
    f"{caught}\t{1 if needs_real_run else 0}\t{ran_at}\t{len(survivors)}\t"
    f"{timestamp_kind}\t{evidence_status}\t{mutation_evidence_status}\t{promotion_status}"
)
PY
}

passed=()
weak_hints=()
bootstrap_hints=()
fail=0

while IFS=$'\t' read -r tid state has_coveredby; do
    [[ -z "$tid" ]] && continue

    # `covered` and `partial` rows are both gated by mutants evidence.
    # Partial rows may remain partial, but the claimed sub-vector still
    # needs present, non-placeholder evidence with at least one caught
    # mutant.
    if [[ "$state" != "covered" && "$state" != "partial" ]]; then
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
    ran_at="$(printf '%s' "$evidence_record" | cut -f3)"
    survivor_count="$(printf '%s' "$evidence_record" | cut -f4)"
    timestamp_kind="$(printf '%s' "$evidence_record" | cut -f5)"
    evidence_status="$(printf '%s' "$evidence_record" | cut -f6)"
    mutation_evidence_status="$(printf '%s' "$evidence_record" | cut -f7)"
    promotion_status="$(printf '%s' "$evidence_record" | cut -f8)"

    if [[ "$needs_real_run" == "1" ]]; then
        # Bootstrap placeholder consistency: the stale-timestamp check requires
        # `ran_at: 1970-01-01T00:00:00Z` whenever needs_real_run is true, so
        # a real cargo-mutants run timestamp combined with needs_real_run=true
        # is internally inconsistent.
        if [[ "$ran_at" != "1970-01-01T00:00:00Z" ]]; then
            weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=inconsistent_bootstrap (needs_real_run=true requires ran_at=1970-01-01T00:00:00Z, got ${ran_at:-<missing>})")
            fail=1
            continue
        fi
        if [[ "${caught:-0}" -ne 0 || "${survivor_count:-0}" -ne 0 ]]; then
            weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=inconsistent_bootstrap (needs_real_run=true requires caught=0 and no survivors)")
            fail=1
            continue
        fi
        if [[ -n "$timestamp_kind" && "$timestamp_kind" != "bootstrap-placeholder" ]]; then
            weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=inconsistent_bootstrap (needs_real_run=true requires timestamp_kind=bootstrap-placeholder, got $timestamp_kind)")
            fail=1
            continue
        fi
        if [[ -n "$evidence_status" && "$evidence_status" != "conformance-only" ]]; then
            weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=inconsistent_bootstrap (needs_real_run=true requires evidence_status=conformance-only, got $evidence_status)")
            fail=1
            continue
        fi
        if [[ -n "$mutation_evidence_status" && "$mutation_evidence_status" != "not-run" ]]; then
            weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=inconsistent_bootstrap (needs_real_run=true requires mutation_evidence_status=not-run, got $mutation_evidence_status)")
            fail=1
            continue
        fi
        if [[ -n "$promotion_status" && "$promotion_status" != "not-promoted" ]]; then
            weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=inconsistent_bootstrap (needs_real_run=true requires promotion_status=not-promoted, got $promotion_status)")
            fail=1
            continue
        fi
        # Hard expiry: after BOOTSTRAP_EXPIRES_DATE, bootstrap placeholders
        # become a real failure (reason=bootstrap_expired).
        if [[ "$BOOTSTRAP_EXPIRED" == "1" ]]; then
            weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=bootstrap_expired (bootstrap accommodation expired on $BOOTSTRAP_EXPIRES_DATE)")
            fail=1
            continue
        fi
        bootstrap_hints+=("WEAK: $tid should be marked weak_coverage; reason=bootstrap_placeholder")
        if [[ "$ALLOW_BOOTSTRAP_PLACEHOLDERS" != "1" ]]; then
            fail=1
        fi
        continue
    fi

    if [[ -n "$timestamp_kind" && "$timestamp_kind" != "cargo-mutants-run" && "$timestamp_kind" != "command-wall-clock" ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=non_mutants_metadata (timestamp_kind=$timestamp_kind cannot pass as cargo-mutants evidence)")
        fail=1
        continue
    fi
    if [[ "$evidence_status" == "conformance-only" || "$mutation_evidence_status" == "not-run" || "$promotion_status" == "not-promoted" ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=non_mutants_metadata (metadata is ${evidence_status:-unspecified}/${mutation_evidence_status:-unspecified}/${promotion_status:-unspecified})")
        fail=1
        continue
    fi

    if [[ "$ran_at" == *"T00:00:00Z" && "$timestamp_kind" != "cargo-mutants-run" && "$timestamp_kind" != "command-wall-clock" ]]; then
        weak_hints+=("WEAK: $tid should label synthetic-looking ran_at metadata; reason=synthetic_timestamp_unlabeled")
        fail=1
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

# Always print every hint so authors see the full picture. Use the
# `${arr[@]+"${arr[@]}"}` indirection so an empty array does not trip
# `set -u` (which fires on `${empty[@]}` in older bash builds).
for h in ${bootstrap_hints[@]+"${bootstrap_hints[@]}"}; do
    echo "$h"
done
for h in ${weak_hints[@]+"${weak_hints[@]}"}; do
    echo "$h" >&2
done

if [[ "$fail" -eq 1 && "$DRY_RUN" -ne 1 ]]; then
    echo "" >&2
    echo "FAIL: per-row mutants evidence is missing or empty for one or more covered/partial threats." >&2
    echo "hint: re-run cargo-mutants for the listed rows and update audits/evidence/threats/<id>.json," >&2
    echo "       or downgrade the row to coverage_state=weak_coverage in $THREAT_MODEL." >&2
    exit 1
fi

if [[ "$fail" -eq 1 ]]; then
    echo ""
    echo "DRY-RUN: ${#weak_hints[@]} row(s) would fail the mutants gate; not exiting non-zero."
fi

echo "PASS: per-row mutants evidence gate"
