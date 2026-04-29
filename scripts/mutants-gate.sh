#!/usr/bin/env bash
# mutants-gate.sh - Decide advisory or blocking posture for cargo-mutants.
#
# Reads releases.toml at the repository root:
#
#   [mutants]
#   phase3_merge_tag = "vX.Y.Z"   # tag of the M02 P3 merge release
#   cycle_end_tag    = ""          # filled in by the next release after P3
#
# Posture rule:
#   - cycle_end_tag empty (default today)  -> advisory; exit 0 unconditionally.
#   - cycle_end_tag non-empty               -> blocking; exit 1 when the
#                                              upstream cargo-mutants step
#                                              reported a non-zero exit
#                                              (surviving mutants beyond
#                                              the per-crate budget).
#
# Environment:
#   MUTANTS_PACKAGE     : crate name being scored (informational).
#   MUTANTS_OUTPUT_DIR  : directory holding cargo-mutants outcomes.json
#                         (informational; reserved for the M02 P3 catch-
#                         ratio threshold check).
#   MUTANTS_EXIT        : exit code from the cargo-mutants step
#                         (0 = clean, non-zero = survivors).
#   MUTANTS_GATE_OVERRIDE_REASON
#                       : optional escape hatch. When set to a non-empty
#                         string, a blocking-fail verdict is
#                         downgraded to a loud advisory pass: the script
#                         emits a `WARN mutants-gate-override` line on
#                         stderr, appends an audit row to
#                         docs/fuzzing/mutants-overrides.log (timestamp,
#                         package, exit code, cycle_end_tag, reason) and
#                         exits 0. Empty/unset = no override (default).
#                         The corresponding label-based override path is a
#                         PR titled `mutants-gate-override` that clears
#                         cycle_end_tag in releases.toml; CODEOWNERS gates
#                         that PR on principal-engineer review.
#
# Exit codes:
#   0 advisory pass (or blocking pass when survivors == 0, or
#     blocking-fail downgraded by MUTANTS_GATE_OVERRIDE_REASON)
#   1 blocking fail (cycle_end_tag non-empty AND survivors detected AND
#     no override reason supplied)
#
# This script is invoked by .github/workflows/mutants.yml's mutants-pr
# and mutants-nightly jobs. It is also safe to run locally:
#
#   MUTANTS_EXIT=0 bash scripts/mutants-gate.sh
#
# Today releases.toml ships with cycle_end_tag empty so this script
# always exits 0; the M02 P3 release-binaries auto-flip will populate
# cycle_end_tag and start enforcing without a workflow edit.

set -euo pipefail

PACKAGE="${MUTANTS_PACKAGE:-unknown}"
OUTPUT_DIR="${MUTANTS_OUTPUT_DIR:-}"
EXIT_CODE="${MUTANTS_EXIT:-0}"
OVERRIDE_REASON="${MUTANTS_GATE_OVERRIDE_REASON:-}"

# Locate releases.toml relative to the script. The script lives in
# scripts/ at the repo root, so releases.toml sits one directory up.
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
releases_toml="${repo_root}/releases.toml"

if [[ ! -f "${releases_toml}" ]]; then
    printf 'mutants-gate: releases.toml missing at %s; defaulting to advisory\n' \
        "${releases_toml}" >&2
    printf 'mutants-gate: package=%s exit=%s posture=advisory verdict=pass\n' \
        "${PACKAGE}" "${EXIT_CODE}"
    exit 0
fi

# Extract cycle_end_tag value. Tolerate whitespace and quoting variants:
#   cycle_end_tag = ""
#   cycle_end_tag="vX.Y.Z"
# Stripped to the unquoted string. A pure-bash extractor avoids a TOML
# parser dependency on the runner.
cycle_end_tag=""
while IFS= read -r line; do
    # Strip leading and trailing whitespace.
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    case "${trimmed}" in
        cycle_end_tag*=*)
            value="${trimmed#*=}"
            # Strip leading whitespace and surrounding double-quotes.
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value#\"}"
            value="${value%\"}"
            cycle_end_tag="${value}"
            break
            ;;
    esac
done < "${releases_toml}"

if [[ -z "${cycle_end_tag}" ]]; then
    printf 'mutants-gate: package=%s exit=%s posture=advisory verdict=pass (cycle_end_tag empty)\n' \
        "${PACKAGE}" "${EXIT_CODE}"
    exit 0
fi

# Blocking posture: cycle_end_tag is set. Any non-zero upstream exit fails
# the gate.
if [[ "${EXIT_CODE}" == "0" ]]; then
    printf 'mutants-gate: package=%s exit=0 posture=blocking verdict=pass (cycle_end_tag=%s)\n' \
        "${PACKAGE}" "${cycle_end_tag}"
    exit 0
fi

printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=fail (cycle_end_tag=%s)\n' \
    "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" >&2
if [[ -n "${OUTPUT_DIR}" && -d "${OUTPUT_DIR}" ]]; then
    printf 'mutants-gate: see %s for outcomes.json detail\n' "${OUTPUT_DIR}" >&2
fi

# MUTANTS_GATE_OVERRIDE_REASON downgrades a blocking fail to a loud advisory
# pass and appends an audit row. The corresponding permanent path is a PR
# labelled `mutants-gate-override` that clears cycle_end_tag in
# releases.toml; CODEOWNERS gates that PR on principal engineer review. The
# env-var path here exists for in-flight CI runs where waiting on a
# CODEOWNERS-reviewed PR is not feasible (e.g. a release-train hot-fix).
# Either path leaves an audit trail.
if [[ -n "${OVERRIDE_REASON}" ]]; then
    audit_log="${repo_root}/docs/fuzzing/mutants-overrides.log"
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # Sanitize the reason: collapse newlines/tabs to single spaces so the
    # audit row stays on one line. Pipe character is reserved as the field
    # separator; replace any embedded pipes with a slash.
    reason_clean="${OVERRIDE_REASON//$'\n'/ }"
    reason_clean="${reason_clean//$'\t'/ }"
    reason_clean="${reason_clean//|/\/}"
    actor="${GITHUB_ACTOR:-${USER:-unknown}}"
    if [[ -f "${audit_log}" ]]; then
        printf '%s | package=%s | exit=%s | cycle_end_tag=%s | actor=%s | reason=%s\n' \
            "${timestamp}" "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}" \
            "${actor}" "${reason_clean}" >> "${audit_log}"
    else
        printf 'mutants-gate: WARN audit log missing at %s; override not recorded\n' \
            "${audit_log}" >&2
    fi
    printf 'mutants-gate: WARN mutants-gate-override engaged package=%s actor=%s reason=%s\n' \
        "${PACKAGE}" "${actor}" "${reason_clean}" >&2
    printf 'mutants-gate: package=%s exit=%s posture=blocking verdict=override (cycle_end_tag=%s)\n' \
        "${PACKAGE}" "${EXIT_CODE}" "${cycle_end_tag}"
    exit 0
fi

exit 1
