#!/usr/bin/env bash
# mutants-comment.sh - Post a cargo-mutants summary as a PR comment.
#
# Invoked from .github/workflows/mutants.yml mutants-pr job. Reads
# cargo-mutants JSON output (outcomes.json) under the supplied output
# dir, formats a Markdown summary, and posts it via `gh pr comment`.
#
# Usage:
#   scripts/mutants-comment.sh <pr-number> <mutants-output-dir>
#
# Environment:
#   GH_TOKEN          : required for gh pr comment.
#   MUTANTS_PACKAGE   : optional; appended to the comment header when set
#                       (CI sets it from the matrix entry).
#   CHIO_MUTANTS_GATE : optional; requested advisory or blocking comment
#                       label. The effective label is resolved from
#                       releases.toml when that file is present.
#   MUTANTS_PR_SURVIVOR_CAP
#                     : optional; number of survivors to list inline.
#
# Exit codes:
#   0  comment posted (or no comment needed because outcomes.json missing)
#   1  precondition failure (gh missing, bad args)
#
# This script is intentionally tolerant of a missing outcomes.json: when
# cargo-mutants finds zero mutants in the PR diff (the common case for
# docs-only or non-trust-boundary edits) the JSON file does not exist and
# we post a one-liner saying so rather than failing the workflow.

set -euo pipefail

PR_NUMBER="${1:-}"
OUTPUT_DIR="${2:-}"
PACKAGE="${MUTANTS_PACKAGE:-}"
REQUESTED_GATE_MODE="${CHIO_MUTANTS_GATE:-advisory}"
SURVIVOR_CAP="${MUTANTS_PR_SURVIVOR_CAP:-5}"

err() { printf '%s\n' "$*" >&2; }

if [[ -z "${PR_NUMBER}" || -z "${OUTPUT_DIR}" ]]; then
    err "usage: $0 <pr-number> <mutants-output-dir>"
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    err "missing required tool: gh"
    exit 1
fi

case "${REQUESTED_GATE_MODE}" in
    advisory|blocking) ;;
    *)
        err "invalid CHIO_MUTANTS_GATE=${REQUESTED_GATE_MODE}; expected advisory or blocking"
        exit 1
        ;;
esac

read_release_scalar() {
    local key="$1"
    local releases_toml="${2:-releases.toml}"
    local line trimmed name value
    [[ -f "${releases_toml}" ]] || return 0
    while IFS= read -r line; do
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        [[ "${trimmed}" == *=* ]] || continue
        name="${trimmed%%=*}"
        name="${name%"${name##*[![:space:]]}"}"
        if [[ "${name}" != "${key}" ]]; then
            continue
        fi
        value="${trimmed#*=}"
        value="${value%%#*}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        value="${value#\"}"
        value="${value%\"}"
        printf '%s\n' "${value}"
        return 0
    done < "${releases_toml}"
    return 0
}

resolve_gate_mode() {
    local releases_toml="releases.toml"
    local cycle_end_tag required_successes observed_successes
    if [[ ! -f "${releases_toml}" ]]; then
        printf '%s\n' "${REQUESTED_GATE_MODE}"
        return 0
    fi

    cycle_end_tag="$(read_release_scalar cycle_end_tag "${releases_toml}")"
    required_successes="$(read_release_scalar required_consecutive_nightly_successes "${releases_toml}")"
    observed_successes="$(read_release_scalar observed_consecutive_nightly_successes "${releases_toml}")"
    required_successes="${required_successes:-2}"
    observed_successes="${observed_successes:-0}"

    if [[ ! "${required_successes}" =~ ^[0-9]+$ || ! "${observed_successes}" =~ ^[0-9]+$ ]]; then
        err "invalid mutants gate evidence fields in ${releases_toml}"
        exit 1
    fi

    if [[ -n "${cycle_end_tag}" ]] && (( observed_successes >= required_successes )); then
        printf 'blocking\n'
    else
        printf 'advisory\n'
    fi
}

GATE_MODE="$(resolve_gate_mode)"
TARGET_PERCENT="$(read_release_scalar target_catch_ratio_percent releases.toml)"
TARGET_PERCENT="${TARGET_PERCENT:-80}"
if [[ ! "${TARGET_PERCENT}" =~ ^[0-9]+$ ]]; then
    err "invalid target_catch_ratio_percent=${TARGET_PERCENT}; expected integer"
    exit 1
fi

if [[ ! "${SURVIVOR_CAP}" =~ ^[0-9]+$ ]]; then
    err "invalid MUTANTS_PR_SURVIVOR_CAP=${SURVIVOR_CAP}; expected integer"
    exit 1
fi

OUTCOMES_JSON="${OUTPUT_DIR}/outcomes.json"

header="### cargo-mutants ${GATE_MODE} report"
if [[ -n "${PACKAGE}" ]]; then
    header="${header} (${PACKAGE})"
fi

if [[ ! -f "${OUTCOMES_JSON}" ]]; then
    body="${header}

No mutants generated in the PR diff for \`${PACKAGE:-the changed crate}\`.
This usually means the changes are outside trust-boundary modules
covered by \`.cargo/mutants.toml\` examine_globs, or the diff touched
only test/bench/build files. The lane mode is \`${GATE_MODE}\`; see
\`docs/fuzzing/mutants.md\` for triage policy."
    gh pr comment "${PR_NUMBER}" --body "${body}"
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    body="${header}

\`outcomes.json\` written to \`${OUTPUT_DIR}\` but \`jq\` not available
on the runner; raw report attached as a workflow artifact. The lane is
\`${GATE_MODE}\`; see \`docs/fuzzing/mutants.md\` for triage policy."
    gh pr comment "${PR_NUMBER}" --body "${body}"
    exit 0
fi

# Aggregate counts per cargo-mutants outcomes.json schema. The helper also
# tolerates object-keyed outcomes and root-array fixtures used by dry-runs.
outcomes_filter='
def outcomes:
    if (.outcomes | type) == "array" then .outcomes
    elif (.outcomes | type) == "object" then [.outcomes[]]
    elif type == "array" then .
    else []
    end;
'
total=$(jq "${outcomes_filter} outcomes | length" "${OUTCOMES_JSON}")
caught=$(jq "${outcomes_filter} outcomes | map(select((.summary // .status) == \"CaughtMutant\")) | length" "${OUTCOMES_JSON}")
missed=$(jq "${outcomes_filter} outcomes | map(select((.summary // .status) == \"MissedMutant\")) | length" "${OUTCOMES_JSON}")
timeout=$(jq "${outcomes_filter} outcomes | map(select((.summary // .status) == \"Timeout\")) | length" "${OUTCOMES_JSON}")
unviable=$(jq "${outcomes_filter} outcomes | map(select((.summary // .status) == \"Unviable\")) | length" "${OUTCOMES_JSON}")
survivors=$(( missed + timeout ))
scoreable=$(( total - unviable ))
if (( scoreable < 0 )); then
    err "invalid outcome counts: total=${total} unviable=${unviable}"
    exit 1
fi

if [[ "${scoreable}" -eq 0 ]]; then
    catch_pct="n/a"
else
    # Percentage with one decimal, integer math: caught*1000/scoreable -> "85.2".
    pct_x10=$(( caught * 1000 / scoreable ))
    catch_pct="$(( pct_x10 / 10 )).$(( pct_x10 % 10 ))%"
fi

# Surviving mutants by broad mutation class. This is intentionally heuristic:
# cargo-mutants exposes the human-readable replacement text, not a stable class
# enum in all versions.
class_breakdown=$(jq -r '
    def outcomes:
        if (.outcomes | type) == "array" then .outcomes
        elif (.outcomes | type) == "object" then [.outcomes[]]
        elif type == "array" then .
        else []
        end;
    def replacement:
        (.scenario.mutant.replacement
         // .scenario.mutant.description
         // .scenario.name
         // .description
         // "");
    def verdict: (.summary // .status // "");
    def survivor: verdict == "MissedMutant" or verdict == "Timeout";
    def mutant_class:
        if (replacement | test("^delete ")) then "deleted code"
        elif (replacement | test("replace (==|!=|<|<=|>|>=) with")) then "comparison operator"
        elif (replacement | test("replace (&&|\\|\\|) with")) then "boolean operator"
        elif (replacement | test("delete !")) then "negation"
        elif (replacement | test("-> bool")) then "boolean return"
        elif (replacement | test("-> Result")) then "result return"
        elif (replacement | test("Default::default|String::new|vec!")) then "default value"
        else "other"
        end;
    [outcomes[] | select(survivor) | mutant_class]
    | if length == 0 then empty
      else group_by(.) | map({class: .[0], count: length}) | sort_by(.class)[]
      | "| \(.class) | \(.count) |"
      end
' "${OUTCOMES_JSON}" 2>/dev/null || true)

if [[ -z "${class_breakdown}" ]]; then
    class_breakdown="_No surviving mutants._"
else
    class_breakdown="| Class | Survivors |
|-------|-----------|
${class_breakdown}"
fi

# Top surviving mutants by file:line description.
top_survivors=$(jq -r --argjson cap "${SURVIVOR_CAP}" '
    def outcomes:
        if (.outcomes | type) == "array" then .outcomes
        elif (.outcomes | type) == "object" then [.outcomes[]]
        elif type == "array" then .
        else []
        end;
    def verdict: (.summary // .status // "unknown");
    def survivor: verdict == "MissedMutant" or verdict == "Timeout";
    def pathish($value):
        if ($value | type) == "object" then
            pathish($value.path // $value.file // $value.name // empty)
        elif ($value | type) == "string" then
            if $value == "" or $value == "null" then empty else $value end
        elif $value == null then
            empty
        else
            ($value | tostring)
        end;
    def source_file:
        (pathish(.scenario.mutant.source_file)
         // pathish(.source_file)
         // pathish(.file)
         // pathish(.filename)
         // "unknown");
    def source_line:
        (.scenario.mutant.span.start.line
         // .scenario.mutant.line
         // .line
         // 0);
    def replacement:
        (.scenario.mutant.replacement
         // .scenario.mutant.description
         // .scenario.name
         // .description
         // "unknown mutation");
    [outcomes[] | select(survivor)]
    | .[0:$cap]
    | to_entries
    | map("\(.key + 1). \(.value | source_file):\(.value | source_line) - `\(.value | replacement)` (\(.value | verdict))")
    | .[]
' "${OUTCOMES_JSON}" 2>/dev/null || true)

if [[ -z "${top_survivors}" ]]; then
    top_survivors_block="_No surviving mutants in the PR diff._"
else
    top_survivors_block="${top_survivors}"
fi

body="${header}

| Crate | Mutants | Scoreable | Caught | Survivors | Missed | Timeout | Unviable | Catch ratio |
|-------|---------|-----------|--------|-----------|--------|---------|----------|-------------|
| ${PACKAGE:-unknown} | ${total} | ${scoreable} | ${caught} | ${survivors} | ${missed} | ${timeout} | ${unviable} | ${catch_pct} |

Survivor class breakdown:
${class_breakdown}

Top ${SURVIVOR_CAP} surviving mutants:
${top_survivors_block}

Mode: \`${GATE_MODE}\` | Threshold: ${TARGET_PERCENT}% | Cycle: \`releases.toml\`.
Triage policy:
\`docs/fuzzing/mutants.md\`."

gh pr comment "${PR_NUMBER}" --body "${body}"
