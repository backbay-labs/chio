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

err() { printf '%s\n' "$*" >&2; }

if [[ -z "${PR_NUMBER}" || -z "${OUTPUT_DIR}" ]]; then
    err "usage: $0 <pr-number> <mutants-output-dir>"
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    err "missing required tool: gh"
    exit 1
fi

OUTCOMES_JSON="${OUTPUT_DIR}/outcomes.json"

header="### cargo-mutants advisory report"
if [[ -n "${PACKAGE}" ]]; then
    header="${header} (${PACKAGE})"
fi

if [[ ! -f "${OUTCOMES_JSON}" ]]; then
    body="${header}

No mutants generated in the PR diff for \`${PACKAGE:-the changed crate}\`.
This usually means the changes are outside trust-boundary modules
covered by \`.cargo/mutants.toml\` examine_globs, or the diff touched
only test/bench/build files. The lane is advisory; see
\`docs/fuzzing/mutants.md\` for triage policy."
    gh pr comment "${PR_NUMBER}" --body "${body}"
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    body="${header}

\`outcomes.json\` written to \`${OUTPUT_DIR}\` but \`jq\` not available
on the runner; raw report attached as a workflow artifact. The lane is
advisory; see \`docs/fuzzing/mutants.md\` for triage policy."
    gh pr comment "${PR_NUMBER}" --body "${body}"
    exit 0
fi

# Aggregate counts per cargo-mutants outcomes.json schema.
total=$(jq '[.outcomes[]?] | length' "${OUTCOMES_JSON}")
caught=$(jq '[.outcomes[]? | select(.summary == "CaughtMutant")] | length' "${OUTCOMES_JSON}")
missed=$(jq '[.outcomes[]? | select(.summary == "MissedMutant")] | length' "${OUTCOMES_JSON}")
timeout=$(jq '[.outcomes[]? | select(.summary == "Timeout")] | length' "${OUTCOMES_JSON}")
unviable=$(jq '[.outcomes[]? | select(.summary == "Unviable")] | length' "${OUTCOMES_JSON}")

if [[ "${total}" -eq 0 ]]; then
    catch_pct="n/a"
else
    # Percentage with one decimal, integer math: caught*1000/total -> "85.2".
    pct_x10=$(( caught * 1000 / total ))
    catch_pct="$(( pct_x10 / 10 )).$(( pct_x10 % 10 ))%"
fi

# Top 5 missed mutants by file:line description.
top_missed=$(jq -r '
    [.outcomes[]? | select(.summary == "MissedMutant")]
    | .[0:5]
    | to_entries
    | map("\(.key + 1). \(.value.scenario.mutant.source_file.path):\(.value.scenario.mutant.span.start.line) - `\(.value.scenario.mutant.replacement)`")
    | .[]
' "${OUTCOMES_JSON}" 2>/dev/null || true)

if [[ -z "${top_missed}" ]]; then
    top_missed_block="_No surviving mutants in the PR diff._"
else
    top_missed_block="${top_missed}"
fi

body="${header}

| Crate | Mutants | Caught | Missed | Timeout | Unviable | Catch ratio |
|-------|---------|--------|--------|---------|----------|-------------|
| ${PACKAGE:-unknown} | ${total} | ${caught} | ${missed} | ${timeout} | ${unviable} | ${catch_pct} |

Top 5 missed mutants:
${top_missed_block}

Lane is **advisory** until \`releases.toml\` populates \`cycle_end_tag\`.
Triage policy:
\`docs/fuzzing/mutants.md\`."

gh pr comment "${PR_NUMBER}" --body "${body}"
