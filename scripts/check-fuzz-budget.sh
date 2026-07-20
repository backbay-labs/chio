#!/usr/bin/env bash
# check-fuzz-budget.sh - Budget report for GitHub Actions fuzz minutes.
#
# Sums the observed run wall time of the cflite_pr.yml, cflite_batch.yml,
# fuzz.yml, mutants.yml, mutants-fuzz-cocoverage.yml, and proof-mutants.yml
# workflows across the last 30 days and converts to minutes. cap_mode defaults
# to "fail" so
# exceeding the cap hard-halts; set GH_FUZZ_BUDGET_CAP_MODE=warn only for
# ad hoc budget reports.
#
# Usage:
#   scripts/check-fuzz-budget.sh                      # default repo: backbay-labs/chio
#   scripts/check-fuzz-budget.sh OWNER/REPO
#   GH_FUZZ_BUDGET_MINUTES=900 scripts/check-fuzz-budget.sh    # override cap
#   GH_FUZZ_BUDGET_RATE_LIMIT_MODE=warn scripts/check-fuzz-budget.sh
#   GH_FUZZ_BUDGET_MISSING_WORKFLOW_MODE=warn scripts/check-fuzz-budget.sh
#   GH_FUZZ_BUDGET_CAP_MODE=warn scripts/check-fuzz-budget.sh
#
# Exit codes:
#   0  budget OK
#   1  budget exceeded (sum >= cap)
#   2  precondition failure (gh missing, jq missing, API error)
#
# Requires: gh, jq

set -euo pipefail

REPO="${1:-backbay-labs/chio}"
CAP_MINUTES="${GH_FUZZ_BUDGET_MINUTES:-1800}"
WINDOW_DAYS=30
if [[ -n "${GH_FUZZ_BUDGET_WORKFLOWS:-}" ]]; then
    IFS=',' read -r -a WORKFLOWS <<<"${GH_FUZZ_BUDGET_WORKFLOWS}"
else
    WORKFLOWS=(
        "cflite_pr.yml"
        "cflite_batch.yml"
        "fuzz.yml"
        "mutants.yml"
        "mutants-fuzz-cocoverage.yml"
        "proof-mutants.yml"
    )
fi
if [[ "${#WORKFLOWS[@]}" -eq 0 ]]; then
    err "fuzz-budget: GH_FUZZ_BUDGET_WORKFLOWS selected no workflows"
    exit 2
fi

err() { printf '%s\n' "$*" >&2; }

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "missing required tool: $1"
        exit 2
    fi
}

require gh
require jq
require date

# Compute ISO-8601 UTC timestamp for the window start.
case "$(uname -s)" in
    Darwin) since="$(date -u -v-${WINDOW_DAYS}d +%Y-%m-%dT%H:%M:%SZ)" ;;
    Linux)  since="$(date -u -d "${WINDOW_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ)" ;;
    *)      err "unsupported platform: $(uname -s)"; exit 2 ;;
esac

total_seconds=0

rate_limit_mode="${GH_FUZZ_BUDGET_RATE_LIMIT_MODE:-fail}"
missing_workflow_mode="${GH_FUZZ_BUDGET_MISSING_WORKFLOW_MODE:-fail}"
cap_mode="${GH_FUZZ_BUDGET_CAP_MODE:-fail}"

for wf in "${WORKFLOWS[@]}"; do
    runs_path="repos/${REPO}/actions/workflows/${wf}/runs"
    # Fetch runs created in the window, paginate up to 1000.
    api_error="$(mktemp)"
    if ! runs="$(gh api --paginate \
        "${runs_path}?created=>=${since}&per_page=100" \
        2>"${api_error}")"; then
        error_text="$(cat "${api_error}")"
        rm -f "${api_error}"
        if grep -Eq 'HTTP 404|Not Found' <<<"${error_text}"; then
            err "fuzz-budget: workflow ${wf} is not registered; budget usage is unverified"
            if [[ "${missing_workflow_mode}" == "warn" ]]; then
                err "fuzz-budget: continuing because GH_FUZZ_BUDGET_MISSING_WORKFLOW_MODE=warn"
                continue
            fi
            exit 2
        fi
        if grep -Eiq 'rate limit exceeded|HTTP 403' <<<"${error_text}" \
            && [[ "${rate_limit_mode}" == "warn" ]]; then
            err "fuzz-budget: GitHub API rate limited while checking ${wf}; budget usage is unverified"
            err "fuzz-budget: continuing because GH_FUZZ_BUDGET_RATE_LIMIT_MODE=warn"
            continue
        fi
        err "fuzz-budget: GitHub API failed for ${wf}: ${error_text}"
        exit 2
    fi
    rm -f "${api_error}"
    if [[ -z "${runs}" ]]; then
        err "fuzz-budget: GitHub API returned an empty runs payload for ${wf}"
        exit 2
    fi
    # gh api --paginate returns concatenated JSON objects; jq -s merges.
    # Use run wall time from the list payload instead of one timing API call
    # per run. This keeps the gate inside the GitHub App installation rate
    # limit even when several fuzz and mutation checks start together.
    if ! workflow_seconds="$(printf '%s' "${runs}" \
        | jq -s '[.[].workflow_runs[]?
            | select(.run_started_at != null and .updated_at != null)
            | ((.updated_at | fromdateiso8601) - (.run_started_at | fromdateiso8601))
            | if . < 0 then 0 else . end
        ] | add // 0 | floor')"; then
        err "fuzz-budget: failed to parse workflow runs for ${wf}"
        exit 2
    fi
    if [[ -z "${workflow_seconds}" ]]; then
        continue
    fi
    total_seconds=$(( total_seconds + workflow_seconds ))
done

total_minutes=$(( (total_seconds + 59) / 60 ))
remaining=$(( CAP_MINUTES - total_minutes ))

printf 'fuzz-budget: window=%s days, used=%d min, cap=%d min, remaining=%d min\n' \
    "${WINDOW_DAYS}" "${total_minutes}" "${CAP_MINUTES}" "${remaining}"

if (( total_minutes >= CAP_MINUTES )); then
    err "fuzz-budget: HALT - used ${total_minutes} min >= cap ${CAP_MINUTES} min in last ${WINDOW_DAYS} days"
    if [[ "${cap_mode}" == "warn" ]]; then
        err "fuzz-budget: continuing because GH_FUZZ_BUDGET_CAP_MODE=warn"
        exit 0
    fi
    exit 1
fi
exit 0
