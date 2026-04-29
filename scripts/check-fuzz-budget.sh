#!/usr/bin/env bash
# check-fuzz-budget.sh - Self-imposed cap on GitHub Actions fuzz minutes.
#
# The public-repo free tier on GitHub Actions allows 2,000 runner-minutes
# per month. The trajectory's continuous-fuzzing-path decision (locked in
# .planning/trajectory/decisions.yml) holds ClusterFuzzLite at 1,800
# runner-minutes per rolling 30-day window, leaving 200-minute headroom
# for everything else on the free tier.
#
# This script queries the workflow-run history for the cflite_pr.yml,
# cflite_batch.yml, fuzz.yml, mutants.yml, and mutants-fuzz-cocoverage.yml workflows, sums their
# observed run wall time across the last 30 days, converts to minutes, and
# exits non-zero when the sum crosses 1,800. The orchestrator runs this on a
# scheduled cadence and as a step in cflite_batch.yml plus fuzz.yml so the
# cap acts as a hard halt rather than a soft warning.
#
# Cleanup C6: fuzz.yml was previously omitted from the WORKFLOWS array,
# which meant the native cargo-fuzz scheduled matrix could burn its full
# nightly 13 * 30 = 390 billed-min without contributing to the cap. The
# entry below restores the gate's intended coverage of every fuzz lane on
# the 1,800-min budget.
#
# Usage:
#   scripts/check-fuzz-budget.sh                      # default repo: bb-connor/arc
#   scripts/check-fuzz-budget.sh OWNER/REPO
#   GH_FUZZ_BUDGET_MINUTES=900 scripts/check-fuzz-budget.sh    # override cap
#   GH_FUZZ_BUDGET_RATE_LIMIT_MODE=warn scripts/check-fuzz-budget.sh
#
# Exit codes:
#   0  budget OK
#   1  budget exceeded (sum >= cap)
#   2  precondition failure (gh missing, jq missing, API error)
#
# Requires: gh, jq

set -euo pipefail

REPO="${1:-bb-connor/arc}"
CAP_MINUTES="${GH_FUZZ_BUDGET_MINUTES:-1800}"
WINDOW_DAYS=30
WORKFLOWS=("cflite_pr.yml" "cflite_batch.yml" "fuzz.yml" "mutants.yml" "mutants-fuzz-cocoverage.yml")

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
            err "fuzz-budget: workflow ${wf} is not registered yet; counting 0 minutes"
            continue
        fi
        if grep -Eiq 'rate limit exceeded|HTTP 403' <<<"${error_text}" \
            && [[ "${rate_limit_mode}" == "warn" ]]; then
            err "fuzz-budget: GitHub API rate limited while checking ${wf}; budget usage is unverified"
            err "fuzz-budget: continuing because GH_FUZZ_BUDGET_RATE_LIMIT_MODE=warn"
            exit 0
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
    exit 1
fi
exit 0
