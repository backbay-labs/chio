#!/usr/bin/env bash
# update-mutants-banner.sh - Refresh the README mutation baseline banner from
# the committed trust-boundary mutation baseline.

set -euo pipefail

BASELINE_FILE="${MUTANTS_BASELINE_FILE:-docs/fuzzing/trust-boundary-mutants-baseline.toml}"
README_FILE="${MUTANTS_README_FILE:-README.md}"

err() { printf '%s\n' "$*" >&2; }

if [[ ! -f "${BASELINE_FILE}" ]]; then
    err "missing baseline file: ${BASELINE_FILE}"
    exit 1
fi

if [[ ! -f "${README_FILE}" ]]; then
    err "missing README file: ${README_FILE}"
    exit 1
fi

read_toml_number() {
    local key="$1"
    awk -F '=' -v key="${key}" '
        $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
            value = $2
            gsub(/[[:space:]]/, "", value)
            print value
            exit
        }
    ' "${BASELINE_FILE}"
}

kill_rate=$(read_toml_number "measured_kill_rate_excluding_unviable")
caught=$(read_toml_number "caught_total")
missed=$(read_toml_number "missed_total")
timeout=$(read_toml_number "timeout_total")
generated_at=$(awk -F '=' '
    $1 ~ /^[[:space:]]*generated_at[[:space:]]*$/ {
        value = $2
        gsub(/^[[:space:]]*"|"[[:space:]]*$/, "", value)
        print value
        exit
    }
' "${BASELINE_FILE}")

for name in kill_rate caught missed timeout generated_at; do
    value="${!name}"
    if [[ -z "${value}" ]]; then
        err "missing ${name} in ${BASELINE_FILE}"
        exit 1
    fi
done

if [[ ! "${kill_rate}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    err "invalid measured_kill_rate_excluding_unviable=${kill_rate}"
    exit 1
fi

if [[ ! "${caught}" =~ ^[0-9]+$ || ! "${missed}" =~ ^[0-9]+$ || ! "${timeout}" =~ ^[0-9]+$ ]]; then
    err "invalid aggregate mutant counts in ${BASELINE_FILE}"
    exit 1
fi

viable=$((caught + missed + timeout))
kill_int=$(awk -v rate="${kill_rate}" 'BEGIN { printf "%d", rate + 0.5 }')
banner="  <strong>Mutation kill: ${kill_int}%</strong> - six-crate trust-boundary mutation baseline, mixed sweep/shard n=${viable} viable mutants - ${generated_at}"

start_count=$(grep -c '<!-- chio-mutants-banner:start -->' "${README_FILE}" || true)
end_count=$(grep -c '<!-- chio-mutants-banner:end -->' "${README_FILE}" || true)
if [[ "${start_count}" -ne "${end_count}" ]]; then
    err "mismatched mutation banner markers in ${README_FILE}"
    exit 1
fi
if [[ "${start_count}" -gt 1 ]]; then
    err "multiple mutation banner blocks found in ${README_FILE}"
    exit 1
fi
mode="insert"
if [[ "${start_count}" -eq 1 ]]; then
    mode="replace"
fi

tmp=$(mktemp)
awk -v banner="${banner}" -v mode="${mode}" '
    BEGIN {
        inserted = 0
        skipping = 0
    }
    /<!-- chio-mutants-banner:start -->/ {
        print
        print "  <br/>"
        print banner
        skipping = 1
        inserted = 1
        next
    }
    /<!-- chio-mutants-banner:end -->/ {
        skipping = 0
        print
        next
    }
    skipping == 1 {
        next
    }
    {
        print
        if (mode == "insert" && inserted == 0 && $0 == "  <em>Capability validation, fail-closed policy, budgets, and signed receipts</em>") {
            print "  <!-- chio-mutants-banner:start -->"
            print "  <br/>"
            print banner
            print "  <!-- chio-mutants-banner:end -->"
            inserted = 1
        }
    }
    END {
        if (inserted == 0) {
            exit 2
        }
    }
' "${README_FILE}" >"${tmp}" || {
    rm -f "${tmp}"
    err "failed to update mutation banner in ${README_FILE}"
    exit 1
}

mv "${tmp}" "${README_FILE}"
printf 'updated %s with %s\n' "${README_FILE}" "${banner}"
