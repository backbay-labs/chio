#!/usr/bin/env bash
# check-mutants-rationale.sh - Verify mutation skip lists carry rationale.

set -euo pipefail

err() { printf '%s\n' "$*" >&2; }

if ! command -v git >/dev/null 2>&1; then
    err "missing required tool: git"
    exit 1
fi

files=$(git ls-files '.cargo/mutants.toml' 'crates/*/mutants.toml' 'crates/*/*/mutants.toml')
if [[ -z "${files}" ]]; then
    err "no mutants.toml files found"
    exit 1
fi

failures=0

while IFS= read -r file; do
    [[ -n "${file}" ]] || continue
    if [[ ! -f "${file}" ]]; then
        err "missing tracked mutants.toml file: ${file}"
        failures=$((failures + 1))
        continue
    fi

    in_exclude=0
    pending_rationale=0
    line_no=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line_no=$((line_no + 1))

        if [[ "${line}" =~ ^[[:space:]]*exclude_globs[[:space:]]*= ]]; then
            in_exclude=1
            pending_rationale=0
            continue
        fi

        if [[ "${in_exclude}" -eq 0 ]]; then
            continue
        fi

        if [[ "${line}" =~ ^[[:space:]]*\] ]]; then
            in_exclude=0
            pending_rationale=0
            continue
        fi

        if [[ "${line}" =~ ^[[:space:]]*$ ]]; then
            pending_rationale=0
            continue
        fi

        if [[ "${line}" =~ ^[[:space:]]*# ]]; then
            if [[ "${line}" =~ rationale: ]]; then
                pending_rationale=1
            else
                pending_rationale=0
            fi
            continue
        fi

        if [[ "${line}" =~ \"[^\"]+\" ]]; then
            if [[ "${line}" =~ rationale: ]]; then
                pending_rationale=0
                continue
            fi
            if [[ "${pending_rationale}" -eq 1 ]]; then
                pending_rationale=0
                continue
            fi
            err "${file}:${line_no}: exclude_globs entry lacks a rationale comment"
            failures=$((failures + 1))
            pending_rationale=0
        fi
    done <"${file}"
done <<<"${files}"

if [[ "${failures}" -ne 0 ]]; then
    err "mutants rationale check failed with ${failures} issue(s)"
    exit 1
fi

printf 'mutants rationale check passed for %s file(s)\n' "$(printf '%s\n' "${files}" | sed '/^$/d' | wc -l | tr -d ' ')"
