#!/usr/bin/env bash
# regen-codeowners.sh - Regenerate the root CODEOWNERS file from
# .planning/trajectory/OWNERS.toml. CI fails if CODEOWNERS has drifted
# from the regenerated output, so this script is the single source of
# truth for any CODEOWNERS edit.
#
# Behaviour:
#   1. Read [teams] mapping; resolve every milestone slug, SEQUENCER,
#      M05_FREEZE, and SECURITY label to a GitHub handle.
#   2. Read [[ownership]] entries in declaration order. Frozen entries
#      sort to the end so later patterns override earlier ones (which is
#      how CODEOWNERS precedence works).
#   3. Emit one CODEOWNERS line per ownership entry, deduplicating
#      multi-owner paths down to the unique handle set.
#
# Usage:
#   scripts/regen-codeowners.sh                  # rewrites CODEOWNERS in place
#   scripts/regen-codeowners.sh --check          # exits non-zero on drift
#   scripts/regen-codeowners.sh --print          # emit to stdout, no write
#
# Exit codes:
#   0  success (or no drift in --check mode)
#   1  drift detected in --check mode
#   2  precondition failure (yq missing, OWNERS.toml invalid)
#
# Requires: yq (mikefarah v4.x)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OWNERS="${ROOT}/.planning/trajectory/OWNERS.toml"
CODEOWNERS="${ROOT}/CODEOWNERS"
GITHUB_CODEOWNERS="${ROOT}/.github/CODEOWNERS"

mode="write"
case "${1:-}" in
    --check) mode="check" ;;
    --print) mode="print" ;;
    "")      mode="write" ;;
    *)       printf 'unknown flag: %s\n' "$1" >&2; exit 2 ;;
esac

err() { printf '%s\n' "$*" >&2; }
if ! command -v yq >/dev/null 2>&1; then
    err "missing required tool: yq (mikefarah v4.x)"
    exit 2
fi
if [[ ! -f "${OWNERS}" ]]; then
    err "OWNERS.toml not found: ${OWNERS}"
    exit 2
fi

generated="$(yq -p=toml -oy '
    .teams as $teams
    | .ownership
    | map(select(.codeowners != false))
    | map(. + {"handles": [.owners[] | $teams[.] // ("@MISSING_TEAM_" + .)] | unique})
    | sort_by((.frozen // false))
    | .[]
    | .glob + " " + (.handles | join(" "))
' "${OWNERS}")"

if [[ -z "${generated}" ]]; then
    err "yq produced empty CODEOWNERS body; OWNERS.toml may be malformed"
    exit 2
fi

# Pad the path column so handles align at column 45 when feasible.
formatted="$(printf '%s\n' "${generated}" | awk '
    {
        path=$1
        $1=""
        rest=substr($0, 2)
        if (length(path) < 45) {
            printf "%-44s %s\n", path, rest
        } else {
            printf "%s %s\n", path, rest
        }
    }
')"

header="$(cat <<'HEADER'
# CODEOWNERS - GENERATED from .planning/trajectory/OWNERS.toml
# Do not hand-edit. Regenerate with `scripts/regen-codeowners.sh`.
# CI fails if this file drifts from OWNERS.toml.
#
# Order matters in CODEOWNERS: later patterns take precedence over earlier
# ones. The generator places frozen entries last so they override any
# broader pattern.

HEADER
)"

new_content="${header}
${formatted}"

case "${mode}" in
    print)
        printf '%s\n' "${new_content}"
        ;;
    write)
        printf '%s\n' "${new_content}" > "${CODEOWNERS}"
        mkdir -p "$(dirname "${GITHUB_CODEOWNERS}")"
        printf '%s\n' "${new_content}" > "${GITHUB_CODEOWNERS}"
        printf 'wrote %s\n' "${CODEOWNERS}"
        printf 'wrote %s\n' "${GITHUB_CODEOWNERS}"
        ;;
    check)
        if [[ ! -f "${CODEOWNERS}" ]]; then
            err "CODEOWNERS missing; run regen-codeowners.sh"
            exit 1
        fi
        existing="$(cat "${CODEOWNERS}")"
        if [[ "${existing}" != "${new_content}" ]]; then
            err "CODEOWNERS drift detected; run scripts/regen-codeowners.sh"
            diff -u <(printf '%s\n' "${existing}") <(printf '%s\n' "${new_content}") || true
            exit 1
        fi
        if [[ ! -f "${GITHUB_CODEOWNERS}" || -L "${GITHUB_CODEOWNERS}" ]]; then
            err ".github/CODEOWNERS must be a regular file; run scripts/regen-codeowners.sh"
            exit 1
        fi
        github_existing="$(cat "${GITHUB_CODEOWNERS}")"
        if [[ "${github_existing}" != "${new_content}" ]]; then
            err ".github/CODEOWNERS drift detected; run scripts/regen-codeowners.sh"
            diff -u <(printf '%s\n' "${github_existing}") <(printf '%s\n' "${new_content}") || true
            exit 1
        fi
        printf 'CODEOWNERS in sync with OWNERS.toml\n'
        ;;
esac
