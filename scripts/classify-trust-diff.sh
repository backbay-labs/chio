#!/usr/bin/env bash
# classify-trust-diff.sh - Label PRs that touch trust-boundary crates.
#
# The trust-boundary set is enumerated in
# .planning/trajectory/freezes.yml under the trust-boundary-set freeze
# entry, which mirrors EXECUTION-BOARD.md section 7 "Trust-boundary set".
# Substantive edits (non-blank, non-comment) require Security x2 review;
# cosmetic edits (whitespace, comments, doc strings) require one Security
# reviewer. This script reads the PR diff, strips blank-only and
# comment-only chunks, and prints exactly one of:
#
#   trust-boundary/none          no trust-boundary path touched
#   trust-boundary/cosmetic      only blank-or-comment changes
#   trust-boundary/substantive   non-comment code changes inside the set
#
# The orchestrator's required check (m05-freeze-guard) refuses to merge
# any PR that touches a trust-boundary path without one of the two latter
# labels.
#
# Usage:
#   scripts/classify-trust-diff.sh <diff-file>            # classify a saved diff
#   gh pr diff 123 | scripts/classify-trust-diff.sh -     # classify from stdin
#   scripts/classify-trust-diff.sh                        # diff origin/HEAD..HEAD
#
# Exit codes:
#   0  emitted exactly one label on stdout
#   2  precondition failure (yq/awk missing, malformed input)
#
# Requires: yq (mikefarah v4.x), awk, grep

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FREEZES="${ROOT}/.planning/trajectory/freezes.yml"

err() { printf '%s\n' "$*" >&2; }
require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "missing required tool: $1"
        exit 2
    fi
}

require yq
require awk
require grep
require git

if [[ ! -f "${FREEZES}" ]]; then
    err "freezes.yml not found: ${FREEZES}"
    exit 2
fi

# Source diff: file path, stdin, or computed against origin's branch tip.
src="${1:-}"
diff_text=""
if [[ "${src}" == "-" ]]; then
    diff_text="$(cat)"
elif [[ -n "${src}" ]]; then
    if [[ ! -f "${src}" ]]; then
        err "diff file not found: ${src}"
        exit 2
    fi
    diff_text="$(cat "${src}")"
else
    base_ref="$(git -C "${ROOT}" symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null \
        | sed 's|^origin/||' || echo "main")"
    diff_text="$(git -C "${ROOT}" diff --no-color "origin/${base_ref}...HEAD")"
fi

if [[ -z "${diff_text}" ]]; then
    printf 'trust-boundary/none\n'
    exit 0
fi

# Pull the trust-boundary path globs out of freezes.yml.
globs=()
while IFS= read -r glob; do
    [[ -n "${glob}" ]] && globs+=("${glob}")
done < <(yq -r '.freezes[] | select(.id == "trust-boundary-set") | .paths[]' "${FREEZES}")
if (( ${#globs[@]} == 0 )); then
    err "freezes.yml has no trust-boundary-set entry"
    exit 2
fi

glob_to_regex() {
    local g="$1"
    g="${g//./\\.}"
    g="${g//\*\*/__DOUBLESTAR__}"
    g="${g//\*/[^/]*}"
    g="${g//__DOUBLESTAR__/.*}"
    printf '^%s$' "${g}"
}

regexes=()
for g in "${globs[@]}"; do
    regexes+=("$(glob_to_regex "${g}")")
done

regex_blob=""
for regex in "${regexes[@]}"; do
    regex_blob+="${regex}"$'\034'
done

awk_path_match='
function path_matches(p) {
    for (i in regexes) {
        if (p ~ regexes[i]) return 1
    }
    return 0
}
'

# Walk the diff, tracking the current target file. For each line in a
# trust-boundary file, classify additions/removals as substantive when
# they include any non-comment, non-blank code; otherwise cosmetic.
result="$(printf '%s' "${diff_text}" | awk -v RS='\n' \
    -v RGX="${regex_blob}" \
    '
    BEGIN {
        n = split(RGX, arr, "\034")
        for (i=1; i<=n; i++) {
            if (arr[i] != "") regexes[i] = arr[i]
        }
        any_match = 0
        substantive = 0
    }
    /^diff --git / {
        # diff --git a/PATH b/PATH
        cur = $4
        sub(/^b\//, "", cur)
        in_target = 0
        for (i in regexes) {
            if (cur ~ regexes[i]) { in_target = 1; any_match = 1; break }
        }
        next
    }
    !in_target { next }
    /^[+-]{3} / { next }    # file headers
    /^@@/        { next }    # hunk headers
    /^[+-]/ {
        line = substr($0, 2)
        # Strip leading whitespace.
        sub(/^[[:space:]]+/, "", line)
        if (line == "") next
        # Comment-only? Heuristic across Rust, TS, Python, shell, YAML, TOML.
        if (line ~ /^\/\//) next        # // ...
        if (line ~ /^\/\*/) next        # /* ... */
        if (line ~ /^\*/)  next         # * ... (block comment continuation)
        if (line ~ /^#/) {
            if (line ~ /^#(!)?\[/) { substantive = 1; next } # Rust attributes.
            if (line ~ /^#!/)      { substantive = 1; next } # Shebangs.
            next                                      # # ...
        }
        if (line ~ /^;/)   next         # ; ...
        substantive = 1
    }
    END {
        if (!any_match)      print "trust-boundary/none"
        else if (substantive) print "trust-boundary/substantive"
        else                  print "trust-boundary/cosmetic"
    }
    '
)"

printf '%s\n' "${result}"
