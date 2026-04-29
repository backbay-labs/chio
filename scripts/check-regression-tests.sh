#!/usr/bin/env bash
# scripts/check-regression-tests.sh
#
# Regression-test deletion guard. Detects deletion of fuzz-promoted regression
# tests under either tests/regression_*.rs (legacy layout) or
# crates/*/tests/regression_*.rs (current layout). Fails CI when any such
# file disappears between BASE..HEAD without a paired issue link in the PR
# body or merge commit message.
#
# Mechanism:
#   1. git diff --diff-filter=D --name-only $BASE..$HEAD
#   2. filter for tests/regression_*.rs or crates/*/tests/regression_*.rs
#   3. for each deleted file, look for a paired issue link in:
#        - the GitHub PR body (PR_BODY env var, set by ci.yml step)
#        - the range of commit messages between BASE and HEAD
#      A "paired issue link" is one of:
#        - "closes #N", "fixes #N", "resolves #N", "tracks #N"  (any case)
#        - a URL to a github.com issue or PR
#   4. exit 0 if no deletions OR every deletion is paired; exit 1 otherwise.
#
# Usage:
#   check-regression-tests.sh [--dry-run] [--base REF] [--head REF] [--help]
#
# Args:
#   --dry-run    no-op self-test, exit 0 (used by gate_check)
#   --base REF   base ref (default: origin/main, or $GITHUB_BASE_REF)
#   --head REF   head ref (default: HEAD)
#   --help       show this help and exit 0


set -euo pipefail

usage() {
    cat <<'EOF'
Usage: check-regression-tests.sh [--dry-run] [--base REF] [--head REF] [--help]

Regression-test deletion guard. Fails CI when a regression_*.rs file is
deleted between BASE..HEAD without a paired issue link in the PR body
or commit messages.

Args:
  --dry-run    no-op self-test, exit 0
  --base REF   base ref (default: origin/main or $GITHUB_BASE_REF)
  --head REF   head ref (default: HEAD)
  --help       show this help

Env:
  PR_BODY        GitHub PR body, used to look for paired issue links
  GITHUB_BASE_REF  fallback for --base when running under actions/checkout

Exit codes:
  0  no deletions, or every deletion paired with an issue link
  1  unpaired deletion detected
  2  invocation error
EOF
}

DRY_RUN=0
BASE=""
HEAD_REF="HEAD"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --base)
            if [[ $# -lt 2 ]]; then
                echo "check-regression-tests: --base requires an argument" >&2
                exit 2
            fi
            BASE="$2"
            shift 2
            ;;
        --head)
            if [[ $# -lt 2 ]]; then
                echo "check-regression-tests: --head requires an argument" >&2
                exit 2
            fi
            HEAD_REF="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "check-regression-tests: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "check-regression-tests: dry-run OK"
    exit 0
fi

# Resolve BASE if not given. Three cases:
#   1. PR runs: GITHUB_BASE_REF is set; diff against the merge target.
#   2. Push runs: prefer the pre-push SHA (GitHub injects it as
#      `github.event.before`, which surfaces here as GITHUB_EVENT_BEFORE
#      when the workflow forwards it). Fall back to HEAD~1 so the diff
#      is against the previous commit on the same branch rather than
#      `origin/main`, which on a post-push checkout points to HEAD itself
#      and would always produce an empty diff.
#   3. Local / unknown: default to origin/main (developer-facing usage).
if [[ -z "$BASE" ]]; then
    if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
        BASE="origin/${GITHUB_BASE_REF}"
    elif [[ "${GITHUB_EVENT_NAME:-}" == "push" ]]; then
        if [[ -n "${GITHUB_EVENT_BEFORE:-}" ]] \
            && [[ "${GITHUB_EVENT_BEFORE}" != "0000000000000000000000000000000000000000" ]] \
            && git rev-parse --verify --quiet "${GITHUB_EVENT_BEFORE}" >/dev/null 2>&1; then
            BASE="${GITHUB_EVENT_BEFORE}"
        elif git rev-parse --verify --quiet "HEAD~1" >/dev/null 2>&1; then
            BASE="HEAD~1"
        else
            BASE="origin/main"
        fi
    else
        BASE="origin/main"
    fi
fi

# Sanity-check refs exist.
if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
    echo "check-regression-tests: base ref '$BASE' not found" >&2
    exit 2
fi
if ! git rev-parse --verify --quiet "$HEAD_REF" >/dev/null; then
    echo "check-regression-tests: head ref '$HEAD_REF' not found" >&2
    exit 2
fi

# Collect deleted files between BASE..HEAD that match regression-test paths.
DELETED=$(git diff --diff-filter=D --name-only "$BASE..$HEAD_REF" \
    | grep -E '(^tests/regression_[^/]+\.rs$|^crates/[^/]+/tests/regression_[^/]+\.rs$)' \
    || true)

if [[ -z "$DELETED" ]]; then
    echo "check-regression-tests: no regression-test deletions in $BASE..$HEAD_REF; OK"
    exit 0
fi

# Gather text to search for issue links: PR body + commit message range.
SEARCH_TEXT=""
if [[ -n "${PR_BODY:-}" ]]; then
    SEARCH_TEXT+="${PR_BODY}"$'\n'
fi
SEARCH_TEXT+="$(git log --format='%B' "$BASE..$HEAD_REF" 2>/dev/null || true)"

# Pairing regex:
#   - closes/fixes/resolves/tracks/refs #N
#   - github.com/<org>/<repo>/issues/N or /pull/N URL
PAIR_REGEX='(closes|fixes|resolves|tracks|refs)[[:space:]]+#[0-9]+|https?://github\.com/[^/[:space:]]+/[^/[:space:]]+/(issues|pull)/[0-9]+'

unpaired=0
echo "check-regression-tests: deleted regression tests detected; checking for paired issue links"
while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    # Per-file pairing: a single `closes #N` at the top of the PR body must
    # NOT silently approve N unrelated regression-test deletions; the contract
    # is one paired reference per deleted file. We require that either the
    # full path
    # OR the file's basename appears in the search text alongside a
    # paired issue link. Either form ties the link to this specific
    # deletion rather than treating any link anywhere in the diff as
    # a wildcard waiver.
    base="$(basename "$path")"
    # Escape regex metacharacters in path/basename for safe substring grep.
    path_lit_re="$(printf '%s' "$path" | sed 's/[][\\.^$*+?(){}|/]/\\&/g')"
    base_lit_re="$(printf '%s' "$base" | sed 's/[][\\.^$*+?(){}|/]/\\&/g')"
    has_link=0
    has_name=0
    if echo "$SEARCH_TEXT" | grep -iqE "$PAIR_REGEX"; then
        has_link=1
    fi
    if echo "$SEARCH_TEXT" | grep -qE "(${path_lit_re}|${base_lit_re})"; then
        has_name=1
    fi
    if (( has_link == 1 )) && (( has_name == 1 )); then
        echo "  PAIRED   $path"
    else
        if (( has_link == 0 )); then
            echo "  UNPAIRED $path (no closes/fixes/refs #N or github issue/PR URL)" >&2
        else
            echo "  UNPAIRED $path (issue link present but does not name this file; mention the path or basename next to the link)" >&2
        fi
        unpaired=$((unpaired + 1))
    fi
done <<< "$DELETED"

if [[ "$unpaired" -gt 0 ]]; then
    cat >&2 <<EOF

check-regression-tests: $unpaired regression test(s) deleted without a
per-file paired issue link. For each deleted file, the PR body or one
of the commit messages must contain BOTH:

  1. an issue/PR reference, one of:
       closes #<n>            (or fixes / resolves / tracks / refs)
       https://github.com/<org>/<repo>/issues/<n>
       https://github.com/<org>/<repo>/pull/<n>
  2. the deleted file's path or basename next to that reference,
     e.g. "closes #123 (drops crates/foo/tests/regression_<sha>.rs)".

Each deleted regression_*.rs corresponds to a fuzz-found crash. Removing
it without naming a follow-up issue silently regresses crash coverage.
EOF
    exit 1
fi

echo "check-regression-tests: all deletions paired; OK"
exit 0
