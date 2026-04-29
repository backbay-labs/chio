#!/usr/bin/env bash
# seal-bless-audit.sh -- rewrite `<commit-sha-pending>` rows in the bless
# audit log to the real commit SHA of the bless commit they describe.
#
# Background
# ----------
# At bless time the staged goldens, audit-log line, and (optionally)
# docs/replay-compat.md are not yet committed, so `git rev-parse HEAD`
# does not yet reflect the SHA the audit line will be embedded in. The
# bless flow (see tests/replay/src/bless.rs, PENDING_SHA_MARKER) records
# the placeholder `<commit-sha-pending>` instead. Once the bless commit
# (or its squash-merge counterpart) is known, this script rewrites every
# placeholder row in tests/replay/.bless-audit.log to that SHA in place.
#
# Usage
# -----
#   scripts/seal-bless-audit.sh                       # uses HEAD (typical)
#   scripts/seal-bless-audit.sh <commit-sha>          # explicit SHA (e.g.
#                                                       a squash-merge SHA
#                                                       you obtained via
#                                                       gh pr view --json
#                                                       mergeCommit)
#   scripts/seal-bless-audit.sh -h | --help
#
# The script makes a single sed-like rewrite of the audit log and stages
# the file (`git add tests/replay/.bless-audit.log`); the resulting diff
# should be reviewed and committed with a message like
# `chore(replay): seal bless-audit SHAs to <commit-sha>`.
#
# Idempotency: re-running with no placeholders left exits with code 0
# and prints "no placeholders to seal".
#

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
PLACEHOLDER='<commit-sha-pending>'
AUDIT_LOG_RELPATH='tests/replay/.bless-audit.log'

usage() {
  cat <<'USAGE'
seal-bless-audit.sh -- replace <commit-sha-pending> placeholders in the
bless audit log with the real commit SHA.

Usage:
  scripts/seal-bless-audit.sh                # uses HEAD
  scripts/seal-bless-audit.sh <commit-sha>   # explicit SHA
  scripts/seal-bless-audit.sh -h | --help

Behaviour:
  - Locates the repo root (script lives in scripts/).
  - Counts <commit-sha-pending> rows in the audit log; exits 0 with a
    note if there are none.
  - Validates the supplied (or auto-detected) SHA is a known commit via
    `git rev-parse --verify <sha>^{commit}`.
  - Replaces every placeholder occurrence with the abbreviated SHA
    (matches the existing audit-log convention of short SHAs).
  - Stages the audit log with `git add` so the operator commits the
    rewrite in a follow-up commit.

The follow-up commit message convention is:
  chore(replay): seal bless-audit SHAs to <short-sha>
USAGE
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

err() {
  printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2
}

note() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
}

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

AUDIT_LOG="$REPO_ROOT/$AUDIT_LOG_RELPATH"
if [ ! -f "$AUDIT_LOG" ]; then
  err "audit log not found at $AUDIT_LOG"
  exit 2
fi

PENDING_COUNT="$(grep -vE '^#' "$AUDIT_LOG" | grep -cF "$PLACEHOLDER" || true)"
if [ "$PENDING_COUNT" -eq 0 ]; then
  note "no placeholders to seal in $AUDIT_LOG_RELPATH (header comments are ignored)"
  exit 0
fi
note "$PENDING_COUNT placeholder data row(s) to seal (header comments are ignored)"

# Resolve the target SHA. Default to HEAD; accept an explicit short or
# long SHA as $1.
TARGET_REF="${1:-HEAD}"
if ! FULL_SHA="$(git rev-parse --verify "${TARGET_REF}^{commit}" 2>/dev/null)"; then
  err "could not resolve '$TARGET_REF' to a commit. Pass an explicit SHA."
  exit 3
fi
SHORT_SHA="$(git rev-parse --short "$FULL_SHA")"
note "sealing rows to $SHORT_SHA (full: $FULL_SHA)"

# Use a portable in-place edit. macOS and GNU sed disagree on -i syntax;
# write to a temp file and atomically rename.
TMP="$(mktemp "${AUDIT_LOG}.seal.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
# Replace the literal placeholder string in data rows only. Lines that
# begin with `#` are header comments (the audit log's documented
# convention) and may legitimately mention `<commit-sha-pending>` as
# part of the format documentation; rewriting those would corrupt the
# header. The audit log is tab-separated with the placeholder
# occupying the entire <sha> column on data rows, so a literal string
# substitution is safe.
awk -v placeholder="$PLACEHOLDER" -v sha="$SHORT_SHA" '
  /^#/ {
    print
    next
  }
  {
    n = index($0, placeholder)
    while (n > 0) {
      $0 = substr($0, 1, n - 1) sha substr($0, n + length(placeholder))
      n = index($0, placeholder)
    }
    print
  }
' "$AUDIT_LOG" > "$TMP"
mv "$TMP" "$AUDIT_LOG"
trap - EXIT

git add "$AUDIT_LOG_RELPATH"
note "staged $AUDIT_LOG_RELPATH"
note "review the diff and commit with:"
note "  git commit -m 'chore(replay): seal bless-audit SHAs to $SHORT_SHA'"
