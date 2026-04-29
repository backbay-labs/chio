#!/usr/bin/env bash
# bless-replay-goldens.sh -- wrapper around the chio-replay-gate --bless flow.
#
# Refuses to invoke the binary when the working tree contains changes to the
# replay-relevant source paths (chio-core / chio-core-types / chio-kernel
# receipt_support) without an accompanying delta in docs/replay-compat.md.
# The deeper gate logic (CHIO_BLESS=1, BLESS_REASON, branch checks, audit log,
# TTY+CI checks) lives in tests/replay/src/bless.rs. This script is a
# fast-fail wrapper that catches misuse before the binary runs.
#
# Usage:
#   BLESS_REASON="rationale" scripts/bless-replay-goldens.sh
#   scripts/bless-replay-goldens.sh -h | --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
  cat <<'USAGE'
bless-replay-goldens.sh -- bless replay goldens via chio-replay-gate.

Usage:
  BLESS_REASON="rationale" scripts/bless-replay-goldens.sh
  scripts/bless-replay-goldens.sh -h | --help

Required environment:
  BLESS_REASON   Free-form rationale string. Recorded in
                 tests/replay/.bless-audit.log alongside timestamp, branch,
                 SHA, and committer identity.

Behaviour:
  - Sets CHIO_BLESS=1 and exports BLESS_REASON for the child process.
  - Refuses to run if CI=true (CI is banned from blessing).
  - Refuses to run on branch 'main' or 'release/*'.
  - Refuses to run if changes exist under crates/chio-core/src/,
    crates/chio-core-types/src/, or crates/chio-kernel/src/receipt_support.rs
    without a corresponding modification to docs/replay-compat.md.
  - Refuses to run if other unrelated paths (outside the bless allowlist of
    tests/replay/goldens/, tests/replay/.bless-audit.log, and
    docs/replay-compat.md) are dirty.
  - Invokes: cargo run --release -p chio-replay-gate -- --bless

The full gate (TTY check, audit-log coupling, BLESS_REASON validation,
branch protection coupling) is enforced by tests/replay/src/bless.rs in
the binary itself; this wrapper provides a fast-fail user-friendly front
end before the binary runs.

After a successful bless, commit the goldens, the audit-log delta, and any
docs/replay-compat.md update in a single commit. The audit-log <sha> column
is written as the placeholder `<commit-sha-pending>`; once the bless commit
(or its squash-merge SHA) is known, run scripts/seal-bless-audit.sh to
rewrite the placeholder rows to the real SHA on a follow-up commit.
USAGE
}

# Help / no-arg invocation prints usage and exits 0 only when the user is
# clearly asking for help. Bare invocations without BLESS_REASON fall through
# to the gate check below so the error message is precise.
case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

# Locate repo root (script lives in scripts/).
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

err() {
  printf '%s: error: %s\n' "$SCRIPT_NAME" "$*" >&2
}

note() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$*" >&2
}

# 1) BLESS_REASON must be set and non-empty.
if [ -z "${BLESS_REASON:-}" ]; then
  err "BLESS_REASON is required. Set it to a free-form rationale string."
  err "Example: BLESS_REASON=\"refresh after canonicalization tweak\" $SCRIPT_NAME"
  exit 2
fi

# 2) CI must not be set to a truthy value. CI is banned from blessing.
case "${CI:-}" in
  ""|"false"|"0"|"False"|"FALSE")
    ;;
  *)
    err "CI=${CI} detected. CI is banned from blessing replay goldens."
    err "Run this helper interactively from a developer workstation."
    exit 3
    ;;
esac

# 3) Branch must not be main or release/*.
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")"
if [ -z "$CURRENT_BRANCH" ] || [ "$CURRENT_BRANCH" = "HEAD" ]; then
  err "could not determine current branch (detached HEAD?). Refusing."
  exit 4
fi
case "$CURRENT_BRANCH" in
  main|release/*)
    err "current branch '$CURRENT_BRANCH' is protected. Bless from a topic branch."
    exit 4
    ;;
esac

# 4) Compute dirty status. We use 'git status --porcelain=v1' so both staged
#    and unstaged modifications count, but commits already on the topic
#    branch are intentionally not considered dirty by this wrapper - the
#    binary's audit log handles cross-commit coherence. Pinning to v1 keeps
#    the parser stable across git versions and matches the rename-line shape
#    documented below ("R  old -> new").

PORCELAIN="$(git status --porcelain=v1 --untracked-files=normal)"

# Helper: extract every path referenced by porcelain output.
#
# Each porcelain line is "XY <path>" or, for renames/copies,
# "XY <old> -> <new>". For renames we want BOTH paths so the allowlist
# check cannot be bypassed by renaming a file from inside the allowlist
# to outside (or vice versa). The previous implementation only captured
# the first token after the status code, missing the rename destination.
porcelain_paths() {
  printf '%s\n' "$PORCELAIN" | awk '
    NF {
      # $0 = "XY path...". Drop the leading "XY " (3 chars).
      rest = substr($0, 4)
      idx = index(rest, " -> ")
      if (idx > 0) {
        # Rename or copy: emit both old and new paths.
        old = substr(rest, 1, idx - 1)
        new = substr(rest, idx + 4)
        print old
        print new
      } else {
        print rest
      }
    }
  ' | sort -u
}

ALL_DIRTY_PATHS="$(porcelain_paths)"

# Helper: filter the dirty path list down to entries matching $1 (a grep -E
# regex applied to each path).
dirty_paths_matching() {
  printf '%s\n' "$ALL_DIRTY_PATHS" | grep -E "$1" || true
}

# Replay-source paths whose modification requires a docs/replay-compat.md delta.
SOURCE_PATTERN='^(crates/chio-core/src/|crates/chio-core-types/src/|crates/chio-kernel/src/receipt_support\.rs$)'
SOURCE_DIRTY="$(dirty_paths_matching "$SOURCE_PATTERN")"

# Paths in the bless allowlist (always permitted to be dirty during a bless).
ALLOW_PATTERN='^(tests/replay/goldens/|tests/replay/\.bless-audit\.log$|docs/replay-compat\.md$)'

# Compat-doc delta presence.
COMPAT_DIRTY="$(dirty_paths_matching '^docs/replay-compat\.md$')"

if [ -n "$SOURCE_DIRTY" ] && [ -z "$COMPAT_DIRTY" ]; then
  err "replay-relevant source files are dirty without a docs/replay-compat.md delta:"
  printf '%s\n' "$SOURCE_DIRTY" | sed 's/^/  - /' >&2
  err "Add an entry to docs/replay-compat.md describing the wire-level impact"
  err "(or document why there is none) and re-run."
  exit 5
fi

# 5) Refuse if any *other* path outside the bless allowlist is dirty. This is
#    a fast-fail superset of the binary-side check; the binary enforces it
#    again as part of CHIO_BLESS gate logic step 4.
#
# Source paths are excluded from the outside-dirty list ONLY when the bless
# is paired with a docs/replay-compat.md delta (the SOURCE_DIRTY-with-
# COMPAT_DIRTY case is gated above). Without that pairing, source paths
# are themselves "outside the allowlist" and should fail this check.
if [ -n "$SOURCE_DIRTY" ] && [ -n "$COMPAT_DIRTY" ]; then
  OUTSIDE_DIRTY="$(printf '%s\n' "$ALL_DIRTY_PATHS" \
    | grep -Ev "$ALLOW_PATTERN" \
    | grep -Ev "$SOURCE_PATTERN" || true)"
else
  OUTSIDE_DIRTY="$(printf '%s\n' "$ALL_DIRTY_PATHS" \
    | grep -Ev "$ALLOW_PATTERN" || true)"
fi

if [ -n "$OUTSIDE_DIRTY" ]; then
  err "working tree has changes outside the bless allowlist:"
  printf '%s\n' "$OUTSIDE_DIRTY" | sed 's/^/  - /' >&2
  err "Allowed paths: tests/replay/goldens/, tests/replay/.bless-audit.log,"
  err "docs/replay-compat.md, plus replay-source paths when accompanied by a"
  err "docs/replay-compat.md delta."
  err "Stash or commit unrelated changes and re-run."
  exit 6
fi

# 6) Export gate flags. CHIO_BLESS=1 is the explicit opt-in checked by the
#    binary (see tests/replay/src/bless.rs).
export CHIO_BLESS=1
export BLESS_REASON

note "branch: $CURRENT_BRANCH"
note "BLESS_REASON: $BLESS_REASON"
if [ -n "$SOURCE_DIRTY" ]; then
  note "replay-source delta detected (with docs/replay-compat.md update):"
  printf '%s\n' "$SOURCE_DIRTY" | sed "s/^/  $SCRIPT_NAME:   /" >&2
fi
note "invoking chio-replay-gate --bless"

# 7) Invoke the binary. The --bless flag enters the gate path inside the
#    binary; further checks (TTY, audit-log coupling, golden write) live there.
cargo run --release -p chio-replay-gate -- --bless "$@"

note "bless complete. Review the diff and commit:"
note "  - tests/replay/goldens/<changed-fixtures>"
note "  - tests/replay/.bless-audit.log"
if [ -n "$COMPAT_DIRTY" ]; then
  note "  - docs/replay-compat.md"
fi
note "Then push and request CODEOWNERS review on tests/replay/goldens/."
note ""
note "Audit-log <sha> rows are recorded as <commit-sha-pending> at bless time;"
note "after the bless commit lands, run scripts/seal-bless-audit.sh to rewrite"
note "the placeholder rows to the real SHA on a follow-up commit."
