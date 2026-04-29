#!/usr/bin/env bash
# tests/ci_guards/regression_deletion_test.sh
#
# Self-test for scripts/check-regression-tests.sh.
#
# Builds an isolated temp git repo, then drives the guard script through
# four scenarios:
#
#   case 1: no regression deletions               -> guard exits 0
#   case 2: regression deleted, no issue link     -> guard exits 1
#   case 3: regression deleted, link in PR_BODY   -> guard exits 0
#   case 4: regression deleted, link in commit    -> guard exits 0
#
# Each case asserts the expected exit code; the script aborts (set -e)
# on the first failure. Runs without network or any repo state outside
# its $TMPDIR.
#
# Usage:
#   regression_deletion_test.sh [--dry-run]
#
# --dry-run: no-op self-test, exit 0 (used by gate_check)

set -euo pipefail

if [[ "${1:-}" == "--dry-run" ]]; then
    echo "regression_deletion_test: dry-run OK"
    exit 0
fi

# Resolve absolute path to the guard script before we cd anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GUARD="$REPO_ROOT/scripts/check-regression-tests.sh"

if [[ ! -x "$GUARD" ]]; then
    echo "regression_deletion_test: guard not executable at $GUARD" >&2
    exit 2
fi

TMP="$(mktemp -d -t chio-regression-guard-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"
git init -q -b main .
git config user.email "guard-test@chio.local"
git config user.name "guard-test"
git config commit.gpgsign false

# Seed: one regression test under crates/<owner>/tests, one under
# legacy tests/regression_*.rs, plus an unrelated file.
mkdir -p crates/chio-kernel-core/tests
mkdir -p tests
cat > crates/chio-kernel-core/tests/regression_deadbeef.rs <<'EOF'
// fuzz-promoted regression test for crash deadbeef
#[test]
fn regression_deadbeef() {}
EOF
cat > tests/regression_cafef00d.rs <<'EOF'
// legacy fuzz-promoted regression test
#[test]
fn regression_cafef00d() {}
EOF
echo "// unrelated" > src_lib.rs

git add -A
git commit -q -m "seed: add two regression tests"
BASE=$(git rev-parse HEAD)

run_guard() {
    # Wrapper: invoke guard, capture exit code without tripping set -e.
    # Redirect both streams to stderr so only the numeric rc reaches stdout.
    local rc=0
    PR_BODY="${PR_BODY:-}" bash "$GUARD" --base "$BASE" --head HEAD >&2 2>&1 || rc=$?
    echo "$rc"
}

# ----------------------------------------------------------------------
# case 1: edit unrelated file, no regression deletion -> exit 0
# ----------------------------------------------------------------------
echo "// touched" >> src_lib.rs
git add src_lib.rs
git commit -q -m "case1: touch unrelated file"
unset PR_BODY
rc=$(run_guard)
if [[ "$rc" -ne 0 ]]; then
    echo "case 1 FAIL: expected exit 0, got $rc" >&2
    exit 1
fi
echo "case 1 OK (no deletions, exit 0)"

# Reset to BASE for the next case so each case is independent.
git reset -q --hard "$BASE"

# ----------------------------------------------------------------------
# case 2: delete a regression test, no issue link anywhere -> exit 1
# ----------------------------------------------------------------------
git rm -q crates/chio-kernel-core/tests/regression_deadbeef.rs
git commit -q -m "case2: drop a regression test with no justification"
unset PR_BODY
rc=$(run_guard)
if [[ "$rc" -ne 1 ]]; then
    echo "case 2 FAIL: expected exit 1, got $rc" >&2
    exit 1
fi
echo "case 2 OK (unpaired deletion, exit 1)"

git reset -q --hard "$BASE"

# ----------------------------------------------------------------------
# case 3: delete + paired issue link in PR_BODY -> exit 0
# ----------------------------------------------------------------------
git rm -q tests/regression_cafef00d.rs
git commit -q -m "case3: drop legacy regression test"
export PR_BODY="Removing the cafef00d regression because closes #4242 fixed the underlying parser bug."
rc=$(run_guard)
if [[ "$rc" -ne 0 ]]; then
    echo "case 3 FAIL: expected exit 0, got $rc" >&2
    exit 1
fi
echo "case 3 OK (paired via PR_BODY, exit 0)"
unset PR_BODY

git reset -q --hard "$BASE"

# ----------------------------------------------------------------------
# case 4: delete + paired issue URL in commit message -> exit 0
# ----------------------------------------------------------------------
git rm -q crates/chio-kernel-core/tests/regression_deadbeef.rs
git commit -q -m "case4: drop deadbeef regression

Crash was reclassified as a duplicate of
https://github.com/bb-connor/arc/issues/9999 so the regression test is
redundant."
unset PR_BODY
rc=$(run_guard)
if [[ "$rc" -ne 0 ]]; then
    echo "case 4 FAIL: expected exit 0, got $rc" >&2
    exit 1
fi
echo "case 4 OK (paired via commit URL, exit 0)"

echo
echo "regression_deletion_test: ALL CASES PASS"
exit 0
