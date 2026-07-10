#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
scratch="$(mktemp -d -t chio-regression-guard-XXXXXX)"
trap 'rm -rf "$scratch"' EXIT

git -C "$scratch" init -q
git -C "$scratch" config user.email "regression-guard@invalid"
git -C "$scratch" config user.name "Regression Guard"
mkdir -p "$scratch/scripts" "$scratch/formal/diff-tests/tests"
cp "$repo_root/scripts/check-regression-tests.sh" "$scratch/scripts/"
printf '#[test]\nfn retained_regression() {}\n' \
  >"$scratch/formal/diff-tests/tests/regression_formal_first.rs"
printf '#[test]\nfn retained_regression() {}\n' \
  >"$scratch/formal/diff-tests/tests/regression_formal_second.rs"
git -C "$scratch" add .
git -C "$scratch" -c commit.gpgsign=false commit -qm "test: add regression"
base="$(git -C "$scratch" rev-parse HEAD)"
base_branch="$(git -C "$scratch" symbolic-ref --short HEAD)"

git -C "$scratch" switch -qc rename-case
git -C "$scratch" mv \
  formal/diff-tests/tests/regression_formal_first.rs \
  formal/diff-tests/tests/formal_first.rs
git -C "$scratch" -c commit.gpgsign=false commit -qm "test: rename regression"
rename_head="$(git -C "$scratch" rev-parse HEAD)"
if (
  cd "$scratch"
  bash scripts/check-regression-tests.sh \
    --base "$base" --head "$rename_head" >"$scratch/out" 2>"$scratch/err"
); then
  echo "FAIL: unpaired formal regression rename passed" >&2
  exit 1
fi
grep -Fq "UNPAIRED formal/diff-tests/tests/regression_formal_first.rs" "$scratch/err"
git -C "$scratch" switch -q "$base_branch"

rm "$scratch/formal/diff-tests/tests/regression_formal_first.rs"
rm "$scratch/formal/diff-tests/tests/regression_formal_second.rs"
git -C "$scratch" add -u
git -C "$scratch" -c commit.gpgsign=false commit -qm "test: remove regression"
head="$(git -C "$scratch" rev-parse HEAD)"

if (
  cd "$scratch"
  bash scripts/check-regression-tests.sh \
    --base "$base" --head "$head" >"$scratch/out" 2>"$scratch/err"
); then
  echo "FAIL: unpaired formal regression deletion passed" >&2
  exit 1
fi
grep -Fq "UNPAIRED formal/diff-tests/tests/regression_formal_first.rs" "$scratch/err"
grep -Fq "UNPAIRED formal/diff-tests/tests/regression_formal_second.rs" "$scratch/err"

if (
  cd "$scratch"
  PR_BODY=$'closes #123 (formal/diff-tests/tests/regression_formal_first.rs)\nformal/diff-tests/tests/regression_formal_second.rs' \
    bash scripts/check-regression-tests.sh \
      --base "$base" --head "$head" >"$scratch/out" 2>"$scratch/err"
); then
  echo "FAIL: one issue link authorized two formal regression deletions" >&2
  exit 1
fi
grep -Fq "PAIRED   formal/diff-tests/tests/regression_formal_first.rs" "$scratch/out"
grep -Fq "UNPAIRED formal/diff-tests/tests/regression_formal_second.rs" "$scratch/err"

(
  cd "$scratch"
  PR_BODY=$'closes #123 (formal/diff-tests/tests/regression_formal_first.rs)\ncloses #124 (formal/diff-tests/tests/regression_formal_second.rs)' \
    bash scripts/check-regression-tests.sh \
      --base "$base" --head "$head" >"$scratch/out" 2>"$scratch/err"
)
grep -Fq "PAIRED   formal/diff-tests/tests/regression_formal_first.rs" "$scratch/out"
grep -Fq "PAIRED   formal/diff-tests/tests/regression_formal_second.rs" "$scratch/out"

echo "check-regression-tests.test.sh: all assertions passed"
