#!/usr/bin/env bash
# Assert generated codegen trees match committed bytes and contain no untracked files.
# Used by `make spec-drift` after codegen --check lanes run.
# Mirrors the git diff and untracked-file steps in .github/workflows/spec-drift.yml.
set -euo pipefail

cd "$(dirname "$0")/.."

git diff --exit-code \
  crates/core/chio-core-types/src/_generated \
  sdks/python/chio-sdk-python/src/chio_sdk/_generated \
  sdks/typescript/packages/conformance/src/_generated \
  sdks/go/chio-go-http/types.go

untracked=$(git ls-files --others --exclude-standard -- \
  crates/core/chio-core-types/src/_generated \
  sdks/python/chio-sdk-python/src/chio_sdk/_generated \
  sdks/typescript/packages/conformance/src/_generated \
  sdks/go/chio-go-http)
if [ -n "$untracked" ]; then
  echo "codegen produced untracked files in a generated path:" >&2
  echo "$untracked" >&2
  exit 1
fi
