#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
workflow="$repo_root/.github/workflows/chio-runtime.yml"

for path in \
  "fixtures/proof-room/runtime-security/**" \
  "fixtures/proof-room/catalog.json"; do
  count="$( (grep -F -- "$path" "$workflow" || true) | wc -l | tr -d ' ')"
  if [[ "$count" -lt 2 ]]; then
    echo "chio-runtime.workflow.path-missing: $path" >&2
    exit 1
  fi
done

echo "check-chio-runtime-workflow.test.sh: runtime workflow paths passed"
