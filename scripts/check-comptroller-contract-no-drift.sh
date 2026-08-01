#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/crates/products/chio-cli/dashboard"
npm install --silent
npm run gen:contracts >/dev/null
cd "$ROOT"
if ! git diff --exit-code -- crates/products/chio-cli/dashboard/src/generated/comptroller-surface.ts; then
  echo "FAIL: generated comptroller-surface TypeScript is out of date; run npm run gen:contracts" >&2
  exit 1
fi
echo "OK comptroller contract TypeScript is in sync with the published schema"
