#!/usr/bin/env bash
set -euo pipefail

# Navigate to package root relative to this script
cd "$(dirname "$0")/.."

echo "==> Generating types from WIT..."
npx jco types --world-name guard --out-dir ./src/types ../../../wit/chio-guard

echo "==> Bundling example guard with esbuild..."
npx esbuild examples/tool-gate/guard.ts --bundle --format=esm --outfile=dist/tool-gate.js

echo "==> Compiling WASM component with jco componentize..."
npx jco componentize dist/tool-gate.js --wit ../../../wit/chio-guard --world-name guard --out dist/tool-gate.wasm --disable all

echo "==> Done. Output: dist/tool-gate.wasm"
ls -lh dist/tool-gate.wasm
