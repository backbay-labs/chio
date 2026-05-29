#!/usr/bin/env bash
set -euo pipefail

# Navigate to package root relative to this script
cd "$(dirname "$0")/.."

echo "==> Step 1: Generating Python bindings from WIT..."
componentize-py -d ../../../wit/chio-guard -w guard --world-module guard bindings .

echo "==> Step 2: Creating dist/ directory..."
mkdir -p dist

echo "==> Step 3: Compiling example guard to WASM component..."
componentize-py \
    -d ../../../wit/chio-guard \
    -w guard \
    --world-module guard \
    componentize \
    -p examples/tool-gate \
    --stub-wasi \
    app \
    -o dist/tool-gate.wasm

echo "==> Done. Output:"
ls -lh dist/tool-gate.wasm
