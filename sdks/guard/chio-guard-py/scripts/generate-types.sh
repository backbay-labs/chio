#!/usr/bin/env bash
set -euo pipefail

# Navigate to package root relative to this script
cd "$(dirname "$0")/.."

echo "==> Generating Python bindings from WIT..."
componentize-py -d ../../../wit/chio-guard -w guard --world-module guard bindings .
echo "==> Bindings written to guard/"
