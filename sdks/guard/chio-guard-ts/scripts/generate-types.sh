#!/usr/bin/env bash
set -euo pipefail

# Navigate to package root relative to this script
cd "$(dirname "$0")/.."

npx jco types --world-name guard --out-dir ./src/types ../../../wit/chio-guard
