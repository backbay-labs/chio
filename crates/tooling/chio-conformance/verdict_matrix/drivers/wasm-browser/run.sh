#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
cd "${ROOT}"

cargo test -p chio-kernel-browser --test verdict_matrix_wasm --quiet
wasm-pack test --headless --chrome "${ROOT}/crates/kernel/chio-kernel-browser" --test verdict_matrix_wasm
