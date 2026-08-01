#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

RUSTFLAGS="--cfg chio_kernel_loom" \
  cargo test -p chio-kernel --test loom_concurrency protocol_primitives_
