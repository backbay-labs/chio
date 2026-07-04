#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 contract parity requires jq on PATH" >&2
  exit 1
fi

env CARGO_TARGET_DIR=target/chio-web3-parity CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-web3 -- --test-threads=1
env CARGO_TARGET_DIR=target/chio-web3-bindings-parity CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 \
  cargo test -p chio-web3-bindings -- --test-threads=1
scripts/check-chio-schema-registry.sh
diff -qr contracts/artifacts crates/economy/chio-web3-bindings/artifacts
diff -u contracts/deployments/local-devnet.json \
  crates/economy/chio-web3-bindings/deployments/local-devnet.json
diff -u contracts/reports/local-devnet-qualification.json \
  crates/economy/chio-web3-bindings/reports/local-devnet-qualification.json
jq empty \
  docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json \
  docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json \
  docs/standards/CHIO_WEB3_QUALIFICATION_MATRIX.json \
  docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json

echo "web3 contract parity verified"
