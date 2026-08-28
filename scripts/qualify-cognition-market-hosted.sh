#!/usr/bin/env bash
set -euo pipefail

umask 022
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_TEST_DEBUG=0

cargo fmt --all -- --check
python3 scripts/check-rust-file-hygiene.py
bash scripts/check-workspace-layering.sh
cargo test -p chio-signing-remote
cargo test -p chio-finding-worker
cargo test -p chio-finding-market-store-postgres
cargo test -p chio-kernel payment
cargo test -p chio-control-plane --lib finding_challenge
cargo test -p chio-control-plane --lib finding_purchase
cargo test -p chio-control-plane --lib finding_status
cargo test -p chio-cli missing_secret_references_fail_closed
cargo clippy \
  -p chio-signing-remote \
  -p chio-finding-worker \
  -p chio-finding-market-store-postgres \
  -p chio-kernel \
  -p chio-control-plane \
  -p chio-cli \
  --all-targets -- -D warnings
make codegen-check
cargo vet check --locked
