#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
umask 022
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_TEST_DEBUG=0

if [[ -z "${CHIO_TEST_POSTGRES_URL:-}" || -z "${CHIO_TEST_POSTGRES_RUNTIME_URL:-}" ]]; then
  echo "hosted cognition-market qualification requires PostgreSQL test URLs" >&2
  exit 1
fi

cargo fmt --all -- --check
python3 scripts/check-rust-file-hygiene.py
bash scripts/check-workspace-layering.sh
cargo test -p chio-signing-remote
cargo test -p chio-finding-worker
cargo test -p chio-finding-worker-daemon
cargo test -p chio-finding-market-store-postgres
cargo test -p chio-finding-market-store-postgres \
  --features postgres-integration \
  --test postgres_store -- --test-threads=1
cargo test -p chio-finding-hosted-edge
cargo test -p chio-kernel payment
cargo test -p chio-settle finding
cargo test -p chio-control-plane --lib finding_challenge
cargo test -p chio-control-plane --lib finding_purchase
cargo test -p chio-control-plane --lib finding_status
cargo test -p chio-cli missing_secret_references_fail_closed
cargo clippy \
  -p chio-signing-remote \
  -p chio-finding-worker \
  -p chio-finding-worker-daemon \
  -p chio-finding-market-store-postgres \
  -p chio-finding-hosted-edge \
  -p chio-kernel \
  -p chio-control-plane \
  -p chio-cli \
  --all-targets \
  --features chio-finding-market-store-postgres/postgres-integration \
  -- -D warnings
make codegen-check
cargo vet check --locked
