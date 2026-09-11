#!/usr/bin/env bash
set -euo pipefail
EXAMPLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="${BUYER_STATE_DIR:-${EXAMPLE_ROOT}/artifacts/live/buyer-sidecar}"
mkdir -p "${STATE_DIR}"
CHIO_BIN="${CHIO_BIN:-$(command -v chio || true)}"
if [[ ! -x "${CHIO_BIN}" ]]; then
  echo 'Install the documented Chio CLI or set CHIO_BIN to your built executable.' >&2
  exit 1
fi
: "${CHIO_CONTROL_URL:?Configure the authority address}"
: "${CHIO_CONTROL_TOKEN:?Configure the authority credential}"
: "${CHIO_TRUSTED_ISSUER_KEY:?Pin the authority issuer before starting the gateway}"
exec "${CHIO_BIN}" \
  --control-url "${CHIO_CONTROL_URL}" \
  --control-token "${CHIO_CONTROL_TOKEN}" \
  --authority-seed-file "${BUYER_AUTHORITY_SEED_FILE:-${STATE_DIR}/authority.hex}" \
  api protect \
  --upstream "${BUYER_UPSTREAM_URL:-http://127.0.0.1:8101}" \
  --spec "${EXAMPLE_ROOT}/buyer/openapi.yaml" \
  --listen "${BUYER_SIDECAR_LISTEN:-127.0.0.1:9101}" \
  --receipt-store "${BUYER_RECEIPT_STORE:-${STATE_DIR}/receipts.sqlite3}"
