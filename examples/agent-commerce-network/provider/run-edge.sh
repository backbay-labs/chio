#!/usr/bin/env bash
set -euo pipefail
EXAMPLE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHIO_BIN="${CHIO_BIN:-$(command -v chio || true)}"
if [[ ! -x "${CHIO_BIN}" ]]; then
  echo 'Install the documented Chio CLI or set CHIO_BIN to your built executable.' >&2
  exit 1
fi
: "${CHIO_CONTROL_URL:?Start the application authority first}"
: "${CHIO_CONTROL_TOKEN:?Configure the authority credential}"
: "${CHIO_EDGE_TOKEN:?Configure the provider edge credential}"
: "${PROVIDER_SESSION_DB:?Select the durable provider session database}"
exec "${CHIO_BIN}" \
  --control-url "${CHIO_CONTROL_URL}" \
  --control-token "${CHIO_CONTROL_TOKEN}" \
  mcp serve-http \
  --policy "${EXAMPLE_ROOT}/provider/policy.yaml" \
  --server-id provider-security-review \
  --server-name "Vanguard Security Review" \
  --listen "${PROVIDER_EDGE_LISTEN:-127.0.0.1:8931}" \
  --auth-token "${CHIO_EDGE_TOKEN}" \
  --session-db "${PROVIDER_SESSION_DB}" \
  -- python3 "${EXAMPLE_ROOT}/provider/review_server.py"
