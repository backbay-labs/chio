#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"

ARTIFACT_ROOT="${EXAMPLE_ROOT}/artifacts/live/$(date -u +"%Y%m%dT%H%M%SZ")"
LOG_DIR="${ARTIFACT_ROOT}/logs"
STATE_DIR="${ARTIFACT_ROOT}/state"
mkdir -p "${LOG_DIR}" "${STATE_DIR}"

CHIO_BIN="$(ensure_chio_bin)"
SERVICE_TOKEN="${CHIO_SERVICE_TOKEN:-demo-token}"
CHIO_AUTH_TOKEN="${CHIO_AUTH_TOKEN:-demo-token}"

# Ports
TRUST_PORT="$(pick_free_port)"
OBS_PORT="$(pick_free_port)"
GIT_PORT="$(pick_free_port)"
PD_PORT="$(pick_free_port)"
OPS_PORT="$(pick_free_port)"
BROKER_PORT="$(pick_free_port)"
COORD_PORT="$(pick_free_port)"
EXEC_PORT="$(pick_free_port)"
COORD_SIDECAR_PORT="$(pick_free_port)"
EXEC_SIDECAR_PORT="$(pick_free_port)"

export INCIDENT_NETWORK_CUSTOMER_WORKSPACE="${EXAMPLE_ROOT}/workspaces/customer-lab"
export INCIDENT_NETWORK_PROVIDER_WORKSPACE="${EXAMPLE_ROOT}/workspaces/provider-lab"
export INCIDENT_NETWORK_ACP_STATE_DIR="${STATE_DIR}/acp-broker"

# Reset provider workspace
mkdir -p "${EXAMPLE_ROOT}/workspaces/provider-lab/tenants/MeridianLabs/services"
cp "${EXAMPLE_ROOT}/workspaces/provider-lab/templates/inference-gateway.seed.json" \
   "${EXAMPLE_ROOT}/workspaces/provider-lab/tenants/MeridianLabs/services/inference-gateway.json"
cp "${EXAMPLE_ROOT}/workspaces/provider-lab/templates/edge-global.seed.json" \
   "${EXAMPLE_ROOT}/workspaces/provider-lab/tenants/MeridianLabs/services/edge-global.json"
mkdir -p "${EXAMPLE_ROOT}/workspaces/provider-lab/operations"
printf '[]\n' > "${EXAMPLE_ROOT}/workspaces/provider-lab/operations/audit-log.json"
rm -rf "${EXAMPLE_ROOT}/workspaces/provider-lab/operations/evidence"

BG_PIDS=()
cleanup() {
  for pid in "${BG_PIDS[@]}"; do
    kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
  done
}
trap cleanup EXIT

# -- Chio trust-control --
"${CHIO_BIN}" trust serve \
  --listen "127.0.0.1:${TRUST_PORT}" --service-token "${SERVICE_TOKEN}" \
  --receipt-db "${STATE_DIR}/trust-receipts.sqlite3" \
  --revocation-db "${STATE_DIR}/trust-revocations.sqlite3" \
  --authority-db "${STATE_DIR}/trust-authority.sqlite3" \
  --budget-db "${STATE_DIR}/trust-budgets.sqlite3" \
  >"${LOG_DIR}/trust.log" 2>&1 &
BG_PIDS+=($!)

# -- Chio MCP edges --
for spec in \
  "mcp-observability:${OBS_PORT}:observability:tools/observability.py" \
  "mcp-github:${GIT_PORT}:github:tools/github.py" \
  "mcp-pagerduty:${PD_PORT}:pagerduty:tools/pagerduty.py" \
  "mcp-provider-ops:${OPS_PORT}:provider-ops:tools/provider_ops.py"; do
  IFS=: read -r sid port policy script <<< "${spec}"
  "${CHIO_BIN}" mcp serve-http \
    --policy "${EXAMPLE_ROOT}/policies/${policy}.yaml" \
    --server-id "${sid}" --listen "127.0.0.1:${port}" \
    --auth-token "${CHIO_AUTH_TOKEN}" --shared-hosted-owner \
    --session-db "${STATE_DIR}/${sid}-session.sqlite3" \
    -- python "${EXAMPLE_ROOT}/${script}" \
    >"${LOG_DIR}/chio-${sid}.log" 2>&1 &
  BG_PIDS+=($!)
done

# -- Chio api protect sidecars (the chio_asgi middleware in services talks to these) --
"${CHIO_BIN}" \
  --control-url "http://127.0.0.1:${TRUST_PORT}" \
  --control-token "${SERVICE_TOKEN}" \
  api protect \
  --upstream "http://127.0.0.1:${COORD_PORT}" \
  --spec "${EXAMPLE_ROOT}/services/coordinator-openapi.yaml" \
  --listen "127.0.0.1:${COORD_SIDECAR_PORT}" \
  --receipt-store "${STATE_DIR}/coordinator-receipts.sqlite3" \
  >"${LOG_DIR}/chio-coordinator-sidecar.log" 2>&1 &
BG_PIDS+=($!)

# Executor does its own Chio validation (capabilities, revocation, budget)
# and calls tools through chio mcp serve-http. No sidecar needed.

# -- Python services (with chio_asgi middleware pointing to their sidecars) --
uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/acp_broker.py" \
  --port "${BROKER_PORT}" >"${LOG_DIR}/acp-broker.log" 2>&1 &
BG_PIDS+=($!)

CHIO_SIDECAR_URL="http://127.0.0.1:${COORD_SIDECAR_PORT}" \
  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/coordinator.py" \
  --port "${COORD_PORT}" >"${LOG_DIR}/coordinator.log" 2>&1 &
BG_PIDS+=($!)

uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/executor.py" \
  --port "${EXEC_PORT}" >"${LOG_DIR}/executor.log" 2>&1 &
BG_PIDS+=($!)

# -- Wait --
wait_for_http "http://127.0.0.1:${TRUST_PORT}/health"
wait_for_port 127.0.0.1 "${OBS_PORT}"
wait_for_port 127.0.0.1 "${GIT_PORT}"
wait_for_port 127.0.0.1 "${PD_PORT}"
wait_for_port 127.0.0.1 "${OPS_PORT}"
wait_for_http "http://127.0.0.1:${BROKER_PORT}/health"
wait_for_http "http://127.0.0.1:${COORD_PORT}/health"
wait_for_http "http://127.0.0.1:${EXEC_PORT}/health"
wait_for_port 127.0.0.1 "${COORD_SIDECAR_PORT}"

# -- Run orchestrator (calls services directly; chio_asgi middleware handles Chio) --
uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/orchestrate.py" \
  --control-url "http://127.0.0.1:${TRUST_PORT}" \
  --service-token "${SERVICE_TOKEN}" \
  --broker-url "http://127.0.0.1:${BROKER_PORT}" \
  --provider-coordinator-url "http://127.0.0.1:${COORD_PORT}" \
  --provider-executor-url "http://127.0.0.1:${EXEC_PORT}" \
  --provider-executor-internal-url "http://127.0.0.1:${EXEC_PORT}" \
  --observability-mcp-url "http://127.0.0.1:${OBS_PORT}" \
  --github-mcp-url "http://127.0.0.1:${GIT_PORT}" \
  --pagerduty-mcp-url "http://127.0.0.1:${PD_PORT}" \
  --provider-ops-mcp-url "http://127.0.0.1:${OPS_PORT}" \
  --chio-auth-token "${CHIO_AUTH_TOKEN}" \
  --artifact-dir "${ARTIFACT_ROOT}" \
  > "${ARTIFACT_ROOT}/run-result.json"

# -- Verify --
uv run --project "${EXAMPLE_ROOT}" python -c "
import sys; sys.path.insert(0, '${EXAMPLE_ROOT}')
from incident_network.verify import verify_bundle
import json
r = verify_bundle('${ARTIFACT_ROOT}')
json.dump(r, open('${ARTIFACT_ROOT}/review-result.json', 'w'), indent=2)
assert r['ok'], r['errors']
"

printf 'internet-of-agents-incident-network smoke passed\n'
printf 'artifacts: %s\n' "${ARTIFACT_ROOT}"
