#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXAMPLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"

prepare_scenario_dir() {
  local name="$1"
  local dir="${EXAMPLE_ROOT}/artifacts/${name}/$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

start_live_topology() {
  local bundle_dir="$1"
  CHIO_BIN="$(ensure_chio_bin)"
  SERVICE_TOKEN="${CHIO_SERVICE_TOKEN:-demo-token}"
  CHIO_AUTH_TOKEN="${CHIO_AUTH_TOKEN:-demo-token}"
  LOG_DIR="${bundle_dir}/logs"
  STATE_DIR="${bundle_dir}/state"
  mkdir -p "${LOG_DIR}" "${STATE_DIR}"

  export INCIDENT_NETWORK_CUSTOMER_WORKSPACE="${EXAMPLE_ROOT}/workspaces/customer-lab"
  export INCIDENT_NETWORK_PROVIDER_WORKSPACE="${EXAMPLE_ROOT}/workspaces/provider-lab"
  export INCIDENT_NETWORK_ACP_STATE_DIR="${STATE_DIR}/acp-broker"

  mkdir -p "${EXAMPLE_ROOT}/workspaces/provider-lab/tenants/MeridianLabs/services"
  cp "${EXAMPLE_ROOT}/workspaces/provider-lab/templates/inference-gateway.seed.json" \
     "${EXAMPLE_ROOT}/workspaces/provider-lab/tenants/MeridianLabs/services/inference-gateway.json"
  cp "${EXAMPLE_ROOT}/workspaces/provider-lab/templates/edge-global.seed.json" \
     "${EXAMPLE_ROOT}/workspaces/provider-lab/tenants/MeridianLabs/services/edge-global.json"
  mkdir -p "${EXAMPLE_ROOT}/workspaces/provider-lab/operations"
  printf '[]\n' > "${EXAMPLE_ROOT}/workspaces/provider-lab/operations/audit-log.json"
  rm -rf "${EXAMPLE_ROOT}/workspaces/provider-lab/operations/evidence"

  TRUST_PORT="$(pick_free_port)"
  OBS_PORT="$(pick_free_port)"
  GIT_PORT="$(pick_free_port)"
  PD_PORT="$(pick_free_port)"
  OPS_PORT="$(pick_free_port)"
  BROKER_PORT="$(pick_free_port)"
  COORD_RAW_PORT="$(pick_free_port)"
  EXEC_RAW_PORT="$(pick_free_port)"
  COORD_SIDECAR_PORT="$(pick_free_port)"
  EXEC_SIDECAR_PORT="$(pick_free_port)"
  APPROVAL_PORT="$(pick_free_port)"

  CONTROL_URL="http://127.0.0.1:${TRUST_PORT}"
  BROKER_URL="http://127.0.0.1:${BROKER_PORT}"
  COORD_URL="http://127.0.0.1:${COORD_SIDECAR_PORT}"
  EXEC_URL="http://127.0.0.1:${EXEC_SIDECAR_PORT}"
  APPROVAL_URL="http://127.0.0.1:${APPROVAL_PORT}"
  OBS_URL="http://127.0.0.1:${OBS_PORT}"
  GIT_URL="http://127.0.0.1:${GIT_PORT}"
  PD_URL="http://127.0.0.1:${PD_PORT}"
  OPS_URL="http://127.0.0.1:${OPS_PORT}"

  # Trust-control
  "${CHIO_BIN}" trust serve \
    --listen "127.0.0.1:${TRUST_PORT}" --service-token "${SERVICE_TOKEN}" \
    --receipt-db "${STATE_DIR}/trust-receipts.sqlite3" \
    --revocation-db "${STATE_DIR}/trust-revocations.sqlite3" \
    --authority-db "${STATE_DIR}/trust-authority.sqlite3" \
    --budget-db "${STATE_DIR}/trust-budgets.sqlite3" \
    >"${LOG_DIR}/trust.log" 2>&1 &
  TRUST_PID=$!

  # MCP edges
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
  done

  # Raw services
  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/acp_broker.py" \
    --port "${BROKER_PORT}" >"${LOG_DIR}/acp-broker.log" 2>&1 &
  BROKER_PID=$!
  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/coordinator.py" \
    --port "${COORD_RAW_PORT}" >"${LOG_DIR}/coordinator.log" 2>&1 &
  COORD_PID=$!
  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/executor.py" \
    --port "${EXEC_RAW_PORT}" >"${LOG_DIR}/executor.log" 2>&1 &
  EXEC_PID=$!
  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/approval.py" \
    --port "${APPROVAL_PORT}" >"${LOG_DIR}/approval.log" 2>&1 &
  APPROVAL_PID=$!

  # Chio api protect sidecars
  "${CHIO_BIN}" --control-url "${CONTROL_URL}" --control-token "${SERVICE_TOKEN}" \
    api protect --upstream "http://127.0.0.1:${COORD_RAW_PORT}" \
    --spec "${EXAMPLE_ROOT}/services/coordinator-openapi.yaml" \
    --listen "127.0.0.1:${COORD_SIDECAR_PORT}" \
    --receipt-store "${STATE_DIR}/coordinator-receipts.sqlite3" \
    >"${LOG_DIR}/chio-coordinator-sidecar.log" 2>&1 &
  COORD_SIDECAR_PID=$!

  "${CHIO_BIN}" --control-url "${CONTROL_URL}" --control-token "${SERVICE_TOKEN}" \
    api protect --upstream "http://127.0.0.1:${EXEC_RAW_PORT}" \
    --spec "${EXAMPLE_ROOT}/services/executor-openapi.yaml" \
    --listen "127.0.0.1:${EXEC_SIDECAR_PORT}" \
    --receipt-store "${STATE_DIR}/executor-receipts.sqlite3" \
    >"${LOG_DIR}/chio-executor-sidecar.log" 2>&1 &
  EXEC_SIDECAR_PID=$!

  # Wait
  wait_for_http "${CONTROL_URL}/health"
  wait_for_port 127.0.0.1 "${OBS_PORT}"
  wait_for_port 127.0.0.1 "${GIT_PORT}"
  wait_for_port 127.0.0.1 "${PD_PORT}"
  wait_for_port 127.0.0.1 "${OPS_PORT}"
  wait_for_http "http://127.0.0.1:${BROKER_PORT}/health"
  wait_for_http "http://127.0.0.1:${COORD_RAW_PORT}/health"
  wait_for_http "http://127.0.0.1:${EXEC_RAW_PORT}/health"
  wait_for_http "http://127.0.0.1:${APPROVAL_PORT}/health"
  wait_for_port 127.0.0.1 "${COORD_SIDECAR_PORT}"
  wait_for_port 127.0.0.1 "${EXEC_SIDECAR_PORT}"
}

stop_live_topology() {
  for v in COORD_SIDECAR_PID EXEC_SIDECAR_PID APPROVAL_PID EXEC_PID COORD_PID BROKER_PID TRUST_PID; do
    [[ -n "${!v:-}" ]] && kill -0 "${!v}" 2>/dev/null && kill "${!v}" 2>/dev/null && wait "${!v}" 2>/dev/null
  done
  jobs -p | xargs -r kill 2>/dev/null || true
}

run_live_scenario() {
  local bundle_dir="$1"
  local mode="$2"

  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/orchestrate.py" \
    --mode "${mode}" \
    --control-url "${CONTROL_URL}" --service-token "${SERVICE_TOKEN}" \
    --broker-url "${BROKER_URL}" \
    --provider-coordinator-url "${COORD_URL}" \
    --provider-executor-url "${EXEC_URL}" \
    --provider-executor-internal-url "http://127.0.0.1:${EXEC_RAW_PORT}" \
    --approval-service-url "${APPROVAL_URL}" \
    --observability-mcp-url "${OBS_URL}" \
    --github-mcp-url "${GIT_URL}" \
    --pagerduty-mcp-url "${PD_URL}" \
    --provider-ops-mcp-url "${OPS_URL}" \
    --chio-auth-token "${CHIO_AUTH_TOKEN}" \
    --artifact-dir "${bundle_dir}" \
    > "${bundle_dir}/run-result.json"

  uv run --project "${EXAMPLE_ROOT}" python -c "
import sys; sys.path.insert(0, '${EXAMPLE_ROOT}')
from incident_network.verify import verify_bundle
import json
r = verify_bundle('${bundle_dir}')
json.dump(r, open('${bundle_dir}/review-result.json', 'w'), indent=2)
"
}

assert_review_ok() {
  python3 -c "
import json, sys
r = json.load(open('$1/review-result.json'))
assert r['ok'], r['errors']
"
}
