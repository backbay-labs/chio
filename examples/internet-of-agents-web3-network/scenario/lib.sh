#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXAMPLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"

prepare_scenario_dir() {
  local name="$1"
  local dir="${EXAMPLE_ROOT}/artifacts/${name}/$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "${dir}"
  printf '%s\n' "${dir}"
}

make_authority_seed() {
  local label="$1"
  local seed_path="$2"
  uv run --project "${EXAMPLE_ROOT}" python - "${label}" "${seed_path}" <<'PY'
import hashlib
import os
import sys
from pathlib import Path

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

label = sys.argv[1]
seed_path = Path(sys.argv[2])
seed = hashlib.sha256(f"chio-ioa-web3:{label}:authority".encode("utf-8")).digest()
seed_path.parent.mkdir(parents=True, exist_ok=True)
seed_path.write_text(seed.hex() + "\n", encoding="utf-8")
os.chmod(seed_path, 0o600)
print(SigningKey(seed).verify_key.encode(encoder=HexEncoder).decode("utf-8"))
PY
}

start_live_topology() {
  local bundle_dir="$1"
  CHIO_BIN="$(ensure_chio_bin)"
  SERVICE_TOKEN="${CHIO_SERVICE_TOKEN:-demo-token}"
  CHIO_AUTH_TOKEN="${CHIO_AUTH_TOKEN:-demo-token}"
  LOG_DIR="${bundle_dir}/logs"
  STATE_DIR="${bundle_dir}/state"
  mkdir -p "${LOG_DIR}" "${STATE_DIR}"

  OPERATOR_TRUST_PORT="$(pick_free_port)"
  PROVIDER_TRUST_PORT="$(pick_free_port)"
  SUBCONTRACTOR_TRUST_PORT="$(pick_free_port)"
  FEDERATION_TRUST_PORT="$(pick_free_port)"
  MARKET_RAW_PORT="$(pick_free_port)"
  SETTLEMENT_RAW_PORT="$(pick_free_port)"
  MARKET_SIDECAR_PORT="$(pick_free_port)"
  SETTLEMENT_SIDECAR_PORT="$(pick_free_port)"
  WEB3_EVIDENCE_MCP_PORT="$(pick_free_port)"
  PROVIDER_REVIEW_MCP_PORT="$(pick_free_port)"
  SUBCONTRACTOR_REVIEW_MCP_PORT="$(pick_free_port)"

  OPERATOR_CONTROL_URL="http://127.0.0.1:${OPERATOR_TRUST_PORT}"
  PROVIDER_CONTROL_URL="http://127.0.0.1:${PROVIDER_TRUST_PORT}"
  SUBCONTRACTOR_CONTROL_URL="http://127.0.0.1:${SUBCONTRACTOR_TRUST_PORT}"
  FEDERATION_CONTROL_URL="http://127.0.0.1:${FEDERATION_TRUST_PORT}"
  MARKET_RAW_URL="http://127.0.0.1:${MARKET_RAW_PORT}"
  SETTLEMENT_RAW_URL="http://127.0.0.1:${SETTLEMENT_RAW_PORT}"
  MARKET_URL="http://127.0.0.1:${MARKET_SIDECAR_PORT}"
  SETTLEMENT_URL="http://127.0.0.1:${SETTLEMENT_SIDECAR_PORT}"
  WEB3_EVIDENCE_MCP_URL="http://127.0.0.1:${WEB3_EVIDENCE_MCP_PORT}"
  PROVIDER_REVIEW_MCP_URL="http://127.0.0.1:${PROVIDER_REVIEW_MCP_PORT}"
  SUBCONTRACTOR_REVIEW_MCP_URL="http://127.0.0.1:${SUBCONTRACTOR_REVIEW_MCP_PORT}"
  OPERATOR_AUTHORITY_SEED="${STATE_DIR}/operator-authority.seed"
  PROVIDER_AUTHORITY_SEED="${STATE_DIR}/provider-authority.seed"
  SUBCONTRACTOR_AUTHORITY_SEED="${STATE_DIR}/subcontractor-authority.seed"
  FEDERATION_AUTHORITY_SEED="${STATE_DIR}/federation-authority.seed"
  OPERATOR_AUTHORITY_PUB="$(make_authority_seed operator "${OPERATOR_AUTHORITY_SEED}")"
  PROVIDER_AUTHORITY_PUB="$(make_authority_seed provider "${PROVIDER_AUTHORITY_SEED}")"
  SUBCONTRACTOR_AUTHORITY_PUB="$(make_authority_seed subcontractor "${SUBCONTRACTOR_AUTHORITY_SEED}")"
  FEDERATION_AUTHORITY_PUB="$(make_authority_seed federation "${FEDERATION_AUTHORITY_SEED}")"

  export CHIO_IOA_WEB3_WORKSPACE="${EXAMPLE_ROOT}/workspaces"
  export CHIO_IOA_WEB3_MARKET_STATE_DIR="${STATE_DIR}/market"
  export CHIO_IOA_WEB3_REPO_ROOT="${ROOT}"
  export PYTHONDONTWRITEBYTECODE=1

  "${CHIO_BIN}" trust serve \
    --listen "127.0.0.1:${OPERATOR_TRUST_PORT}" \
    --advertise-url "${OPERATOR_CONTROL_URL}" \
    --service-token "${SERVICE_TOKEN}" \
    --receipt-db "${STATE_DIR}/operator-receipts.sqlite3" \
    --revocation-db "${STATE_DIR}/operator-revocations.sqlite3" \
    --authority-seed-file "${OPERATOR_AUTHORITY_SEED}" \
    --budget-db "${STATE_DIR}/operator-budgets.sqlite3" \
    >"${LOG_DIR}/operator-trust-control.log" 2>&1 &
  OPERATOR_TRUST_PID=$!

  "${CHIO_BIN}" trust serve \
    --listen "127.0.0.1:${PROVIDER_TRUST_PORT}" \
    --advertise-url "${PROVIDER_CONTROL_URL}" \
    --service-token "${SERVICE_TOKEN}" \
    --receipt-db "${STATE_DIR}/provider-receipts.sqlite3" \
    --revocation-db "${STATE_DIR}/provider-revocations.sqlite3" \
    --authority-seed-file "${PROVIDER_AUTHORITY_SEED}" \
    --budget-db "${STATE_DIR}/provider-budgets.sqlite3" \
    >"${LOG_DIR}/provider-trust-control.log" 2>&1 &
  PROVIDER_TRUST_PID=$!

  "${CHIO_BIN}" trust serve \
    --listen "127.0.0.1:${SUBCONTRACTOR_TRUST_PORT}" \
    --advertise-url "${SUBCONTRACTOR_CONTROL_URL}" \
    --service-token "${SERVICE_TOKEN}" \
    --receipt-db "${STATE_DIR}/subcontractor-receipts.sqlite3" \
    --revocation-db "${STATE_DIR}/subcontractor-revocations.sqlite3" \
    --authority-seed-file "${SUBCONTRACTOR_AUTHORITY_SEED}" \
    --budget-db "${STATE_DIR}/subcontractor-budgets.sqlite3" \
    >"${LOG_DIR}/subcontractor-trust-control.log" 2>&1 &
  SUBCONTRACTOR_TRUST_PID=$!

  "${CHIO_BIN}" trust serve \
    --listen "127.0.0.1:${FEDERATION_TRUST_PORT}" \
    --advertise-url "${FEDERATION_CONTROL_URL}" \
    --service-token "${SERVICE_TOKEN}" \
    --receipt-db "${STATE_DIR}/federation-receipts.sqlite3" \
    --revocation-db "${STATE_DIR}/federation-revocations.sqlite3" \
    --authority-seed-file "${FEDERATION_AUTHORITY_SEED}" \
    --budget-db "${STATE_DIR}/federation-budgets.sqlite3" \
    >"${LOG_DIR}/federation-trust-control.log" 2>&1 &
  FEDERATION_TRUST_PID=$!

  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/market_broker.py" \
    --port "${MARKET_RAW_PORT}" >"${LOG_DIR}/market-broker.log" 2>&1 &
  MARKET_PID=$!

  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/services/settlement_desk.py" \
    --port "${SETTLEMENT_RAW_PORT}" >"${LOG_DIR}/settlement-desk.log" 2>&1 &
  SETTLEMENT_PID=$!

  CHIO_TRUSTED_ISSUER_KEY="${OPERATOR_AUTHORITY_PUB}" \
    "${CHIO_BIN}" --control-url "${OPERATOR_CONTROL_URL}" --control-token "${SERVICE_TOKEN}" \
    api protect \
    --upstream "${MARKET_RAW_URL}" \
    --spec "${EXAMPLE_ROOT}/services/market-broker-openapi.yaml" \
    --listen "127.0.0.1:${MARKET_SIDECAR_PORT}" \
    --receipt-store "${STATE_DIR}/market-sidecar-receipts.sqlite3" \
    >"${LOG_DIR}/chio-market-sidecar.log" 2>&1 &
  MARKET_SIDECAR_PID=$!

  CHIO_TRUSTED_ISSUER_KEY="${OPERATOR_AUTHORITY_PUB}" \
    "${CHIO_BIN}" --control-url "${OPERATOR_CONTROL_URL}" --control-token "${SERVICE_TOKEN}" \
    api protect \
    --upstream "${SETTLEMENT_RAW_URL}" \
    --spec "${EXAMPLE_ROOT}/services/settlement-desk-openapi.yaml" \
    --listen "127.0.0.1:${SETTLEMENT_SIDECAR_PORT}" \
    --receipt-store "${STATE_DIR}/settlement-sidecar-receipts.sqlite3" \
    >"${LOG_DIR}/chio-settlement-sidecar.log" 2>&1 &
  SETTLEMENT_SIDECAR_PID=$!

  "${CHIO_BIN}" --control-url "${FEDERATION_CONTROL_URL}" --control-token "${SERVICE_TOKEN}" \
    mcp serve-http \
    --policy "${EXAMPLE_ROOT}/policies/web3-evidence.yaml" \
    --server-id "web3-evidence" \
    --server-name "Meridian Web3 Evidence" \
    --listen "127.0.0.1:${WEB3_EVIDENCE_MCP_PORT}" \
    --auth-token "${CHIO_AUTH_TOKEN}" \
    --session-db "${STATE_DIR}/web3-evidence-sessions.sqlite3" \
    --shared-hosted-owner \
    -- python "${EXAMPLE_ROOT}/tools/web3_evidence.py" \
    >"${LOG_DIR}/chio-web3-evidence-mcp.log" 2>&1 &
  WEB3_EVIDENCE_MCP_PID=$!

  "${CHIO_BIN}" --control-url "${PROVIDER_CONTROL_URL}" --control-token "${SERVICE_TOKEN}" \
    mcp serve-http \
    --policy "${EXAMPLE_ROOT}/policies/provider-review.yaml" \
    --server-id "provider-review" \
    --server-name "ProofWorks Provider Review" \
    --listen "127.0.0.1:${PROVIDER_REVIEW_MCP_PORT}" \
    --auth-token "${CHIO_AUTH_TOKEN}" \
    --session-db "${STATE_DIR}/provider-review-sessions.sqlite3" \
    --shared-hosted-owner \
    -- python "${EXAMPLE_ROOT}/tools/provider_review.py" \
    >"${LOG_DIR}/chio-provider-review-mcp.log" 2>&1 &
  PROVIDER_REVIEW_MCP_PID=$!

  "${CHIO_BIN}" --control-url "${SUBCONTRACTOR_CONTROL_URL}" --control-token "${SERVICE_TOKEN}" \
    mcp serve-http \
    --policy "${EXAMPLE_ROOT}/policies/subcontractor-review.yaml" \
    --server-id "subcontractor-review" \
    --server-name "CipherWorks Specialist Review" \
    --listen "127.0.0.1:${SUBCONTRACTOR_REVIEW_MCP_PORT}" \
    --auth-token "${CHIO_AUTH_TOKEN}" \
    --session-db "${STATE_DIR}/subcontractor-review-sessions.sqlite3" \
    --shared-hosted-owner \
    -- python "${EXAMPLE_ROOT}/tools/subcontractor_review.py" \
    >"${LOG_DIR}/chio-subcontractor-review-mcp.log" 2>&1 &
  SUBCONTRACTOR_REVIEW_MCP_PID=$!

  wait_for_http "${OPERATOR_CONTROL_URL}/health"
  wait_for_http "${PROVIDER_CONTROL_URL}/health"
  wait_for_http "${SUBCONTRACTOR_CONTROL_URL}/health"
  wait_for_http "${FEDERATION_CONTROL_URL}/health"
  wait_for_http "${MARKET_RAW_URL}/health"
  wait_for_http "${SETTLEMENT_RAW_URL}/health"
  wait_for_port 127.0.0.1 "${MARKET_SIDECAR_PORT}"
  wait_for_port 127.0.0.1 "${SETTLEMENT_SIDECAR_PORT}"
  wait_for_port 127.0.0.1 "${WEB3_EVIDENCE_MCP_PORT}"
  wait_for_port 127.0.0.1 "${PROVIDER_REVIEW_MCP_PORT}"
  wait_for_port 127.0.0.1 "${SUBCONTRACTOR_REVIEW_MCP_PORT}"
}

stop_live_topology() {
  for v in SUBCONTRACTOR_REVIEW_MCP_PID PROVIDER_REVIEW_MCP_PID WEB3_EVIDENCE_MCP_PID SETTLEMENT_SIDECAR_PID MARKET_SIDECAR_PID SETTLEMENT_PID MARKET_PID FEDERATION_TRUST_PID SUBCONTRACTOR_TRUST_PID PROVIDER_TRUST_PID OPERATOR_TRUST_PID; do
    if [[ -n "${!v:-}" ]] && kill -0 "${!v}" 2>/dev/null; then
      kill "${!v}" 2>/dev/null || true
      wait "${!v}" 2>/dev/null || true
    fi
  done
  return 0
}

run_live_scenario() {
  local bundle_dir="$1"
  local require_base_sepolia="$2"
  local e2e_report="${3:-}"
  local promotion_report="${4:-}"
  local ops_audit="${5:-}"
  local args=(
    --repo-root "${ROOT}"
    --artifact-dir "${bundle_dir}"
    --operator-control-url "${OPERATOR_CONTROL_URL}"
    --provider-control-url "${PROVIDER_CONTROL_URL}"
    --subcontractor-control-url "${SUBCONTRACTOR_CONTROL_URL}"
    --federation-control-url "${FEDERATION_CONTROL_URL}"
    --service-token "${SERVICE_TOKEN}"
    --chio-auth-token "${CHIO_AUTH_TOKEN}"
    --market-broker-url "${MARKET_URL}"
    --settlement-desk-url "${SETTLEMENT_URL}"
    --web3-evidence-mcp-url "${WEB3_EVIDENCE_MCP_URL}"
    --provider-review-mcp-url "${PROVIDER_REVIEW_MCP_URL}"
    --subcontractor-review-mcp-url "${SUBCONTRACTOR_REVIEW_MCP_URL}"
  )

  if [[ "${require_base_sepolia}" == "1" ]]; then
    args+=(--require-base-sepolia-smoke)
  fi

  if [[ -n "${e2e_report}" ]]; then
    args+=(--e2e-report "${e2e_report}")
  fi
  if [[ -n "${promotion_report}" ]]; then
    args+=(--promotion-report "${promotion_report}")
  fi
  if [[ -n "${ops_audit}" ]]; then
    args+=(--ops-audit "${ops_audit}")
  fi

  uv run --project "${EXAMPLE_ROOT}" python "${EXAMPLE_ROOT}/orchestrate.py" "${args[@]}" \
    > "${bundle_dir}/run-result.json"

  PYTHONPATH="${EXAMPLE_ROOT}" uv run --project "${EXAMPLE_ROOT}" python - "${bundle_dir}" "${require_base_sepolia}" <<'PY'
import json
import sys
from internet_web3.verify import verify_bundle

bundle_dir = sys.argv[1]
require_base_sepolia = sys.argv[2] == "1"
result = verify_bundle(bundle_dir, require_base_sepolia_smoke=require_base_sepolia)
with open(f"{bundle_dir}/review-result.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
    f.write("\n")
PY
}

assert_review_ok() {
  python3 - "$1" <<'PY'
import json
import sys
from pathlib import Path

result = json.loads((Path(sys.argv[1]) / "review-result.json").read_text(encoding="utf-8"))
assert result["ok"], result["errors"]
PY
}

verify_transaction_passport() {
  local bundle_dir="$1"
  local source_dir="${bundle_dir}/transaction-passport-source"
  local passport_dir="${bundle_dir}/transaction-passport"
  local minimal_fixture="${ROOT}/fixtures/proof-room/minimal-passport/valid"
  local signer_seed="${CHIO_PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX:-0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b}"
  local trusted_roots="${CHIO_TRANSACTION_TRUSTED_ROOT_KEYS:-ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96,66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a}"

  rm -rf "${source_dir}" "${passport_dir}"
  mkdir -p "${source_dir}/minimal"

  for artifact in \
    capability-proof.json \
    guard-decision.json \
    kernel-receipt.json \
    policy.json \
    request-digest.json \
    response-digest.json \
    trust-root.json
  do
    cp "${minimal_fixture}/${artifact}" "${source_dir}/minimal/${artifact}"
  done

  CHIO_PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX="${signer_seed}" \
  "${CHIO_BIN}" proof assemble \
    --artifact-dir "${source_dir}" \
    --verifier-policy "${minimal_fixture}/verifier-policy.json" \
    --passport-id "passport-ioa-web3-service-order" \
    --issued-at "2026-06-10T00:00:00Z" \
    --out "${passport_dir}" \
    --json \
    >"${bundle_dir}/transaction-passport-assemble-report.json"

  CHIO_TRANSACTION_TRUSTED_ROOT_KEYS="${trusted_roots}" \
  "${CHIO_BIN}" proof verify "${passport_dir}" \
    --out "${passport_dir}/verifier-report.json"

  python3 - "${passport_dir}/verifier-report.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report.get("verdict") != "verified":
    raise SystemExit(f"transaction passport did not verify: {report.get('verdict')}")
PY

  CHIO_BIN="${CHIO_BIN}" \
    "${ROOT}/scripts/check-chio-transaction-passport.sh" \
    >"${passport_dir}/negative-fixture-gate.log"
}
