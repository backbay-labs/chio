#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"

ARTIFACT_ROOT="${EXAMPLE_ROOT}/.artifacts/$(date -u +"%Y%m%dT%H%M%SZ")"
LOG_DIR="${ARTIFACT_ROOT}/logs"
STATE_DIR="${ARTIFACT_ROOT}/state"
mkdir -p "${LOG_DIR}" "${STATE_DIR}"

CHIO_BIN="$(ensure_chio_bin)"
SERVICE_TOKEN="${CHIO_SERVICE_TOKEN:-demo-token}"
TRUST_PORT="$(pick_free_port)"
CONTROL_URL="http://127.0.0.1:${TRUST_PORT}"
TRUST_RECEIPT_DB="${STATE_DIR}/trust-receipts.sqlite3"
REVOCATION_DB="${STATE_DIR}/trust-revocations.sqlite3"
AUTHORITY_DB="${STATE_DIR}/trust-authority.sqlite3"
BUDGET_DB="${STATE_DIR}/trust-budgets.sqlite3"
CHECK_RECEIPT_DB="${STATE_DIR}/check-receipts.sqlite3"
EVIDENCE_DIR="${ARTIFACT_ROOT}/evidence"

cleanup() {
  local code=$?
  if [[ -n "${TRUST_PID:-}" ]] && kill -0 "${TRUST_PID}" >/dev/null 2>&1; then
    kill "${TRUST_PID}" >/dev/null 2>&1 || true
    wait "${TRUST_PID}" >/dev/null 2>&1 || true
  fi
  return "${code}"
}
trap cleanup EXIT

"${CHIO_BIN}" trust serve \
  --listen "127.0.0.1:${TRUST_PORT}" \
  --service-token "${SERVICE_TOKEN}" \
  --receipt-db "${TRUST_RECEIPT_DB}" \
  --revocation-db "${REVOCATION_DB}" \
  --authority-db "${AUTHORITY_DB}" \
  --budget-db "${BUDGET_DB}" \
  >"${LOG_DIR}/trust.log" 2>&1 &
TRUST_PID=$!

wait_for_http "${CONTROL_URL}/health"

issue_demo_capability "${CONTROL_URL}" "${SERVICE_TOKEN}" "${ARTIFACT_ROOT}/capability.json" "hello_trust_control_invoke"
materialize_capability_token "${ARTIFACT_ROOT}/capability.json" "${ARTIFACT_ROOT}/capability.token"

CAPABILITY_ID="$(python3 - "${ARTIFACT_ROOT}/capability.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload["capability"]["id"])
PY
)"

"${CHIO_BIN}" \
  --control-url "${CONTROL_URL}" \
  --control-token "${SERVICE_TOKEN}" \
  trust status \
  --capability-id "${CAPABILITY_ID}" \
  --json \
  > "${ARTIFACT_ROOT}/status-before.json"

"${CHIO_BIN}" \
  --control-url "${CONTROL_URL}" \
  --control-token "${SERVICE_TOKEN}" \
  trust revoke \
  --capability-id "${CAPABILITY_ID}" \
  --json \
  > "${ARTIFACT_ROOT}/revoke.json"

"${CHIO_BIN}" \
  --control-url "${CONTROL_URL}" \
  --control-token "${SERVICE_TOKEN}" \
  trust status \
  --capability-id "${CAPABILITY_ID}" \
  --json \
  > "${ARTIFACT_ROOT}/status-after.json"

"${CHIO_BIN}" check \
  --policy "${EXAMPLE_ROOT}/policy.yaml" \
  --tool read_file \
  --params '{"path":"README.md"}' \
  --receipt-db "${CHECK_RECEIPT_DB}" \
  --json \
  > "${ARTIFACT_ROOT}/check.json"

"${CHIO_BIN}" receipt \
  --receipt-db "${CHECK_RECEIPT_DB}" \
  list \
  --admin-all \
  --limit 20 \
  > "${ARTIFACT_ROOT}/receipts.ndjson"

"${CHIO_BIN}" evidence export \
  --receipt-db "${CHECK_RECEIPT_DB}" \
  --admin-all \
  --output "${EVIDENCE_DIR}"

"${CHIO_BIN}" evidence verify \
  --input "${EVIDENCE_DIR}" \
  --json \
  > "${ARTIFACT_ROOT}/verify.json"

python3 "${EXAMPLE_ROOT}/verify_artifacts.py" \
  "${ARTIFACT_ROOT}" \
  --write-summary \
  > "${ARTIFACT_ROOT}/artifact-validation.json"

RECEIPT_ID="$(python3 - "${ARTIFACT_ROOT}/summary.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload["receipt_id"])
PY
)"

cat <<EOF
hello-trust-control smoke passed
artifacts: ${ARTIFACT_ROOT}
capability id: ${CAPABILITY_ID}
receipt id: ${RECEIPT_ID}
evidence dir: ${EVIDENCE_DIR}
EOF
