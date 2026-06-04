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
APP_PORT="$(pick_free_port)"
SIDECAR_PORT="$(pick_free_port)"
CONTROL_URL="http://127.0.0.1:${TRUST_PORT}"
APP_URL="http://127.0.0.1:${APP_PORT}"
SIDECAR_URL="http://127.0.0.1:${SIDECAR_PORT}"
RECEIPT_STORE="${STATE_DIR}/sidecar-receipts.sqlite3"

cleanup() {
  local code=$?
  for pid in ${SIDECAR_PID:-} ${APP_PID:-} ${TRUST_PID:-}; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
  return "${code}"
}
trap cleanup EXIT

"${CHIO_BIN}" trust serve \
  --listen "127.0.0.1:${TRUST_PORT}" \
  --service-token "${SERVICE_TOKEN}" \
  --receipt-db "${STATE_DIR}/trust-receipts.sqlite3" \
  --revocation-db "${STATE_DIR}/trust-revocations.sqlite3" \
  --authority-db "${STATE_DIR}/trust-authority.sqlite3" \
  --budget-db "${STATE_DIR}/trust-budgets.sqlite3" \
  >"${LOG_DIR}/trust.log" 2>&1 &
TRUST_PID=$!

wait_for_http "${CONTROL_URL}/health"
TRUSTED_ISSUER_KEY="$(trust_authority_public_key "${CONTROL_URL}" "${SERVICE_TOKEN}")"

(
  export CHIO_SIDECAR_URL="${SIDECAR_URL}"
  export HELLO_ELYSIA_PORT="${APP_PORT}"
  "${EXAMPLE_ROOT}/run.sh"
) >"${LOG_DIR}/app.log" 2>&1 &
APP_PID=$!

wait_for_http "${APP_URL}/healthz"

(
  export CHIO_TRUSTED_ISSUER_KEY="${TRUSTED_ISSUER_KEY}"
  exec "${CHIO_BIN}" \
    --control-url "${CONTROL_URL}" \
    --control-token "${SERVICE_TOKEN}" \
    api protect \
    --upstream "${APP_URL}" \
    --spec "${EXAMPLE_ROOT}/openapi.yaml" \
    --listen "127.0.0.1:${SIDECAR_PORT}" \
    --receipt-store "${RECEIPT_STORE}"
) >"${LOG_DIR}/sidecar.log" 2>&1 &
SIDECAR_PID=$!

wait_for_port 127.0.0.1 "${SIDECAR_PORT}"

curl -sS -D "${ARTIFACT_ROOT}/hello.headers" "${APP_URL}/hello" > "${ARTIFACT_ROOT}/hello.json"

python3 - "${ARTIFACT_ROOT}/hello.json" <<'PY'
import json
import sys
from pathlib import Path

body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert body["message"] == "hello from elysia", body
PY

curl -sS -D "${ARTIFACT_ROOT}/deny.headers" \
  -H "content-type: application/json" \
  --data '{"message":"denied","count":1}' \
  "${APP_URL}/echo" \
  > "${ARTIFACT_ROOT}/deny.json"

python3 - "${ARTIFACT_ROOT}/deny.json" <<'PY'
import json
import sys
from pathlib import Path

body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert body["error"] == "chio_access_denied", body
assert body["receipt_id"], body
PY

issue_demo_capability \
  "${CONTROL_URL}" \
  "${SERVICE_TOKEN}" \
  "${ARTIFACT_ROOT}/capability.json" \
  "authorize_http_request" \
  "chio_http_authority"
materialize_capability_token "${ARTIFACT_ROOT}/capability.json" "${ARTIFACT_ROOT}/capability.token"

curl -sS -D "${ARTIFACT_ROOT}/allow.headers" \
  -H "content-type: application/json" \
  -H "X-Chio-Capability: $(tr -d '\n' < "${ARTIFACT_ROOT}/capability.token")" \
  --data '{"message":"hello","count":2}' \
  "${APP_URL}/echo" \
  > "${ARTIFACT_ROOT}/allow.json"

python3 - "${ARTIFACT_ROOT}/allow.json" <<'PY'
import json
import sys
from pathlib import Path

body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert body["message"] == "hello", body
assert body["count"] == 2, body
PY

HELLO_RECEIPT_ID="$(header_value "${ARTIFACT_ROOT}/hello.headers" "x-chio-receipt-id")"
DENY_RECEIPT_ID="$(header_value "${ARTIFACT_ROOT}/deny.headers" "x-chio-receipt-id")"
ALLOW_RECEIPT_ID="$(header_value "${ARTIFACT_ROOT}/allow.headers" "x-chio-receipt-id")"

if [[ -z "${DENY_RECEIPT_ID}" ]]; then
  DENY_RECEIPT_ID="$(python3 - "${ARTIFACT_ROOT}/deny.json" <<'PY'
import json
import sys
from pathlib import Path

body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(body.get("receipt_id", ""))
PY
)"
fi

python3 - \
  "${RECEIPT_STORE}" \
  "${ARTIFACT_ROOT}/receipts.ndjson" \
  "${ARTIFACT_ROOT}/receipt-summary.json" \
  "${HELLO_RECEIPT_ID}" \
  "${DENY_RECEIPT_ID}" \
  "${ALLOW_RECEIPT_ID}" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

receipt_store = Path(sys.argv[1])
output_path = Path(sys.argv[2])
summary_path = Path(sys.argv[3])
expected_ids = set(sys.argv[4:])
assert "" not in expected_ids, {"expected_ids": sorted(expected_ids)}

with sqlite3.connect(receipt_store) as db:
    rows = db.execute("SELECT receipt_json FROM http_receipts ORDER BY rowid ASC").fetchall()

receipts = [json.loads(row[0]) for row in rows]
receipt_ids = {receipt["id"] for receipt in receipts}
missing = expected_ids - receipt_ids
assert not missing, {"missing": sorted(missing), "stored": sorted(receipt_ids)}

decisions = {
    (
        receipt.get("method"),
        receipt.get("route_pattern"),
        receipt.get("verdict", {}).get("verdict"),
        receipt.get("response_status"),
    ): receipt["id"]
    for receipt in receipts
}
assert ("GET", "/hello", "allow", 200) in decisions, decisions
assert ("POST", "/echo", "deny", 403) in decisions, decisions
assert ("POST", "/echo", "allow", 200) in decisions, decisions

output_path.write_text(
    "".join(json.dumps(receipt, separators=(",", ":")) + "\n" for receipt in receipts),
    encoding="utf-8",
)
summary_path.write_text(
    json.dumps(
        {
            "hello": decisions[("GET", "/hello", "allow", 200)],
            "deny": decisions[("POST", "/echo", "deny", 403)],
            "allow": decisions[("POST", "/echo", "allow", 200)],
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY

cat <<EOF
hello-elysia smoke passed
artifacts: ${ARTIFACT_ROOT}
hello receipt: ${HELLO_RECEIPT_ID}
deny receipt: ${DENY_RECEIPT_ID}
allow receipt: ${ALLOW_RECEIPT_ID}
EOF
