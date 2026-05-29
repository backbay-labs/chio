#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
chio_bin="${repo_root}/target/debug/chio"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-framework-examples.XXXXXX")"
venv_dir="${work_dir}/python-venv"
auth_token="demo-token"

cleanup() {
  local exit_code=$?
  if [[ -n "${mcp_pid:-}" ]] && kill -0 "${mcp_pid}" >/dev/null 2>&1; then
    kill "${mcp_pid}" >/dev/null 2>&1 || true
    wait "${mcp_pid}" 2>/dev/null || true
  fi
  if [[ -n "${control_pid:-}" ]] && kill -0 "${control_pid}" >/dev/null 2>&1; then
    kill "${control_pid}" >/dev/null 2>&1 || true
    wait "${control_pid}" 2>/dev/null || true
  fi
  if [[ $exit_code -ne 0 ]]; then
    if [[ -f "${work_dir}/control.log" ]]; then
      echo "---- trust service log ----" >&2
      cat "${work_dir}/control.log" >&2
    fi
    if [[ -f "${work_dir}/mcp.log" ]]; then
      echo "---- hosted edge log ----" >&2
      cat "${work_dir}/mcp.log" >&2
    fi
  fi
  rm -rf "${work_dir}"
}
trap cleanup EXIT

for command in cargo python3 node npm curl; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "framework example checks require ${command} on PATH" >&2
    exit 1
  fi
done

read -r control_port mcp_port < <(
  python3 - <<'PY'
import socket

ports = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    ports.append(str(sock.getsockname()[1]))
    sock.close()
print(" ".join(ports))
PY
)

control_url="http://127.0.0.1:${control_port}"
mcp_url="http://127.0.0.1:${mcp_port}"

cargo build -p chio-cli --bin chio >/dev/null
npm --prefix "${repo_root}/sdks/typescript/chio-ts" ci --no-fund --no-audit >/dev/null
npm --prefix "${repo_root}/sdks/typescript/chio-ts" run build >/dev/null

"${chio_bin}" \
  --receipt-db "${work_dir}/receipts.sqlite" \
  --revocation-db "${work_dir}/revocations.sqlite" \
  --authority-db "${work_dir}/authority.sqlite" \
  --budget-db "${work_dir}/budgets.sqlite" \
  trust serve \
  --listen "127.0.0.1:${control_port}" \
  --service-token "${auth_token}" \
  >"${work_dir}/control.log" 2>&1 &
control_pid=$!

for _ in $(seq 1 200); do
  if ! kill -0 "${control_pid}" >/dev/null 2>&1; then
    echo "trust service exited before becoming ready" >&2
    exit 1
  fi
  if curl --silent --fail "${control_url}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if ! curl --silent --fail "${control_url}/health" >/dev/null 2>&1; then
  echo "trust service did not become ready" >&2
  exit 1
fi

"${chio_bin}" \
  --control-url "${control_url}" \
  --control-token "${auth_token}" \
  mcp serve-http \
  --policy "${repo_root}/examples/docker/policy.yaml" \
  --server-id "framework-example-mock" \
  --server-name "Framework Example Mock" \
  --listen "127.0.0.1:${mcp_port}" \
  --auth-token "${auth_token}" \
  -- \
  python3 "${repo_root}/examples/docker/mock_mcp_server.py" \
  >"${work_dir}/mcp.log" 2>&1 &
mcp_pid=$!

for _ in $(seq 1 200); do
  if ! kill -0 "${mcp_pid}" >/dev/null 2>&1; then
    echo "hosted edge exited before becoming ready" >&2
    exit 1
  fi
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' "${mcp_url}/mcp" || true)"
  if [[ "${status}" == "401" ]]; then
    break
  fi
  sleep 0.1
done
status="$(curl --silent --output /dev/null --write-out '%{http_code}' "${mcp_url}/mcp" || true)"
if [[ "${status}" != "401" ]]; then
  echo "hosted edge did not become ready" >&2
  exit 1
fi

npm --prefix "${repo_root}/examples/anthropic-sdk" ci --no-fund --no-audit >/dev/null
npm --prefix "${repo_root}/examples/openai-compatible" ci --no-fund --no-audit >/dev/null

CHIO_BASE_URL="${mcp_url}" \
CHIO_CONTROL_URL="${control_url}" \
CHIO_AUTH_TOKEN="${auth_token}" \
node "${repo_root}/examples/anthropic-sdk/run.mjs" --dry-run \
  >"${work_dir}/anthropic.json"

python3 -m venv "${venv_dir}"
. "${venv_dir}/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e "${repo_root}/sdks/python/chio-py" -e "${repo_root}/examples/langchain"

CHIO_BASE_URL="${mcp_url}" \
CHIO_CONTROL_URL="${control_url}" \
CHIO_AUTH_TOKEN="${auth_token}" \
python "${repo_root}/examples/langchain/run.py" \
  >"${work_dir}/langchain.json"

deactivate

CHIO_BASE_URL="${mcp_url}" \
CHIO_CONTROL_URL="${control_url}" \
CHIO_AUTH_TOKEN="${auth_token}" \
node "${repo_root}/examples/openai-compatible/run.mjs" --dry-run \
  >"${work_dir}/openai.json"

python3 - <<'PY' \
  "${work_dir}/anthropic.json" \
  "${work_dir}/langchain.json" \
  "${work_dir}/openai.json" \
  "${repo_root}/docs/start-here/PROGRESSIVE_TUTORIAL.md"
from pathlib import Path
import json
import sys

for path in sys.argv[1:4]:
    payload = json.loads(Path(path).read_text())
    if payload.get("echo") is None:
        raise SystemExit(f"{path} did not report an echoed tool result")
    if payload.get("receiptId") is None:
        raise SystemExit(f"{path} did not report a receipt id")
    if payload.get("capabilityId") is None:
        raise SystemExit(f"{path} did not report a capability id")

tutorial = Path(sys.argv[4]).read_text()
for phrase in (
    "Chio Concepts",
    "Write A Policy",
    "Wrap A Tool",
    "Execute A Governed Call",
    "Read A Receipt",
    "Delegate A Capability",
):
    if phrase not in tutorial:
        raise SystemExit(f"tutorial is missing section: {phrase}")

print("Framework integration examples verified")
PY
