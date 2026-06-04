#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

pick_free_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-60}"

  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "timed out waiting for HTTP endpoint: ${url}" >&2
  return 1
}

wait_for_port() {
  local host="$1"
  local port="$2"
  local attempts="${3:-60}"

  for _ in $(seq 1 "${attempts}"); do
    if python3 - "${host}" "${port}" <<'PY' >/dev/null 2>&1
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(0.5)
    sock.connect((host, port))
PY
    then
      return 0
    fi
    sleep 1
  done

  echo "timed out waiting for TCP port ${host}:${port}" >&2
  return 1
}

trust_authority_public_key() {
  local control_url="$1"
  local service_token="${2:-}"

  python3 - "${control_url}" "${service_token}" <<'PY'
import json
import sys
import urllib.request

control_url = sys.argv[1].rstrip("/")
service_token = sys.argv[2]
request = urllib.request.Request(f"{control_url}/v1/authority")
if service_token:
    request.add_header("Authorization", f"Bearer {service_token}")
with urllib.request.urlopen(request, timeout=5) as response:
    body = json.loads(response.read().decode("utf-8"))
public_key = body.get("publicKey")
if not public_key:
    raise SystemExit(f"trust service did not report an authority public key: {body!r}")
print(public_key)
PY
}

ensure_chio_bin() {
  if [[ -n "${CHIO_BIN:-}" ]]; then
    if [[ ! -x "${CHIO_BIN}" ]]; then
      echo "CHIO_BIN is set but is not executable: ${CHIO_BIN}" >&2
      return 1
    fi
    printf '%s\n' "${CHIO_BIN}"
    return 0
  fi

  local chio_bin="${ROOT}/target/debug/chio"
  if [[ ! -x "${chio_bin}" ]]; then
    (cd "${ROOT}" && cargo build --bin chio >/dev/null)
  fi
  printf '%s\n' "${chio_bin}"
}

issue_demo_capability() {
  local control_url="$1"
  local service_token="$2"
  local output_json="$3"
  local tool_name="${4:-hello_write}"
  local server_id="${5:-http-sidecar-client}"

  python3 - "${control_url}" "${service_token}" "${output_json}" "${tool_name}" "${server_id}" <<'PY'
import json
import sys
import urllib.request
from pathlib import Path

control_url = sys.argv[1].rstrip("/")
token = sys.argv[2]
output_path = Path(sys.argv[3])
tool_name = sys.argv[4]
server_id = sys.argv[5]

payload = {
    "subjectPublicKey": "00" * 32,
    "scope": {
        "grants": [
            {
                "server_id": server_id,
                "tool_name": tool_name,
                "operations": ["invoke"],
                "constraints": [],
            }
        ],
        "resource_grants": [],
        "prompt_grants": [],
    },
    "ttlSeconds": 3600,
}

request = urllib.request.Request(
    f"{control_url}/v1/capabilities/issue",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=5) as response:
    result = json.loads(response.read().decode("utf-8"))
output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
PY
}

materialize_capability_token() {
  local input_json="$1"
  local output_token="$2"

  python3 - "${input_json}" "${output_token}" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
Path(sys.argv[2]).write_text(
    json.dumps(payload["capability"], separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
}

header_value() {
  local file="$1"
  local header_name="$2"

  python3 - "${file}" "${header_name}" <<'PY'
import sys
from pathlib import Path

target = sys.argv[2].lower()
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if ":" not in line:
        continue
    name, value = line.split(":", 1)
    if name.strip().lower() == target:
        print(value.strip())
        break
PY
}
