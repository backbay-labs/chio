#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
doc="$repo_root/docs/start-here/PROOF_ROOM_QUICKSTART.md"
work="$(mktemp -d)"
server_pid=""

cleanup() {
  if [[ -z "$server_pid" && -f "$work/server.pid" ]]; then
    server_pid="$(cat "$work/server.pid")"
  fi
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

require_doc_line() {
  local line="$1"
  if ! grep -Fqx "$line" "$doc"; then
    echo "proof-room.quickstart.doc-drift: missing documented line: $line" >&2
    exit 1
  fi
}

require_doc_line "source scripts/proof-room-quickstart-env.sh"
require_doc_line "cargo run -p chio-cli -- proof doctor --scenario single-call-authority --root . --json"
require_doc_line "cargo run -p chio-cli -- proof serve fixtures/proof-room/first-run/single-call-authority/proof-room-bundle --listen 127.0.0.1:7391"
require_doc_line "cargo run -p chio-proof-room -- \\"
require_doc_line "  --bundle fixtures/proof-room/first-run/single-call-authority/proof-room-bundle \\"
require_doc_line "  --verify-only \\"
require_doc_line "  --doctor-report /tmp/chio-proof-room-doctor.json"

env -i \
  PATH="${PATH:-/usr/bin:/bin}" \
  HOME="${HOME:-$work/home}" \
  CARGO_HOME="${CARGO_HOME:-${HOME:-$work/home}/.cargo}" \
  RUSTUP_HOME="${RUSTUP_HOME:-${HOME:-$work/home}/.rustup}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  REPO_ROOT="$repo_root" \
  WORK_DIR="$work" \
  bash <<'BASH'
set -euo pipefail

cd "$REPO_ROOT"
source scripts/proof-room-quickstart-env.sh
rm -f /tmp/chio-proof-room-doctor.json

cargo run -p chio-cli -- proof doctor --scenario single-call-authority --root . --json \
  > "$WORK_DIR/doctor.json"
python3 - "$WORK_DIR/doctor.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("schema") != "chio.proof.doctor-report.v1":
    raise SystemExit("proof-room.quickstart.doctor-schema-mismatch")
if report.get("verdict") != "passed":
    raise SystemExit("proof-room.quickstart.doctor-unverified")
for check in report.get("checks", []):
    if check.get("status") != "passed":
        raise SystemExit(f"proof-room.quickstart.doctor-check-failed: {check.get('id')}")
PY

cargo run -p chio-cli -- proof serve fixtures/proof-room/first-run/single-call-authority/proof-room-bundle --listen 127.0.0.1:7391 \
  > "$WORK_DIR/serve.out" 2>&1 &
server_pid=$!
echo "$server_pid" > "$WORK_DIR/server.pid"

python3 - <<'PY'
import sys
import time
import urllib.error
import urllib.request

url = "http://127.0.0.1:7391/manifest.json"
last_error = None
for _ in range(90):
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            body = response.read()
        if b"chio.proof-room.bundle.v1" in body:
            raise SystemExit(0)
        last_error = "manifest schema missing"
    except (OSError, urllib.error.URLError) as error:
        last_error = str(error)
    time.sleep(1)
raise SystemExit(f"proof-room.quickstart.serve-unreachable: {last_error}")
PY

cargo run -p chio-proof-room -- \
  --bundle fixtures/proof-room/first-run/single-call-authority/proof-room-bundle \
  --verify-only \
  --doctor-report /tmp/chio-proof-room-doctor.json

python3 - /tmp/chio-proof-room-doctor.json <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("schema") != "chio.proof-room.quickstart-doctor-report.v1":
    raise SystemExit("proof-room.quickstart.report-schema-mismatch")
if report.get("verdict") != "verified":
    raise SystemExit("proof-room.quickstart.report-unverified")
PY
BASH

if [[ -f "$work/server.pid" ]]; then
  server_pid="$(cat "$work/server.pid")"
fi

echo "OK Proof Room source quickstart"
