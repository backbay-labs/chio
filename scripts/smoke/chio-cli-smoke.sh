#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHIO_VERSION="${CHIO_VERSION:-0.1.0}"
TMP_ROOT="${CHIO_SMOKE_TMP:-$(mktemp -d -t chio-cli-smoke.XXXXXX)}"
ARTIFACT_ROOT="${CHIO_SMOKE_ARTIFACT_ROOT:-${TMP_ROOT}/artifacts}"
INSTALL_ROOT="${TMP_ROOT}/install"
SUMMARY_FILE="${ARTIFACT_ROOT}/summary.txt"

USE_LOCAL=0
SKIP_INSTALL=0
RUN_EXTENDED=0
RUN_BACKSTOPS=0
CONTINUE_ON_FAIL=0
SELECTED_GROUPS=()
FAILURES=()
CHIO_BIN="${CHIO_BIN:-}"
SMOKE_HELPER=""

usage() {
  cat <<EOF
Usage:
  scripts/smoke/chio-cli-smoke.sh [options] [group ...]

Groups:
  install-shape       Install chio and verify CLI command shape
  core                init, scaffold demo, check, receipts, evidence
  guard               guard new, build, inspect, test, pack, install
  mcp                 chio mcp serve stdio allow and deny flow
  http-api            trust serve and api protect hello examples
  identity            did, passport create/verify, reputation local/compare
  cert                cert generate and verify from seeded ACP receipts
  certify             certify check, verify, registry publish/list/resolve/revoke
  backstops           targeted cargo integration tests
  extended            examples/run-hello-smokes.sh full adapter matrix

Options:
  --use-local         Build and smoke target/debug/chio instead of cargo install
  --skip-install      Require CHIO_BIN to be set and executable
  --extended          Also run the full hello example matrix
  --with-backstops    Also run targeted chio-cli integration tests
  --continue-on-fail  Keep running groups after a failure
  -h, --help          Show this help

Environment:
  CHIO_BIN                         Existing chio binary to smoke
  CHIO_VERSION                     Crates.io version to install, default 0.1.0
  CHIO_SMOKE_TMP                   Temp root, default mktemp
  CHIO_SMOKE_ARTIFACT_ROOT         Artifact root, default TMP/artifacts
  CHIO_SMOKE_CARGO_INSTALL_LOCKED  Set to 1 to pass --locked to cargo install
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --use-local)
      USE_LOCAL=1
      ;;
    --skip-install)
      SKIP_INSTALL=1
      ;;
    --extended)
      RUN_EXTENDED=1
      ;;
    --with-backstops)
      RUN_BACKSTOPS=1
      ;;
    --continue-on-fail)
      CONTINUE_ON_FAIL=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      SELECTED_GROUPS+=("$1")
      ;;
  esac
  shift
done

mkdir -p "${ARTIFACT_ROOT}"
: > "${SUMMARY_FILE}"

log() {
  printf '[chio-cli-smoke] %s\n' "$*"
}

record_failure() {
  local group="$1"
  local message="$2"
  FAILURES+=("${group}: ${message}")
  printf 'FAIL %s: %s\n' "${group}" "${message}" >> "${SUMMARY_FILE}"
  if [[ "${CONTINUE_ON_FAIL}" -ne 1 ]]; then
    exit 1
  fi
}

group_enabled() {
  local group="$1"
  if [[ "${#SELECTED_GROUPS[@]}" -eq 0 ]]; then
    case "${group}" in
      backstops)
        [[ "${RUN_BACKSTOPS}" -eq 1 ]]
        return
        ;;
      extended)
        [[ "${RUN_EXTENDED}" -eq 1 ]]
        return
        ;;
      *)
        return 0
        ;;
    esac
  fi

  local selected
  for selected in "${SELECTED_GROUPS[@]}"; do
    [[ "${selected}" == "${group}" ]] && return 0
  done
  return 1
}

run_cmd_in() {
  local group="$1"
  local name="$2"
  local cwd="$3"
  shift 3

  local dir="${ARTIFACT_ROOT}/${group}"
  local restore_errexit=0
  case "$-" in
    *e*) restore_errexit=1 ;;
  esac
  mkdir -p "${dir}"
  printf '%q ' "$@" > "${dir}/${name}.cmd"
  printf '\n' >> "${dir}/${name}.cmd"
  log "${group}: ${name}"

  set +e
  (
    cd "${cwd}"
    "$@"
  ) > "${dir}/${name}.out" 2> "${dir}/${name}.err"
  local code=$?
  if [[ "${restore_errexit}" -eq 1 ]]; then
    set -e
  else
    set +e
  fi

  printf '%s\n' "${code}" > "${dir}/${name}.status"
  if [[ "${code}" -ne 0 ]]; then
    echo "command failed with status ${code}: ${ARTIFACT_ROOT}/${group}/${name}.*" >&2
    return "${code}"
  fi
  return 0
}

run_cmd() {
  local group="$1"
  local name="$2"
  shift 2
  run_cmd_in "${group}" "${name}" "${ROOT}" "$@"
}

run_cmd_expect_failure() {
  local group="$1"
  local name="$2"
  shift 2

  local dir="${ARTIFACT_ROOT}/${group}"
  local restore_errexit=0
  case "$-" in
    *e*) restore_errexit=1 ;;
  esac
  mkdir -p "${dir}"
  printf '%q ' "$@" > "${dir}/${name}.cmd"
  printf '\n' >> "${dir}/${name}.cmd"
  log "${group}: ${name}"

  set +e
  (
    cd "${ROOT}"
    "$@"
  ) > "${dir}/${name}.out" 2> "${dir}/${name}.err"
  local code=$?
  if [[ "${restore_errexit}" -eq 1 ]]; then
    set -e
  else
    set +e
  fi

  printf '%s\n' "${code}" > "${dir}/${name}.status"
  if [[ "${code}" -eq 0 ]]; then
    echo "command was expected to fail but succeeded: ${ARTIFACT_ROOT}/${group}/${name}.*" >&2
    return 1
  fi
  return 0
}

json_assert() {
  local file="$1"
  local expression="$2"
  python3 - "${file}" "${expression}" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not eval(sys.argv[2], {"payload": payload}):
    raise SystemExit(f"JSON assertion failed: {sys.argv[2]}\npayload={payload!r}")
PY
}

text_assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -F "${needle}" "${file}" >/dev/null; then
    echo "expected ${file} to contain: ${needle}" >&2
    return 1
  fi
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required tool not found: $1" >&2
    return 1
  fi
}

install_or_select_chio() {
  require_tool cargo
  require_tool python3
  require_tool curl

  if [[ -n "${CHIO_BIN}" ]]; then
    if [[ ! -x "${CHIO_BIN}" ]]; then
      echo "CHIO_BIN is set but is not executable: ${CHIO_BIN}" >&2
      return 1
    fi
    export CHIO_BIN
    return 0
  fi

  if [[ "${SKIP_INSTALL}" -eq 1 ]]; then
    echo "--skip-install requires CHIO_BIN to be set" >&2
    return 1
  fi

  if [[ "${USE_LOCAL}" -eq 1 ]]; then
    run_cmd "install-shape" "cargo-build-local-chio" cargo build --bin chio
    CHIO_BIN="${ROOT}/target/debug/chio"
    export CHIO_BIN
    return 0
  fi

  local install_args=(install chio --version "${CHIO_VERSION}" --root "${INSTALL_ROOT}" --force)
  if [[ "${CHIO_SMOKE_CARGO_INSTALL_LOCKED:-0}" == "1" ]]; then
    install_args+=(--locked)
  fi
  run_cmd "install-shape" "cargo-install-chio" cargo "${install_args[@]}"
  CHIO_BIN="${INSTALL_ROOT}/bin/chio"
  export CHIO_BIN
}

run_group() {
  local group="$1"
  local fn="$2"
  if ! group_enabled "${group}"; then
    return 0
  fi

  if [[ "${group}" != "install-shape" && "${group}" != "backstops" && -z "${CHIO_BIN}" ]]; then
    if ! install_or_select_chio; then
      record_failure "${group}" "could not select a chio binary"
      return 0
    fi
  fi

  log "starting group: ${group}"
  set +e
  (
    set -e
    "${fn}"
  )
  local code=$?
  set -e
  if [[ "${code}" -ne 0 ]]; then
    record_failure "${group}" "see ${ARTIFACT_ROOT}/${group}"
    return 0
  fi
  printf 'PASS %s\n' "${group}" >> "${SUMMARY_FILE}"
}

needs_chio_binary() {
  if [[ "${#SELECTED_GROUPS[@]}" -eq 0 ]]; then
    return 0
  fi

  local selected
  for selected in "${SELECTED_GROUPS[@]}"; do
    if [[ "${selected}" != "backstops" ]]; then
      return 0
    fi
  done
  return 1
}

smoke_install_shape() {
  install_or_select_chio

  run_cmd "install-shape" "version" "${CHIO_BIN}" --version
  text_assert_contains "${ARTIFACT_ROOT}/install-shape/version.out" "chio"
  if [[ "${USE_LOCAL}" -ne 1 && "${SKIP_INSTALL}" -ne 1 ]]; then
    text_assert_contains "${ARTIFACT_ROOT}/install-shape/version.out" "${CHIO_VERSION}"
  fi

  run_cmd "install-shape" "help-root" "${CHIO_BIN}" --help
  local helps=(
    "init --help"
    "check --help"
    "guard --help"
    "guard test --help"
    "mcp serve --help"
    "api protect --help"
    "trust serve --help"
    "receipt list --help"
    "evidence export --help"
    "evidence verify --help"
    "cert verify --help"
    "passport create --help"
    "reputation local --help"
    "reputation compare --help"
    "certify check --help"
    "certify registry --help"
  )
  local idx=0
  local help_args
  for help_args in "${helps[@]}"; do
    idx=$((idx + 1))
    read -r -a parts <<< "${help_args}"
    run_cmd "install-shape" "help-${idx}" "${CHIO_BIN}" "${parts[@]}"
  done
}

smoke_core() {
  local dir="${TMP_ROOT}/core"
  local project="${dir}/init-project"
  local receipt_db="${dir}/receipts.sqlite3"
  local evidence_dir="${dir}/evidence"
  local tampered_dir="${dir}/evidence-tampered"
  mkdir -p "${dir}"

  run_cmd "core" "init" "${CHIO_BIN}" init "${project}"
  for path in Cargo.toml README.md policy.yaml .gitignore src/bin/hello_server.rs src/bin/demo.rs; do
    [[ -e "${project}/${path}" ]] || {
      echo "missing scaffold path: ${project}/${path}" >&2
      return 1
    }
  done

  run_cmd "core" "scaffold-demo" env \
    CHIO_BIN="${CHIO_BIN}" \
    CARGO_TARGET_DIR="${dir}/target" \
    cargo run --quiet --manifest-path "${project}/Cargo.toml" --bin demo -- Codex
  text_assert_contains "${ARTIFACT_ROOT}/core/scaffold-demo.out" "Hello, Codex! This call was mediated by Chio."

  run_cmd "core" "check-allow" "${CHIO_BIN}" \
    --format json \
    --receipt-db "${receipt_db}" \
    check \
    --policy "examples/policies/default.yaml" \
    --server "*" \
    --tool bash \
    --params '{"command":"echo durable receipt"}'
  json_assert "${ARTIFACT_ROOT}/core/check-allow.out" "payload['verdict'].lower() == 'allow' and bool(payload.get('receipt_id'))"

  run_cmd_expect_failure "core" "check-deny" "${CHIO_BIN}" \
    --format json \
    check \
    --policy "crates/products/chio-cli/src/policies/code_agent.yaml" \
    --server fs \
    --tool write_file \
    --params '{"path":"/workspace/project/.env","content":"BAD=1"}'
  json_assert "${ARTIFACT_ROOT}/core/check-deny.out" "payload['verdict'].lower() == 'deny'"

  run_cmd "core" "receipt-list" "${CHIO_BIN}" \
    --receipt-db "${receipt_db}" \
    receipt list --limit 20
  [[ -s "${ARTIFACT_ROOT}/core/receipt-list.out" ]]

  run_cmd "core" "evidence-export" "${CHIO_BIN}" \
    --receipt-db "${receipt_db}" \
    evidence export --output "${evidence_dir}"
  run_cmd "core" "evidence-verify" "${CHIO_BIN}" \
    --format json \
    evidence verify --input "${evidence_dir}"
  json_assert "${ARTIFACT_ROOT}/core/evidence-verify.out" "payload['toolReceipts'] >= 1 and payload['verifiedFiles'] >= 1"

  cp -R "${evidence_dir}" "${tampered_dir}"
  python3 - "${tampered_dir}/query.json" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_text('{"tampered":true}\n', encoding="utf-8")
PY
  run_cmd_expect_failure "core" "evidence-tamper-fails" "${CHIO_BIN}" \
    --format json \
    evidence verify --input "${tampered_dir}"
}

smoke_guard() {
  local dir="${TMP_ROOT}/guard"
  local project="${dir}/smoke-guard"
  local fixture="${dir}/allow-fixture.yaml"
  local install_dir="${dir}/installed-guards"
  local wasm="${project}/target/wasm32-unknown-unknown/release/smoke_guard.wasm"
  mkdir -p "${dir}"

  run_cmd "guard" "new" "${CHIO_BIN}" guard new "${project}"
  run_cmd_in "guard" "build" "${project}" "${CHIO_BIN}" guard build
  [[ -f "${wasm}" ]] || {
    echo "missing built wasm: ${wasm}" >&2
    return 1
  }

  cat > "${fixture}" <<'YAML'
- name: allow_generated_guard
  request:
    tool_name: read_file
    server_id: smoke-server
    agent_id: smoke-agent
    arguments:
      path: README.md
    scopes: []
  expected_verdict: allow
YAML

  run_cmd "guard" "inspect" "${CHIO_BIN}" guard inspect "${wasm}"
  text_assert_contains "${ARTIFACT_ROOT}/guard/inspect.out" "ABI compatibility: COMPATIBLE"
  run_cmd "guard" "test" "${CHIO_BIN}" guard test --wasm "${wasm}" "${fixture}"
  text_assert_contains "${ARTIFACT_ROOT}/guard/test.out" "0 failed"
  run_cmd_in "guard" "pack" "${project}" "${CHIO_BIN}" guard pack
  run_cmd "guard" "install" "${CHIO_BIN}" guard install \
    "${project}/smoke-guard-0.1.0.arcguard" \
    --target-dir "${install_dir}"
  [[ -f "${install_dir}/smoke-guard/guard-manifest.yaml" ]]
}

write_mcp_smoke_fixture() {
  local dir="$1"
  mkdir -p "${dir}"
  cat > "${dir}/policy.yaml" <<'YAML'
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
capabilities:
  default:
    tools:
      - server: smoke-mcp
        tool: echo_text
        operations: [invoke]
        ttl: 300
YAML

  cat > "${dir}/mock_mcp_server.py" <<'PY'
import json
import sys

TOOLS = [
    {
        "name": "echo_text",
        "description": "Echo a message",
        "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "dangerous",
        "description": "Should be hidden by policy",
        "inputSchema": {"type": "object"},
    },
]

def respond(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    if not line.strip():
        continue
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "smoke-upstream", "version": "0.1.0"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = message.get("params", {}).get("name")
        args = message.get("params", {}).get("arguments", {})
        if name == "dangerous":
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"content": [{"type": "text", "text": "dangerous reached"}], "isError": False},
            })
        else:
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": args.get("message", "fixture-response")}],
                    "structuredContent": {"echo": args.get("message", "")},
                    "isError": False,
                },
            })
    else:
        respond({"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601, "message": "unknown method"}})
PY

  cat > "${dir}/mcp_client.py" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

chio, receipt_db, policy, server, artifact_dir = sys.argv[1:]
artifact_dir = Path(artifact_dir)
artifact_dir.mkdir(parents=True, exist_ok=True)

proc = subprocess.Popen(
    [
        chio,
        "--receipt-db",
        receipt_db,
        "mcp",
        "serve",
        "--policy",
        policy,
        "--server-id",
        "smoke-mcp",
        "--server-name",
        "Smoke MCP",
        "--",
        "python3",
        server,
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=(artifact_dir / "mcp-serve.stderr").open("w", encoding="utf-8"),
    text=True,
    bufsize=1,
)

def send(message):
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()

def read_response(expected_id):
    assert proc.stdout is not None
    notifications = []
    while True:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("chio mcp serve exited before response")
        payload = json.loads(line)
        if payload.get("id") == expected_id:
            return payload, notifications
        notifications.append(payload)

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0.1.0"}}})
initialize, _ = read_response(1)
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
listed, _ = read_response(2)
send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "echo_text", "arguments": {"message": "hello edge"}}})
allowed, _ = read_response(3)
send({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "dangerous", "arguments": {}}})
denied, denied_notifications = read_response(4)

proc.stdin.close()
code = proc.wait(timeout=30)
if code != 0:
    raise SystemExit(f"chio mcp serve exited with {code}")

(artifact_dir / "initialize.json").write_text(json.dumps(initialize, indent=2) + "\n", encoding="utf-8")
(artifact_dir / "tools-list.json").write_text(json.dumps(listed, indent=2) + "\n", encoding="utf-8")
(artifact_dir / "allowed-call.json").write_text(json.dumps(allowed, indent=2) + "\n", encoding="utf-8")
(artifact_dir / "denied-call.json").write_text(json.dumps(denied, indent=2) + "\n", encoding="utf-8")
(artifact_dir / "denied-notifications.json").write_text(json.dumps(denied_notifications, indent=2) + "\n", encoding="utf-8")

tools = listed["result"]["tools"]
assert [tool["name"] for tool in tools] == ["echo_text"], listed
assert allowed["result"]["isError"] is False, allowed
assert allowed["result"]["structuredContent"]["echo"] == "hello edge", allowed
assert denied["result"]["isError"] is True, denied
assert "not authorized" in denied["result"]["content"][0]["text"], denied
assert denied_notifications, denied_notifications
PY
}

smoke_mcp() {
  local dir="${TMP_ROOT}/mcp"
  local receipt_db="${dir}/receipts.sqlite3"
  write_mcp_smoke_fixture "${dir}"

  run_cmd "mcp" "stdio-flow" python3 \
    "${dir}/mcp_client.py" \
    "${CHIO_BIN}" \
    "${receipt_db}" \
    "${dir}/policy.yaml" \
    "${dir}/mock_mcp_server.py" \
    "${ARTIFACT_ROOT}/mcp/client"
  run_cmd "mcp" "receipt-list" "${CHIO_BIN}" \
    --receipt-db "${receipt_db}" \
    receipt list --limit 20
  [[ -s "${ARTIFACT_ROOT}/mcp/receipt-list.out" ]]
}

smoke_http_api() {
  run_cmd "http-api" "hello-trust-control" env \
    CHIO_BIN="${CHIO_BIN}" \
    "${ROOT}/examples/hello-trust-control/smoke.sh"
  run_cmd "http-api" "hello-openapi-sidecar" env \
    CHIO_BIN="${CHIO_BIN}" \
    "${ROOT}/examples/hello-openapi-sidecar/smoke.sh"
}

build_smoke_helper() {
  if [[ -n "${SMOKE_HELPER}" ]]; then
    return 0
  fi

  local dir="${TMP_ROOT}/state-seed-helper"
  mkdir -p "${dir}/src"
  cat > "${dir}/Cargo.toml" <<EOF
[package]
name = "chio-smoke-state-seed"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
chio-core = { path = "${ROOT}/crates/core/chio-core" }
chio-kernel = { path = "${ROOT}/crates/kernel/chio-kernel" }
chio-store-sqlite = { path = "${ROOT}/crates/platform/chio-store-sqlite" }
rusqlite = { version = "0.39", features = ["bundled"] }
serde_json = "1"
EOF

  cat > "${dir}/src/main.rs" <<'RS'
use std::path::PathBuf;

use chio_core::capability::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, ReceiptAttributionMetadata, ToolCallAction,
};
use chio_core::TrustLevel;
use chio_kernel::{BudgetStore, CapabilityAuthority, LocalCapabilityAuthority, ReceiptStore};
use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};
use rusqlite::params;

fn make_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    timestamp: u64,
) -> ChioReceipt {
    let kernel_kp = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/workspace/safe/data.txt"
            }))
            .unwrap(),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: issuer_key.to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                }
            })),
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_kp.public_key(),
        },
        &kernel_kp,
    )
    .unwrap()
}

fn seed_identity(receipt_db_path: PathBuf, budget_db_path: PathBuf, subject_out: PathBuf) {
    let subject_kp = Keypair::generate();
    let authority = LocalCapabilityAuthority::new(Keypair::generate());
    let capability = authority
        .issue_capability(
            &subject_kp.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Read],
                    constraints: Vec::new(),
                    max_invocations: Some(10),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            300,
        )
        .unwrap();

    let mut receipt_store = SqliteReceiptStore::open(&receipt_db_path).unwrap();
    receipt_store
        .record_capability_snapshot(&capability, None)
        .unwrap();

    let subject_key = subject_kp.public_key().to_hex();
    let issuer_key = authority.authority_public_key().to_hex();
    receipt_store
        .append_chio_receipt(&make_receipt(
            "rep-smoke-1",
            &capability.id,
            &subject_key,
            &issuer_key,
            1_700_000_000,
        ))
        .unwrap();
    receipt_store
        .append_chio_receipt(&make_receipt(
            "rep-smoke-2",
            &capability.id,
            &subject_key,
            &issuer_key,
            1_700_086_500,
        ))
        .unwrap();

    let mut budget_store = SqliteBudgetStore::open(&budget_db_path).unwrap();
    let _ = budget_store
        .try_charge_cost(&capability.id, 0, Some(10), 25, Some(50), Some(500))
        .unwrap();
    std::fs::write(subject_out, format!("{subject_key}\n")).unwrap();
}

fn seed_cert(receipt_db_path: PathBuf, session_id: &str) {
    let keypair = Keypair::generate();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "acp-smoke-1".to_string(),
            timestamp: 1_700_000_000,
            capability_id: format!("acp-session:{session_id}:cap-1"),
            tool_server: "acp-smoke".to_string(),
            tool_name: "fs/read".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "fs/readme.md"
            }))
            .unwrap(),
            decision: Decision::Allow,
            content_hash: "content-acp-smoke-1".to_string(),
            policy_hash: "policy-acp-smoke".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "acp": {
                    "sessionId": session_id,
                    "enforcementMode": "enforce"
                }
            })),
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let conn = rusqlite::Connection::open(receipt_db_path).unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chio_receipts (id TEXT PRIMARY KEY, capability_id TEXT NOT NULL, json_data TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO chio_receipts (id, capability_id, json_data) VALUES (?1, ?2, ?3)",
        params![receipt.id, receipt.capability_id, json],
    )
    .unwrap();
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("identity") if args.len() == 4 => seed_identity(
            PathBuf::from(&args[1]),
            PathBuf::from(&args[2]),
            PathBuf::from(&args[3]),
        ),
        Some("cert") if args.len() == 3 => seed_cert(PathBuf::from(&args[1]), &args[2]),
        _ => {
            eprintln!("usage: chio-smoke-state-seed identity <receipt-db> <budget-db> <subject-out>");
            eprintln!("   or: chio-smoke-state-seed cert <receipt-db> <session-id>");
            std::process::exit(2);
        }
    }
}
RS

  run_cmd "helper" "build-state-seed" cargo build --quiet --release --manifest-path "${dir}/Cargo.toml"
  SMOKE_HELPER="${dir}/target/release/chio-smoke-state-seed"
}

smoke_identity() {
  local dir="${TMP_ROOT}/identity"
  local receipt_db="${dir}/receipts.sqlite3"
  local budget_db="${dir}/budgets.sqlite3"
  local subject_file="${dir}/subject.txt"
  local passport="${dir}/passport.json"
  local seed="${dir}/passport-seed.txt"
  local verifier_policy="${dir}/passport-verifier.yaml"
  mkdir -p "${dir}"

  build_smoke_helper
  run_cmd "identity" "seed-state" "${SMOKE_HELPER}" identity "${receipt_db}" "${budget_db}" "${subject_file}"
  local subject_hex
  subject_hex="$(tr -d '\n' < "${subject_file}")"

  run_cmd "identity" "did-resolve" "${CHIO_BIN}" \
    --format json \
    did resolve --public-key "${subject_hex}"
  json_assert "${ARTIFACT_ROOT}/identity/did-resolve.out" "payload['id'].startswith('did:chio:')"

  run_cmd "identity" "passport-create" "${CHIO_BIN}" \
    --format json \
    --receipt-db "${receipt_db}" \
    --budget-db "${budget_db}" \
    passport create \
    --subject-public-key "${subject_hex}" \
    --output "${passport}" \
    --signing-seed-file "${seed}"
  [[ -f "${passport}" ]]

  run_cmd "identity" "passport-verify" "${CHIO_BIN}" \
    --format json \
    passport verify --input "${passport}"
  json_assert "${ARTIFACT_ROOT}/identity/passport-verify.out" "payload['credentialCount'] >= 1 and payload['issuerCount'] >= 1"

  python3 - "${passport}" "${verifier_policy}" <<'PY'
import json
import sys
from pathlib import Path

passport = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
issuer = passport["credentials"][0]["issuer"]
score = passport["credentials"][0]["credentialSubject"]["metrics"]["composite_score"]["value"]
Path(sys.argv[2]).write_text(
    f'issuerAllowlist:\n  - "{issuer}"\nminCompositeScore: {max(score - 0.01, 0.0)}\nminReceiptCount: 2\nminLineageRecords: 1\n',
    encoding="utf-8",
)
PY

  run_cmd "identity" "reputation-local" "${CHIO_BIN}" \
    --format json \
    --receipt-db "${receipt_db}" \
    --budget-db "${budget_db}" \
    reputation local \
    --subject-public-key "${subject_hex}" \
    --policy "examples/policies/hushspec-reputation.yaml"
  json_assert "${ARTIFACT_ROOT}/identity/reputation-local.out" "payload['subjectKey'] == '${subject_hex}' and payload['scoringSource'] == 'issuance_policy'"

  run_cmd "identity" "reputation-compare" "${CHIO_BIN}" \
    --format json \
    --receipt-db "${receipt_db}" \
    --budget-db "${budget_db}" \
    reputation compare \
    --subject-public-key "${subject_hex}" \
    --passport "${passport}" \
    --verifier-policy "${verifier_policy}"
  json_assert "${ARTIFACT_ROOT}/identity/reputation-compare.out" "payload['subjectMatches'] is True and payload['passportEvaluation']['accepted'] is True"
}

smoke_cert() {
  local dir="${TMP_ROOT}/cert"
  local receipt_db="${dir}/receipts.sqlite3"
  local session_id="smoke-session"
  local cert_path="${dir}/certificate.json"
  local seed="${dir}/authority-seed.txt"
  mkdir -p "${dir}"

  build_smoke_helper
  run_cmd "cert" "seed-acp-receipt" "${SMOKE_HELPER}" cert "${receipt_db}" "${session_id}"
  run_cmd "cert" "generate" "${CHIO_BIN}" \
    --format json \
    cert generate \
    --session-id "${session_id}" \
    --receipt-db "${receipt_db}" \
    --output "${cert_path}" \
    --authority-seed-file "${seed}"
  json_assert "${ARTIFACT_ROOT}/cert/generate.out" "payload['body']['session_id'] == '${session_id}' and payload['body']['receipt_count'] == 1"
  run_cmd "cert" "verify-light" "${CHIO_BIN}" \
    --format json \
    cert verify --certificate "${cert_path}"
  json_assert "${ARTIFACT_ROOT}/cert/verify-light.out" "payload['passed'] is True"
  run_cmd "cert" "verify-full" "${CHIO_BIN}" \
    --format json \
    cert verify --certificate "${cert_path}" --full --receipt-db "${receipt_db}"
  json_assert "${ARTIFACT_ROOT}/cert/verify-full.out" "payload['passed'] is True and payload['receipts_reverified'] == 1"
}

smoke_certify() {
  local dir="${TMP_ROOT}/certify"
  local scenarios="${dir}/scenarios"
  local results="${dir}/results"
  local artifact="${dir}/artifact.json"
  local seed="${dir}/seed.txt"
  local registry="${dir}/registry.json"
  mkdir -p "${scenarios}" "${results}"

  cat > "${scenarios}/initialize.json" <<'JSON'
{
  "id": "initialize",
  "title": "Initialize",
  "area": "core",
  "category": "mcp-core",
  "specVersions": ["2025-11-25"],
  "transport": ["stdio"],
  "peerRoles": ["client_to_chio_server"],
  "deploymentModes": ["wrapped_stdio"],
  "requiredCapabilities": {"server": [], "client": []},
  "tags": ["smoke"],
  "expected": "pass"
}
JSON

  cat > "${results}/results.json" <<'JSON'
[
  {
    "scenarioId": "initialize",
    "peer": "smoke",
    "peerRole": "client_to_chio_server",
    "deploymentMode": "wrapped_stdio",
    "transport": "stdio",
    "specVersion": "2025-11-25",
    "category": "mcp-core",
    "status": "pass",
    "durationMs": 10,
    "assertions": [{"name": "ok", "status": "pass"}]
  }
]
JSON

  run_cmd "certify" "check" "${CHIO_BIN}" \
    --format json \
    certify check \
    --scenarios-dir "${scenarios}" \
    --results-dir "${results}" \
    --output "${artifact}" \
    --tool-server-id smoke-server \
    --tool-server-name "Smoke Server" \
    --signing-seed-file "${seed}"
  json_assert "${ARTIFACT_ROOT}/certify/check.out" "payload['verdict'] == 'pass'"

  run_cmd "certify" "verify" "${CHIO_BIN}" \
    --format json \
    certify verify --input "${artifact}"
  json_assert "${ARTIFACT_ROOT}/certify/verify.out" "payload['verified'] is True and payload['verdict'] == 'pass'"

  run_cmd "certify" "registry-publish" "${CHIO_BIN}" \
    --format json \
    certify registry publish \
    --input "${artifact}" \
    --certification-registry-file "${registry}"
  json_assert "${ARTIFACT_ROOT}/certify/registry-publish.out" "payload['status'] == 'active' and payload['toolServerId'] == 'smoke-server'"
  local artifact_id
  artifact_id="$(python3 - "${ARTIFACT_ROOT}/certify/registry-publish.out" <<'PY'
import json
import sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["artifactId"])
PY
)"

  run_cmd "certify" "registry-list" "${CHIO_BIN}" \
    --format json \
    certify registry list \
    --certification-registry-file "${registry}"
  json_assert "${ARTIFACT_ROOT}/certify/registry-list.out" "payload['count'] >= 1"

  run_cmd "certify" "registry-resolve" "${CHIO_BIN}" \
    --format json \
    certify registry resolve \
    --tool-server-id smoke-server \
    --certification-registry-file "${registry}"
  json_assert "${ARTIFACT_ROOT}/certify/registry-resolve.out" "payload['state'] == 'active'"

  run_cmd "certify" "registry-revoke" "${CHIO_BIN}" \
    --format json \
    certify registry revoke \
    --artifact-id "${artifact_id}" \
    --reason smoke-revoked \
    --certification-registry-file "${registry}"
  json_assert "${ARTIFACT_ROOT}/certify/registry-revoke.out" "payload['status'] == 'revoked'"
}

smoke_backstops() {
  local tests=(
    init
    mcp_serve
    mcp_serve_http
    receipt_db
    evidence_export
    passport
    certify
    trust_revocation
  )
  local test_name
  for test_name in "${tests[@]}"; do
    run_cmd "backstops" "cargo-test-${test_name}" cargo test -p chio-cli --test "${test_name}"
  done
}

smoke_extended() {
  run_cmd "extended" "run-hello-smokes" env \
    CHIO_BIN="${CHIO_BIN}" \
    "${ROOT}/examples/run-hello-smokes.sh"
}

log "artifacts: ${ARTIFACT_ROOT}"
if needs_chio_binary; then
  install_or_select_chio
fi

run_group "install-shape" smoke_install_shape
run_group "core" smoke_core
run_group "guard" smoke_guard
run_group "mcp" smoke_mcp
run_group "http-api" smoke_http_api
run_group "identity" smoke_identity
run_group "cert" smoke_cert
run_group "certify" smoke_certify
run_group "backstops" smoke_backstops
run_group "extended" smoke_extended

if [[ "${#FAILURES[@]}" -gt 0 ]]; then
  log "failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  log "artifacts: ${ARTIFACT_ROOT}"
  exit 1
fi

log "all selected smoke groups passed"
log "artifacts: ${ARTIFACT_ROOT}"
