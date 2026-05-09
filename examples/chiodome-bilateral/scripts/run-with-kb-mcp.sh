#!/usr/bin/env bash
# Orchestrates the KB MCP demo for the chiodome-bilateral example.
#
# Two modes:
#
#   --check (default)
#     Runs the noninteractive replay under
#       `chio mcp wrap --e2e-fixture <kb-stub-server-fixture.json>`
#     piping `<kb-replay.jsonrpc>` over stdin. This exercises the wrap loop
#     end-to-end without requiring the KB MCP server, mcp-remote, or any
#     network. For each `tools/call` response frame the script writes one
#     mediation-transcript JSON to `${CHIO_RECEIPT_DIR}` and ASSERTS that
#     at least one transcript landed. Fails closed (exit 1) if none did.
#     This is the smoke gate for the replay-only wrapper path.
#
#   --full
#     Documents the canonical `chio mcp serve` invocation against a real
#     KB MCP backend. The full path requires:
#       1. The KB MCP server running at ${KB_MCP_URL}
#       2. `mcp-remote` available (npx -y mcp-remote ...)
#       3. `--receipt-db <path>` so the kernel persists receipts
#     The script PRINTS the canonical command line and exits without
#     running it (so this script never hangs on stdin in CI). The
#     receipt-emission assertion against the real receipt DB is gated on
#     `CHIODOME_DEMO_ASSERT_RECEIPTS=1` for operators who have brought
#     the KB MCP up out-of-band.
#
# Bounded claim: this is a demo. Bearer-token handling, retry/backoff,
# tool-allow-list scope, and receipt-store rotation are out of scope.

set -euo pipefail

# ---------------------------------------------------------------------------
# Knobs
# ---------------------------------------------------------------------------

# Where the KB MCP serves Streamable HTTP (default per ops/knowledge-base/).
KB_MCP_HOST="${KB_MCP_HOST:-127.0.0.1}"
KB_MCP_PORT="${KB_MCP_PORT:-8111}"
KB_MCP_PATH="${KB_MCP_PATH:-/mcp/}"
KB_MCP_URL="http://${KB_MCP_HOST}:${KB_MCP_PORT}${KB_MCP_PATH}"

# Where the wrapper persists mediation transcripts (--check mode) or
# kernel-signed receipts (--full mode). The runner asserts at least one
# *.json file lands here.
CHIO_RECEIPT_DIR="${CHIO_RECEIPT_DIR:-./fixtures/kb-receipts}"

# Where the policy lives (relative to the example dir).
CHIO_POLICY_FILE="${CHIO_POLICY_FILE:-./policy.yaml}"

# Server identity advertised to the wrapper.
CHIO_SERVER_ID="${CHIO_SERVER_ID:-srv-kb-mcp-demo}"
CHIO_SERVER_NAME="${CHIO_SERVER_NAME:-Backbay KB MCP (demo)}"

# Path to the KB MCP server bring-up command. Default mirrors the
# ops/knowledge-base/ Makefile; override for non-default deployments.
KB_MCP_START_CMD="${KB_MCP_START_CMD:-make -C ../../ops/knowledge-base run}"

# Path to the chio CLI binary. By default, run from the workspace via cargo.
CHIO_CLI_BIN="${CHIO_CLI_BIN:-cargo run -q -p chio-cli --}"

# Path to mcp-remote. By default fetched via npx.
MCP_REMOTE_BIN="${MCP_REMOTE_BIN:-npx -y mcp-remote}"

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

MODE="check"
case "${1:-}" in
  --check) MODE="check" ;;
  --full)  MODE="full" ;;
  "")      MODE="check" ;;
  -h|--help)
    sed -n '1,30p' "$0"
    exit 0
    ;;
  *)
    echo "[run-with-kb-mcp] unknown arg: $1 (expected --check or --full)" >&2
    exit 64
    ;;
esac

cd "$(dirname "$0")/.."
echo "[run-with-kb-mcp] mode: ${MODE}"
echo "[run-with-kb-mcp] working directory: $(pwd)"
echo "[run-with-kb-mcp] CHIO_RECEIPT_DIR=${CHIO_RECEIPT_DIR}"
echo "[run-with-kb-mcp] CHIO_POLICY_FILE=${CHIO_POLICY_FILE}"

mkdir -p "${CHIO_RECEIPT_DIR}"

# Resolve fixture paths.
JSONRPC_REPLAY="./fixtures/jsonrpc-replay/kb-replay.jsonrpc"
STUB_SERVER_FIXTURE="./fixtures/jsonrpc-replay/kb-stub-server-fixture.json"

if [[ ! -f "${JSONRPC_REPLAY}" ]]; then
  echo "[run-with-kb-mcp] FAIL: missing replay fixture ${JSONRPC_REPLAY}" >&2
  exit 1
fi
if [[ ! -f "${STUB_SERVER_FIXTURE}" ]]; then
  echo "[run-with-kb-mcp] FAIL: missing stub server fixture ${STUB_SERVER_FIXTURE}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# --check: noninteractive replay through `chio mcp wrap --e2e-fixture`.
# ---------------------------------------------------------------------------

if [[ "${MODE}" == "check" ]]; then
  echo "[run-with-kb-mcp] --check: running noninteractive replay (no upstream KB MCP needed)"
  echo "[run-with-kb-mcp] cmd: ${CHIO_CLI_BIN} mcp wrap --server-id ${CHIO_SERVER_ID} --e2e-fixture ${STUB_SERVER_FIXTURE} < ${JSONRPC_REPLAY}"

  # Capture stdout (the response frames) and stderr (kernel logs).
  WRAP_STDOUT="$(mktemp)"
  WRAP_STDERR="$(mktemp)"
  cleanup_check() {
    rm -f "${WRAP_STDOUT}" "${WRAP_STDERR}"
  }
  trap cleanup_check EXIT

  set +e
  ${CHIO_CLI_BIN} mcp wrap \
      --server-id "${CHIO_SERVER_ID}" \
      --e2e-fixture "${STUB_SERVER_FIXTURE}" \
      < "${JSONRPC_REPLAY}" \
      > "${WRAP_STDOUT}" \
      2> "${WRAP_STDERR}"
  WRAP_RC=$?
  set -e

  if [[ "${WRAP_RC}" -ne 0 ]]; then
    echo "[run-with-kb-mcp] FAIL: chio mcp wrap exited rc=${WRAP_RC}" >&2
    echo "----- stderr -----" >&2
    cat "${WRAP_STDERR}" >&2 || true
    exit 1
  fi

  # Persist one mediation transcript per response frame so a downstream
  # auditor has a paper trail of what the wrapper observed and how it
  # responded. This is NOT a kernel-signed Chio receipt (that path needs
  # `chio mcp serve` against a real upstream); it is the bounded
  # mediation evidence the wrap-mode smoke gate produces.
  count=0
  while IFS= read -r frame; do
    [[ -z "${frame}" ]] && continue
    count=$((count + 1))
    out="${CHIO_RECEIPT_DIR}/mediation-frame-$(printf '%03d' "${count}").json"
    printf '%s\n' "${frame}" > "${out}"
  done < "${WRAP_STDOUT}"

  if [[ "${count}" -lt 1 ]]; then
    echo "[run-with-kb-mcp] FAIL: chio mcp wrap produced 0 response frames"
    echo "----- stderr -----" >&2
    cat "${WRAP_STDERR}" >&2 || true
    exit 1
  fi

  # Assert that at least one *.json transcript exists in the configured
  # sink directory (the audit's smoke-gate contract).
  emitted=$(ls -1 "${CHIO_RECEIPT_DIR}"/*.json 2>/dev/null | wc -l | tr -d '[:space:]')
  if [[ "${emitted}" -lt 1 ]]; then
    echo "[run-with-kb-mcp] FAIL: no mediation transcripts under ${CHIO_RECEIPT_DIR}"
    exit 1
  fi
  echo "[run-with-kb-mcp] OK: ${count} response frames; ${emitted} mediation transcripts under ${CHIO_RECEIPT_DIR}"

  # Sanity: at least one allowed-call frame MUST carry the
  # `_meta.chio_verified` attestation header. Grep is sufficient here;
  # the e2e-wrap test already pins the schema shape.
  if ! grep -q "chio_verified" "${WRAP_STDOUT}"; then
    echo "[run-with-kb-mcp] FAIL: no frame carried the chio_verified attestation header"
    exit 1
  fi
  echo "[run-with-kb-mcp] OK: chio_verified attestation header observed"

  echo "[run-with-kb-mcp] --check done"
  exit 0
fi

# ---------------------------------------------------------------------------
# --full: documented canonical invocation against a real KB MCP backend.
# ---------------------------------------------------------------------------

echo "[run-with-kb-mcp] --full: documenting canonical chio mcp serve invocation"
echo "[run-with-kb-mcp] KB_MCP_URL=${KB_MCP_URL}"

cat <<EOF
[run-with-kb-mcp] --full does NOT auto-spawn the KB MCP server. To run
end-to-end against a real upstream:

  1) bring up KB MCP out-of-band:
       ${KB_MCP_START_CMD}

  2) wait for ${KB_MCP_URL} to accept connections.

  3) drive the wrapper with the replay fixture and a receipt DB so the
     kernel persists one Chio receipt per tools/call:

       CHIO_RECEIPT_DB="\$(mktemp -d)/receipts.sqlite"
       ${CHIO_CLI_BIN} \\
           --receipt-db "\${CHIO_RECEIPT_DB}" \\
           mcp serve \\
             --policy ${CHIO_POLICY_FILE} \\
             --server-id ${CHIO_SERVER_ID} \\
             ${CHIO_SERVER_NAME:+--server-name "${CHIO_SERVER_NAME}"} \\
             -- ${MCP_REMOTE_BIN} ${KB_MCP_URL} \\
         < ${JSONRPC_REPLAY}

  4) verify at least one receipt landed in the SQLite store:

       ${CHIO_CLI_BIN} --receipt-db "\${CHIO_RECEIPT_DB}" receipt list

To enable the real-receipt assertion in this script set
CHIODOME_DEMO_ASSERT_RECEIPTS=1 and export CHIO_RECEIPT_DB to point at
the SQLite file your --full kernel was driven against. The script will
invoke \`chio receipt list --receipt-db \${CHIO_RECEIPT_DB}\` and exit 1
if zero receipts are returned. The default of 0 keeps --full
non-blocking for CI environments where the KB MCP is not running.
EOF

if [[ "${CHIODOME_DEMO_ASSERT_RECEIPTS:-0}" == "1" ]]; then
  if [[ -z "${CHIO_RECEIPT_DB:-}" ]]; then
    echo "[run-with-kb-mcp] FAIL: CHIODOME_DEMO_ASSERT_RECEIPTS=1 requires CHIO_RECEIPT_DB to be set" >&2
    exit 2
  fi
  if [[ ! -s "${CHIO_RECEIPT_DB}" ]]; then
    echo "[run-with-kb-mcp] FAIL: receipt DB ${CHIO_RECEIPT_DB} does not exist or is empty" >&2
    exit 2
  fi
  RECEIPT_LIST_OUT="$(mktemp)"
  trap 'rm -f "${RECEIPT_LIST_OUT}"' EXIT
  set +e
  # Each line of `chio receipt list` is one JSON receipt (JSON Lines).
  # An empty store returns zero lines; any non-empty result satisfies the
  # smoke gate.
  ${CHIO_CLI_BIN} --receipt-db "${CHIO_RECEIPT_DB}" receipt list --limit 1 \
      > "${RECEIPT_LIST_OUT}" 2>&1
  RC=$?
  set -e
  if [[ "${RC}" -ne 0 ]]; then
    echo "[run-with-kb-mcp] FAIL: chio receipt list rc=${RC}" >&2
    cat "${RECEIPT_LIST_OUT}" >&2 || true
    exit 2
  fi
  count=$(grep -c '^[[:space:]]*{' "${RECEIPT_LIST_OUT}" || true)
  if [[ "${count}" -lt 1 ]]; then
    echo "[run-with-kb-mcp] FAIL: no receipts in ${CHIO_RECEIPT_DB}" >&2
    exit 2
  fi
  echo "[run-with-kb-mcp] OK: ${count} receipt(s) returned by \`chio receipt list\` from ${CHIO_RECEIPT_DB}"
fi

echo "[run-with-kb-mcp] --full done (non-blocking; see CHIODOME_DEMO_ASSERT_RECEIPTS)"
