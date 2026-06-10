#!/usr/bin/env bash
# shellcheck shell=bash
#
# test-harness.sh -- validate the Istio ext_authz reference integration.
#
# Assumes you have already:
#   1. Installed Istio 1.22+ with 01-meshconfig-patch.yaml applied.
#   2. Deployed the Chio sidecar via 00-chio-sidecar-deployment.yaml.
#   3. Applied 02-authorization-policy.yaml and 03-demo-workload.yaml.
#   4. Issued a demo capability token into $CHIO_DEMO_CAPABILITY_TOKEN.
#
# Two requests are sent through a `kubectl port-forward` against the demo
# Service. The first carries a capability token and must return HTTP 200
# with an `x-chio-receipt-id` header injected by the Chio adapter. The second
# omits all credentials and must come back as HTTP 403 from the DENY policy
# (no token -> Istio DENY action triggers before Chio ever runs, which is the
# fail-closed invariant).
#
# Exits 0 on success, non-zero with a human-readable diagnostic on failure.
set -euo pipefail

NAMESPACE="${NAMESPACE:-agent-tools}"
SERVICE="${SERVICE:-demo-tool}"
LOCAL_PORT="${LOCAL_PORT:-18080}"
REMOTE_PORT="${REMOTE_PORT:-80}"
KUBECTL="${KUBECTL:-kubectl}"
CURL="${CURL:-curl}"
CAPABILITY_TOKEN="${CHIO_DEMO_CAPABILITY_TOKEN:-demo-capability-token}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-${SCRIPT_DIR}/.artifacts/$(date -u +"%Y%m%dT%H%M%SZ")}"
mkdir -p "${ARTIFACT_DIR}"

log() {
  printf '[test-harness] %s\n' "$*" >&2
}

fail() {
  log "FAIL: $*"
  exit 1
}

require() {
  local name="$1"
  command -v "${name}" >/dev/null 2>&1 || fail "missing required command: ${name}"
}

require "${KUBECTL}"
require "${CURL}"

PF_PID=""
cleanup() {
  local code=$?
  if [[ -n "${PF_PID}" ]] && kill -0 "${PF_PID}" >/dev/null 2>&1; then
    kill "${PF_PID}" >/dev/null 2>&1 || true
    wait "${PF_PID}" >/dev/null 2>&1 || true
  fi
  exit "${code}"
}
trap cleanup EXIT

log "waiting for Service ${NAMESPACE}/${SERVICE} endpoints to be Ready..."
"${KUBECTL}" -n "${NAMESPACE}" wait \
  --for=condition=Available \
  --timeout=120s \
  "deployment/${SERVICE}"

log "starting port-forward: 127.0.0.1:${LOCAL_PORT} -> svc/${SERVICE}:${REMOTE_PORT}"
"${KUBECTL}" -n "${NAMESPACE}" port-forward \
  "svc/${SERVICE}" "${LOCAL_PORT}:${REMOTE_PORT}" \
  >"${ARTIFACT_DIR}/port-forward.log" 2>&1 &
PF_PID=$!

# Wait for the port-forward to accept connections. kubectl writes "Forwarding
# from" once the listener is up; poll the socket rather than grep the log so
# we do not race on stdout buffering.
log "waiting for port-forward readiness..."
for _ in $(seq 1 30); do
  if "${CURL}" -s -o /dev/null \
      --max-time 1 "http://127.0.0.1:${LOCAL_PORT}/healthz"; then
    break
  fi
  sleep 0.5
done

ALLOW_HEADERS="${ARTIFACT_DIR}/allow.headers"
ALLOW_BODY="${ARTIFACT_DIR}/allow.body"
DENY_HEADERS="${ARTIFACT_DIR}/deny.headers"
DENY_BODY="${ARTIFACT_DIR}/deny.body"

log "issuing allow request (capability token present)..."
ALLOW_STATUS="$(
  "${CURL}" -sS \
    -o "${ALLOW_BODY}" \
    -D "${ALLOW_HEADERS}" \
    -w '%{http_code}' \
    -H "x-chio-capability-token: ${CAPABILITY_TOKEN}" \
    -H "authorization: Bearer ${CAPABILITY_TOKEN}" \
    -X POST \
    --data '{"hello":"world"}' \
    "http://127.0.0.1:${LOCAL_PORT}/tools/hello"
)"

if [[ "${ALLOW_STATUS}" != "200" ]]; then
  log "allow response headers:"
  cat "${ALLOW_HEADERS}" >&2 || true
  fail "expected HTTP 200 on allow, got ${ALLOW_STATUS}"
fi

# Header names are case-insensitive per RFC 7230. Match loosely.
RECEIPT_ID="$(
  awk 'BEGIN{IGNORECASE=1} /^x-chio-receipt-id:/ { sub(/\r$/, ""); print $2; exit }' \
    "${ALLOW_HEADERS}"
)"

if [[ -z "${RECEIPT_ID}" ]]; then
  log "allow response headers:"
  cat "${ALLOW_HEADERS}" >&2 || true
  fail "allow response missing x-chio-receipt-id header"
fi

log "allow OK: status=200 receipt=${RECEIPT_ID}"

log "issuing deny request (no credentials)..."
DENY_STATUS="$(
  "${CURL}" -sS \
    -o "${DENY_BODY}" \
    -D "${DENY_HEADERS}" \
    -w '%{http_code}' \
    -X POST \
    --data '{"hello":"denied"}' \
    "http://127.0.0.1:${LOCAL_PORT}/tools/hello"
)"

if [[ "${DENY_STATUS}" != "403" ]]; then
  log "deny response headers:"
  cat "${DENY_HEADERS}" >&2 || true
  fail "expected HTTP 403 on deny, got ${DENY_STATUS}"
fi

log "deny OK: status=403"

cat <<SUMMARY
istio-ext-authz test-harness: PASS
  artifacts: ${ARTIFACT_DIR}
  allow receipt id: ${RECEIPT_ID}
  deny status:      ${DENY_STATUS}
SUMMARY
