#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
ARTIFACT_ROOT="$(mktemp -d)"
trap 'rm -rf "${ARTIFACT_ROOT}"' EXIT

# shellcheck source=/dev/null
source "${ROOT}/examples/_shared/hello-http-common.sh"

CHIO_BIN="$(ensure_chio_bin)"

# 1) Positive: CLI-hosted kernel with the sim adapter runs a governed MustPrepay
#    tool call and writes the signed tool-call receipt to the bundle.
"${CHIO_BIN}" mcp governed-sim \
  --payment-adapter sim \
  --governed-mustprepay \
  --out "${ARTIFACT_ROOT}/receipt.json"

# 2) Negative: same intent with the adapter disabled must be denied with no
#    execution receipt.
set +e
"${CHIO_BIN}" mcp governed-sim \
  --payment-adapter none \
  --governed-mustprepay \
  --out "${ARTIFACT_ROOT}/deny.json"
deny_rc=$?
set -e

python3 "${HERE}/assert_receipt.py" \
  --receipt "${ARTIFACT_ROOT}/receipt.json" \
  --deny-rc "${deny_rc}" \
  --deny-out "${ARTIFACT_ROOT}/deny.json"

echo "governed-x402-sim smoke: OK"
