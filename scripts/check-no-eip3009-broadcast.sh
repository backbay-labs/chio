#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

scanned=0
violations=0
while IFS= read -r file; do
  scanned=$((scanned + 1))
  # Allow the doc-comment mention; forbid an actual submit/broadcast in the off-chain lane.
  if grep -nE "eth_sendTransaction|\.send_transaction\(|broadcast_transfer_with_authorization" "${file}" \
       | grep -v "^[0-9]*:[[:space:]]*//" >/dev/null; then
    echo "VIOLATION: broadcast path in off-chain settle lane: ${file}"
    violations=$((violations + 1))
  fi
done < <(find "${ROOT}/crates/economy/chio-settle/src" -name 'payments.rs')

if [[ "${scanned}" -eq 0 ]]; then
  echo "FALSE-GREEN GUARD: scanned 0 files"; exit 1
fi
if [[ "${violations}" -ne 0 ]]; then
  echo "check-no-eip3009-broadcast: FAILED"; exit 1
fi
echo "check-no-eip3009-broadcast: OK (${scanned} files scanned)"
