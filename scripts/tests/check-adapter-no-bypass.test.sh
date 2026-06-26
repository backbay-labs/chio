#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
gate="${repo_root}/scripts/check-adapter-no-bypass.sh"

if [[ ! -x "$gate" ]]; then
  echo "adapter-no-bypass.gate-missing: scripts/check-adapter-no-bypass.sh" >&2
  exit 1
fi

for marker in \
  "swarm_runtime_route_plan_contract" \
  "verify_swarm_authority_reference_from_store" \
  "routePlanReceiptSha256" \
  "consume_swarm_continuation" \
  "admit_capability_budget"; do
  if ! grep -Fq "$marker" "$gate"; then
    echo "adapter-no-bypass.swarm-route-plan-contract-missing: $marker" >&2
    exit 1
  fi
done

"$gate"

echo "check-adapter-no-bypass.test.sh: adapter no-bypass gate passed"
