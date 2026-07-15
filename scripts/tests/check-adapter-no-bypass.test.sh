#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
gate="${repo_root}/scripts/check-adapter-no-bypass.sh"

if [[ ! -x "$gate" ]]; then
  echo "adapter-no-bypass.gate-missing: scripts/check-adapter-no-bypass.sh" >&2
  exit 1
fi

if ! grep -Fq 'exec cargo xtask check adapter-no-bypass' "$gate"; then
  echo "adapter-no-bypass.wrapper-is-not-thin" >&2
  exit 1
fi

policy="${repo_root}/xtask/src/adapter_no_bypass.rs"
for marker in \
  "verify_swarm_authority_reference_from_store" \
  "routePlanReceiptSha256" \
  "consume_swarm_continuation" \
  "admit_capability_budget" \
  "compatibility-surface" \
  "CommandNew" \
  "DangerousKind::Spawn" \
  "DangerousKind::Invoke"; do
  if ! grep -Fq "$marker" "$policy"; then
    echo "adapter-no-bypass.structured-contract-missing: $marker" >&2
    exit 1
  fi
done

"$gate"

echo "check-adapter-no-bypass.test.sh: adapter no-bypass gate passed"
