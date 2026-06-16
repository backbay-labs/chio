#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

registry="$(mktemp)"
observed="$(mktemp)"
observed_raw="$(mktemp)"
trap 'rm -f "${registry}" "${observed}" "${observed_raw}"' EXIT

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required for the SRE metric registry gate" >&2
  exit 2
fi

cut -d'|' -f1 crates/observability/chio-metrics-spec/metrics.snapshot | sort -u > "${registry}"

# Scope includes the edge crates that consume the registry plus
# `chio-wasm-guards`. The grep is anchored at `crates/<name>/src` to avoid
# pulling matches out of `target/` artifacts.
rg_status=0
rg -P --no-filename -o '(?<![A-Za-z0-9_])chio_[a-z0-9_]*(seconds|total|depth|bytes|ready|size)(?![A-Za-z0-9_])' \
  crates/observability/chio-metrics-spec \
  crates/kernel/chio-kernel/src \
  crates/protocol/chio-mcp-edge/src \
  crates/protocol/chio-acp-edge/src \
  crates/protocol/chio-a2a-edge/src \
  crates/platform/chio-http-core/src \
  crates/economy/chio-anchor/src \
  crates/trust/chio-federation/src \
  crates/trust/chio-pheromone-relay/src \
  crates/guards/chio-wasm-guards/src \
  crates/observability/chio-siem \
  deploy/prometheus \
  .github/workflows \
  scripts \
  docs/operator-runbook \
  > "${observed_raw}" || rg_status=$?

if [[ "${rg_status}" -eq 0 ]]; then
  sort -u < "${observed_raw}" > "${observed}"
elif [[ "${rg_status}" -eq 1 ]]; then
  : > "${observed}"
else
  echo "failed to scan Chio metric names with rg (exit ${rg_status})" >&2
  exit "${rg_status}"
fi

failed=0
while IFS= read -r metric; do
  if [[ -z "${metric}" ]]; then
    continue
  fi
  if ! grep -Fxq "${metric}" "${registry}"; then
    echo "unregistered Chio metric name: ${metric}" >&2
    failed=1
  fi
done < "${observed}"

if [[ "${failed}" -ne 0 ]]; then
  echo "add new metric names to crates/observability/chio-metrics-spec before using them" >&2
  exit 1
fi

echo "SRE metric registry gate passed"
