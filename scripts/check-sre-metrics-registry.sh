#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

registry="$(mktemp)"
observed="$(mktemp)"
trap 'rm -f "${registry}" "${observed}"' EXIT

cut -d'|' -f1 crates/observability/chio-metrics-spec/metrics.snapshot | sort -u > "${registry}"

# Scope includes the edge crates that consume the registry plus
# `chio-wasm-guards`. The grep is anchored at `crates/<name>/src` to avoid
# pulling matches out of `target/` artifacts.
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
  | sort -u > "${observed}" || true

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
