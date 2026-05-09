#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

registry="$(mktemp)"
observed="$(mktemp)"
trap 'rm -f "${registry}" "${observed}"' EXIT

cut -d'|' -f1 crates/chio-metrics-spec/metrics.snapshot | sort -u > "${registry}"

# Scope includes the edge crates that consume the registry plus
# `chio-wasm-guards`. The grep is anchored at `crates/<name>/src` to avoid
# pulling matches out of `target/` artifacts.
rg --no-filename -o 'chio_[a-z0-9_]*(seconds|total|depth|bytes|ready|size)' \
  crates/chio-metrics-spec \
  crates/chio-kernel/src \
  crates/chio-mcp-edge/src \
  crates/chio-acp-edge/src \
  crates/chio-a2a-edge/src \
  crates/chio-http-core/src \
  crates/chio-anchor/src \
  crates/chio-federation/src \
  crates/chio-wasm-guards/src \
  crates/chio-siem \
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
  echo "add new metric names to crates/chio-metrics-spec before using them" >&2
  exit 1
fi

echo "SRE metric registry gate passed"
