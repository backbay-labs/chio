#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

registry="$(mktemp)"
observed="$(mktemp)"
observed_raw="$(mktemp)"
trap 'rm -f "${registry}" "${observed}" "${observed_raw}"' EXIT

cut -d'|' -f1 crates/observability/chio-metrics-spec/metrics.snapshot | sort -u > "${registry}"

# Scope includes the edge crates that consume the registry plus
# `chio-wasm-guards`. The grep is anchored at `crates/<name>/src` to avoid
# pulling matches out of `target/` artifacts.
scan_paths=(
  crates/observability/chio-metrics-spec
  crates/kernel/chio-kernel/src
  crates/protocol/chio-mcp-edge/src
  crates/protocol/chio-acp-edge/src
  crates/protocol/chio-a2a-edge/src
  crates/platform/chio-http-core/src
  crates/economy/chio-anchor/src
  crates/trust/chio-federation/src
  crates/trust/chio-pheromone-relay/src
  crates/guards/chio-wasm-guards/src
  crates/observability/chio-siem
  deploy/prometheus
  .github/workflows
  scripts
  docs/operator-runbook
)

scan_status=0
if command -v rg >/dev/null 2>&1; then
  rg -P --no-filename -o '(?<![A-Za-z0-9_])chio_[a-z0-9_]*(seconds|total|depth|bytes|ready|size)(?![A-Za-z0-9_])' \
    "${scan_paths[@]}" \
    > "${observed_raw}" || scan_status=$?
else
  git grep -h -E '(^|[^A-Za-z0-9_])chio_[a-z0-9_]*(seconds|total|depth|bytes|ready|size)([^A-Za-z0-9_]|$)' \
    -- "${scan_paths[@]}" \
    | python3 -c 'import re, sys
pattern = re.compile(r"(?<![A-Za-z0-9_])chio_[a-z0-9_]*(?:seconds|total|depth|bytes|ready|size)(?![A-Za-z0-9_])")
for line in sys.stdin:
    for match in pattern.finditer(line):
        print(match.group(0))' \
    > "${observed_raw}" || scan_status=$?
fi

if [[ "${scan_status}" -eq 0 ]]; then
  sort -u < "${observed_raw}" > "${observed}"
elif [[ "${scan_status}" -eq 1 ]]; then
  : > "${observed}"
else
  echo "failed to scan Chio metric names (exit ${scan_status})" >&2
  exit "${scan_status}"
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
