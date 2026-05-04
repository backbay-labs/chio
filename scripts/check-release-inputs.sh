#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

matches=()
while IFS= read -r path; do
  case "${path}" in
    */__pycache__/*|*.pyc|*.pyo|*.pyd|packages/sdk/chio-py/build/*|packages/sdk/chio-py/src/*.egg-info|packages/sdk/chio-py/src/*.egg-info/*|packages/sdk/chio-ts/dist/*|packages/sdk/chio-ts/node_modules/*|crates/chio-cli/dashboard/dist/*|crates/chio-cli/dashboard/node_modules/*|tests/conformance/results/generated/*|tests/conformance/reports/generated/*)
      matches+=("${path}")
      ;;
  esac
done < <(git ls-files)

if ((${#matches[@]} > 0)); then
  echo "tracked generated or cache artifacts must not be part of release inputs:" >&2
  printf '  %s\n' "${matches[@]}" >&2
  exit 1
fi

m08_evidence_files=(
  ".planning/trajectory-3/audits/M08-vendor-evidence.md"
  "compliance/hitrust/evidence-bundles/2026-05-02/M08/audit/M08-vendor-evidence.md"
)
m08_stale_claim_pattern='m08_final_report|final[ -]report|public[ -]report|vendor public|vendor-hosted mirror|selected vendor|SOW signed|vendor sign-off|NCC reviewer accepted|Trail of Bits.+Reply received'

if ! grep -qF "m08_internal_readiness_draft:" releases.toml; then
  echo "M08 release-audit evidence must use m08_internal_readiness_draft" >&2
  exit 1
fi

if grep -qF "activation_evidence.m08_final_report" releases.toml; then
  echo "M08 release-audit evidence still references legacy m08_final_report" >&2
  exit 1
fi

for path in "${m08_evidence_files[@]}"; do
  if [[ ! -f "${path}" ]]; then
    echo "missing M08 evidence file: ${path}" >&2
    exit 1
  fi

  stale_matches="$(grep -inE "${m08_stale_claim_pattern}" "${path}" || true)"
  if [[ -n "${stale_matches}" ]]; then
    echo "M08 evidence must remain internal-readiness-only; stale external-review wording found in ${path}:" >&2
    printf '%s\n' "${stale_matches}" >&2
    exit 1
  fi

  if ! grep -qiF "internal readiness draft" "${path}"; then
    echo "M08 evidence must state internal readiness draft wording: ${path}" >&2
    exit 1
  fi

  if ! grep -qF "m08_internal_readiness_draft" "${path}"; then
    echo "M08 evidence must cite the reclassified release row: ${path}" >&2
    exit 1
  fi
done

echo "release input inventory clean"
