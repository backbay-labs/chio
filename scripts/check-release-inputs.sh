#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

matches=()
while IFS= read -r path; do
  case "${path}" in
    */__pycache__/*|*.pyc|*.pyo|*.pyd|sdks/python/chio-py/build/*|sdks/python/chio-py/src/*.egg-info|sdks/python/chio-py/src/*.egg-info/*|sdks/typescript/chio-ts/dist/*|sdks/typescript/chio-ts/node_modules/*|crates/chio-cli/dashboard/dist/*|crates/chio-cli/dashboard/node_modules/*|tests/conformance/results/generated/*|tests/conformance/reports/generated/*)
      matches+=("${path}")
      ;;
  esac
done < <(git ls-files)

if ((${#matches[@]} > 0)); then
  echo "tracked generated or cache artifacts must not be part of release inputs:" >&2
  printf '  %s\n' "${matches[@]}" >&2
  exit 1
fi

if ! grep -qF "m08_internal_readiness_draft:" releases.toml; then
  echo "release-audit evidence must use the m08_internal_readiness_draft key" >&2
  exit 1
fi

if grep -qF "activation_evidence.m08_final_report" releases.toml; then
  echo "release-audit evidence still references the legacy m08_final_report key" >&2
  exit 1
fi

m09_package_path="compliance/hitrust/readiness-package/readiness-package.md"
m09_package_sha256="92d00cc1af96047c9116332f0f1467ce2a456fe9c31c64e9a667f6fa72a27cc6"
m09_evidence_files=(
  "${m09_package_path}"
  "docs/external-attestation/hitrust-i1/index.md"
)
m09_stale_claim_pattern='HITRUST-i1-CHIO|mycsf://|Certificate received|HITRUST QA round|Final report submitted|selected external assessor|Assessor identity|issued[[:space:]]+2026-05-02|HITRUST-QA'

if ! grep -qF "m09_hitrust_i1_readiness_package:" releases.toml; then
  echo "HITRUST readiness evidence must use the m09_hitrust_i1_readiness_package key" >&2
  exit 1
fi

if ! grep -qF "package_sha256: ${m09_package_sha256}" releases.toml; then
  echo "HITRUST readiness package hash is not pinned in releases.toml" >&2
  exit 1
fi

actual_m09_sha="$(shasum -a 256 "${m09_package_path}" | awk '{print $1}')"
if [[ "${actual_m09_sha}" != "${m09_package_sha256}" ]]; then
  echo "HITRUST readiness package hash mismatch: expected ${m09_package_sha256}, got ${actual_m09_sha}" >&2
  exit 1
fi

for path in "${m09_evidence_files[@]}"; do
  if [[ ! -f "${path}" ]]; then
    echo "missing HITRUST readiness evidence file: ${path}" >&2
    exit 1
  fi

  stale_matches="$(grep -inE "${m09_stale_claim_pattern}" "${path}" || true)"
  if [[ -n "${stale_matches}" ]]; then
    echo "HITRUST readiness evidence must remain readiness-only; stale issued-certificate wording found in ${path}:" >&2
    printf '%s\n' "${stale_matches}" >&2
    exit 1
  fi

  if ! grep -qiF "readiness" "${path}"; then
    echo "HITRUST readiness evidence must state readiness-only wording: ${path}" >&2
    exit 1
  fi
done

echo "release input inventory clean"
