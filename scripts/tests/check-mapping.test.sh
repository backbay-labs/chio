#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

fixture_root="${TMP_DIR}/fixture"
mkdir -p \
  "${fixture_root}/.dst" \
  "${fixture_root}/.loom" \
  "${fixture_root}/scripts" \
  "${fixture_root}/formal/tla" \
  "${fixture_root}/formal/apalache" \
  "${fixture_root}/crates/kernel/chio-kernel-core/src"
cp "${REPO_ROOT}/scripts/check-mapping.sh" "${fixture_root}/scripts/check-mapping.sh"
if [[ "$(grep -Ec 'LC_ALL=C comm -(13|23)' "${fixture_root}/scripts/check-mapping.sh")" -ne 4 ]]; then
  echo "check-mapping must run all sorted-set comparisons under the C locale" >&2
  exit 1
fi

printf '%s\n' \
  '| Property | Model |' \
  '|----------|-------|' \
  "| \`RevocationStateCoupled\` | \`formal/tla/RevocationPropagation.tla\` |" \
  "| \`AllowReceiptsBudgetChecked\` | \`formal/apalache/ReceiptBeforeAllow.tla\` |" \
  "| \`DirectParentInClosure\` | \`formal/apalache/RevocationCutCompleteness.tla\` |" \
  '' \
  '## Loom interleaving harnesses' \
  '' \
  '| Property | Source |' \
  '|----------|--------|' \
  '| `loom_fixture` | fixture |' \
  '' \
  '## Deterministic simulation harnesses' \
  '' \
  '| Property | Source |' \
  '|----------|--------|' \
  '| `dst_fixture` | fixture |' \
  > "${fixture_root}/formal/MAPPING.md"

printf '%s\n' \
  '---- MODULE RevocationPropagation ----' \
  'RevocationStateCoupled ==' \
  '    TRUE' \
  'SafetyInv ==' \
  '    /\ RevocationStateCoupled' \
  '=======================================' \
  > "${fixture_root}/formal/tla/RevocationPropagation.tla"

printf '%s\n' \
  '---- MODULE DistributedRevocation ----' \
  '=======================================' \
  > "${fixture_root}/formal/tla/DistributedRevocation.tla"

printf '%s\n' \
  '---- MODULE DistributedRevocationTemporal ----' \
  '===============================================' \
  > "${fixture_root}/formal/tla/DistributedRevocationTemporal.tla"

printf '%s\n' \
  '---- MODULE ReceiptBeforeAllow ----' \
  'AllowReceiptsBudgetChecked ==' \
  '    TRUE' \
  'SafetyInv ==' \
  '    /\ AllowReceiptsBudgetChecked' \
  '====================================' \
  > "${fixture_root}/formal/apalache/ReceiptBeforeAllow.tla"

printf '%s\n' \
  '---- MODULE RevocationCutCompleteness ----' \
  'DirectParentInClosure ==' \
  '    TRUE' \
  'SafetyInv ==' \
  '    /\ DirectParentInClosure' \
  '===========================================' \
  > "${fixture_root}/formal/apalache/RevocationCutCompleteness.tla"

printf '%s\n' \
  '---- MODULE PostAdmissionDropGuard ----' \
  '========================================' \
  > "${fixture_root}/formal/apalache/PostAdmissionDropGuard.tla"
printf '%s\n' '// No Kani harnesses in this fixture.' \
  > "${fixture_root}/crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs"
printf '%s\n' '# fixture manifest' > "${fixture_root}/.loom/harnesses.toml"
printf '%s\n' '# fixture manifest' > "${fixture_root}/.dst/harnesses.toml"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf '\''%s\n'\'' '\''fixture::loom_fixture'\''' \
  > "${fixture_root}/scripts/run-loom-manifest.sh"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf '\''%s\n'\'' '\''fixture::dst_fixture'\''' \
  > "${fixture_root}/scripts/run-dst.sh"

run_gate() {
  local root="$1"
  (
    cd "${root}"
    bash scripts/check-mapping.sh
  ) 2>&1
}

expect_failure() {
  local root="$1"
  local expected="$2"
  local output
  if output="$(run_gate "${root}")"; then
    echo "expected mapping gate failure containing: ${expected}" >&2
    exit 1
  fi
  if ! grep -qF "${expected}" <<< "${output}"; then
    echo "mapping gate failure did not contain: ${expected}" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

remove_exact_line() {
  local path="$1"
  local line="$2"
  grep -vF -x -e "${line}" "${path}" > "${path}.tmp" || true
  mv "${path}.tmp" "${path}"
}

run_gate "${fixture_root}" >/dev/null

model_files=(
  'formal/tla/RevocationPropagation.tla'
  'formal/apalache/ReceiptBeforeAllow.tla'
  'formal/apalache/RevocationCutCompleteness.tla'
)
invariant_names=(
  'RevocationStateCoupled'
  'AllowReceiptsBudgetChecked'
  'DirectParentInClosure'
)

for index in "${!invariant_names[@]}"; do
  name="${invariant_names[${index}]}"
  relative_model="${model_files[${index}]}"

  missing_definition="${TMP_DIR}/missing-definition-${index}"
  cp -R "${fixture_root}" "${missing_definition}"
  remove_exact_line "${missing_definition}/${relative_model}" "${name} =="
  expect_failure "${missing_definition}" "required model invariant definition(s) missing"

  missing_conjunct="${TMP_DIR}/missing-conjunct-${index}"
  cp -R "${fixture_root}" "${missing_conjunct}"
  remove_exact_line "${missing_conjunct}/${relative_model}" "    /\ ${name}"
  expect_failure "${missing_conjunct}" "required invariant(s) missing from SafetyInv"

  missing_mapping="${TMP_DIR}/missing-mapping-${index}"
  cp -R "${fixture_root}" "${missing_mapping}"
  grep -vF -e "\`${name}\`" "${missing_mapping}/formal/MAPPING.md" \
    > "${missing_mapping}/formal/MAPPING.md.tmp"
  mv "${missing_mapping}/formal/MAPPING.md.tmp" \
    "${missing_mapping}/formal/MAPPING.md"
  expect_failure "${missing_mapping}" "required model invariant(s) not cited"
done

echo "check-mapping regression tests: PASS"
