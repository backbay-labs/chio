#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

source_file="crates/kernel/chio-kernel-core/src/formal_aeneas.rs"
work_dir="target/formal/aeneas-production"
llbc_dir="${work_dir}/llbc"
lean_dir="${work_dir}/lean"

if [[ ! -f "${source_file}" ]]; then
  echo "Aeneas production source missing: ${source_file}" >&2
  exit 1
fi

if ! command -v aeneas >/dev/null 2>&1; then
  echo "Aeneas production check requires aeneas on PATH" >&2
  exit 1
fi

if [[ -n "${CHIO_CHARON:-}" ]]; then
  charon_bin="${CHIO_CHARON}"
elif [[ -x "${HOME}/.cargo/bin/charon" ]]; then
  charon_bin="${HOME}/.cargo/bin/charon"
elif command -v charon >/dev/null 2>&1; then
  charon_bin="$(command -v charon)"
else
  echo "Aeneas production check requires charon on PATH" >&2
  exit 1
fi

rm -rf "${work_dir}"
mkdir -p "${llbc_dir}" "${lean_dir}"

echo "==> Charon extraction for production formal core"
"${charon_bin}" rustc --preset=aeneas --dest "${llbc_dir}" -- \
  --crate-type lib "${source_file}"

llbc_file="${llbc_dir}/formal_aeneas.llbc"
if [[ ! -f "${llbc_file}" ]]; then
  echo "Aeneas production check failed: Charon did not produce ${llbc_file}" >&2
  exit 1
fi

echo "==> Aeneas Lean extraction for production formal core"
aeneas -backend lean -split-files -namespace Chio.AeneasProduction \
  -dest "${lean_dir}" "${llbc_file}"

funs_file="${lean_dir}/Funs.lean"
types_file="${lean_dir}/Types.lean"
if [[ ! -f "${funs_file}" || ! -f "${types_file}" ]]; then
  echo "Aeneas production check failed: expected Lean output files are missing" >&2
  exit 1
fi

for symbol in \
  classify_time_window_code \
  time_window_valid \
  exact_or_wildcard_covers_by_flags \
  prefix_wildcard_or_exact_covers_by_flags \
  optional_u32_cap_is_subset \
  required_true_is_preserved \
  monetary_cap_is_subset_by_parts \
  budget_precheck \
  budget_commit \
  dpop_freshness_valid \
  dpop_admits \
  nonce_admits \
  guard_step_allows \
  revocation_snapshot_denies \
  receipt_fields_coupled
do
  if ! grep -q "def ${symbol}" "${funs_file}"; then
    echo "Aeneas production check failed: generated Lean is missing ${symbol}" >&2
    exit 1
  fi
done

for type_name in BudgetCommitResult; do
  if ! grep -q "${type_name}" "${types_file}"; then
    echo "Aeneas production check failed: generated Lean is missing ${type_name}" >&2
    exit 1
  fi
done

if [[ "${CHIO_SKIP_AENEAS_EQ:-0}" != "1" ]]; then
  ./scripts/check-aeneas-equivalence.sh
fi

echo "Aeneas production extraction and equivalence passed"
