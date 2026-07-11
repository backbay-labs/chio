#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

temporary_dir="$(mktemp -d)"
trap 'rm -rf "${temporary_dir}"' EXIT

generated_dir="${temporary_dir}/generated"
snapshot_dir="${temporary_dir}/snapshot"
mkdir -p "${generated_dir}" "${snapshot_dir}"

printf '%s\n' 'def generatedValue := true' >"${generated_dir}/Funs.lean"
printf '%s\n' 'structure GeneratedType' >"${generated_dir}/Types.lean"

./scripts/snapshot-aeneas-generated.sh --write \
  --generated-dir "${generated_dir}" --snapshot-dir "${snapshot_dir}"

./scripts/snapshot-aeneas-generated.sh --check \
  --generated-dir "${generated_dir}" --snapshot-dir "${snapshot_dir}"

printf '%s\n' 'def generatedValue := false' >"${generated_dir}/Funs.lean"
if ./scripts/snapshot-aeneas-generated.sh --check \
  --generated-dir "${generated_dir}" --snapshot-dir "${snapshot_dir}" \
  >"${temporary_dir}/stdout" 2>"${temporary_dir}/stderr"; then
  echo "snapshot drift check accepted changed generated code" >&2
  exit 1
fi

grep -Fq "GENERATED SNAPSHOT DRIFT" "${temporary_dir}/stderr"

./scripts/snapshot-aeneas-generated.sh --write \
  --generated-dir "${generated_dir}" --snapshot-dir "${snapshot_dir}"

./scripts/snapshot-aeneas-generated.sh --check \
  --generated-dir "${generated_dir}" --snapshot-dir "${snapshot_dir}"

echo "Aeneas snapshot drift tests passed"
