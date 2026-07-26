#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mode="write"
generated_dir="target/formal/aeneas-production/lean"
snapshot_dir="formal/lean4/Chio/FormalAeneas"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --check)
      mode="check"
      shift
      ;;
    --write)
      mode="write"
      shift
      ;;
    --generated-dir)
      generated_dir="${2:?missing value for --generated-dir}"
      shift 2
      ;;
    --snapshot-dir)
      snapshot_dir="${2:?missing value for --snapshot-dir}"
      shift 2
      ;;
    *)
      echo "usage: $0 [--check|--write] [--generated-dir DIR] [--snapshot-dir DIR]" >&2
      exit 2
      ;;
  esac
done
files=(Funs.lean Types.lean)

for file in "${files[@]}"; do
  if [[ ! -f "${generated_dir}/${file}" ]]; then
    echo "Aeneas snapshot source missing: ${generated_dir}/${file}" >&2
    exit 1
  fi
done

if [[ "${mode}" == "write" ]]; then
  mkdir -p "${snapshot_dir}"
  for file in "${files[@]}"; do
    cp "${generated_dir}/${file}" "${snapshot_dir}/${file}"
  done
  echo "Updated Aeneas Lean snapshots in ${snapshot_dir}"
  exit 0
fi

drift=0
for file in "${files[@]}"; do
  if [[ ! -f "${snapshot_dir}/${file}" ]] || \
    ! cmp -s "${generated_dir}/${file}" "${snapshot_dir}/${file}"; then
    echo "aeneas-equivalence: GENERATED SNAPSHOT DRIFT" >&2
    echo "  regenerated ${generated_dir}/${file} differs from" >&2
    echo "  committed ${snapshot_dir}/${file}" >&2
    drift=1
  fi
done

if [[ "${drift}" -ne 0 ]]; then
  echo "  Re-run: ./scripts/check-aeneas-production.sh" >&2
  echo "  then: ./scripts/snapshot-aeneas-generated.sh" >&2
  echo "  Commit the snapshot diff after reviewing the generated semantics." >&2
  exit 1
fi

echo "Aeneas Lean snapshots match regenerated output"
