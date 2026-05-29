#!/usr/bin/env bash
set -euo pipefail

package_root="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "${package_root}/../../.." && pwd)"
out_dir="${CHIO_GUARD_CPP_GENERATED_DIR:-${package_root}/generated}"
wit_file="${CHIO_GUARD_CPP_WIT:-${repo_root}/wit/chio-guard/world.wit}"
language="${CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND:-c}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      out_dir="$2"
      shift 2
      ;;
    --wit)
      wit_file="$2"
      shift 2
      ;;
    --language|--subcommand)
      language="$2"
      shift 2
      ;;
    --help|-h)
      cat <<EOF
Usage: $0 [--out-dir DIR] [--wit FILE] [--language c|cpp]

Generates Chio guard guest bindings from wit/chio-guard/world.wit.
The default language is "c" because wit-bindgen documents its C output as
C/C++ compatible and it produces guard.h, guard.c, and guard_component_type.o.
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if ! command -v wit-bindgen >/dev/null 2>&1; then
  echo "chio-guard-cpp generation requires wit-bindgen on PATH" >&2
  exit 1
fi

if [[ "${language}" != "c" && "${language}" != "cpp" ]]; then
  echo "CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND must be c or cpp" >&2
  exit 2
fi

mkdir -p "${out_dir}"
wit-bindgen "${language}" --world guard --out-dir "${out_dir}" "${wit_file}"

echo "generated Chio guard ${language} bindings in ${out_dir}"
