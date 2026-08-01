#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

usage() {
  cat >&2 <<'EOF'
usage: check-apalache-positive.sh (--invariant NAME | --temporal NAME) --length N --timeout-seconds N --config PATH [--no-deadlock] SPEC
EOF
}

mode=""
property=""
length=""
timeout_seconds=""
config=""
no_deadlock=0
spec=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --invariant)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      [[ -z "${mode}" ]] || { usage; exit 2; }
      mode="invariant"
      property="$2"
      shift 2
      ;;
    --temporal)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      [[ -z "${mode}" ]] || { usage; exit 2; }
      mode="temporal"
      property="$2"
      shift 2
      ;;
    --length)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      length="$2"
      shift 2
      ;;
    --timeout-seconds)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      timeout_seconds="$2"
      shift 2
      ;;
    --config)
      [[ "$#" -ge 2 ]] || { usage; exit 2; }
      config="$2"
      shift 2
      ;;
    --no-deadlock)
      no_deadlock=1
      shift
      ;;
    --*)
      usage
      exit 2
      ;;
    *)
      if [[ -n "${spec}" ]]; then
        usage
        exit 2
      fi
      spec="$1"
      shift
      ;;
  esac
done

if [[ -z "${mode}" || -z "${property}" || -z "${length}" ||
      -z "${timeout_seconds}" || -z "${config}" || -z "${spec}" ]]; then
  usage
  exit 2
fi
if [[ ! "${length}" =~ ^[0-9]+$ || ! "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]]; then
  echo "positive Apalache check: length must be non-negative and timeout must be positive" >&2
  exit 2
fi
if [[ ! -f "${config}" || ! -f "${spec}" ]]; then
  echo "positive Apalache check: config and specification must be files" >&2
  exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "positive Apalache check: timeout command is required" >&2
  exit 2
fi

apalache_bin="${APALACHE_BIN:-apalache-mc}"
if ! command -v "${apalache_bin}" >/dev/null 2>&1; then
  echo "positive Apalache check: executable not found: ${apalache_bin}" >&2
  exit 2
fi
apalache_bin="$(command -v "${apalache_bin}")"
version="$("${apalache_bin}" version 2>&1)"
if [[ "${version}" != "0.50.1" ]]; then
  echo "positive Apalache check: Apalache 0.50.1 is required" >&2
  exit 2
fi

if [[ -n "${CHIO_APALACHE_POSITIVE_OUTPUT_DIR:-}" ]]; then
  mkdir -p "${CHIO_APALACHE_POSITIVE_OUTPUT_DIR}"
  work_root="$(mktemp -d "${CHIO_APALACHE_POSITIVE_OUTPUT_DIR%/}/run.XXXXXX")"
  cleanup=0
else
  work_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-apalache-positive.XXXXXX")"
  cleanup=1
fi
if [[ "${cleanup}" -eq 1 ]]; then
  trap 'rm -rf "${work_root}"' EXIT
fi

out_dir="${work_root}/out"
run_dir="${work_root}/run"
log_file="${work_root}/apalache.log"
mkdir -p "${out_dir}" "${run_dir}"

check_args=()
if [[ "${no_deadlock}" -eq 1 ]]; then
  check_args+=(--no-deadlock)
fi
if [[ "${mode}" == "temporal" ]]; then
  check_args+=("--temporal=${property}")
fi

set +e
timeout "${timeout_seconds}" "${apalache_bin}" \
  --out-dir="${out_dir}" \
  --run-dir="${run_dir}" \
  check \
  "${check_args[@]}" \
  --length="${length}" \
  --config="${config}" \
  "${spec}" >"${log_file}" 2>&1
exit_code=$?
set -e

cat "${log_file}"
if ! python3 scripts/lib/apalache_evidence.py positive \
  "${log_file}" "${work_root}" "${mode}" "${property}" "${length}" "${exit_code}"
then
  echo "positive Apalache check: evidence validation failed" >&2
  exit 1
fi

echo "positive Apalache check: ${mode} ${property} passed at length ${length}"
