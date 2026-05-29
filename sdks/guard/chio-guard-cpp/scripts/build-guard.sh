#!/usr/bin/env bash
set -euo pipefail

package_root="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${CHIO_GUARD_CPP_BUILD_DIR:-${package_root}/build}"
generated_dir="${CHIO_GUARD_CPP_GENERATED_DIR:-${build_dir}/generated}"
language="${CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND:-c}"

usage() {
  cat <<EOF
Usage: $0 [--build-dir DIR] [--generated-dir DIR]

Builds the sample Chio C++ guard component with WASI SDK.

Required tools:
  WASI_SDK_PATH   path to a WASI SDK install
  wit-bindgen     on PATH

Optional:
  CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND=c|cpp

The sample component target currently builds against wit-bindgen c output.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      build_dir="$2"
      shift 2
      ;;
    --generated-dir)
      generated_dir="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${WASI_SDK_PATH:-}" ]]; then
  echo "set WASI_SDK_PATH to build C++ guard components" >&2
  exit 1
fi
if [[ ! -f "${WASI_SDK_PATH}/share/cmake/wasi-sdk.cmake" ]]; then
  echo "WASI_SDK_PATH does not contain share/cmake/wasi-sdk.cmake: ${WASI_SDK_PATH}" >&2
  exit 1
fi
if ! command -v wit-bindgen >/dev/null 2>&1; then
  echo "chio-guard-cpp component builds require wit-bindgen on PATH" >&2
  exit 1
fi
if [[ "${language}" != "c" ]]; then
  echo "sample component currently requires CHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND=c" >&2
  exit 2
fi

cmake -S "${package_root}" -B "${build_dir}" \
  -DCHIO_GUARD_CPP_GENERATE=ON \
  -DCHIO_GUARD_CPP_BUILD_EXAMPLES=ON \
  -DCHIO_GUARD_CPP_BUILD_TESTS=OFF \
  -DCHIO_GUARD_CPP_BUILD_WASI_COMPONENT=ON \
  -DCHIO_GUARD_CPP_GENERATED_DIR="${generated_dir}" \
  -DCHIO_GUARD_CPP_WIT_BINDGEN_SUBCOMMAND="${language}" \
  -DCMAKE_TOOLCHAIN_FILE="${WASI_SDK_PATH}/share/cmake/wasi-sdk.cmake"
cmake --build "${build_dir}" --target chio_guard_cpp_path_guard_component

echo "built sample guard component in ${build_dir}"
