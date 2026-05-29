#!/usr/bin/env bash
set -euo pipefail

package_root="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${CHIO_GUARD_CPP_NATIVE_BUILD_DIR:-${package_root}/build-native}"

cmake -S "${package_root}" -B "${build_dir}" \
  -DCHIO_GUARD_CPP_BUILD_EXAMPLES=ON \
  -DCHIO_GUARD_CPP_BUILD_TESTS=ON \
  -DCHIO_GUARD_CPP_GENERATE=OFF \
  -DCHIO_GUARD_CPP_BUILD_WASI_COMPONENT=OFF
cmake --build "${build_dir}" --target chio_guard_cpp_path_guard_smoke
ctest --test-dir "${build_dir}" --output-on-failure
