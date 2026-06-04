#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${CHIO_DROGON_BUILD_DIR:-${repo_root}/target/chio-drogon}"
example_build_dir="${CHIO_DROGON_EXAMPLE_BUILD_DIR:-${repo_root}/target/hello-drogon}"

cd "${repo_root}"

if ! command -v cmake >/dev/null 2>&1; then
  echo "chio-drogon checks require cmake on PATH" >&2
  exit 1
fi

cmake -S sdks/cpp/chio-drogon -B "${build_dir}" \
  -DCHIO_DROGON_BUILD_TESTS=ON

if [[ -f "${build_dir}/CMakeCache.txt" ]] &&
   cmake --build "${build_dir}" --target help 2>/dev/null | grep -q "chio_drogon"; then
  cmake --build "${build_dir}"
  ctest --test-dir "${build_dir}" --output-on-failure
else
  echo "chio-drogon package build skipped because Drogon or ChioCpp was unavailable"
fi

cmake -S examples/hello-drogon -B "${example_build_dir}"
if [[ -f "${example_build_dir}/hello-drogon.skip" ]]; then
  echo "hello-drogon example skipped: $(tr -d '\n' < "${example_build_dir}/hello-drogon.skip")"
else
  cmake --build "${example_build_dir}" --target hello_drogon
  cmake --build "${example_build_dir}" --target hello_drogon_contract_tests
  ctest --test-dir "${example_build_dir}" --output-on-failure
fi

bash -n examples/hello-drogon/run.sh examples/hello-drogon/smoke.sh
if [[ -f "${example_build_dir}/hello-drogon.skip" ]]; then
  ./examples/hello-drogon/run.sh
fi
./examples/hello-drogon/smoke.sh

echo "chio-drogon checks passed"
