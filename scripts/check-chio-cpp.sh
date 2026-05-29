#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${CHIO_CPP_BUILD_DIR:-${repo_root}/target/chio-cpp}"
prefix_dir="${build_dir}/install"
consumer_dir="${build_dir}/consumer"
smoke_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-cpp-smoke.XXXXXX")"

cleanup() {
  rm -rf "${smoke_dir}"
}
trap cleanup EXIT

cd "${repo_root}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "chio-cpp checks require cargo on PATH" >&2
  exit 1
fi
if ! command -v cmake >/dev/null 2>&1; then
  echo "chio-cpp checks require cmake on PATH" >&2
  exit 1
fi
if ! command -v cc >/dev/null 2>&1; then
  echo "chio-cpp checks require a C compiler named cc on PATH" >&2
  exit 1
fi

compare_generated_header() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "chio-cpp generated-header checks require python3 on PATH" >&2
    exit 1
  fi
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import difflib
import sys

expected_path = Path(sys.argv[1])
actual_path = Path(sys.argv[2])
expected = expected_path.read_bytes().replace(b"\r\n", b"\n")
actual = actual_path.read_bytes().replace(b"\r\n", b"\n")
if expected == actual:
    raise SystemExit(0)

expected_text = expected.decode("utf-8").splitlines(keepends=True)
actual_text = actual.decode("utf-8").splitlines(keepends=True)
sys.stdout.writelines(
    difflib.unified_diff(
        expected_text,
        actual_text,
        fromfile=str(expected_path),
        tofile=str(actual_path),
    )
)
raise SystemExit(1)
PY
}

cargo test -p chio-bindings-ffi
cargo build -p chio-bindings-ffi

require_cbindgen="${CHIO_CPP_REQUIRE_CBINDGEN:-${CI:-}}"
if command -v cbindgen >/dev/null 2>&1; then
  generated_header="${smoke_dir}/chio_ffi.h"
  cbindgen crates/chio-bindings-ffi -o "${generated_header}"
  compare_generated_header crates/chio-bindings-ffi/include/chio/chio_ffi.h "${generated_header}"
elif [[ -n "${require_cbindgen}" && "${require_cbindgen}" != "0" ]]; then
  echo "cbindgen is required for chio_ffi.h freshness but is not on PATH" >&2
  exit 1
else
  echo "skipping chio_ffi.h freshness check because cbindgen is not on PATH"
fi

cat > "${smoke_dir}/smoke.c" <<'EOF'
#include <string.h>

#include "chio/chio_ffi.h"

int main(void) {
  ChioFfiResult result = chio_sha256_hex_utf8("hello");
  const char *expected =
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
  int ok = result.status == CHIO_FFI_STATUS_OK &&
           result.data.len == strlen(expected) &&
           memcmp(result.data.ptr, expected, result.data.len) == 0;
  chio_buffer_free(result.data);
  return ok ? 0 : 1;
}
EOF

ffi_lib="${repo_root}/target/debug/libchio_bindings_ffi.a"
extra_link=()
case "$(uname -s)" in
  Darwin)
    extra_link+=("-framework" "Security" "-framework" "CoreFoundation")
    ;;
  Linux)
    extra_link+=("-ldl" "-lpthread" "-lm")
    ;;
esac
cc -I "${repo_root}/crates/chio-bindings-ffi/include" \
  "${smoke_dir}/smoke.c" "${ffi_lib}" "${extra_link[@]}" \
  -o "${smoke_dir}/smoke"
"${smoke_dir}/smoke"

{
  nm -g "${ffi_lib}" 2>/dev/null || true
} |
  awk '$2 == "T" {print $3}' |
  sed 's/^_//' |
  grep -E '^chio_' |
  sort -u > "${smoke_dir}/actual.symbols" || true
grep -v '^#' tests/abi/chio-bindings-ffi.symbols |
  sed '/^[[:space:]]*$/d' |
  sort -u > "${smoke_dir}/expected.symbols"
diff -u "${smoke_dir}/expected.symbols" "${smoke_dir}/actual.symbols"

cmake -S sdks/cpp/chio-cpp -B "${build_dir}" \
  -DCHIO_CPP_BUILD_TESTS=ON \
  -DCHIO_CPP_BUILD_EXAMPLES=ON \
  -DCHIO_CPP_ENABLE_CURL=OFF
cmake --build "${build_dir}"
ctest --test-dir "${build_dir}" --output-on-failure

rm -rf "${prefix_dir}" "${consumer_dir}"
cmake --install "${build_dir}" --prefix "${prefix_dir}"
mkdir -p "${consumer_dir}"
cat > "${consumer_dir}/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(ChioCppConsumerSmoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(ChioCpp CONFIG REQUIRED)

add_executable(chio_cpp_consumer main.cpp)
target_link_libraries(chio_cpp_consumer PRIVATE ChioCpp::chio_cpp)
EOF

cat > "${consumer_dir}/main.cpp" <<'EOF'
#include "chio/chio.hpp"

#include <iostream>

int main() {
  auto hash = chio::invariants::sha256_hex_utf8("hello");
  if (!hash) {
    std::cerr << hash.error().message << "\n";
    return 1;
  }
  return hash.value() ==
                 "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
             ? 0
             : 1;
}
EOF

cmake -S "${consumer_dir}" -B "${consumer_dir}/build" \
  -DCMAKE_PREFIX_PATH="${prefix_dir}"
cmake --build "${consumer_dir}/build"
"${consumer_dir}/build/chio_cpp_consumer"

echo "chio-cpp checks passed"
