#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/release-qualification/mobile-kernel/ios"
SWIFT_OUT="${OUT_DIR}/swift"
FRAMEWORK_OUT="${OUT_DIR}/ChioKernel.xcframework"
UDL="${ROOT}/crates/chio-kernel-mobile/src/chio_kernel_mobile.udl"

if [[ "${1:-}" == "--test-only" ]]; then
  bash -n "$0"
  test -f "${ROOT}/sdks/swift/Package.swift"
  test -f "${ROOT}/sdks/swift/Sources/Chio/AppAttest.swift"
  test -f "${ROOT}/sdks/swift/Tests/ChioTests/AppAttestTests.swift"
  grep -q "DCAppAttestService" "${ROOT}/sdks/swift/Sources/Chio/AppAttest.swift"
  grep -q "generateAssertion" "${ROOT}/sdks/swift/Sources/Chio/AppAttest.swift"
  grep -q "binaryTarget" "${ROOT}/sdks/swift/Package.swift"
  mkdir -p "${OUT_DIR}"
  cat > "${OUT_DIR}/test-only-summary.json" <<JSON
{"lane":"ios_framework","status":"pass","mode":"test-only"}
JSON
  exit 0
fi

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required tool missing: $1" >&2
    exit 1
  fi
}

require_tool cargo
require_tool lipo
require_tool xcodebuild

run_uniffi_bindgen() {
  if command -v uniffi-bindgen >/dev/null 2>&1; then
    uniffi-bindgen "$@"
    return
  fi

  local shim_dir="${TARGET_DIR}/uniffi-bindgen-shim"
  mkdir -p "${shim_dir}/src"
  cat > "${shim_dir}/Cargo.toml" <<'TOML'
[package]
name = "chio-mobile-uniffi-bindgen-shim"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
uniffi = { version = "0.28", features = ["cli"] }

[workspace]
TOML
  cat > "${shim_dir}/src/main.rs" <<'RS'
fn main() {
    uniffi::uniffi_bindgen_main();
}
RS

  cargo run --manifest-path "${shim_dir}/Cargo.toml" -- "$@"
}

mkdir -p "${OUT_DIR}" "${SWIFT_OUT}"

TARGET_DIR="${ROOT}/target/wave3k-mobile-ios"
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --release --target aarch64-apple-ios -p chio-kernel-mobile
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --release --target aarch64-apple-ios-sim -p chio-kernel-mobile
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --release --target x86_64-apple-ios -p chio-kernel-mobile

run_uniffi_bindgen generate --language swift --out-dir "${SWIFT_OUT}" "${UDL}"

SIM_UNIVERSAL="${TARGET_DIR}/ios-sim-universal/release"
mkdir -p "${SIM_UNIVERSAL}"
lipo -create \
  "${TARGET_DIR}/aarch64-apple-ios-sim/release/libchio_kernel_mobile.a" \
  "${TARGET_DIR}/x86_64-apple-ios/release/libchio_kernel_mobile.a" \
  -output "${SIM_UNIVERSAL}/libchio_kernel_mobile.a"

rm -rf "${FRAMEWORK_OUT}"
xcodebuild -create-xcframework \
  -library "${TARGET_DIR}/aarch64-apple-ios/release/libchio_kernel_mobile.a" \
  -headers "${SWIFT_OUT}" \
  -library "${SIM_UNIVERSAL}/libchio_kernel_mobile.a" \
  -headers "${SWIFT_OUT}" \
  -output "${FRAMEWORK_OUT}"
