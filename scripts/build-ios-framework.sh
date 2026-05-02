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
require_tool uniffi-bindgen
require_tool xcodebuild

mkdir -p "${OUT_DIR}" "${SWIFT_OUT}"

TARGET_DIR="${ROOT}/target/wave3k-mobile-ios"
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --release --target aarch64-apple-ios -p chio-kernel-mobile
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --release --target aarch64-apple-ios-sim -p chio-kernel-mobile
CARGO_TARGET_DIR="${TARGET_DIR}" cargo build --release --target x86_64-apple-ios -p chio-kernel-mobile

uniffi-bindgen generate --language swift --out-dir "${SWIFT_OUT}" "${UDL}"

rm -rf "${FRAMEWORK_OUT}"
xcodebuild -create-xcframework \
  -library "${TARGET_DIR}/aarch64-apple-ios/release/libchio_kernel_mobile.a" \
  -headers "${SWIFT_OUT}" \
  -library "${TARGET_DIR}/aarch64-apple-ios-sim/release/libchio_kernel_mobile.a" \
  -headers "${SWIFT_OUT}" \
  -library "${TARGET_DIR}/x86_64-apple-ios/release/libchio_kernel_mobile.a" \
  -headers "${SWIFT_OUT}" \
  -output "${FRAMEWORK_OUT}"
