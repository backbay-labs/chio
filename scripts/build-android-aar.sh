#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="${ROOT}/sdks/jvm/chio-kernel-mobile"
KOTLIN_OUT="${MODULE}/src/main/kotlin"
JNI_OUT="${MODULE}/src/main/jniLibs"
UDL="${ROOT}/crates/chio-kernel-mobile/src/chio_kernel_mobile.udl"

if [[ "${1:-}" == "--test-only" ]]; then
  bash -n "$0"
  test -f "${MODULE}/build.gradle.kts"
  test -f "${MODULE}/src/main/kotlin/dev/chio/kernel/PlayIntegrity.kt"
  test -f "${MODULE}/src/androidTest/kotlin/dev/chio/kernel/PlayIntegrityInstrumentedTest.kt"
  grep -q "IntegrityManager" "${MODULE}/src/main/kotlin/dev/chio/kernel/PlayIntegrity.kt"
  grep -q "setIsStrongBoxBacked" "${MODULE}/src/main/kotlin/dev/chio/kernel/Keystore.kt"
  mkdir -p "${MODULE}/build/outputs/aar"
  cat > "${MODULE}/build/outputs/aar/test-only-summary.json" <<JSON
{"lane":"android_aar","status":"pass","mode":"test-only"}
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
require_tool cargo-ndk
require_tool uniffi-bindgen

GRADLEW="${ROOT}/sdks/jvm/gradlew"
if [[ ! -x "${GRADLEW}" ]]; then
  echo "required tool missing: ${GRADLEW}" >&2
  exit 1
fi

mkdir -p "${JNI_OUT}"

cargo ndk \
  --target arm64-v8a \
  --target armeabi-v7a \
  --target x86_64 \
  --target x86 \
  -o "${JNI_OUT}" \
  build --release -p chio-kernel-mobile

uniffi-bindgen generate --language kotlin --out-dir "${KOTLIN_OUT}" "${UDL}"

(
  cd "${MODULE}"
  "${GRADLEW}" assembleRelease
)
