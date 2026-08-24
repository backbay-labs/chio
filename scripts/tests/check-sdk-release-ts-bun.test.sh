#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-sdk-release.sh"

grep -F 'pkg.requiresBun = /\bbun\b/.test(packageScriptText);' "$SCRIPT" >/dev/null
grep -F 'pkg.requiresWasmToolchain = /\b(build:wasm|build-wasm\.sh|wasm-pack)\b/.test(packageScriptText);' "$SCRIPT" >/dev/null
grep -F 'if [[ "${ts_requires_bun}" == "1" ]] && ! command -v bun >/dev/null 2>&1; then' "$SCRIPT" >/dev/null
grep -F 'declares a Bun-backed build or test script' "$SCRIPT" >/dev/null
grep -F 'Chio TypeScript release checks require wasm-pack ${required_wasm_pack_version} on PATH because a package declares a wasm build script' "$SCRIPT" >/dev/null
grep -F 'Chio TypeScript release checks require wasm-bindgen-cli ${required_wasm_bindgen_version} on PATH because a package declares a wasm build script' "$SCRIPT" >/dev/null
grep -F 'read -r package_dir package_name has_build has_test requires_bun requires_wasm_toolchain has_import has_require bin_names local_deps' "$SCRIPT" >/dev/null
grep -F 'CHIO_REQUIRE_WASM_TOOLCHAIN="${requires_wasm_toolchain}" npm run build' "$SCRIPT" >/dev/null
grep -F 'packed_package_deps+=("${local_deps}")' "$SCRIPT" >/dev/null
grep -F 'append_packed_dependency_closure "${dep_name}"' "$SCRIPT" >/dev/null
grep -F 'TypeScript release smoke is missing packed local dependency ${requested_name}' "$SCRIPT" >/dev/null
grep -F 'append_packed_dependency_closure "${package_name}"' "$SCRIPT" >/dev/null

echo "check-sdk-release-ts-bun.test.sh: TS toolchains and packed dependency closure are preflighted"
