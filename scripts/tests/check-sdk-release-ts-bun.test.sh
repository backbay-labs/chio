#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-sdk-release.sh"

grep -F 'pkg.requiresBun = /\bbun\b/.test(packageScriptText);' "$SCRIPT" >/dev/null
grep -F 'if [[ "${ts_requires_bun}" == "1" ]] && ! command -v bun >/dev/null 2>&1; then' "$SCRIPT" >/dev/null
grep -F 'declares a Bun-backed build or test script' "$SCRIPT" >/dev/null
grep -F 'read -r package_dir package_name has_build has_test requires_bun has_import has_require bin_names local_deps' "$SCRIPT" >/dev/null

echo "check-sdk-release-ts-bun.test.sh: Bun-backed TS scripts are preflighted"
