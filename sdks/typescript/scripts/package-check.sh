#!/usr/bin/env bash
# Local smoke-test for every Chio TypeScript SDK package.
#
# For each package listed below:
#   1. Run `npm run build`.
#   2. Require the built ./dist entry point in a child Node process.
#   3. Report pass/fail.
#
# Exits non-zero on the first failure and prints a summary. Mirrors the
# build legs of .github/workflows/release-npm.yml. The `conformance`
# workspace is intentionally excluded because it is marked
# `"private": true` in its package.json.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TS_ROOT="${REPO_ROOT}/sdks/typescript"

# chio-ts is the core SDK package. node-http stays ahead of packages that
# import it via file:../node-http.
PACKAGES=(
  "chio-ts"
  "packages/node-http"
  "packages/express"
  "packages/fastify"
  "packages/elysia"
  "packages/ai-sdk"
)

if ! command -v npm >/dev/null 2>&1; then
  echo "ERROR: npm is not installed." >&2
  exit 127
fi

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node is not installed." >&2
  exit 127
fi

echo "Installing workspace dependencies..."
if [[ -f "${TS_ROOT}/package-lock.json" ]]; then
  (cd "${TS_ROOT}" && npm ci --workspaces --include-workspace-root)
else
  (cd "${TS_ROOT}" && npm install --workspaces --include-workspace-root)
fi

passed=()
failed=()

for rel_path in "${PACKAGES[@]}"; do
  pkg_dir="${TS_ROOT}/${rel_path}"
  slug="$(basename "${rel_path}")"

  if [[ ! -f "${pkg_dir}/package.json" ]]; then
    echo "SKIP ${slug}: no package.json at ${pkg_dir}" >&2
    failed+=("${slug}: missing package.json")
    continue
  fi

  echo "=== ${slug} ==="

  if ! (cd "${pkg_dir}" && npm run build); then
    failed+=("${slug}: npm run build failed")
    continue
  fi

  if node -e "const pkg = require('${pkg_dir}/package.json'); process.exit(pkg.scripts?.lint ? 0 : 1)"; then
    if ! (cd "${pkg_dir}" && npm run lint); then
      failed+=("${slug}: npm run lint failed")
      continue
    fi
  fi

  # Smoke-require the built entry point. package.json "main" points at
  # ./dist/index.js and the build produces ESM -- use dynamic import.
  main_file=$(node -e "process.stdout.write(require('${pkg_dir}/package.json').main || './dist/index.js')")
  smoke_script="import('${pkg_dir}/${main_file}').then(m => { console.log('  imported', Object.keys(m).slice(0, 5)); }).catch(e => { console.error(e); process.exit(1); });"
  if node --input-type=module -e "${smoke_script}"; then
    passed+=("${slug}")
  else
    failed+=("${slug}: smoke import failed")
  fi
done

echo
echo "=== Summary ==="
echo "Passed: ${#passed[@]}"
for p in "${passed[@]}"; do
  echo "  OK  ${p}"
done
echo "Failed: ${#failed[@]}"
for f in "${failed[@]}"; do
  echo "  FAIL ${f}"
done

if [[ ${#failed[@]} -gt 0 ]]; then
  exit 1
fi
