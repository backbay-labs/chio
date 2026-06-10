#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
source_dir="${repo_root}/crates/products/chio-cli/dashboard"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-dashboard-release.XXXXXX")"
dashboard_dir="${work_dir}/dashboard"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

if ! command -v npm >/dev/null 2>&1; then
  echo "dashboard release checks require npm on PATH" >&2
  exit 1
fi

cp -R "${source_dir}" "${dashboard_dir}"
rm -rf "${dashboard_dir}/node_modules" "${dashboard_dir}/dist"

(
  cd "${dashboard_dir}"
  npm ci
  npm test -- --run
  npm run build
)

test -f "${dashboard_dir}/dist/index.html"

echo "dashboard release qualification passed"
