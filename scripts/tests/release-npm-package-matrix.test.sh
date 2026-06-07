#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/release-npm.yml"

expected="$(mktemp)"
actual="$(mktemp)"
trap 'rm -f "$expected" "$actual"' EXIT

node - "$REPO_ROOT" >"$expected" <<'NODE'
const fs = require("fs");
const path = require("path");

const root = process.argv[2];
const workspaceRoot = path.join(root, "sdks/typescript");
const rootPackage = JSON.parse(
  fs.readFileSync(path.join(workspaceRoot, "package.json"), "utf8"),
);
for (const pattern of rootPackage.workspaces ?? []) {
  if (typeof pattern !== "string" || pattern.includes("*")) {
    throw new Error(`unsupported workspace pattern in release matrix test: ${pattern}`);
  }
  const packageDir = path.join(workspaceRoot, pattern);
  const manifestPath = path.join(packageDir, "package.json");
  if (!fs.existsSync(manifestPath)) continue;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.private === true || manifest.publishConfig == null) continue;
  console.log(path.relative(root, packageDir).replaceAll(path.sep, "/"));
}
NODE

awk '
  /all_packages=\(/ { in_list = 1; next }
  in_list && /\)/ { in_list = 0; next }
  in_list {
    gsub(/[ "]/, "", $0)
    if ($0 != "") print $0
  }
' "$WORKFLOW" >"$actual"

sort -u "$expected" -o "$expected"
sort -u "$actual" -o "$actual"

if ! diff -u "$expected" "$actual"; then
  echo "release-npm.yml all_packages must match non-private publishConfig TypeScript workspaces" >&2
  exit 1
fi

echo "release-npm-package-matrix.test.sh: npm package matrix covers publishable TS workspaces"
