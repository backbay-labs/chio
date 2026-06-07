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

grep -F 'pkg.scripts?.lint ? 0 : 1' "$WORKFLOW" >/dev/null
grep -F 'package has no lint script; skipping' "$WORKFLOW" >/dev/null
grep -F 'pkg.scripts?.test ? 0 : 1' "$WORKFLOW" >/dev/null
grep -F 'package has no test script; skipping' "$WORKFLOW" >/dev/null
grep -F 'Detect wasm-backed package' "$WORKFLOW" >/dev/null
grep -F 'cargo install wasm-pack --version "$(cat .tooling/wasm-pack.version)" --locked' "$WORKFLOW" >/dev/null
grep -F 'CHIO_REQUIRE_WASM_TOOLCHAIN: "1"' "$WORKFLOW" >/dev/null
grep -F 'using local same-release ${block}.${name}' "$WORKFLOW" >/dev/null
grep -F 'SAME_RELEASE_MARKER' "$WORKFLOW" >/dev/null
grep -F 'npm install -g npm@^11.5.1' "$WORKFLOW" >/dev/null
grep -F 'node trusted publishing runtime must be >= 22.14.0' "$WORKFLOW" >/dev/null
grep -F 'npm trusted publishing CLI must be >= 11.5.1' "$WORKFLOW" >/dev/null
grep -F 'ERROR: wasm-pack ${WASM_PACK_VERSION} is required for CI and release wasm builds.' "$REPO_ROOT/sdks/typescript/scripts/build-wasm.sh" >/dev/null

node - "$REPO_ROOT" <<'NODE'
const fs = require("fs");
const path = require("path");

const root = process.argv[2];
const workspaceRoot = path.join(root, "sdks/typescript");
const packageDirs = [
  path.join(workspaceRoot, "chio-ts"),
  ...fs
    .readdirSync(path.join(workspaceRoot, "packages"))
    .map((entry) => path.join(workspaceRoot, "packages", entry)),
];
for (const packageDir of packageDirs) {
  const manifestPath = path.join(packageDir, "package.json");
  if (!fs.existsSync(manifestPath)) continue;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.private === true || manifest.publishConfig == null) continue;
  const scripts = Object.values(manifest.scripts ?? {}).join("\n");
  if (!/\btsc\b/.test(scripts)) continue;
  if (manifest.devDependencies?.typescript == null) {
    throw new Error(`${path.relative(root, packageDir)} invokes tsc but does not declare devDependencies.typescript`);
  }
}
NODE

echo "release-npm-package-matrix.test.sh: npm package matrix covers publishable TS workspaces"
