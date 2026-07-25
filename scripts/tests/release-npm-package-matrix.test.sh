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
  if (typeof manifest.scripts?.build !== "string" || manifest.scripts.build.trim() === "") {
    throw new Error(`${path.relative(root, packageDir)} is publishable but has no build script`);
  }
  const runtimeEntries = [
    manifest.main,
    manifest.module,
    manifest.exports?.["."]?.import,
    manifest.exports?.["."]?.require,
    manifest.exports?.["."]?.default,
  ].filter((entry) => typeof entry === "string");
  for (const entry of runtimeEntries) {
    if (/\.(?:[cm]?ts|tsx)$/.test(entry)) {
      throw new Error(`${path.relative(root, packageDir)} publishes TypeScript runtime entry ${entry}`);
    }
  }
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

duplicates="$(sort "$actual" | uniq -d)"
if [[ -n "$duplicates" ]]; then
  echo "release-npm.yml all_packages contains duplicate entries:" >&2
  echo "$duplicates" >&2
  exit 1
fi

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
grep -F 'const wasmScriptPattern = /\bbuild:wasm\b|build-wasm\.sh/;' "$WORKFLOW" >/dev/null
grep -F 'if (visit(localDir)) return true;' "$WORKFLOW" >/dev/null
grep -F 'cargo install wasm-pack --version "$(cat .tooling/wasm-pack.version)" --locked' "$WORKFLOW" >/dev/null
grep -F 'CHIO_REQUIRE_WASM_TOOLCHAIN: "1"' "$WORKFLOW" >/dev/null
grep -F 'using local same-release ${block}.${name}' "$WORKFLOW" >/dev/null
grep -F 'visit(localDir);' "$WORKFLOW" >/dev/null
grep -F 'SAME_RELEASE_MARKER' "$WORKFLOW" >/dev/null
grep -F 'npm install -g npm@^11.5.1' "$WORKFLOW" >/dev/null
grep -F 'node trusted publishing runtime must be >= 22.14.0' "$WORKFLOW" >/dev/null
grep -F 'npm trusted publishing CLI must be >= 11.5.1' "$WORKFLOW" >/dev/null
grep -F 'Smoke install packed tarball' "$WORKFLOW" >/dev/null
grep -F 'npm install --ignore-scripts --no-fund --no-audit "${install_args[@]}"' "$WORKFLOW" >/dev/null
grep -F 'ESM import smoke verified ${packageName}' "$WORKFLOW" >/dev/null
grep -F 'CommonJS require smoke verified ${packageName}' "$WORKFLOW" >/dev/null
grep -F 'CLI smoke verified ${binName}' "$WORKFLOW" >/dev/null
grep -F '@chio-protocol/workers' "$WORKFLOW" >/dev/null
grep -F 'dist/bundler/chio_kernel_browser_bg.wasm' "$WORKFLOW" >/dev/null
grep -F 'CHIO_WORKERS_PACKAGE_JSON="${consumer_dir}/node_modules/@chio-protocol/workers/package.json"' "$WORKFLOW" >/dev/null
grep -F 'import { Miniflare } from "miniflare";' "$WORKFLOW" >/dev/null
grep -F '/__chio_workers_smoke' "$WORKFLOW" >/dev/null
grep -F 'Workers Miniflare smoke verified @chio-protocol/workers' "$WORKFLOW" >/dev/null
grep -F 'npm pack --pack-destination "$local_dep_pack_dir" --silent' "$WORKFLOW" >/dev/null
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
const localByName = new Map();
const publishable = [];
const wasmScriptPattern = /\bbuild:wasm\b|build-wasm\.sh/;

for (const packageDir of packageDirs) {
  const manifestPath = path.join(packageDir, "package.json");
  if (!fs.existsSync(manifestPath)) continue;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  localByName.set(manifest.name, packageDir);
  if (manifest.private !== true && manifest.publishConfig != null) {
    publishable.push(packageDir);
  }
}

function needsWasm(packageDir, seen = new Set()) {
  const resolved = path.resolve(packageDir);
  if (seen.has(resolved)) return false;
  seen.add(resolved);
  const manifest = JSON.parse(
    fs.readFileSync(path.join(resolved, "package.json"), "utf8"),
  );
  if (wasmScriptPattern.test(Object.values(manifest.scripts ?? {}).join("\n"))) {
    return true;
  }
  for (const block of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    for (const name of Object.keys(manifest[block] ?? {})) {
      if (!name.startsWith("@chio-protocol/")) continue;
      const localDir = localByName.get(name);
      if (localDir && path.resolve(localDir) !== resolved && needsWasm(localDir, seen)) {
        return true;
      }
    }
  }
  return false;
}

const wasmRequired = publishable
  .filter((packageDir) => needsWasm(packageDir))
  .map((packageDir) => path.relative(root, packageDir).replaceAll(path.sep, "/"))
  .sort();
for (const expected of [
  "sdks/typescript/packages/chio-ai-sdk-middleware",
  "sdks/typescript/packages/mobile",
  "sdks/typescript/packages/passkey",
]) {
  if (!wasmRequired.includes(expected)) {
    throw new Error(`release-npm wasm detection must include local wasm dependency closure for ${expected}`);
  }
}
NODE

node - "$REPO_ROOT" <<'NODE'
const fs = require("fs");
const path = require("path");

const root = process.argv[2];
const privatePackages = [];
for (const entry of fs.readdirSync(path.join(root, "sdks/typescript/packages"))) {
  const manifestPath = path.join(root, "sdks/typescript/packages", entry, "package.json");
  if (!fs.existsSync(manifestPath)) continue;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.private === true) privatePackages.push(manifest.name);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

for (const doc of fs.readdirSync(path.join(root, "docs/sdk"))) {
  if (!doc.endsWith(".md")) continue;
  const docPath = path.join(root, "docs/sdk", doc);
  const lines = fs.readFileSync(docPath, "utf8").split(/\r?\n/);
  for (const packageName of privatePackages) {
    const escaped = escapeRegex(packageName);
    const publicUse = new RegExp(
      `(?:npm\\s+install\\s+${escaped}|from\\s+["']${escaped}["']|require\\(\\s*["']${escaped}["']|import\\s+["']${escaped}["'])`,
    );
    lines.forEach((line, index) => {
      if (publicUse.test(line)) {
        throw new Error(`${path.relative(root, docPath)}:${index + 1} advertises private package ${packageName}`);
      }
    });
  }
}
NODE

echo "release-npm-package-matrix.test.sh: npm package matrix covers publishable TS workspaces"
