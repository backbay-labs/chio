import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptName = process.argv[2];
if (scriptName == null || scriptName === "") {
  console.error("usage: node ./scripts/run-publishable-workspaces.mjs <script>");
  process.exit(2);
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rootManifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const workspacePatterns = rootManifest.workspaces ?? [];
const packageDirs = [];

for (const pattern of workspacePatterns) {
  if (typeof pattern !== "string") {
    continue;
  }
  if (!pattern.includes("*")) {
    packageDirs.push(join(root, pattern));
    continue;
  }
  const [prefix, suffix = ""] = pattern.split("*", 2);
  const baseDir = join(root, prefix);
  if (!existsSync(baseDir)) {
    continue;
  }
  for (const entry of readdirSync(baseDir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      packageDirs.push(join(baseDir, entry.name, suffix));
    }
  }
}

const packages = [];
for (const dir of packageDirs) {
  const manifestPath = join(dir, "package.json");
  if (!existsSync(manifestPath)) {
    continue;
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.private === true) {
    continue;
  }
  if (
    manifest.scripts == null ||
    typeof manifest.scripts !== "object" ||
    typeof manifest.scripts[scriptName] !== "string"
  ) {
    continue;
  }
  packages.push({
    manifest,
    name: manifest.name,
    dir,
    localDeps: [],
  });
}

const byName = new Map(packages.map(pkg => [pkg.name, pkg]));
for (const pkg of packages) {
  const dependencyBlocks = [
    pkg.manifest.dependencies,
    pkg.manifest.optionalDependencies,
    pkg.manifest.peerDependencies,
  ];
  const localDeps = new Set();
  for (const block of dependencyBlocks) {
    if (block == null || typeof block !== "object") {
      continue;
    }
    for (const name of Object.keys(block)) {
      if (byName.has(name)) {
        localDeps.add(name);
      }
    }
  }
  pkg.localDeps = [...localDeps].sort();
}

const ordered = [];
const seen = new Set();
const visiting = new Set();

function visit(pkg) {
  if (seen.has(pkg.name)) {
    return;
  }
  if (visiting.has(pkg.name)) {
    throw new Error(`cycle in TypeScript package dependencies at ${pkg.name}`);
  }
  visiting.add(pkg.name);
  for (const depName of pkg.localDeps) {
    visit(byName.get(depName));
  }
  visiting.delete(pkg.name);
  seen.add(pkg.name);
  ordered.push(pkg);
}

for (const pkg of [...packages].sort((left, right) => left.name.localeCompare(right.name))) {
  visit(pkg);
}

for (const pkg of ordered) {
  const result = spawnSync(
    "npm",
    ["run", scriptName, "--workspace", pkg.name],
    {
      cwd: root,
      stdio: "inherit",
      shell: false,
    },
  );
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
