import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const DIST_DIR = resolve(process.cwd(), "dist");
const IMPORT_PATTERN = /((?:from|export)\s+["'][^"']+)\.ts(["'])/g;

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(path);
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    if (!path.endsWith(".js") && !path.endsWith(".d.ts")) {
      continue;
    }
    const source = await readFile(path, "utf8");
    const rewritten = source.replace(IMPORT_PATTERN, "$1.js$2");
    if (rewritten !== source) {
      await writeFile(path, rewritten, "utf8");
    }
  }
}

try {
  const distStats = await stat(DIST_DIR);
  if (distStats.isDirectory()) {
    await walk(DIST_DIR);
  }
} catch (error) {
  console.error(`failed to rewrite dist imports: ${error}`);
  process.exitCode = 1;
}
