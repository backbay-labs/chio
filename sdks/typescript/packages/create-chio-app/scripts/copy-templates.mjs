import { cpSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(packageRoot, "../..");
const source = resolve(workspaceRoot, "templates");
const destination = resolve(packageRoot, "templates");

rmSync(destination, { recursive: true, force: true });
cpSync(source, destination, { recursive: true });
