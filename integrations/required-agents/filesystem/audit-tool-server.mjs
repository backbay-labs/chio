import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { openSync, writeSync, fsyncSync, closeSync, lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";

// Resource-side observer outside the kernel and every host profile. The observation
// is durable before the official server receives the request. File contents stay out.
// The four exposed tools cannot create aliases. Imported or resumed volumes must
// satisfy this invariant before any server starts. Operator imports require all
// owners stopped; no process outside this owner may mutate the mounted volume.
function validateTree(path) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1)) {
    throw new Error("Resource volume contains a symbolic or hard link");
  }
  if (stat.isDirectory()) {
    for (const name of readdirSync(path)) validateTree(join(path, name));
  } else if (!stat.isFile()) {
    throw new Error("Resource volume contains an unsupported special file");
  }
}
validateTree("/workspace");
const audit = openSync("/audit/dispatch.jsonl", "a", 0o600);
const server = spawn(process.execPath, [
  "/opt/resource/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "/workspace",
], { stdio: ["pipe", "pipe", "inherit"] });
server.stdout.pipe(process.stdout);
let sequence = 0;
let failed = false;
function fail() {
  if (failed) return;
  failed = true;
  server.stdin.destroy();
  server.kill("SIGTERM");
  process.stderr.write("Resource dispatch audit failed; no further requests accepted.\n");
  process.exitCode = 1;
}
const reader = createInterface({ input: process.stdin, crlfDelay: Infinity });
reader.on("line", line => {
  if (failed) return;
  try {
    if (Buffer.byteLength(line) > 1024 * 1024) throw new Error("oversized resource request");
    const message = JSON.parse(line);
    for (const request of Array.isArray(message) ? message : [message]) {
      if (request?.method !== "tools/call") continue;
      const observation = {
        schema: "chio.resource-dispatch-observation.v1", processId: process.pid,
        sequence: ++sequence, observedAt: new Date().toISOString(),
        upstreamRequestId: request.id, tool: request.params?.name,
        path: typeof request.params?.arguments?.path === "string" ? request.params.arguments.path : null,
        argumentsSha256: createHash("sha256").update(JSON.stringify(request.params?.arguments ?? {})).digest("hex"),
        frameSha256: createHash("sha256").update(line).digest("hex"),
      };
      const bytes = Buffer.from(JSON.stringify(observation) + "\n");
      let offset = 0;
      while (offset < bytes.length) {
        const written = writeSync(audit, bytes, offset, bytes.length - offset);
        if (!written) throw new Error("audit did not persist");
        offset += written;
      }
      fsyncSync(audit);
    }
    server.stdin.write(line + "\n");
  } catch { fail(); }
});
reader.on("close", () => server.stdin.end());
server.on("error", fail);
server.stdin.on("error", fail);
server.on("exit", code => {
  closeSync(audit);
  reader.close();
  process.exitCode = failed ? 1 : (code ?? 1);
});
