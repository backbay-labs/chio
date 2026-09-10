import { execFileSync } from "node:child_process";
import { readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative } from "node:path";

export function isWithin(base: string, target: string): boolean {
  const path = relative(base, target);
  return path === "" || (path !== ".." && !path.startsWith("../") && !isAbsolute(path));
}

async function runtimeLibraries(executables: string[]): Promise<string[]> {
  const files = new Set<string>(), pending = [...executables];
  while (pending.length) {
    const path = pending.pop()!;
    if (files.has(path)) continue;
    files.add(path);
    const output = execFileSync("/usr/bin/otool", ["-L", path], { encoding: "utf8" });
    for (const line of output.split("\n").slice(1)) {
      const library = line.trim().split(" ")[0];
      if (!library || library.startsWith("/usr/lib/") || library.startsWith("/System/")) continue;
      let resolved = library;
      if (library.startsWith("@rpath/")) {
        try { resolved = await realpath(join(dirname(path), library.slice(7))); }
        catch { resolved = join(dirname(executables[0]!), "..", "lib", library.slice(7)); }
      } else if (library.startsWith("@loader_path/")) resolved = join(dirname(path), library.slice(13));
      else if (library.startsWith("@executable_path/")) resolved = join(dirname(path), library.slice(17));
      if (!isAbsolute(resolved)) throw new Error("Unsupported runtime library resolution");
      pending.push(await realpath(resolved));
    }
  }
  return [...files];
}

export interface ProcessBoundary {
  codex: string; profile: string; workspace: string; gatewayPort: number; modelPort: number;
}

/** The guest can execute only the pinned host and cannot fork descendants.
 * Kernel authority and durable journals remain in the launcher process. */
export async function buildSandboxPolicy(options: ProcessBoundary): Promise<string> {
  const libraries = await runtimeLibraries([options.codex]);
  return `(version 1)
(deny default)
(allow sysctl-read (sysctl-name-prefix "hw.") (sysctl-name "kern.hostname") (sysctl-name "kern.ostype") (sysctl-name "kern.osrelease") (sysctl-name "kern.osversion") (sysctl-name "kern.osproductversion") (sysctl-name "kern.version") (sysctl-name "kern.maxfilesperproc") (sysctl-name "kern.tcsm_available") (sysctl-name "kern.tcsm_enable") (sysctl-name "machdep.cpu.brand_string"))
(allow file-read-metadata)
(allow file-read-data (literal "/"))
(allow file-read-data (require-all (literal ${JSON.stringify(options.workspace)}) (vnode-type DIRECTORY)))
(allow file-read* (subpath "/System/Library") (subpath "/System/Volumes/Preboot/Cryptexes/OS") (subpath "/usr/lib") (subpath "/Library/Apple/System") (subpath "/private/var/db/dyld")
  (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom")
  ${libraries.map(path => `(literal ${JSON.stringify(path)})`).join("\n  ")})
(allow file-read* file-write* (subpath ${JSON.stringify(options.profile)}) (literal "/dev/null"))
(deny process-fork)
(allow process-exec (literal ${JSON.stringify(options.codex)}))
(allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.system.opendirectoryd.libinfo"))
(allow network-outbound (remote tcp "localhost:${options.gatewayPort}") (remote tcp "localhost:${options.modelPort}"))
(deny file-link)
`;
}

export async function requireSessionCredential(path: string) {
  const config = JSON.parse(await readFile(path, "utf8"));
  const credential = config.sessionCredential, execution = config.execution;
  if (!credential || credential.schema !== "chio.mcp.session-credential.v1"
    || credential.sessionId !== execution?.sessionId || credential.subjectKey !== execution?.subjectKey
    || credential.serverId !== execution?.serverId || credential.endpointPath !== "/mcp"
    || !Array.isArray(credential.capabilityIds) || credential.capabilityIds.length !== 1
    || credential.capabilityIds[0] !== execution?.capabilityId) {
    throw new Error("Restricted mode requires operator-prepared delegated session authority");
  }
  const tools = config.tools?.map((tool: { name: string }) => tool.name).sort();
  if (!Array.isArray(credential.allowedTools) || JSON.stringify([...credential.allowedTools].sort()) !== JSON.stringify(tools)) {
    throw new Error("Delegated tool binding differs from prepared inventory");
  }
  const endpoint = new URL(execution.endpoint);
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || !endpoint.port
    || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== "/") {
    throw new Error("Qualified process boundary requires the exact loopback IPv4 kernel MCP endpoint");
  }
  return { config, kernelPort: Number(endpoint.port) };
}
