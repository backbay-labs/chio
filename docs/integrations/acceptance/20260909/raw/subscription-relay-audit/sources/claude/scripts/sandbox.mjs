import { realpathSync, existsSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { execFileSync } from "node:child_process";

function quote(value) {
  if (typeof value!=="string" || /[\x00-\x1f]/.test(value)) throw new Error("invalid sandbox path");
  return JSON.stringify(value);
}
export function runtimeLibraries(executable) {
  const root=realpathSync(executable), pending=[root], files=new Set();
  while (pending.length) {
    const path=pending.pop();
    if (files.has(path)) continue;
    if (files.size>=128) throw new Error("runtime library graph exceeds qualified bound");
    files.add(path);
    const output=execFileSync("/usr/bin/otool",["-L",path],{encoding:"utf8",timeout:5000});
    for (const line of output.split("\n").slice(1)) {
      if (!line.startsWith("\t")) continue;
      const name=line.trim().split(" (compatibility")[0];
      if (name.startsWith("/usr/lib/") || name.startsWith("/System/Library/")) continue;
      let target=name;
      if (name.startsWith("@rpath/")) {
        target=join(dirname(path),name.slice(7));
        if (!existsSync(target)) target=join(dirname(root),"..","lib",name.slice(7));
      } else if (name.startsWith("@loader_path/")) target=join(dirname(path),name.slice(13));
      else if (name.startsWith("@executable_path/")) target=join(dirname(root),name.slice(17));
      if (!isAbsolute(target)) throw new Error("unqualified runtime library location");
      pending.push(realpathSync(target));
    }
  }
  return [...files];
}

export function buildSandboxPolicy({host,node,gateway,config,profile,journal,workspace,temporary,controlFiles,kernelPort,modelPort,operatorTransport=false}) {
  if (process.platform!=="darwin" || !existsSync("/usr/bin/sandbox-exec")) throw new Error("qualified mode requires macOS sandbox-exec");
  for (const port of [kernelPort,modelPort]) if (!Number.isInteger(port) || port<1 || port>65535) throw new Error("exact loopback service ports required");
  const executables=(operatorTransport?[host]:[host,node]).map(path=>realpathSync(path));
  const libraries=[...new Set(executables.flatMap(runtimeLibraries))];
  const files=[...(operatorTransport?[]:[gateway,config]),...controlFiles,...libraries].map(path=>realpathSync(path));
  return `(version 1)
(deny default)
(allow file-read-metadata)
(allow file-read-data (literal "/"))
(allow file-read-data (require-all (literal ${quote(workspace)}) (vnode-type DIRECTORY)))
(allow sysctl-read (sysctl-name-prefix "hw.") (sysctl-name "kern.hostname") (sysctl-name "kern.ostype") (sysctl-name "kern.osrelease") (sysctl-name "kern.osversion") (sysctl-name "kern.osproductversion") (sysctl-name "kern.version") (sysctl-name "kern.maxfilesperproc") (sysctl-name "kern.tcsm_available") (sysctl-name "kern.tcsm_enable") (sysctl-name "machdep.cpu.brand_string"))
(allow file-read* (subpath "/System/Library") (subpath "/System/Volumes/Preboot/Cryptexes/OS") (subpath "/usr/lib") (subpath "/Library/Apple/System") (subpath "/private/var/db/dyld") (subpath "/usr/share/icu") (subpath "/private/var/db/timezone")
 (literal "/private/etc/localtime") (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom")
 ${files.map(path=>`(literal ${quote(path)})`).join("\n ")})
(allow file-read* file-write* (subpath ${quote(profile)}) ${operatorTransport?"":`(subpath ${quote(journal)})`} (subpath ${quote(temporary)}) (literal "/dev/null"))
(deny file-link)
${operatorTransport?"(deny process-fork)":"(allow process-fork)"}
(allow process-exec ${executables.map(path=>`(literal ${quote(path)})`).join(" ")})
(allow process-info* (target self))
(allow signal (target children) (target self))
(allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.system.opendirectoryd.libinfo"))
(allow network-outbound (remote tcp "localhost:${kernelPort}") (remote tcp "localhost:${modelPort}"))
`;
}

export function requireSessionCredential(config,now=Math.floor(Date.now()/1000)) {
  const c=config.sessionCredential,e=config.execution,names=config.tools?.map(tool=>tool.name).sort();
  if (!c || c.schema!=="chio.mcp.session-credential.v1" || c.sessionId!==e?.sessionId || c.subjectKey!==e?.subjectKey || c.serverId!==e?.serverId || c.endpointPath!=="/mcp" || JSON.stringify(c.capabilityIds)!==JSON.stringify([e?.capabilityId])
    || !Array.isArray(c.allowedTools) || !Array.isArray(names) || !names.length || new Set(names).size!==names.length || names.some(name=>typeof name!=="string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(name)) || JSON.stringify([...c.allowedTools].sort())!==JSON.stringify(names)
    || !Number.isSafeInteger(c.issuedAt) || !Number.isSafeInteger(c.expiresAt) || c.issuedAt>now+5 || c.expiresAt<=now || c.expiresAt<=c.issuedAt || c.expiresAt-c.issuedAt>3600) throw new Error("qualified mode requires matching live delegated session authority");
  return config;
}
