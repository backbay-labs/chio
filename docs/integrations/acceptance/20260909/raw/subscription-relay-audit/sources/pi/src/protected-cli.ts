#!/usr/bin/env node
import { access, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { startGatewayHttp } from "@chio/bridge";
import { readPreparedConfig } from "./configured.js";
import { readCodexAuthority, startModelRelay, type ModelAuthority } from "./model-relay.js";
import { buildSandboxPolicy, isWithin, requireSessionCredential } from "./sandbox.js";

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    process.stdout.write("Usage: chio-pi --config /absolute/delegated.json --profile /absolute/profile --cwd /absolute/disposable-workspace --provider openai|openai-codex --model gpt-4.1-mini|gpt-5.5 --prompt 'task' [--codex-auth /absolute/private/codex/auth.json] [--resume /absolute/profile/sessions/session.jsonl]\nProtected candidate requires macOS, an installed package, and delegated retained-session credentials. Codex subscription mode requires --codex-auth; API mode requires operator OPENAI_API_KEY.\n");
    return;
  }
  if (process.platform !== "darwin") throw new Error("Protected candidate currently requires macOS sandbox-exec");
  const values = new Map<string, string>();
  const names = new Set(["--config", "--profile", "--cwd", "--provider", "--model", "--prompt", "--resume", "--codex-auth"]);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]; const value = args[index + 1];
    if (!name || !names.has(name) || values.has(name) || !value) throw new Error("Invalid or missing argument; use chio-pi --help");
    values.set(name, value);
  }
  for (const name of [...names].filter(name => name !== "--resume" && name !== "--codex-auth")) if (!values.has(name)) throw new Error(`Required argument ${name}`);
  const subscription = values.get("--provider") === "openai-codex" && values.get("--model") === "gpt-5.5";
  if (!subscription && (values.get("--provider") !== "openai" || values.get("--model") !== "gpt-4.1-mini")) throw new Error("Model relay supports openai/gpt-4.1-mini or openai-codex/gpt-5.5");
  if (subscription !== values.has("--codex-auth")) throw new Error("--codex-auth is required only for openai-codex");
  if (!subscription && !process.env.OPENAI_API_KEY) throw new Error("Operator OPENAI_API_KEY required");
  const authPath = subscription ? await realpath(values.get("--codex-auth")!) : undefined;
  const authority: ModelAuthority = authPath ? await readCodexAuthority(authPath) : {provider: "openai", apiKey: process.env.OPENAI_API_KEY!};
  values.delete("--codex-auth");
  await access("/usr/bin/sandbox-exec", constants.X_OK);
  const packageRoot = await realpath(join(dirname(fileURLToPath(import.meta.url)), ".."));
  const installation = dirname(dirname(packageRoot));
  if (basename(dirname(packageRoot)) !== "@chio" || basename(installation) !== "node_modules") throw new Error("Protected launcher requires the installed artifact, not a source checkout");
  const executable = await realpath(process.execPath);
  const configPath = await realpath(values.get("--config")!);
  await readPreparedConfig(configPath);
  const config = await requireSessionCredential(configPath);
  const endpoint = new URL(config.execution.endpoint);
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" || !endpoint.port || endpoint.username || endpoint.password) throw new Error("Protected candidate requires an explicit local kernel HTTP endpoint");
  const requestedProfile = resolve(values.get("--profile")!);
  await mkdir(requestedProfile, { recursive: true, mode: 0o700 });
  const profile = await realpath(requestedProfile);
  const profileStat = await lstat(profile);
  if (profileStat.mode & 0o077 || isWithin(installation, profile) || isWithin(profile, installation) || isWithin(profile, configPath) || isWithin(installation, configPath)) throw new Error("Profile, immutable configuration and installed code require separate private paths");
  const profileMarker = join(profile, ".chio-pi-profile.json");
  const contents = await readdir(profile);
  if (contents.length) {
    const markerStat = await lstat(profileMarker);
    if (!markerStat.isFile() || markerStat.isSymbolicLink() || markerStat.mode & 0o077) throw new Error("Existing profile lacks a private Chio ownership marker");
    const marker = JSON.parse(await readFile(profileMarker, "utf8"));
    if (marker.schema !== "chio.pi.profile.v1" || marker.sessionId !== config.execution.sessionId) throw new Error("Profile belongs to another kernel session");
  } else {
    const marker = await open(profileMarker, "wx", 0o600);
    try { await marker.writeFile(JSON.stringify({ schema: "chio.pi.profile.v1", sessionId: config.execution.sessionId })); await marker.sync(); }
    finally { await marker.close(); }
  }
  const requestedCwd = resolve(values.get("--cwd")!);
  await mkdir(requestedCwd, { recursive: true, mode: 0o700 });
  const cwd = await realpath(requestedCwd);
  if (authPath && [profile, installation, cwd].some(path => isWithin(path, authPath))) throw new Error("Native Codex credentials must remain outside guest paths");
  if (isWithin(cwd, profile) || isWithin(cwd, configPath) || isWithin(cwd, installation)) throw new Error("Disposable workspace cannot contain private state or installed code");
  const journal = resolve(config.journalDir);
  if (journal !== config.journalDir || isWithin(profile, journal) || isWithin(installation, journal)
    || isWithin(journal, profile) || isWithin(journal, installation) || isWithin(journal, configPath)) throw new Error("Authoritative gateway journal must be outside guest-readable and writable state");
  values.set("--config", configPath); values.set("--profile", profile); values.set("--cwd", cwd);
  const transport = await startGatewayHttp(config);
  let relay: Awaited<ReturnType<typeof startModelRelay>> | undefined;
  try {
    const confirmed = new Set<string>();
    let confirmations = Promise.resolve();
    relay = await startModelRelay(authority, values.get("--model")!, async outcomes => {
      confirmations = confirmations.then(async () => {
        for (const raw of outcomes) {
          const outcome = raw as {state?: string; evidence?: string; requestId?: string};
          if (outcome?.state !== "completed" || outcome.evidence !== "verified" || typeof outcome.requestId !== "string") continue;
          const identity = createHash("sha256").update(JSON.stringify(outcome)).digest("hex");
          if (confirmed.has(identity)) continue;
          const result = await transport.acknowledgeReceivedOutcome(outcome);
          if (!result.acknowledged) throw new Error("Native host result delivery remains unconfirmed; no next model turn");
          confirmed.add(identity);
        }
      });
      await confirmations;
    });
    const guestConfig = join(profile, "gateway-transport.json");
    await writeFile(guestConfig, JSON.stringify({schema: "chio.pi.transport.v1", sessionId: config.sessionId,
      transport: {url: transport.url, token: transport.token}, tools: config.tools, approvals: Boolean(config.approval),
      binding: {subjectKey: config.execution.subjectKey, capabilityId: config.execution.capabilityId, serverId: config.execution.serverId, trustedSigners: config.execution.trustedSigners}}), {mode: 0o600});
    values.set("--config", guestConfig);
    const policy = await buildSandboxPolicy({ executable, installation, profile, cwd, gatewayPort: transport.port, modelPort: relay.port });
    const control = await mkdtemp(join(tmpdir(), "chio-pi-sandbox-"));
    const policyPath = join(control, "profile.sb");
    await writeFile(policyPath, policy, { mode: 0o600 });
    const temporary = join(profile, "tmp"); await mkdir(temporary, { recursive: true, mode: 0o700 });
    process.stdout.write(JSON.stringify({ type: "chio_protected_runtime", policyPath, policySha256: createHash("sha256").update(policy).digest("hex"), node: executable, installation, sessionId: config.execution.sessionId }) + "\n");
    const child = spawn("/usr/bin/sandbox-exec", ["-f", policyPath, executable, join(packageRoot, "dist", "cli.js"), ...[...values].flat()], {
      cwd, stdio: ["ignore", "inherit", "inherit"],
      env: { PATH: dirname(executable), LANG: "en_US.UTF-8", TMPDIR: temporary, PI_CODING_AGENT_DIR: profile, OPENSSL_CONF: "/dev/null", CHIO_PI_MODEL_TOKEN: relay.token, CHIO_PI_GATEWAY_TRANSPORT: "1", CHIO_PI_MODEL_BASE_URL: `http://127.0.0.1:${relay.port}/v1` },
    });
    const interrupt = () => child.kill("SIGINT"); const terminate = () => child.kill("SIGTERM");
    process.on("SIGINT", interrupt); process.on("SIGTERM", terminate);
    try {
      process.exitCode = await new Promise<number>((resolve, reject) => { child.once("error", reject); child.once("exit", (code, signal) => resolve(code ?? (signal === "SIGINT" ? 130 : signal === "SIGTERM" ? 143 : 1))); });
    } finally { process.off("SIGINT", interrupt); process.off("SIGTERM", terminate); }
  } finally { await transport.close(); await relay?.close(); }
}

main().catch(error => { process.stderr.write(`Chio Pi protected launch refused: ${error instanceof Error ? error.message : "unknown failure"}\n`); process.exitCode = 1; });
