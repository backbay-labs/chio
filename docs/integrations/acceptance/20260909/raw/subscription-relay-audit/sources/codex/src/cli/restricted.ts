import { StringDecoder } from "node:string_decoder";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSandboxPolicy, isWithin, requireSessionCredential } from "./sandbox.js";
import { startModelRelay, chatGptCredential } from "./modelRelay.js";
import { startGatewayHttp } from "@chio/bridge";

// The selected model must expose ordinary MCP tools. Code-mode-only models
// need separate qualification and cannot silently replace this host contract.
export const RESTRICTED_MODEL = "gpt-5.5";
export const RESTRICTED_HOST_VERSION = "codex-cli 0.153.4";
export const RESTRICTED_HOST_SHA256 = "b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3";
export const DISABLED_FEATURES = [
  "shell_tool", "unified_exec", "multi_agent", "multi_agent_v2", "apps",
  "plugins", "browser_use", "browser_use_external", "computer_use", "code_mode",
  "code_mode_only", "in_app_browser", "image_generation", "view_image", "artifact",
  "goals", "sleep_tool", "memories", "tool_suggest", "recommended_plugins",
  "remote_plugin", "enable_mcp_apps", "browser_use_full_cdp_access",
  "request_permissions_tool", "skill_search", "skill_mcp_dependency_install",
  "hooks", "shell_snapshot", "in_app_local_automation",
] as const;

interface RestrictedOptions { gatewayConfig: string; modelKeyFile?: string; modelAuthFile?: string; codexBinary: string; evidenceDir: string; prompt: string }

export function prepareGatewayCmd(args: string[]): number {
  if (args.length !== 2 || args.some(path => !isAbsolute(path))) throw new Error("prepare-gateway: requires /absolute/private-request.json /absolute/new-config.json");
  const script = join(dirname(fileURLToPath(import.meta.resolve("@chio/bridge/package.json"))), "dist", "prepare-gateway.js");
  const result = spawnSync(process.execPath, [script, ...args], { stdio: "inherit", timeout: 40_000 });
  return result.status ?? 1;
}

function parseArgs(args: string[]): RestrictedOptions {
  const values = new Map<string, string>();
  const known = new Set(["--gateway-config", "--model-key-file", "--model-auth-file", "--codex-binary", "--evidence-dir", "--prompt"]);
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (!flag || !known.has(flag) || !value || value.startsWith("--") || values.has(flag)) {
      throw new Error("restricted: use --gateway-config FILE --evidence-dir NEW-DIR --prompt TEXT; arbitrary host arguments are not supported");
    }
    values.set(flag, value);
  }
  const gatewayConfig = values.get("--gateway-config");
  const evidenceDir = values.get("--evidence-dir");
  const prompt = values.get("--prompt");
  if (!gatewayConfig || !evidenceDir || !prompt || !isAbsolute(gatewayConfig) || !isAbsolute(evidenceDir)) throw new Error("restricted: absolute gateway config, new evidence directory and prompt are required");
  if (values.has("--model-key-file") && values.has("--model-auth-file")) throw new Error("Choose one explicit provider authentication mode");
  return { gatewayConfig, evidenceDir, prompt, ...(values.has("--model-key-file") ? { modelKeyFile: values.get("--model-key-file")! } : {}),
    ...(values.has("--model-auth-file") ? { modelAuthFile: values.get("--model-auth-file")! } : {}),
    codexBinary: values.get("--codex-binary") ?? "codex" };
}

export function resolveCodexNative(requested: string): string {
  const path = isAbsolute(requested) ? requested : (process.env["PATH"] ?? "").split(":").map(directory => join(directory, requested)).find(existsSync);
  if (!path) throw new Error("Codex executable was not found");
  let binary = realpathSync(path);
  if (binary.endsWith("/@openai/codex/bin/codex.js")) {
    binary = realpathSync(join(dirname(dirname(dirname(binary))), "codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex"));
  }
  if (!["cffaedfe", "feedfacf", "cafebabe", "bebafeca", "cafebabf"].includes(readFileSync(binary).subarray(0, 4).toString("hex"))) {
    throw new Error("Restricted mode requires the installed native Darwin Codex executable");
  }
  return binary;
}

function requirePrivateFile(path: string): string {
  if (!isAbsolute(path)) throw new Error("Operator file path must be absolute");
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) {
    throw new Error("Operator file must be a private owned regular file");
  }
  return realpathSync(path);
}

function readChatGptCache(path: string) {
  try { return chatGptCredential(JSON.parse(readFileSync(path, "utf8"))); }
  catch { throw new Error("Invalid native ChatGPT cache; credential contents are not logged"); }
}

/** Fixed configuration, never supplemented with agent-provided host flags. */
export function restrictedHostArgs(workspace: string, gatewayUrl: string, prompt: string, approval = false): string[] {
  const tools = ["read_text_file", "write_file", "edit_file", "list_directory", ...(approval ? ["chio_resume"] : [])];
  const server = `mcp_servers={chio={url=${JSON.stringify(gatewayUrl)},bearer_token_env_var="CHIO_CODEX_GATEWAY_TOKEN",required=true,startup_timeout_sec=10,tool_timeout_sec=40,default_tools_approval_mode="approve",enabled_tools=${JSON.stringify(tools)}}}`;
  const args = ["exec", "--strict-config", "--ignore-user-config", "--ignore-rules", "--ephemeral", "--sandbox", "read-only", "--skip-git-repo-check", "-C", workspace, "--model", RESTRICTED_MODEL, "--json",
    "-c", 'approval_policy="never"', "-c", 'web_search="disabled"', "-c", "agents.enabled=false", "-c", 'developer_instructions="Chio MCP file tools operate on a separate remote resource rooted at /workspace. Preserve remote absolute paths exactly. Do not translate them to the local working directory. Only a verified completed Chio result establishes a completed resource call; an isError result is a tool failure."', "-c", server];
  for (const feature of DISABLED_FEATURES) args.push("--disable", feature);
  args.push("--", prompt);
  return args;
}

/** Host turn completion does not establish successful protected execution. */
export function summarizeRestrictedOutcome(stdout: string, hostExit: number | null, signal: string | null, interrupted = false) {
  let completed = 0, denied = 0, notDispatched = 0, unknown = 0, toolFailures = 0, awaitingApproval = 0;
  let hostFailed = interrupted;
  const pending = new Set<string>(), finished = new Set<string>();
  for (const line of stdout.split("\n").filter(line => line.trim())) {
    try {
      const event = JSON.parse(line) as { type?: string; item?: {
        id?: string; type?: string; server?: string; status?: string; error?: unknown;
        result?: { content?: { type?: string; text?: string }[] };
      } };
      if (event.type === "error" || event.type === "turn.failed") hostFailed = true;
      const item = event.item;
      if (item?.type !== "mcp_tool_call") continue;
      if (!item.id) { unknown++; continue; }
      if (event.type === "item.started") { pending.add(item.id); continue; }
      if (event.type !== "item.completed" || finished.has(item.id)) continue;
      pending.delete(item.id); finished.add(item.id);
      if (item.server !== "chio" || item.error) { unknown++; continue; }
      const content = item.result?.content;
      if (content?.length !== 1 || content[0]?.type !== "text") { unknown++; continue; }
      const outcome = JSON.parse(content[0].text ?? "") as {
        state?: string; evidence?: string; result?: { isError?: boolean };
      };
      if (outcome.state === "awaiting_approval") awaitingApproval++;
      else if (outcome.state === "not_dispatched") notDispatched++;
      else if (outcome.state === "denied" && outcome.evidence === "verified") denied++;
      else if (outcome.state === "completed" && outcome.evidence === "verified") {
        if (outcome.result?.isError === true) toolFailures++;
        else if (item.status === "failed") unknown++;
        else completed++;
      } else unknown++;
    } catch { unknown++; }
  }
  unknown += pending.size;
  const hostCode = hostExit ?? 1;
  const status = unknown ? "unknown" : hostCode !== 0 || signal || hostFailed ? "host_failed"
    : awaitingApproval ? "awaiting_operator_approval"
    : denied || notDispatched || toolFailures ? "protected_work_incomplete"
    : completed ? "protected_calls_completed" : "host_completed_without_protected_result";
  const exitCode = unknown ? 2 : hostCode !== 0 ? hostCode : signal || hostFailed ? 1
    : awaitingApproval ? 4 : denied || notDispatched || toolFailures ? 3 : 0;
  return { status, exitCode, hostExitCode: hostExit, hostSignal: signal,
    completed, denied, notDispatched, unknown, toolFailures, awaitingApproval };
}

export async function restrictedCmd(args: string[]): Promise<number> {
  const options = parseArgs(args);
  if (process.platform !== "darwin" || process.arch !== "arm64") throw new Error("Restricted process mode is qualified only for macOS arm64");
  const configPath = requirePrivateFile(options.gatewayConfig);
  const authority = await requireSessionCredential(configPath);
  const binary = resolveCodexNative(options.codexBinary);
  if (createHash("sha256").update(readFileSync(binary)).digest("hex") !== RESTRICTED_HOST_SHA256) throw new Error("restricted: native host digest is not qualified");
  const host = spawnSync(binary, ["--version"], { encoding: "utf8", timeout: 10_000 });
  if (host.status !== 0 || host.stdout.trim() !== RESTRICTED_HOST_VERSION) throw new Error(`restricted: requires ${RESTRICTED_HOST_VERSION}; this host is not qualified`);
  const gateway = realpathSync(join(dirname(fileURLToPath(import.meta.resolve("@chio/bridge/package.json"))), "dist", "gateway-http.js"));
  if (!lstatSync(gateway).isFile()) throw new Error("restricted: packaged gateway is missing");
  const installation = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), "../.."));
  const keyFile = options.modelAuthFile ? requirePrivateFile(options.modelAuthFile) : options.modelKeyFile ? requirePrivateFile(options.modelKeyFile) : undefined;
  if (keyFile && isWithin(installation, keyFile)) throw new Error("Provider credential must be outside the readable installation");
  const credential = options.modelAuthFile ? readChatGptCache(keyFile!)
    : keyFile ? readFileSync(keyFile, "utf8").trim() : process.env["OPENAI_API_KEY"];
  if (!credential) throw new Error("Operator API key or --model-auth-file native ChatGPT cache is required; credentials stay outside the host");
  mkdirSync(options.evidenceDir, { mode: 0o700 });
  const runtime = realpathSync(mkdtempSync(join(tmpdir(), "chio-codex-restricted-")));
  const profile = join(runtime, "profile"), workspace = join(runtime, "workspace");
  mkdirSync(profile, { mode: 0o700 }); mkdirSync(workspace, { mode: 0o700 });
  const temporary = join(profile, "tmp"); mkdirSync(temporary, { mode: 0o700 });
  if (!isAbsolute(authority.config.journalDir)) throw new Error("Journal path must be absolute");
  mkdirSync(authority.config.journalDir, { recursive: true, mode: 0o700 });
  const journalStat = lstatSync(authority.config.journalDir);
  if (!journalStat.isDirectory() || journalStat.isSymbolicLink() || (journalStat.mode & 0o077) !== 0 || journalStat.uid !== process.getuid?.()) throw new Error("Journal must be a private owned directory");
  const journal = realpathSync(authority.config.journalDir);
  if (isWithin(journal, configPath) || isWithin(journal, installation) || isWithin(installation, journal)
    || keyFile && (isWithin(journal, keyFile) || isWithin(profile, keyFile))) throw new Error("Writable journal must not contain operator credentials or installed code");
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "USER", "LOGNAME", "LANG"]) if (process.env[key]) env[key] = process.env[key];
  env["CODEX_HOME"] = profile; env["TMPDIR"] = temporary; env["OPENSSL_CONF"] = "/dev/null";
  const transport = await startGatewayHttp(authority.config);
  let delivered = 0, deliveryFailed = false;
  let acknowledgements = Promise.resolve();
  const confirmed = new Set<string>();
  function receiveHostResults(outcomes: unknown[]): Promise<void> {
    acknowledgements = acknowledgements.then(async () => {
      for (const value of outcomes) {
        const outcome = value as {state?: string; evidence?: string};
        if (outcome?.state !== "completed" || outcome.evidence !== "verified") continue;
        const identity = createHash("sha256").update(JSON.stringify(outcome)).digest("hex");
        if (confirmed.has(identity)) continue;
        const receipt = await transport.acknowledgeReceivedOutcome(outcome);
        if (!receipt.acknowledged) throw new Error("Actual host result delivery is unresolved");
        confirmed.add(identity); delivered++;
      }
    }).catch(error => { deliveryFailed = true; throw error; });
    return acknowledgements;
  }
  let relay: Awaited<ReturnType<typeof startModelRelay>> | undefined;
  try {
  if (typeof transport.acknowledgeReceivedOutcome !== "function") throw new Error("Host delivery acknowledgement transport is required");
  relay = await startModelRelay(credential, RESTRICTED_MODEL, receiveHostResults);
  env["CHIO_CODEX_MODEL_TOKEN"] = relay.token;
  env["CHIO_CODEX_GATEWAY_TOKEN"] = transport.token;
  const command = restrictedHostArgs(workspace, transport.url, options.prompt, Boolean(authority.config.approval));
  command.splice(command.indexOf("--"), 0, "-c", 'model_provider="chio_model"', "-c", 'model_providers.chio_model.name="Chio model relay"',
    "-c", `model_providers.chio_model.base_url="http://127.0.0.1:${relay.port}/v1"`, "-c", 'model_providers.chio_model.wire_api="responses"',
    "-c", 'model_providers.chio_model.env_key="CHIO_CODEX_MODEL_TOKEN"', "-c", "model_providers.chio_model.supports_websockets=false");
  const boundary = { codex: binary, profile, workspace, gatewayPort: transport.port, modelPort: relay.port };
  const policy = await buildSandboxPolicy(boundary), policyPath = join(runtime, "boundary.sb");
  writeFileSync(policyPath, policy, { mode: 0o600 });
  const report: Record<string, unknown> = { host: RESTRICTED_HOST_VERSION, model: RESTRICTED_MODEL, model_auth: options.modelAuthFile ? "chatgpt-native-cache" : "api-key", runtime, workspace, profile,
    boundary, policy_path: policyPath, policy_sha256: createHash("sha256").update(policy).digest("hex"),
    host_binary_sha256: createHash("sha256").update(readFileSync(binary)).digest("hex"),
    gateway_sha256: createHash("sha256").update(readFileSync(gateway)).digest("hex"),
    config_sha256: createHash("sha256").update(readFileSync(configPath)).digest("hex"),
    command, acceptance: "candidate: independent effect verification required", started_at: new Date().toISOString() };
  writeFileSync(join(options.evidenceDir, "launch.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  process.stderr.write(`Restricted candidate evidence: ${options.evidenceDir}\n`);
    const code = await new Promise<number>((done) => {
      const child = spawn("/usr/bin/sandbox-exec", ["-f", policyPath, binary, ...command], { env, cwd: workspace, stdio: ["ignore", "pipe", "pipe"] });
      let forceStop: NodeJS.Timeout | undefined;
      const deadline = setTimeout(() => {
        report["timed_out"] = true;
        child.kill("SIGTERM");
        forceStop = setTimeout(() => child.kill("SIGKILL"), 5_000);
      }, 180_000);
      const stdout: Buffer[] = [], stderr: Buffer[] = [];
      const decoder = new StringDecoder("utf8");
      let hostLines = "";
      child.stdout.on("data", data => {
        stdout.push(data); process.stdout.write(data); hostLines += decoder.write(data);
        if (Buffer.byteLength(hostLines) > 16 * 1024 * 1024) { deliveryFailed = true; child.kill("SIGTERM"); return; }
        let end: number;
        while ((end = hostLines.indexOf("\n")) >= 0) {
          const line = hostLines.slice(0, end); hostLines = hostLines.slice(end + 1);
          try {
            const event = JSON.parse(line); const item = event.item;
            if (event.type !== "item.completed" || item?.type !== "mcp_tool_call" || item.server !== "chio" || item.error
              || item.result?.content?.length !== 1 || item.result.content[0].type !== "text") continue;
            const outcome = JSON.parse(item.result.content[0].text);
            if (outcome.state !== "completed" || outcome.evidence !== "verified" || !outcome.delivery) continue;
            void receiveHostResults([outcome]).catch(() => { child.kill("SIGTERM"); });
          } catch { /* Missing host proof never releases the operation fence. */ }
        }
      });
      child.stderr.on("data", data => { stderr.push(data); process.stderr.write(data); });
      const forward = (signal: NodeJS.Signals) => { report["operator_interrupt"] = signal; child.kill(signal); };
      const term = () => forward("SIGTERM"), interrupt = () => forward("SIGINT");
      process.once("SIGTERM", term); process.once("SIGINT", interrupt);
      child.once("error", error => { stderr.push(Buffer.from(error.message)); });
      child.once("close", async (status, signal) => {
        await acknowledgements.catch(() => { deliveryFailed = true; });
        clearTimeout(deadline); if (forceStop) clearTimeout(forceStop);
        process.removeListener("SIGTERM", term); process.removeListener("SIGINT", interrupt);
        writeFileSync(join(options.evidenceDir, "stdout.jsonl"), Buffer.concat(stdout), { mode: 0o600 });
        writeFileSync(join(options.evidenceDir, "stderr.txt"), Buffer.concat(stderr), { mode: 0o600 });
        report["exit_code"] = status; report["signal"] = signal; report["finished_at"] = new Date().toISOString();
        const outcome = summarizeRestrictedOutcome(Buffer.concat(stdout).toString("utf8"), status, signal,
          report["timed_out"] === true || report["operator_interrupt"] !== undefined);
        report["host_delivery"] = {confirmed: delivered, failed: deliveryFailed};
        if (deliveryFailed) { outcome.status = "delivery_unresolved"; outcome.exitCode = 2; }
        report["execution_outcome"] = outcome;
        report["model_relay"] = { ...relay?.stats };
        writeFileSync(join(options.evidenceDir, "launch.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
        done(outcome.exitCode);
      });
    });
    return code;
  } finally {
    await transport.close();
    await relay?.close();
  }
}
