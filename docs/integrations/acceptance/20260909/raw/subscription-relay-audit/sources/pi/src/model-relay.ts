import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { zstdDecompressSync } from "node:zlib";
import { lstat, readFile } from "node:fs/promises";

export type ModelAuthority = { provider: "openai"; apiKey: string } | { provider: "openai-codex"; accessToken: string; accountId: string };

/** Read native Codex's cache without modifying or refreshing its credentials. */
export async function readCodexAuthority(path: string): Promise<ModelAuthority> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.mode & 0o077 || stat.uid !== process.getuid?.() || stat.size > 1024 * 1024) throw new Error("Native Codex auth must be a private operator-owned file");
  let value;
  try { value = JSON.parse(await readFile(path, "utf8")); }
  catch { throw new Error("Native Codex auth cache is unreadable or malformed"); }
  const token = value?.tokens?.access_token;
  const accountId = value?.tokens?.account_id;
  if (!object(value) || (value.auth_mode !== undefined && value.auth_mode !== "chatgpt") || value.OPENAI_API_KEY != null || typeof token !== "string" || typeof accountId !== "string" || !accountId) throw new Error("Native Codex ChatGPT login required");
  let claims;
  try { claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()); }
  catch { throw new Error("Native Codex access token is malformed"); }
  if (typeof claims.exp !== "number" || claims.exp * 1000 <= Date.now() + 60_000) throw new Error("Native Codex login expired; refresh through native Codex before restarting Pi");
  if (claims["https://api.openai.com/auth"]?.chatgpt_account_id !== accountId) throw new Error("Native Codex account binding mismatch");
  return { provider: "openai-codex", accessToken: token, accountId };
}

function object(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function keys(value: Record<string, unknown>, allowed: string[]) { return Object.keys(value).every(key => allowed.includes(key)); }
function textContent(value: unknown, output = false): boolean {
  if (typeof value === "string") return true;
  return Array.isArray(value) && value.every(item => object(item) && keys(item, ["type", "text", "annotations"]) && item.type === (output ? "output_text" : "input_text") && typeof item.text === "string" && (item.annotations === undefined || Array.isArray(item.annotations) && item.annotations.length === 0));
}

/** Extract the exact representation emitted by the native Chio extension.
 * This is parsing only. The caller must still validate the signed outcome and
 * match its original private operation before confirming delivery. */
export function nativeToolOutcome(output: unknown): unknown {
  if (Array.isArray(output) && output.length === 1 && output[0]?.type === "input_text") output = output[0].text;
  if (typeof output !== "string") return undefined;
  const prefix = "Chio tool completed with an error: ";
  const prefixed = output.startsWith(prefix);
  try {
    const value: unknown = JSON.parse(prefixed ? output.slice(prefix.length) : output);
    if (prefixed && (!object(value) || value.state !== "completed" || !object(value.result) || value.result.isError !== true)) return undefined;
    return value;
  } catch { return undefined; }
}

export function validateModelRequest(body: Record<string, unknown>, model: string, provider: ModelAuthority["provider"] = "openai") {
  const allowed = new Set(["model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "stream", "store", "reasoning", "text", "temperature", "top_p", "max_output_tokens", "service_tier", "include", "truncation", "prompt_cache_key", "prompt_cache_retention", "prompt_cache_options"]);
  if (Object.keys(body).some(key => !allowed.has(key)) || body.model !== model || body.store !== false || body.stream !== true || !Array.isArray(body.input)) throw new Error("Model request exceeds selected mode");
  if (body.tools !== undefined && (!Array.isArray(body.tools) || body.tools.some(tool => !object(tool) || tool.type !== "function" || tool.name !== "chio_execute"))) throw new Error("Hosted or alternate tools are unavailable");
  if (body.include !== undefined && (!Array.isArray(body.include) || body.include.some(value => provider !== "openai-codex" || value !== "reasoning.encrypted_content"))) throw new Error("Alternate provider expansions are unavailable");
  const choice = body.tool_choice;
  if (choice !== undefined && !["auto", "none", "required"].includes(choice as string) && !(object(choice) && keys(choice, ["type", "name"]) && choice.type === "function" && choice.name === "chio_execute")) throw new Error("Alternate tool choice is unavailable");
  for (const item of body.input) {
    if (!object(item)) throw new Error("Input must contain complete inline items");
    if ((item.type === undefined || item.type === "message") && keys(item, ["type", "role", "content", "id", "status", "phase"]) && ["system", "developer", "user", "assistant"].includes(item.role as string) && textContent(item.content, item.role === "assistant")) {
      // Never ask the operator's provider account to resolve an item by identifier.
      if (provider === "openai-codex" && item.phase !== undefined && (item.role !== "assistant" || !["commentary", "final_answer"].includes(item.phase as string))) throw new Error("Unsupported native assistant phase");
      delete item.id; delete item.status;
      if (provider !== "openai-codex") delete item.phase;
    } else if (item.type === "function_call" && keys(item, ["type", "id", "call_id", "name", "arguments", "status"]) && item.name === "chio_execute" && typeof item.arguments === "string" && typeof item.call_id === "string") {
      delete item.id; delete item.status;
    } else if (item.type === "function_call_output" && keys(item, ["type", "call_id", "output", "id", "status"]) && typeof item.call_id === "string" && textContent(item.output)) {
      delete item.id; delete item.status;
    } else if (provider === "openai-codex" && item.type === "reasoning" && keys(item, ["type", "id", "summary", "encrypted_content", "status", "content"])
      && typeof item.encrypted_content === "string" && /^[A-Za-z0-9_=-]+$/.test(item.encrypted_content)
      && (item.content === undefined || Array.isArray(item.content) && item.content.length === 0)
      && Array.isArray(item.summary) && item.summary.every(part => object(part) && keys(part, ["type", "text"]) && part.type === "summary_text" && typeof part.text === "string")) {
      // Complete inline encrypted reasoning is required by the native Codex
      // history contract. Identifier-only reasoning remains forbidden.
      delete item.id; delete item.status;
    } else throw new Error("Only complete inline text and Chio function history are supported");
  }
}

/** Operator-owned model transport. It exposes only the selected provider's
 * synchronous function-calling response route, never arbitrary proxying. */
export async function startModelRelay(authority: ModelAuthority, model: string, onToolResults?: (outcomes: unknown[]) => Promise<void>) {
  const nonce = randomBytes(32).toString("hex");
  // Native Pi extracts an account claim before making its request. This is
  // an opaque local credential, never an upstream login or signed JWT.
  const token = authority.provider === "openai-codex"
    ? `${Buffer.from('{"typ":"chio-relay"}').toString("base64url")}.${Buffer.from(JSON.stringify({"https://api.openai.com/auth": {chatgpt_account_id: "chio-local-relay"}, nonce})).toString("base64url")}.${nonce}` : nonce;
  const route = authority.provider === "openai-codex" ? "/v1/codex/responses" : "/v1/responses";
  let port = 0;
  const server = createServer(async (request, response) => {
    const controller = new AbortController();
    response.on("close", () => controller.abort());
    try {
      if (request.method !== "POST" || request.url !== route || request.headers.authorization !== `Bearer ${token}` || request.headers.origin || request.headers.host !== `127.0.0.1:${port}`) {
        response.writeHead(403); response.end("Model route refused"); return;
      }
      const chunks: Buffer[] = []; let bytes = 0;
      for await (const chunk of request) {
        bytes += chunk.length;
        if (bytes > 8 * 1024 * 1024) throw new Error("Model request too large");
        chunks.push(chunk);
      }
      let raw = Buffer.concat(chunks);
      if (request.headers["content-encoding"] === "zstd" && authority.provider === "openai-codex") raw = zstdDecompressSync(raw, {maxOutputLength: 8 * 1024 * 1024});
      else if (request.headers["content-encoding"]) throw new Error("Unsupported model body encoding");
      const body = JSON.parse(raw.toString()) as Record<string, unknown>;
      validateModelRequest(body, model, authority.provider);
      body.parallel_tool_calls = false;
      const outcomes: unknown[] = [];
      for (const item of body.input as Record<string, unknown>[]) {
        if (item.type !== "function_call_output") continue;
        const outcome = nativeToolOutcome(item.output);
        if (outcome !== undefined) outcomes.push(outcome);
      }
      await onToolResults?.(outcomes);
      const headers: Record<string, string> = {"content-type": "application/json", accept: "text/event-stream"};
      if (authority.provider === "openai-codex") {
        headers.authorization = `Bearer ${authority.accessToken}`;
        headers["ChatGPT-Account-Id"] = authority.accountId;
        headers["OpenAI-Beta"] = "responses=experimental";
        headers.originator = "pi";
      } else headers.authorization = `Bearer ${authority.apiKey}`;
      const upstream = await fetch(authority.provider === "openai-codex" ? "https://chatgpt.com/backend-api/codex/responses" : "https://api.openai.com/v1/responses", {
        method: "POST", redirect: "error", signal: controller.signal,
        headers, body: JSON.stringify(body),
      });
      response.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      if (upstream.body) for await (const data of upstream.body) response.write(data);
      response.end();
    } catch {
      if (!response.headersSent) response.writeHead(502);
      response.end("Model relay refused or failed");
    }
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Model relay failed to bind");
  port = address.port;
  return { port, token, async close() { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } };
}
