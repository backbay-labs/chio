import { randomBytes } from "node:crypto";
import { createServer } from "node:http";

type ObjectValue = Record<string, unknown>;
export type ModelCredential = { kind: "api-key"; secret: string } | { kind: "chatgpt"; secret: string; accountId: string };

/** Read only a native Codex cache. Native Codex owns login and token refresh. */
export function chatGptCredential(value: unknown): ModelCredential {
  if (!object(value) || (value.auth_mode !== undefined && value.auth_mode !== null && value.auth_mode !== "chatgpt")
    || value.OPENAI_API_KEY || !object(value.tokens)
    || typeof value.tokens.access_token !== "string" || !value.tokens.access_token
    || typeof value.tokens.account_id !== "string" || !value.tokens.account_id
    || /[\r\n]/.test(value.tokens.access_token + value.tokens.account_id)) {
    throw new Error("Native ChatGPT login cache required; refresh it with Codex login");
  }
  return { kind: "chatgpt", secret: value.tokens.access_token, accountId: value.tokens.account_id };
}
function object(value: unknown): value is ObjectValue { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function keys(value: ObjectValue, allowed: string[]): boolean { return Object.keys(value).every(key => allowed.includes(key)); }
const localFunctions = new Set(["list_mcp_resources", "list_mcp_resource_templates", "read_mcp_resource", "request_user_input"]);
const chioFunctions = new Set(["read_text_file", "write_file", "edit_file", "list_directory", "chio_resume"]);
function callable(name: unknown, namespace?: unknown): boolean {
  return typeof name === "string" && (namespace === "mcp__chio" ? chioFunctions.has(name) : namespace === undefined && localFunctions.has(name));
}
function inlineText(value: unknown): boolean {
  return typeof value === "string" || Array.isArray(value) && value.every(item => object(item)
    && keys(item, ["type", "text", "annotations"])
    && ["input_text", "output_text", "text"].includes(item.type as string) && typeof item.text === "string"
    && (item.annotations === undefined || Array.isArray(item.annotations) && item.annotations.length === 0));
}
function tool(value: unknown, namespace?: string): boolean {
  if (!object(value)) return false;
  if (value.type === "function") return callable(value.name, namespace);
  if (value.type === "custom") return !namespace && value.name === "apply_patch";
  if (value.type === "tool_search") return !namespace && value.execution === "client";
  return !namespace && value.type === "namespace" && value.name === "mcp__chio"
    && Array.isArray(value.tools) && value.tools.every(item => tool(item, "mcp__chio"));
}

/** Allow only complete inline model context and local tool declarations.
 * Account item references, hosted tools and arbitrary provider routes are absent. */
export function validateModelRequest(body: ObjectValue, model: string): void {
  // Codex adds client diagnostics. They are not needed for model inference and
  // must not turn this relay into an account-metadata write surface.
  delete body.client_metadata;
  if (!keys(body, ["model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "stream", "store",
    "reasoning", "text", "temperature", "top_p", "max_output_tokens", "service_tier", "include", "truncation",
    "prompt_cache_key", "prompt_cache_retention", "prompt_cache_options"])
    || body.model !== model || body.store !== false || body.stream !== true || !Array.isArray(body.input)) {
    throw new Error("Model request exceeds selected mode");
  }
  if (body.tools !== undefined && (!Array.isArray(body.tools) || !body.tools.every(item => tool(item)))) throw new Error("Hosted or alternate tools are unavailable");
  const choice = body.tool_choice;
  if (choice !== undefined && !["auto", "none", "required"].includes(choice as string)
    && !(object(choice) && keys(choice, ["type", "name", "namespace"])
      && (choice.type === "function" && callable(choice.name, choice.namespace) || choice.type === "custom" && choice.name === "apply_patch"))) {
    throw new Error("Alternate tool choice is unavailable");
  }
  for (const item of body.input) {
    if (!object(item)) throw new Error("Complete inline input required");
    if ((item.type === undefined || item.type === "message")
      && keys(item, ["type", "id", "role", "content", "status", "phase"])
      && ["system", "developer", "user", "assistant"].includes(item.role as string) && inlineText(item.content)) {
      delete item.id; delete item.status;
    } else if (item.type === "function_call" && keys(item, ["type", "id", "call_id", "name", "namespace", "arguments", "status"])
      && callable(item.name, item.namespace) && typeof item.arguments === "string" && typeof item.call_id === "string") {
      delete item.id; delete item.status;
    } else if (item.type === "custom_tool_call" && keys(item, ["type", "id", "call_id", "name", "input", "status"])
      && item.name === "apply_patch" && typeof item.input === "string" && typeof item.call_id === "string") {
      delete item.id; delete item.status;
    } else if (["function_call_output", "custom_tool_call_output"].includes(item.type as string)
      && keys(item, ["type", "id", "call_id", "output", "status"]) && typeof item.call_id === "string" && inlineText(item.output)) {
      delete item.id; delete item.status;
    } else if (item.type === "tool_search_call" && keys(item, ["type", "id", "call_id", "status", "execution", "arguments"])
      && item.execution === "client" && typeof item.call_id === "string" && object(item.arguments)
      && keys(item.arguments, ["query", "limit"]) && typeof item.arguments.query === "string") {
      delete item.id; delete item.status;
    } else if (item.type === "tool_search_output" && keys(item, ["type", "id", "call_id", "status", "execution", "tools"])
      && item.execution === "client" && typeof item.call_id === "string" && Array.isArray(item.tools) && item.tools.every(value => tool(value))) {
      delete item.id; delete item.status;
    } else if (item.type === "reasoning" && keys(item, ["type", "id", "summary", "encrypted_content", "status"])
      && typeof item.encrypted_content === "string" && Array.isArray(item.summary)
      && item.summary.every(value => object(value) && keys(value, ["type", "text"]) && value.type === "summary_text" && typeof value.text === "string")) {
      delete item.id; delete item.status;
    } else throw new Error("Unsupported or referenced model history");
  }
}

/** Operator-owned fixed OpenAI Responses transport. The child sees only a
 * temporary relay token, never the provider account credential. */
export async function startModelRelay(credential: string | ModelCredential, model: string, onToolResults?: (outcomes: unknown[]) => Promise<void>) {
  const auth = typeof credential === "string" ? { kind: "api-key" as const, secret: credential } : credential;
  const endpoint = auth.kind === "chatgpt" ? "https://chatgpt.com/backend-api/codex/responses" : "https://api.openai.com/v1/responses";
  const token = randomBytes(32).toString("hex");
  const stats = { requests: 0, forwarded: 0, refused: 0, upstreamFailures: 0, cancelled: 0, lastRefusal: "", lastRequestKeys: [] as string[], nativeTools: [] as {callId: string; input: string; output?: unknown}[] };
  let port = 0;
  const server = createServer(async (request, response) => {
    stats.requests++;
    const controller = new AbortController();
    response.on("close", () => controller.abort());
    try {
      if (request.method !== "POST" || request.url !== "/v1/responses" || request.headers.authorization !== `Bearer ${token}` || request.headers.origin || request.headers.host !== `127.0.0.1:${port}`) {
        stats.refused++; response.writeHead(403); response.end("Model route refused"); return;
      }
      const chunks: Buffer[] = []; let bytes = 0;
      for await (const chunk of request) { bytes += chunk.length; if (bytes > 8 * 1024 * 1024) throw new Error("Model request too large"); chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks).toString()) as ObjectValue;
      stats.lastRequestKeys = Object.keys(body);
      validateModelRequest(body, model);
      // Codex exec JSONL can omit rejected native patch events. Retain the host's
      // exact local call/result history at the model boundary for qualification.
      for (const item of body.input as ObjectValue[]) {
        if (item.type === "custom_tool_call" && item.name === "apply_patch"
          && !stats.nativeTools.some(value => value.callId === item.call_id)) {
          if (stats.nativeTools.length >= 128 || String(item.input).length > 16384) throw new Error("Native observation limit exceeded");
          stats.nativeTools.push({callId: String(item.call_id), input: String(item.input)});
        }
        if (item.type === "custom_tool_call_output") {
          const call = stats.nativeTools.find(value => value.callId === item.call_id);
          if (call) {
            if (JSON.stringify(item.output).length > 16384) throw new Error("Native observation limit exceeded");
            call.output = item.output;
          }
        }
      }
      const outcomes: unknown[] = [];
      for (const item of body.input as ObjectValue[]) {
        if (item.type !== "function_call_output") continue;
        let output: unknown = item.output;
        for (let depth = 0; depth < 4; depth++) {
          if (typeof output === "string") {
            try { output = JSON.parse(output); } catch { break; }
          } else if (Array.isArray(output) && output.length === 1 && object(output[0]) && typeof output[0].text === "string") {
            output = output[0].text;
          } else if (object(output) && Array.isArray(output.content)) {
            output = output.content;
          } else break;
        }
        if (object(output) && output.state !== undefined) outcomes.push(output);
      }
      await onToolResults?.(outcomes);
      body.parallel_tool_calls = false;
      stats.forwarded++;
      const headers: Record<string, string> = { authorization: `Bearer ${auth.secret}`, "content-type": "application/json" };
      if (auth.kind === "chatgpt") headers["ChatGPT-Account-Id"] = auth.accountId;
      const upstream = await fetch(endpoint, { method: "POST", redirect: "error", signal: controller.signal,
        headers, body: JSON.stringify(body) });
      if (!upstream.ok) stats.upstreamFailures++;
      response.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      if (upstream.body) for await (const data of upstream.body) response.write(data);
      response.end();
    } catch (error) {
      if (controller.signal.aborted) { stats.cancelled++; return; }
      stats.refused++;
      stats.lastRefusal = error instanceof Error ? error.message : "Model relay failure";
      if (!response.headersSent) response.writeHead(502);
      response.end("Model relay refused or failed");
    }
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Model relay failed to bind");
  port = address.port;
  return { port, token, stats, async close() { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } };
}
