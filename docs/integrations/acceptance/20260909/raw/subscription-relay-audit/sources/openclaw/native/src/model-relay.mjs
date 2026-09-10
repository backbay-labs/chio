import {createServer} from "node:http";
import {randomBytes} from "node:crypto";
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const only = (value, keys) => object(value) && Object.keys(value).every(key => keys.includes(key));
// Native Codex owns authentication and refresh. The parent reads only the
// currently issued access token and account routing value from its cache.
export function chatGptCredential(value) {
  if (!object(value) || (value.auth_mode !== undefined && value.auth_mode !== null && value.auth_mode !== "chatgpt") || value.OPENAI_API_KEY || !object(value.tokens) ||
      typeof value.tokens.access_token !== "string" || !value.tokens.access_token || typeof value.tokens.account_id !== "string" || !value.tokens.account_id ||
      /[^\x21-\x7e]/.test(value.tokens.access_token + value.tokens.account_id)) throw new Error("Native ChatGPT cache required; use native Codex login to authenticate or refresh");
  return {kind:"chatgpt",secret:value.tokens.access_token,accountId:value.tokens.account_id};
}
const inlineText = value => typeof value === "string" || Array.isArray(value) && value.every(part => only(part,["type","text","annotations"]) && ["input_text","output_text","text"].includes(part.type) && typeof part.text === "string" && (part.annotations === undefined || Array.isArray(part.annotations) && part.annotations.length === 0));
export function validateCodexRequest(body, model) {
  if (!only(body,["model","input","instructions","tools","tool_choice","parallel_tool_calls","stream","store","reasoning","text","include","prompt_cache_key","temperature","max_output_tokens"]) ||
      body.model !== model || body.store !== false || body.stream !== true || typeof body.instructions !== "string" || !Array.isArray(body.input) || body.input.length > 512) throw new Error("Unsupported subscription model request");
  if (body.max_output_tokens !== undefined && (!Number.isSafeInteger(body.max_output_tokens) || body.max_output_tokens < 1 || body.max_output_tokens > 4096)) throw new Error("Model output budget refused");
  // OpenClaw keeps max_output_tokens for custom base URLs; the subscription
  // endpoint does not support it. Validate the host budget before removing it.
  delete body.max_output_tokens; delete body.temperature;
  if (body.tools !== undefined && (!Array.isArray(body.tools) || body.tools.length > 1 || !body.tools.every(tool => only(tool,["type","name","description","parameters","strict"]) && tool.type === "function" && tool.name === "chio_call" && object(tool.parameters)))) throw new Error("Only inline native Chio functions are allowed");
  if (body.tool_choice !== undefined && !["auto","none","required"].includes(body.tool_choice)) throw new Error("Alternate tool choice refused");
  if (body.include !== undefined && (JSON.stringify(body.include) !== JSON.stringify(["reasoning.encrypted_content"]))) throw new Error("Provider references refused");
  if (body.reasoning !== undefined && (!only(body.reasoning,["effort","summary"]) || ![undefined,"none","minimal","low","medium"].includes(body.reasoning.effort) || ![undefined,"auto","concise"].includes(body.reasoning.summary))) throw new Error("Reasoning budget refused");
  if (body.text !== undefined && (!only(body.text,["verbosity"]) || !["low","medium","high"].includes(body.text.verbosity))) throw new Error("Only text output is supported");
  if (body.prompt_cache_key !== undefined && (typeof body.prompt_cache_key !== "string" || body.prompt_cache_key.length > 256)) throw new Error("Invalid cache key");
  for (const item of body.input) {
    if (!object(item)) throw new Error("Complete inline input required");
    if ((item.type === undefined || item.type === "message") && only(item,["type","id","role","content","status","phase"]) && ["system","developer","user","assistant"].includes(item.role) && inlineText(item.content)) {
      delete item.id; delete item.status;
    } else if (item.type === "function_call" && only(item,["type","id","call_id","name","arguments","status"]) && item.name === "chio_call" && typeof item.call_id === "string" && typeof item.arguments === "string") {
      delete item.id; delete item.status;
    } else if (item.type === "function_call_output" && only(item,["type","id","call_id","output","status"]) && typeof item.call_id === "string" && inlineText(item.output)) {
      delete item.id; delete item.status;
    } else if (item.type === "reasoning" && only(item,["type","id","summary","encrypted_content","status"]) && typeof item.encrypted_content === "string" && Array.isArray(item.summary) && item.summary.every(part => only(part,["type","text"]) && part.type === "summary_text" && typeof part.text === "string")) {
      delete item.id; delete item.status;
    } else throw new Error("Unsupported or referenced subscription history");
  }
}
export function validateModelRequest(body, model) {
  if (!only(body, ["model","messages","tools","tool_choice","parallel_tool_calls","stream","stream_options","max_tokens","max_completion_tokens","temperature","top_p","frequency_penalty","presence_penalty","seed","stop","store"]) || body.model !== model || body.store === true || !Array.isArray(body.messages) || !body.messages.length || body.messages.length > 512) throw new Error("Unsupported model request");
  for (const key of ["max_tokens", "max_completion_tokens"]) if (body[key] !== undefined && (!Number.isSafeInteger(body[key]) || body[key] < 1 || body[key] > 4096)) throw new Error("Model output budget refused");
  for (const tool of body.tools ?? []) if (!only(tool, ["type","function"]) || tool.type !== "function" || !only(tool.function, ["name","description","parameters","strict"]) || tool.function.name !== "chio_call" || !object(tool.function.parameters)) throw new Error("Only native Chio function definitions are allowed");
  if (body.tool_choice !== undefined && !["auto","none","required"].includes(body.tool_choice)
    && !(only(body.tool_choice,["type","function"]) && body.tool_choice.type === "function" && only(body.tool_choice.function,["name"]) && body.tool_choice.function.name === "chio_call")) throw new Error("Alternate tool choice refused");
  for (const message of body.messages) {
    if (!only(message, ["role","content","tool_calls","tool_call_id","name"]) || !["system","developer","user","assistant","tool"].includes(message.role)) throw new Error("Only inline model history is supported");
    if (message.content !== null && typeof message.content !== "string" && !(Array.isArray(message.content) && message.content.every(part => only(part,["type","text"]) && part.type === "text" && typeof part.text === "string"))) throw new Error("Nontext or referenced content refused");
    for (const call of message.tool_calls ?? []) if (!only(call,["id","type","function"]) || typeof call.id !== "string" || call.type !== "function" || !only(call.function,["name","arguments"]) || call.function.name !== "chio_call" || typeof call.function.arguments !== "string") throw new Error("Alternate function history refused");
  }
}
export async function startModelRelay(credential, model = "gpt-4.1-mini", onToolResults) {
  const auth = typeof credential === "string" ? {kind:"api-key",secret:credential} : credential;
  const subscription = auth?.kind === "chatgpt";
  if (!auth?.secret || !["api-key","chatgpt"].includes(auth.kind) || model !== (subscription ? "gpt-5.5" : "gpt-4.1-mini") || subscription && !auth.accountId) throw new Error("Operator credential and pinned model required");
  // PI's native Codex provider extracts an account value from its credential.
  // This is a local-only opaque relay secret, not a provider JWT or account.
  const token = subscription ? `${Buffer.from('{"typ":"CHIO-LOCAL-RELAY","alg":"HS256"}').toString("base64url")}.${Buffer.from(JSON.stringify({"https://api.openai.com/auth":{chatgpt_account_id:"chio-local-relay"}})).toString("base64")}.${randomBytes(32).toString("base64url")}` : randomBytes(32).toString("base64url");
  const route = subscription ? "/v1/codex/responses" : "/v1/chat/completions";
  const endpoint = subscription ? "https://chatgpt.com/backend-api/codex/responses" : "https://api.openai.com/v1/chat/completions";
  const events = []; let port, remaining = 100;
  const server = createServer(async (request, response) => {
    const event = {forwarded: false, routeMatches:request.url===route, authorizationMatches:request.headers.authorization===`Bearer ${token}`, methodMatches:request.method==="POST", hostMatches:request.headers.host===`127.0.0.1:${port}`, originAbsent:!request.headers.origin}; events.push(event);
    const controller = new AbortController(); response.once("close", () => controller.abort());
    let stage="validation";
    try {
      if (request.method !== "POST" || request.url !== route || request.headers.host !== `127.0.0.1:${port}` || request.headers.origin || request.headers.authorization !== `Bearer ${token}` || remaining <= 0) throw new Error("Model route refused");
      let raw = ""; for await (const chunk of request) {raw += chunk; if (Buffer.byteLength(raw) > 8*1024*1024) throw new Error("Model request too large");}
      const body = JSON.parse(raw); event.requestKeys = Object.keys(body);
      (subscription ? validateCodexRequest : validateModelRequest)(body, model);
      // Body parsing yields to other requests. Reserve the quota synchronously
      // after validation, before any callback or provider request can yield.
      if (remaining <= 0) throw new Error("Model request quota exhausted");
      remaining--;
      // This supported mode admits one tool per model turn. The resource owner
      // fences any overlapping call until the guest confirms the first result.
      body.store = false; body.parallel_tool_calls = false;
      if (!subscription && body.max_tokens === undefined && body.max_completion_tokens === undefined) body.max_tokens = 4096;
      event.tools = (body.tools ?? []).map(tool => subscription ? tool.name : tool.function.name);
      event.results = subscription ? body.input.filter(item => item.type === "function_call_output").map(item => ({toolCallId:item.call_id,content:typeof item.output === "string" ? item.output : item.output.map(part=>part.text).join("\n")})) : body.messages.filter(message => message.role === "tool").map(message => ({toolCallId: message.tool_call_id, content: message.content}));
      stage="delivery";await onToolResults?.(event.results);
      stage="provider";
      const headers = {"Content-Type":"application/json",Authorization:`Bearer ${auth.secret}`};
      if (subscription) {headers["ChatGPT-Account-Id"]=auth.accountId;headers.accept="text/event-stream";headers.originator="pi";}
      const upstream = await fetch(endpoint, {method: "POST", redirect: "error", signal: AbortSignal.any([controller.signal,AbortSignal.timeout(60000)]), headers, body: JSON.stringify(body)});
      event.forwarded = true; event.status = upstream.status;
      if (!upstream.ok) {await upstream.body?.cancel();response.writeHead(upstream.status,{"Content-Type":"application/json"});response.end(JSON.stringify({error:{message:`Operator model provider returned HTTP ${upstream.status}`}}));return;}
      event.upstreamContentType = /^(text\/event-stream|application\/json)(;.*)?$/i.test(upstream.headers.get("content-type")??"") ? upstream.headers.get("content-type") : "other-or-missing";
      // Subscription stream:true is always SSE. Some upstream routes omit the
      // header; labeling that stream as JSON makes the native host reframe it.
      response.writeHead(upstream.status, {"Content-Type":subscription ? "text/event-stream" : upstream.headers.get("content-type") ?? "application/json"});
      if (upstream.body) for await (const chunk of upstream.body) response.write(chunk);
      response.end();
    } catch (error) {event.failed = true; event.reason = stage!=="validation" ? `Model ${stage} failed` : error instanceof SyntaxError ? "Malformed model JSON" : error.message; if (!response.headersSent) response.writeHead(403,{"Content-Type":"application/json"}); response.end('{"error":{"message":"Operator model relay refused or failed"}}');}
  });
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);}); port=server.address().port;
  return {port,token,events,api:subscription?"openai-codex-responses":"openai-completions",model,authMode:subscription?"chatgpt-native-cache":"api-key",async close(){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}};
}
