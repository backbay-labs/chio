import { createHash } from "node:crypto";
import { verifyBoundReceipt, verifyReceivedOutcome } from "@chio/bridge";

// The native plugin is a guest of the operator HTTP gateway. It never receives
// a kernel bearer, resource credentials or the authoritative operation journal.
export function createHttpExecutor(options) {
  const endpoint = new URL(options.endpoint);
  const token = process.env[options.tokenEnv];
  if (options.transport !== "launcher-http-v1" || endpoint.protocol !== "http:" || !["127.0.0.1", "chio-transport"].includes(endpoint.hostname)
    || endpoint.pathname !== "/mcp" || !endpoint.port || endpoint.username || endpoint.password || endpoint.search || endpoint.hash
    || !token || !options.gatewaySessionId || !Array.isArray(options.allowedTools) || !options.allowedTools.length) throw new Error("Prepared launcher HTTP transport required");
  let session = "", unresolved = false;
  async function rpc(id, method, params, signal) {
    const response = await fetch(endpoint, {method: "POST", redirect: "error",
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(40000)]) : AbortSignal.timeout(40000),
      headers: {"Content-Type": "application/json", Authorization: `Bearer ${token}`, ...(session ? {"Mcp-Session-Id": session} : {})},
      body: JSON.stringify({jsonrpc: "2.0", id, method, params})});
    if (!response.ok) throw new Error("Operator gateway transport unavailable; preserve original operation");
    if (method === "initialize") {session = response.headers.get("mcp-session-id"); if (!session) throw new Error("Missing gateway session");}
    const text = await response.text(); if (text.length > 16 * 1024 * 1024) throw new Error("Gateway result exceeds limit");
    const body = JSON.parse(text);
    if (body.jsonrpc !== "2.0" || body.id !== id || body.error || !body.result) throw new Error("Invalid gateway response");
    return body.result;
  }
  let ready;
  function initialize() {
    return ready ??= (async () => {
      const value = await rpc("initialize", "initialize", {protocolVersion: "2025-11-25"});
      if (value.capabilities?.experimental?.chioDeliveryAcknowledgement?.version !== "1") throw new Error("Host delivery contract required");
      const inventory = await rpc("inventory", "tools/list", {});
      if (JSON.stringify(inventory.tools?.map(tool => tool.name).sort()) !== JSON.stringify([...options.allowedTools].sort())) throw new Error("Gateway inventory differs from operator allowlist");
    })();
  }
  return async (request, {signal} = {}) => {
    if (unresolved) return {state: "unknown", evidence: "unverified", requestId: request.requestId, reason: "Prior host outcome remains unresolved; no automatic retry"};
    if (signal?.aborted || !options.allowedTools.includes(request.tool)) return {state: "not_dispatched", evidence: "unverified", requestId: request.requestId, reason: "Cancelled or outside operator tool allowlist"};
    try {
      await initialize();
      const expected = request.tool === "chio_resume" ? request.arguments.requestId : `${options.gatewaySessionId}:${createHash("sha256").update(JSON.stringify({id: `${session}:${JSON.stringify(request.requestId)}`})).digest("hex")}`;
      const raw = await rpc(request.requestId, "tools/call", {name: request.tool, arguments: request.arguments}, signal);
      if (raw.content?.length !== 1 || raw.content[0].type !== "text") throw new Error("Missing gateway result");
      const outcome = JSON.parse(raw.content[0].text);
      if (outcome.requestId !== expected) throw new Error("Gateway result belongs to another host operation");
      if (["not_dispatched", "awaiting_approval"].includes(outcome.state)) return outcome;
      if (!["completed", "denied"].includes(outcome.state) || outcome.evidence !== "verified") throw new Error("External outcome unresolved");
      const original = request.tool === "chio_resume" ? request.arguments : request;
      if (!verifyBoundReceipt(outcome.receipt, {subjectKey: options.subjectKey, capabilityId: options.capabilityId,
        serverId: options.serverId, trustedSigners: options.trustedSigners, tool: original.tool, parameters: original.arguments, requestId: expected})) throw new Error("Receipt differs from the intended caller, request or resource owner");
      if (outcome.state === "completed") {
        if (!verifyReceivedOutcome(outcome, {...options, tool: original.tool, parameters: original.arguments, requestId: expected})) throw new Error("Received output differs from signed terminal result");
        // Acknowledge in the trusted model relay after OpenClaw records and
        // echoes this verified tool result, never inside the guest tool call.
      }
      return outcome;
    } catch {
      unresolved = true;
      return {state: "unknown", evidence: "unverified", requestId: request.requestId, reason: "Gateway transport, evidence or host delivery failed; preserve original operation"};
    }
  };
}
