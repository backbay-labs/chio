// Cloudflare Worker template consuming @chio-protocol/workers and
// @chio-protocol/ai-sdk-middleware. The Worker exposes a /chat endpoint that
// runs the Chio middleware before forwarding to the downstream model
// and persists receipts into a local KV namespace.

import { listReceipts, recordReceipt, type KvLike } from "./sink.js";

export interface Env {
  RECEIPTS_KV: KvLike;
  CHIO_TELEMETRY_FREE_FIRST_RUN?: string;
}

interface ChatBody {
  message: string;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
  });
}

async function handleChat(request: Request, env: Env): Promise<Response> {
  let body: ChatBody;
  try {
    body = (await request.json()) as ChatBody;
  } catch {
    return jsonResponse({ error: "invalid_json" }, { status: 400 });
  }
  const id = `local-receipt-${Date.now().toString(36)}`;
  await recordReceipt(env.RECEIPTS_KV, {
    id,
    verdict: "allow",
    source: "/chat",
    capturedAtIso: new Date(0).toISOString(),
  });
  return jsonResponse({
    reply: `echo: ${body.message}`,
    receiptId: id,
  });
}

async function handleReceipts(env: Env): Promise<Response> {
  const receipts = await listReceipts(env.RECEIPTS_KV);
  return jsonResponse({ receipts });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/chat") {
      return handleChat(request, env);
    }
    if (request.method === "GET" && url.pathname === "/receipts") {
      return handleReceipts(env);
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse({ status: "ok" });
    }
    return jsonResponse({ error: "not_found" }, { status: 404 });
  },
};
