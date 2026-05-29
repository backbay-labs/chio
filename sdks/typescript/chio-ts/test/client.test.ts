import test from "node:test";
import assert from "node:assert/strict";

import { ChioClient, ChioSession } from "../src/index.ts";

function streamResponse(chunks: string[], init?: ResponseInit): Response {
  const encoder = new TextEncoder();
  let index = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(encoder.encode(chunks[index] ?? ""));
      index += 1;
    },
  });
  return new Response(body, init);
}

test("ChioClient.initialize returns a ChioSession backed by the transport layer", async () => {
  const calls: Array<{ input: unknown; init: RequestInit | undefined }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    calls.push({ input, init });
    if (calls.length === 1) {
      return streamResponse(
        [
          "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"serverInfo\":{\"name\":\"Chio MCP Edge\"}}}\n\n",
        ],
        {
          status: 200,
          headers: {
            "content-type": "text/event-stream",
            "mcp-session-id": "session-1",
          },
        },
      );
    }

    return new Response("", { status: 202 });
  };

  const client = ChioClient.withStaticBearer("http://127.0.0.1:7777", "token", fetchImpl);
  const session = await client.initialize({
    clientInfo: {
      name: "chio-ts-test",
      version: "0.1.0",
    },
  });

  assert.ok(session instanceof ChioSession);
  assert.ok(session.handshake);
  assert.equal(session.sessionId, "session-1");
  assert.equal(session.protocolVersion, "2025-11-25");
  assert.equal(session.handshake?.initializeResponse.status, 200);
  assert.equal(session.handshake?.initializedResponse.status, 202);
  assert.equal(calls.length, 2);
});

test("ChioSession convenience helpers issue JSON-RPC requests with session state", async () => {
  const calls: Array<{ input: unknown; init: RequestInit | undefined }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    calls.push({ input, init });
    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        result: {
          tools: [{ name: "echo_text" }],
        },
      }),
      {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      },
    );
  };

  const session = new ChioSession({
    baseUrl: "http://127.0.0.1:7777",
    authToken: "token",
    sessionId: "session-1",
    protocolVersion: "2025-11-25",
    fetchImpl,
  });

  const result = await session.listTools();

  assert.deepEqual(result, {
    tools: [{ name: "echo_text" }],
  });
  assert.equal(String(calls[0]?.input), "http://127.0.0.1:7777/mcp");
  assert.deepEqual(calls[0]?.init?.headers, {
    Authorization: "Bearer token",
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Session-Id": "session-1",
    "MCP-Protocol-Version": "2025-11-25",
  });
});

test("ChioSession.sendEnvelope posts explicit JSON-RPC envelopes for nested callback responses", async () => {
  const calls: Array<{ input: unknown; init: RequestInit | undefined }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    calls.push({ input, init });
    return new Response("", { status: 202 });
  };

  const session = new ChioSession({
    baseUrl: "http://127.0.0.1:7777",
    authToken: "token",
    sessionId: "session-1",
    protocolVersion: "2025-11-25",
    fetchImpl,
  });

  await session.sendEnvelope({
    jsonrpc: "2.0",
    id: "edge-client-1",
    result: {
      roots: [{ uri: "file:///workspace/root", name: "root" }],
    },
  });

  assert.equal(String(calls[0]?.input), "http://127.0.0.1:7777/mcp");
  assert.equal(calls[0]?.init?.body, JSON.stringify({
    jsonrpc: "2.0",
    id: "edge-client-1",
    result: {
      roots: [{ uri: "file:///workspace/root", name: "root" }],
    },
  }));
});
