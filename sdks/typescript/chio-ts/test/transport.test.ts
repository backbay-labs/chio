import test from "node:test";
import assert from "node:assert/strict";

import {
  buildRpcHeaders,
  buildSessionDeleteHeaders,
  initializeSession,
  parseRpcMessages,
  postRpc,
  readRpcMessagesUntilTerminal,
} from "../src/transport/index.ts";

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

test("parseRpcMessages parses a single JSON body", () => {
  assert.deepEqual(parseRpcMessages("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}"), [
    {
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    },
  ]);
});

test("parseRpcMessages parses text/event-stream bodies", () => {
  const rawBody = [
    "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"index\":1}}",
    "",
    "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}",
    "",
  ].join("\n");

  assert.deepEqual(parseRpcMessages(rawBody), [
    {
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { index: 1 },
    },
    {
      jsonrpc: "2.0",
      id: 7,
      result: { ok: true },
    },
  ]);
});

test("readRpcMessagesUntilTerminal stops after the matching terminal response", async () => {
  const seen: unknown[] = [];
  const response = streamResponse(
    [
      "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"index\":1}}\n\n",
      "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n",
      "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"index\":2}}\n\n",
    ],
    {
      status: 200,
      headers: {
        "content-type": "text/event-stream",
      },
    },
  );

  const messages = await readRpcMessagesUntilTerminal(response, 7, async (message) => {
    seen.push(message);
  });

  assert.deepEqual(messages, [
    {
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { index: 1 },
    },
    {
      jsonrpc: "2.0",
      id: 7,
      result: { ok: true },
    },
  ]);
  assert.deepEqual(seen, [
    {
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { index: 1 },
    },
  ]);
});

test("header helpers encode session and protocol state", () => {
  assert.deepEqual(buildRpcHeaders("token", "session-1", "2025-11-25"), {
    Authorization: "Bearer token",
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Session-Id": "session-1",
    "MCP-Protocol-Version": "2025-11-25",
  });
  assert.deepEqual(buildSessionDeleteHeaders("token", "session-1"), {
    Authorization: "Bearer token",
    "MCP-Session-Id": "session-1",
  });
});

test("postRpc sends JSON-RPC requests with MCP headers", async () => {
  const calls: Array<{ input: unknown; init: RequestInit | undefined }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    calls.push({ input, init });
    return new Response("{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"ok\":true}}", {
      status: 200,
      headers: {
        "content-type": "application/json",
        "mcp-session-id": "session-1",
      },
    });
  };

  const response = await postRpc(
    "http://127.0.0.1:7777",
    "token",
    "session-1",
    "2025-11-25",
    {
      jsonrpc: "2.0",
      id: 9,
      method: "tools/list",
    },
    async () => {},
    fetchImpl,
  );

  assert.equal(String(calls[0]?.input), "http://127.0.0.1:7777/mcp");
  assert.deepEqual(calls[0]?.init?.headers, {
    Authorization: "Bearer token",
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Session-Id": "session-1",
    "MCP-Protocol-Version": "2025-11-25",
  });
  assert.deepEqual(response.messages, [
    {
      jsonrpc: "2.0",
      id: 9,
      result: { ok: true },
    },
  ]);
});

test("initializeSession performs initialize and notifications/initialized", async () => {
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

    return streamResponse(
      [
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"ready\":true}}\n\n",
      ],
      {
        status: 202,
        headers: {
          "content-type": "text/event-stream",
        },
      },
    );
  };

  const nestedMessages: unknown[] = [];
  const initialized = await initializeSession(
    "http://127.0.0.1:7777",
    "token",
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: {
          name: "chio-conformance-js",
          version: "0.1.0",
        },
      },
    },
    async (message) => {
      nestedMessages.push(message);
    },
    fetchImpl,
  );

  assert.equal(initialized.sessionId, "session-1");
  assert.equal(initialized.protocolVersion, "2025-11-25");
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1]?.init?.headers, {
    Authorization: "Bearer token",
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Session-Id": "session-1",
    "MCP-Protocol-Version": "2025-11-25",
  });
  assert.deepEqual(nestedMessages, [
    {
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { ready: true },
    },
  ]);
});
