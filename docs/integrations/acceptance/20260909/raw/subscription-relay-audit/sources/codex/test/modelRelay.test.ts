import { test } from "node:test";
import assert from "node:assert/strict";
import { validateModelRequest, startModelRelay, chatGptCredential } from "../dist/cli/modelRelay.js";
const model = "gpt-5.5";
function request(): Record<string, unknown> {
  return {model, store: false, stream: true, input: [{role: "user", content: "Read the designated file"}],
    tools: [{type: "namespace", name: "mcp__chio", tools: [{type: "function", name: "read_text_file", parameters: {type: "object"}}]}]};
}
test("inline Chio context permits ordinary tools and strips account diagnostic writes", () => {
  const body = request(); body.client_metadata = {task: "local"};
  validateModelRequest(body, model); assert.equal(body.client_metadata, undefined);
});
test("hosted tools, remote MCP, alternate namespace and referenced account context are refused", () => {
  for (const tools of [[{type: "web_search"}], [{type: "mcp", server_url: "https://example.invalid"}],
    [{type: "namespace", name: "mcp__other", tools: [{type: "function", name: "write_file"}]}]]) {
    assert.throws(() => validateModelRequest({...request(), tools}, model));
  }
  for (const extra of [{previous_response_id: "resp_private"}, {conversation: "conv_private"}, {store: true}, {model: "other"},
    {input: [{type: "item_reference", id: "private"}]}, {input: [{role: "user", content: [{type: "input_file", file_id: "file_private"}]}]}]) {
    assert.throws(() => validateModelRequest({...request(), ...extra}, model));
  }
});
test("relay rejects wrong authority, origin, route and hosted tools before forwarding", async () => {
  const relay = await startModelRelay("unused-refusal-test-credential", model);
  try {
    for (const [path, headers, body] of [
      ["/v1/responses", {authorization: "Bearer wrong"}, request()],
      ["/v1/responses", {authorization: `Bearer ${relay.token}`, origin: "https://example.invalid"}, request()],
      ["/v1/files", {authorization: `Bearer ${relay.token}`}, request()],
      ["/v1/responses", {authorization: `Bearer ${relay.token}`}, {...request(), tools: [{type: "web_search"}]}],
    ] as const) {
      const response = await fetch(`http://127.0.0.1:${relay.port}${path}`, {method: "POST", headers, body: JSON.stringify(body)});
      assert.ok(response.status >= 400); await response.text();
    }
    assert.equal(relay.stats.forwarded, 0); assert.equal(relay.stats.requests, 4);
  } finally { await relay.close(); }
});
test("unverified received tool bytes are refused before the next provider turn", async () => {
  const received: unknown[][] = [];
  const relay = await startModelRelay("unused-rejection-test-credential", model, async outcomes => {
    received.push(outcomes);
    throw new Error("received result differs from trusted receipt");
  });
  try {
    const outcome = {state: "completed", evidence: "verified", result: "substituted"};
    for (const output of [JSON.stringify(outcome), [{type: "input_text", text: JSON.stringify(outcome)}],
      JSON.stringify({content: [{type: "text", text: JSON.stringify(outcome)}]})]) {
      const response = await fetch(`http://127.0.0.1:${relay.port}/v1/responses`, {
        method: "POST", headers: {authorization: `Bearer ${relay.token}`},
        body: JSON.stringify({...request(), input: [{type: "function_call_output", call_id: "call-1", output}]}),
      });
      assert.equal(response.status, 502); await response.text();
      assert.deepEqual(received.at(-1), [outcome]);
    }
    assert.equal(relay.stats.forwarded, 0);
  } finally { await relay.close(); }
});

test("native ChatGPT cache requires an unambiguous account credential and never accepts API fallback", () => {
  const cache = {tokens: {access_token: "local-test-token", account_id: "local-test-account", refresh_token: "must-not-be-forwarded"}};
  assert.deepEqual(chatGptCredential(cache), {kind: "chatgpt", secret: "local-test-token", accountId: "local-test-account"});
  for (const invalid of [null, {}, {...cache, auth_mode: "apikey"}, {...cache, OPENAI_API_KEY: "other"},
    {tokens: {access_token: "x"}}, {tokens: {access_token: "x\r\nInjected: value", account_id: "y"}}]) {
    assert.throws(() => chatGptCredential(invalid), /Native ChatGPT login cache required/);
  }
});
