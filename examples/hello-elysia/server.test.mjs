import assert from "node:assert/strict";
import test from "node:test";

import { createApp } from "./server.mjs";

async function requestJson(app, method, path, payload) {
  const body = payload === undefined ? undefined : JSON.stringify(payload);
  const response = await app.handle(
    new Request(`http://localhost${path}`, {
      method,
      headers:
        body === undefined
          ? undefined
          : {
              "content-type": "application/json",
            },
      body,
    }),
  );
  const text = await response.text();

  return {
    status: response.status,
    headers: response.headers,
    body: text.length === 0 ? null : JSON.parse(text),
  };
}

test("healthz route bypass shape", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "GET", "/healthz");

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { status: "ok" });
});

test("hello route returns no receipt header without plugin", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "GET", "/hello");

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-chio-receipt-id"), null);
  assert.deepEqual(response.body, { message: "hello from elysia" });
});

test("echo defaults count", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "POST", "/echo", {
    message: "hello",
  });

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    message: "hello",
    count: 1,
  });
});

test("echo rejects non-object bodies", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "POST", "/echo", ["hello"]);

  assert.equal(response.status, 400);
  assert.deepEqual(response.body, { error: "body must be a JSON object" });
});

test("echo rejects empty messages", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "POST", "/echo", {
    message: "",
    count: 1,
  });

  assert.equal(response.status, 400);
  assert.deepEqual(response.body, {
    error: "message must be a non-empty string",
  });
});

test("echo rejects coerced counts", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "POST", "/echo", {
    message: "hello",
    count: "2",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(response.body, {
    error: "count must be an integer greater than or equal to 1",
  });
});

test("echo rejects extra fields", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "POST", "/echo", {
    message: "hello",
    count: 1,
    admin: true,
  });

  assert.equal(response.status, 400);
  assert.deepEqual(response.body, { error: "unexpected fields: admin" });
});
