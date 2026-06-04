import assert from "node:assert/strict";
import test from "node:test";

import { createServer } from "./server.mjs";

async function withServer(callback) {
  const fastify = await createServer({ enableChio: false });
  try {
    await fastify.ready();
    await callback(fastify);
  } finally {
    await fastify.close();
  }
}

test("healthz route bypass shape", async () => {
  await withServer(async (fastify) => {
    const response = await fastify.inject({ method: "GET", url: "/healthz" });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), { status: "ok" });
  });
});

test("hello route returns no receipt without middleware", async () => {
  await withServer(async (fastify) => {
    const response = await fastify.inject({ method: "GET", url: "/hello" });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      message: "hello from fastify",
      receipt_id: null,
    });
  });
});

test("echo defaults count and reports parsed body availability", async () => {
  await withServer(async (fastify) => {
    const response = await fastify.inject({
      method: "POST",
      url: "/echo",
      payload: { message: "hello" },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      message: "hello",
      count: 1,
      receipt_id: null,
      body_cached: true,
    });
  });
});

test("echo rejects non-object bodies", async () => {
  await withServer(async (fastify) => {
    const response = await fastify.inject({
      method: "POST",
      url: "/echo",
      payload: ["hello"],
    });

    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), { error: "body must be a JSON object" });
  });
});

test("echo rejects empty messages", async () => {
  await withServer(async (fastify) => {
    const response = await fastify.inject({
      method: "POST",
      url: "/echo",
      payload: { message: "", count: 1 },
    });

    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), {
      error: "message must be a non-empty string",
    });
  });
});

test("echo rejects coerced counts", async () => {
  await withServer(async (fastify) => {
    const response = await fastify.inject({
      method: "POST",
      url: "/echo",
      payload: { message: "hello", count: "2" },
    });

    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), {
      error: "count must be an integer greater than or equal to 1",
    });
  });
});

test("echo rejects extra fields", async () => {
  await withServer(async (fastify) => {
    const response = await fastify.inject({
      method: "POST",
      url: "/echo",
      payload: { message: "hello", count: 1, admin: true },
    });

    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), { error: "unexpected fields: admin" });
  });
});
