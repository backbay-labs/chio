import assert from "node:assert/strict";
import http from "node:http";
import { PassThrough } from "node:stream";
import test from "node:test";

import { createApp } from "./server.mjs";

async function requestJson(app, method, path, payload) {
  return new Promise((resolve, reject) => {
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const headers =
      body === undefined
        ? {}
        : {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(body).toString(),
          };

    const req = new http.IncomingMessage(new PassThrough());
    req.method = method;
    req.url = path;
    req.headers = headers;

    const res = new http.ServerResponse(req);
    const chunks = [];
    res.write = (chunk, encoding, callback) => {
      if (chunk !== undefined) {
        chunks.push(
          Buffer.isBuffer(chunk)
            ? chunk
            : Buffer.from(chunk, typeof encoding === "string" ? encoding : undefined),
        );
      }
      if (typeof encoding === "function") {
        encoding();
      }
      if (typeof callback === "function") {
        callback();
      }
      return true;
    };
    res.end = (chunk, encoding, callback) => {
      if (chunk !== undefined) {
        chunks.push(
          Buffer.isBuffer(chunk)
            ? chunk
            : Buffer.from(chunk, typeof encoding === "string" ? encoding : undefined),
        );
      }
      if (typeof encoding === "function") {
        encoding();
      }
      if (typeof callback === "function") {
        callback();
      }
      res.emit("finish");
      return res;
    };
    res.once("finish", () => {
      const text = Buffer.concat(chunks).toString("utf-8");
      resolve({
        status: res.statusCode ?? 0,
        body: text.length === 0 ? null : JSON.parse(text),
      });
    });
    app.handle(req, res, reject);
    if (body !== undefined) {
      req.push(body);
    }
    req.push(null);
  });
}

test("healthz route bypass shape", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "GET", "/healthz");

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { status: "ok" });
});

test("hello route returns no receipt without middleware", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "GET", "/hello");

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    message: "hello from express",
    receipt_id: null,
  });
});

test("echo defaults count and reports raw body absence without middleware", async () => {
  const app = createApp({ enableChio: false });
  const response = await requestJson(app, "POST", "/echo", {
    message: "hello",
  });

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, {
    message: "hello",
    count: 1,
    receipt_id: null,
    has_raw_body: false,
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
