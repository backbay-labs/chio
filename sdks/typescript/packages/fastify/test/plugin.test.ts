import { createHash } from "node:crypto";
import http from "node:http";
import { describe, it, expect } from "vitest";
import Fastify from "fastify";
import { chio } from "../src/index.js";
import type { EvaluateResponse } from "@chio-protocol/node-http";

function allowResponse(): EvaluateResponse {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id: "rcpt-1",
      request_id: "req-1",
      route_pattern: "/echo",
      method: "POST",
      caller_identity_hash: "a".repeat(64),
      verdict: { verdict: "allow" },
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      tool_origin: "caller_executed",
      redaction_mode: "none",
      trust_level: "mediated",
      evidence: [],
      response_status: 200,
      timestamp: 1_700_000_000,
      content_hash: "b".repeat(64),
      policy_hash: "c".repeat(64),
      kernel_key: "d".repeat(64),
      signature: "e".repeat(128),
    },
    evidence: [],
  };
}

function verifyResponse() {
  return {
    signature_valid: true,
    signer_trusted: true,
    receipt_id_valid: true,
    parameter_hash_valid: true,
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    trust_level: "mediated",
    result: "allow",
    authorized: true,
    signer_key_hex: "d".repeat(64),
    ok: true,
  };
}

async function startMockSidecar(
  onEvaluate?: (requestBody: string) => void,
): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/chio/evaluate") {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        onEvaluate?.(Buffer.concat(chunks).toString("utf-8"));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(allowResponse()));
      });
      return;
    }

    if (req.method === "POST" && req.url === "/chio/verify") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(verifyResponse()));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const addr = server.address();
  if (addr == null || typeof addr === "string") {
    throw new Error("sidecar not listening");
  }

  return {
    server,
    url: `http://127.0.0.1:${addr.port}`,
  };
}

describe("chio fastify plugin", () => {
  it("exports chio as a function", () => {
    expect(typeof chio).toBe("function");
  });

  it("registers without error", async () => {
    const fastify = Fastify();
    await fastify.register(chio, {
      sidecarUrl: "http://127.0.0.1:1",
      skip: ["/health"],
    });

    fastify.get("/health", async () => {
      return { ok: true };
    });

    // Verify the plugin registered successfully
    await fastify.ready();
    await fastify.close();
  });

  it("skipped routes bypass Chio evaluation", async () => {
    const fastify = Fastify();
    await fastify.register(chio, {
      sidecarUrl: "http://127.0.0.1:1", // Unreachable
      skip: ["/health"],
    });

    fastify.get("/health", async () => {
      return { ok: true };
    });

    const response = await fastify.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ ok: true });
    await fastify.close();
  });

  it("denies requests when sidecar is unreachable (fail-closed)", async () => {
    const fastify = Fastify();

    // Register Chio plugin
    await fastify.register(chio, {
      sidecarUrl: "http://127.0.0.1:1", // Unreachable
      timeoutMs: 1000,
    });

    fastify.get("/test", async (_request, _reply) => {
      return { data: "should not reach here" };
    });

    await fastify.ready();

    const response = await fastify.inject({
      method: "GET",
      url: "/test",
    });

    // When the sidecar is unreachable and onSidecarError is "deny" (default),
    // the plugin should return 502.
    expect(response.statusCode).toBe(502);
    const body = JSON.parse(response.body);
    expect(body.error).toBe("chio_sidecar_unreachable");
    await fastify.close();
  });

  it("fails closed when reserved onSidecarError is allow", async () => {
    const fastify = Fastify();
    await fastify.register(chio, {
      sidecarUrl: "http://127.0.0.1:1", // Unreachable
      onSidecarError: "allow",
      timeoutMs: 500,
    });

    fastify.get("/test", async () => {
      return { data: "reached handler" };
    });

    const response = await fastify.inject({
      method: "GET",
      url: "/test",
    });

    expect(response.statusCode).toBe(502);
    expect(JSON.parse(response.body).error).toBe("chio_sidecar_unreachable");
    await fastify.close();
  });

  it("returns a controlled error for malformed query encoding", async () => {
    const fastify = Fastify();
    let handlerReached = false;
    await fastify.register(chio, {
      sidecarUrl: "http://127.0.0.1:1",
      timeoutMs: 500,
    });

    fastify.get("/test", async () => {
      handlerReached = true;
      return { data: "reached handler" };
    });

    const response = await fastify.inject({
      method: "GET",
      url: "/test?bad=%E0%A4%A",
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).message).toBe("malformed query parameter encoding");
    expect(handlerReached).toBe(false);
    await fastify.close();
  });

  it("skip patterns with regex work", async () => {
    const fastify = Fastify();
    await fastify.register(chio, {
      sidecarUrl: "http://127.0.0.1:1", // Unreachable
      skip: [/^\/internal\//],
    });

    fastify.get("/internal/status", async () => {
      return { status: "ok" };
    });

    const response = await fastify.inject({
      method: "GET",
      url: "/internal/status",
    });

    expect(response.statusCode).toBe(200);
    await fastify.close();
  });

  it("hashes the raw request bytes instead of reparsed JSON", async () => {
    let observedBodyHash: string | undefined;
    let observedBodyLength: number | undefined;
    const sidecar = await startMockSidecar((requestBody) => {
      const parsed = JSON.parse(requestBody) as { body_hash?: string; body_length?: number };
      observedBodyHash = parsed.body_hash;
      observedBodyLength = parsed.body_length;
    });

    const fastify = Fastify();
    await fastify.register(chio, {
      sidecarUrl: sidecar.url,
    });

    fastify.post("/echo", async (request) => request.body);

    const payload = '{\n  "hello": "world",\n  "count": 2\n}';
    const response = await fastify.inject({
      method: "POST",
      url: "/echo",
      headers: { "content-type": "application/json" },
      payload,
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ hello: "world", count: 2 });
    expect(observedBodyHash).toBe(
      createHash("sha256").update(Buffer.from(payload, "utf-8")).digest("hex"),
    );
    expect(observedBodyLength).toBe(Buffer.byteLength(payload));

    sidecar.server.close();
    await fastify.close();
  });

  it("forwards configured headers to Chio evaluation", async () => {
    let observedHeaders: Record<string, string> | undefined;
    const sidecar = await startMockSidecar((requestBody) => {
      const parsed = JSON.parse(requestBody) as { headers?: Record<string, string> };
      observedHeaders = parsed.headers;
    });

    const fastify = Fastify();
    await fastify.register(chio, {
      sidecarUrl: sidecar.url,
      forwardHeaders: ["content-type", "x-tenant-id"],
    });

    fastify.post("/tenant", async () => ({ ok: true }));

    const response = await fastify.inject({
      method: "POST",
      url: "/tenant",
      headers: {
        "content-type": "application/json",
        "x-tenant-id": "tenant-1",
        "x-secret": "drop-me",
      },
      payload: "{}",
    });

    expect(response.statusCode).toBe(200);
    expect(observedHeaders).toMatchObject({
      "content-type": "application/json",
      "x-tenant-id": "tenant-1",
    });
    expect(observedHeaders).not.toHaveProperty("x-secret");

    sidecar.server.close();
    await fastify.close();
  });

  it("decodes plus signs in query parameters like URLSearchParams", async () => {
    let observedQuery: Record<string, string> | undefined;
    const sidecar = await startMockSidecar((requestBody) => {
      const parsed = JSON.parse(requestBody) as { query?: Record<string, string> };
      observedQuery = parsed.query;
    });

    const fastify = Fastify();
    await fastify.register(chio, {
      sidecarUrl: sidecar.url,
    });

    fastify.get("/search", async () => ({ ok: true }));

    const response = await fastify.inject({
      method: "GET",
      url: "/search?q=hello+world&flag",
    });

    expect(response.statusCode).toBe(200);
    expect(observedQuery).toEqual({ q: "hello world", flag: "" });
    sidecar.server.close();
    await fastify.close();
  });
});
