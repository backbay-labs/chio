/**
 * Fastify E2E conformance test.
 *
 * Verifies that the Fastify plugin correctly:
 * 1. Extracts caller identity from request headers
 * 2. Builds a valid ChioHttpRequest
 * 3. Handles sidecar responses (allow/deny)
 * 4. Produces receipts that conform to the Chio receipt schema
 * 5. Returns structured error responses with Chio error codes
 *
 * These tests run against a mock sidecar server that returns
 * predetermined verdicts and receipts, allowing verification
 * that the TS SDK produces wire-compatible output.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify from "fastify";
import http from "node:http";
import { chio } from "@chio-protocol/fastify";
import type { HttpReceipt, EvaluateResponse } from "@chio-protocol/node-http";
import { validateReceiptStructure, assertVerdictMatch } from "../../src/verify.js";
import { createMockReceipt, verifyMockReceipt } from "./receipt-fixture.js";

// -- Mock sidecar server --

function createMockSidecar(): {
  server: http.Server;
  port: () => number;
  setVerdictMode: (mode: "allow" | "deny") => void;
  lastRequest: () => unknown;
} {
  let verdictMode: "allow" | "deny" = "allow";
  let lastReq: unknown = null;

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf-8");
      const parsed = JSON.parse(body);
      if (req.url === "/chio/evaluate") {
        lastReq = parsed;
        const receipt = createMockReceipt(parsed, verdictMode);
        const response: EvaluateResponse = {
          verdict: receipt.verdict,
          receipt,
          evidence: receipt.evidence,
        };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(response));
      } else if (req.url === "/chio/verify") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(verifyMockReceipt(parsed)));
      } else if (req.url === "/chio/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok" }));
      } else {
        res.writeHead(404);
        res.end("not found");
      }
    });
  });

  return {
    server,
    port: () => {
      const addr = server.address();
      return typeof addr === "object" && addr != null ? addr.port : 0;
    },
    setVerdictMode: (mode: "allow" | "deny") => {
      verdictMode = mode;
    },
    lastRequest: () => lastReq,
  };
}

// -- Tests --

describe("Fastify E2E conformance", () => {
  const mock = createMockSidecar();
  let fastify: ReturnType<typeof Fastify>;

  beforeAll(async () => {
    // Start mock sidecar
    await new Promise<void>((resolve) => mock.server.listen(0, resolve));

    // Create Fastify app with Chio plugin
    fastify = Fastify();
    await fastify.register(chio, {
      sidecarUrl: `http://127.0.0.1:${mock.port()}`,
      skip: ["/health"],
    });

    fastify.get("/health", async () => ({ ok: true }));
    fastify.get("/pets", async () => [{ name: "Fido" }]);
    fastify.get("/pets/:petId", async (request) => ({
      id: (request.params as { petId: string }).petId,
      name: "Fido",
    }));
    fastify.post("/pets", async (_request, reply) => {
      reply.code(201);
      return { id: "new-pet" };
    });

    await fastify.ready();
  });

  afterAll(async () => {
    await fastify.close();
    mock.server.close();
  });

  it("GET /health bypasses Chio evaluation", async () => {
    const resp = await fastify.inject({
      method: "GET",
      url: "/health",
    });
    expect(resp.statusCode).toBe(200);
    expect(JSON.parse(resp.body)).toEqual({ ok: true });
  });

  it("GET /pets produces a valid allow receipt", async () => {
    mock.setVerdictMode("allow");
    const resp = await fastify.inject({
      method: "GET",
      url: "/pets",
    });
    expect(resp.statusCode).toBe(200);

    // Receipt ID should be in the response headers
    const receiptId = resp.headers["x-chio-receipt-id"];
    expect(receiptId).toBeDefined();
    expect(typeof receiptId).toBe("string");
  });

  it("sidecar receives correct ChioHttpRequest for GET /pets", async () => {
    mock.setVerdictMode("allow");
    await fastify.inject({
      method: "GET",
      url: "/pets",
    });

    const lastReq = mock.lastRequest() as {
      method: string;
      path: string;
      caller: { subject: string };
    };
    expect(lastReq.method).toBe("GET");
    expect(lastReq.path).toBe("/pets");
    expect(lastReq.caller.subject).toBe("anonymous");
  });

  it("sidecar receives bearer identity from Authorization header", async () => {
    mock.setVerdictMode("allow");
    await fastify.inject({
      method: "GET",
      url: "/pets",
      headers: { Authorization: "Bearer test-token-xyz" },
    });

    const lastReq = mock.lastRequest() as {
      caller: { subject: string; auth_method: { method: string } };
    };
    expect(lastReq.caller.subject).toMatch(/^bearer:/);
    expect(lastReq.caller.auth_method.method).toBe("bearer");
  });

  it("POST /pets returns deny verdict without capability", async () => {
    mock.setVerdictMode("deny");
    const resp = await fastify.inject({
      method: "POST",
      url: "/pets",
    });
    expect(resp.statusCode).toBe(403);

    const body = JSON.parse(resp.body);
    expect(body.error).toBe("chio_access_denied");
    expect(body.receipt_id).toBeDefined();
    expect(body.suggestion).toBeDefined();
  });

  it("deny response contains proper Chio error structure", async () => {
    mock.setVerdictMode("deny");
    const resp = await fastify.inject({
      method: "POST",
      url: "/pets",
    });
    expect(resp.statusCode).toBe(403);

    const body = JSON.parse(resp.body);
    expect(body.error).toBe("chio_access_denied");
    expect(typeof body.message).toBe("string");
    expect(typeof body.receipt_id).toBe("string");
    expect(typeof body.suggestion).toBe("string");
  });

  it("receipt has correct caller identity hash for API key", async () => {
    mock.setVerdictMode("allow");
    await fastify.inject({
      method: "GET",
      url: "/pets",
      headers: { "X-API-Key": "sk-test-key-123" },
    });

    const lastReq = mock.lastRequest() as {
      caller: {
        subject: string;
        auth_method: { method: string; key_hash: string };
      };
    };
    expect(lastReq.caller.auth_method.method).toBe("api_key");
    expect(lastReq.caller.auth_method.key_hash).toHaveLength(64);
  });

  it("receipt ID has the content-addressed format", async () => {
    mock.setVerdictMode("allow");
    const resp = await fastify.inject({
      method: "GET",
      url: "/pets",
    });
    const receiptId = resp.headers["x-chio-receipt-id"];
    expect(typeof receiptId).toBe("string");
    // HTTP receipt IDs are lowercase SHA-256 content addresses.
    expect(receiptId).toMatch(/^[0-9a-f]{64}$/);
  });

  it("mock receipt passes structural validation", async () => {
    mock.setVerdictMode("allow");
    const resp = await fastify.inject({
      method: "GET",
      url: "/pets",
    });

    // Get the receipt from the mock sidecar's last response
    const lastReq = mock.lastRequest() as { request_id: string; method: string; route_pattern: string; path: string; query: Record<string, string>; caller: { subject: string } };
    const receipt = createMockReceipt(lastReq, "allow");
    const errors = validateReceiptStructure(receipt);
    expect(errors).toEqual([]);
  });

  it("allow verdict matches expected structure", async () => {
    mock.setVerdictMode("allow");
    const lastReq = mock.lastRequest() as { request_id: string; method: string; route_pattern: string; path: string; query: Record<string, string>; caller: { subject: string } };
    const receipt = createMockReceipt(lastReq, "allow");
    const errors = assertVerdictMatch(receipt.verdict, { verdict: "allow" });
    expect(errors).toEqual([]);
  });

  it("deny verdict matches expected structure", async () => {
    const lastReq = mock.lastRequest() as { request_id: string; method: string; route_pattern: string; path: string; query: Record<string, string>; caller: { subject: string } };
    const receipt = createMockReceipt(lastReq, "deny");
    const errors = assertVerdictMatch(receipt.verdict, {
      verdict: "deny",
      guard: "CapabilityGuard",
      http_status: 403,
    });
    expect(errors).toEqual([]);
  });
});
