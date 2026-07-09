import http from "node:http";
import { describe, it, expect } from "vitest";
import { Elysia } from "elysia";
import { chio } from "../src/index.js";
import type { EvaluateResponse } from "@chio-protocol/node-http";

function allowResponse(): EvaluateResponse {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id: "rcpt-1",
      request_id: "req-1",
      route_pattern: "/tenant",
      method: "GET",
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

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address == null || typeof address === "string") {
    throw new Error("mock sidecar did not bind to a TCP port");
  }
  return { server, url: `http://127.0.0.1:${address.port}` };
}

describe("chio elysia plugin", () => {
  it("exports chio as a function", () => {
    expect(typeof chio).toBe("function");
  });

  it("returns an Elysia instance", () => {
    const plugin = chio({});
    expect(plugin).toBeInstanceOf(Elysia);
  });

  it("skip patterns bypass evaluation", async () => {
    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: "http://127.0.0.1:1", // Unreachable
          skip: ["/health"],
        }),
      )
      .get("/health", () => ({ ok: true }));

    const response = await app.handle(
      new Request("http://localhost/health", { method: "GET" }),
    );

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({ ok: true });
  });

  it("denies requests when sidecar is unreachable (fail-closed)", async () => {
    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: "http://127.0.0.1:1", // Unreachable
          timeoutMs: 500,
        }),
      )
      .get("/test", () => ({ data: "should not reach here" }));

    const response = await app.handle(
      new Request("http://localhost/test", { method: "GET" }),
    );

    expect(response.status).toBe(502);
    const body = await response.json();
    expect(body.error).toBe("chio_sidecar_unreachable");
  });

  it("fails closed when reserved onSidecarError is allow", async () => {
    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: "http://127.0.0.1:1", // Unreachable
          onSidecarError: "allow",
          timeoutMs: 500,
        }),
      )
      .get("/test", () => ({ data: "reached handler" }));

    const response = await app.handle(
      new Request("http://localhost/test", { method: "GET" }),
    );

    expect(response.status).toBe(502);
    const body = await response.json();
    expect(body.error).toBe("chio_sidecar_unreachable");
  });

  it("skip patterns with regex work", async () => {
    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: "http://127.0.0.1:1", // Unreachable
          skip: [/^\/internal\//],
        }),
      )
      .get("/internal/status", () => ({ status: "ok" }));

    const response = await app.handle(
      new Request("http://localhost/internal/status", { method: "GET" }),
    );

    expect(response.status).toBe(200);
  });

  it("forwards configured headers to Chio evaluation", async () => {
    let observedHeaders: Record<string, string> | undefined;
    const sidecar = await startMockSidecar((requestBody) => {
      const parsed = JSON.parse(requestBody) as { headers?: Record<string, string> };
      observedHeaders = parsed.headers;
    });

    const app = new Elysia()
      .use(
        chio({
          sidecarUrl: sidecar.url,
          forwardHeaders: ["content-type", "x-tenant-id"],
        }),
      )
      .get("/tenant", () => ({ ok: true }));

    try {
      const response = await app.handle(
        new Request("http://localhost/tenant", {
          method: "GET",
          headers: {
            "content-type": "application/json",
            "x-tenant-id": "tenant-a",
            "x-secret": "do-not-forward",
          },
        }),
      );

      expect(response.status).toBe(200);
      expect(observedHeaders?.["content-type"]).toBe("application/json");
      expect(observedHeaders?.["x-tenant-id"]).toBe("tenant-a");
      expect(observedHeaders?.["x-secret"]).toBeUndefined();
    } finally {
      sidecar.server.close();
    }
  });
});
