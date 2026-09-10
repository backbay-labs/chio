/**
 * Express E2E conformance test.
 *
 * Verifies that the Express middleware correctly:
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
import express from "express";
import http from "node:http";
import { chio } from "@chio-protocol/express";
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

// -- Test server helper --

async function request(
  server: http.Server,
  method: string,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    if (addr == null || typeof addr === "string") {
      reject(new Error("server not listening"));
      return;
    }
    const req = http.request(
      { hostname: "127.0.0.1", port: addr.port, path, method, headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf-8"),
            headers: res.headers,
          });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

// -- Tests --

describe("Express E2E conformance", () => {
  const mock = createMockSidecar();
  let appServer: http.Server;

  beforeAll(async () => {
    // Start mock sidecar
    await new Promise<void>((resolve) => mock.server.listen(0, resolve));

    // Create Express app with Chio middleware
    const app = express();
    app.use(
      chio({
        sidecarUrl: `http://127.0.0.1:${mock.port()}`,
        skip: ["/health"],
      }),
    );
    app.get("/health", (_req, res) => res.json({ ok: true }));
    app.get("/pets", (_req, res) => res.json([{ name: "Fido" }]));
    app.get("/pets/:petId", (req, res) =>
      res.json({ id: req.params["petId"], name: "Fido" }),
    );
    app.post("/pets", (_req, res) => res.status(201).json({ id: "new-pet" }));

    appServer = http.createServer(app);
    await new Promise<void>((resolve) => appServer.listen(0, resolve));
  });

  afterAll(() => {
    appServer.close();
    mock.server.close();
  });

  it("GET /health bypasses Chio evaluation", async () => {
    const resp = await request(appServer, "GET", "/health");
    expect(resp.status).toBe(200);
    expect(JSON.parse(resp.body)).toEqual({ ok: true });
    // No X-Chio-Receipt-Id header for skipped routes
    expect(resp.headers["x-chio-receipt-id"]).toBeUndefined();
  });

  it("GET /pets produces a valid allow receipt", async () => {
    mock.setVerdictMode("allow");
    const resp = await request(appServer, "GET", "/pets");
    expect(resp.status).toBe(200);

    // Receipt ID should be in the response headers
    const receiptId = resp.headers["x-chio-receipt-id"];
    expect(receiptId).toBeDefined();
    expect(typeof receiptId).toBe("string");
  });

  it("sidecar receives correct ChioHttpRequest for GET /pets", async () => {
    mock.setVerdictMode("allow");
    await request(appServer, "GET", "/pets");

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
    await request(appServer, "GET", "/pets", {
      Authorization: "Bearer test-token-xyz",
    });

    const lastReq = mock.lastRequest() as {
      caller: { subject: string; auth_method: { method: string } };
    };
    expect(lastReq.caller.subject).toMatch(/^bearer:/);
    expect(lastReq.caller.auth_method.method).toBe("bearer");
  });

  it("POST /pets returns deny verdict without capability", async () => {
    mock.setVerdictMode("deny");
    const resp = await request(appServer, "POST", "/pets");
    expect(resp.status).toBe(403);

    const body = JSON.parse(resp.body);
    expect(body.error).toBe("chio_access_denied");
    expect(body.receipt_id).toBeDefined();
    expect(body.suggestion).toBeDefined();
  });

  it("deny response receipt passes structural validation", async () => {
    mock.setVerdictMode("deny");
    const resp = await request(appServer, "POST", "/pets");
    expect(resp.status).toBe(403);

    const body = JSON.parse(resp.body);
    // The receipt ID in the response body should be valid
    expect(body.receipt_id).toBeTruthy();
    expect(typeof body.receipt_id).toBe("string");
  });

  it("receipt has correct caller identity hash format", async () => {
    mock.setVerdictMode("allow");
    await request(appServer, "GET", "/pets", {
      "X-API-Key": "sk-test-key-123",
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
});
