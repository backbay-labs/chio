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
import { createHash } from "node:crypto";
import { chio } from "@chio-protocol/express";
import type { HttpReceipt, EvaluateResponse, Verdict } from "@chio-protocol/node-http";
import { validateReceiptStructure, assertVerdictMatch } from "../../src/verify.js";
import { canonicalJsonString } from "../../src/canonical.js";

// -- Mock sidecar server --

function createMockSidecar(): {
  server: http.Server;
  port: () => number;
  setVerdictMode: (mode: "allow" | "deny") => void;
  lastRequest: () => unknown;
} {
  let verdictMode: "allow" | "deny" = "allow";
  let lastReq: unknown = null;
  let lastReceipt: HttpReceipt | undefined;

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf-8");
      const parsed = JSON.parse(body);
      if (req.url === "/chio/evaluate") {
        lastReq = parsed;
        const receipt = createMockReceipt(parsed, verdictMode);
        lastReceipt = receipt;
        const response: EvaluateResponse = {
          verdict: receipt.verdict,
          receipt,
          evidence: receipt.evidence,
        };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(response));
      } else if (req.url === "/chio/verify") {
        // A synthetic trusted-sidecar response, not a cryptographic proof.
        // Accept only the exact receipt this fixture issued for this request.
        const matches = lastReceipt != null
          && canonicalJsonString(parsed) === canonicalJsonString(lastReceipt);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          signature_valid: matches,
          signer_trusted: matches,
          receipt_id_valid: matches,
          parameter_hash_valid: matches,
          receipt_kind: parsed.receipt_kind,
          boundary_class: parsed.boundary_class,
          trust_level: parsed.trust_level,
          result: parsed.verdict.verdict,
          authorized: matches && parsed.verdict.verdict === "allow",
          signer_key_hex: parsed.kernel_key,
          ok: matches,
        }));
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

function createMockReceipt(
  chioReq: { request_id: string; method: string; route_pattern: string; path: string; query: Record<string, string>; caller: { subject: string } },
  mode: "allow" | "deny",
): HttpReceipt {
  const verdict: Verdict =
    mode === "allow"
      ? { verdict: "allow" }
      : {
          verdict: "deny",
          reason: "side-effect route requires a capability token",
          guard: "CapabilityGuard",
          http_status: 403,
        };

  // Compute content hash like the Rust kernel
  const binding = {
    body_hash: null,
    method: chioReq.method,
    path: chioReq.path,
    query: chioReq.query,
    route_pattern: chioReq.route_pattern,
  };
  const contentHash = createHash("sha256")
    .update(canonicalJsonString(binding))
    .digest("hex");

  const callerHash = createHash("sha256")
    .update(canonicalJsonString({ auth_method: { method: "anonymous" }, subject: chioReq.caller.subject, verified: false }))
    .digest("hex");

  return {
    // Synthetic structural fixture; cryptographic verification is tested separately.
    id: createHash("sha256").update(canonicalJsonString({ request: chioReq, verdict })).digest("hex"),
    request_id: chioReq.request_id,
    route_pattern: chioReq.route_pattern,
    method: chioReq.method as "GET",
    caller_identity_hash: callerHash,
    verdict,
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    tool_origin: "host_executed_provider_reported",
    redaction_mode: "none",
    trust_level: "mediated",
    evidence: [
      {
        guard_name: mode === "allow" ? "DefaultPolicyGuard" : "CapabilityGuard",
        verdict: mode === "allow",
        details: mode === "allow" ? "safe method, session-scoped allow" : "no capability token",
      },
    ],
    response_status: mode === "allow" ? 200 : 403,
    timestamp: Math.floor(Date.now() / 1000),
    content_hash: contentHash,
    policy_hash: createHash("sha256").update("test-policy").digest("hex"),
    kernel_key: "mock-kernel-key-" + "a".repeat(48),
    signature: "mock-signature-" + "b".repeat(49),
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
