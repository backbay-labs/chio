import { describe, it, expect } from "vitest";
import express from "express";
import http from "node:http";
import { chio, chioErrorHandler } from "../src/index.js";
import type { EvaluateResponse } from "@chio-protocol/node-http";

// Helper to make HTTP requests to a test server
async function request(
  server: http.Server,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: string,
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    if (addr == null || typeof addr === "string") {
      reject(new Error("server not listening"));
      return;
    }
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: addr.port,
        path,
        method,
        headers,
      },
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
    if (body != null) {
      req.write(body);
    }
    req.end();
  });
}

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

async function startMockSidecar(): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/chio/evaluate") {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(allowResponse()));
      });
      return;
    }

    if (req.method === "POST" && req.url === "/chio/verify") {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(verifyResponse()));
      });
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

describe("chio() middleware", () => {
  it("exports chio as a function", () => {
    expect(typeof chio).toBe("function");
  });

  it("returns Express middleware (a function)", () => {
    const middleware = chio({});
    expect(typeof middleware).toBe("function");
  });

  it("skip patterns bypass evaluation", async () => {
    const app = express();
    app.use(
      chio({
        skip: ["/health", /^\/internal\//],
        sidecarUrl: "http://127.0.0.1:1", // Unreachable on purpose
      }),
    );
    app.get("/health", (_req, res) => {
      res.json({ ok: true });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const resp = await request(server, "GET", "/health");
      expect(resp.status).toBe(200);
      expect(JSON.parse(resp.body)).toEqual({ ok: true });
    } finally {
      server.close();
    }
  });

  it("denies requests when sidecar is unreachable (fail-closed)", async () => {
    const app = express();
    app.use(
      chio({
        sidecarUrl: "http://127.0.0.1:1", // Unreachable
        timeoutMs: 500,
      }),
    );
    app.get("/test", (_req, res) => {
      res.json({ data: "should not reach here" });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const resp = await request(server, "GET", "/test");
      expect(resp.status).toBe(502);
      const body = JSON.parse(resp.body);
      expect(body.error).toBe("chio_sidecar_unreachable");
    } finally {
      server.close();
    }
  });

  it("fails closed when legacy onSidecarError is allow", async () => {
    const app = express();
    app.use(
      chio({
        sidecarUrl: "http://127.0.0.1:1", // Unreachable
        onSidecarError: "allow",
        timeoutMs: 500,
      }),
    );
    app.get("/test", (req, res) => {
      const chioReq = req as import("../src/index.js").ChioRequest;
      res.json({
        hasChioResult: chioReq.chioResult != null,
        chioPassthrough: chioReq.chioPassthrough,
      });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const resp = await request(server, "GET", "/test");
      expect(resp.status).toBe(502);
      expect(resp.headers["x-chio-receipt-id"]).toBeUndefined();
      expect(JSON.parse(resp.body).error).toBe("chio_sidecar_unreachable");
    } finally {
      server.close();
    }
  });

  it("preserves request bodies for downstream Express parsers", async () => {
    const sidecar = await startMockSidecar();
    const app = express();
    app.use(chio({ sidecarUrl: sidecar.url }));
    app.use(express.json());
    app.post("/echo", (req, res) => {
      res.json({
        parsed: req.body,
        hasRawBody: Buffer.isBuffer((req as { rawBody?: unknown }).rawBody),
      });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const payload = JSON.stringify({ hello: "world", count: 2 });
      const resp = await request(
        server,
        "POST",
        "/echo",
        {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload).toString(),
        },
        payload,
      );
      expect(resp.status).toBe(200);
      expect(JSON.parse(resp.body)).toEqual({
        parsed: { hello: "world", count: 2 },
        hasRawBody: true,
      });
    } finally {
      server.close();
      sidecar.server.close();
    }
  });
});

describe("chioErrorHandler", () => {
  it("exports chioErrorHandler as a function", () => {
    expect(typeof chioErrorHandler).toBe("function");
  });
});
