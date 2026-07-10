import { createHash } from "node:crypto";
import http, { type IncomingHttpHeaders } from "node:http";
import { PassThrough } from "node:stream";
import { describe, it, expect } from "vitest";
import {
  buildChioHttpRequest,
  interceptNodeRequest,
  interceptWebRequest,
  resolveConfig,
} from "../src/interceptor.js";
import type { BuildRequestOptions } from "../src/interceptor.js";
import type { EvaluateResponse } from "../src/types.js";

function allowResponse(): EvaluateResponse {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id: "rcpt-1",
      request_id: "req-1",
      route_pattern: "/upload",
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
  onEvaluate?: (body: string, headers: IncomingHttpHeaders) => void,
): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/chio/evaluate") {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        onEvaluate?.(Buffer.concat(chunks).toString("utf-8"), req.headers);
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

    if (req.method === "GET" && req.url === "/chio/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "healthy", version: "1.0.0" }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (address == null || typeof address === "string") {
    throw new Error("server not listening");
  }

  return {
    server,
    url: `http://127.0.0.1:${address.port}`,
  };
}

async function request(
  server: http.Server,
  method: string,
  path: string,
  body?: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string; headers: IncomingHttpHeaders }> {
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

describe("buildChioHttpRequest", () => {
  it("creates a valid ChioHttpRequest", () => {
    const opts: BuildRequestOptions = {
      method: "GET",
      path: "/pets/42",
      query: { verbose: "true" },
      headers: {
        "content-type": "application/json",
        authorization: "Bearer token",
        "x-custom": "value",
      },
      caller: {
        subject: "test-user",
        auth_method: { method: "anonymous" },
        verified: false,
      },
      bodyHash: undefined,
      bodyLength: 0,
      routePattern: "/pets/{petId}",
      capabilityId: undefined,
    };

    const req = buildChioHttpRequest(opts);

    expect(req.method).toBe("GET");
    expect(req.path).toBe("/pets/42");
    expect(req.route_pattern).toBe("/pets/{petId}");
    expect(req.query).toEqual({ verbose: "true" });
    expect(req.caller.subject).toBe("test-user");
    expect(req.body_hash).toBeUndefined();
    expect(req.body_length).toBe(0);
    expect(req.request_id).toBeTruthy();
    expect(req.timestamp).toBeGreaterThan(0);
  });

  it("filters headers to only allowed set", () => {
    const opts: BuildRequestOptions = {
      method: "POST",
      path: "/pets",
      query: {},
      headers: {
        "content-type": "application/json",
        authorization: "Bearer secret",
        "x-chio-capability": "{\"id\":\"cap-123\"}",
        "x-custom-header": "should-not-appear",
      },
      caller: {
        subject: "anonymous",
        auth_method: { method: "anonymous" },
        verified: false,
      },
      bodyHash: "abc123",
      bodyLength: 42,
      routePattern: "/pets",
      capabilityId: "cap-123",
    };

    const req = buildChioHttpRequest(opts);

    expect(req.headers["content-type"]).toBe("application/json");
    expect(req.headers["x-chio-capability"]).toBeUndefined();
    // Authorization should NOT be forwarded (not in allowed set)
    expect(req.headers["authorization"]).toBeUndefined();
    // Custom headers should NOT be forwarded
    expect(req.headers["x-custom-header"]).toBeUndefined();
    expect(req.body_hash).toBe("abc123");
    expect(req.body_length).toBe(42);
    expect(req.capability_id).toBe("cap-123");
  });

  it("honors custom forwarded headers", () => {
    const opts: BuildRequestOptions = {
      method: "GET",
      path: "/tenant",
      query: {},
      headers: {
        "content-type": "application/json",
        "x-tenant-id": "tenant-a",
        authorization: "Bearer secret",
      },
      caller: {
        subject: "anonymous",
        auth_method: { method: "anonymous" },
        verified: false,
      },
      bodyHash: undefined,
      bodyLength: 0,
      routePattern: "/tenant",
      capabilityId: undefined,
      forwardHeaders: ["content-type", "x-tenant-id"],
    };

    const req = buildChioHttpRequest(opts);

    expect(req.headers["content-type"]).toBe("application/json");
    expect(req.headers["x-tenant-id"]).toBe("tenant-a");
    expect(req.headers["authorization"]).toBeUndefined();
  });

  it("filters credential headers from custom forwarded header allowlists", () => {
    const opts: BuildRequestOptions = {
      method: "POST",
      path: "/pets",
      query: {},
      headers: {
        "content-type": "application/json",
        cookie: "sid=secret",
        authorization: "Bearer policy-token",
        "x-api-key": "api-key-secret",
        "x-chio-capability": "{\"id\":\"cap-123\"}",
        "x-chio-capability-token": "cap-token-secret",
        "x-tenant-id": "tenant-a",
      },
      caller: {
        subject: "anonymous",
        auth_method: { method: "anonymous" },
        verified: false,
      },
      bodyHash: undefined,
      bodyLength: 0,
      routePattern: "/pets",
      capabilityId: undefined,
      forwardHeaders: [
        "authorization",
        "cookie",
        "x-api-key",
        "x-chio-capability",
        "x-chio-capability-token",
        "x-tenant-id",
      ],
    };

    const req = buildChioHttpRequest(opts);

    expect(req.headers).toEqual({
      "x-tenant-id": "tenant-a",
    });
  });
});

describe("resolveConfig", () => {
  it("applies defaults when no config provided", () => {
    const resolved = resolveConfig({});

    expect(resolved.onSidecarError).toBe("deny");
    expect(resolved.timeoutMs).toBe(5000);
    expect(resolved.forwardHeaders).toEqual([
      "content-type",
      "content-length",
    ]);
    expect(resolved.identityExtractor).toBeDefined();
    expect(resolved.routePatternResolver).toBeDefined();
    expect(resolved.client).toBeDefined();
  });

  it("returns a fresh default header list", () => {
    const first = resolveConfig({});
    first.forwardHeaders.push("authorization");

    expect(resolveConfig({}).forwardHeaders).toEqual([
      "content-type",
      "content-length",
    ]);
  });

  it("coerces fail-open sidecar errors to fail-closed", () => {
    const resolved = resolveConfig({ onSidecarError: "allow" });
    expect(resolved.onSidecarError).toBe("deny");
  });

  it("returns a fresh default forwarded header list", () => {
    const first = resolveConfig({});
    first.forwardHeaders.push("authorization");

    const second = resolveConfig({});
    expect(second.forwardHeaders).toEqual([
      "content-type",
      "content-length",
    ]);
  });

  it("uses custom timeout", () => {
    const resolved = resolveConfig({ timeoutMs: 10000 });
    expect(resolved.timeoutMs).toBe(10000);
  });

  it("stores custom forwarded headers", () => {
    const resolved = resolveConfig({ forwardHeaders: ["x-tenant-id"] });
    expect(resolved.forwardHeaders).toEqual(["x-tenant-id"]);
  });
});

describe("request body preservation", () => {
  it("decodes plus signs in query parameters like URLSearchParams", async () => {
    let observedQuery: Record<string, string> | undefined;
    const sidecar = await startMockSidecar((body) => {
      observedQuery = JSON.parse(body).query as Record<string, string>;
    });
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });

    const server = http.createServer(async (req, res) => {
      const outcome = await interceptNodeRequest(req, res, resolved);
      if (outcome.responseSent) {
        return;
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const response = await request(server, "GET", "/search?q=hello+world&flag");
      expect(response.status).toBe(200);
      expect(observedQuery).toEqual({ q: "hello world", flag: "" });
    } finally {
      server.close();
      sidecar.server.close();
    }
  });

  it("allows known-empty parsed bodies to evaluate as empty requests", async () => {
    let observed: { body_hash?: string; body_length?: number } | undefined;
    const sidecar = await startMockSidecar((body) => {
      observed = JSON.parse(body) as { body_hash?: string; body_length?: number };
    });
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });

    const server = http.createServer(async (req, res) => {
      (req as http.IncomingMessage & { body?: unknown }).body = {};

      const outcome = await interceptNodeRequest(req, res, resolved);
      if (outcome.responseSent) {
        return;
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const response = await request(server, "GET", "/empty");
      expect(response.status).toBe(200);
      expect(observed?.body_length).toBe(0);
      expect(observed).not.toHaveProperty("body_hash");
    } finally {
      server.close();
      sidecar.server.close();
    }
  });

  it("preserves IncomingMessage bodies for downstream consumers", async () => {
    const sidecar = await startMockSidecar();
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });

    const server = http.createServer(async (req, res) => {
      const outcome = await interceptNodeRequest(req, res, resolved);
      if (outcome.responseSent) {
        return;
      }
      expect(outcome.result).not.toBeNull();
      expect(outcome.passthrough).toBeNull();

      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(Buffer.concat(chunks).toString("utf-8"));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const response = await request(
        server,
        "POST",
        "/upload",
        "hello world",
        { "content-type": "text/plain" },
      );
      expect(response.status).toBe(200);
      expect(response.body).toBe("hello world");
    } finally {
      server.close();
      sidecar.server.close();
    }
  });

  it("does not hang when the request stream was already consumed", async () => {
    let evaluateCalls = 0;
    const sidecar = await startMockSidecar(() => {
      evaluateCalls += 1;
    });
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });

    const server = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        void (async () => {
          const outcome = await interceptNodeRequest(req, res, resolved);
          if (outcome.responseSent) {
            return;
          }
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("ok");
        })().catch((error: unknown) => {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end(error instanceof Error ? error.message : String(error));
        });
      });
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const body = "already consumed";
      const response = await request(
        server,
        "POST",
        "/upload",
        body,
        {
          "content-length": String(Buffer.byteLength(body)),
          "content-type": "text/plain",
        },
      );
      expect(response.status).toBe(400);
      expect(JSON.parse(response.body)).toMatchObject({
        error: "chio_evaluation_failed",
      });
      expect(evaluateCalls).toBe(0);
    } finally {
      server.close();
      sidecar.server.close();
    }
  });

  it("fails closed when a chunked request stream was already consumed", async () => {
    let evaluateCalls = 0;
    const sidecar = await startMockSidecar(() => {
      evaluateCalls += 1;
    });
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });

    const server = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        void (async () => {
          const outcome = await interceptNodeRequest(req, res, resolved);
          if (outcome.responseSent) {
            return;
          }
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("ok");
        })().catch((error: unknown) => {
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end(error instanceof Error ? error.message : String(error));
        });
      });
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const response = await request(
        server,
        "POST",
        "/upload",
        "already consumed",
        { "content-type": "text/plain" },
      );
      expect(response.status).toBe(400);
      expect(JSON.parse(response.body)).toMatchObject({
        error: "chio_evaluation_failed",
      });
      expect(evaluateCalls).toBe(0);
    } finally {
      server.close();
      sidecar.server.close();
    }
  });

  it("reads complete but not drained IncomingMessage bodies", async () => {
    let lastEvaluateBody: string | undefined;
    const sidecar = await startMockSidecar((body) => {
      lastEvaluateBody = body;
    });
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });
    const body = "complete body";
    const req = new PassThrough() as PassThrough & http.IncomingMessage;
    req.method = "POST";
    req.url = "/upload";
    req.headers = { "content-type": "text/plain" };
    Object.defineProperty(req, "complete", {
      configurable: true,
      value: true,
    });
    req.end(body);
    const res = new http.ServerResponse(req);

    try {
      const outcome = await interceptNodeRequest(req, res, resolved);
      expect(outcome.responseSent).toBe(false);

      const parsed = JSON.parse(lastEvaluateBody ?? "{}") as {
        body_hash?: string;
        body_length?: number;
      };
      expect(parsed.body_length).toBe(Buffer.byteLength(body));
      expect(parsed.body_hash).toBe(
        createHash("sha256").update(Buffer.from(body, "utf-8")).digest("hex"),
      );

      const replayed: Buffer[] = [];
      for await (const chunk of req) {
        replayed.push(Buffer.from(chunk));
      }
      expect(Buffer.concat(replayed).toString("utf-8")).toBe(body);
    } finally {
      sidecar.server.close();
    }
  });

  it("preserves Web Request bodies by reading from a clone", async () => {
    let lastBodyHash: string | undefined;
    const sidecar = await startMockSidecar((body) => {
      lastBodyHash = JSON.parse(body).body_hash as string | undefined;
    });
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });

    try {
      const request = new Request("http://example.com/upload?kind=text", {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "hello web",
      });

      const { response, result, passthrough } = await interceptWebRequest(request, resolved);
      expect(response.status).toBe(200);
      expect(result).not.toBeNull();
      expect(passthrough).toBeNull();
      expect(await request.text()).toBe("hello web");
      expect(lastBodyHash).toBe(
        createHash("sha256").update(Buffer.from("hello web", "utf-8")).digest("hex"),
      );
    } finally {
      sidecar.server.close();
    }
  });

  it("forwards configured Node request headers to the sidecar", async () => {
    let lastEvaluateBody: string | undefined;
    const sidecar = await startMockSidecar((body) => {
      lastEvaluateBody = body;
    });
    const resolved = resolveConfig({
      sidecarUrl: sidecar.url,
      forwardHeaders: ["content-type", "x-tenant-id"],
    });

    const server = http.createServer(async (req, res) => {
      const outcome = await interceptNodeRequest(req, res, resolved);
      if (outcome.responseSent) {
        return;
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const response = await request(
        server,
        "GET",
        "/tenant",
        undefined,
        { "content-type": "application/json", "x-tenant-id": "tenant-a" },
      );
      expect(response.status).toBe(200);
      expect(lastEvaluateBody).toBeDefined();
      const evaluated = JSON.parse(lastEvaluateBody ?? "{}") as { headers: Record<string, string> };
      expect(evaluated.headers["x-tenant-id"]).toBe("tenant-a");
      expect(evaluated.headers["content-type"]).toBe("application/json");
    } finally {
      server.close();
      sidecar.server.close();
    }
  });

  it("fails closed for Node sidecar errors even when fail-open is requested", async () => {
    const resolved = resolveConfig({
      sidecarUrl: "http://127.0.0.1:1",
      onSidecarError: "allow",
      timeoutMs: 200,
    });

    const server = http.createServer(async (req, res) => {
      const outcome = await interceptNodeRequest(req, res, resolved);
      expect(outcome.responseSent).toBe(true);
      expect(outcome.result).toBeNull();
      expect(outcome.passthrough).toBeNull();
      expect(res.getHeader("X-Chio-Receipt-Id")).toBeUndefined();
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const response = await request(server, "GET", "/health");
      expect(response.status).toBe(502);
      expect(response.headers["x-chio-receipt-id"]).toBeUndefined();
    } finally {
      server.close();
    }
  });

  it("returns a controlled error for malformed Node query encoding", async () => {
    const resolved = resolveConfig({
      sidecarUrl: "http://127.0.0.1:1",
      timeoutMs: 200,
    });
    let handlerReached = false;

    const server = http.createServer(async (req, res) => {
      const outcome = await interceptNodeRequest(req, res, resolved);
      if (!outcome.responseSent) {
        handlerReached = true;
        res.writeHead(200);
        res.end("handler");
      }
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const response = await request(server, "GET", "/test?bad=%E0%A4%A");
      expect(response.status).toBe(400);
      expect(JSON.parse(response.body).message).toBe("malformed query parameter encoding");
      expect(handlerReached).toBe(false);
    } finally {
      server.close();
    }
  });

  it("fails closed for Web sidecar errors even when fail-open is requested", async () => {
    const resolved = resolveConfig({
      sidecarUrl: "http://127.0.0.1:1",
      onSidecarError: "allow",
      timeoutMs: 200,
    });

    const { response, result, passthrough } = await interceptWebRequest(
      new Request("http://example.com/health", { method: "GET" }),
      resolved,
    );

    expect(response.status).toBe(502);
    expect(result).toBeNull();
    expect(passthrough).toBeNull();
    expect(response.headers.get("X-Chio-Receipt-Id")).toBeNull();
  });

  it("forwards query capability tokens to the sidecar", async () => {
    let forwardedCapability: string | string[] | undefined;
    let evaluatedCapabilityId: string | undefined;
    const token = JSON.stringify({ id: "cap-query" });
    const sidecar = await startMockSidecar((body, headers) => {
      forwardedCapability = headers["x-chio-capability"];
      evaluatedCapabilityId = JSON.parse(body).capability_id as string | undefined;
    });
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });

    try {
      const { response } = await interceptWebRequest(
        new Request(`http://example.com/upload?chio_capability=${encodeURIComponent(token)}`, {
          method: "GET",
        }),
        resolved,
      );

      expect(response.status).toBe(200);
      expect(forwardedCapability).toBe(token);
      expect(evaluatedCapabilityId).toBe("cap-query");
    } finally {
      sidecar.server.close();
    }
  });

  it("denies duplicate query capability tokens before sidecar evaluation", async () => {
    let called = false;
    const sidecar = await startMockSidecar(() => {
      called = true;
    });
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });

    try {
      const { response, result } = await interceptWebRequest(
        new Request("http://example.com/upload?chio_capability=a&chio_capability=b", {
          method: "GET",
        }),
        resolved,
      );

      expect(response.status).toBe(403);
      expect(result).toBeNull();
      expect(called).toBe(false);
    } finally {
      sidecar.server.close();
    }
  });

  it("fails closed when Web request bodies cannot be cloned", async () => {
    const sidecar = await startMockSidecar();
    const resolved = resolveConfig({ sidecarUrl: sidecar.url });
    const request = new Request("http://example.com/upload", {
      method: "POST",
      body: "already consumed",
    });
    await request.text();

    try {
      const { response, result, passthrough } = await interceptWebRequest(request, resolved);

      expect(response.status).toBe(502);
      expect(result).toBeNull();
      expect(passthrough).toBeNull();
    } finally {
      sidecar.server.close();
    }
  });
});
