import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  ChioClient,
  ChioToolError,
  chioTool,
  type ChioReceipt,
} from "../src/index.js";

// -- Helpers ---------------------------------------------------------------

interface FetchCall {
  url: string;
  body: unknown;
  headers: Record<string, string>;
}

/**
 * Build a fake `fetch` that records each call and returns a sequence of
 * pre-baked `Response` objects. Uses `Response` from the global Node
 * environment (Node >= 18).
 */
function fakeFetch(
  receipts: Array<ChioReceipt | Record<string, unknown> | { error: string; status: number }>,
): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  let i = 0;
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const body = init?.body != null ? JSON.parse(init.body as string) : null;
    const headers: Record<string, string> = {};
    const rawHeaders = init?.headers;
    if (rawHeaders != null && typeof rawHeaders === "object" && !Array.isArray(rawHeaders)) {
      for (const [k, v] of Object.entries(rawHeaders as Record<string, string>)) {
        headers[k.toLowerCase()] = v;
      }
    }
    calls.push({ url, body, headers });
    const next = receipts[i++];
    if (next == null) {
      throw new Error("fakeFetch: no more responses queued");
    }
    if ("error" in next) {
      return new Response(next.error, { status: next.status });
    }
    return new Response(JSON.stringify(next), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { fetch: impl, calls };
}

function throwingFetch(error: Error): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const body = init?.body != null ? JSON.parse(init.body as string) : null;
    const headers: Record<string, string> = {};
    const rawHeaders = init?.headers;
    if (rawHeaders != null && typeof rawHeaders === "object" && !Array.isArray(rawHeaders)) {
      for (const [k, v] of Object.entries(rawHeaders as Record<string, string>)) {
        headers[k.toLowerCase()] = v;
      }
    }
    calls.push({ url, body, headers });
    throw error;
  }) as typeof fetch;
  return { fetch: impl, calls };
}

function allowReceipt(id = "r-allow"): ChioReceipt {
  return {
    id,
    decision: { verdict: "allow" },
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    tool_origin: "caller_executed",
    redaction_mode: "none",
    trust_level: "mediated",
  };
}

function advisoryEvaluationResponse(id = "r-advisory"): Record<string, unknown> {
  return {
    schema: "chio.sidecar.advisory-evaluation.v1",
    authorization: false,
    authorizationBasis: "advisory_only",
    receipt: {
      id,
      receipt_kind: "advisory_evaluation",
      boundary_class: "advisory_only",
      observation_outcome: "evaluated",
      tool_origin: "host_executed_unmediated",
      redaction_mode: "none",
      trust_level: "advisory",
    },
  };
}

function advisoryReceipt(id = "r-advisory"): ChioReceipt {
  return {
    id,
    receipt_kind: "advisory_evaluation",
    boundary_class: "advisory_only",
    observation_outcome: "evaluated",
    tool_origin: "host_executed_unmediated",
    redaction_mode: "none",
    trust_level: "advisory",
  };
}

function denyReceipt(reason = "no permission", guard = "TestGuard", id = "r-deny"): ChioReceipt {
  return {
    id,
    decision: { verdict: "deny", reason, guard },
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    tool_origin: "caller_executed",
    redaction_mode: "none",
    trust_level: "mediated",
  };
}

function lambdaAllowReceipt(id = "r-allow"): Record<string, unknown> {
  return {
    receipt_id: id,
    decision: "allow",
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    capability_id: "cap-1",
    tool_server: "math",
    tool_name: "double",
    timestamp: 1_700_000_000,
  };
}

function sidecarAllowEvaluateResponse(id = "r-allow"): Record<string, unknown> {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id,
      decision: { verdict: "allow" },
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      tool_origin: "caller_executed",
      redaction_mode: "none",
      trust_level: "mediated",
      verdict: { verdict: "allow" },
      route_pattern: "/chio/tools/math/double",
      method: "POST",
    },
    evidence: [],
  };
}

/**
 * Mirror the canonical Rust `EvaluateResponse` wire shape: the receipt
 * carries `verdict` (tagged enum) and NO sibling `decision` field. The
 * normalizer must lift `verdict` into `decision` for `chioTool`.
 */
function sidecarVerdictOnlyAllowResponse(id = "r-allow"): Record<string, unknown> {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id,
      verdict: { verdict: "allow" },
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      tool_origin: "caller_executed",
      redaction_mode: "none",
      trust_level: "mediated",
      route_pattern: "/chio/tools/math/double",
      method: "POST",
    },
    evidence: [],
  };
}

/**
 * Verdict-only deny receipt as produced by the Rust HTTP sidecar:
 * `receipt.verdict` is `{"verdict":"deny", "reason":..., "guard":...,
 * "http_status":403}` with NO sibling `decision` field.
 */
function sidecarVerdictOnlyDenyResponse(
  reason = "not allowed",
  guard = "FsDenylist",
  id = "r-deny",
): Record<string, unknown> {
  return {
    verdict: { verdict: "deny", reason, guard, http_status: 403 },
    receipt: {
      id,
      verdict: { verdict: "deny", reason, guard, http_status: 403 },
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      tool_origin: "caller_executed",
      redaction_mode: "none",
      trust_level: "mediated",
      route_pattern: "/chio/tools/fs/read",
      method: "POST",
    },
    evidence: [],
  };
}

const CAPABILITY_TOKEN = JSON.stringify({
  id: "cap-1",
  issuer: "issuer-placeholder",
  subject: "subject-placeholder",
});

function trustedReceiptVerifier() {
  return {
    receipt_kind: "mediated_decision" as const,
    boundary_class: "prevent" as const,
    trust_level: "mediated" as const,
    result: "allow",
    authorized: true,
    ok: true,
    signer_trusted: true,
    signature_valid: true,
    receipt_id_valid: true,
    parameter_hash_valid: true,
  };
}

// -- chioTool: basic shape --------------------------------------------------

describe("chioTool: shape and type preservation", () => {
  it("returns a tool object with the same top-level fields", () => {
    const params = z.object({ q: z.string() });
    const { fetch } = fakeFetch([]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      description: "Search",
      parameters: params,
      execute: async ({ q }: { q: string }) => ({ q }),
      scope: { toolServer: "srv", toolName: "search" },
      clientOptions: { sidecarUrl: "http://127.0.0.1:9090", fetch },
    });

    expect(wrapped.description).toBe("Search");
    expect(wrapped.parameters).toBe(params);
    expect(typeof wrapped.execute).toBe("function");
  });

  it("preserves zod parameter schema reference (no re-wrapping)", () => {
    const schema = z.object({ q: z.string().min(1) });
    const { fetch } = fakeFetch([]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: schema,
      execute: async ({ q }: { q: string }) => q,
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });
    expect(wrapped.parameters).toBe(schema);
  });

  it("preserves the `inputSchema` field used by Vercel AI SDK v5", () => {
    const schema = z.object({ q: z.string() });
    const { fetch } = fakeFetch([]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      inputSchema: schema,
      execute: async ({ q }: { q: string }) => q,
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });
    expect(wrapped.inputSchema).toBe(schema);
  });

  it("strips Chio-only config fields from the wrapper's public surface", () => {
    const { fetch } = fakeFetch([]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      description: "d",
      parameters: z.object({}),
      execute: async () => "ok",
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
      onSidecarError: "deny",
    });
    expect("scope" in wrapped).toBe(false);
    expect("clientOptions" in wrapped).toBe(false);
    expect("onSidecarError" in wrapped).toBe(false);
  });
});

// -- chioTool: allow/deny path ---------------------------------------------

describe("chioTool: allow path invokes underlying execute", () => {
  it("delegates to the original execute on allow and returns its value", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("http://127.0.0.1:9090/chio/evaluate");
    expect(calls[0]!.body).toMatchObject({
      request_id: expect.any(String),
      method: "POST",
      route_pattern: "/chio/tools/math/double",
      path: "/chio/tools/math/double",
      query: {},
      headers: {
        "content-type": "application/json",
        "content-length": String(JSON.stringify({ n: 21 }).length),
      },
      caller: {
        subject: "anonymous",
        auth_method: { method: "anonymous" },
        verified: false,
      },
      body_hash: expect.any(String),
      body_length: JSON.stringify({ n: 21 }).length,
      timestamp: expect.any(Number),
      tool_server: "math",
      tool_name: "double",
      capability_id: "cap-1",
      arguments: { n: 21 },
    });
    expect(calls[0]!.headers["x-chio-capability"]).toBe(CAPABILITY_TOKEN);
  });

  it("verifies via /chio/verify by default when no explicit verifier is configured", async () => {
    // Without verifyReceipt, the wrapper must fall back to POSTing the
    // raw receipt body to the sidecar's /chio/verify route (same default
    // URL as the evaluate path) so default-configured callers continue to
    // verify before invoking the underlying tool. This mirrors the
    // chio-ai-sdk-middleware applyReceiptAuthority fallback.
    const verifyBodies: string[] = [];
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const body = init?.body == null ? "" : String(init.body);
      if (url.endsWith("/chio/evaluate")) {
        return new Response(JSON.stringify(allowReceipt("r-default-verify")), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/chio/verify")) {
        verifyBodies.push(body);
        return new Response(
          JSON.stringify({
            receipt_kind: "mediated_decision",
            boundary_class: "prevent",
            trust_level: "mediated",
            result: "allow",
            authorized: true,
            ok: true,
            signer_trusted: true,
            signature_valid: true,
            receipt_id_valid: true,
            parameter_hash_valid: true,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected fetch in default-verify test: ${url}`);
    }) as typeof fetch;

    const wrapped = chioTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch: fetchImpl, sidecarUrl: "http://sidecar.test" },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
    expect(verifyBodies).toHaveLength(1);
    // The Rust /chio/verify handler deserializes the request body
    // directly as an HttpReceipt. Wrapping it as { receipt: ... } would
    // cause the real sidecar to return 400, so the wrapper must POST the
    // receipt body verbatim.
    const parsed = JSON.parse(verifyBodies[0]!);
    expect(parsed.id).toBe("r-default-verify");
    expect(parsed.receipt).toBeUndefined();
  });

  it("reuses a preconstructed client transport for default verification", async () => {
    const calls: string[] = [];
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      calls.push(url);
      if (url === "http://custom-sidecar.test/chio/evaluate") {
        return new Response(JSON.stringify(allowReceipt("r-client-verify")), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "http://custom-sidecar.test/chio/verify") {
        return new Response(JSON.stringify(trustedReceiptVerifier()), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected client transport URL: ${url}`);
    }) as typeof fetch;
    const client = new ChioClient({
      fetch: fetchImpl,
      sidecarUrl: "http://custom-sidecar.test",
    });
    const wrapped = chioTool({
      client,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
    });

    await expect(wrapped.execute!({ n: 21 })).resolves.toEqual({ doubled: 42 });
    expect(calls).toEqual([
      "http://custom-sidecar.test/chio/evaluate",
      "http://custom-sidecar.test/chio/verify",
    ]);
  });

  it("honors the client timeout while verifying by default", async () => {
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return new Response(JSON.stringify(allowReceipt("r-verify-timeout")), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/chio/verify")) {
        return await new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        });
      }
      throw new Error(`unexpected fetch in timeout test: ${url}`);
    }) as typeof fetch;
    const wrapped = chioTool({
      clientOptions: {
        fetch: fetchImpl,
        sidecarUrl: "http://sidecar.test",
        timeoutMs: 1,
      },
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
    });

    await expect(wrapped.execute!({ n: 21 })).rejects.toMatchObject({
      verdict: "sidecar_unreachable",
      receiptId: "r-verify-timeout",
    });
  });

  it("fails closed when /chio/verify returns partial authority", async () => {
    // The default /chio/verify path must still enforce that every
    // authority field is set. A partial response (missing
    // parameter_hash_valid) is treated as non-authorizing.
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return new Response(JSON.stringify(allowReceipt("r-partial-auth")), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/chio/verify")) {
        return new Response(
          JSON.stringify({
            receipt_kind: "mediated_decision",
            boundary_class: "prevent",
            trust_level: "mediated",
            result: "allow",
            authorized: true,
            ok: true,
            signer_trusted: true,
            signature_valid: true,
            receipt_id_valid: true,
            // parameter_hash_valid intentionally omitted
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected fetch in partial-authority test: ${url}`);
    }) as typeof fetch;
    const wrapped = chioTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch: fetchImpl, sidecarUrl: "http://sidecar.test" },
    });

    await expect(wrapped.execute!({ n: 21 })).rejects.toMatchObject({
      verdict: "incomplete",
      receiptId: "r-partial-auth",
    });
  });

  it("fails closed when /chio/verify is unreachable", async () => {
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return new Response(JSON.stringify(allowReceipt("r-verify-unreachable")), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/chio/verify")) {
        throw new TypeError("connection refused");
      }
      throw new Error(`unexpected fetch in unreachable-verify test: ${url}`);
    }) as typeof fetch;
    const wrapped = chioTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch: fetchImpl, sidecarUrl: "http://sidecar.test" },
    });

    await expect(wrapped.execute!({ n: 21 })).rejects.toMatchObject({
      verdict: "sidecar_unreachable",
      receiptId: "r-verify-unreachable",
    });
  });

  it("fails closed when verifier omits semantic authority fields", async () => {
    const { fetch } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: () => ({
        authorized: true,
        ok: true,
        signer_trusted: true,
        signature_valid: true,
        receipt_id_valid: true,
        parameter_hash_valid: true,
      }),
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({ n: 21 })).rejects.toMatchObject({
      verdict: "incomplete",
      receiptId: "r-allow",
    });
  });

  it("forwards capability token in X-Chio-Capability header when provided", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => "ok",
      scope: {
        toolServer: "s",
        toolName: "t",
        capabilityToken: '{"id":"cap-xyz"}',
      },
      clientOptions: { fetch },
    });

    await wrapped.execute!({});
    expect(calls[0]!.headers["x-chio-capability"]).toBe('{"id":"cap-xyz"}');
    expect(calls[0]!.body).toMatchObject({
      capability_id: "cap-xyz",
      capability: { id: "cap-xyz" },
      arguments: {},
    });
  });

  it("forwards scope metadata into the evaluation request", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => "ok",
      scope: {
        toolServer: "s",
        toolName: "t",
        metadata: { trace_id: "trace-1" },
      },
      clientOptions: { fetch },
    });

    await wrapped.execute!({});
    expect(calls[0]!.body).toMatchObject({
      metadata: { trace_id: "trace-1" },
    });
  });

  it("rejects the old Lambda evaluator response contract", async () => {
    const { fetch } = fakeFetch([lambdaAllowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({ n: 21 })).rejects.toMatchObject({
      reason: expect.stringContaining("sidecar response missing a recognizable receipt id"),
    });
  });

  it("normalizes the sidecar EvaluateResponse contract", async () => {
    const { fetch } = fakeFetch([sidecarAllowEvaluateResponse()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
  });

  it("rejects advisory evaluation wrappers as execution authorization", async () => {
    const { fetch } = fakeFetch([advisoryEvaluationResponse()]);
    const client = new ChioClient({ fetch });

    await expect(
      client.evaluateToolCall({
        capability_id: "cap-1",
        tool_server: "math",
        tool_name: "double",
        parameters: { n: 21 },
      }),
    ).rejects.toMatchObject({
      code: "chio_invalid_receipt",
      message: expect.stringContaining("advisory evaluation"),
    });
  });

  it("rejects bare advisory receipts as execution authorization", async () => {
    const { fetch } = fakeFetch([advisoryReceipt()]);
    const client = new ChioClient({ fetch });

    await expect(
      client.evaluateToolCall({
        capability_id: "cap-1",
        tool_server: "math",
        tool_name: "double",
        parameters: { n: 21 },
      }),
    ).rejects.toMatchObject({
      code: "chio_invalid_receipt",
      message: expect.stringContaining("advisory receipt"),
    });
  });

  it("lifts receipt.verdict into decision when sidecar omits decision", async () => {
    // Canonical Rust EvaluateResponse: the receipt carries `verdict` with
    // no sibling `decision` field. normalizeReceipt must lift `verdict`
    // into `decision`, otherwise chioTool reads `verdict == null` and
    // throws a non-authorizing ChioToolError.
    const { fetch } = fakeFetch([sidecarVerdictOnlyAllowResponse()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
  });

  it("forwards ToolExecuteOptions (abortSignal, toolCallId) to underlying execute", async () => {
    const { fetch } = fakeFetch([allowReceipt()]);
    let capturedOpts: unknown;
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async (_params: unknown, options) => {
        capturedOpts = options;
        return "ok";
      },
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });

    const controller = new AbortController();
    await wrapped.execute!({}, {
      toolCallId: "call-1",
      abortSignal: controller.signal,
      messages: [],
    });
    expect(capturedOpts).toMatchObject({ toolCallId: "call-1" });
    expect((capturedOpts as { abortSignal?: AbortSignal }).abortSignal).toBe(controller.signal);
  });

  it("resolves a capability token when only capabilityId is configured", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: { toolServer: "math", toolName: "double", capabilityId: "cap-1" },
      resolveCapabilityToken: async (capabilityId) =>
        capabilityId === "cap-1" ? CAPABILITY_TOKEN : undefined,
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
    expect(calls[0]!.headers["x-chio-capability"]).toBe(CAPABILITY_TOKEN);
  });

  it("fails fast when capabilityId is configured without a presented token", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: { toolServer: "math", toolName: "double", capabilityId: "cap-1" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({ n: 21 })).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "incomplete",
    });
    expect(calls).toHaveLength(0);
  });
});

describe("chioTool: deny path throws ChioToolError", () => {
  it("throws ChioToolError with verdict/guard/reason on deny", async () => {
    const { fetch } = fakeFetch([denyReceipt("not allowed", "FsDenylist", "r-42")]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ path: z.string() }),
      execute: async () => "should not run",
      scope: { toolServer: "fs", toolName: "read" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({ path: "/etc/passwd" })).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "deny",
      guard: "FsDenylist",
      reason: "not allowed",
      receiptId: "r-42",
    });
  });

  it("surfaces a verdict-only deny receipt as ChioToolError", async () => {
    // Sidecar emits a deny receipt with tagged `verdict` and no sibling
    // `decision` field (canonical Rust EvaluateResponse wire shape).
    // chioTool must still surface guard/reason from the lifted decision
    // and never call the underlying execute.
    const { fetch } = fakeFetch([
      sidecarVerdictOnlyDenyResponse("not allowed", "FsDenylist", "r-deny-1"),
    ]);
    let called = false;
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ path: z.string() }),
      execute: async () => {
        called = true;
        return "should not run";
      },
      scope: { toolServer: "fs", toolName: "read" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({ path: "/etc/passwd" })).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "deny",
      guard: "FsDenylist",
      reason: "not allowed",
      receiptId: "r-deny-1",
    });
    expect(called).toBe(false);
  });

  it("never calls underlying execute on deny", async () => {
    const { fetch } = fakeFetch([denyReceipt()]);
    let called = false;
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => {
        called = true;
        return "ran";
      },
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({})).rejects.toBeInstanceOf(ChioToolError);
    expect(called).toBe(false);
  });

  it("fails closed on sidecar error by default", async () => {
    const { fetch } = fakeFetch([{ error: "boom", status: 500 }]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => "ran",
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({})).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "sidecar_unreachable",
    });
  });

  it("fails closed even when reserved onSidecarError=allow is configured", async () => {
    const { fetch } = throwingFetch(new Error("connect ECONNREFUSED"));
    let called = false;
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => {
        called = true;
        return "ran";
      },
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
      onSidecarError: "allow",
    });

    await expect(wrapped.execute!({})).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "sidecar_unreachable",
    });
    expect(called).toBe(false);
  });

  it("keeps sidecar control responses blocking even when onSidecarError=allow", async () => {
    const { fetch } = fakeFetch([{ error: "approval required", status: 409 }]);
    let called = false;
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => {
        called = true;
        return "ran";
      },
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
      onSidecarError: "allow",
    });

    await expect(wrapped.execute!({})).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "sidecar_unreachable",
    });
    expect(called).toBe(false);
  });
});

// -- Streaming preservation ------------------------------------------------

describe("chioTool: streaming preservation", () => {
  it("passes ReadableStream return value through unchanged (no buffering)", async () => {
    const stream = new ReadableStream<string>({
      start(controller) {
        controller.enqueue("a");
        controller.enqueue("b");
        controller.enqueue("c");
        controller.close();
      },
    });

    const { fetch } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => stream,
      scope: { toolServer: "s", toolName: "stream" },
      clientOptions: { fetch },
    });

    const returned = await wrapped.execute!({});
    // Critical: the wrapper must return the exact same ReadableStream
    // instance -- no tee, no clone, no buffering.
    expect(returned).toBe(stream);
    expect(returned instanceof ReadableStream).toBe(true);

    // The stream must still be uncollected and readable end-to-end.
    const reader = (returned as ReadableStream<string>).getReader();
    const chunks: string[] = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    expect(chunks).toEqual(["a", "b", "c"]);
  });

  it("preserves async generator return type (lazy iteration)", async () => {
    let yielded = 0;
    async function* gen(): AsyncGenerator<number> {
      for (let i = 0; i < 3; i++) {
        yielded++;
        yield i;
      }
    }

    const { fetch } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => gen(),
      scope: { toolServer: "s", toolName: "gen" },
      clientOptions: { fetch },
    });

    const returned = await wrapped.execute!({});
    // Wrapper must not have iterated the generator -- `yielded` stays 0
    // until the caller drives the iterator.
    expect(yielded).toBe(0);
    expect(typeof (returned as AsyncGenerator<number>)[Symbol.asyncIterator]).toBe("function");

    const collected: number[] = [];
    for await (const n of returned as AsyncGenerator<number>) {
      collected.push(n);
    }
    expect(collected).toEqual([0, 1, 2]);
    expect(yielded).toBe(3);
  });

  it("returns the same reference identity for ReadableStream (object identity check)", async () => {
    const stream = new ReadableStream<Uint8Array>();
    const { fetch } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => stream,
      scope: { toolServer: "s", toolName: "stream" },
      clientOptions: { fetch },
    });

    const a = await wrapped.execute!({});
    expect(Object.is(a, stream)).toBe(true);
  });
});

// -- Shared client reuse --------------------------------------------------

describe("chioTool: client reuse", () => {
  it("reuses a caller-provided ChioClient across invocations", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt(), allowReceipt()]);
    const client = new ChioClient({ fetch });
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({}),
      execute: async () => "ok",
      scope: { toolServer: "s", toolName: "t" },
      client,
    });

    await wrapped.execute!({});
    await wrapped.execute!({});
    expect(calls).toHaveLength(2);
    expect(calls[0]!.url).toBe(calls[1]!.url);
  });
});

// -- Receipt verdict lifting (regression coverage) -------------------------

describe("chioTool: verdict lifting across wire shapes", () => {
  it("lifts nested receipt.verdict.verdict into decision when sidecar response uses the Verdict-tagged shape", async () => {
    // Mirrors the Rust `Verdict` enum
    // (`#[serde(tag = "verdict", rename_all = "snake_case")]`): the
    // HttpReceipt carries `verdict: {verdict:"allow"}` with NO sibling
    // `decision` field. The normalizer must handle this tagged shape;
    // if it only reads `receipt.decision`, chioTool denies every
    // otherwise-authorized tool use because `decision` stays undefined.
    const { fetch } = fakeFetch([sidecarVerdictOnlyAllowResponse("r-tagged-allow")]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
  });

  it("falls back to top-level record.verdict when receipt verdict is malformed", async () => {
    // Defensive last-resort fallback. If the receipt body somehow lands
    // without a parseable `decision`/`verdict` (e.g. a sidecar that
    // strips the inner field but keeps the envelope-level verdict), the
    // already-parsed top-level EvaluateResponse `verdict` should still
    // authorize the call. Without this fallback, an otherwise-authorized
    // tool use is silently denied.
    const malformedResponse: Record<string, unknown> = {
      verdict: { verdict: "allow" },
      receipt: {
        id: "r-toplevel-fallback",
        // Receipt body intentionally omits both `decision` and a
        // parseable `verdict` so the normalizer must consult the
        // enveloping top-level verdict instead.
        receipt_kind: "mediated_decision",
        boundary_class: "prevent",
        tool_origin: "caller_executed",
        redaction_mode: "none",
        trust_level: "mediated",
        route_pattern: "/chio/tools/math/double",
        method: "POST",
      },
      evidence: [],
    };
    const { fetch } = fakeFetch([malformedResponse]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
  });

  it("accepts a plain-string receipt.decision", async () => {
    // Some evaluator shims write the decision as a plain string rather than
    // the tagged-enum object. Both shapes must lift identically.
    const plainStringShape: Record<string, unknown> = {
      verdict: "allow",
      receipt: {
        id: "r-string-decision",
        // Alternate shim shape: receipt.decision is a plain string, not an object.
        decision: "allow",
        receipt_kind: "mediated_decision",
        boundary_class: "prevent",
        tool_origin: "caller_executed",
        redaction_mode: "none",
        trust_level: "mediated",
      },
      evidence: [],
    };
    const { fetch } = fakeFetch([plainStringShape]);
    const wrapped = chioTool({
      verifyReceipt: trustedReceiptVerifier,
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
  });
});
