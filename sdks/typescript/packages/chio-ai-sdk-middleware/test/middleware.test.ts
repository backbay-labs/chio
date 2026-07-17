import { describe, expect, it, mock } from "bun:test";
import {
  ChioMiddlewareDeniedError,
  createChioMiddleware,
  isAsyncIterable,
  isReadableStreamLike,
  wrapWithChio,
  type ChioReceiptAuthority,
  type LanguageModelInvocation,
} from "../src/index.js";

function authorizedAllow() {
  return {
    verdict: "allow" as const,
    decision: "allow" as const,
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

describe("wrapWithChio", () => {
  it("runs verdict evaluation before generation when tools are present", async () => {
    const calls: string[] = [];
    const model = {
      async doGenerate(_request: LanguageModelInvocation) {
        calls.push("model");
        return { text: "ok" };
      },
    };
    const wrapped = wrapWithChio(model, {
      evaluate: ({ toolUse }) => {
        calls.push(`verdict:${toolUse?.name}`);
        return authorizedAllow();
      },
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });

    expect(result).toEqual({ text: "ok" });
    expect(calls).toEqual(["verdict:search", "model"]);
  });

  it("denies before invoking the underlying model", async () => {
    let invoked = false;
    const wrapped = wrapWithChio({
      async doGenerate() {
        invoked = true;
        return {};
      },
    }, {
      evaluate: () => ({ verdict: "deny", reason: "blocked", receiptId: "r-deny" }),
    });

    await expect(wrapped.doGenerate({ toolCalls: [{ toolName: "search" }] }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });

  it("passes stream results through without buffering", async () => {
    const stream = new ReadableStream();
    const wrapped = wrapWithChio({
      async doStream() {
        return stream;
      },
    }, {
      evaluate: () => authorizedAllow(),
    });

    const result = await wrapped.doStream({ tools: { search: {} } });

    expect(result).toBe(stream);
    expect(isReadableStreamLike(result)).toBe(true);
    expect(isAsyncIterable({
      async *[Symbol.asyncIterator]() {
        yield "chunk";
      },
    })).toBe(true);
  });

  it("skips evaluation when the request carries no tool-use surface", async () => {
    let evaluations = 0;
    let modelCalls = 0;
    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "no-tools" };
      },
    }, {
      evaluate: () => {
        evaluations += 1;
        return authorizedAllow();
      },
    });

    const result = await wrapped.doGenerate({ prompt: "hello" });

    expect(result).toEqual({ text: "no-tools" });
    expect(evaluations).toBe(0);
    expect(modelCalls).toBe(1);
  });

  it("evaluates each named tool once when multiple tools are present", async () => {
    const seen: string[] = [];
    const wrapped = wrapWithChio({
      async doGenerate() {
        return { text: "ok" };
      },
    }, {
      evaluate: ({ toolUse }) => {
        seen.push(toolUse?.name ?? "<missing>");
        return authorizedAllow();
      },
    });

    await wrapped.doGenerate({
      tools: {
        search: {},
        fetch_url: {},
      },
    });

    // Names are sorted to stabilize evaluation order across runtimes.
    expect(seen).toEqual(["fetch_url", "search"]);
  });

  it("falls back to declared tools when explicit toolCalls is empty", async () => {
    const seen: string[] = [];
    const wrapped = wrapWithChio({
      async doGenerate() {
        return { text: "ok" };
      },
    }, {
      evaluate: ({ toolUse }) => {
        seen.push(toolUse?.name ?? "<missing>");
        return authorizedAllow();
      },
    });

    await wrapped.doGenerate({
      tools: { search: {} },
      toolCalls: [],
    });

    expect(seen).toEqual(["search"]);
  });

  it("createChioMiddleware exposes AI SDK wrapGenerate/wrapStream hooks", async () => {
    // The Vercel AI SDK invokes `wrapGenerate({ doGenerate, params })` and
    // `wrapStream({ doStream, params })` once per call. Without these
    // hooks, passing the result to `wrapLanguageModel({ middleware })`
    // would silently no-op and bypass Chio. The test asserts they exist
    // and that the gate runs before the underlying call.
    const middleware = createChioMiddleware({
      evaluate: ({ toolUse }) =>
        toolUse?.name === "blocked"
          ? { verdict: "deny", reason: "blocked tool" }
          : authorizedAllow(),
    });

    expect(typeof middleware.wrapGenerate).toBe("function");
    expect(typeof middleware.wrapStream).toBe("function");

    // Allow path runs the inner doGenerate with the original params.
    const allowResult = await middleware.wrapGenerate<LanguageModelInvocation, { ok: boolean }>({
      doGenerate: async (p) => ({ ok: p.tools != null }),
      params: { tools: { search: {} } } as LanguageModelInvocation,
    });
    expect(allowResult).toEqual({ ok: true });

    // Deny path throws ChioMiddlewareDeniedError before the inner call.
    let invoked = false;
    await expect(
      middleware.wrapStream<LanguageModelInvocation, unknown>({
        doStream: async () => {
          invoked = true;
          return null;
        },
        params: { toolCalls: [{ toolName: "blocked" }] } as LanguageModelInvocation,
      }),
    ).rejects.toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });

  it("denies on the first denying tool and stops invoking the model", async () => {
    let modelCalls = 0;
    const seen: string[] = [];
    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "should not run" };
      },
    }, {
      evaluate: ({ toolUse }) => {
        seen.push(toolUse?.name ?? "<missing>");
        if (toolUse?.name === "fetch_url") {
          return { verdict: "deny", reason: "domain not on allowlist" };
        }
        return authorizedAllow();
      },
    });

    await expect(wrapped.doGenerate({
      toolCalls: [
        { toolName: "search" },
        { toolName: "fetch_url" },
        { toolName: "execute" },
      ],
    })).rejects.toThrow(ChioMiddlewareDeniedError);

    expect(seen).toEqual(["search", "fetch_url"]);
    expect(modelCalls).toBe(0);
  });

  it("rejects bare allow responses without verified receipt authority", async () => {
    let invoked = false;
    const wrapped = wrapWithChio({
      async doGenerate() {
        invoked = true;
        return { text: "should not run" };
      },
    }, {
      evaluate: () => ({ verdict: "allow" }),
    });

    await expect(wrapped.doGenerate({ tools: { search: {} } }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });

  it("denies non-canonical authorized result strings", async () => {
    let invoked = false;
    const wrapped = wrapWithChio({
      async doGenerate() {
        invoked = true;
        return { text: "should not run" };
      },
    }, {
      evaluate: () => ({ ...authorizedAllow(), result: "authorized" }),
    });

    await expect(wrapped.doGenerate({ tools: { search: {} } }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });
});

/// Minimal `/chio/evaluate` response carrying just the verdict and receipt
/// body. Authority fields are deliberately omitted because the raw wire
/// response does not produce them; they are the output of verification.
function evaluateResponseBody(receiptId = "r-1") {
  return {
    verdict: "allow",
    receipt_id: receiptId,
    decision: "allow",
    receipt: {
      id: receiptId,
      decision: { verdict: "allow" },
      signed_body: "stub",
    },
  };
}

function authorityAllow(): ChioReceiptAuthority {
  return {
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
  };
}

/// Matches the wire shape produced by `VerifyReceiptResponse` in
/// `crates/platform/chio-http-core/src/evaluation.rs`: `result` is `"allow"` not
/// `"authorized"`. The middleware must accept this value.
function sidecarVerifyAllow(): Record<string, unknown> {
  return {
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
    signer_key_hex: "deadbeef",
  };
}

interface MockResponseInit {
  status?: number;
  body?: unknown;
}

function jsonResponse(init: MockResponseInit = {}): Response {
  const status = init.status ?? 200;
  return new Response(JSON.stringify(init.body ?? {}), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("receipt authority verification", () => {
  it("populates authority fields from explicit verifyReceipt and authorizes the call", async () => {
    const seenReceipts: Array<Record<string, unknown>> = [];
    let modelCalls = 0;
    let evaluateCalls = 0;

    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        evaluateCalls += 1;
        return jsonResponse({ body: evaluateResponseBody("r-explicit") });
      }
      throw new Error(`unexpected fetch in explicit-verifier test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
      verifyReceipt: (receipt) => {
        seenReceipts.push(receipt);
        return authorityAllow();
      },
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });

    expect(result).toEqual({ text: "ok" });
    expect(evaluateCalls).toBe(1);
    expect(modelCalls).toBe(1);
    expect(seenReceipts).toHaveLength(1);
    expect(seenReceipts[0]?.["id"]).toBe("r-explicit");
  });

  it("defaults to /chio/verify when no verifyReceipt is configured", async () => {
    const seenPaths: string[] = [];
    const verifyBodies: string[] = [];
    let modelCalls = 0;

    const fetchMock = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      seenPaths.push(url);
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-verify") });
      }
      if (url.endsWith("/chio/verify")) {
        // Confirm the receipt body was forwarded.
        const body = init?.body == null ? "" : String(init.body);
        verifyBodies.push(body);
        expect(body).toContain("r-verify");
        return jsonResponse({ body: authorityAllow() });
      }
      throw new Error(`unexpected fetch in default-verify test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });

    expect(result).toEqual({ text: "ok" });
    expect(modelCalls).toBe(1);
    expect(seenPaths.some(path => path.endsWith("/chio/evaluate"))).toBe(true);
    expect(seenPaths.some(path => path.endsWith("/chio/verify"))).toBe(true);
    // The Rust `/chio/verify` handler deserializes the request body
    // directly as an `HttpReceipt`. Wrapping the payload as
    // `{ receipt: ... }` would cause the real sidecar to return 400, so
    // the middleware must POST the raw receipt body. We assert the
    // top-level body matches the receipt body verbatim.
    expect(verifyBodies).toHaveLength(1);
    const parsed = JSON.parse(verifyBodies[0]!);
    expect(parsed).toEqual({
      id: "r-verify",
      decision: { verdict: "allow" },
      signed_body: "stub",
    });
    expect(parsed.receipt).toBeUndefined();
  });

  it("verifies via the default localhost sidecar when sidecarUrl is omitted", async () => {
    // Mirrors the default-configured node path: no explicit `sidecarUrl`
    // and no `verifyReceipt`. The middleware should still call
    // `/chio/verify` against the default `http://127.0.0.1:9090`
    // (matching `resolveSidecarUrl(undefined)` on the evaluate path).
    const seenPaths: string[] = [];
    let modelCalls = 0;

    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      seenPaths.push(url);
      if (url === "http://127.0.0.1:9090/chio/evaluate") {
        return jsonResponse({ body: evaluateResponseBody("r-default-host") });
      }
      if (url === "http://127.0.0.1:9090/chio/verify") {
        return jsonResponse({ body: authorityAllow() });
      }
      throw new Error(`unexpected fetch in default-host-verify test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      runtime: "node",
      // sidecarUrl deliberately omitted to exercise the documented default.
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });

    expect(result).toEqual({ text: "ok" });
    expect(modelCalls).toBe(1);
    expect(seenPaths).toEqual([
      "http://127.0.0.1:9090/chio/evaluate",
      "http://127.0.0.1:9090/chio/verify",
    ]);
  });

  it("accepts the sidecar's result: \"allow\" response shape from /chio/verify", async () => {
    // The Rust `/chio/verify` route returns `result: "allow"` (see
    // `VerifyReceiptResponse::from_http_receipt` in
    // `crates/platform/chio-http-core/src/evaluation.rs`); the middleware must
    // accept that shape and authorize when every authority field is true.
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-allow") });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({ body: sidecarVerifyAllow() });
      }
      throw new Error(`unexpected fetch in result-allow test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });
    expect(result).toEqual({ text: "ok" });
    expect(modelCalls).toBe(1);
  });

  it("verifies via the resolved default URL on otherwise-allowed tool use without sidecarUrl or verifyReceipt", async () => {
    // Guards: applyReceiptAuthority must not deny tool use when callers rely on
    // the default sidecar URL (no explicit sidecarUrl / verifyReceipt).
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url === "http://127.0.0.1:9090/chio/evaluate") {
        return jsonResponse({ body: evaluateResponseBody("r-no-config") });
      }
      if (url === "http://127.0.0.1:9090/chio/verify") {
        return jsonResponse({ body: authorityAllow() });
      }
      throw new Error(`unexpected fetch in no-config test: ${url}`);
    };

    let modelCalls = 0;
    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      // Neither `sidecarUrl` nor `verifyReceipt` is configured. The
      // middleware must still authorize because both default to the
      // local sidecar and the authority response says allow.
      runtime: "node",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });
    expect(result).toEqual({ text: "ok" });
    expect(modelCalls).toBe(1);
  });

  it("fails closed when the sidecar /chio/verify route is unreachable", async () => {
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-unreachable") });
      }
      if (url.endsWith("/chio/verify")) {
        throw new TypeError("connection refused");
      }
      throw new Error(`unexpected fetch in unreachable-verify test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "should not run" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate({ tools: { search: {} } }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
  });

  it("fails closed when verifyReceipt reports a partial authority", async () => {
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-partial") });
      }
      throw new Error(`unexpected fetch in partial-authority test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "should not run" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
      verifyReceipt: () => ({
        // Authority result is intentionally partial: it carries the descriptive
        // fields but omits parameter_hash_valid, so the middleware must deny.
        receipt_kind: "mediated_decision",
        boundary_class: "prevent",
        trust_level: "mediated",
        result: "allow",
        authorized: true,
        ok: true,
        signer_trusted: true,
        signature_valid: true,
        receipt_id_valid: true,
      }),
    });

    await expect(wrapped.doGenerate({ tools: { search: {} } }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
  });

  it("denies on edge runtime without an explicit verifyReceipt (no fetch fallback)", async () => {
    // Guards: the edge runtime must not fall back to a localhost /chio/verify
    // fetch (unreachable from Vercel/Workers); it denies with a clear reason instead.
    // We must keep this verification in-process for
    // edge runtimes (or via an explicit verifier) because the
    // in-process @chio-protocol/edge `verify_receipt` binding needs a
    // binary envelope the JSON `/chio/evaluate` response does not carry.
    //
    // To exercise applyReceiptAuthority on the edge path we have to bypass
    // the `options.evaluate` short-circuit, so we stub the dynamic import
    // of `@chio-protocol/edge` rather than the option. The stubbed
    // wasm-level evaluator returns an allow envelope; the middleware then
    // reaches applyReceiptAuthority and must deny because no verifyReceipt
    // was provided and the fetch fallback is disabled on edge.
    mock.module("@chio-protocol/edge", () => ({
      evaluate: () => ({
        verdict: "allow",
        receipt: { id: "r-edge-no-verifier" },
      }),
    }));

    let modelCalls = 0;
    let fetchCalls = 0;
    const fetchMock = async () => {
      fetchCalls += 1;
      throw new Error(
        "edge runtime must not fall through to fetch-based /chio/verify",
      );
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "should not run" };
      },
    }, {
      runtime: "edge",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate({ tools: { search: {} } }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
    expect(fetchCalls).toBe(0);
  });

  it("authorizes on edge runtime when an explicit verifyReceipt is configured", async () => {
    // Edge callers can still authorize by supplying their own verifier
    // (the documented edge path uses @chio-protocol/edge `verify_receipt`
    // directly). The middleware must not require fetch in that case.
    mock.module("@chio-protocol/edge", () => ({
      evaluate: () => ({
        verdict: "allow",
        receipt: { id: "r-edge-with-verifier" },
      }),
    }));

    let modelCalls = 0;
    let fetchCalls = 0;
    const fetchMock = async () => {
      fetchCalls += 1;
      throw new Error("edge runtime with verifyReceipt must not hit fetch");
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      runtime: "edge",
      fetch: fetchMock as typeof fetch,
      verifyReceipt: () => authorityAllow(),
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });
    expect(result).toEqual({ text: "ok" });
    expect(modelCalls).toBe(1);
    expect(fetchCalls).toBe(0);
  });

  it("fails closed when /chio/verify response omits required authority fields", async () => {
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-omit") });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({
          body: {
            // Descriptive fields are present, but authority booleans are
            // omitted. The middleware must not authorize.
            receipt_kind: "mediated_decision",
            boundary_class: "prevent",
            trust_level: "mediated",
            result: "allow",
            authorized: true,
            ok: true,
          },
        });
      }
      throw new Error(`unexpected fetch in omit-authority test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "should not run" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate({ tools: { search: {} } }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
  });
});

/**
 * Mirror the canonical Rust `EvaluateResponse` wire shape: the top-level
 * `verdict` is a tagged-enum object (`{verdict:"allow"}`) and the inner
 * `HttpReceipt` carries `verdict: {verdict:"allow"}` with NO sibling
 * `decision` field. These tests deliberately omit any top-level
 * `decision` string so the verdict must be lifted from the tagged-enum
 * shape alone.
 */
function httpReceiptOnlyAllowResponse(receiptId = "r-canonical"): Record<string, unknown> {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id: receiptId,
      verdict: { verdict: "allow" },
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      tool_origin: "caller_executed",
      redaction_mode: "none",
      trust_level: "mediated",
      route_pattern: "/chio/tools/search/run",
      method: "POST",
      signed_body: "stub",
    },
    evidence: [],
  };
}

describe("receipt verdict lifting", () => {
  it("lifts nested receipt.verdict.verdict into decision when sidecar response uses the Verdict-tagged shape", async () => {
    // The Rust `Verdict` enum is `#[serde(tag = "verdict")]`, so the
    // real `HttpReceipt.verdict` is `{verdict:"allow"}` rather than a
    // plain string. The middleware must lift this nested shape: if it
    // only reads a string `record.decision` or `receipt.decision.verdict`,
    // `evaluation.decision` stays undefined and every otherwise-authorized
    // tool use is denied because `isAuthorizedEvaluation` requires
    // `decision === "allow"`. This test deliberately omits the
    // `record.decision` shim and the `receipt.decision` field so it
    // exercises the nested `receipt.verdict.verdict` lifting path.
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: httpReceiptOnlyAllowResponse("r-nested") });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({ body: sidecarVerifyAllow() });
      }
      throw new Error(`unexpected fetch in nested-verdict test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });
    expect(result).toEqual({ text: "ok" });
    expect(modelCalls).toBe(1);
  });

  it("falls back to top-level record.verdict when receipt verdict is malformed", async () => {
    // Defensive fallback: even if a receipt body somehow lands without
    // a parseable verdict, the already-parsed top-level EvaluateResponse
    // `verdict` still authorizes the call. Without this fallback an
    // otherwise-allowed tool use is silently denied.
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({
          body: {
            verdict: { verdict: "allow" },
            receipt: {
              id: "r-toplevel-fallback",
              // Receipt body intentionally omits both `decision` and a
              // parseable `verdict` so the normalizer has to consult the
              // enveloping top-level verdict instead.
              receipt_kind: "mediated_decision",
              boundary_class: "prevent",
              tool_origin: "caller_executed",
              redaction_mode: "none",
              trust_level: "mediated",
              route_pattern: "/chio/tools/search/run",
              method: "POST",
              signed_body: "stub",
            },
            evidence: [],
          },
        });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({ body: sidecarVerifyAllow() });
      }
      throw new Error(`unexpected fetch in top-level-fallback test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });
    expect(result).toEqual({ text: "ok" });
    expect(modelCalls).toBe(1);
  });

  it("lifts a plain string receipt.verdict into decision", async () => {
    // Hand-rolled fixtures sometimes carry a plain-string `verdict` on
    // the receipt body rather than the Rust tagged-enum object. Both
    // shapes must resolve to the same `decision` value.
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({
          body: {
            verdict: "allow",
            receipt: {
              id: "r-plain-verdict",
              verdict: "allow",
              receipt_kind: "mediated_decision",
              boundary_class: "prevent",
              tool_origin: "caller_executed",
              redaction_mode: "none",
              trust_level: "mediated",
              signed_body: "stub",
            },
            evidence: [],
          },
        });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({ body: sidecarVerifyAllow() });
      }
      throw new Error(`unexpected fetch in plain-string-verdict test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "ok" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate({ tools: { search: {} } });
    expect(result).toEqual({ text: "ok" });
    expect(modelCalls).toBe(1);
  });

  it("surfaces a tagged deny verdict on the receipt as a deny evaluation", async () => {
    // The deny path must mirror the allow path: a Rust-tagged
    // `{verdict:"deny",...}` on `receipt.verdict` should lift into the
    // decision so the middleware fails closed with a deny rather than
    // an "no allow or deny verdict" parse error.
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({
          body: {
            verdict: { verdict: "deny", reason: "not allowed", guard: "FsDenylist", http_status: 403 },
            receipt: {
              id: "r-tagged-deny",
              verdict: {
                verdict: "deny",
                reason: "not allowed",
                guard: "FsDenylist",
                http_status: 403,
              },
              receipt_kind: "mediated_decision",
              boundary_class: "prevent",
              tool_origin: "caller_executed",
              redaction_mode: "none",
              trust_level: "mediated",
              signed_body: "stub",
            },
            evidence: [],
          },
        });
      }
      throw new Error(`unexpected fetch in tagged-deny test: ${url}`);
    };

    const wrapped = wrapWithChio({
      async doGenerate() {
        modelCalls += 1;
        return { text: "should not run" };
      },
    }, {
      runtime: "node",
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate({ tools: { search: {} } }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
  });
});
