import { describe, expect, it } from "bun:test";
import {
  ChioMiddlewareDeniedError,
  createChioMiddleware,
  isAsyncIterable,
  isReadableStreamLike,
  wrapWithChio,
  type LanguageModelInvocation,
} from "../src/index.js";

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
        return { verdict: "allow" };
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
      evaluate: () => ({ verdict: "allow" }),
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
        return { verdict: "allow" };
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
        return { verdict: "allow" };
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
          : { verdict: "allow" },
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
        return { verdict: "allow" };
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
});
