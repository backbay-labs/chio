import { describe, expect, it } from "bun:test";
import {
  ChioMiddlewareDeniedError,
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
