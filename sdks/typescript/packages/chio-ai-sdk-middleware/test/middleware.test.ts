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
});
