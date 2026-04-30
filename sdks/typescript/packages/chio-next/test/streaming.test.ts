import { describe, expect, it } from "bun:test";
import {
  ChioActionDeniedError,
  createDenialResponse,
  passThroughStreamingResponse,
  withChio,
  withChioAction,
} from "../src/index.js";

describe("@chio/next streaming and denial response", () => {
  it("returns allowed streaming responses by reference", async () => {
    const stream = new ReadableStream();
    const response = new Response(stream);
    const wrapped = withChio(async () => response, {
      evaluate: () => ({ verdict: "allow" }),
    });

    const result = await wrapped(new Request("https://app.test/api/chat"));

    expect(result).toBe(response);
    expect(passThroughStreamingResponse(response)).toBe(response);
  });

  it("emits typed denial JSON", async () => {
    const response = createDenialResponse({ reason: "blocked", receiptId: "r-1" });

    expect(response.status).toBe(403);
    expect(response.headers.get("x-chio-verdict")).toBe("deny");
    expect(await response.json()).toEqual({
      error: "chio_denied",
      reason: "blocked",
      receipt_id: "r-1",
    });
  });

  it("denies server actions before invoking the action", async () => {
    let invoked = false;
    const action = withChioAction(async () => {
      invoked = true;
      return "ok";
    }, {
      evaluate: () => ({ verdict: "deny", reason: "blocked" }),
    });

    await expect(action()).rejects.toThrow(ChioActionDeniedError);
    expect(invoked).toBe(false);
  });
});
