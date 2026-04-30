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
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      error: "chio_denied",
      reason: "blocked",
      receipt_id: "r-1",
    });
  });

  it("propagates reason_code through the denial response and headers", async () => {
    const response = createDenialResponse({
      reason: "scope missing",
      reasonCode: "urn:chio:error:capability:scope-missing",
      receiptId: "r-7",
    });

    expect(response.status).toBe(403);
    expect(response.headers.get("x-chio-reason-code"))
      .toBe("urn:chio:error:capability:scope-missing");
    expect(response.headers.get("x-chio-receipt-id")).toBe("r-7");
    expect(await response.json()).toEqual({
      error: "chio_denied",
      reason: "scope missing",
      reason_code: "urn:chio:error:capability:scope-missing",
      receipt_id: "r-7",
    });
  });

  it("forwards reason_code from the route evaluator into the denial response", async () => {
    const wrapped = withChio(async () => new Response("never reached"), {
      evaluate: () => ({
        verdict: "deny",
        reason: "policy denied",
        reasonCode: "urn:chio:error:policy:custom",
        receiptId: "r-route",
      }),
    });

    const response = await wrapped(new Request("https://app.test/api/chat", {
      method: "POST",
    }));

    expect(response.status).toBe(403);
    expect(response.headers.get("x-chio-reason-code"))
      .toBe("urn:chio:error:policy:custom");
    expect(await response.json()).toEqual({
      error: "chio_denied",
      reason: "policy denied",
      reason_code: "urn:chio:error:policy:custom",
      receipt_id: "r-route",
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
