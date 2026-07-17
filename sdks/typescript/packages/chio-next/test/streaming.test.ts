import { describe, expect, it } from "bun:test";
import {
  ChioActionDeniedError,
  createDenialResponse,
  passThroughStreamingResponse,
  withChio,
  withChioAction,
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

describe("@chio-protocol/next streaming and denial response", () => {
  it("returns allowed streaming responses by reference", async () => {
    const stream = new ReadableStream();
    const response = new Response(stream);
    const wrapped = withChio(async () => response, {
      evaluate: () => authorizedAllow(),
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

  it("preserves the request body when the evaluator reads it", async () => {
    const wrapped = withChio(async (request) => {
      return new Response(await request.text());
    }, {
      evaluate: async (request) => {
        expect(await request.text()).toBe("hello next");
        return authorizedAllow();
      },
    });

    const response = await wrapped(new Request("https://app.test/api/chat", {
      method: "POST",
      body: "hello next",
    }));

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("hello next");
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

  it("rejects bare allow route evaluations without verified receipt authority", async () => {
    const wrapped = withChio(async () => new Response("never reached"), {
      evaluate: () => ({ verdict: "allow" }),
    });

    const response = await wrapped(new Request("https://app.test/api/chat", {
      method: "POST",
    }));

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: "chio_denied",
      reason: "Chio evaluation did not include verified receipt authorization",
    });
  });

  it("rejects bare allow server actions without verified receipt authority", async () => {
    let invoked = false;
    const action = withChioAction(async () => {
      invoked = true;
      return "ok";
    }, {
      evaluate: () => ({ verdict: "allow" }),
    });

    await expect(action()).rejects.toThrow(ChioActionDeniedError);
    expect(invoked).toBe(false);
  });

  it("authorizes only the canonical SDK allow result", async () => {
    const allowed = withChio(async () => new Response("allow"), {
      evaluate: () => ({
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
      }),
    });
    const response = await allowed(
      new Request("https://app.test/api/chat"),
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("allow");

    for (const result of ["authorized", "Authorized", "Allow"]) {
      const denied = withChio(async () => new Response(result), {
        evaluate: () => ({
          verdict: "allow" as const,
          decision: "allow" as const,
          receipt_kind: "mediated_decision" as const,
          boundary_class: "prevent" as const,
          trust_level: "mediated" as const,
          result,
          authorized: true,
          ok: true,
          signer_trusted: true,
          signature_valid: true,
          receipt_id_valid: true,
          parameter_hash_valid: true,
        }),
      });
      const deniedResponse = await denied(
        new Request("https://app.test/api/chat"),
      );
      expect(deniedResponse.status).toBe(403);
      expect(deniedResponse.headers.get("x-chio-verdict")).toBe("deny");
    }
  });
});
