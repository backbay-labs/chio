import http from "node:http";
import { describe, it, expect } from "vitest";
import { ChioSidecarClient, resolveSidecarUrl, SidecarError } from "../src/sidecar-client.js";
import type {
  ChioHttpRequest,
  EvaluateResponse,
  HttpReceipt,
  VerifyReceiptResponse,
} from "../src/types.js";

function legacyBareReceipt(): HttpReceipt {
  return {
    id: "rcpt-1",
    request_id: "req-1",
    route_pattern: "/pets",
    method: "GET",
    caller_identity_hash: "a".repeat(64),
    verdict: { verdict: "allow" },
    evidence: [],
    response_status: 200,
    timestamp: 1_700_000_000,
    content_hash: "b".repeat(64),
    policy_hash: "c".repeat(64),
    kernel_key: "d".repeat(64),
    signature: "e".repeat(128),
  } as unknown as HttpReceipt;
}

function authoritativeAllowReceipt(): HttpReceipt {
  return {
    ...legacyBareReceipt(),
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    tool_origin: "caller_executed",
    redaction_mode: "none",
    trust_level: "mediated",
  };
}

function advisoryAllowReceipt(): HttpReceipt {
  return {
    ...legacyBareReceipt(),
    receipt_kind: "advisory_evaluation",
    boundary_class: "advisory_only",
    observation_outcome: "evaluated",
    tool_origin: "host_executed_unmediated",
    redaction_mode: "none",
    trust_level: "advisory",
  };
}

function verifyResponse(authorized: boolean): VerifyReceiptResponse {
  return {
    signature_valid: authorized,
    signer_trusted: authorized,
    receipt_id_valid: authorized,
    parameter_hash_valid: authorized,
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    trust_level: "mediated",
    result: authorized ? "allow" : "deny",
    authorized,
    signer_key_hex: "d".repeat(64),
    ok: authorized,
  };
}

function testRequest(): ChioHttpRequest {
  return {
    request_id: "req-1",
    method: "GET",
    route_pattern: "/pets",
    path: "/pets",
    query: {},
    headers: {},
    caller: {
      subject: "user-1",
      auth_method: { method: "anonymous" },
      verified: false,
    },
    body_length: 0,
    timestamp: 1_700_000_000,
  };
}

async function startVerifySidecar(
  onVerify: (res: http.ServerResponse) => void,
): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer((req, res) => {
    void (async () => {
      if (req.method === "POST" && req.url === "/chio/verify") {
        await discardRequestBody(req);
        onVerify(res);
        return;
      }

      res.writeHead(404);
      res.end();
    })().catch((error: unknown) => {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(error instanceof Error ? error.message : String(error));
    });
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

async function closeServer(server: http.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error != null) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

async function discardRequestBody(req: http.IncomingMessage): Promise<void> {
  for await (const _chunk of req) {
    // Drain the body so keep-alive connections can be reused safely.
  }
}

async function startEvaluateSidecar(
  result: unknown,
  verifyValid: boolean,
  onVerify?: () => void,
): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer((req, res) => {
    void (async () => {
      if (req.method === "POST" && req.url === "/chio/evaluate") {
        await discardRequestBody(req);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
        return;
      }

      if (req.method === "POST" && req.url === "/chio/verify") {
        await discardRequestBody(req);
        onVerify?.();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(verifyResponse(verifyValid)));
        return;
      }

      res.writeHead(404);
      res.end();
    })().catch((error: unknown) => {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(error instanceof Error ? error.message : String(error));
    });
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

async function startEvaluateRawSidecar(
  body: string,
): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer((req, res) => {
    void (async () => {
      if (req.method === "POST" && req.url === "/chio/evaluate") {
        await discardRequestBody(req);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(body);
        return;
      }

      res.writeHead(404);
      res.end();
    })().catch((error: unknown) => {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(error instanceof Error ? error.message : String(error));
    });
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

async function expectSidecarError(
  promise: Promise<unknown>,
  code: string,
  statusCode?: number,
): Promise<void> {
  let caught: unknown;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(SidecarError);
  const sidecarError = caught as SidecarError;
  expect(sidecarError.code).toBe(code);
  expect(sidecarError.statusCode).toBe(statusCode);
}

describe("resolveSidecarUrl", () => {
  it("uses config sidecarUrl when provided", () => {
    expect(resolveSidecarUrl({ sidecarUrl: "http://localhost:8080" })).toBe(
      "http://localhost:8080",
    );
  });

  it("strips trailing slashes", () => {
    expect(resolveSidecarUrl({ sidecarUrl: "http://localhost:8080/" })).toBe(
      "http://localhost:8080",
    );
  });

  it("defaults to 127.0.0.1:9090 when no config or env", () => {
    const original = process.env["CHIO_SIDECAR_URL"];
    delete process.env["CHIO_SIDECAR_URL"];
    try {
      expect(resolveSidecarUrl({})).toBe("http://127.0.0.1:9090");
    } finally {
      if (original != null) {
        process.env["CHIO_SIDECAR_URL"] = original;
      }
    }
  });
});

describe("SidecarError", () => {
  it("sets code and message", () => {
    const err = new SidecarError("chio_timeout", "timed out");
    expect(err.code).toBe("chio_timeout");
    expect(err.message).toBe("timed out");
    expect(err.name).toBe("SidecarError");
    expect(err.statusCode).toBeUndefined();
  });

  it("sets status code when provided", () => {
    const err = new SidecarError("chio_evaluation_failed", "bad", 500);
    expect(err.statusCode).toBe(500);
  });

  it("is an instance of Error", () => {
    const err = new SidecarError("chio_timeout", "timed out");
    expect(err).toBeInstanceOf(Error);
  });
});

describe("ChioSidecarClient.evaluate", () => {
  it("returns allow only after receipt authority verification", async () => {
    let verifyCalls = 0;
    const result: EvaluateResponse = {
      verdict: { verdict: "allow" },
      receipt: authoritativeAllowReceipt(),
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true, () => {
      verifyCalls += 1;
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expect(client.evaluate(testRequest())).resolves.toEqual(result);
      expect(verifyCalls).toBe(1);
    } finally {
      await closeServer(server);
    }
  });

  it("normalizes omitted receipt evidence to an empty array", async () => {
    const receipt = authoritativeAllowReceipt() as Partial<HttpReceipt>;
    delete receipt.evidence;
    const result = {
      verdict: { verdict: "allow" },
      receipt,
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      const evaluated = await client.evaluate(testRequest());
      expect(evaluated.receipt.evidence).toEqual([]);
    } finally {
      await closeServer(server);
    }
  });

  it("rejects allow-shaped responses without structural receipt authority", async () => {
    const result: EvaluateResponse = {
      verdict: { verdict: "allow" },
      receipt: legacyBareReceipt(),
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_invalid_receipt",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("rejects advisory receipts as execution authorization", async () => {
    const result: EvaluateResponse = {
      verdict: { verdict: "allow" },
      receipt: advisoryAllowReceipt(),
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_invalid_receipt",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("rejects unverified authoritative allow receipts", async () => {
    const result: EvaluateResponse = {
      verdict: { verdict: "allow" },
      receipt: authoritativeAllowReceipt(),
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, false);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_invalid_receipt",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("rejects inconsistent deny verdict with allow-shaped receipt", async () => {
    const result: EvaluateResponse = {
      verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
      receipt: authoritativeAllowReceipt(),
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_invalid_receipt",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("does not verify non-allow responses", async () => {
    let verifyCalls = 0;
    const result: EvaluateResponse = {
      verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
      receipt: {
        ...authoritativeAllowReceipt(),
        verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
        response_status: 403,
      },
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true, () => {
      verifyCalls += 1;
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expect(client.evaluate(testRequest())).resolves.toEqual(result);
      expect(verifyCalls).toBe(0);
    } finally {
      await closeServer(server);
    }
  });

  it("allows deny responses that omit the receipt field", async () => {
    const result = {
      verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
      evidence: [],
    } as unknown as EvaluateResponse;
    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expect(client.evaluate(testRequest())).resolves.toEqual(result);
    } finally {
      await closeServer(server);
    }
  });

  it("rejects allow responses that omit the receipt field", async () => {
    const result = {
      verdict: { verdict: "allow" },
      evidence: [],
    } as unknown as EvaluateResponse;

    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_invalid_receipt",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("rejects non-allow responses with receipts missing semantics fields", async () => {
    const result: EvaluateResponse = {
      verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
      receipt: {
        ...legacyBareReceipt(),
        verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
      },
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_evaluation_failed",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("rejects mediated decision receipts with observation outcomes", async () => {
    const result: EvaluateResponse = {
      verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
      receipt: {
        ...authoritativeAllowReceipt(),
        verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
        response_status: 403,
        observation_outcome: "observed",
      },
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_evaluation_failed",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("rejects advisory receipts without observation outcomes", async () => {
    const result: EvaluateResponse = {
      verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
      receipt: {
        ...advisoryAllowReceipt(),
        verdict: { verdict: "deny", reason: "blocked", guard: "policy", http_status: 403 },
        response_status: 403,
        observation_outcome: undefined,
      },
      evidence: [],
    };
    const { server, url } = await startEvaluateSidecar(result, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_evaluation_failed",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("throws evaluation-failed SidecarError for malformed JSON evaluate responses", async () => {
    const { server, url } = await startEvaluateRawSidecar("{not json");

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_evaluation_failed",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("throws evaluation-failed SidecarError for incomplete evaluate responses", async () => {
    const { server, url } = await startEvaluateSidecar({}, true);

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.evaluate(testRequest()),
        "chio_evaluation_failed",
      );
    } finally {
      await closeServer(server);
    }
  });
});

describe("ChioSidecarClient.verifyReceipt", () => {
  it("returns structured non-authorizing verifier reports", async () => {
    const { server, url } = await startVerifySidecar((res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(verifyResponse(false)));
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expect(client.verifyReceipt(legacyBareReceipt())).resolves.toEqual(
        verifyResponse(false),
      );
    } finally {
      await closeServer(server);
    }
  });

  it("throws invalid-receipt SidecarError for definitive non-200 verifier bodies", async () => {
    const cases: unknown[] = [{ valid: false }, { error: "chio_invalid_receipt" }];

    for (const body of cases) {
      const { server, url } = await startVerifySidecar((res) => {
        res.writeHead(422, { "Content-Type": "application/json" });
        res.end(JSON.stringify(body));
      });

      try {
        const client = new ChioSidecarClient({ sidecarUrl: url });
        await expectSidecarError(
          client.verifyReceipt(legacyBareReceipt()),
          "chio_invalid_receipt",
          422,
        );
      } finally {
        await closeServer(server);
      }
    }
  });

  it("throws evaluation-failed SidecarError for non-verdict 4xx verifier responses", async () => {
    const cases = [400, 401, 403, 422];

    for (const statusCode of cases) {
      const { server, url } = await startVerifySidecar((res) => {
        res.writeHead(statusCode, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "bad receipt" }));
      });

      try {
        const client = new ChioSidecarClient({ sidecarUrl: url });
        await expectSidecarError(
          client.verifyReceipt(legacyBareReceipt()),
          "chio_evaluation_failed",
          statusCode,
        );
      } finally {
        await closeServer(server);
      }
    }
  });

  it("throws sidecar-unavailable SidecarError for non-verdict unavailable verifier responses", async () => {
    const cases = [404, 429];

    for (const statusCode of cases) {
      const { server, url } = await startVerifySidecar((res) => {
        res.writeHead(statusCode, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "sidecar unavailable" }));
      });

      try {
        const client = new ChioSidecarClient({ sidecarUrl: url });
        await expectSidecarError(
          client.verifyReceipt(legacyBareReceipt()),
          "chio_sidecar_unavailable",
          statusCode,
        );
      } finally {
        await closeServer(server);
      }
    }
  });

  it("throws sidecar-unavailable SidecarError for 5xx verifier responses", async () => {
    const { server, url } = await startVerifySidecar((res) => {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "sidecar unavailable" }));
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.verifyReceipt(legacyBareReceipt()),
        "chio_sidecar_unavailable",
        503,
      );
    } finally {
      await closeServer(server);
    }
  });

  it("throws sidecar-unreachable SidecarError for network failure", async () => {
    const { server, url } = await startVerifySidecar((res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(verifyResponse(true)));
    });
    await closeServer(server);

    const client = new ChioSidecarClient({ sidecarUrl: url, timeoutMs: 250 });
    await expectSidecarError(
      client.verifyReceipt(legacyBareReceipt()),
      "chio_sidecar_unreachable",
    );
  });

  it("throws evaluation-failed SidecarError for malformed JSON verifier responses", async () => {
    const { server, url } = await startVerifySidecar((res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{not json");
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.verifyReceipt(legacyBareReceipt()),
        "chio_evaluation_failed",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("throws evaluation-failed SidecarError when verifier response omits valid", async () => {
    const { server, url } = await startVerifySidecar((res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.verifyReceipt(legacyBareReceipt()),
        "chio_evaluation_failed",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("throws timeout SidecarError when verifier body read times out", async () => {
    const { server, url } = await startVerifySidecar((res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write('{"valid":');
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url, timeoutMs: 25 });
      await expectSidecarError(
        client.verifyReceipt(legacyBareReceipt()),
        "chio_timeout",
      );
    } finally {
      await closeServer(server);
    }
  });

  it("throws sidecar-unreachable SidecarError when verifier body read fails", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      ({
        ok: true,
        text: async () => {
          throw new TypeError("terminated");
        },
        json: async () => {
          throw new TypeError("terminated");
        },
      }) as Response) as typeof fetch;

    try {
      const client = new ChioSidecarClient({ sidecarUrl: "http://127.0.0.1:9090" });
      await expectSidecarError(
        client.verifyReceipt(legacyBareReceipt()),
        "chio_sidecar_unreachable",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
