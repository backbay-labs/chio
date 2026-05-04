import http from "node:http";
import { describe, it, expect } from "vitest";
import { ChioSidecarClient, resolveSidecarUrl, SidecarError } from "../src/sidecar-client.js";
import type { HttpReceipt } from "../src/types.js";

function testReceipt(): HttpReceipt {
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
  };
}

async function startVerifySidecar(
  onVerify: (res: http.ServerResponse) => void,
): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/chio/verify") {
      onVerify(res);
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

describe("ChioSidecarClient.verifyReceipt", () => {
  it("returns false without error when the verifier returns valid false", async () => {
    const { server, url } = await startVerifySidecar((res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ valid: false }));
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expect(client.verifyReceipt(testReceipt())).resolves.toBe(false);
    } finally {
      await closeServer(server);
    }
  });

  it("throws invalid-receipt SidecarError for 4xx verifier responses", async () => {
    const { server, url } = await startVerifySidecar((res) => {
      res.writeHead(422, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "bad receipt" }));
    });

    try {
      const client = new ChioSidecarClient({ sidecarUrl: url });
      await expectSidecarError(
        client.verifyReceipt(testReceipt()),
        "chio_invalid_receipt",
        422,
      );
    } finally {
      await closeServer(server);
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
        client.verifyReceipt(testReceipt()),
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
      res.end(JSON.stringify({ valid: true }));
    });
    await closeServer(server);

    const client = new ChioSidecarClient({ sidecarUrl: url, timeoutMs: 250 });
    await expectSidecarError(
      client.verifyReceipt(testReceipt()),
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
        client.verifyReceipt(testReceipt()),
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
        client.verifyReceipt(testReceipt()),
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
        client.verifyReceipt(testReceipt()),
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
        client.verifyReceipt(testReceipt()),
        "chio_sidecar_unreachable",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
