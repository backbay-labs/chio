import { describe, expect, it } from "vitest";
import { createServer } from "node:http";
import { join, resolve } from "node:path";
import {
  evaluateScenario,
  runVerdictMatrixScenarios,
  scenarioToHttpRequest,
  type VerdictScenario,
} from "../../../../../crates/chio-conformance/verdict_matrix/drivers/typescript/run_scenarios.ts";

const repoRoot = resolve(import.meta.dirname, "../../../../..");
const scenarioRoot = join(repoRoot, "crates/chio-conformance/verdict_matrix/scenarios");

describe("verdict matrix TypeScript node-http driver", () => {
  it("reports scenarios as unsupported without a live sidecar", async () => {
    const outcomes = await runVerdictMatrixScenarios(scenarioRoot);
    const unsupported = outcomes.filter((outcome) => outcome.status === "unsupported");
    const failures = outcomes.filter((outcome) => outcome.status === "fail");

    expect(outcomes).toHaveLength(48);
    expect(unsupported).toHaveLength(48);
    expect(failures).toEqual([]);
  });

  it("adapts neutral tool calls into node-http SDK requests", () => {
    const scenario: VerdictScenario = {
      schema: "chio.verdict-matrix.scenario.v1",
      id: "capability-subset-001-read-exact",
      category: "capability",
      script: {
        operation: "tool.call",
        tool: "files.read",
        input_json: "{\"path\":\"README.md\"}",
        capability_scopes: ["tool:read"],
        required_scope: "tool:read",
      },
      expected: {
        verdict: "allow",
        reason_code: "urn:chio:error:none",
        scope_set: ["tool:read"],
      },
    };

    const request = scenarioToHttpRequest(scenario);

    expect(request.method).toBe("GET");
    expect(request.route_pattern).toBe("verdict-matrix:files.read");
    expect(request.capability_id).toBe("cap-capability-subset-001-read-exact");
    expect(request.headers["content-type"]).toBe("application/json");
  });

  it("projects the tuple from the sidecar response instead of scenario fields", async () => {
    const scenario: VerdictScenario = {
      schema: "chio.verdict-matrix.scenario.v1",
      id: "capability-subset-001-read-exact",
      category: "capability",
      script: {
        operation: "tool.call",
        tool: "files.read",
        input_json: "{\"path\":\"README.md\"}",
        capability_scopes: ["tool:read"],
        required_scope: "tool:read",
      },
      expected: {
        verdict: "allow",
        reason_code: "urn:chio:error:none",
        scope_set: ["tool:read"],
      },
    };
    const server = createServer((req, res) => {
      if (req.method !== "POST" || req.url !== "/chio/evaluate") {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        verdict: {
          verdict: "deny",
          reason: "urn:chio:error:capability:scope-exceeded",
          guard: "sidecar",
          http_status: 403,
        },
        evidence: [],
        receipt: {
          id: "receipt-sidecar",
          request_id: "request-sidecar",
          route_pattern: "verdict-matrix:files.read",
          method: "GET",
          caller_identity_hash: "a".repeat(64),
          verdict: {
            verdict: "deny",
            reason: "urn:chio:error:capability:scope-exceeded",
            guard: "sidecar",
            http_status: 403,
          },
          evidence: [],
          response_status: 403,
          timestamp: 1,
          content_hash: "b".repeat(64),
          policy_hash: "policy",
          metadata: {
            verdict_matrix: {
              reason_code: "urn:chio:error:capability:scope-exceeded",
              scope_set: ["tool:write"],
            },
          },
          kernel_key: "kernel",
          signature: "signature",
        },
      }));
    });
    const sidecarUrl = await listen(server);
    try {
      await expect(evaluateScenario(scenario)).rejects.toThrow(
        "missing CHIO_VERDICT_MATRIX_SIDECAR_URL",
      );
      const actual = await evaluateScenario(scenario, { sidecarUrl });

      expect(actual).toEqual({
        verdict: "deny",
        reason_code: "urn:chio:error:capability:scope-exceeded",
        scope_set: ["tool:write"],
      });
    } finally {
      await close(server);
    }
  });
});

function listen(server: ReturnType<typeof createServer>): Promise<string> {
  return new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (address == null || typeof address === "string") {
        reject(new Error("server did not bind to an IPv4 address"));
        return;
      }
      resolveListen(`http://127.0.0.1:${address.port}`);
    });
  });
}

function close(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolveClose, reject) => {
    server.close((error) => {
      if (error != null) {
        reject(error);
        return;
      }
      resolveClose();
    });
  });
}
