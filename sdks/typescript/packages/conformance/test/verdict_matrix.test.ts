import { describe, expect, it } from "vitest";
import { join, resolve } from "node:path";
import {
  evaluateScenario,
  runVerdictMatrixScenarios,
  scenarioToHttpRequest,
  tupleFromEvaluateResponse,
  type VerdictScenario,
} from "../../../../../crates/chio-conformance/verdict_matrix/drivers/typescript/run_scenarios.ts";

const repoRoot = resolve(import.meta.dirname, "../../../../..");
const scenarioRoot = join(repoRoot, "crates/chio-conformance/verdict_matrix/scenarios");

describe("verdict matrix TypeScript node-http driver", () => {
  it("reports scenarios as unsupported without a live sidecar", async () => {
    const previousMatrixSidecarUrl = process.env.CHIO_VERDICT_MATRIX_SIDECAR_URL;
    const previousSidecarUrl = process.env.CHIO_SIDECAR_URL;
    delete process.env.CHIO_VERDICT_MATRIX_SIDECAR_URL;
    delete process.env.CHIO_SIDECAR_URL;
    try {
      const outcomes = await runVerdictMatrixScenarios(scenarioRoot);
      const unsupported = outcomes.filter((outcome) => outcome.status === "unsupported");
      const failures = outcomes.filter((outcome) => outcome.status === "fail");

      expect(outcomes).toHaveLength(48);
      expect(unsupported).toHaveLength(48);
      expect(failures).toEqual([]);
    } finally {
      restoreEnv("CHIO_VERDICT_MATRIX_SIDECAR_URL", previousMatrixSidecarUrl);
      restoreEnv("CHIO_SIDECAR_URL", previousSidecarUrl);
    }
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
    expect(request.route_pattern).toBe("/chio/tools/verdict-matrix/files.read");
    expect(request.capability_id).toBe("cap-capability-subset-001-read-exact");
    expect(request.headers["content-type"]).toBe("application/json");
    expect(request.headers["x-verdict-scenario"]).toBeUndefined();
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
    await expect(evaluateScenario(scenario)).rejects.toThrow(
      "missing CHIO_VERDICT_MATRIX_SIDECAR_URL",
    );

    const actual = tupleFromEvaluateResponse({
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
        verdict: {
          verdict: "deny",
          reason: "urn:chio:error:capability:scope-exceeded",
          guard: "sidecar",
          http_status: 403,
        },
        caller_identity_hash: "a".repeat(64),
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
    });

    expect(actual).toEqual({
      verdict: "deny",
      reason_code: "urn:chio:error:capability:scope-exceeded",
      scope_set: ["tool:write"],
    });
  });
});

function restoreEnv(name: string, value: string | undefined): void {
  if (value == null) {
    delete process.env[name];
    return;
  }
  process.env[name] = value;
}
