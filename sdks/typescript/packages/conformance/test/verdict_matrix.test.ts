import { describe, expect, it } from "vitest";
import { join, resolve } from "node:path";
import {
  runVerdictMatrixScenarios,
  scenarioToHttpRequest,
  type VerdictScenario,
} from "../../../../../crates/chio-conformance/verdict_matrix/drivers/typescript/run_scenarios.ts";

const repoRoot = resolve(import.meta.dirname, "../../../../..");
const scenarioRoot = join(repoRoot, "crates/chio-conformance/verdict_matrix/scenarios");

describe("verdict matrix TypeScript node-http driver", () => {
  it("emits the expected tuple for every active scenario", async () => {
    const outcomes = await runVerdictMatrixScenarios(scenarioRoot);
    const failures = outcomes.filter((outcome) => outcome.status !== "pass");

    expect(outcomes).toHaveLength(48);
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
});
