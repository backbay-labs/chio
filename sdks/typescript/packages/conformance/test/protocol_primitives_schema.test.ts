import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import type {
  Agent_ActiveResponseGovernedIntent,
  Capability_AggregateInvocationBudget,
  Capability_GovernedApprovalToken,
  Capability_SupplementalAuthorization,
  Capability_ThresholdApprovalProposal,
  Capability_Token,
  Kernel_CombinedCaptureMetadata,
} from "../src/_generated/index.js";

type ProtocolPrimitive =
  | Agent_ActiveResponseGovernedIntent.ChioGovernedActiveResponseIntentBody
  | Capability_AggregateInvocationBudget.ChioAggregateInvocationBudget
  | Capability_GovernedApprovalToken.ChioGovernedApprovalToken
  | Capability_SupplementalAuthorization.ChioOpaqueSupplementalAuthorization
  | Capability_ThresholdApprovalProposal.ChioThresholdApprovalProposal
  | Capability_Token.ChioCapabilitytoken
  | Kernel_CombinedCaptureMetadata.ChioCombinedAdmissionCaptureMetadata;

interface FixtureCase {
  name: string;
  schema_file: string;
  valid: boolean;
  instance: ProtocolPrimitive | Record<string, unknown>;
}

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../..");
const schemaRoot = resolve(workspaceRoot, "spec/schemas/chio-wire/v1");
const corpus = JSON.parse(
  readFileSync(
    resolve(workspaceRoot, "tests/bindings/fixtures/protocol-primitives-v1.json"),
    "utf8",
  ),
) as { cases: FixtureCase[] };

const schemaFiles = new Set(corpus.cases.map((fixture) => fixture.schema_file));
schemaFiles.add("capability/aggregate-budget-root.schema.json");
schemaFiles.add("capability/cumulative-approval-root.schema.json");

const ajv = new Ajv2020({ allErrors: true, strict: false });
for (const schemaFile of schemaFiles) {
  ajv.addSchema(JSON.parse(readFileSync(resolve(schemaRoot, schemaFile), "utf8")));
}

describe("protocol primitive generated schemas", () => {
  it("compile and validate the shared positive and negative fixtures", () => {
    for (const fixture of corpus.cases) {
      const schema = JSON.parse(
        readFileSync(resolve(schemaRoot, fixture.schema_file), "utf8"),
      ) as { $id: string };
      const validate = ajv.getSchema(schema.$id);
      expect(validate, fixture.name).toBeDefined();
      expect(validate?.(fixture.instance), fixture.name).toBe(fixture.valid);
      if (fixture.valid) {
        expect(JSON.parse(JSON.stringify(fixture.instance))).toEqual(fixture.instance);
      }
    }
  });
});
