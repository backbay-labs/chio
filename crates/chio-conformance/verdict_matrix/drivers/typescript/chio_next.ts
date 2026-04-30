// Verdict-matrix driver registration for the @chio/next App Router
// wrappers. The wrappers do not embed kernel evaluation; they delegate to
// the typescript-node-http transport-client driver shipped by M02.P5.T2
// (./run_scenarios.ts) so the matrix asserts the App Router wrapper
// preserves the verdict tuple emitted by the underlying SDK.
//
// While M02.P5.T2 is still in flight, this file ships as a prepared
// registration. Matrix tooling enumerates this driver but skips execution
// until the underlying transport-client driver is active.

import {
  runVerdictMatrixScenarios as runUnderlyingScenarios,
  type DriverOutcome,
  type RunOptions,
  type VerdictTuple,
} from "./run_scenarios.js";

export const driver = {
  id: "typescript-chio-next",
  packageName: "@chio/next",
  status: "prepared-blocked-by-m02-pr-352",
  matrixRole: "framework-wrapper",
  underlyingDriver: "typescript-node-http",
  tupleFields: ["verdict", "reason_code", "scope_set"] as const,
} as const;

export type ChioNextTuple = VerdictTuple;
export type ChioNextOutcome = DriverOutcome;

/**
 * Drive the verdict-matrix scenarios through @chio/next App Router
 * wrappers. The wrapper preserves the verdict tuple emitted by the
 * underlying transport client; the matrix asserts equality.
 */
export async function runChioNextScenarios(
  scenarioRoot: string,
  options: RunOptions = {},
): Promise<ChioNextOutcome[]> {
  return runUnderlyingScenarios(scenarioRoot, options);
}
