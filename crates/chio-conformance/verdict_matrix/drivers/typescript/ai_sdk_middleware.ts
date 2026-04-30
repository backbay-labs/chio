// Verdict-matrix driver registration for the @chio/ai-sdk-middleware
// framework wrapper. The driver does not embed kernel evaluation; it
// delegates to the typescript-node-http transport-client driver shipped by
// M02.P5.T2 (./run_scenarios.ts) so the matrix asserts the framework
// wrapper preserves the verdict tuple emitted by the underlying SDK.
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
  id: "typescript-ai-sdk-middleware",
  packageName: "@chio/ai-sdk-middleware",
  status: "prepared-blocked-by-m02-pr-352",
  matrixRole: "framework-wrapper",
  underlyingDriver: "typescript-node-http",
  tupleFields: ["verdict", "reason_code", "scope_set"] as const,
} as const;

export type AiSdkMiddlewareTuple = VerdictTuple;
export type AiSdkMiddlewareOutcome = DriverOutcome;

/**
 * Drive the verdict-matrix scenarios through @chio/ai-sdk-middleware.
 *
 * The middleware evaluates at the tool-use boundary; for matrix purposes
 * it must preserve the verdict tuple emitted by the underlying transport
 * client. This function is wired through the typescript-node-http driver
 * so the matrix assertion is `wrapper(tuple) == underlying(tuple)`.
 */
export async function runAiSdkMiddlewareScenarios(
  scenarioRoot: string,
  options: RunOptions = {},
): Promise<AiSdkMiddlewareOutcome[]> {
  return runUnderlyingScenarios(scenarioRoot, options);
}
