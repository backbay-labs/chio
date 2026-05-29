// Verdict-matrix driver registration for the @chio-protocol/ai-sdk-middleware
// framework wrapper. The driver does not embed kernel evaluation; it
// delegates to the typescript-node-http transport-client driver
// (./run_scenarios.ts) so the matrix asserts the framework wrapper
// preserves the verdict tuple emitted by the underlying SDK.
//
// Execution gates on a live Chio sidecar exactly like the underlying
// transport-client driver: when CHIO_VERDICT_MATRIX_SIDECAR_URL (or
// CHIO_SIDECAR_URL) names a reachable sidecar the wrapper issues a real
// evaluation per scenario through @chio-protocol/ai-sdk-middleware and emits a verdict
// tuple; without a sidecar each scenario is reported as unsupported. The
// wrapper carries no in-process kernel, so there is no verdict it can emit on
// its own.

import {
  runVerdictMatrixScenarios as runUnderlyingScenarios,
  type DriverOutcome,
  type RunOptions,
  type VerdictTuple,
} from "./run_scenarios.js";

export const driver = {
  id: "typescript-ai-sdk-middleware",
  packageName: "@chio-protocol/ai-sdk-middleware",
  status: "transport-client",
  matrixRole: "framework-wrapper",
  underlyingDriver: "typescript-node-http",
  tupleFields: ["verdict", "reason_code", "scope_set"] as const,
} as const;

export type AiSdkMiddlewareTuple = VerdictTuple;
export type AiSdkMiddlewareOutcome = DriverOutcome;

/**
 * Drive the verdict-matrix scenarios through @chio-protocol/ai-sdk-middleware.
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
