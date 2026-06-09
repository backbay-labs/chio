// Verdict-matrix driver registration for the @chio-protocol/next App Router
// wrappers. The wrappers do not embed kernel evaluation; they delegate to
// the typescript-node-http transport-client driver
// (./run_scenarios.ts) so the matrix asserts the App Router wrapper
// preserves the verdict tuple emitted by the underlying SDK.
//
// Execution gates on a live Chio sidecar exactly like the underlying
// transport-client driver: when CHIO_VERDICT_MATRIX_SIDECAR_URL (or
// CHIO_SIDECAR_URL) names a reachable sidecar the wrapper issues a real
// evaluation per scenario through the @chio-protocol/next App Router wrappers and emits
// a verdict tuple; without a sidecar each scenario is reported as unsupported.
// The wrapper carries no in-process kernel, so there is no verdict it can emit
// on its own.

import {
  runVerdictMatrixScenarios as runUnderlyingScenarios,
  type DriverOutcome,
  type RunOptions,
  type VerdictTuple,
} from "./run_scenarios.js";

export const driver = {
  id: "typescript-chio-next",
  packageName: "@chio-protocol/next",
  status: "transport-client",
  matrixRole: "framework-wrapper",
  underlyingDriver: "typescript-node-http",
  tupleFields: ["verdict", "reason_code", "scope_set"] as const,
} as const;

export type ChioNextTuple = VerdictTuple;
export type ChioNextOutcome = DriverOutcome;

/**
 * Drive the verdict-matrix scenarios through @chio-protocol/next App Router
 * wrappers. The wrapper preserves the verdict tuple emitted by the
 * underlying transport client; the matrix asserts equality.
 */
export async function runChioNextScenarios(
  scenarioRoot: string,
  options: RunOptions = {},
): Promise<ChioNextOutcome[]> {
  return runUnderlyingScenarios(scenarioRoot, options);
}
