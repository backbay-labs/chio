/**
 * @chio-protocol/express
 *
 * Express middleware for the Chio protocol. Provides:
 *
 * - `chio()` middleware that evaluates requests against the Chio sidecar
 * - `chioErrorHandler` for structured Chio error responses
 * - Chio evaluation results attached to req.chioResult when Chio produced a signed receipt
 *
 * @example
 * ```ts
 * import express from "express";
 * import { chio, chioErrorHandler } from "@chio-protocol/express";
 *
 * const app = express();
 * app.use(chio({ config: "chio.yaml" }));
 * app.use(chioErrorHandler);
 * ```
 */

export { chio, chioErrorHandler, type ChioExpressConfig, type ChioRequest } from "./middleware.js";

// Re-export key types from node-http for convenience
export type {
  ChioConfig,
  ChioPassthrough,
  EvaluateResponse,
  HttpReceipt,
  Verdict,
  CallerIdentity,
  GuardEvidence,
  ChioErrorResponse,
} from "@chio-protocol/node-http";
