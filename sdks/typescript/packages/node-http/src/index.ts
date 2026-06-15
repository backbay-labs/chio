/**
 * @chio-protocol/node-http
 *
 * Common HTTP interception substrate for the Chio protocol.
 * Works with Node.js and Bun runtimes. Provides:
 *
 * - Identity extraction from Authorization headers, cookies, API keys
 * - Chio sidecar client for localhost HTTP evaluation
 * - Node.js (req, res) interception
 * - Web API (Request -> Response) interception
 * - Signed receipt production via Chio sidecar
 */

export * from "./types.js";
export * from "./identity.js";
export * from "./sidecar-client.js";
export {
  VALID_METHODS,
  verdictStatus,
  verdictReason,
  shouldSkip,
} from "./http-helpers.js";
export {
  interceptNodeRequest,
  interceptWebRequest,
  getBufferedNodeRequestBody,
  buildChioHttpRequest,
  preserveReadableBody,
  resolveConfig,
  extractRequestPath,
  type ResolvedConfig,
  type BuildRequestOptions,
  type NodeInterceptionOutcome,
  type WebInterceptionOutcome,
  type PreserveReadableBodyOptions,
} from "./interceptor.js";
