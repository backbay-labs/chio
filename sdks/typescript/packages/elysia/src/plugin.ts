/**
 * Elysia lifecycle hook for Chio protocol.
 *
 * Usage:
 *   import { Elysia } from "elysia";
 *   import { chio } from "@chio-protocol/elysia";
 *
 *   const app = new Elysia()
 *     .use(chio({ config: "chio.yaml" }))
 *     .get("/", () => "Hello");
 *
 * The plugin intercepts every request via Elysia's beforeHandle lifecycle,
 * evaluates it against the Chio sidecar kernel, and either allows it to
 * proceed or returns a structured error response with Chio error codes.
 */

import { Elysia } from "elysia";
import {
  type ChioConfig,
  type EvaluateResponse,
  type HttpMethod,
  CHIO_ERROR_CODES,
  isAuthoritativeVerification,
  isAuthorizedHttpReceipt,
  isAllowed,
  resolveConfig,
  buildChioHttpRequest,
  extractRequestPath,
  type Verdict,
} from "@chio-protocol/node-http";
import { createHash } from "node:crypto";

/** Elysia-specific Chio config. */
export interface ChioElysiaConfig extends ChioConfig {
  /**
   * Skip Chio evaluation for specific paths.
   * Accepts exact paths or RegExp patterns.
   */
  skip?: Array<string | RegExp> | undefined;
}

/** Valid HTTP methods for Chio evaluation. */
const VALID_METHODS = new Set<string>([
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
]);

/** Per-request Chio evaluation results keyed by Request object. */
const requestChioResults = new WeakMap<Request, EvaluateResponse>();

function verdictStatus(verdict: Verdict): number {
  return "http_status" in verdict ? verdict.http_status : 403;
}

function verdictReason(verdict: Verdict): string {
  return "reason" in verdict ? verdict.reason : "request was not authorized";
}

/**
 * Create an Elysia plugin that evaluates every request against Chio.
 *
 * @example
 * ```ts
 * import { Elysia } from "elysia";
 * import { chio } from "@chio-protocol/elysia";
 *
 * const app = new Elysia()
 *   .use(chio({ config: "chio.yaml" }))
 *   .get("/pets", () => [{ name: "Fido" }]);
 * ```
 */
export function chio(config: ChioElysiaConfig = {}) {
  const resolved = resolveConfig(config);
  const skipPatterns = config.skip ?? [];

  return new Elysia({ name: "@chio-protocol/elysia" })
    .onBeforeHandle({ as: "global" }, async ({ request, set }) => {
      const path = extractRequestPath(request.url);
      const url = new URL(request.url);

      // Check skip patterns
      if (shouldSkip(path, skipPatterns)) {
        return undefined;
      }

      const method = request.method.toUpperCase();
      if (!VALID_METHODS.has(method)) {
        set.status = 405;
        return {
          error: CHIO_ERROR_CODES.EVALUATION_FAILED,
          message: `unsupported HTTP method: ${method}`,
        };
      }

      const httpMethod = method as HttpMethod;

      // Extract headers
      const rawHeaders: Record<string, string> = {};
      const headerObj: Record<string, string | string[] | undefined> = {};
      request.headers.forEach((value, key) => {
        rawHeaders[key.toLowerCase()] = value;
        headerObj[key] = value;
      });

      // Extract caller identity
      const caller = resolved.identityExtractor(headerObj);
      const routePattern = resolved.routePatternResolver(httpMethod, path);

      // Parse query parameters
      const query: Record<string, string> = {};
      url.searchParams.forEach((value, key) => {
        query[key] = value;
      });

      // Compute body hash
      let bodyHash: string | undefined;
      let bodyLength = 0;
      if (request.body != null) {
        try {
          // Clone request to read the body without consuming it
          const cloned = request.clone();
          const bodyBytes = new Uint8Array(await cloned.arrayBuffer());
          bodyLength = bodyBytes.length;
          if (bodyLength > 0) {
            bodyHash = createHash("sha256").update(bodyBytes).digest("hex");
          }
        } catch (error) {
          set.status = 400;
          return {
            error: CHIO_ERROR_CODES.EVALUATION_FAILED,
            message: `request body could not be read for Chio evaluation: ${error instanceof Error ? error.message : String(error)}`,
          };
        }
      }

      const capabilityToken = rawHeaders["x-chio-capability"] ?? query["chio_capability"] ?? undefined;
      let capabilityId: string | undefined;
      if (capabilityToken != null) {
        try {
          const parsed = JSON.parse(capabilityToken) as { id?: unknown };
          capabilityId = typeof parsed.id === "string" ? parsed.id : undefined;
        } catch {
          capabilityId = undefined;
        }
      }

      const chioReq = buildChioHttpRequest({
        method: httpMethod,
        path,
        query,
        headers: rawHeaders,
        caller,
        bodyHash,
        bodyLength,
        routePattern,
        capabilityId,
        forwardHeaders: resolved.forwardHeaders,
      });

      try {
        const result = await resolved.client.evaluate(chioReq, rawHeaders["x-chio-capability"] ?? undefined);

        if (!isAllowed(result.verdict) || !isAuthorizedHttpReceipt(result.receipt)) {
          set.status = verdictStatus(result.verdict);
          return {
            error: CHIO_ERROR_CODES.ACCESS_DENIED,
            message: verdictReason(result.verdict),
            receipt_id: result.receipt.id,
            suggestion: "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
          };
        }

        const verification = await resolved.client.verifyReceipt(result.receipt);
        if (!isAuthoritativeVerification(verification, result.receipt)) {
          set.status = 502;
          return {
            error: CHIO_ERROR_CODES.INVALID_RECEIPT,
            message: "sidecar returned an unverified receipt",
            receipt_id: result.receipt.id,
          };
        }

        // Set receipt header after authorization and receipt verification.
        set.headers["X-Chio-Receipt-Id"] = result.receipt.id;
        requestChioResults.set(request, result);

        // Allow the request to proceed
        return undefined;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        set.status = 502;
        return {
          error: CHIO_ERROR_CODES.SIDECAR_UNREACHABLE,
          message,
        };
      }
    })
    .resolve({ as: "scoped" }, ({ request }) => ({
      chioResult: requestChioResults.get(request),
    }));
}

// -- Helpers --

function shouldSkip(path: string, patterns: Array<string | RegExp>): boolean {
  for (const pattern of patterns) {
    if (typeof pattern === "string") {
      if (path === pattern) return true;
    } else {
      if (pattern.test(path)) return true;
    }
  }
  return false;
}
