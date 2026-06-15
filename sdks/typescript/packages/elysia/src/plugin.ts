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
  VALID_METHODS,
  verdictStatus,
  verdictReason,
  shouldSkip,
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

// Note: this plugin keeps its own Web Request handling below rather than
// delegating to interceptWebRequest from @chio-protocol/node-http (the way
// Express uses interceptNodeRequest). Elysia's beforeHandle swallows body-read
// errors (continue without a body hash) and drives responses through
// `set.status`/`set.headers`, whereas interceptWebRequest throws on unreadable
// bodies and returns a marker Response. Sharing only the pure helpers
// (VALID_METHODS/verdictStatus/verdictReason/shouldSkip) keeps behavior
// byte-for-byte identical.

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
    .state("chioResult", undefined as EvaluateResponse | undefined)
    .derive({ as: "global" }, ({ store }) => ({
      chioResult: store.chioResult,
    }))
    .onBeforeHandle({ as: "global" }, async ({ request, set, store }) => {
      const url = new URL(request.url);
      const path = url.pathname;

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
        } catch {
          // Body may not be readable; continue without hash
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
        store.chioResult = result;

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
    });
}
