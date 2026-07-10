/**
 * Fastify plugin for Chio protocol.
 *
 * Usage:
 *   import Fastify from "fastify";
 *   import { chio } from "@chio-protocol/fastify";
 *
 *   const fastify = Fastify();
 *   fastify.register(chio, { config: "chio.yaml" });
 *
 * The plugin intercepts every request via an onRequest hook, evaluates it
 * against the Chio sidecar kernel, and either allows it to proceed or
 * returns a structured error response with Chio error codes.
 */

import type {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyRequest,
  FastifyReply,
} from "fastify";
import fp from "fastify-plugin";
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
  VALID_METHODS,
  verdictStatus,
  verdictReason,
  shouldSkip,
} from "@chio-protocol/node-http";
import { createHash } from "node:crypto";
import { PassThrough } from "node:stream";

function decodeQueryComponent(value: string): string | undefined {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return undefined;
  }
}

/** Fastify-specific Chio config. */
export interface ChioFastifyConfig extends ChioConfig {
  /**
   * Skip Chio evaluation for specific paths.
   * Accepts exact paths or RegExp patterns.
   */
  skip?: Array<string | RegExp> | undefined;
}

/** Augment FastifyRequest to carry Chio evaluation result. */
declare module "fastify" {
  interface FastifyRequest {
    chioResult?: EvaluateResponse | undefined;
    chioRawBody?: Buffer | undefined;
  }
}

/**
 * Internal plugin implementation (before wrapping with fastify-plugin).
 */
const chioPlugin: FastifyPluginAsync<ChioFastifyConfig> = async (
  fastify: FastifyInstance,
  opts: ChioFastifyConfig,
): Promise<void> => {
  const resolved = resolveConfig(opts);
  const skipPatterns = opts.skip ?? [];

  // Decorate request with chioResult
  fastify.decorateRequest("chioResult", undefined);
  fastify.decorateRequest("chioRawBody", undefined);

  fastify.addHook("preParsing", async (request, _reply, payload) => {
    const chunks: Buffer[] = [];
    for await (const chunk of payload) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }

    const bodyBytes = Buffer.concat(chunks);
    request.chioRawBody = bodyBytes;

    const replay = new PassThrough();
    replay.end(bodyBytes);
    (replay as PassThrough & { receivedEncodedLength?: number }).receivedEncodedLength =
      bodyBytes.length;
    return replay;
  });

  // Register preHandler hook (runs after parsing, before the handler)
  fastify.addHook("preHandler", async (request: FastifyRequest, reply: FastifyReply) => {
    // Check skip patterns
    const path = request.url.split("?")[0] ?? request.url;
    if (shouldSkip(path, skipPatterns)) {
      return;
    }

    const method = request.method.toUpperCase();
    if (!VALID_METHODS.has(method)) {
      reply.code(405).send({
        error: CHIO_ERROR_CODES.EVALUATION_FAILED,
        message: `unsupported HTTP method: ${method}`,
      });
      return reply;
    }

    const httpMethod = method as HttpMethod;

    // Extract headers
    const rawHeaders: Record<string, string> = {};
    const headerObj: Record<string, string | string[] | undefined> = {};
    for (const [key, value] of Object.entries(request.headers)) {
      if (value != null) {
        rawHeaders[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
        headerObj[key] = value;
      }
    }

    // Extract caller identity
    const caller = resolved.identityExtractor(headerObj);

    // Get route pattern from Fastify's router
    const routePattern = extractRoutePattern(request, path);

    // Parse query parameters
    const query: Record<string, string> = {};
    const qIndex = request.url.indexOf("?");
    if (qIndex !== -1) {
      const qs = request.url.slice(qIndex + 1);
      for (const pair of qs.split("&")) {
        const eqIndex = pair.indexOf("=");
        if (eqIndex === -1) {
          const key = decodeQueryComponent(pair);
          if (key == null) {
            reply.code(400).send({
              error: CHIO_ERROR_CODES.EVALUATION_FAILED,
              message: "malformed query parameter encoding",
            });
            return reply;
          }
          query[key] = "";
        } else {
          const key = decodeQueryComponent(pair.slice(0, eqIndex));
          const value = decodeQueryComponent(pair.slice(eqIndex + 1));
          if (key == null || value == null) {
            reply.code(400).send({
              error: CHIO_ERROR_CODES.EVALUATION_FAILED,
              message: "malformed query parameter encoding",
            });
            return reply;
          }
          query[key] = value;
        }
      }
    }

    // Compute body hash from the raw request bytes captured in preParsing.
    let bodyHash: string | undefined;
    let bodyLength = 0;
    const rawBody = request.chioRawBody;
    if (rawBody != null && rawBody.length > 0) {
      bodyLength = rawBody.length;
      bodyHash = createHash("sha256").update(rawBody).digest("hex");
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
      const receipt = result.receipt;

      if (
        !isAllowed(result.verdict)
        || receipt == null
        || !isAuthorizedHttpReceipt(receipt)
      ) {
        const payload: {
          error: string;
          message: string;
          receipt_id?: string;
          suggestion: string;
        } = {
          error: CHIO_ERROR_CODES.ACCESS_DENIED,
          message: verdictReason(result.verdict),
          suggestion: "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
        };
        if (receipt?.id != null) {
          payload.receipt_id = receipt.id;
        }
        reply.code(verdictStatus(result.verdict)).send(payload);
        return reply;
      }

      const verification = await resolved.client.verifyReceipt(receipt);
      if (!isAuthoritativeVerification(verification, receipt)) {
        reply.code(502).send({
          error: CHIO_ERROR_CODES.INVALID_RECEIPT,
          message: "sidecar returned an unverified receipt",
          receipt_id: receipt.id,
        });
        return reply;
      }

      // Attach receipt ID header after authorization and receipt verification.
      reply.header("X-Chio-Receipt-Id", receipt.id);

      // Attach result for downstream handlers
      request.chioResult = result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      reply.code(502).send({
        error: CHIO_ERROR_CODES.SIDECAR_UNREACHABLE,
        message,
      });
      return reply;
    }
  });
};

/**
 * Fastify plugin that evaluates every request against Chio.
 * Wrapped with fastify-plugin to skip encapsulation, so hooks apply
 * to all routes in the Fastify instance.
 */
export const chio = fp(chioPlugin, {
  name: "@chio-protocol/fastify",
  fastify: ">=4.0.0",
});

// -- Helpers --

function extractRoutePattern(request: FastifyRequest, fallbackPath: string): string {
  // Fastify provides routeOptions.url which is the route pattern
  if (request.routeOptions != null && typeof request.routeOptions.url === "string") {
    return request.routeOptions.url;
  }
  return fallbackPath;
}
