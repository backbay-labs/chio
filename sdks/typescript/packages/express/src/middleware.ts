/**
 * Express middleware for Chio protocol.
 *
 * Usage:
 *   import { chio } from "@chio-protocol/express";
 *   app.use(chio({ config: "chio.yaml" }));
 *
 * The middleware intercepts every request, evaluates it against the Chio
 * sidecar kernel, and either allows it to proceed or returns a structured
 * error response with Chio error codes.
 */

import type { Request, Response, NextFunction, RequestHandler } from "express";
import {
  type ChioConfig,
  type ChioPassthrough,
  type EvaluateResponse,
  type HttpMethod,
  type Verdict,
  CHIO_ERROR_CODES,
  isDenied,
  resolveConfig,
  interceptNodeRequest,
  preserveReadableBody,
  shouldSkip,
} from "@chio-protocol/node-http";

/** Express-specific Chio config with route pattern extraction. */
export interface ChioExpressConfig extends ChioConfig {
  /**
   * Skip Chio evaluation for specific paths.
   * Accepts exact paths or RegExp patterns.
   */
  skip?: Array<string | RegExp> | undefined;
}

/**
 * Create an Express middleware that evaluates every request against Chio.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { chio } from "@chio-protocol/express";
 *
 * const app = express();
 * app.use(chio({ config: "chio.yaml" }));
 * ```
 */
export function chio(config: ChioExpressConfig = {}): RequestHandler {
  const resolved = resolveConfig(config);
  const skipPatterns = config.skip ?? [];

  // Override route pattern resolver to use Express route information
  const originalResolver = resolved.routePatternResolver;
  resolved.routePatternResolver = (method: HttpMethod, path: string): string => {
    // Express populates req.route after matching. Since we run as
    // middleware before the route handler, we fall back to the raw path.
    // Framework-level route pattern is injected in the middleware below.
    return originalResolver(method, path);
  };

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Check skip patterns
    if (shouldSkip(req.path, skipPatterns)) {
      next();
      return;
    }

    try {
      // Use a per-request resolved config so concurrent route-pattern
      // injections cannot race through shared middleware state.
      const routePattern = extractRoutePattern(req);
      const requestResolved =
        routePattern == null
          ? resolved
          : { ...resolved, routePatternResolver: () => routePattern };
      const rawBody = await ensureExpressBufferedBody(req as ChioRequest);
      const outcome = await interceptNodeRequest(req, res, requestResolved);
      if (!outcome.responseSent) {
        hydrateExpressBody(req as ChioRequest, rawBody);
        if (outcome.result != null) {
          (req as ChioRequest).chioResult = outcome.result;
        }
        if (outcome.passthrough != null) {
          (req as ChioRequest).chioPassthrough = outcome.passthrough;
        }
        next();
      }
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Express request with Chio evaluation result attached.
 */
export interface ChioRequest extends Request {
  chioResult?: EvaluateResponse | undefined;
  chioPassthrough?: ChioPassthrough | undefined;
  rawBody?: Buffer | undefined;
  _body?: boolean | undefined;
}

/**
 * Express error handler that formats Chio errors as structured JSON.
 */
export function chioErrorHandler(
  err: Error,
  _req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (res.headersSent) {
    next(err);
    return;
  }

  // Check if this is a Chio-related error
  if ("code" in err && typeof (err as { code: unknown }).code === "string") {
    const code = (err as { code: string }).code;
    if (code.startsWith("chio_")) {
      res.status(502).json({
        error: code,
        message: err.message,
      });
      return;
    }
  }

  next(err);
}

// -- Helpers --

function extractRoutePattern(req: Request): string | null {
  // Express 4/5 populates req.route after matching.
  // In middleware that runs before route matching, this is not available.
  // We try req.route.path first, then fall back.
  if (req.route != null && typeof req.route.path === "string") {
    // Combine with baseUrl for mounted routers
    const base = req.baseUrl ?? "";
    return `${base}${req.route.path}`;
  }
  return null;
}

async function ensureExpressBufferedBody(req: ChioRequest): Promise<Buffer> {
  if (Buffer.isBuffer(req.rawBody)) {
    return req.rawBody;
  }

  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const rawBody = Buffer.concat(chunks);
  req.rawBody = rawBody;
  preserveReadableBody(req, rawBody);
  return rawBody;
}

function hydrateExpressBody(req: ChioRequest, rawBody: Buffer): void {
  if (req.body !== undefined) {
    return;
  }

  const contentTypeHeader = req.headers["content-type"];
  const contentType = Array.isArray(contentTypeHeader)
    ? contentTypeHeader[0]
    : contentTypeHeader;
  const normalizedType = contentType?.split(";")[0]?.trim().toLowerCase();

  try {
    if (normalizedType === "application/json" || normalizedType?.endsWith("+json") === true) {
      req.body = rawBody.length > 0 ? JSON.parse(rawBody.toString("utf-8")) : {};
      req._body = true;
      return;
    }

    if (normalizedType === "application/x-www-form-urlencoded") {
      req.body = Object.fromEntries(
        new URLSearchParams(rawBody.toString("utf-8")).entries(),
      );
      req._body = true;
      return;
    }

    if (normalizedType?.startsWith("text/") === true) {
      req.body = rawBody.toString("utf-8");
      req._body = true;
      return;
    }

    if (rawBody.length > 0) {
      req.body = rawBody;
      req._body = true;
    }
  } catch {
    // Leave body parsing to downstream middleware when Chio cannot safely infer it.
  }
}
