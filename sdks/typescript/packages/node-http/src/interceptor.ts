/**
 * HTTP request interceptor -- the core interception substrate.
 *
 * Handles both Node.js (req, res) and Web API (Request -> Response) patterns.
 * Extracts caller identity, builds ChioHttpRequest, sends to sidecar,
 * and produces signed receipts.
 */

import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { PassThrough } from "node:stream";
import { defaultIdentityExtractor } from "./identity.js";
import { ChioSidecarClient, SidecarError } from "./sidecar-client.js";
import type {
  ChioConfig,
  ChioErrorResponse,
  ChioHttpRequest,
  ChioPassthrough,
  CallerIdentity,
  EvaluateResponse,
  HttpMethod,
  IdentityExtractor,
  RoutePatternResolver,
  Verdict,
} from "./types.js";
import {
  CHIO_ERROR_CODES,
  isAllowed,
  isAuthoritativeVerification,
  isAuthorizedHttpReceipt,
} from "./types.js";

const bufferedNodeBodies = new WeakMap<IncomingMessage, Buffer>();

// -- Helpers --

function sha256Hex(input: Uint8Array | string): string {
  return createHash("sha256").update(input).digest("hex");
}

function normalizeMethod(method: string): HttpMethod | null {
  const upper = method.toUpperCase();
  const valid: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
  return valid.includes(upper as HttpMethod) ? (upper as HttpMethod) : null;
}

function headersToRecord(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value != null) {
      result[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
    }
  }
  return result;
}

function parseQueryString(url: string): Record<string, string> {
  const query: Record<string, string> = {};
  const qIndex = url.indexOf("?");
  if (qIndex === -1) return query;
  const qs = url.slice(qIndex + 1);
  for (const pair of qs.split("&")) {
    const eqIndex = pair.indexOf("=");
    if (eqIndex === -1) {
      query[decodeURIComponent(pair)] = "";
    } else {
      const key = decodeURIComponent(pair.slice(0, eqIndex));
      const value = decodeURIComponent(pair.slice(eqIndex + 1));
      query[key] = value;
    }
  }
  return query;
}

function extractPath(url: string): string {
  const qIndex = url.indexOf("?");
  return qIndex === -1 ? url : url.slice(0, qIndex);
}

function verdictStatus(verdict: Verdict): number {
  return "http_status" in verdict ? verdict.http_status : 403;
}

function verdictReason(verdict: Verdict): string {
  return "reason" in verdict ? verdict.reason : "request was not authorized";
}

/** Default route pattern resolver -- returns the raw path as pattern. */
const defaultRoutePatternResolver: RoutePatternResolver = (_method, path) => path;

// -- Resolved config with defaults applied --

export interface ResolvedConfig {
  sidecarUrl: string;
  identityExtractor: IdentityExtractor;
  routePatternResolver: RoutePatternResolver;
  onSidecarError: "deny" | "allow";
  timeoutMs: number;
  forwardHeaders: string[];
  client: ChioSidecarClient;
}

/** Resolve config defaults. */
export function resolveConfig(config: ChioConfig): ResolvedConfig {
  const client = new ChioSidecarClient(config);
  return {
    sidecarUrl: config.sidecarUrl ?? process.env["CHIO_SIDECAR_URL"] ?? "http://127.0.0.1:9090",
    identityExtractor: config.identityExtractor ?? defaultIdentityExtractor,
    routePatternResolver: config.routePatternResolver ?? defaultRoutePatternResolver,
    onSidecarError: "deny",
    timeoutMs: config.timeoutMs ?? 5000,
    forwardHeaders: config.forwardHeaders ?? ["content-type", "content-length"],
    client,
  };
}

// -- Build ChioHttpRequest from Node.js IncomingMessage --

export interface BuildRequestOptions {
  method: HttpMethod;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  caller: CallerIdentity;
  bodyHash: string | undefined;
  bodyLength: number;
  routePattern: string;
  capabilityId: string | undefined;
  /**
   * Optional sidecar tool-server identity. Required for synthetic tool-call
   * evaluations so the kernel's capability-scope checks see
   * `requested_tool_server` and can apply scope-subset rules.
   */
  toolServer?: string | undefined;
  /** Optional sidecar tool name (companion to `toolServer`). */
  toolName?: string | undefined;
  /** Optional structured arguments forwarded with synthetic tool calls. */
  toolArguments?: unknown;
  modelMetadata?: ChioHttpRequest["model_metadata"] | undefined;
}

export function getBufferedNodeRequestBody(req: IncomingMessage): Buffer | undefined {
  return bufferedNodeBodies.get(req);
}

export interface NodeInterceptionOutcome {
  responseSent: boolean;
  result: EvaluateResponse | null;
  passthrough: ChioPassthrough | null;
}

export interface WebInterceptionOutcome {
  response: Response;
  result: EvaluateResponse | null;
  passthrough: ChioPassthrough | null;
}

function capabilityIdFromToken(rawToken: string | undefined): string | undefined {
  if (rawToken == null || rawToken.length === 0) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(rawToken) as { id?: unknown };
    return typeof parsed.id === "string" ? parsed.id : undefined;
  } catch {
    return undefined;
  }
}

/** Build a ChioHttpRequest from extracted request parts. */
export function buildChioHttpRequest(opts: BuildRequestOptions): ChioHttpRequest {
  return {
    request_id: randomUUID(),
    method: opts.method,
    route_pattern: opts.routePattern,
    path: opts.path,
    query: opts.query,
    headers: filterHeaders(opts.headers, ["content-type", "content-length"]),
    caller: opts.caller,
    body_hash: opts.bodyHash,
    body_length: opts.bodyLength,
    session_id: undefined,
    capability_id: opts.capabilityId,
    tool_server: opts.toolServer,
    tool_name: opts.toolName,
    arguments: opts.toolArguments,
    model_metadata: opts.modelMetadata,
    timestamp: Math.floor(Date.now() / 1000),
  };
}

function filterHeaders(
  headers: Record<string, string>,
  allowed: string[],
): Record<string, string> {
  const result: Record<string, string> = {};
  const allowedSet = new Set(allowed.map((h) => h.toLowerCase()));
  for (const [key, value] of Object.entries(headers)) {
    if (allowedSet.has(key.toLowerCase())) {
      result[key] = value;
    }
  }
  return result;
}

// -- Node.js (req, res) interceptor --

/**
 * Intercept a Node.js (IncomingMessage, ServerResponse) pair.
 * Evaluates against the Chio sidecar and either allows the request
 * to proceed or sends a deny response.
 *
 * Returns a structured outcome. Real signed Chio evidence is exposed via
 * `result`. Sidecar errors fail closed.
 */
export async function interceptNodeRequest(
  req: IncomingMessage,
  res: ServerResponse,
  resolved: ResolvedConfig,
): Promise<NodeInterceptionOutcome> {
  const method = normalizeMethod(req.method ?? "GET");
  if (method == null) {
    sendJsonResponse(res, 405, {
      error: CHIO_ERROR_CODES.EVALUATION_FAILED,
      message: `unsupported HTTP method: ${req.method ?? "unknown"}`,
    });
    return { responseSent: true, result: null, passthrough: null };
  }

  const url = req.url ?? "/";
  const path = extractPath(url);
  const query = parseQueryString(url);
  const rawHeaders = headersToRecord(req.headers as Record<string, string | string[] | undefined>);
  const caller = resolved.identityExtractor(req.headers as Record<string, string | string[] | undefined>);
  const routePattern = resolved.routePatternResolver(method, path);

  // Read body for hashing and replay it for downstream consumers.
  const bodyBytes = await getNodeRequestBody(req);
  const bodyHash = bodyBytes.length > 0 ? sha256Hex(bodyBytes) : undefined;
  const bodyLength = bodyBytes.length;

  const capabilityToken = rawHeaders["x-chio-capability"] ?? query["chio_capability"] ?? undefined;
  const capabilityId = capabilityIdFromToken(capabilityToken);

  const chioReq = buildChioHttpRequest({
    method,
    path,
    query,
    headers: rawHeaders,
    caller,
    bodyHash: bodyHash,
    bodyLength,
    routePattern,
    capabilityId,
  });

  try {
    const result = await resolved.client.evaluate(chioReq, rawHeaders["x-chio-capability"] ?? undefined);

    if (!isAllowed(result.verdict) || !isAuthorizedHttpReceipt(result.receipt)) {
      sendJsonResponse(res, verdictStatus(result.verdict), {
        error: CHIO_ERROR_CODES.ACCESS_DENIED,
        message: verdictReason(result.verdict),
        receipt_id: result.receipt.id,
        suggestion: "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
      });
      return { responseSent: true, result, passthrough: null };
    }

    const verification = await resolved.client.verifyReceipt(result.receipt);
    if (!isAuthoritativeVerification(verification, result.receipt)) {
      sendJsonResponse(res, 502, {
        error: CHIO_ERROR_CODES.INVALID_RECEIPT,
        message: "sidecar returned an unverified receipt",
        receipt_id: result.receipt.id,
      });
      return { responseSent: true, result, passthrough: null };
    }

    res.setHeader("X-Chio-Receipt-Id", result.receipt.id);
    return { responseSent: false, result, passthrough: null };
  } catch (error) {
    return handleSidecarError(res, resolved, error);
  }
}

// -- Web API Request -> Response interceptor --

/**
 * Intercept a Web API Request.
 * Returns a structured outcome. Real signed Chio evidence is exposed via
 * `result`. Sidecar errors fail closed.
 */
export async function interceptWebRequest(
  request: Request,
  resolved: ResolvedConfig,
): Promise<WebInterceptionOutcome> {
  const url = new URL(request.url);
  const method = normalizeMethod(request.method);

  if (method == null) {
    return {
      response: jsonResponse(405, {
        error: CHIO_ERROR_CODES.EVALUATION_FAILED,
        message: `unsupported HTTP method: ${request.method}`,
      }),
      result: null,
      passthrough: null,
    };
  }

  const path = url.pathname;
  const query: Record<string, string> = {};
  url.searchParams.forEach((value, key) => {
    query[key] = value;
  });

  const rawHeaders: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    rawHeaders[key.toLowerCase()] = value;
  });

  const headerObj: Record<string, string | string[] | undefined> = {};
  request.headers.forEach((value, key) => {
    headerObj[key] = value;
  });
  const caller = resolved.identityExtractor(headerObj);
  const routePattern = resolved.routePatternResolver(method, path);

  // Read body for hashing
  let bodyHash: string | undefined;
  let bodyLength = 0;
  if (request.body != null) {
    const bodyBytes = new Uint8Array(await request.clone().arrayBuffer());
    bodyLength = bodyBytes.length;
    if (bodyLength > 0) {
      bodyHash = sha256Hex(bodyBytes);
    }
  }

  const capabilityToken = rawHeaders["x-chio-capability"] ?? query["chio_capability"] ?? undefined;
  const capabilityId = capabilityIdFromToken(capabilityToken);

  const chioReq = buildChioHttpRequest({
    method,
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
    const evalResult = await resolved.client.evaluate(chioReq, rawHeaders["x-chio-capability"] ?? undefined);

    if (!isAllowed(evalResult.verdict) || !isAuthorizedHttpReceipt(evalResult.receipt)) {
      const resp = jsonResponse(verdictStatus(evalResult.verdict), {
        error: CHIO_ERROR_CODES.ACCESS_DENIED,
        message: verdictReason(evalResult.verdict),
        receipt_id: evalResult.receipt.id,
        suggestion: "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
      });
      return { response: resp, result: evalResult, passthrough: null };
    }

    const verification = await resolved.client.verifyReceipt(evalResult.receipt);
    if (!isAuthoritativeVerification(verification, evalResult.receipt)) {
      return {
        response: jsonResponse(502, {
          error: CHIO_ERROR_CODES.INVALID_RECEIPT,
          message: "sidecar returned an unverified receipt",
          receipt_id: evalResult.receipt.id,
        }),
        result: evalResult,
        passthrough: null,
      };
    }

    // Return a marker response that the framework wrapper will replace
    // with the actual upstream response.
    const resp = new Response(null, { status: 200 });
    resp.headers.set("X-Chio-Receipt-Id", evalResult.receipt.id);
    return { response: resp, result: evalResult, passthrough: null };
  } catch (error) {
    const message =
      error instanceof SidecarError
        ? error.message
        : `sidecar error: ${error instanceof Error ? error.message : String(error)}`;

    return {
      response: jsonResponse(502, {
        error: CHIO_ERROR_CODES.SIDECAR_UNREACHABLE,
        message,
      }),
      result: null,
      passthrough: null,
    };
  }
}

// -- Helpers --

type ReplayableIncomingMessage = IncomingMessage & {
  rawBody?: unknown;
  body?: unknown;
  [Symbol.asyncIterator]?: () => AsyncIterableIterator<Buffer>;
};

function bufferedBodyFromValue(value: unknown): Buffer | null {
  if (value == null) {
    return null;
  }
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  if (typeof value === "string") {
    return Buffer.from(value, "utf-8");
  }
  return null;
}

function preserveReadableBody(req: IncomingMessage, bodyBytes: Buffer): void {
  const replay = new PassThrough();
  replay.end(bodyBytes);
  const replayWithState = replay as PassThrough & { _readableState: unknown };

  const replayable = req as unknown as Record<string | symbol, unknown>;
  const replayMethods = [
    "on",
    "once",
    "addListener",
    "prependListener",
    "prependOnceListener",
    "removeListener",
    "off",
    "pipe",
    "unpipe",
    "pause",
    "resume",
    "read",
    "setEncoding",
  ] as const;

  for (const method of replayMethods) {
    const impl = replay[method];
    if (typeof impl === "function") {
      replayable[method] = impl.bind(replay) as unknown;
    }
  }

  replayable[Symbol.asyncIterator] = replay[Symbol.asyncIterator].bind(replay) as unknown;

  Object.defineProperty(replayable, "_readableState", {
    configurable: true,
    enumerable: false,
    get: () => replayWithState._readableState,
  });

  Object.defineProperty(replayable, "complete", {
    configurable: true,
    enumerable: false,
    get: () => replay.readableEnded,
  });

  for (const property of [
    "readable",
    "readableEnded",
    "readableEncoding",
    "readableFlowing",
    "readableLength",
  ] as const) {
    Object.defineProperty(replayable, property, {
      configurable: true,
      enumerable: false,
      get: () => replay[property],
    });
  }
}

async function getNodeRequestBody(req: IncomingMessage): Promise<Buffer> {
  const replayable = req as ReplayableIncomingMessage;
  const preBuffered =
    bufferedBodyFromValue(replayable.rawBody) ??
    bufferedBodyFromValue(replayable.body);
  if (preBuffered != null) {
    bufferedNodeBodies.set(req, preBuffered);
    replayable.rawBody = preBuffered;
    return preBuffered;
  }

  const bodyBytes = await readBody(req);
  bufferedNodeBodies.set(req, bodyBytes);
  replayable.rawBody = bodyBytes;
  if (bodyBytes.length > 0) {
    preserveReadableBody(req, bodyBytes);
  }
  return bodyBytes;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJsonResponse(res: ServerResponse, status: number, body: ChioErrorResponse): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function jsonResponse(status: number, body: ChioErrorResponse): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Handle a sidecar error during Node.js request interception.
 *
 * Sends a 502 error response and returns a blocked outcome to signal that the
 * response has already been sent.
 */
function handleSidecarError(
  res: ServerResponse,
  resolved: ResolvedConfig,
  error: unknown,
): NodeInterceptionOutcome {
  const message =
    error instanceof SidecarError
      ? error.message
      : `sidecar error: ${error instanceof Error ? error.message : String(error)}`;

  sendJsonResponse(res, 502, {
    error: CHIO_ERROR_CODES.SIDECAR_UNREACHABLE,
    message,
  });
  return { responseSent: true, result: null, passthrough: null };
}
