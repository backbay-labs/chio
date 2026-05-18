/**
 * `chioTool` -- Vercel AI SDK tool wrapper that gates each invocation
 * through the Chio sidecar without disturbing streaming.
 *
 * ## Streaming contract
 *
 * The Vercel AI SDK passes whatever `execute` returns straight through its
 * streaming pipeline (`streamText`, `streamObject`). `execute` may return:
 *
 *   - a plain scalar result (`string`, `object`, ...)
 *   - a `ReadableStream<...>` (for SSE-style streaming tools)
 *   - an async generator / async iterable (for chunked partial results)
 *
 * This wrapper MUST NOT buffer, clone, tee, or iterate any of those return
 * values. It does exactly two things:
 *
 *   1. Ask the Chio sidecar to evaluate the invocation (`allow` vs `deny`).
 *   2. If `allow`, call the original `execute` with the original arguments
 *      and return its result untouched -- preserving reference identity for
 *      `ReadableStream` and async-iterable values.
 *
 * ## Generic inference
 *
 * Vercel AI SDK's `tool()` returns a generic `Tool` shape whose exact
 * structure has evolved across major versions (3.x -> 4.x -> 5.x). To stay
 * compatible across `ai@>=3.4 <6` without pinning to an internal type, we
 * accept a structural `ToolLike<PARAMS, RESULT>` and return the same shape
 * with the wrapped `execute`. The caller keeps full type inference on both
 * parameters and result type.
 */

import { ChioClient, type ChioClientOptions, ChioClientError } from "./client.js";
import { ChioToolError } from "./errors.js";

/**
 * Structural typing for the subset of the Vercel AI SDK `Tool<T>` shape we
 * touch. Kept permissive to support `ai@>=3.4 <6`: older versions expose
 * `parameters`, newer versions expose `inputSchema`. We pass both fields
 * through unchanged via spread, so the wrapper never needs to know which.
 */
export interface ToolLike<PARAMS, RESULT> {
  /** Human-readable description shown to the model. */
  description?: string | undefined;
  /** Zod schema describing the tool's input (AI SDK v3/v4 shape). */
  parameters?: unknown;
  /** Zod schema describing the tool's input (AI SDK v5 shape). */
  inputSchema?: unknown;
  /**
   * Tool implementation. Receives validated parameters and optional runtime
   * options (e.g. `abortSignal`, `toolCallId`). May return a plain value, a
   * Promise, a `ReadableStream`, or an async generator.
   */
  execute?: ((params: PARAMS, options?: ToolExecuteOptions) => RESULT | Promise<RESULT>) | undefined;
  /** Pass-through of any other tool fields declared by the caller. */
  [key: string]: unknown;
}

/**
 * Subset of the runtime options the Vercel AI SDK forwards to `execute`.
 * Kept structural to avoid pinning to a specific AI SDK major version.
 */
export interface ToolExecuteOptions {
  toolCallId?: string | undefined;
  messages?: unknown;
  abortSignal?: AbortSignal | undefined;
  [key: string]: unknown;
}

/**
 * Identity scope declared by the caller. Maps onto the sidecar's
 * capability / tool-server / tool-name evaluation input.
 */
export interface ChioToolScope {
  /** Capability token ID already granted to the caller. */
  capabilityId?: string | undefined;
  /** Raw capability token body, forwarded via `X-Chio-Capability`. */
  capabilityToken?: string | undefined;
  /** Logical tool-server identifier this tool belongs to. */
  toolServer: string;
  /**
   * Tool name registered with the sidecar. Defaults to the key the caller
   * binds this tool under in their `tools` map; callers can override here
   * when the key differs from the registered name.
   */
  toolName: string;
  /** Optional free-form metadata forwarded alongside the evaluation payload. */
  metadata?: Record<string, unknown> | undefined;
}

/**
 * Optional hook that resolves a raw capability token for a configured
 * capability ID. This is the only safe way to keep `capabilityId` as the
 * declarative scope handle while still presenting a signed token to the
 * sidecar.
 */
export type CapabilityTokenResolver =
  (capabilityId: string) => string | Promise<string | undefined> | undefined;

/** Receipt verification result accepted by `chioTool`. */
export interface ChioReceiptAuthority {
  receipt_kind?: "mediated_decision" | "trace_observation" | "advisory_evaluation" | undefined;
  boundary_class?: "prevent" | "detect_only" | "advisory_only" | undefined;
  trust_level?: "mediated" | "verified" | "advisory" | undefined;
  result?: string | undefined;
  authorized?: boolean | undefined;
  ok?: boolean | undefined;
  signer_trusted?: boolean | undefined;
  signature_valid?: boolean | undefined;
  receipt_id_valid?: boolean | undefined;
  parameter_hash_valid?: boolean | undefined;
}

/** Caller-supplied receipt verifier, usually from `@chio-protocol/sdk` invariants. */
export type ChioReceiptVerifier =
  (receipt: Record<string, unknown>) =>
    ChioReceiptAuthority
    | Promise<ChioReceiptAuthority>;

/**
 * Options accepted by `chioTool`. Mirrors the Vercel AI SDK `tool()` shape
 * (`description`, `parameters`/`inputSchema`, `execute`) and adds Chio
 * binding fields under `scope`.
 */
export interface ChioToolOptions<PARAMS, RESULT> extends ToolLike<PARAMS, RESULT> {
  /** Scope describing how this tool binds to Chio capability evaluation. */
  scope: ChioToolScope;
  /**
   * Pre-constructed `ChioClient`. Takes precedence over `client*` options.
   * Useful for sharing a single client across many tools.
   */
  client?: ChioClient | undefined;
  /** Inline `ChioClient` options used when `client` is not provided. */
  clientOptions?: ChioClientOptions | undefined;
  /**
   * Legacy sidecar-error option retained for source compatibility. Current
   * v1 always throws `ChioToolError` when the sidecar is unreachable.
   */
  onSidecarError?: "deny" | "allow" | undefined;
  /**
   * Optional debug hook -- forwarded to the Chio client. The wrapper never
   * writes to stdout/stderr on its own.
   */
  debug?: ((message: string, data?: unknown) => void) | undefined;
  /**
   * Optional hook used when `scope.capabilityId` is configured without an
   * inline `scope.capabilityToken`. The resolver must return the full raw
   * capability token JSON that should be presented to the sidecar.
   */
  resolveCapabilityToken?: CapabilityTokenResolver | undefined;
  /**
   * Verifies the signed receipt before tool execution. Required for an
   * allow-shaped receipt to invoke the wrapped tool.
   */
  verifyReceipt?: ChioReceiptVerifier | undefined;
}

/** Lazily cached shared client for callers that provide only `clientOptions`. */
function resolveClient<PARAMS, RESULT>(opts: ChioToolOptions<PARAMS, RESULT>): ChioClient {
  if (opts.client != null) {
    return opts.client;
  }
  const clientOptions: ChioClientOptions = { ...(opts.clientOptions ?? {}) };
  if (clientOptions.debug == null && opts.debug != null) {
    clientOptions.debug = opts.debug;
  }
  return new ChioClient(clientOptions);
}

/**
 * Wrap a Vercel AI SDK `tool()` definition so every invocation is evaluated
 * by the Chio sidecar before the underlying `execute` runs.
 *
 * The return value shares the structural shape of the input (so it drops
 * directly into `streamText({ tools: { ... } })`) and preserves generic
 * parameter / result type inference.
 *
 * @example
 * ```ts
 * import { tool } from "ai";
 * import { z } from "zod";
 * import { chioTool } from "@chio-protocol/ai-sdk";
 *
 * const searchTool = chioTool({
 *   description: "Search the web",
 *   parameters: z.object({ query: z.string() }),
 *   execute: async ({ query }) => runSearch(query),
 *   scope: { toolServer: "web-tools", toolName: "search" },
 * });
 * ```
 */
export function chioTool<PARAMS, RESULT>(
  options: ChioToolOptions<PARAMS, RESULT>,
): ToolLike<PARAMS, RESULT> {
  const {
    scope,
    client: _client,
    clientOptions: _clientOptions,
    onSidecarError: _onSidecarError,
    debug: _debug,
    resolveCapabilityToken,
    verifyReceipt,
    execute: originalExecute,
    ...rest
  } = options;
  const client = resolveClient(options);

  const wrappedExecute = async (
    params: PARAMS,
    executeOptions?: ToolExecuteOptions,
  ): Promise<RESULT> => {
    let receipt;
    try {
      const clientArgs: { capabilityToken?: string | undefined } = {};
      let capabilityToken = scope.capabilityToken;
      if (capabilityToken == null
        && scope.capabilityId != null
        && resolveCapabilityToken != null) {
        capabilityToken = await resolveCapabilityToken(scope.capabilityId);
      }
      if (capabilityToken == null && scope.capabilityId != null) {
        throw new ChioToolError({
          verdict: "incomplete",
          guard: "",
          reason:
            "scope.capabilityId is only a hint; provide scope.capabilityToken or resolveCapabilityToken so chioTool can present a signed capability token",
        });
      }
      if (capabilityToken != null) {
        clientArgs.capabilityToken = capabilityToken;
      }
      const request: Parameters<ChioClient["evaluateToolCall"]>[0] = {
        tool_server: scope.toolServer,
        tool_name: scope.toolName,
        arguments: params,
      };
      if (scope.capabilityId != null) {
        request.capability_id = scope.capabilityId;
      }
      if (scope.metadata != null) {
        request.metadata = scope.metadata;
      }
      receipt = await client.evaluateToolCall(request, clientArgs);
    } catch (error) {
      if (error instanceof ChioClientError) {
        throw new ChioToolError({
          verdict: "sidecar_unreachable",
          guard: "",
          reason: error.message,
        });
      }
      throw error;
    }

    const verdict = receipt.decision?.verdict;
    const authorized =
      receipt.receipt_kind === "mediated_decision"
      && receipt.boundary_class === "prevent"
      && receipt.observation_outcome == null
      && receipt.trust_level === "mediated"
      && verdict === "allow";
    if (verdict == null) {
      throw new ChioToolError({
        verdict: "incomplete",
        guard: "",
        reason: `Chio receipt ${receipt.id} is non-authorizing (${String(receipt.receipt_kind ?? "unknown")})`,
        receiptId: receipt.id,
      });
    }
    if (!authorized) {
      throw new ChioToolError({
        verdict,
        guard: receipt.decision?.guard ?? "",
        reason: receipt.decision?.reason ?? `Chio verdict: ${verdict}`,
        receiptId: receipt.id,
      });
    }

    if (verifyReceipt == null) {
      throw new ChioToolError({
        verdict: "incomplete",
        guard: "",
        reason: `Chio receipt ${receipt.id} has no trusted receipt verifier configured`,
        receiptId: receipt.id,
      });
    }
    const authority = await verifyReceipt(receipt);
    if (!receiptAuthorityAllows(authority)) {
      throw new ChioToolError({
        verdict: "incomplete",
        guard: "",
        reason: `Chio receipt ${receipt.id} did not pass trusted receipt verification`,
        receiptId: receipt.id,
      });
    }

    if (originalExecute == null) {
      throw new ChioToolError({
        verdict: "incomplete",
        guard: "",
        reason: "chioTool wrapper has no underlying execute() to call",
        receiptId: receipt.id,
      });
    }

    // IMPORTANT: do NOT await + repackage. Returning the promise from
    // `invokeOriginal` preserves `ReadableStream` / async-generator
    // reference identity through the Vercel AI SDK streaming pipeline.
    return invokeOriginal(originalExecute, params, executeOptions);
  };

  // Reassemble in the same structural shape Vercel AI SDK's `tool()` would
  // have produced. Spread `rest` first so explicit fields (description,
  // parameters, inputSchema, ...) land unmodified; `execute` is the last
  // field set so TypeScript infers its type from `wrappedExecute`.
  const wrapped: ToolLike<PARAMS, RESULT> = {
    ...rest,
    execute: wrappedExecute,
  };
  return wrapped;
}

function receiptAuthorityAllows(authority: ChioReceiptAuthority): boolean {
  return authority.authorized === true
    && authority.ok === true
    && authority.signer_trusted === true
    && authority.signature_valid === true
    && authority.receipt_id_valid === true
    && authority.parameter_hash_valid === true
    && authority.receipt_kind === "mediated_decision"
    && authority.boundary_class === "prevent"
    && authority.trust_level === "mediated"
    && (
      authority.result === "allow"
      || authority.result === "authorized"
      || authority.result === "Authorized"
    );
}

/**
 * Call the caller's `execute` and return its result promise directly. We
 * do not `await` it here: that would force every return value through a
 * microtask but is otherwise a no-op, and omitting the `await` makes the
 * "no buffering" guarantee easier to audit.
 */
function invokeOriginal<PARAMS, RESULT>(
  execute: NonNullable<ToolLike<PARAMS, RESULT>["execute"]>,
  params: PARAMS,
  executeOptions: ToolExecuteOptions | undefined,
): Promise<RESULT> {
  const result = executeOptions === undefined ? execute(params) : execute(params, executeOptions);
  return Promise.resolve(result);
}
