/**
 * SDK-level error hierarchy for Chio TypeScript SDK.
 *
 * ChioError is the base for all SDK-level errors.
 * ChioInvariantError (in invariants/errors.ts) is a separate, lower-level layer
 * and does NOT extend ChioError.
 */

export class ChioError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ChioError";
    this.code = code;
  }
}

export class DpopSignError extends ChioError {
  constructor(message: string, options?: ErrorOptions) {
    super("dpop_sign_error", message, options);
    this.name = "DpopSignError";
  }
}

export class QueryError extends ChioError {
  readonly status: number | undefined;

  constructor(message: string, status?: number, options?: ErrorOptions) {
    super("query_error", message, options);
    this.name = "QueryError";
    this.status = status;
  }
}

export class TransportError extends ChioError {
  constructor(message: string, options?: ErrorOptions) {
    super("transport_error", message, options);
    this.name = "TransportError";
  }
}
