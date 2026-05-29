export type ChioInvariantErrorCode =
  | "json"
  | "canonical_json"
  | "invalid_hex"
  | "invalid_public_key"
  | "invalid_signature";

export class ChioInvariantError extends Error {
  readonly code: ChioInvariantErrorCode;

  constructor(code: ChioInvariantErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ChioInvariantError";
    this.code = code;
  }
}

export function parseJsonText<T>(input: string): T {
  try {
    return JSON.parse(input) as T;
  } catch (cause) {
    throw new ChioInvariantError("json", "input is not valid JSON", { cause });
  }
}
