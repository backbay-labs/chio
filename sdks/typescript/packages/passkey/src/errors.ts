// Typed error codes for @chio-protocol/passkey.
//
// The codes mirror spec/errors/registry.yaml entries under the
// urn:chio:error:custody namespace. The TS surface is the caller-facing
// branch alphabet; throwing a wider set silently strips the caller's
// ability to handle revocations, replays, or expirations distinctly.
// Keep this enum and the registry in lockstep; any new custody-domain
// code added to the registry MUST land here alongside it.
//
// Codegen contract (LSP-driven typed-enum codegen):
//
//   The CHIO_CUSTODY_ERROR_CODES constant below is the exhaustive list.
//   `CustodyErrorCode` is its `keyof` derivative, so adding a member to
//   the constant flows automatically into every consumer's type-narrowing
//   code path. The match-exhaustiveness test in
//   tests/errors.spec.ts pins this contract; any future codegen pass that
//   regenerates the file MUST keep the constant + type alias shape.

/**
 * Exhaustive list of urn:chio:error:custody:* codes the @chio-protocol/passkey
 * SDK throws. Mirrors the rows in spec/errors/registry.yaml under the
 * custody domain.
 *
 * The list is `as const` so the inferred type is a literal-string union;
 * downstream consumers can switch over CustodyErrorCode and rely on TS
 * exhaustiveness checking.
 */
export const CHIO_CUSTODY_ERROR_CODES = [
  'urn:chio:error:custody:assertion-rejected',
  'urn:chio:error:custody:audience-mismatch',
  'urn:chio:error:custody:replay-detected',
  'urn:chio:error:custody:capability-expired',
  'urn:chio:error:custody:credential-revoked',
  'urn:chio:error:custody:user-verification-required',
  'urn:chio:error:custody:hardware-key-unavailable',
  'urn:chio:error:custody:internal-encoding',
] as const;

/** Stable typed-enum surface for the urn:chio:error:custody:* namespace. */
export type CustodyErrorCode = (typeof CHIO_CUSTODY_ERROR_CODES)[number];

/** Type guard: narrow an arbitrary string to the typed CustodyErrorCode union. */
export function isCustodyErrorCode(s: unknown): s is CustodyErrorCode {
  return (
    typeof s === 'string' &&
    (CHIO_CUSTODY_ERROR_CODES as readonly string[]).includes(s)
  );
}

/**
 * Stable error class thrown from @chio-protocol/passkey when the SDK or the
 * issuer reports a custody-domain failure. The `code` field is one of
 * CustodyErrorCode; never widen it.
 */
export class ChioCustodyError extends Error {
  readonly code: CustodyErrorCode;
  readonly cause?: unknown;
  constructor(code: CustodyErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'ChioCustodyError';
    this.code = code;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

/**
 * Convert a possibly-untyped urn string (e.g. one received over the wire
 * from the issuer) into a typed ChioCustodyError. Falls back to
 * `urn:chio:error:custody:internal-encoding` for unknown values; this is
 * fail-closed: callers branching on `code` cannot be tricked into a
 * "treat-as-success" path by an unrecognised code.
 */
export function toChioCustodyError(
  rawCode: string,
  message: string,
  cause?: unknown,
): ChioCustodyError {
  if (isCustodyErrorCode(rawCode)) {
    return new ChioCustodyError(rawCode, message, cause);
  }
  return new ChioCustodyError(
    'urn:chio:error:custody:internal-encoding',
    `unknown custody error code "${rawCode}": ${message}`,
    cause,
  );
}
