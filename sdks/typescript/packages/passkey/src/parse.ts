// Local parseCapabilityToken fallback.
//
// In production the @chio-protocol/browser package exposes
// parseCapabilityToken; this module mirrors the shape so a consumer can
// load the SDK without the peer dep installed (e.g. in unit tests, or
// in environments where the wasm build of @chio-protocol/browser is not
// yet available). The local fallback decodes the canonical-JSON envelope
// shape the issuer mints (see crates/trust/chio-custody-hw/src/capability.rs)
// and validates required fields. It does NOT verify the issuer signature
// - that is fail-closed at the kernel verifier.

export interface PasskeyCapabilityShape {
  audience: string;
  credential_id: string;
  scope_set: string[];
  iat: string;
  exp: string;
  challenge_nonce: string;
  signature: string;
}

export class CapabilityParseError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'CapabilityParseError';
    this.code = code;
  }
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isString);
}

/**
 * Parse a capability token (canonical-JSON encoded PasskeyCapability) into
 * a structurally validated object. Throws CapabilityParseError on any
 * structural deviation; fail-closed.
 *
 * Signature verification is intentionally NOT performed here - the kernel
 * verifier is the only authority that decides whether a capability is
 * accepted. This function only ensures the envelope is shaped correctly so
 * the caller does not pass garbage further down the pipe.
 */
export function parseCapabilityToken(raw: string): PasskeyCapabilityShape {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new CapabilityParseError(
      'urn:chio:error:custody:internal-encoding',
      `capability token is not valid JSON: ${msg}`,
    );
  }
  if (parsed == null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new CapabilityParseError(
      'urn:chio:error:custody:internal-encoding',
      'capability token must decode to a JSON object',
    );
  }
  const obj = parsed as Record<string, unknown>;
  const required: Array<keyof PasskeyCapabilityShape> = [
    'audience',
    'credential_id',
    'scope_set',
    'iat',
    'exp',
    'challenge_nonce',
    'signature',
  ];
  for (const key of required) {
    if (!(key in obj)) {
      throw new CapabilityParseError(
        'urn:chio:error:custody:internal-encoding',
        `capability token missing required field: ${key}`,
      );
    }
  }
  if (
    !isString(obj.audience) ||
    !isString(obj.credential_id) ||
    !isString(obj.iat) ||
    !isString(obj.exp) ||
    !isString(obj.challenge_nonce) ||
    !isString(obj.signature)
  ) {
    throw new CapabilityParseError(
      'urn:chio:error:custody:internal-encoding',
      'capability token has malformed string field',
    );
  }
  if (!isStringArray(obj.scope_set)) {
    throw new CapabilityParseError(
      'urn:chio:error:custody:internal-encoding',
      'capability token scope_set must be an array of strings',
    );
  }
  return {
    audience: obj.audience,
    credential_id: obj.credential_id,
    scope_set: obj.scope_set,
    iat: obj.iat,
    exp: obj.exp,
    challenge_nonce: obj.challenge_nonce,
    signature: obj.signature,
  };
}
