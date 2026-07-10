// requestCapability: thin browser-side caller that presents a WebAuthn
// passkey assertion to a Chio issuer and returns the issuer-minted
// PasskeyCapability.
//
// Trust contract:
//
//   * The browser holds ZERO key material. The only crypto primitive
//     touched here is navigator.credentials.get, which is platform-side
//     and never returns a private key to the page. The assertion is
//     produced by the platform authenticator (Touch ID, security key,
//     etc.) and forwarded as base64url-encoded bytes.
//   * No envelope is signed in the browser. The audience-pinned
//     PasskeyCapability is signed server-side by the issuer using the
//     HybridBackend (see crates/trust/chio-custody-hw/src/issuer.rs).
//   * Fail-closed at every step. A missing issuer challenge, a missing
//     navigator.credentials, a non-2xx fetch, or a structurally invalid
//     capability all throw with a stable urn:chio:error:custody:* code.
//   * Audience is supplied by the caller and round-tripped through both
//     the issuer challenge request and the issuer mint request. The
//     issuer rejects audience confusion fail-closed.

import { parseCapabilityToken, type PasskeyCapabilityShape } from './parse.js';
import { type CustodyErrorCode, isCustodyErrorCode } from './errors.js';

/** Options for requestCapability. */
export interface RequestCapabilityOptions {
  /** WebAuthn relying-party id (e.g. `"login.example.com"`). */
  rpId: string;
  /** Audience pin the capability MUST be minted for. The issuer rejects
   *  mismatches fail-closed. */
  audience: string;
  /** Requested capability scope set. The issuer SHOULD reject scopes the
   *  card-bound provider does not list. */
  scopes: string[];
  /** Issuer base URL. The helper appends `/challenge` and `/mint`. */
  issuerUrl: string;
  /** Optional fetch override (test injection). Defaults to `globalThis.fetch`. */
  fetchImpl?: typeof fetch;
  /** Optional `navigator.credentials` override (test injection). Defaults
   *  to `globalThis.navigator.credentials`. */
  credentials?: CredentialsContainer;
  /** Optional UV preference. Defaults to `"required"`; the issuer
   *  requires user verification on its side regardless. */
  userVerification?: UserVerificationRequirement;
}

/** Re-export of the structurally validated envelope shape. */
export type PasskeyCapability = PasskeyCapabilityShape;

/** Stable error class for browser-side failures. The `code` field carries
 *  a typed urn:chio:error:custody:* code matching the custody error
 *  registry; the union is enforced by the typed-enum codegen via
 *  CustodyErrorCode in errors.ts. */
export class RequestCapabilityError extends Error {
  readonly code: CustodyErrorCode;
  readonly cause?: unknown;
  constructor(code: CustodyErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = 'RequestCapabilityError';
    this.code = code;
    if (cause !== undefined) {
      this.cause = cause;
    }
  }
}

interface ChallengeResponse {
  /** Base64url-no-pad WebAuthn challenge bytes. */
  challenge: string;
  /** Optional list of base64url credential ids the issuer expects. */
  allowCredentials?: Array<{ id: string; type: 'public-key' }>;
  /** Optional UV preference advertised by the issuer. */
  userVerification?: UserVerificationRequirement;
}

interface MintBody {
  audience: string;
  scope_set: string[];
  challenge_nonce: string;
  assertion: {
    credential_id: string;
    raw_id: string;
    client_data_json: string;
    authenticator_data: string;
    signature: string;
    user_handle: string | null;
  };
}

interface MintResponseShape {
  capability: unknown;
}

function pickFetch(opts: RequestCapabilityOptions): typeof fetch {
  if (opts.fetchImpl) return opts.fetchImpl;
  const f = (globalThis as { fetch?: typeof fetch }).fetch;
  if (typeof f !== 'function') {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'no fetch implementation available; pass options.fetchImpl in non-browser environments',
    );
  }
  return f;
}

function pickCredentials(opts: RequestCapabilityOptions): CredentialsContainer {
  if (opts.credentials) return opts.credentials;
  const nav = (globalThis as { navigator?: Navigator }).navigator;
  if (!nav || !nav.credentials) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:assertion-rejected',
      'navigator.credentials is unavailable; this SDK only runs in WebAuthn-capable browsers',
    );
  }
  return nav.credentials;
}

function returnedScopeIsWithinRequest(returnedScopes: string[], requestedScopes: string[]): boolean {
  const requested = new Set(requestedScopes);
  return returnedScopes.every(scope => requested.has(scope));
}

/** Strip whitespace / trailing slash from a URL prefix and append a path. */
function joinUrl(base: string, path: string): string {
  const trimmed = base.endsWith('/') ? base.slice(0, -1) : base;
  return `${trimmed}${path.startsWith('/') ? path : `/${path}`}`;
}

// btoa / atob are part of the DOM / Web standards lib (and are also
// present in Node >= 16). The package targets browsers; tests run in bun
// which provides both. We avoid a node-types dependency to keep the SDK
// surface tight (30 KB gzipped ceiling).
declare const btoa: (s: string) => string;
declare const atob: (s: string) => string;

function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < u8.length; i += 1) {
    bin += String.fromCharCode(u8[i] as number);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(s: string): ArrayBuffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return buf;
}

async function fetchChallenge(
  opts: RequestCapabilityOptions,
  fetchImpl: typeof fetch,
): Promise<ChallengeResponse> {
  let res: Response;
  try {
    res = await fetchImpl(joinUrl(opts.issuerUrl, '/challenge'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        rp_id: opts.rpId,
        audience: opts.audience,
        scope_set: opts.scopes,
      }),
    });
  } catch (cause) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:assertion-rejected',
      'issuer challenge fetch failed (network error)',
      cause,
    );
  }
  if (!res.ok) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:assertion-rejected',
      `issuer challenge fetch failed with HTTP ${res.status}`,
    );
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch (cause) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'issuer challenge response was not JSON',
      cause,
    );
  }
  if (
    !body ||
    typeof body !== 'object' ||
    typeof (body as { challenge?: unknown }).challenge !== 'string'
  ) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'issuer challenge response missing challenge field',
    );
  }
  return body as ChallengeResponse;
}

async function getAssertion(
  opts: RequestCapabilityOptions,
  challenge: ChallengeResponse,
  credentials: CredentialsContainer,
): Promise<PublicKeyCredential> {
  let allowCredentials: PublicKeyCredentialDescriptor[] | undefined;
  let publicKey: PublicKeyCredentialRequestOptions;
  try {
    allowCredentials = challenge.allowCredentials?.map((entry) => ({
      id: base64UrlToBytes(entry.id),
      type: 'public-key',
    }));
    publicKey = {
      challenge: base64UrlToBytes(challenge.challenge),
      rpId: opts.rpId,
      userVerification:
        opts.userVerification ?? challenge.userVerification ?? 'required',
      timeout: 60_000,
    };
  } catch (cause) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'issuer challenge response contained malformed base64url bytes',
      cause,
    );
  }
  if (allowCredentials && allowCredentials.length > 0) {
    publicKey.allowCredentials = allowCredentials;
  }
  let cred: Credential | null;
  try {
    cred = await credentials.get({ publicKey });
  } catch (cause) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:assertion-rejected',
      'navigator.credentials.get rejected the WebAuthn assertion',
      cause,
    );
  }
  if (!cred) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:assertion-rejected',
      'navigator.credentials.get returned null',
    );
  }
  if ((cred as PublicKeyCredential).type !== 'public-key') {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:assertion-rejected',
      'navigator.credentials.get did not return a public-key credential',
    );
  }
  return cred as PublicKeyCredential;
}

function buildMintBody(
  opts: RequestCapabilityOptions,
  challenge: ChallengeResponse,
  cred: PublicKeyCredential,
): MintBody {
  const response = cred.response as AuthenticatorAssertionResponse;
  return {
    audience: opts.audience,
    scope_set: [...opts.scopes],
    challenge_nonce: challenge.challenge,
    assertion: {
      credential_id: cred.id,
      raw_id: bytesToBase64Url(cred.rawId),
      client_data_json: bytesToBase64Url(response.clientDataJSON),
      authenticator_data: bytesToBase64Url(response.authenticatorData),
      signature: bytesToBase64Url(response.signature),
      user_handle: response.userHandle
        ? bytesToBase64Url(response.userHandle)
        : null,
    },
  };
}

async function postMint(
  opts: RequestCapabilityOptions,
  body: MintBody,
  fetchImpl: typeof fetch,
): Promise<PasskeyCapability> {
  let res: Response;
  try {
    res = await fetchImpl(joinUrl(opts.issuerUrl, '/mint'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (cause) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:assertion-rejected',
      'issuer mint fetch failed (network error)',
      cause,
    );
  }
  if (res.status === 401 || res.status === 403) {
    // The issuer signals revoked or stale credentials with 401/403; the
    // exact code disambiguation is encoded in the response body when the
    // issuer follows the custody contract. Fail-closed regardless: an unknown
    // urn collapses to assertion-rejected (the conservative bucket) so the
    // caller cannot be tricked into a treat-as-success path by a wire
    // value outside the typed enum.
    let urn: CustodyErrorCode = 'urn:chio:error:custody:assertion-rejected';
    try {
      const body = (await res.clone().json()) as { error?: { code?: string } };
      const code = body?.error?.code;
      if (isCustodyErrorCode(code)) {
        urn = code;
      }
    } catch {
      // Fall through to default urn.
    }
    throw new RequestCapabilityError(
      urn,
      `issuer rejected the assertion (HTTP ${res.status})`,
    );
  }
  if (!res.ok) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:assertion-rejected',
      `issuer mint fetch failed with HTTP ${res.status}`,
    );
  }
  let payload: MintResponseShape;
  try {
    payload = (await res.json()) as MintResponseShape;
  } catch (cause) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'issuer mint response was not JSON',
      cause,
    );
  }
  if (!payload || typeof payload !== 'object' || payload.capability == null) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'issuer mint response missing capability field',
    );
  }
  // The wire shape is JSON; serialise once and parse via the canonical
  // parser to keep one structural validator on the call path.
  const tokenJson = JSON.stringify(payload.capability);
  try {
    const capability = parseCapabilityToken(tokenJson);
    if (capability.audience !== opts.audience) {
      throw new RequestCapabilityError(
        'urn:chio:error:custody:audience-mismatch',
        `issuer minted capability for audience ${capability.audience} instead of ${opts.audience}`,
      );
    }
    if (!returnedScopeIsWithinRequest(capability.scope_set, opts.scopes)) {
      throw new RequestCapabilityError(
        'urn:chio:error:custody:assertion-rejected',
        'issuer minted capability scope_set outside the requested scopes',
      );
    }
    return capability;
  } catch (cause) {
    if (cause instanceof Error && 'code' in cause) {
      const code = (cause as { code?: unknown }).code;
      const typed: CustodyErrorCode = isCustodyErrorCode(code)
        ? code
        : 'urn:chio:error:custody:internal-encoding';
      throw new RequestCapabilityError(typed, cause.message, cause);
    }
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'capability parse failed',
      cause,
    );
  }
}

/**
 * Run the hardware-custody browser flow:
 *
 *   1. POST `{rp_id, audience, scope_set}` to `${issuerUrl}/challenge`;
 *      receive a WebAuthn challenge bound to those parameters.
 *   2. Call `navigator.credentials.get` with the challenge so the platform
 *      authenticator (passkey) signs it under user verification.
 *   3. POST `{audience, scope_set, challenge_nonce, assertion}` to
 *      `${issuerUrl}/mint`; the issuer verifies the assertion and returns
 *      a signed PasskeyCapability minted via the HybridBackend.
 *   4. Structurally validate the returned capability and return it.
 *
 * The browser never holds key material. All signing is server-side.
 */
export async function requestCapability(
  options: RequestCapabilityOptions,
): Promise<PasskeyCapability> {
  if (!options.rpId || !options.audience || !options.issuerUrl) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'requestCapability requires rpId, audience, and issuerUrl',
    );
  }
  if (!Array.isArray(options.scopes) || !options.scopes.every(scope => typeof scope === 'string')) {
    throw new RequestCapabilityError(
      'urn:chio:error:custody:internal-encoding',
      'requestCapability requires scopes to be an array of strings',
    );
  }
  const fetchImpl = pickFetch(options);
  const credentials = pickCredentials(options);
  const challenge = await fetchChallenge(options, fetchImpl);
  const assertion = await getAssertion(options, challenge, credentials);
  const body = buildMintBody(options, challenge, assertion);
  return postMint(options, body, fetchImpl);
}
