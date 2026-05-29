/*
 * In-page test-double for the issuer + kernel + revocation oracle.
 *
 * The double lives in the demo only; in a real deployment the SDK calls a
 * real issuer URL. The double is exported as a separate module so the bun
 * e2e test (../../../sdks/typescript/packages/passkey/tests/e2e.spec.ts)
 * can import it directly and run the same code paths the demo runs.
 *
 * The double simulates:
 *   - POST /challenge: returns a deterministic base64url challenge.
 *   - POST /mint: minimally validates audience + scope_set, then returns
 *     a fixture PasskeyCapability. The signature slot is empty (this is
 *     fixture material, not a real hybrid envelope); the kernel
 *     test-double similarly does not verify the signature - it only
 *     checks the credential id against the revocation state to demonstrate
 *     the cascade.
 *   - GET /kernel/call: returns 200 if the credential is fresh, 403 with
 *     urn:chio:error:custody:credential-revoked otherwise.
 *
 * The double also installs a fake navigator.credentials so
 * navigator.credentials.get returns a stub PublicKeyCredential. This is
 * the only way to keep the demo self-contained in a headless test
 * environment; in a real browser the platform authenticator runs.
 */

export interface RevocationState {
  revokedCredentialIds: Set<string>;
}

export interface InstallOptions {
  issuerUrl: string;
  kernelUrl: string;
  audience: string;
  revocationState: RevocationState;
}

export interface KernelVerdict {
  allowed: boolean;
  errorCode?: string;
}

const FIXTURE_CHALLENGE = 'Y2hhbGxlbmdl-fixture';
const FIXTURE_CREDENTIAL_ID = 'AAAA-passkey-demo';

function asArrayBuffer(s: string): ArrayBuffer {
  const enc = new TextEncoder().encode(s);
  return enc.buffer.slice(enc.byteOffset, enc.byteOffset + enc.byteLength);
}

function fixtureCapability(audience: string, scopes: string[], nonce: string): Record<string, unknown> {
  // iat / exp are static-fixture timestamps so the demo render is
  // reproducible; in production the issuer fills them off the kernel
  // clock.
  return {
    audience,
    credential_id: FIXTURE_CREDENTIAL_ID,
    scope_set: [...scopes],
    iat: '2026-04-29T00:00:00Z',
    exp: '2026-04-29T00:05:00Z',
    challenge_nonce: nonce,
    signature: '',
  };
}

function makeStubCredentials(): CredentialsContainer {
  return {
    get: async (_options?: CredentialRequestOptions): Promise<Credential | null> => {
      return {
        id: FIXTURE_CREDENTIAL_ID,
        type: 'public-key',
        rawId: asArrayBuffer(FIXTURE_CREDENTIAL_ID),
        response: {
          clientDataJSON: asArrayBuffer(
            JSON.stringify({ type: 'webauthn.get', challenge: FIXTURE_CHALLENGE, origin: 'https://localhost' }),
          ),
          authenticatorData: asArrayBuffer('auth-data-fixture'),
          signature: asArrayBuffer('sig-fixture'),
          userHandle: null,
        },
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: null,
      } as unknown as Credential;
    },
    create: async () => null,
    preventSilentAccess: async () => undefined,
    store: async (cred: Credential) => cred,
  } as unknown as CredentialsContainer;
}

/**
 * Install the issuer test-double into globalThis.fetch and
 * globalThis.navigator.credentials. Must be called before requestCapability.
 *
 * In test environments where importing this module from outside a browser
 * causes globalThis.navigator to not exist, the function falls back to
 * leaving navigator alone (the caller is expected to pass `credentials` to
 * requestCapability directly).
 */
export function installIssuerTestDouble(options: InstallOptions): void {
  const { issuerUrl, audience } = options;
  const originalFetch = globalThis.fetch;
  const stubFetch: typeof fetch = async (input, init) => {
    const req = new Request(input as Request, init);
    const url = req.url;
    if (url === `${issuerUrl}/challenge` || url === `${trim(issuerUrl)}/challenge`) {
      return new Response(JSON.stringify({ challenge: FIXTURE_CHALLENGE, userVerification: 'required' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url === `${issuerUrl}/mint` || url === `${trim(issuerUrl)}/mint`) {
      const body = (await req.json()) as { audience?: string; scope_set?: string[]; challenge_nonce?: string };
      if (body.audience !== audience) {
        return new Response(
          JSON.stringify({ error: { code: 'urn:chio:error:custody:audience-mismatch' } }),
          { status: 403, headers: { 'content-type': 'application/json' } },
        );
      }
      const cap = fixtureCapability(audience, body.scope_set ?? [], body.challenge_nonce ?? '');
      return new Response(JSON.stringify({ capability: cap }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return originalFetch(input, init);
  };
  globalThis.fetch = stubFetch;
  const nav = (globalThis as { navigator?: Navigator & { credentials?: CredentialsContainer } }).navigator;
  if (nav) {
    Object.defineProperty(nav, 'credentials', {
      value: makeStubCredentials(),
      configurable: true,
      writable: true,
    });
  }
}

/** Mark a credential id revoked. The kernel test-double consults this on
 *  each call and denies fail-closed when the credential is in the set. */
export function simulateRevocation(state: RevocationState, credentialId: string): void {
  state.revokedCredentialIds.add(credentialId);
}

/**
 * Simulate a kernel call against the revocation oracle. Returns allow when
 * the credential is fresh; otherwise returns deny with
 * urn:chio:error:custody:credential-revoked. The oracle is consulted on
 * every call so the cascade is observable in the demo without waiting on a
 * wall-clock tick.
 */
export async function simulateKernelCall(
  _kernelUrl: string,
  cap: { credential_id: string },
  state: RevocationState,
): Promise<KernelVerdict> {
  // No real network; the kernel-side e2e covers the wire path.
  if (state.revokedCredentialIds.has(cap.credential_id)) {
    return { allowed: false, errorCode: 'urn:chio:error:custody:credential-revoked' };
  }
  return { allowed: true };
}

function trim(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}
