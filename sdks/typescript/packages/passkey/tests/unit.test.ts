// Unit tests for @chio-protocol/passkey.
//
// These tests exercise the requestCapability call sequence with injected
// fetch + credentials stubs so they run anywhere bun runs (no real
// WebAuthn authenticator required). The shape of the issuer protocol is
// pinned here so server-side changes that break the wire format are
// caught at the SDK boundary.

import { describe, expect, test } from 'bun:test';
import { parseCapabilityToken, CapabilityParseError } from '../src/parse.js';
import {
  requestCapability,
  RequestCapabilityError,
  type RequestCapabilityOptions,
} from '../src/request.js';

function fixtureCapability(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    audience: 'urn:chio:audience:kernel',
    credential_id: 'AAAA',
    scope_set: ['tool:read', 'tool:write'],
    iat: '2026-04-29T00:00:00Z',
    exp: '2026-04-29T00:05:00Z',
    challenge_nonce: 'nonce-abc',
    signature: '',
    ...overrides,
  };
}

function asArrayBuffer(s: string): ArrayBuffer {
  const enc = new TextEncoder().encode(s);
  // Slice to detach from the underlying TextEncoder buffer.
  return enc.buffer.slice(enc.byteOffset, enc.byteOffset + enc.byteLength);
}

function fakeCredentials(): CredentialsContainer {
  return {
    get: async (_options?: CredentialRequestOptions): Promise<Credential | null> => {
      return {
        id: 'AAAA',
        type: 'public-key',
        rawId: asArrayBuffer('AAAA'),
        response: {
          clientDataJSON: asArrayBuffer('{"type":"webauthn.get"}'),
          authenticatorData: asArrayBuffer('auth-data'),
          signature: asArrayBuffer('sig'),
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

function makeFetch(steps: Array<(req: Request) => Response | Promise<Response>>): typeof fetch {
  let i = 0;
  return ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const req = new Request(input as Request, init);
    const handler = steps[i];
    i += 1;
    if (!handler) {
      return Promise.reject(new Error(`unexpected fetch call (step ${i})`));
    }
    return Promise.resolve(handler(req));
  }) as typeof fetch;
}

const baseOpts = (overrides: Partial<RequestCapabilityOptions> = {}): RequestCapabilityOptions => ({
  rpId: 'login.example.com',
  audience: 'urn:chio:audience:kernel',
  scopes: ['tool:read', 'tool:write'],
  issuerUrl: 'https://issuer.example.com',
  credentials: fakeCredentials(),
  ...overrides,
});

describe('parseCapabilityToken', () => {
  test('round-trips a fully populated envelope', () => {
    const cap = fixtureCapability();
    const parsed = parseCapabilityToken(JSON.stringify(cap));
    expect(parsed.audience).toBe('urn:chio:audience:kernel');
    expect(parsed.scope_set).toEqual(['tool:read', 'tool:write']);
    expect(parsed.signature).toBe('');
  });

  test('rejects non-JSON', () => {
    let err: unknown;
    try {
      parseCapabilityToken('not json');
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(CapabilityParseError);
    expect((err as CapabilityParseError).code).toBe(
      'urn:chio:error:custody:internal-encoding',
    );
  });

  test('rejects missing required fields', () => {
    const bad = JSON.stringify({ audience: 'x' });
    expect(() => parseCapabilityToken(bad)).toThrow(CapabilityParseError);
  });

  test('rejects malformed scope_set type', () => {
    const cap = fixtureCapability({ scope_set: 'tool:read' });
    expect(() => parseCapabilityToken(JSON.stringify(cap))).toThrow(CapabilityParseError);
  });
});

describe('requestCapability', () => {
  test('happy path: challenge then mint, returns parsed capability', async () => {
    const fetchImpl = makeFetch([
      async (req) => {
        expect(req.url.endsWith('/challenge')).toBe(true);
        const body = (await req.json()) as Record<string, unknown>;
        expect(body.audience).toBe('urn:chio:audience:kernel');
        expect(body.rp_id).toBe('login.example.com');
        return new Response(
          JSON.stringify({ challenge: 'Y2hhbGxlbmdl', userVerification: 'required' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      },
      async (req) => {
        expect(req.url.endsWith('/mint')).toBe(true);
        const body = (await req.json()) as Record<string, unknown>;
        expect(body.audience).toBe('urn:chio:audience:kernel');
        expect(body.challenge_nonce).toBe('Y2hhbGxlbmdl');
        const assertion = body.assertion as Record<string, string>;
        expect(typeof assertion.client_data_json).toBe('string');
        expect(typeof assertion.signature).toBe('string');
        return new Response(
          JSON.stringify({ capability: fixtureCapability() }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      },
    ]);
    const cap = await requestCapability(baseOpts({ fetchImpl }));
    expect(cap.audience).toBe('urn:chio:audience:kernel');
    expect(cap.credential_id).toBe('AAAA');
    expect(cap.scope_set).toEqual(['tool:read', 'tool:write']);
  });

  test('challenge fetch non-2xx throws assertion-rejected', async () => {
    const fetchImpl = makeFetch([
      async () => new Response('nope', { status: 500 }),
    ]);
    let err: unknown;
    try {
      await requestCapability(baseOpts({ fetchImpl }));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RequestCapabilityError);
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:assertion-rejected',
    );
  });

  test('mint 403 with urn:chio:error:custody:credential-revoked propagates code', async () => {
    const fetchImpl = makeFetch([
      async () =>
        new Response(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      async () =>
        new Response(
          JSON.stringify({ error: { code: 'urn:chio:error:custody:credential-revoked' } }),
          { status: 403, headers: { 'content-type': 'application/json' } },
        ),
    ]);
    let err: unknown;
    try {
      await requestCapability(baseOpts({ fetchImpl }));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RequestCapabilityError);
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:credential-revoked',
    );
  });

  test('mint 401 with no body falls back to assertion-rejected', async () => {
    const fetchImpl = makeFetch([
      async () =>
        new Response(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      async () => new Response('', { status: 401 }),
    ]);
    let err: unknown;
    try {
      await requestCapability(baseOpts({ fetchImpl }));
    } catch (e) {
      err = e;
    }
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:assertion-rejected',
    );
  });

  test('issuer mint returns malformed capability rejects with internal-encoding', async () => {
    const fetchImpl = makeFetch([
      async () =>
        new Response(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      async () =>
        new Response(JSON.stringify({ capability: { audience: 'x' } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    ]);
    let err: unknown;
    try {
      await requestCapability(baseOpts({ fetchImpl }));
    } catch (e) {
      err = e;
    }
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:internal-encoding',
    );
  });

  test('missing audience throws synchronously', async () => {
    let err: unknown;
    try {
      await requestCapability({
        rpId: 'x',
        audience: '',
        scopes: [],
        issuerUrl: 'https://i',
        fetchImpl: () => Promise.reject(new Error('unreachable')),
        credentials: fakeCredentials(),
      });
    } catch (e) {
      err = e;
    }
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:internal-encoding',
    );
  });

  test('rejects non-string scopes before contacting issuer', async () => {
    let fetchCalls = 0;
    const fetchImpl = (() => {
      fetchCalls += 1;
      return Promise.reject(new Error('unreachable'));
    }) as typeof fetch;
    let err: unknown;
    try {
      await requestCapability(
        baseOpts({
          fetchImpl,
          scopes: [42 as unknown as string],
        }),
      );
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RequestCapabilityError);
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:internal-encoding',
    );
    expect(fetchCalls).toBe(0);
  });

  test('credentials.get rejection becomes assertion-rejected', async () => {
    const fetchImpl = makeFetch([
      async () =>
        new Response(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    ]);
    const credentials: CredentialsContainer = {
      get: async () => {
        throw new Error('user cancelled');
      },
      create: async () => null,
      preventSilentAccess: async () => undefined,
      store: async (cred: Credential) => cred,
    } as unknown as CredentialsContainer;
    let err: unknown;
    try {
      await requestCapability(baseOpts({ fetchImpl, credentials }));
    } catch (e) {
      err = e;
    }
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:assertion-rejected',
    );
  });

  test('malformed challenge bytes become internal-encoding', async () => {
    const fetchImpl = makeFetch([
      async () =>
        new Response(JSON.stringify({ challenge: '%%%not-base64url%%%' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    ]);
    let err: unknown;
    try {
      await requestCapability(baseOpts({ fetchImpl }));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RequestCapabilityError);
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:internal-encoding',
    );
  });

  test('round-trips audience + scopes verbatim into mint body', async () => {
    let captured: Record<string, unknown> | undefined;
    const fetchImpl = makeFetch([
      async () =>
        new Response(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      async (req) => {
        captured = (await req.json()) as Record<string, unknown>;
        return new Response(
          JSON.stringify({
            capability: fixtureCapability({
              audience: 'urn:chio:audience:control',
              scope_set: ['admin:read'],
            }),
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      },
    ]);
    await requestCapability(
      baseOpts({
        fetchImpl,
        audience: 'urn:chio:audience:control',
        scopes: ['admin:read'],
      }),
    );
    expect(captured).toBeDefined();
    expect((captured as Record<string, unknown>).audience).toBe('urn:chio:audience:control');
    expect((captured as Record<string, unknown>).scope_set).toEqual(['admin:read']);
  });

  test('issuer mint success with wrong audience rejects fail-closed', async () => {
    const fetchImpl = makeFetch([
      async () =>
        new Response(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      async () =>
        new Response(
          JSON.stringify({ capability: fixtureCapability({ audience: 'urn:chio:audience:evil' }) }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    ]);
    let err: unknown;
    try {
      await requestCapability(baseOpts({ fetchImpl }));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RequestCapabilityError);
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:audience-mismatch',
    );
  });

  test('issuer mint success with expanded scope rejects fail-closed', async () => {
    const fetchImpl = makeFetch([
      async () =>
        new Response(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      async () =>
        new Response(
          JSON.stringify({
            capability: fixtureCapability({ scope_set: ['tool:read', 'tool:write', 'admin:write'] }),
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    ]);
    let err: unknown;
    try {
      await requestCapability(baseOpts({ fetchImpl }));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(RequestCapabilityError);
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:assertion-rejected',
    );
  });
});
