// Typed-enum surface tests for the urn:chio:error:custody:* codes
// consumed by @chio-protocol/passkey.
//
// The constant CHIO_CUSTODY_ERROR_CODES is the exhaustive set. The tests
// here pin the contract:
//
//   - the `code` field on RequestCapabilityError narrows to
//     CustodyErrorCode (verified at compile time via the assignability
//     check at the bottom of this file)
//   - isCustodyErrorCode is a strict allow-list (the conservative
//     bucket); unknown wire values collapse to internal-encoding
//   - all eight registry entries land in the constant; mismatch is a
//     trip-wire so future codegen passes cannot silently drop an entry
//   - exhaustiveness: a switch/case over CustodyErrorCode is checked at
//     compile time via the never-narrowing assertNever sentinel

import { describe, expect, test } from 'bun:test';
import {
  CHIO_CUSTODY_ERROR_CODES,
  ChioCustodyError,
  isCustodyErrorCode,
  toChioCustodyError,
  type CustodyErrorCode,
} from '../src/errors.js';
import { RequestCapabilityError } from '../src/index.js';

describe('CHIO_CUSTODY_ERROR_CODES enum', () => {
  test('contains every registry urn:chio:error:custody:* row', () => {
    // Source-of-truth list from spec/errors/registry.yaml under the
    // custody domain. If this set diverges from the registry, the
    // typed-enum contract has drifted; one of these (registry / SDK) is
    // wrong and the codegen pass MUST regenerate.
    const expected = new Set([
      'urn:chio:error:custody:assertion-rejected',
      'urn:chio:error:custody:audience-mismatch',
      'urn:chio:error:custody:replay-detected',
      'urn:chio:error:custody:capability-expired',
      'urn:chio:error:custody:credential-revoked',
      'urn:chio:error:custody:user-verification-required',
      'urn:chio:error:custody:hardware-key-unavailable',
      'urn:chio:error:custody:internal-encoding',
    ]);
    const actual = new Set(CHIO_CUSTODY_ERROR_CODES);
    expect(actual).toEqual(expected);
  });

  test('every entry is in the urn:chio:error:custody namespace', () => {
    for (const code of CHIO_CUSTODY_ERROR_CODES) {
      expect(code.startsWith('urn:chio:error:custody:')).toBe(true);
    }
  });

  test('isCustodyErrorCode is a strict allow-list', () => {
    for (const code of CHIO_CUSTODY_ERROR_CODES) {
      expect(isCustodyErrorCode(code)).toBe(true);
    }
    expect(isCustodyErrorCode('urn:chio:error:custody:made-up')).toBe(false);
    expect(isCustodyErrorCode('urn:chio:error:other:thing')).toBe(false);
    expect(isCustodyErrorCode('')).toBe(false);
    expect(isCustodyErrorCode(null)).toBe(false);
    expect(isCustodyErrorCode(undefined)).toBe(false);
    expect(isCustodyErrorCode(42)).toBe(false);
  });

  test('toChioCustodyError preserves typed codes verbatim', () => {
    const err = toChioCustodyError(
      'urn:chio:error:custody:credential-revoked',
      'revoked',
    );
    expect(err).toBeInstanceOf(ChioCustodyError);
    expect(err.code).toBe('urn:chio:error:custody:credential-revoked');
  });

  test('toChioCustodyError collapses unknown codes to internal-encoding (fail-closed)', () => {
    const err = toChioCustodyError('urn:chio:error:custody:future-thing', 'mystery');
    expect(err.code).toBe('urn:chio:error:custody:internal-encoding');
    expect(err.message).toContain('unknown custody error code');
  });
});

describe('RequestCapabilityError carries a typed CustodyErrorCode', () => {
  test('runtime: instance code matches the typed enum', () => {
    const err = new RequestCapabilityError(
      'urn:chio:error:custody:replay-detected',
      'replayed',
    );
    expect(err.code).toBe('urn:chio:error:custody:replay-detected');
    // structural check: the code field must be assignable to the typed
    // enum; the assertion below would not compile if the field were
    // declared as plain string.
    const assigned: CustodyErrorCode = err.code;
    expect(typeof assigned).toBe('string');
  });

  test('exhaustive switch over CustodyErrorCode is type-safe', () => {
    // assertNever is the canonical "make TS verify exhaustiveness"
    // sentinel. If any CustodyErrorCode member is missing from the
    // switch, the never assignment trips at compile time.
    function describeCode(code: CustodyErrorCode): string {
      switch (code) {
        case 'urn:chio:error:custody:assertion-rejected':
          return 'assertion';
        case 'urn:chio:error:custody:audience-mismatch':
          return 'audience';
        case 'urn:chio:error:custody:replay-detected':
          return 'replay';
        case 'urn:chio:error:custody:capability-expired':
          return 'expired';
        case 'urn:chio:error:custody:credential-revoked':
          return 'revoked';
        case 'urn:chio:error:custody:user-verification-required':
          return 'uv';
        case 'urn:chio:error:custody:hardware-key-unavailable':
          return 'hw-key';
        case 'urn:chio:error:custody:internal-encoding':
          return 'enc';
        default: {
          const exhaustive: never = code;
          throw new Error(`unhandled CustodyErrorCode: ${exhaustive as string}`);
        }
      }
    }
    for (const code of CHIO_CUSTODY_ERROR_CODES) {
      expect(typeof describeCode(code)).toBe('string');
    }
  });
});

describe('issuer wire codes flow through the typed enum', () => {
  test('issuer 403 with unknown wire code falls back to assertion-rejected', async () => {
    const fetchImpl: typeof fetch = async (url) => {
      const u = String(url);
      if (u.endsWith('/challenge')) {
        return new Response(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(
        JSON.stringify({ error: { code: 'urn:chio:error:custody:future-thing' } }),
        { status: 403, headers: { 'content-type': 'application/json' } },
      );
    };
    const credentials: CredentialsContainer = {
      get: async () =>
        ({
          id: 'AAAA',
          type: 'public-key',
          rawId: new ArrayBuffer(4),
          response: {
            clientDataJSON: new ArrayBuffer(4),
            authenticatorData: new ArrayBuffer(4),
            signature: new ArrayBuffer(4),
            userHandle: null,
          },
          getClientExtensionResults: () => ({}),
          authenticatorAttachment: null,
        }) as unknown as Credential,
      create: async () => null,
      preventSilentAccess: async () => undefined,
      store: async (cred: Credential) => cred,
    } as unknown as CredentialsContainer;
    const { requestCapability } = await import('../src/index.js');
    let err: unknown;
    try {
      await requestCapability({
        rpId: 'l',
        audience: 'urn:chio:audience:kernel',
        scopes: [],
        issuerUrl: 'https://issuer.local',
        fetchImpl,
        credentials,
      });
    } catch (e) {
      err = e;
    }
    expect((err as RequestCapabilityError).code).toBe(
      'urn:chio:error:custody:assertion-rejected',
    );
  });
});
