// e2e: passkey mint -> capability -> kernel-call flow.
//
// Exercises requestCapability + installIssuerTestDouble under bun;
// no Playwright / chromium binary required. navigator.credentials
// is stubbed identically to the docs/demo test-double.

import { describe, expect, test, beforeEach } from 'bun:test';
import { requestCapability } from '../src/index.js';
import {
  installIssuerTestDouble,
  simulateRevocation,
  simulateKernelCall,
  type RevocationState,
} from '../../../../../docs/demo/passkey/test-double.ts';

const AUDIENCE = 'urn:chio:audience:kernel';
const ISSUER = 'https://issuer.local';
const KERNEL = 'https://kernel.local';

function freshGlobals(): { restoreFetch: () => void } {
  const origFetch = globalThis.fetch;
  // Some Bun runs do not provide a globalThis.navigator; create a minimal
  // shim so installIssuerTestDouble can patch credentials without throwing.
  const g = globalThis as { navigator?: Navigator };
  if (!g.navigator) {
    Object.defineProperty(globalThis, 'navigator', {
      value: {} as Navigator,
      configurable: true,
      writable: true,
    });
  }
  return {
    restoreFetch: () => {
      globalThis.fetch = origFetch;
    },
  };
}

describe('@chio-protocol/passkey demo e2e', () => {
  let env: { restoreFetch: () => void };
  let state: RevocationState;

  beforeEach(() => {
    env = freshGlobals();
    state = { revokedCredentialIds: new Set() };
    installIssuerTestDouble({
      issuerUrl: ISSUER,
      kernelUrl: KERNEL,
      audience: AUDIENCE,
      revocationState: state,
    });
  });

  test('happy path: passkey -> issuer -> capability -> kernel allow', async () => {
    const cap = await requestCapability({
      rpId: 'localhost',
      audience: AUDIENCE,
      scopes: ['tool:read', 'tool:write'],
      issuerUrl: ISSUER,
    });
    expect(cap.audience).toBe(AUDIENCE);
    expect(cap.credential_id).toMatch(/AAAA/);
    expect(cap.scope_set).toEqual(['tool:read', 'tool:write']);
    const verdict = await simulateKernelCall(KERNEL, cap, state);
    expect(verdict.allowed).toBe(true);
    env.restoreFetch();
  });

  test('audience mismatch from issuer surfaces as urn:chio:error:custody:audience-mismatch', async () => {
    let err: unknown;
    try {
      await requestCapability({
        rpId: 'localhost',
        audience: 'urn:chio:audience:wrong',
        scopes: ['tool:read'],
        issuerUrl: ISSUER,
      });
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect((err as { code?: string }).code).toBe('urn:chio:error:custody:audience-mismatch');
    env.restoreFetch();
  });

  test('revocation cascade: revoke credential, kernel call denies', async () => {
    const cap = await requestCapability({
      rpId: 'localhost',
      audience: AUDIENCE,
      scopes: ['tool:read'],
      issuerUrl: ISSUER,
    });
    let verdict = await simulateKernelCall(KERNEL, cap, state);
    expect(verdict.allowed).toBe(true);
    simulateRevocation(state, cap.credential_id);
    verdict = await simulateKernelCall(KERNEL, cap, state);
    expect(verdict.allowed).toBe(false);
    expect(verdict.errorCode).toBe('urn:chio:error:custody:credential-revoked');
    env.restoreFetch();
  });

  test('demo HTML carries the engineering-output banner above the fold', async () => {
    const fs = await import('node:fs/promises');
    const path = await import('node:path');
    const url = await import('node:url');
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    const indexPath = path.resolve(here, '../../../../../docs/demo/passkey/index.html');
    const html = await fs.readFile(indexPath, 'utf8');
    expect(html).toContain('engineering-output-banner');
    expect(html).toContain('zero key material');
    // The banner must be the first body child so it cannot scroll off
    // before the demo content. Cheap structural assertion: banner appears
    // before <main> in source order.
    const bannerIdx = html.indexOf('engineering-output-banner');
    const mainIdx = html.indexOf('<main');
    expect(bannerIdx).toBeGreaterThan(0);
    expect(mainIdx).toBeGreaterThan(bannerIdx);
    env.restoreFetch();
  });
});
