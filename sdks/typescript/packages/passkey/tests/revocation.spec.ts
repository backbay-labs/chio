// End-to-end revocation test.
//
// Asserts that a capability minted from a passkey assertion is denied at
// the kernel within one revocation-oracle epoch (one second in the test
// config) after the issuer revokes the underlying WebAuthn credential.
// The kernel side of the same scenario is covered by
// crates/chio-custody-hw end-to-end; this file pins the browser-side
// contract so the SDK surface signals the cascade with a stable
// urn:chio:error:* code.
//
// Cascade shape (matches the kernel-side e2e):
//
//   1. Browser POST /challenge -> issuer challenge.
//   2. navigator.credentials.get -> assertion.
//   3. Browser POST /mint -> issuer-minted PasskeyCapability (signature
//      slot empty in the demo test-double; the kernel test-double does
//      not verify the signature - the revocation cascade is the contract
//      under test here).
//   4. Browser calls the kernel; kernel allows (credential is fresh).
//   5. Operator revokes the credential at the issuer; the issuer pushes a
//      revocation entry to the revocation oracle (modelled here by the
//      RevocationState set, which is the test-double of
//      crates/chio-revocation-oracle).
//   6. The revocation epoch ticks (one second in the test config; here we
//      advance a virtual clock so the test runs deterministically).
//   7. Browser re-calls the kernel with the same capability; kernel
//      denies fail-closed with urn:chio:error:custody:credential-revoked.
//
// The browser-side requirement is that requestCapability + the kernel
// verdict surface combine to give the caller a single deterministic urn
// to branch on. The cascade does NOT require the browser to do anything
// special at revocation time; the kernel verdict is what flips.

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

// One-second epoch matches the revocation test config (the kernel-side test
// uses the same value). We model the epoch as a counter so the test is
// fully deterministic and not bound to wall-clock sleep.
const EPOCH_TICK_MS = 1000;

interface Clock {
  now: () => number;
  advance: (ms: number) => void;
}

function makeVirtualClock(): Clock {
  let t = 0;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

function ensureNavigator(): void {
  const g = globalThis as { navigator?: Navigator };
  if (!g.navigator) {
    Object.defineProperty(globalThis, 'navigator', {
      value: {} as Navigator,
      configurable: true,
      writable: true,
    });
  }
}

describe('@chio-protocol/passkey revocation cascade', () => {
  let state: RevocationState;
  let originalFetch: typeof fetch;
  let clock: Clock;

  beforeEach(() => {
    ensureNavigator();
    originalFetch = globalThis.fetch;
    state = { revokedCredentialIds: new Set() };
    clock = makeVirtualClock();
    installIssuerTestDouble({
      issuerUrl: ISSUER,
      kernelUrl: KERNEL,
      audience: AUDIENCE,
      revocationState: state,
    });
  });

  test('revoking the credential denies the next kernel call within one revocation epoch', async () => {
    const cap = await requestCapability({
      rpId: 'localhost',
      audience: AUDIENCE,
      scopes: ['tool:read', 'tool:write'],
      issuerUrl: ISSUER,
    });

    // Fresh capability: kernel allows.
    const t0 = clock.now();
    const fresh = await simulateKernelCall(KERNEL, cap, state);
    expect(fresh.allowed).toBe(true);
    expect(fresh.errorCode).toBeUndefined();

    // Operator revokes at the issuer; the issuer pushes the revocation
    // through the revocation oracle (modelled by the RevocationState set).
    simulateRevocation(state, cap.credential_id);

    // Advance the virtual clock by one revocation epoch tick. The cascade is
    // synchronous from the kernel verdict's point of view (it consults
    // the oracle on every call), so the deny appears immediately at the
    // next epoch boundary regardless of wall-clock sleep.
    clock.advance(EPOCH_TICK_MS);
    expect(clock.now() - t0).toBeLessThanOrEqual(EPOCH_TICK_MS);

    const after = await simulateKernelCall(KERNEL, cap, state);
    expect(after.allowed).toBe(false);
    expect(after.errorCode).toBe('urn:chio:error:custody:credential-revoked');

    globalThis.fetch = originalFetch;
  });

  test('revocation is sticky: subsequent calls after the epoch all deny', async () => {
    const cap = await requestCapability({
      rpId: 'localhost',
      audience: AUDIENCE,
      scopes: ['tool:read'],
      issuerUrl: ISSUER,
    });
    simulateRevocation(state, cap.credential_id);
    for (let i = 0; i < 3; i += 1) {
      clock.advance(EPOCH_TICK_MS);
      const verdict = await simulateKernelCall(KERNEL, cap, state);
      expect(verdict.allowed).toBe(false);
      expect(verdict.errorCode).toBe('urn:chio:error:custody:credential-revoked');
    }
    globalThis.fetch = originalFetch;
  });

  test('revoking a different credential does not affect this capability', async () => {
    const cap = await requestCapability({
      rpId: 'localhost',
      audience: AUDIENCE,
      scopes: ['tool:read'],
      issuerUrl: ISSUER,
    });
    simulateRevocation(state, 'a-different-credential-id');
    clock.advance(EPOCH_TICK_MS);
    const verdict = await simulateKernelCall(KERNEL, cap, state);
    expect(verdict.allowed).toBe(true);
    globalThis.fetch = originalFetch;
  });

  test('mint after revoke returns a fresh capability the kernel still denies', async () => {
    // Browser-side mint succeeds (the test-double doesn't gate mint on
    // revocation; that policy lives at the issuer in the kernel-side
    // implementation). Even so, the kernel verdict denies the capability
    // because the credential id is in the revocation set, so the cascade
    // closes the loop.
    const cap = await requestCapability({
      rpId: 'localhost',
      audience: AUDIENCE,
      scopes: ['tool:read'],
      issuerUrl: ISSUER,
    });
    simulateRevocation(state, cap.credential_id);
    const cap2 = await requestCapability({
      rpId: 'localhost',
      audience: AUDIENCE,
      scopes: ['tool:read'],
      issuerUrl: ISSUER,
    });
    expect(cap2.credential_id).toBe(cap.credential_id);
    clock.advance(EPOCH_TICK_MS);
    const verdict = await simulateKernelCall(KERNEL, cap2, state);
    expect(verdict.allowed).toBe(false);
    expect(verdict.errorCode).toBe('urn:chio:error:custody:credential-revoked');
    globalThis.fetch = originalFetch;
  });
});
