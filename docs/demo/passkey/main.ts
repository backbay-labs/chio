/*
 * Chio @chio-protocol/passkey demo.
 *
 * Drives the full passkey-to-capability flow against an in-page issuer
 * test-double:
 *
 *   1. Click "Run passkey flow" -> requestCapability() runs:
 *        a. POST /challenge -> challenge bytes returned by the test-double
 *        b. navigator.credentials.get -> the test-double mints a stub
 *           PublicKeyCredential (so the demo is self-contained and does
 *           not require a real authenticator)
 *        c. POST /mint -> the test-double returns a fixture
 *           PasskeyCapability
 *      The capability is rendered in the DOM, and the demo replays a
 *      kernel call against the fake kernel endpoint which returns 200.
 *   2. Click "Revoke credential and replay" -> the revocation oracle
 *      test-double marks the credential revoked, the kernel endpoint flips
 *      to 403 with urn:chio:error:custody:credential-revoked, and the
 *      verdict cell renders the cascade.
 *
 * The flow is the engineering counterpart to the kernel-side e2e in
 * crates/chio-custody-hw; this page exists so reviewers can see the
 * contract end-to-end without standing up an issuer.
 *
 * Trust contract: the page never holds key material, never signs an
 * envelope, and never calls any cryptographic primitive other than
 * navigator.credentials.get (which is platform-side). The "test-double"
 * issuer in this page exists only because the demo runs offline; in a
 * real deployment requestCapability points at the operator's issuer URL.
 */

import {
  requestCapability,
  RequestCapabilityError,
  type PasskeyCapability,
} from '@chio-protocol/passkey';
import { installIssuerTestDouble, simulateRevocation, simulateKernelCall, RevocationState } from './test-double.js';

const AUDIENCE = 'urn:chio:audience:kernel';
const RP_ID = 'localhost';
const SCOPES = ['tool:read', 'tool:write'];
const ISSUER_URL = 'https://issuer.local';
const KERNEL_URL = 'https://kernel.local';

let lastCapability: PasskeyCapability | null = null;
const revocationState: RevocationState = { revokedCredentialIds: new Set() };

function setText(id: string, value: string, state: 'ok' | 'fail' | 'info' = 'info'): void {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = value;
  el.setAttribute('data-state', state);
}

function setRaw(value: string): void {
  const el = document.getElementById('raw-result');
  if (el) el.textContent = value;
}

function renderCapability(cap: PasskeyCapability): void {
  setText('audience', cap.audience, 'info');
  setText('credential-id', cap.credential_id, 'info');
  setText('scope-set', cap.scope_set.join(', '), 'info');
  setText('iat', cap.iat, 'info');
  setText('exp', cap.exp, 'info');
  setRaw(JSON.stringify(cap, null, 2));
}

async function runFlow(): Promise<void> {
  setText('verdict-fresh', '(running)', 'info');
  setText('verdict-revoked', '(pending)', 'info');
  setText('revocation-urn', '(pending)', 'info');
  try {
    const cap = await requestCapability({
      rpId: RP_ID,
      audience: AUDIENCE,
      scopes: SCOPES,
      issuerUrl: ISSUER_URL,
    });
    lastCapability = cap;
    renderCapability(cap);
    const verdict = await simulateKernelCall(KERNEL_URL, cap, revocationState);
    setText(
      'verdict-fresh',
      verdict.allowed ? 'allow' : `deny (${verdict.errorCode ?? 'unknown'})`,
      verdict.allowed ? 'ok' : 'fail',
    );
    const revokeBtn = document.getElementById('revoke-flow') as HTMLButtonElement | null;
    if (revokeBtn) revokeBtn.disabled = false;
  } catch (cause) {
    const msg = cause instanceof RequestCapabilityError
      ? `${cause.code}: ${cause.message}`
      : cause instanceof Error
        ? cause.message
        : String(cause);
    setText('verdict-fresh', `error: ${msg}`, 'fail');
  }
}

// Cascade renderer.
//
// When the operator presses the revoke button, the issuer test-double
// pushes a revocation entry into the in-page revocation oracle (the
// RevocationState set). The same capability that previously rendered an
// allow now renders a deny carrying urn:chio:error:custody:credential-revoked.
// In the kernel-side e2e the cascade arrives within one revocation-oracle
// epoch (one-second tick in test config); the demo runs synchronously
// because the test-double consults the oracle on every call.
async function revokeAndReplay(): Promise<void> {
  if (!lastCapability) {
    setText('verdict-revoked', 'no capability minted yet', 'fail');
    return;
  }
  simulateRevocation(revocationState, lastCapability.credential_id);
  const verdict = await simulateKernelCall(KERNEL_URL, lastCapability, revocationState);
  setText(
    'verdict-revoked',
    verdict.allowed ? 'allow' : 'deny (revoked)',
    verdict.allowed ? 'ok' : 'fail',
  );
  setText('revocation-urn', verdict.errorCode ?? '(none)', verdict.allowed ? 'info' : 'fail');
}

function bind(): void {
  installIssuerTestDouble({
    issuerUrl: ISSUER_URL,
    kernelUrl: KERNEL_URL,
    audience: AUDIENCE,
    revocationState,
  });
  const runBtn = document.getElementById('run-flow');
  if (runBtn) runBtn.addEventListener('click', () => void runFlow());
  const revokeBtn = document.getElementById('revoke-flow');
  if (revokeBtn) revokeBtn.addEventListener('click', () => void revokeAndReplay());
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
}
