# Trust-boundary review: browser-side delegated subkey signing

Status: rejected
Approver: @bb-connor
Date: 2026-04-27

## 1. Scope of delegated subkeys

Verdict: rejected for M08.

- Audience binding: no browser-resident delegated subkey audience is approved for M08.
- Time bounds: no maximum lifetime is accepted because no provisioning and revocation model has been approved.
- Scope narrowing: root, mint, and delegate scopes remain forbidden in any browser, Worker, Edge function, or user-reachable JavaScript runtime.
- Quantitative limits: no per-session signing budget, per-minute rate, or per-origin cap is accepted without a signed server-side issuance and revocation design.

This decision does not add browser signing, delegated subkey code, package APIs, or a `signRoot` entry point. Root capability authorities and root signing keys must never live in browser-side runtimes.

## 2. Signer provenance

No existing repository evidence establishes a security-owner-approved delegated-subkey provenance chain for browser-side signing.

Required evidence before reconsideration:

- A named server-side authority that issues browser subkeys.
- A signed provisioning envelope with explicit origin, audience, scope, expiry, and issuer metadata.
- A receipt-visible delegation chain shaped like `root -> intermediate -> browser-subkey`.
- A verifier path that proves every browser-signed receipt traces back to a server-side root without trusting browser-held root material.

The current M08 trajectory may continue to ship verify-only browser capability and receipt verification. Delegated signing is moved to a follow-on milestone after stronger evidence is written, reviewed, and approved.

## 3. Revocation surface

No revocation surface is approved for browser-resident delegated subkeys in M08.

Required evidence before reconsideration:

- A revocation-list distribution channel that works for offline and partially stale clients.
- A maximum staleness bound accepted by verifiers.
- A subkey-leak response runbook that covers XSS, malicious extensions, and package compromise.
- Signed audit records for issuance, rotation, and revocation events.

Without those controls, a stolen browser subkey could continue producing signatures that look valid to clients that have not received a revocation update.

## 4. Threat model

The rejected model leaves the following risks unresolved:

- XSS: attacker-controlled JavaScript could sign within any scope exposed to the page.
- Malicious browser extension: extension-injected code can share the page's runtime and observe or use resident key material.
- Supply-chain compromise: a compromised `@chio-protocol/browser` package could sign attacker-chosen payloads until the package and all issued subkeys are rotated.
- Non-browser replay: a leaked subkey can be replayed from another runtime unless the provenance and verifier model binds use to the intended browser context.
- Compromised CA or TLS MITM: provisioning cannot be accepted without a signed bootstrap envelope and verifier-visible issuer chain.

These risks are acceptable for verification-only surfaces because public verification material can be embedded or fetched without granting signing authority. They are not acceptable for browser-side delegated signing without stronger provenance, revocation, and verifier evidence.

## 5. Decision

- [ ] Approved. Phase 3 may proceed with the constraints above.
- [x] Rejected. M08 ships at Phase 2 as verify-only; delegated signing is not pursued in this trajectory, and rationale is recorded here.

Follow-on milestone criteria:

- Define the delegated subkey data model and receipt encoding.
- Prove audience, expiry, scope attenuation, and delegation-chain verification with property-based tests.
- Document server-side issuance and revocation ownership.
- Obtain security-owner approval before adding any browser-side delegated signing API.
