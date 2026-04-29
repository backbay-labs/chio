# M10 Trust-Boundary Audit: Hardware Custody + Policy-Bound Model Cards

**Trajectory:** trajectory-2
**Milestone:** M10
**Wave:** W4
**Status:** TEMPLATE (orchestrator fills as phases close)
**Audit start:** <fill at P0 wave-opener merge>
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M10 closes the two identity-custody holes trajectory-1 left open. The first
surface is hardware-bound custody: a server-side issuer that turns a
WebAuthn / passkey assertion into a short-lived audience-pinned capability
so the browser holds zero capability material. This is the follow-on
milestone the trajectory-1 M08.P3 verdict (`docs/trust-boundary-browser-signing.md`,
status `rejected`, dated 2026-04-27) promised: a named server-side
authority issuing audience-bound subkeys.

The second surface is `chio-weights`: signed model cards binding
`(weights_hash, allowed_capability_set, banned_tools, training_data_class)`
so the kernel will not bind a provider unless the loaded weights match a
card and the requested scopes are a subset of the card's allowed set.

The lens is identity custody and model-identity binding: identity is
something the kernel verifies, not something a runtime asserts. If
schedule pressure forces a cut, custody is the half that ships (D24);
both halves are in scope at trajectory-2 close.

## 2. Pre-flight checklist (mark off at P0 close)

- [ ] Cargo.lock wave-opener ticket M10.P0.T1 merged (webauthn-rs, webauthn-rs-proto, base64ct)
- [ ] freezes.yml entry `m10-custody-issuer-pivot` is in effect (start_trigger M10.P1.T1 merged) covering P1..P3
- [ ] CODEOWNERS regen for `crates/chio-custody-hw/**`, `sdks/typescript/packages/passkey/src/**`, `crates/chio-weights/**`
- [ ] Security x2 review reviewer instances configured (different seeds, no shared scratchpad)
- [ ] M03 `m03-attest-verify-pivot` and M04 `m04-revocation-oracle-pivot` both closed (cross-freeze ordering: m10-custody-issuer-pivot opens AFTER M03 + M04 close so the issuer can sign via M03 hybrid surface and revoke via M04 oracle)
- [ ] M05 threat-model registry rows `passkey_credential_theft`, `audience_confusion`, `weights_hash_spoof` appended (M10.P0.T3)
- [ ] urn:chio:error:custody and urn:chio:error:weights namespaces seeded in error registry (M10.P0.T4) -- M01 dependency
- [ ] M07 cross-provider verdict equality oracle availability tracked for M10.P5.T2

## 3. Per-phase evidence

### P0 wave-opener
- Tickets merged:
  - M10.P0.T1 (Pin webauthn-rs, webauthn-rs-proto, base64ct) merged_sha: <fill>
  - M10.P0.T2 (Open M10 audit doc with starting counts) merged_sha: <fill>
  - M10.P0.T3 (Append three threat-model rows: passkey_credential_theft, audience_confusion, weights_hash_spoof) merged_sha: <fill>
  - M10.P0.T4 (Seed urn:chio:error:custody and urn:chio:error:weights namespaces) merged_sha: <fill>
- Cargo.lock diff: <fill range>
- Build green: <fill ci link or commit>

### P1 chio-custody-hw crate genesis
- Tickets merged:
  - M10.P1.T1 (chio-custody-hw skeleton with workspace registration and forbid-unsafe lints) merged_sha: <fill>
  - M10.P1.T2 (PasskeyVerifier wrapping webauthn-rs assertion-verify primitive) merged_sha: <fill>
  - M10.P1.T3 (PasskeyCapability envelope: 5-min exp + audience pin + canonical-JSON) merged_sha: <fill>
  - M10.P1.T4 (Issuer service skeleton as Axum library handler with pinned fixture round-trip) merged_sha: <fill>
  - M10.P1.T5 (Pinned WebAuthn fixture corpus: 4 positive, 4 negative) merged_sha: <fill>
  - M10.P1.T6 (urn:chio:error:custody:* registry rows: assertion-rejected, audience-mismatch, replay-detected, capability-expired, credential-revoked) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P2 Capability minting and revocation cascade
- Tickets merged:
  - M10.P2.T1 (Wire M03 HybridBackend into issuer mint_capability under crypto_floor policy) merged_sha: <fill>
  - M10.P2.T2 (PasskeyNonceStore trait + in-memory + SQLite impls) merged_sha: <fill>
  - M10.P2.T3 (Revocation cascade through M04 chio-revocation-oracle on credential revoke) merged_sha: <fill>
  - M10.P2.T4 (Audience-confusion proptest enforcing audience-bit-flip rejection) merged_sha: <fill>
  - M10.P2.T5 (Kernel-side PasskeyCapabilityVerifier integration) merged_sha: <fill>
  - M10.P2.T6 (E2E issuer-to-kernel test: passkey -> capability -> kernel call -> revoke -> deny within M04 epoch) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P3 Browser flow and @chio/passkey
- Tickets merged:
  - M10.P3.T1 (Scaffold @chio/passkey TS package: package.json, tsconfig, src/index.ts) merged_sha: <fill>
  - M10.P3.T2 (Implement requestCapability calling navigator.credentials.get and POSTing to issuer) merged_sha: <fill>
  - M10.P3.T3 (Demo HTML at docs/demo/passkey driving the full flow + Playwright e2e) merged_sha: <fill>
  - M10.P3.T4 (E2E revocation test asserting deny within M04 epoch after issuer revoke) merged_sha: <fill>
  - M10.P3.T5 (Per-runtime size budget for @chio/passkey enforced at 30 KB gzipped in CI) merged_sha: <fill>
  - M10.P3.T6 (Surface urn:chio:error:custody:* codes in TS errors via M01 typed-enum codegen) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P4 chio-weights model card schema and arc bind
(P4 is tagged "descope candidate" per D24 if schedule pressure surfaces.)
- Tickets merged:
  - M10.P4.T1 (chio-weights skeleton with workspace registration and forbid-unsafe lints) merged_sha: <fill>
  - M10.P4.T2 (Model card schema model-card.v1.json + ModelCard type with canonical-JSON goldens) merged_sha: <fill>
  - M10.P4.T3 (Cosign bundle helper consuming SigstoreVerifier::verify_bundle) merged_sha: <fill>
  - M10.P4.T4 (policy.weights_card_required enum: disabled | required | required_with_pin) merged_sha: <fill>
  - M10.P4.T5 (Kernel binding refusal on weights_hash/allowed_capability_set/banned_tools mismatch) merged_sha: <fill>
  - M10.P4.T6 (arc bind <provider> --card <path> CLI subcommand) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P5 Cross-cutting (lineage anchoring, equivalence, threat coverage)
(P5 is tagged "descope candidate" per D24 if schedule pressure surfaces.)
- Tickets merged:
  - M10.P5.T1 (Lineage anchoring of model cards via M09 chio-lineage anchor proof) merged_sha: <fill>
  - M10.P5.T2 (Cross-provider equivalence test consuming M07 verdict-equality oracle) merged_sha: <fill>
  - M10.P5.T3 (Threat-model coverage gate marks three M10 threat IDs covered) merged_sha: <fill>
  - M10.P5.T4 (Audit doc final pass with closing counts) merged_sha: <fill>
  - M10.P5.T5 (Documentation pass: docs/custody/passkey-issuer.md + docs/weights/model-cards.md) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

## 4. Trust-boundary attestations

For trust-boundary milestones, every PR was reviewed by:
- Security reviewer instance A: <fill handle or seed>
- Security reviewer instance B: <fill handle or seed>
- Human-side reviewer: @bb-connor

Per-phase PR attestation log (filled by orchestrator):

- P0 PRs reviewed: <fill PR numbers> -- attestation status: <fill>
- P1 PRs reviewed: <fill> -- attestation status: <fill>
- P2 PRs reviewed: <fill> -- attestation status: <fill>
- P3 PRs reviewed: <fill> -- attestation status: <fill>
- P4 PRs reviewed: <fill> -- attestation status: <fill>
- P5 PRs reviewed: <fill> -- attestation status: <fill>

Hot-fix bypass log (record any `hotfix/* + [trajectory-2]` overrides
during `m10-custody-issuer-pivot`):
<fill or "no overrides">

Descope decision log (per D24): if either P4 or P5 was descoped under
schedule pressure, record the decision and follow-on milestone target here.
<fill or "no descope events; both halves shipped">

## 5. Decisions in force

- D23 (WebAuthn assertion is authn, not signing material; passkey-as-authn issuer mints 5-minute audience-pinned capability bound to credential id; browser holds zero capability material)
- D24 (Both halves of M10 are in scope; custody half ships first if schedule pressure)

## 6. Threat-model coverage at close

M10 owns three new threat IDs added in P0 to
`spec/security/chio-threat-model.v1.json`:

- `passkey_credential_theft` -- covered by <fill: M10.P1.T5 negative
  fixtures (replayed challenge, mismatched origin, expired challenge,
  malformed CBOR), M10.P2.T2 PasskeyNonceStore replay rejection, M10.P2.T3
  revocation cascade through M04 oracle>
- `audience_confusion` -- covered by <fill: M10.P2.T4 audience-confusion
  proptest enforcing audience-bit-flip rejection across the capability
  envelope; M10.P2.T5 kernel-side audience pin check>
- `weights_hash_spoof` -- covered by <fill: M10.P4.T2 model card
  canonical-JSON goldens + cosign bundle binding via M10.P4.T3; M10.P4.T5
  kernel binding refusal on weights_hash mismatch>. Note: per the risk
  register, this threat may close as *partially covered* until
  `chio-providers` recomputes the hash from the loaded weights blob; gap
  documented here.

Cross-reference: M05.P5 threat-model-coverage gate consumes the
`coveredBy` cross-link added by M10 in the relevant rows of
`spec/security/chio-threat-model.v1.json`. The three IDs MUST be marked
covered (with the `weights_hash_spoof` partial-coverage note) before M10
closes per M10.P5.T3.

Custody surface coverage:
- WebAuthn fixture corpus (positive/negative): <fill counts>
- Replay-attack resistance test: <fill pass/fail>
- Audience-confusion proptest: <fill pass/fail>
- E2E issuer-to-kernel revocation test (revoke -> deny within M04 epoch):
  <fill pass/fail>
- @chio/passkey size at close: <fill KB gzipped, target < 30 KB>

Model card surface coverage (if P4-P5 shipped):
- Model card canonical-JSON goldens: <fill counts>
- Kernel binding refusal paths
  (`urn:chio:error:weights:card-mismatch`,
  `urn:chio:error:weights:scope-not-subset`,
  `urn:chio:error:weights:tool-banned`): <fill all-pass yes/no>
- M07 cross-provider equivalence test green for at least one card pair:
  <fill yes/no>

## 7. Cross-trajectory artifact handoffs

Produced by M10, consumed downstream:

- `chio-custody-hw` PasskeyVerifier + PasskeyCapability envelope + issuer
  service skeleton -- consumed by `chio-control-plane` operators mounting
  the issuer; this is the response to the trajectory-1 M08.P3 verdict.
- `@chio/passkey` TypeScript package -- consumed by browser-side
  applications via `requestCapability({ rpId, audience, scopes,
  issuerUrl })`; published under the existing `@chio` npm org. Holds zero
  key material.
- `chio-weights` model card schema + cosign bundle helper +
  `arc bind --card <path>` -- consumed by every operator binding a
  provider under `policy.weights_card_required`.
- Three new threat IDs (`passkey_credential_theft`, `audience_confusion`,
  `weights_hash_spoof`) -- consumed by M05.P5 threat-model-coverage gate.
- Public model-card registry entries -- consumed via M09 lineage anchor
  proofs (M10 publishes; M09 owns the anchor surface).

Consumed by M10 from upstream:
- `HybridBackend` from M03.P2.T2 -- signs PasskeyCapability envelopes
  per M10.P2.T1. Capabilities are PQ-ready as soon as
  `crypto_floor=allow_hybrid` lands.
- `chio-revocation-oracle` from M04.P3 close -- revocation cascade per
  M10.P2.T3; the kernel rejects capabilities whose credential id is
  revoked at the next M04 epoch.
- `urn:chio:error:*` registry from M01 -- consumed by both halves
  (custody and weights error namespaces seeded in M10.P0.T4).
- M07 cross-provider verdict equality oracle -- consumed by M10.P5.T2.

Cross-doc invariants enforced (EXECUTION-BOARD section 3):
- `m10-custody-issuer-pivot` opens AFTER `m03-attest-verify-pivot` and
  `m04-revocation-oracle-pivot` close so the issuer can sign via M03
  hybrid surface and revoke via M04 oracle.
- M10 does not extend `chio-attest-verify`; it consumes the existing
  surface (Sigstore single source of truth and PQ-hybrid signing).
- M10 does not invent its own revocation surface; it pushes through M04
  oracle.
- Browser-side wasm boundary stays verify-only; `@chio/passkey` holds
  zero key material (D23 + the trajectory-1 M08.P3 prohibition is
  preserved).

## 8. Halt-and-resume events

If this milestone hit any halt triggers from AUTONOMOUS-PROMPT or
HANDOFF-PROMPT, the event log entry goes here. Examples that would trigger
a halt: webauthn-rs FIDO Metadata Service format divergence between patch
versions; replay across issuer restart breaking durable nonce store;
audience-confusion proptest discovering a kernel-verifier audience-pin
gap; weights-hash spoof discovering a provider-bind-time gap; M07
cross-provider equivalence regression on a card pair.

<fill or "no halt events">

## 9. Close-out signature

- Final commit on `main`: <fill 40hex sha>
- Final ticket merged: M10.P5.T5 (or M10.P3.T6 if P4-P5 descoped per D24)
- Audit closed by: @bb-connor
- Audit close date: <fill yyyy-mm-dd>
