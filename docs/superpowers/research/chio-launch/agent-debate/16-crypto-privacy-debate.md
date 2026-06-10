# Agent 16 Crypto And Privacy Debate

Date: 2026-06-09
Agent: 16
Role: cryptography, privacy, and verifiable-computation skeptic
Scope: `INDEX.md`, `indices/artifact-registry.md`, `architecture/04-lineage-disclosure-system.md`, `plans/04-lineage-disclosure-implementation.md`, and `plans/08-agent-web-proof-envelope-implementation.md`, with adjacent launch gates used only to keep fixture and schema implications concrete.
Confidence: high for launch-claim risk, high for the need to separate cryptographic verification from privacy-policy verification, moderate for final schema placement, moderate for external standard status because source versions can move.

## Executive Position

The strongest counterargument to the current launch story is simple: the docs are close to overclaiming privacy because they name BBS, SD-JWT, VC, and external proof envelopes before key lifecycle, revocation, nonce/audience binding, presentation freshness, and transparency semantics are first-class verifier inputs.

That is not a minor implementation detail. A cryptographic proof that verifies under the wrong key, stale epoch, wrong audience, reused nonce, ambiguous external subject digest, or permissive disclosure policy is worse than no proof because it creates a false verifier verdict.

The current architecture gets one critical thing right: selective disclosure is defined as verifier behavior, not JSON redaction. Keep that. The missing layer is a cryptographic context contract shared by disclosure capsules, signed lineage subgraphs, Transaction Passports, and Agent Web Proof Envelopes.

Launch should claim:

- Chio binds signed receipts, disclosure capsules, lineage subgraphs, and external protocol subjects into a verifier-enforced proof graph.
- BBS and SD-JWT are optional disclosure mechanisms under Chio privacy profiles.
- VC, Verifiable Presentations, in-toto, DSSE, Sigstore, SLSA, AP2, x402, MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, and OpenAPI are external evidence or projection surfaces.
- Chio authority remains the Chio receipt and Transaction Passport authority path.

Launch should not claim:

- generic ZK privacy;
- generic VC wallet interoperability;
- W3C BBS Data Integrity conformance unless that exact processing model is emitted and verified;
- SD-JWT VC interoperability unless that profile is implemented and version-pinned;
- TEE-backed trust unless quote verification, measurement policy, freshness, and fallback semantics exist;
- transparency-log proof unless inclusion and checkpoint semantics are verified;
- threshold security unless membership, threshold, key epochs, and signer identity are verified;
- post-quantum security unless a concrete algorithm suite is implemented and policy-enforced.

## What Is Missing

### 1. Key lifecycle is underspecified

The registry lists verifier-facing artifacts, but the launch privacy and external-envelope plans do not yet define a common key-state object. A signature verifier needs more than `key_id`.

Required verifier facts:

- trust root id;
- issuer id;
- verification method or key id;
- algorithm and ciphersuite;
- key usage;
- key epoch;
- validity interval;
- revocation status;
- rotation predecessor or successor link when applicable;
- compromise reason when a key is revoked;
- status snapshot time;
- verifier clock input;
- transparency inclusion requirement when policy demands public anchoring.

Concrete addition: add a trust and crypto context artifact before accepting privacy or envelope claims.

Candidate schema names, not canonical until registered:

- `chio.trust.key-state.v1`
- `chio.trust.revocation-snapshot.v1`
- `chio.transparency.inclusion-proof.v1`
- `chio.crypto.verification-context.v1`

These can be separate artifacts or one trust bundle. The important part is that verifier reports must bind their digest. A public proof room cannot ask the user to infer key validity from a signing key string.

### 2. Revocation is present in delegation language but missing from disclosure and envelope verification

The launch docs already mention revocation epochs for swarm continuation. Disclosure capsules and Agent Web envelopes need the same seriousness.

Required checks:

- issuer key was not revoked at signing time;
- issuer key is acceptable at verification time under policy;
- holder binding key was not revoked for holder-bound presentations;
- capability, credential, or passport status was not revoked when the disclosed fact was asserted;
- continuation or transaction revocation epoch matches the Transaction Passport verifier policy;
- replayed disclosure presentations fail unless policy allows replay.

Concrete addition: every verifier-facing presentation should carry a `status_refs` or `revocation_refs` section that binds immutable snapshots, not live API hopes.

### 3. Disclosure proofs lack a shared presentation context

BBS and SD-JWT both need presentation context. Without it, a valid proof can be replayed across verifier, transaction, or policy boundaries.

Required fields for `chio.disclosure.capsule.v1`:

- `presentation_id`
- `transaction_passport_ref`
- `privacy_profile_ref`
- `proof_mechanism`
- `issuer_key_ref`
- `issuer_key_state_ref`
- `holder_binding_ref`
- `audience`
- `nonce`
- `challenge`
- `created_at`
- `expires_at`
- `verifier_clock`
- `projection_manifest_ref`
- `disclosed_message_refs`
- `hidden_predicate_refs`
- `status_refs`
- `leakage_ledger_ref`
- `signed_lineage_subgraph_ref`

The verifier should reject a capsule with a valid cryptographic proof if the audience, nonce, transaction passport, projection manifest digest, holder binding, or privacy profile does not match.

### 4. Transparency logs are confused with generic append-only evidence

The research package correctly distinguishes preview-only transparency from trust-anchored proof in other areas. The privacy and envelope plans should inherit that vocabulary.

Three transparency states are needed:

- `none`: no transparency claim;
- `preview`: log-like evidence exists but is not independently anchored or verified;
- `anchored`: inclusion, checkpoint, and trust root verification succeeded.

For Sigstore/Rekor claims, "bundle present" is not "transparency verified." For Chio runtime receipts, "append-only log exists" is not "publicly anchored." For a launch proof, the verifier report must say which state applies.

Concrete addition: make transparency status an explicit verifier result for every signed artifact that is advertised as publicly auditable.

### 5. Verifiable Presentations are useful but should not become the root proof

VC and Verifiable Presentation machinery can help with issuer-holder-verifier semantics, challenge/domain binding, and wallet presentation flows. It should not become the Transaction Passport.

Safe claim: Chio can project selected passport facts into VC or VP-compatible presentations where the data model, securing mechanism, challenge, domain, holder binding, and credential status are implemented.

Unsafe claim: Chio Transaction Passports are VCs by default, or any Chio passport works in generic VC wallets.

Concrete addition: model VC/VP as an external projection in `chio.agent-web.external-projection-manifest.v1`, with unsupported fields reported in `chio.agent-web.interop-verifier-report.v1`.

### 6. Algorithm agility and post-quantum hooks are missing

Post-quantum should be a hook, not a launch claim. The right first move is algorithm agility:

- artifact-level `algorithm`;
- ciphersuite-specific `suite`;
- canonicalization method;
- hash function;
- signature encoding;
- key usage;
- verifier policy allowlist;
- verifier policy denylist;
- optional hybrid signature refs for future migration.

Concrete addition: add `signature_suite_policy` to verifier policy or trust context and require reports to state whether the artifact passed under `required`, `allowed`, `deprecated`, or `rejected` algorithms.

Do not claim post-quantum resistance until a concrete PQ or hybrid signature suite is implemented, fixture-backed, and accepted by policy.

## Capability Debate

| Capability | Launch value | Skeptical verdict | Required addition |
| --- | --- | --- | --- |
| BBS | Strong fit for selective disclosure over typed message slots. | Useful but overhyped if profile checks, nonce binding, issuer key status, and projection manifest digest are missing. | Keep `chio.bbs-projection.manifest.v2`; add key state, nonce/audience binding, holder binding, and over-disclosure rejection. |
| SD-JWT | Operationally practical for JWT ecosystems and selective disclosure. | Useful as a mechanism, not a proof of Chio truth. | Add `proof_mechanism: sd-jwt-rfc9901`, disclosure digest checks, KB holder binding policy, nonce/audience binding, and status refs. |
| ZK proofs | Valuable for future range, membership, and set-inclusion claims. | Reject for launch unless a specific circuit, public input set, and verifier exists. | Add only a future `predicate_proof_refs` hook with circuit id, version, public inputs, and proving system. |
| TEEs | Can attest isolated execution environments. | Reject as launch trust root unless quote verification and measurement policy exist. TEEs shift trust to hardware, firmware, vendor roots, and freshness. | If used later, add quote artifact, measurement policy, nonce freshness, vendor root, and fallback semantics. |
| Threshold signatures | Good for authority resilience and multi-party issuance. | Not privacy and not a substitute for revocation or policy. | Add signer set, threshold, membership epoch, distinct signer checks, and rotation story before claiming threshold trust. |
| Transparency logs | Useful for public audit and key or artifact publication. | Not proof unless inclusion, checkpoint, consistency, and log identity are verified. | Add explicit transparency state and inclusion proof artifact. |
| Verifiable Presentations | Useful holder-verifier presentation model. | Do not make VP the Chio root. Treat it as projection or evidence. | Add VC/VP projection manifest with challenge/domain, holder binding, credential status, and unsupported claim reporting. |
| in-toto and DSSE | Excellent supply-chain wrappers. | They do not prove runtime authority, privacy, or commerce settlement. | Use for release/tool-server provenance and label as supply-chain evidence in interop reports. |
| Key rotation | Essential. | Missing from current launch privacy story. | Add key epochs, predecessor/successor links, and verifier clock behavior. |
| Revocation | Essential. | Partially present in delegation but not pervasive enough. | Add status snapshots to disclosure, envelope, lineage, and passport verification. |
| Post-quantum hooks | Sensible for forward compatibility. | Reject any PQ security claim at launch. | Add algorithm agility and optional hybrid signature refs only. |

## Concrete Additions

### A. Add a shared cryptographic verification context

Every verifier-facing signed artifact should either embed or reference a crypto verification context.

Minimum fields:

- `context_id`
- `schema`
- `artifact_ref`
- `issuer`
- `issuer_key_ref`
- `issuer_key_state_ref`
- `key_epoch`
- `algorithm`
- `suite`
- `hash_algorithm`
- `canonicalization`
- `signature_ref`
- `verification_time`
- `status_snapshot_refs`
- `transparency_refs`
- `policy_ref`
- `verdict`

This context should be consumed by:

- `chio.transaction.verifier-report.v1`
- `chio.disclosure.capsule.v1`
- `chio.lineage.signed-subgraph.v1`
- `chio.agent-web-proof-envelope.v1`
- `chio.agent-web.interop-verifier-report.v1`
- future risk and settlement reports when they rely on signed external inputs.

### B. Tighten `chio.disclosure.verifier-privacy-profile.v1`

Add fields:

- `allowed_proof_mechanisms`
- `required_holder_binding`
- `allowed_issuer_keys`
- `required_key_epoch_min`
- `forbidden_key_epochs`
- `required_status_freshness_seconds`
- `required_audience`
- `nonce_policy`
- `allowed_algorithms`
- `forbidden_algorithms`
- `required_transparency_state`
- `max_presentation_age_seconds`
- `replay_policy`
- `hidden_predicate_registry`

The privacy profile must remain semantic. A BBS proof, SD-JWT presentation, or VP that cryptographically verifies should still fail if it violates these fields.

### C. Tighten `chio.bbs-projection.manifest.v2`

Add fields:

- `manifest_digest`
- `message_slot_count`
- `domain_separation_label`
- `ciphersuite`
- `generator_method`
- `issuer_key_policy_ref`
- `nonce_policy`
- `slot.index`
- `slot.name`
- `slot.type`
- `slot.sensitivity_class`
- `slot.disclosure_eligibility`
- `slot.hidden_predicate_eligibility`
- `slot.redaction_reason_required`
- `slot.commitment_only`

Verifier rule: hidden predicates over commitment-only slots fail unless the manifest explicitly declares a typed predicate input.

### D. Tighten `chio.disclosure.capsule.v1`

Add fields:

- `proof_mechanism`
- `proof_context`
- `audience`
- `nonce`
- `challenge`
- `holder_binding_ref`
- `issuer_key_state_ref`
- `status_refs`
- `transparency_refs`
- `presentation_created_at`
- `presentation_expires_at`
- `disclosure_vector_digest`
- `undisclosed_commitment_refs`
- `profile_evaluation_report_ref`

The verifier should emit separate results for:

- cryptographic proof verification;
- key and revocation verification;
- audience and nonce verification;
- privacy-profile evaluation;
- lineage binding;
- leakage-ledger coverage.

### E. Tighten `chio.agent-web-proof-envelope.v1`

Add fields:

- `external_canonicalization`
- `external_digest_algorithm`
- `external_signature_algorithm`
- `external_signature_verification_result`
- `external_key_state_ref`
- `external_status_ref`
- `projection_context`
- `native_external_claims`
- `chio_sidecar_claims`
- `digest_bound_claims`
- `advisory_claims`
- `unsupported_claims`
- `copy_limitations`

The current plan already has `limitations`; this needs to become typed enough that public copy can be linted from it.

### F. Add copy guardrails for crypto claims

Reject these phrases unless specific verifier coverage exists:

- "zero knowledge"
- "ZK privacy"
- "TEE-secured"
- "hardware-backed trust"
- "threshold-secured"
- "post-quantum"
- "quantum-safe"
- "VC compatible"
- "wallet compatible"
- "BBS privacy"
- "SD-JWT VC support"
- "Rekor verified"
- "transparency verified"

Allowed bounded phrases:

- "BBS-backed disclosure over Chio receipt projections under a Chio privacy profile."
- "SD-JWT disclosure where the RFC 9901 presentation path is implemented and verified."
- "VC or VP projection where a version-pinned profile is implemented."
- "DSSE or in-toto supply-chain evidence bound into the Transaction Passport."
- "Algorithm-agile signature verification with policy-enforced suites."

## Rejected Shiny Objects

### Whole-passport ZK

Reject for launch. A ZK proof over an entire Transaction Passport sounds impressive and will burn engineering time on circuit design, witness generation, public input selection, recursion, and verifier UX before the ordinary signed evidence graph is stable.

Acceptable later slice: one narrow hidden predicate such as amount below cap, region membership, or age over threshold, with a named circuit id, version, proving system, public input digest, and negative fixture.

### TEE as authority

Reject for launch. TEE evidence can say something about code identity under a vendor trust model. It does not prove Chio capability authority, privacy-profile compliance, or commerce settlement. It also adds quote freshness, measurement drift, firmware trust, side-channel, and vendor-root complexity.

Acceptable later slice: TEE quote as advisory execution-environment evidence in an Agent Web envelope, never as the root authority.

### Threshold signatures everywhere

Reject for first slice. Threshold issuance may help capability authority or governance, but it requires membership epochs, threshold verification, signer distinctness, distributed key generation assumptions, recovery, rotation, and compromise handling. It does not solve selective disclosure.

Acceptable later slice: threshold signature for a trust-root or governance approval artifact only, with one threshold-failure fixture.

### Generic VC wallet interop

Reject for launch. A Chio Transaction Passport is richer than a typical credential presentation and includes receipts, policy decisions, lineage, settlement, risk, and external projections. Calling that generic VC interoperability without an implemented profile is misleading.

Acceptable later slice: one VC 2.0 or VP projection over selected passport claims, version-pinned and challenge-bound.

### Post-quantum launch claim

Reject for launch. Hooks are cheap and prudent; claims require implementation. Use algorithm agility now. Do not say "post-quantum" in public copy.

### DSSE as proof layer

Reject as positioning. DSSE is a signing envelope. It can wrap statements; it does not define Chio semantics, policy, revocation, privacy, or runtime authority.

## Schema And Artifact Implications

The current canonical registry needs at least one of these approaches:

1. Add a new Trust/Crypto domain with key-state, revocation-snapshot, transparency-inclusion, and verification-context artifacts.
2. Embed equivalent fields into every v1 launch artifact before schemas are frozen.

The first approach is cleaner because key lifecycle and revocation are shared by Transaction Passport, disclosure, lineage, settlement, risk, and external projection. The second approach is faster but risks inconsistent verifier behavior.

Recommended registry additions, if the project accepts a shared artifact path:

| Domain | Candidate schema ID | Role |
| --- | --- | --- |
| Trust | `chio.trust.key-state.v1` | Signed or registry-bound key validity, purpose, epoch, and rotation state. |
| Trust | `chio.trust.revocation-snapshot.v1` | Immutable snapshot of revoked keys, credentials, capabilities, or passport statuses used by a verifier. |
| Trust | `chio.crypto.verification-context.v1` | Normalized record of algorithm, suite, key state, verifier time, and signature verification result. |
| Trust | `chio.transparency.inclusion-proof.v1` | Log identity, checkpoint, inclusion, and consistency evidence for artifacts that claim public transparency. |

If adopted, each must follow the registry-before-verifier contract:

- schema file under `spec/schemas`;
- entry in `spec/schemas/registry.json`;
- `spec/schemas/MANIFEST.sha256` refresh;
- registry check coverage;
- Rust schema constant or generated binding;
- fail-closed unknown-schema test;
- positive fixture;
- negative unknown-schema fixture;
- verifier rejection before artifact body trust.

Artifact updates:

- `chio.transaction-passport.v1` should bind trust context refs for every signed sub-artifact.
- `chio.transaction.evidence-graph.v1` should include edge predicate `verified-under` or equivalent typed relation from artifact to crypto verification context.
- `chio.disclosure.capsule.v1` should bind presentation context, key state, nonce, audience, holder binding, and revocation snapshots.
- `chio.lineage.signed-subgraph.v1` should bind signing key state and redaction authority, not just graph signature.
- `chio.disclosure.leakage-ledger.v1` should account for derived facts from status, timing bucket, issuer identity, and presentation metadata, not only disclosed fields.
- `chio.agent-web-proof-envelope.v1` should separate external-native proof, Chio-sidecar proof, digest-bound reference, advisory observation, and unsupported claim.
- `chio.agent-web.interop-verifier-report.v1` should report external signature verification, Chio receipt verification, projection support, and crypto context verification separately.

## First Slice

The first slice should not be ZK, TEE, threshold signatures, generic VC wallet export, or PQ crypto. The first slice should prove that Chio rejects a cryptographically valid but semantically invalid disclosure.

Slice name: `DISC-CRYPTO-01: verifier profile beats cryptographic success`

Goal: one disclosure verifier path accepts a valid capsule and rejects a valid cryptographic proof that violates Chio privacy and context rules.

Files likely touched, based on the execution-slicing review:

- `crates/chio-selective-disclosure/src/lib.rs`
- `crates/chio-selective-disclosure/src/encoding.rs`
- `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs`
- `spec/schemas/chio-attest/v1/disclosure-privacy-profile.schema.json`
- `fixtures/chio-launch/disclosure/valid-capsule/capsule.json`
- `fixtures/chio-launch/disclosure/invalid-excess-disclosure/capsule.json`

Minimum implementation behavior:

1. Verify the BBS or placeholder disclosure proof exactly as the current crate does.
2. Evaluate `chio.disclosure.verifier-privacy-profile.v1` after crypto verification.
3. Reject a forbidden disclosed field even when the cryptographic proof verifies.
4. Reject undeclared hidden predicates.
5. Reject transaction passport mismatch.
6. Reject projection manifest digest mismatch.
7. Emit a verifier report that separates `crypto_verified: true` from `privacy_profile_verified: false`.

The key point is the report shape. The public proof must show that cryptography succeeded but Chio policy still failed. That is the launch-grade distinction.

## Negative Fixtures

### Disclosure and BBS

- `invalid-bbs-forbidden-field`: BBS proof verifies, but disclosed field is forbidden by privacy profile.
- `invalid-bbs-undeclared-predicate`: hidden predicate references a slot not declared in `chio.bbs-projection.manifest.v2`.
- `invalid-bbs-commitment-only-predicate`: predicate is evaluated over a commitment-only slot without typed predicate eligibility.
- `invalid-bbs-wrong-manifest`: proof references a projection manifest whose digest does not match the capsule.
- `invalid-bbs-wrong-audience`: presentation audience does not match verifier profile.
- `invalid-bbs-replayed-nonce`: nonce was already used under a no-replay profile.
- `invalid-bbs-revoked-issuer-key`: issuer key status snapshot marks key revoked before presentation verification.

### SD-JWT

- `invalid-sd-jwt-missing-holder-binding`: holder-bound profile requires key binding but presentation lacks it.
- `invalid-sd-jwt-wrong-audience`: JWT audience or presentation context does not match verifier.
- `invalid-sd-jwt-stale-status`: credential or issuer status snapshot is older than profile freshness.
- `invalid-sd-jwt-over-disclosure`: disclosed claim exceeds required fields or reveals forbidden field.
- `invalid-sd-jwt-vc-draft-overclaim`: artifact claims SD-JWT VC support while verifier only supports RFC 9901 SD-JWT lane.

### Verifiable Presentations

- `invalid-vp-missing-challenge`: VP verifies but lacks required challenge.
- `invalid-vp-wrong-domain`: VP domain does not match Chio verifier audience.
- `invalid-vp-unsupported-credential-status`: VP credential status method is unsupported and not reported as unsupported.
- `invalid-vp-passport-root-confusion`: VP is presented as Transaction Passport root without passport signature and evidence graph verification.

### Lineage and leakage

- `invalid-lineage-missing-parent`: signed lineage subgraph omits required parent.
- `invalid-lineage-bad-redaction-authority`: redaction reason exists but signer lacks redaction authority under profile.
- `invalid-lineage-digest-mismatch`: redacted node digest does not match graph commitment.
- `invalid-leakage-missing-derived-fact`: leakage ledger records disclosed fields but omits a derived timing, issuer, or status fact.
- `invalid-leakage-budget-exceeded`: ledger entries are complete but exceed profile leakage budget.

### Agent Web envelope

- `invalid-envelope-external-digest`: external subject digest mismatch.
- `invalid-envelope-sidecar-native-confusion`: Chio sidecar claim is presented as native external proof.
- `invalid-envelope-unsupported-claim`: projection manifest cannot support claim but report omits unsupported status.
- `invalid-envelope-external-signature-missing`: manifest requires external signature but subject has none.
- `invalid-envelope-key-status-stale`: external or Chio key status snapshot violates freshness policy.

### Transparency and supply chain

- `invalid-transparency-preview-claimed-anchored`: artifact has preview log metadata but policy requires anchored inclusion proof.
- `invalid-rekor-claim-without-inclusion`: Sigstore bundle is present but Rekor inclusion or checkpoint verification is absent while copy claims transparency verification.
- `invalid-dsse-wrong-subject`: DSSE signature verifies over a statement whose subject digest differs from the Chio artifact.
- `invalid-in-toto-predicate-overclaim`: Chio-specific predicate is described as upstream-standard in-toto predicate.
- `invalid-slsa-runtime-authority`: SLSA provenance is used to authorize runtime tool invocation.

### TEE, threshold, and post-quantum hooks

- `invalid-tee-stale-quote`: TEE quote nonce is stale or not bound to transaction.
- `invalid-tee-measurement-not-allowed`: quote verifies but measurement is not allowlisted.
- `invalid-threshold-insufficient-signers`: signature aggregate has fewer valid signers than threshold.
- `invalid-threshold-stale-membership`: signer set is from the wrong membership epoch.
- `invalid-pq-unsupported-suite`: artifact advertises PQ or hybrid suite but verifier policy does not support it.
- `invalid-pq-copy-claim`: public copy claims post-quantum security while verifier report has only classical signatures.

## Launch Copy Consequences

Crypto copy must be downstream of verifier coverage. The proof room should be able to produce a sentence like:

"This disclosure proof cryptographically verified under BBS, but failed Chio privacy profile evaluation because field `merchant_account_id` was forbidden and absent from the leakage ledger."

That sentence is valuable. It proves the system is not dazzled by its own cryptography.

The public copy can mention BBS or SD-JWT only when the report can show:

- proof mechanism;
- issuer key status;
- nonce and audience result;
- transaction binding;
- privacy profile result;
- leakage ledger result;
- lineage binding result;
- unsupported claims.

The public copy can mention in-toto, DSSE, Sigstore, SLSA, VC, or VP only when the report can show whether the evidence is native external proof, Chio-sidecar proof, digest-bound reference, advisory observation, or unsupported.

The public copy should not mention ZK, TEE, threshold, or post-quantum at launch unless those words are in a limitations section that says they are not claimed.

## Bottom Line

The launch package does not need more cryptographic ornamentation. It needs fewer ambiguous claims and stronger verifier context. The credible launch path is:

1. signed Transaction Passport root;
2. typed evidence graph;
3. disclosure capsule with BBS or SD-JWT as a mechanism;
4. privacy profile that can defeat a valid cryptographic proof;
5. signed lineage subgraph;
6. leakage ledger;
7. key, revocation, algorithm, and transparency context;
8. detached Agent Web envelope that labels external evidence honestly.

If that path works, Chio can credibly say it is a proof layer. If it skips key lifecycle, revocation, nonce/audience binding, transparency status, and semantic privacy policy, then BBS, SD-JWT, VC, ZK, TEEs, threshold signatures, and post-quantum language are just expensive vocabulary.
