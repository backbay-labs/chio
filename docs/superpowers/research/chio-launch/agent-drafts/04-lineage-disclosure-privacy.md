# Lineage Disclosure, Privacy, and Verifier Policy Architecture

Branch: `research/chio-launch-trust-network`
Scope: research and planning only
Agent: D - Lineage disclosure + privacy/verifier-policy architect
Confidence: high for current-source observations, high for gap identification, moderate for implementation phasing.

## Position

Chio has the right primitives for privacy-preserving transaction disclosure, but the shipped surfaces do not yet compose into a privacy-preserving transaction or lineage verifier product. The strongest current pieces are:

- Ed25519 receipt truth with BBS material bound into the signed receipt wrapper.
- A real BBS projection/proof crate for receipts, workflows, and steps.
- Evidence export/import with signature, scope, checkpoint, and tenant-disclosure verification.
- Session anchors, request lineage records, signed receipt-lineage statements, and a lineage DAG crate.
- Attest-buyer verifier policy support for required BBS fields.
- Passport/OID4VP verifier transaction state and governed transaction metadata.

The problem is that these pieces do not yet meet at a clean disclosure boundary. Kernel runtime receipts do not emit BBS signatures. Evidence export moves full receipts, not disclosure proofs. Federation and buyer verifier policies cannot express hidden predicates or leakage budgets. The lineage graph is not exported as a signed, redacted subgraph. The current "Transaction Passport" concept is architecturally plausible, but it is not a first-class artifact in the repository. It should be defined as a transaction-bound disclosure envelope over governed receipt truth, passport verifier transaction state, selective proofs, and a signed lineage subgraph.

## Current Assets With File References

| Area | Current asset | File references |
| --- | --- | --- |
| Selective disclosure spec | The spec defines a feature-gated real-BBS slice, a secondary BBS commitment over receipts/workflows/steps, predicate goals, proof envelope shape, verification algorithm, failure codes, and future zkVM lane. | `spec/CHIO_SELECTIVE_DISCLOSURE.md:1`, `spec/CHIO_SELECTIVE_DISCLOSURE.md:58`, `spec/CHIO_SELECTIVE_DISCLOSURE.md:109`, `spec/CHIO_SELECTIVE_DISCLOSURE.md:161`, `spec/CHIO_SELECTIVE_DISCLOSURE.md:343`, `spec/CHIO_SELECTIVE_DISCLOSURE.md:395`, `spec/CHIO_SELECTIVE_DISCLOSURE.md:474`, `spec/CHIO_SELECTIVE_DISCLOSURE.md:618` |
| BBS projection/proof implementation | `chio-selective-disclosure` defines projection versions, projection messages, proof envelopes, receipt/workflow/step projection, BBS signing, proof derivation, and proof verification. | `crates/chio-selective-disclosure/src/lib.rs:26`, `crates/chio-selective-disclosure/src/lib.rs:52`, `crates/chio-selective-disclosure/src/lib.rs:190`, `crates/chio-selective-disclosure/src/lib.rs:305`, `crates/chio-selective-disclosure/src/lib.rs:409`, `crates/chio-selective-disclosure/src/lib.rs:667`, `crates/chio-selective-disclosure/src/lib.rs:807`, `crates/chio-selective-disclosure/src/lib.rs:873` |
| BBS proof tests | Tests cover receipt projection signing, receipt-bound BBS proof generation, workflow and step versions, stub/tamper rejection, wrong issuer rejection, message-count rejection, and uppercase hex rejection. | `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs:191`, `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs:229`, `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs:274`, `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs:325`, `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs:356`, `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs:385`, `crates/chio-selective-disclosure/tests/bbs_selective_disclosure.rs:420` |
| Receipt signing model | `ChioReceipt` carries `bbs_projection_version` and `bbs_signature`; the receipt id includes the BBS projection version but not BBS bytes; Ed25519 signs a `ChioReceiptSigningBody` that may include the BBS signature. | `crates/chio-core-types/src/receipt/body.rs:33`, `crates/chio-core-types/src/receipt/body.rs:104`, `crates/chio-core-types/src/receipt/body.rs:173`, `crates/chio-core-types/src/receipt/body.rs:282`, `crates/chio-core-types/src/receipt/body.rs:384`, `crates/chio-core-types/src/receipt/signing.rs:13`, `crates/chio-core-types/src/receipt/signing.rs:91`, `crates/chio-core-types/src/receipt/signing.rs:160` |
| Protocol receipt contract | The protocol documents receipt BBS fields, id binding to projection version, nonce binding, canonical verification, and multi-parent lineage receipt fields. | `spec/PROTOCOL.md:678`, `spec/PROTOCOL.md:715`, `spec/PROTOCOL.md:736`, `spec/PROTOCOL.md:791`, `spec/PROTOCOL.md:801` |
| Kernel receipt signing | Kernel receipt paths build `ChioReceiptBody`, set BBS fields to `None`, and sign through `chio_kernel_core::sign_receipt`. The async signing task also delegates to that non-BBS signing path. | `crates/chio-kernel/src/kernel/responses.rs:1549`, `crates/chio-kernel/src/kernel/responses.rs:1603`, `crates/chio-kernel-core/src/receipts.rs:28`, `crates/chio-kernel-core/src/receipts.rs:89`, `crates/chio-kernel/src/receipt_support/signing.rs:175`, `crates/chio-kernel/src/receipt_support/signing.rs:269`, `crates/chio-kernel/src/kernel/signing_task.rs:477` |
| Evidence export bundle | Kernel evidence export has query filters, tool receipts, child receipts, checkpoints, capability lineage, inclusion proofs, uncheckpointed receipts, retention metadata, and forward-compatible lineage references. | `crates/chio-kernel/src/evidence_export.rs:15`, `crates/chio-kernel/src/evidence_export.rs:53`, `crates/chio-kernel/src/evidence_export.rs:75`, `crates/chio-kernel/src/evidence_export.rs:212`, `crates/chio-kernel/src/evidence_export.rs:251`, `crates/chio-kernel/src/evidence_export.rs:433` |
| Evidence package write/verify/import | Control-plane export writes a package with receipts, child receipts, checkpoints, proof files, capability lineage, retention, optional policies, manifest, and tenant disclosure notice; verify checks scope, receipt signatures, lineage uniqueness, proofs, counts, and disclosure notice; import builds federated shares. | `crates/chio-control-plane/src/evidence_export.rs:201`, `crates/chio-control-plane/src/evidence_export.rs:237`, `crates/chio-control-plane/src/evidence_export.rs:856`, `crates/chio-control-plane/src/evidence_export.rs:886`, `crates/chio-control-plane/src/evidence_export.rs:1217`, `crates/chio-control-plane/src/evidence_export/verification.rs:35`, `crates/chio-control-plane/src/evidence_export/verification.rs:141`, `crates/chio-control-plane/src/evidence_export/verification.rs:255`, `crates/chio-control-plane/src/evidence_export/verification.rs:431`, `crates/chio-control-plane/src/evidence_export/verification.rs:642` |
| Tenant leakage notice tests | Tenant-scoped export tests deliberately exercise same-checkpoint cross-tenant metadata and require tenant-scoped disclosure notices. | `crates/chio-cli/tests/evidence_export.rs:1016`, `crates/chio-cli/tests/evidence_export.rs:1108`, `crates/chio-cli/tests/evidence_export.rs:1174`, `crates/chio-cli/tests/evidence_export.rs:1253` |
| Lineage crate | `chio-lineage` indexes signed receipts, capability lineage, and receipt-lineage statements into a DAG while preserving evidence classes. It has bounded query and frontier anchor support. | `crates/chio-lineage/README.md:1`, `crates/chio-lineage/ARCHITECTURE.md:3`, `crates/chio-lineage/src/schema.rs:8`, `crates/chio-lineage/src/schema.rs:36`, `crates/chio-lineage/src/schema.rs:119`, `crates/chio-lineage/src/query.rs:1`, `crates/chio-lineage/src/anchor.rs:1`, `crates/chio-lineage/src/anchor.rs:61` |
| Session/request/receipt lineage artifacts | The protocol defines evidence classes, versioned session anchors, request-lineage records, receipt-lineage statements, continuations, and evidence-class safety properties. Core types implement signed session anchors, request lineage records, signed receipt-lineage statements, and signed export envelopes. | `spec/PROTOCOL.md:540`, `spec/PROTOCOL.md:550`, `spec/PROTOCOL.md:559`, `spec/PROTOCOL.md:569`, `spec/PROTOCOL.md:611`, `crates/chio-core-types/src/session.rs:542`, `crates/chio-core-types/src/session.rs:563`, `crates/chio-core-types/src/session.rs:632`, `crates/chio-core-types/src/session.rs:728`, `crates/chio-core-types/src/receipt/lineage.rs:210`, `crates/chio-core-types/src/receipt/lineage.rs:316`, `crates/chio-core-types/src/receipt/lineage.rs:404` |
| Federation lineage schemas | Federation has schemas for receipt-lineage statement bundles and bilateral invocation artifacts. The wire lineage statement schema includes signature fields; the federation hash schema is hash-oriented. | `spec/schemas/chio-wire/v1/receipt/lineage_statement.schema.json:1`, `spec/schemas/chio-federation/v1/receipt-lineage-statement.schema.json:7`, `spec/schemas/chio-federation/v1/receipt-lineage-bundle.schema.json:7`, `spec/schemas/chio-federation/v1/bilateral-invocation.schema.json:7` |
| Federation verifier trust bundle | The verifier trust bundle schema already includes trusted BBS issuers and a `disclosurePolicy` object with projection version, ciphersuite, message count, and required disclosed indices/fields. | `spec/schemas/chio-federation/v1/verifier-trust-bundle.schema.json:7`, `spec/schemas/chio-federation/v1/verifier-trust-bundle.schema.json:95`, `spec/schemas/chio-federation/v1/verifier-trust-bundle.schema.json:308` |
| Federation verifier implementation | Bilateral verifier config has peer pins, receipt store, lease registry, governance receipt store, revocation oracle, pinned epoch, and action classes; cosign verification checks DSSE, peer pinning, signature, receipt resolution, and canonical digest. | `crates/chio-federation/src/bilateral_verifier/config.rs:31`, `crates/chio-federation/src/bilateral_verifier/cosign.rs:12`, `crates/chio-federation/src/bilateral_verifier/cosign.rs:111`, `crates/chio-federation/src/artifacts.rs:5` |
| Attest buyer disclosure policy | Buyer verifier policy can require disclosed BBS fields and verify a receipt-bound selective disclosure proof against trusted BBS issuers and revocation state. | `crates/chio-attest-buyer-core/src/disclosure.rs:16`, `crates/chio-attest-buyer-core/src/disclosure.rs:106`, `crates/chio-attest-buyer-core/src/disclosure.rs:178`, `crates/chio-attest-buyer-core/src/trust_bundle.rs:102`, `crates/chio-attest-buyer-core/src/report.rs:286`, `crates/chio-attest-loopback/src/lib.rs:335`, `crates/chio-attest-loopback/src/lib.rs:489` |
| Passport verifier policy | Passport verifier policy can require issuer allowlists, minimum scores, receipt/lineage thresholds, checkpoint coverage, lifecycle state, and max attestation age. OID4VP request flows maintain a durable verifier transaction state. | `docs/reference/AGENT_PASSPORT_GUIDE.md:330`, `docs/reference/AGENT_PASSPORT_GUIDE.md:516`, `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:75`, `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md:264`, `examples/policies/passport-verifier.yaml:1`, `spec/PROTOCOL.md:2638`, `spec/PROTOCOL.md:2678`, `crates/chio-control-plane/src/passport_verifier.rs:979`, `crates/chio-control-plane/src/passport_verifier.rs:1102` |
| Governed transaction metadata | Governed intent, approval token, runtime assurance, call-chain continuation, and governed receipt metadata bind transaction intent, approval, budget, seller, runtime assurance, and provenance into receipt truth. | `spec/PROTOCOL.md:496`, `spec/PROTOCOL.md:862`, `spec/PROTOCOL.md:1358`, `crates/chio-core-types/src/capability/governance.rs:247`, `crates/chio-core-types/src/capability/governance.rs:642`, `crates/chio-core-types/src/capability/governance.rs:743`, `crates/chio-core-types/src/receipt/governance.rs:100` |

## Exact Gaps

1. Projection v1 is not a safe foundation for launch privacy claims. The spec says BBS is a secondary commitment over receipt/workflow/step fields, but the implementation and spec already diverge. The workflow implementation projects a wholesale `steps` hash while the spec says workflow-level steps are not projected. The step implementation includes `workflow_id` and has a different field order than the spec table. Confidence: high. References: `spec/CHIO_SELECTIVE_DISCLOSURE.md:251`, `spec/CHIO_SELECTIVE_DISCLOSURE.md:273`, `crates/chio-selective-disclosure/src/lib.rs:305`, `crates/chio-selective-disclosure/src/lib.rs:388`, `crates/chio-selective-disclosure/src/lib.rs:409`.

2. Receipt projection v1 misses the fields that matter most for transaction disclosure. Current receipt projection covers core receipt fields like action, capability id, content hash, decision, evidence, id, kernel key, metadata hash, policy hash, tenant id, timestamp, tool name, tool server, and trust level. It does not expose typed governed-transaction slots, evidence-class slots, request lineage slots, receipt-lineage statement ids, runtime assurance summaries, economic authorization summaries, or receipt kind/boundary/actor-chain details. Confidence: high. References: `spec/CHIO_SELECTIVE_DISCLOSURE.md:161`, `crates/chio-selective-disclosure/src/lib.rs:190`, `spec/PROTOCOL.md:876`, `crates/chio-core-types/src/receipt/governance.rs:100`.

3. Kernel runtime does not emit BBS receipts. The core receipt type supports BBS binding, and the selective-disclosure crate can sign BBS projections, but the normal kernel paths set `bbs_projection_version` and `bbs_signature` to `None`. Confidence: high. References: `crates/chio-core-types/src/receipt/body.rs:282`, `crates/chio-selective-disclosure/src/lib.rs:746`, `crates/chio-kernel/src/kernel/responses.rs:1603`, `crates/chio-kernel/src/receipt_support/signing.rs:269`, `crates/chio-kernel-core/src/receipts.rs:89`.

4. Proof verification has no hidden predicate semantics. The spec describes `eq`, `cmp`, and `member` predicates, but the current proof struct and verifier are disclosed-message oriented. It verifies schema, version, ciphersuite, issuer key, message counts, indices, and BBS proof bytes; it does not evaluate hidden predicates over undisclosed values. Confidence: high. References: `spec/CHIO_SELECTIVE_DISCLOSURE.md:343`, `crates/chio-selective-disclosure/src/lib.rs:52`, `crates/chio-selective-disclosure/src/lib.rs:873`.

5. Evidence export is an audit package, not a privacy disclosure package. It writes full receipts and capability-lineage snapshots. Tenant-scoped exports have a disclosure notice for checkpoint metadata leakage, but there is no BBS proof file, redacted receipt commitment file, signed lineage subgraph, hidden predicate result, or leakage ledger. Confidence: high. References: `crates/chio-control-plane/src/evidence_export.rs:886`, `crates/chio-control-plane/src/evidence_export.rs:201`, `crates/chio-control-plane/src/evidence_export/verification.rs:492`.

6. Exported lineage references are forward-compatible fields, not populated privacy assets. `EvidenceLineageReferences` has `session_anchor_id`, `request_lineage_id`, and `receipt_lineage_statement_id`, but the export package is still receipt and checkpoint oriented. The verifier's lineage check only detects duplicate capability snapshots; it does not verify a signed, disclosure-scoped lineage DAG. Confidence: high. References: `crates/chio-kernel/src/evidence_export.rs:53`, `crates/chio-control-plane/src/evidence_export/verification.rs:255`.

7. The lineage crate is not wired into the evidence export/import verifier path. `chio-lineage` can represent evidence-classed DAG nodes and edges and compute anchored frontiers, but evidence export/import does not emit or verify that graph as a signed artifact. Confidence: high. References: `crates/chio-lineage/src/schema.rs:36`, `crates/chio-lineage/src/query.rs:78`, `crates/chio-lineage/src/anchor.rs:73`, `crates/chio-control-plane/src/evidence_export.rs:886`.

8. Federation schemas recognize BBS issuers and required disclosed fields, but not privacy profiles. `disclosurePolicy` lacks profile ids, forbidden disclosed fields, hidden predicates, maximum leakage budgets, lineage-depth requirements, evidence-class floors, redaction maps, or transaction binding. Confidence: high. References: `spec/schemas/chio-federation/v1/verifier-trust-bundle.schema.json:308`, `crates/chio-attest-buyer-core/src/disclosure.rs:16`.

9. Attest-buyer disclosure verification cannot express no-leakage contracts. It can require indices and field names, but cannot reject excess disclosure, cannot compute leakage classes, cannot require hidden predicates, and cannot bind a disclosure proof to a signed lineage subgraph. Confidence: high. References: `crates/chio-attest-buyer-core/src/disclosure.rs:16`, `crates/chio-attest-buyer-core/src/disclosure.rs:178`, `crates/chio-attest-buyer-core/src/report.rs:286`.

10. Federation lineage schemas are split between signed wire statements and hash-only federation statements. The wire schema includes signer/signature, while the federation statement schema is hash-oriented. A privacy package needs one signed lineage subgraph export that carries verifiable statement material or explicit hash-to-artifact bindings. Confidence: moderate. References: `spec/schemas/chio-wire/v1/receipt/lineage_statement.schema.json:1`, `spec/schemas/chio-federation/v1/receipt-lineage-statement.schema.json:7`.

11. Transaction Passport is not first-class in current sources. There is a draft transaction passport architecture in `01-transaction-passport-evidence-graph.md` and strong governed transaction/OID4VP transaction state primitives, but no registered `chio.transaction-passport.v1` schema or verifier. Confidence: high. References: `docs/superpowers/research/chio-launch/agent-drafts/01-transaction-passport-evidence-graph.md:44`, `spec/PROTOCOL.md:2638`, `crates/chio-control-plane/src/passport_verifier.rs:979`.

12. There is no unified leakage ledger. Tenant export notices document one known checkpoint metadata leak class, but the repository does not have a machine-readable ledger that accounts for each disclosed field, disclosed derived fact, cross-tenant metadata exposure, redaction reason, or remaining inference risk. Confidence: high. References: `crates/chio-control-plane/src/evidence_export.rs:237`, `crates/chio-cli/tests/evidence_export.rs:1174`.

## BBS Projection v2 Proposal

Projection v2 should be a versioned schema family, not an ad hoc expansion of v1.

### Projection IDs

- `chio.bbs-projection.receipt.v2`
- `chio.bbs-projection.workflow-receipt.v2`
- `chio.bbs-projection.step-record.v2`
- `chio.bbs-projection.lineage-subgraph.v1`
- `chio.bbs-proof-envelope.v2`

### Hard Rules

1. Projection tables must be generated from a checked-in projection manifest. The manifest is the source of truth for field name, path, canonical transform, message index, sensitivity class, predicate support, and whether a field may be disclosed directly.

2. Projection version changes are mandatory whenever field order, transform, hash domain, or predicate support changes.

3. Receipt v2 must preserve v1 fields but add typed transaction and lineage slots. It must not require disclosure of the wholesale `metadata` hash when a verifier only needs a transaction predicate.

4. Workflow and step projections must be reconciled with the spec before launch. The v2 tables should intentionally decide whether workflow-level `steps` is a wholesale commitment. If yes, it must be documented as a commitment-only slot and marked ineligible for nested hidden predicates.

5. Every proof envelope must carry `policyProfileId`, `audience`, `challengeNonce`, `subjectArtifactHash`, `projectionManifestHash`, `issuerKeyId`, `issuedAt`, `expiresAt`, `disclosedMessages`, `hiddenPredicates`, and `leakageLedgerHash`.

### Receipt v2 Message Classes

Receipt v2 should separate messages into classes so verifier policies can reason about leakage:

| Class | Example messages | Disclosure default |
| --- | --- | --- |
| Core receipt identity | `id`, `timestamp`, `kernel_key`, `tool_server`, `tool_name`, `tenant_id_hash`, `capability_id_hash` | Hash or disclose by profile |
| Decision proof | `decision`, `policy_hash`, `trust_level`, `action_hash`, `content_hash` | Selective disclose |
| Bounded metadata | `receipt_kind`, `boundary_class`, `observation_outcome`, `redaction_mode`, `tool_origin`, `actor_chain_hash` | Selective disclose or hidden predicate |
| Governed transaction | `intent_id_hash`, `intent_hash`, `purpose_hash`, `server_id_hash`, `tool_name_hash`, `max_amount_units`, `max_amount_currency`, `seller_hash`, `approval_token_id_hash`, `approval_approved`, `runtime_assurance_tier`, `runtime_assurance_evidence_hash`, `economic_mode`, `rail_hash`, `settlement_mode` | Mostly hidden predicates |
| Lineage | `session_anchor_id_hash`, `request_lineage_id_hash`, `receipt_lineage_statement_id_hash`, `parent_receipt_id_hash`, `call_chain_evidence_class`, `continuation_token_id_hash` | Hash plus policy-gated disclose |
| Checkpoint | `checkpoint_root_hash`, `inclusion_proof_hash`, `retention_class` | Hash disclose |

### Workflow v2

Workflow receipt v2 should include workflow-level identity and aggregate commitments, but not leak every step by default:

- `workflow_id`
- `tenant_id_hash`
- `started_at`
- `completed_at`
- `step_count`
- `root_receipt_id_hash`
- `leaf_receipt_id_hash`
- `workflow_receipt_hash`
- `step_multiset_commitment`
- `policy_profile_hash`
- `lineage_subgraph_hash`

### Step v2

Step v2 should expose the minimum needed for buyer and verifier proofs:

- `workflow_id_hash`
- `step_index`
- `server_id_hash`
- `tool_name_hash`
- `allowed`
- `tool_receipt_id_hash`
- `outcome`
- `duration_ms_bucket`
- `cost_units`
- `cost_currency`
- `output_hash`
- `lineage_edge_id_hash`

The old `duration_ms` direct field should remain v1-only unless a policy explicitly allows exact timing disclosure. v2 should prefer a bucketed or predicate-only field for timing.

## Kernel BBS Runtime Mode

Kernel support must be a runtime mode with fail-closed semantics.

### Modes

| Mode | Behavior |
| --- | --- |
| `bbs_off` | Current behavior. No BBS projection/signature is emitted. |
| `bbs_audit_dual_sign` | Emit Ed25519 receipts with bound BBS material when a BBS key is configured. If BBS signing fails, deny only when policy says BBS is required. |
| `bbs_required_for_governed` | Governed transaction receipts must include BBS projection v2 and a valid bound BBS signature. Non-governed receipts may remain Ed25519-only. |
| `bbs_required_for_cross_boundary` | Cross-kernel, federation, buyer, and export-eligible receipts must include BBS projection v2. |
| `bbs_required_all` | Every kernel receipt must include BBS projection v2. |

### Signing Sequence

1. Build `ChioReceiptBody` with the selected `bbs_projection_version`.
2. Prepare the receipt body so nonce and receipt id are stable.
3. Project the final receipt body through the projection manifest.
4. Sign the projection with the kernel BBS key.
5. Attach `BbsReceiptSignature`.
6. Sign the `ChioReceiptSigningBody` with the kernel Ed25519 or configured signing backend.
7. Verify locally before returning the receipt when a required-BBS mode is enabled.

This uses the shape already supported by `ChioReceipt::sign_prepared_with_bbs` and `validate_bbs_receipt_binding`, but moves it into the kernel runtime path instead of leaving it as a library-only affordance. References: `crates/chio-core-types/src/receipt/body.rs:329`, `crates/chio-core-types/src/receipt/signing.rs:160`, `crates/chio-selective-disclosure/src/lib.rs:746`.

### Key Management

- BBS keys are separate from kernel Ed25519 keys.
- BBS public keys need issuer ids and key ids, not only raw hex.
- Passport, verifier trust bundle, and federation policy surfaces must advertise BBS issuer key ids and revocation state.
- Rotation must preserve verification for historical receipts until retention expiry.
- A configured required-BBS mode with no BBS key is a startup failure, not a warning.

### Runtime Policy Hooks

The capability or kernel policy should be able to require BBS by:

- action class
- tenant
- tool server
- governed transaction status
- cross-boundary/federation path
- evidence export eligibility
- buyer verifier profile id

## Verifier Policy Profiles

Verifier policies should be named profiles with strict contracts. These profiles should live in both federation trust bundles and attest-buyer trust bundles, with one shared semantics module.

| Profile | Intended verifier | Required proof | Default leakage stance |
| --- | --- | --- | --- |
| `receipt_minimal_v1` | Customer or relying party checking one action | Receipt v2 proof disclosing receipt id, decision, tool class, and policy hash | No tenant, capability id, raw action, raw evidence, or metadata |
| `governed_transaction_cap_v1` | Buyer verifying spend bounds | Hidden predicate over `max_amount_units`, disclosed currency, disclosed approval result, disclosed intent hash, seller hash | No raw seller id unless policy asks |
| `lineage_continuity_v1` | Federation peer or downstream kernel | Signed lineage subgraph, evidence-class floor, receipt-lineage statement ids, parent/child receipt hashes | No unrelated siblings, no full receipts |
| `buyer_auditor_v1` | Enterprise auditor | BBS proofs plus checkpoint inclusion and signed lineage subgraph | Disclosure limited by leakage budget |
| `passport_bound_transaction_v1` | Wallet/OID4VP verifier | OID4VP transaction state, passport presentation hash, governed receipt proof, lineage subgraph hash | No agent history beyond policy thresholds |
| `admin_full_evidence_v1` | Same-tenant operator audit | Full evidence export package plus optional BBS proofs | Full disclosure allowed, but ledger still records exposure |

### Required Policy Fields

Every profile should declare:

- `profileId`
- `projectionVersions`
- `trustedBbsIssuers`
- `trustedReceiptIssuers`
- `requiredDisclosedFields`
- `forbiddenDisclosedFields`
- `requiredHiddenPredicates`
- `maxDisclosedMessageCount`
- `maxLeakageScore`
- `requiredLineageDepth`
- `evidenceClassFloor`
- `allowAssertedLineage`
- `requireCheckpointInclusion`
- `requireTenantLeakageNotice`
- `audience`
- `challengeNonce`
- `expiresAt`
- `pinnedRevocationEpoch`
- `failureMode`

The policy must reject excess disclosure by default. Excess disclosure is not harmless; it changes the privacy claim. A proof that leaks tenant id or seller id when only a seller hash was required should fail under privacy profiles even if the cryptographic proof verifies.

## Hidden Predicates

Hidden predicates should be implemented only over typed, manifest-declared fields. Do not allow arbitrary JSONPath predicates over wholesale hashes.

### Supported Predicates For v2

| Predicate | Example | Required commitment support |
| --- | --- | --- |
| `eq_hidden` | Prove `decision == allowed` without disclosing adjacent metadata | BBS message commitment plus public expected value |
| `cmp_range` | Prove `max_amount_units <= 50000` | Integer encoding, signed range bounds, unit declaration |
| `member_set` | Prove `runtime_assurance_tier in ["hardware_tcb", "tee"]` | Canonical enum index and signed allowed set |
| `hash_preimage_eq` | Prove disclosed `intent_hash` equals governed intent digest | Public digest comparison |
| `evidence_class_at_least` | Prove call-chain evidence class is at least `observed` | Ordered enum semantics in manifest |

### Rejected For v2

- OR predicates across unrelated fields.
- Regex over hidden strings.
- Nested predicates inside `metadata`, `evidence`, or `decision` wholesale hashes.
- Predicates over fields not declared in the projection manifest.
- Predicates whose unit is ambiguous, for example amount without currency.

### Predicate Result Shape

Each hidden predicate result should include:

- `predicateId`
- `kind`
- `field`
- `operator`
- `publicOperand`
- `unit`
- `result`
- `proofRef`
- `manifestFieldIndex`
- `leakageClass`

Verifier output must distinguish "predicate cryptographically proven" from "predicate not evaluable under this projection." Unknown predicate kinds fail closed.

## Signed Lineage Subgraph Export

Chio needs a privacy export artifact that is smaller than full evidence export and stronger than scattered receipt ids.

### Artifact

Schema: `chio.lineage-subgraph-export.v1`

The artifact should be wrapped in `SignedExportEnvelope<T>` so the exporter signs the exact disclosure graph. Reference: `crates/chio-core-types/src/receipt/lineage.rs:404`.

### Body

The body should contain:

- `schema`
- `subgraphId`
- `policyProfileId`
- `query`
- `generatedAt`
- `audience`
- `challengeNonce`
- `seedReceiptRefs`
- `nodeCount`
- `edgeCount`
- `truncated`
- `frontierHash`
- `lineageAnchorRef`
- `redactionMapHash`
- `leakageLedgerHash`
- `projectionManifestHash`
- `nodes`
- `edges`
- `proofRefs`

### Node Shape

Each node should include:

- `nodeId`
- `kind`
- `artifactHash`
- `schema`
- `evidenceClass`
- `tenantHash`
- `sourceTable`
- `sourceIdHash`
- `disclosureState`

Valid node kinds should include:

- `receipt`
- `capability_snapshot`
- `session_anchor`
- `request_lineage_record`
- `receipt_lineage_statement`
- `continuation_token`
- `checkpoint`
- `bbs_projection`
- `bbs_proof`
- `passport_presentation`
- `governed_intent`
- `approval_token`
- `runtime_assurance`

### Edge Shape

Each edge should include:

- `edgeId`
- `from`
- `to`
- `kind`
- `evidenceClass`
- `sourceArtifactHash`
- `statementHash`
- `disclosureState`

Valid edge kinds should include:

- `parent_of`
- `issued_under`
- `observed_in_session`
- `continued_by`
- `signed_lineage_statement`
- `included_in_checkpoint`
- `proves_projection`
- `governs_transaction`
- `approves_intent`
- `presented_by`

### Package Files

Privacy export should write:

- `lineage-subgraph.json`
- `lineage-subgraph.sig.json`
- `disclosure-proofs.ndjson`
- `predicate-results.ndjson`
- `lineage-proof-refs.ndjson`
- `redaction-map.json`
- `leakage-ledger.json`
- `manifest.json`

Full evidence export can remain for admin/audit. Privacy export must not write `receipts.ndjson` unless the selected profile is `admin_full_evidence_v1`.

### Verification Rules

1. Verify the exporter's signature over the subgraph body.
2. Verify the frontier hash from nodes and edges.
3. Verify every edge source artifact or declared redaction.
4. Verify session anchors, request lineage records, receipt-lineage statements, and continuation tokens when referenced.
5. Verify BBS proofs against trusted issuer keys.
6. Verify hidden predicate results.
7. Verify checkpoint inclusion where the profile requires it.
8. Verify no node or edge outside the policy query is included.
9. Verify the leakage ledger hash matches the package.
10. Reject asserted lineage when the profile requires observed or verified lineage.

## Leakage Ledger

The leakage ledger is a machine-readable accounting artifact. It should be mandatory for every privacy export, even when the ledger is empty.

### Ledger Shape

Schema: `chio.disclosure-leakage-ledger.v1`

Fields:

- `ledgerId`
- `policyProfileId`
- `subjectArtifactHash`
- `generatedAt`
- `audience`
- `entries`
- `totalLeakageScore`
- `maxAllowedLeakageScore`
- `tenantLeakageNoticeRef`
- `accepted`

Each entry should include:

- `entryId`
- `source`
- `field`
- `disclosureKind`
- `sensitivityClass`
- `valueClass`
- `reason`
- `policyRule`
- `derivedInferences`
- `crossTenantRisk`
- `mitigation`
- `score`

### Sensitivity Classes

- `public_commitment`
- `receipt_identity`
- `tenant_identifier`
- `agent_subject`
- `capability_identifier`
- `tool_identity`
- `commerce_counterparty`
- `amount_or_budget`
- `runtime_assurance`
- `lineage_topology`
- `timing`
- `content_or_action`
- `cross_tenant_checkpoint_metadata`

### Ledger Examples

1. Disclosed field: `decision = allowed`
   - Sensitivity: `receipt_identity`
   - Reason: required by `receipt_minimal_v1`
   - Score: 1

2. Hidden predicate: `max_amount_units <= 50000`
   - Sensitivity: `amount_or_budget`
   - Reason: required by `governed_transaction_cap_v1`
   - Score: 2
   - Derived inference: transaction amount cap is at or below public threshold

3. Disclosed field: `seller_hash`
   - Sensitivity: `commerce_counterparty`
   - Reason: seller allowlist check
   - Score: 2
   - Mitigation: hash only, no raw seller id

4. Checkpoint proof: same checkpoint includes omitted tenant receipts
   - Sensitivity: `cross_tenant_checkpoint_metadata`
   - Reason: checkpoint inclusion proof
   - Score: 3
   - Mitigation: attach tenant disclosure notice and avoid cross-tenant receipt bodies

## Integration With Transaction Passport

The repository does not currently have a registered `chio.transaction-passport.v1` artifact. The closest existing assets are governed transaction receipt metadata, OID4VP passport verifier transactions, and the Agent A draft describing a transaction passport/evidence graph root. The integration should bind those assets instead of inventing a second source of transaction truth.

### Proposed Artifact

Schema: `chio.transaction-passport.v1`

The transaction passport body should contain:

- `transactionPassportId`
- `transactionId`
- `oid4vpExchangeId`
- `oid4vpRequestId`
- `oid4vpRequestHash`
- `passportPresentationHash`
- `governedIntentIdHash`
- `governedIntentHash`
- `approvalTokenIdHash`
- `receiptId`
- `receiptHash`
- `receiptBbsProjectionVersion`
- `lineageSubgraphHash`
- `leakageLedgerHash`
- `verifierPolicyProfileId`
- `predicateResultHashes`
- `checkpointProofRefs`
- `lifecycleState`
- `issuedAt`
- `expiresAt`
- `issuer`
- `signature`

### Binding Rules

1. `oid4vpExchangeId` must equal or be explicitly mapped to the verifier transaction request id. Current protocol aligns exchange id to OID4VP request id. References: `spec/PROTOCOL.md:2638`, `spec/PROTOCOL.md:2662`.

2. `passportPresentationHash` must bind the agent or holder identity evidence used by the verifier. It must not imply full passport-history disclosure.

3. `governedIntentHash` must match the signed governed intent hash in receipt metadata and approval token binding. References: `spec/PROTOCOL.md:533`, `crates/chio-core-types/src/capability/governance.rs:677`, `crates/chio-core-types/src/capability/governance.rs:743`.

4. `receiptHash` must hash the Ed25519-signed receipt. The BBS proof is a selective disclosure of that receipt truth, not a replacement for it.

5. `lineageSubgraphHash` must bind the signed lineage subgraph export. A transaction passport without a lineage subgraph can prove a local receipt fact but cannot claim transaction lineage continuity.

6. `leakageLedgerHash` must bind the privacy accounting used for the transaction presentation.

7. `verifierPolicyProfileId` must select the exact disclosure contract. Reusing the same transaction passport under a different profile requires a new presentation or re-verification result.

### Non-Goals

- Do not merge Agent Passport history, transaction receipt truth, and OID4VP request state into one mutable object.
- Do not treat passport verifier transaction state as a receipt.
- Do not treat BBS proof success as transaction settlement proof.
- Do not upgrade asserted call-chain fields to verified lineage without signed lineage evidence.

## Negative Tests And No-Leakage Gates

These tests should be added before any launch claim that Chio supports private transaction lineage disclosure.

1. Projection drift gate. A generated manifest test must fail if spec projection tables and implementation projection order diverge for receipt, workflow, or step projections.

2. Kernel required-BBS gate. In `bbs_required_for_governed`, a governed receipt with no BBS key or failed BBS signing must be denied before a receipt is returned.

3. Receipt binding tamper gate. A receipt whose Ed25519 body carries one BBS signature but whose projection reconstructs different messages must fail verification.

4. Excess disclosure gate. A proof that reveals tenant id, capability id, raw seller id, exact duration, raw action, or wholesale metadata when not allowed by the policy must fail even if the BBS proof verifies.

5. Hidden predicate tamper gate. Changing public range bounds, membership sets, units, or predicate ids must fail.

6. Unknown predicate gate. Unknown hidden predicate kinds and predicates over non-manifest fields must fail closed.

7. Whole-hash nested predicate gate. A profile attempting a hidden predicate inside `metadata`, `decision`, or `evidence` wholesale hashes must fail under v2.

8. Signed subgraph closure gate. A lineage subgraph with extra sibling receipts, missing parent edges, duplicate nodes, unsupported edge kinds, or unreferenced proof files must fail.

9. Evidence-class downgrade gate. A verifier profile requiring `verified` lineage must reject `asserted` and `observed` lineage even when receipt ids match.

10. Tenant leakage gate. Tenant-scoped privacy exports must not write cross-tenant receipt bodies, capability snapshots, raw tenant ids, or child receipts outside the query. If checkpoint metadata implies omitted tenants, the leakage ledger and tenant disclosure notice must record it.

11. Transaction binding gate. Transaction Passport verification must reject mismatched OID4VP request id, request hash, governed intent hash, approval token id, receipt hash, or lineage subgraph hash.

12. Replay gate. A proof nonce, OID4VP request id, or verifier challenge reused outside its validity window must fail.

13. Wrong issuer gate. BBS proofs signed by an issuer absent from the trust bundle or revoked at the pinned epoch must fail.

14. Full-evidence contamination gate. Privacy export profiles must fail if `receipts.ndjson` or full capability-lineage files are present outside `admin_full_evidence_v1`.

15. Golden leakage ledger gate. Golden fixtures must diff the leakage ledger exactly so new fields cannot silently appear in privacy presentations.

## Phased Plan

### Phase 0 - Freeze And Reconcile Current Projection Truth

- Create a projection manifest for v1 as implemented.
- Update the spec or implementation so receipt, workflow, and step v1 tables match exactly.
- Add generated tests that compare manifest, spec examples, and implementation output.
- Mark v1 as "core receipt disclosure only" and explicitly not transaction-private.

Exit gate: v1 projection drift test passes and documents every projected field.

### Phase 1 - Kernel BBS Runtime Mode

- Add BBS key configuration and issuer key id plumbing.
- Route kernel receipt signing through the BBS-aware sequence for required modes.
- Support `bbs_required_for_governed` first.
- Advertise BBS issuer keys through verifier trust bundle and passport/trust metadata.
- Add failure codes for missing BBS key, BBS projection failure, BBS signing failure, and BBS verification failure.

Exit gate: governed transaction receipts can be emitted with Ed25519 plus bound BBS projection v2 in kernel runtime tests.

### Phase 2 - BBS Projection v2 And Verifier Policy Profiles

- Define receipt/workflow/step v2 projection manifests.
- Add typed governed transaction and lineage fields.
- Add policy profiles with required, forbidden, and hidden predicate sections.
- Add excess-disclosure rejection.
- Add hidden predicate evaluation for manifest-declared integer, enum, hash, and evidence-class fields.

Exit gate: attest-buyer and federation verifier trust bundles can enforce the same privacy profile semantics.

### Phase 3 - Signed Lineage Subgraph Export

- Wire `chio-lineage` bounded graph query into evidence export as a privacy export mode.
- Emit signed subgraph, disclosure proofs, predicate results, redaction map, and leakage ledger.
- Verify session anchors, request lineage records, signed receipt-lineage statements, continuations, and checkpoint inclusion.
- Preserve evidence-class floors and never upgrade asserted lineage implicitly.

Exit gate: a verifier can validate a redacted lineage subgraph without receiving unrelated full receipts.

### Phase 4 - Transaction Passport Binding

- Register `chio.transaction-passport.v1`.
- Bind OID4VP exchange/request state, passport presentation hash, governed intent hash, receipt hash, BBS proof, lineage subgraph hash, leakage ledger hash, and verifier policy profile id.
- Keep Agent Passport history filtering separate from receipt BBS disclosure.
- Add transaction verifier report output.

Exit gate: a governed transaction can be verified through a transaction passport without full evidence export.

### Phase 5 - Launch No-Leakage Qualification

- Add negative fixture corpus for every no-leakage gate.
- Add tenant-scoped privacy export fixtures with checkpoint metadata leakage.
- Add replay, wrong issuer, revocation, stale profile, and mismatched transaction-id fixtures.
- Add one end-to-end buyer auditor flow and one passport-bound transaction flow.
- Publish a launch qualification report that separates "full audit export" from "privacy-preserving disclosure."

Exit gate: launch docs can truthfully claim selective private transaction lineage disclosure, with exact policy profiles and known leakage classes.

## Top Recommendations

1. Do not launch privacy claims on projection v1. Freeze v1 as a compatibility format, reconcile spec/implementation drift, and make projection v2 the transaction disclosure format.

2. Move BBS from library capability to kernel runtime mode. If receipts are not emitted with bound BBS signatures in real kernel paths, selective disclosure is a demo affordance, not protocol behavior.

3. Make verifier policy reject excess disclosure. A cryptographically valid proof that reveals too much is a privacy failure.

4. Export signed lineage subgraphs, not full evidence packages, for privacy presentations. Full evidence export remains valuable for admin audit, but it is the wrong primitive for buyer/verifier privacy.

5. Treat Transaction Passport as a binding envelope over existing truths: OID4VP transaction state, governed intent/receipt truth, BBS proofs, signed lineage subgraph, and leakage ledger. Do not create a new mutable truth source.
