# Transaction Passport and Evidence Graph Architecture

Branch: `research/chio-launch-trust-network`
Scope: research and planning only
Confidence: high for current-source observations, moderate for implementation sizing, low for final product naming until the homepage copy is landed in-repo.

## Contract

Treat the launch copy as binding: Chio is the proof layer and trust network for autonomous commerce. The local README already says Chio proves what agents were allowed to do, what it cost, and what happened, with a signed capability-bound receipt for every decision (`README.md:34-44`). The vision document says the winning protocol is the one that proves what happened when agents did things that mattered, and frames Chio as the authorization, attestation, proof, and evidence layer for auditable, insurable, trustworthy agent operations (`docs/start-here/VISION.md:392-399`).

That contract is stronger than the current artifact model. Chio has excellent receipts, evidence export, buyer proof packages, runtime evidence manifests, passports, and registries. It does not yet have one transaction-level passport that says, for a commercial action, exactly which identity, authorization, runtime, receipt, budget, proof, settlement, and dispute artifacts prove the transaction.

## Current Assets

| Asset | What exists | Useful references |
| --- | --- | --- |
| Receipt and evidence export bundle | `EvidenceExportBundle` packages query, tool receipts, child receipts, checkpointed inclusion proofs, capability lineage, uncheckpointed receipt summary, and retention metadata. | `crates/chio-kernel/src/evidence_export.rs:15-37`, `crates/chio-kernel/src/evidence_export.rs:212-225` |
| Explicit child receipt limitation | Export has a first-class `EvidenceChildReceiptScope`; scoped exports can omit child receipts because no capability or agent join path exists yet. | `crates/chio-kernel/src/evidence_export.rs:39-50`, `crates/chio-kernel/src/evidence_export.rs:361-383` |
| Transparency boundary | Evidence claims distinguish audit facts from preview-only transparency claims unless a trust anchor is present. | `crates/chio-kernel/src/evidence_export.rs:109-166`, `crates/chio-kernel/src/evidence_export.rs:168-209`, `crates/chio-kernel/src/evidence_export.rs:433-496` |
| Evidence package writer | `chio evidence export` writes `query.json`, `receipts.ndjson`, `child-receipts.ndjson`, `checkpoints.ndjson`, checkpoint transparency files, `capability-lineage.ndjson`, `inclusion-proofs.ndjson`, `retention.json`, optional policy, optional federation policy, and `manifest.json`. | `crates/chio-control-plane/src/evidence_export.rs:886-1039` |
| Evidence verifier | Offline verify checks manifest file hashes, query scope, receipt signatures, receipt action hashes, checkpoint signatures, lineage uniqueness, transparency claim recomputation, inclusion proofs, counts, policy attachment, federation policy attachment, and tenant disclosure notice. | `crates/chio-control-plane/src/evidence_export/verification.rs:3-32`, `crates/chio-control-plane/src/evidence_export/verification.rs:35-139`, `crates/chio-control-plane/src/evidence_export/verification.rs:141-179`, `crates/chio-control-plane/src/evidence_export/verification.rs:215-324`, `crates/chio-control-plane/src/evidence_export/verification.rs:326-396`, `crates/chio-control-plane/src/evidence_export/verification.rs:431-547`, `crates/chio-control-plane/src/evidence_export/verification.rs:642-745` |
| CLI evidence surface | CLI exposes `receipt list`, `receipt checkpoint`, `receipt explain`, `evidence export`, `evidence verify`, `evidence import`, and signed evidence federation policies. | `crates/chio-cli/src/cli/types/receipt.rs:3-124`, `crates/chio-cli/src/cli/types/receipt.rs:126-224`, `crates/chio-cli/src/cli/dispatch/receipt_evidence.rs:122-201` |
| Federation policy scope | Evidence sharing can be constrained by a signed bilateral policy with issuer, partner, signer key, query, read boundary, expiry, and `require_proofs`. | `crates/chio-control-plane/src/evidence_export.rs:119-150`, `crates/chio-control-plane/src/evidence_export.rs:588-650`, `crates/chio-control-plane/src/evidence_export.rs:769-864`, `crates/chio-control-plane/src/evidence_export.rs:1059-1129` |
| Remote evidence API | Trust-control can export and import evidence through request/response objects, not only local SQLite. | `crates/chio-control-plane/src/evidence_export.rs:141-183`, `crates/chio-control-plane/src/evidence_export.rs:1131-1215`, `crates/chio-control-plane/src/evidence_export.rs:1217-1267` |
| Buyer proof package | `ChioProofPackage` carries claims, peer ladder bindings, vendor keys, tool receipts, workflow receipt, bilateral envelopes, capability leases, lease scope bindings, governance receipts, workflow intersection, and selective disclosure proof. | `crates/chio-attest-buyer-core/src/proof_package.rs:17-50`, `spec/schemas/chio-attest/v1/proof-package.schema.json:7-67` |
| Buyer proof verifier | Verifier checks proof package schema, context window, trust bundle, workflow receipt, proof claims, hints, workflow intersection, step links, leases, governance receipts, destructive steps, trust revocation, and selective disclosure. | `crates/chio-attest-buyer-core/src/report.rs:76-118`, `crates/chio-attest-buyer-core/src/report.rs:122-163`, `crates/chio-attest-buyer-core/src/report.rs:187-327`, `crates/chio-attest-buyer-core/src/report.rs:415-638` |
| Buyer attestation packet | Packet binds buyer, capability, treaty scope, ladder intersection, cross-boundary admission report, continuation, receipt lineage statement, bilateral invocation, DSSE, workflow receipt, proof package, verifier report, budget refs, and settlement flag. | `crates/chio-runtime-core/src/types.rs:320-339`, `spec/schemas/chio-attest/v1/buyer-attestation-packet.schema.json:7-49` |
| Buyer review package | Review package binds role, path, hash, byte count and rehydrates required artifacts before verifying packet semantics, lineage closure, proof package hydration, strict DSSE, runtime reports, and existing verifier report. | `crates/chio-runtime-core/src/types.rs:363-419`, `crates/chio-runtime-core/src/buyer/review_package.rs:32-188`, `crates/chio-runtime-core/src/buyer/review_package.rs:196-290` |
| Runtime graph primitives | Runtime core has continuation, receipt lineage statement, cross-boundary admission report, bilateral invocation, buyer packet, receipt lineage bundle, step evidence, proof source records, evidence manifest, proof regeneration input, proof regeneration report, and proof parity report. | `crates/chio-runtime-core/src/types.rs:141-169`, `crates/chio-runtime-core/src/types.rs:239-318`, `crates/chio-runtime-core/src/types.rs:353-360`, `crates/chio-runtime-core/src/types.rs:481-604` |
| Runtime harness | Loopback harness runs an admission scenario, captures live receipts, builds a proof package from runtime receipts, verifies it, writes verifier trust bundle, verification context, verifier report, workflow receipt, proof package, buyer packet, proof regeneration report, runtime run report, evidence manifest, and proof regeneration input. | `crates/chio-runtime-harness/src/lib.rs:43-80`, `crates/chio-runtime-harness/src/proof_assembly.rs:79-174`, `crates/chio-runtime-harness/src/proof_assembly.rs:188-260`, `crates/chio-runtime-harness/src/proof_assembly.rs:493-554`, `crates/chio-runtime-harness/src/proof_assembly.rs:603-743` |
| Runtime evidence schema | Runtime evidence manifest is a hash-bound role/path/byte-count index for run artifacts. | `crates/chio-runtime-core/src/types.rs:529-547`, `spec/schemas/chio-runtime/v1/evidence-manifest.schema.json:7-47` |
| Agent passport | Native passport represents an agent subject, reputation credentials, Merkle roots, enterprise identity provenance, issue window, and optional trust tier. | `crates/chio-credentials/src/passport.rs:1-17` |
| Passport lifecycle and verifier policy | Passport status can be active, stale, superseded, revoked, or not found. Verifier policy can require issuer allowlist, score thresholds, receipt count, lineage records, checkpoint coverage, receipt log URLs, enterprise provenance, and active lifecycle. | `crates/chio-credentials/src/passport.rs:19-133`, `crates/chio-credentials/src/passport.rs:401-530` |
| Portable passport verifier | Kernel-core can verify a signed passport envelope with trusted authority keys and clock, but intentionally does not decode full native passport, resolve revocation, or validate issuer chains. | `crates/chio-kernel-core/src/passport_verify.rs:1-23`, `crates/chio-kernel-core/src/passport_verify.rs:44-100`, `crates/chio-kernel-core/src/passport_verify.rs:125-196` |
| Passport evidence source | Passport creation already uses evidence export internally to collect receipt count, receipt IDs, checkpoint roots, lineage record count, and uncheckpointed receipts for an agent subject. | `crates/chio-cli/src/passport.rs:576-635` |
| Tool manifests | Tool manifests are signed declarations for discovery and trust, with schema, server id, tools, server-tool allowlist, required permissions, public key, and signature wrapper. | `crates/chio-manifest/src/lib.rs:1-13`, `crates/chio-manifest/src/lib.rs:24-63`, `crates/chio-manifest/src/lib.rs:205-217` |
| Schema registry | Signed-artifact registry lists `chio.attest.*`, federation lineage artifacts, runtime artifacts, and many other signed schema IDs. | `spec/schemas/registry.json:1-72`, `spec/schemas/registry.json:104-175` |
| Claim registry and proof manifest | Claim registry lists verifiable claims for capabilities, receipts, attenuation, egress, anchors, and content-addressed receipts. Proof manifest maps claims to Lean, Kani, conformance, rust tests, or proposed evidence. | `spec/registries/claim-registry.v1.json:1-86`, `spec/registries/proof-manifest.v1.json:1-125` |
| Commerce examples | The agent-commerce example covers governed procurement. The Internet of Agents web3 example already produces passports, reputation, federation, evidence export/import, payment proof, settlement, disputes, telemetry, and review bundles. | `examples/agent-commerce-network/README.md:1-45`, `examples/internet-of-agents-web3-network/README.md:22-52`, `examples/internet-of-agents-web3-network/README.md:150-220` |
| Mercury trust network package | There is a Mercury-specific trust-network profile and package over counterparty review exchange, checkpoint witness chain, proof inquiry bundle exchange, and retained artifacts. It is not a general autonomous-commerce transaction passport. | `crates/chio-mercury-core/src/trust_network.rs:9-90`, `crates/chio-mercury-core/src/trust_network.rs:117-163` |

## Exact Gaps

1. No transaction-level root artifact. There is no `chio.transaction-passport.v1`, `chio.transaction-proof-package.v1`, or transaction verifier report in `spec/schemas/registry.json`. Existing artifacts are receipt scoped, workflow scoped, run scoped, passport scoped, or evidence-export scoped. Confidence: high.

2. No evidence graph schema. `RuntimeEvidenceManifest` is a role/path/hash list (`crates/chio-runtime-core/src/types.rs:529-547`). `ReceiptLineageBundle` covers root and leaf receipt lineage (`crates/chio-runtime-core/src/types.rs:353-360`). Neither is a typed graph over passports, capabilities, manifests, receipts, checkpoints, inclusion proofs, buyer packets, runtime evidence, settlement, approvals, disputes, and verifier reports. Confidence: high.

3. Child receipt joins are explicitly incomplete. `EvidenceChildReceiptScope::OmittedNoJoinPath` is a shipped truth model (`crates/chio-kernel/src/evidence_export.rs:39-50`), and tenant or subject/capability scoped exports can omit child receipts (`crates/chio-kernel/src/evidence_export.rs:361-383`). A transaction evidence graph must not pretend the child receipt graph is closed unless a join path exists. Confidence: high.

4. Passport is agent-history oriented, not transaction oriented. `AgentPassport` binds subject, credentials, Merkle roots, enterprise provenance, validity, and trust tier (`crates/chio-credentials/src/passport.rs:1-17`). It does not bind to a transaction id, quote id, order id, settlement id, runtime run id, evidence export manifest hash, or buyer proof package hash. Confidence: high.

5. Buyer attestation rejects settlement claims instead of verifying settlement claims. `verify_buyer_attestation_packet_with_resolved_dsse` returns `chio_buyer_packet_settlement_claimed` when `packet.settlement_claimed` is true (`crates/chio-runtime-core/src/buyer/packet.rs:51-58`). That is defensible for current scope, but it blocks the homepage contract if the transaction passport needs to prove autonomous commerce settlement state. Confidence: high.

6. Evidence export and buyer proof verification are separate verifier pipelines. `cmd_evidence_verify` verifies evidence packages (`crates/chio-control-plane/src/evidence_export.rs:1269-1305`), while `cmd_chio_attest_buyer_verify_proof` and `cmd_chio_attest_buyer_verify` verify proof and buyer review packages (`crates/chio-cli/src/cli/chio/dispatch/buyer.rs:109-180`). There is no orchestration verifier that requires all of them and reconciles their hashes into one transaction claim set. Confidence: high.

7. Claim registry has no commerce transaction claims. Current enforced claims stop at capability, receipt, attenuation, egress, anchor, and content-addressed receipt facts (`spec/registries/claim-registry.v1.json:7-86`). There is no `claim.transaction.authorized`, `claim.transaction.fulfilled`, `claim.transaction.settled`, `claim.transaction.disputed`, or `claim.transaction.graph_closed`. Confidence: high.

8. Proof manifest has no transaction proof mapping. `spec/registries/proof-manifest.v1.json:7-125` maps low-level claims to proof evidence. It does not map transaction-level claims to evidence export, buyer package verification, runtime harness reports, payment proof, settlement reconciliation, or dispute artifacts. Confidence: high.

9. No transaction verifier policy. Passport verifier policy has thresholds for history and lifecycle (`crates/chio-credentials/src/passport.rs:421-450`), and federation evidence policies constrain export scope (`crates/chio-control-plane/src/evidence_export.rs:119-150`). There is no policy that says which transaction claims must be proven, which evidence graph edge classes are required, how stale is too stale, whether settlement is required, or whether preview-only transparency is acceptable. Confidence: high.

10. Trust-network wording is overloaded. Mercury has `chio.mercury.trust_network_*` types (`crates/chio-mercury-core/src/trust_network.rs:9-10`), while agent-economy docs explicitly avoid a permissionless trust network (`docs/reference/AGENT_ECONOMY.md:1041-1056`). The launch architecture must define "trust network" as verifier-composable proof exchange, not ambient global admission or a universal reputation score. Confidence: high.

## Proposed Architecture

### Principle

Do not create a giant opaque "proof bundle." Create a transaction passport as the signed root of a typed evidence graph. Every node is a content-addressed artifact. Every edge states why that artifact matters. Every claim has a registry row and a verifier rule. The passport is only accepted when the graph is closed over the requested transaction policy.

### Core Artifacts

1. `TransactionPassport`

   Schema: `chio.transaction.passport.v1`

   Purpose: the compact, portable, verifier-facing root artifact. It should contain:

   - `passportId`: content-derived id over canonical body.
   - `transactionId`: stable business transaction id, such as service order id, quote id, settlement packet id, or payment intent id.
   - `commerceContext`: buyer id, seller/provider id, optional subcontractor ids, product or service class, currency, amount ceilings, payment rail, settlement state, dispute state.
   - `subjectRefs`: buyer passport refs, provider passport refs, runtime identity refs, workload identity refs.
   - `artifactRoots`: evidence graph hash, transaction proof package manifest hash, evidence export manifest hashes, runtime evidence manifest hashes, buyer review package hash, proof package hash, verifier report hashes.
   - `claimSet`: ordered references to claim registry ids, with accepted, rejected, or not-applicable state.
   - `verificationPolicySha256`: hash of the transaction verifier policy used.
   - `issuedAtUnixMs`, `expiresAtUnixMs`, `issuer`, `signature`.

2. `TransactionEvidenceGraph`

   Schema: `chio.transaction.evidence-graph.v1`

   Purpose: the typed DAG of evidence nodes and edges. It should contain:

   - `graphId`, `transactionId`, `generatedAtUnixMs`.
   - `nodes[]`: `{nodeId, kind, schema, role, artifactSha256, canonicalSha256?, path?, sourcePackage?, subject?, createdAt?}`.
   - `edges[]`: `{edgeId, kind, from, to, claimRef?, predicate, accepted, verifierCode?, evidenceClass}`.
   - `roots`: transaction passport body hash, package manifest hash, graph hash.
   - `closure`: expected node kinds, observed node kinds, missing edge classes, unreachable nodes, unsupported claims.

   Required node kinds for MVP:

   - `agent_passport`, `passport_lifecycle_resolution`, `passport_policy_evaluation`
   - `capability_token`, `capability_lineage_snapshot`
   - `tool_manifest`, `signed_policy`, `federation_policy`
   - `tool_receipt`, `child_receipt`, `checkpoint`, `inclusion_proof`, `evidence_export_manifest`
   - `runtime_admission_report`, `runtime_step_evidence`, `runtime_evidence_manifest`, `runtime_run_report`
   - `proof_package`, `verifier_trust_bundle`, `verification_context`, `verifier_report`
   - `buyer_attestation_packet`, `buyer_attestation_review_package`, `buyer_attestation_review_report`
   - `approval_artifact`, `payment_proof`, `settlement_reconciliation`, `dispute_record`

   Required edge kinds for MVP:

   - `contains`: package or manifest contains artifact.
   - `hashes`: artifact hash equals manifest entry.
   - `authorizes`: capability, policy, admission, or receipt authorizes an action.
   - `proves_inclusion`: inclusion proof binds receipt to checkpoint root.
   - `issued_under`: passport, policy, capability, or verifier report was issued under a trusted authority.
   - `presented_by`: passport presentation or workload identity binds to buyer/provider.
   - `derived_from`: runtime proof package derives from captured live receipts.
   - `lineage_parent_of`: parent receipt or continuation leads to child receipt.
   - `verifies`: verifier report accepts a package or graph.
   - `pays_for`: payment proof or settlement artifact pays for order, quote, or fulfillment.
   - `fulfills`: provider output or attestation fulfills the transaction.
   - `disputes`: dispute or refund artifact challenges a transaction result.

3. `TransactionProofPackage`

   Schema: `chio.transaction.proof-package.v1`

   Purpose: directory-level package manifest. It should follow the evidence export pattern, not invent new path handling. It contains file refs for:

   - `transaction-passport.json`
   - `transaction-evidence-graph.json`
   - zero or more embedded `evidence-export/` packages
   - zero or more embedded `runtime-evidence/` packages
   - zero or more embedded `buyer-review/` packages
   - zero or more passport and presentation artifacts
   - commerce artifacts such as approval, payment proof, settlement reconciliation, fulfillment, dispute, refund

   It must use safe relative paths like `RuntimeEvidenceManifest` (`spec/schemas/chio-runtime/v1/evidence-manifest.schema.json:35-44`) and evidence export (`crates/chio-control-plane/src/evidence_export.rs:866-884`).

4. `TransactionVerifierReport`

   Schema: `chio.transaction.verifier-report.v1`

   Purpose: final verifier result. It contains:

   - package, passport, graph, policy, and registry hashes.
   - `accepted`, `failureCode`, `verificationState`.
   - `claimResults[]`: each with `claimRef`, `accepted`, `required`, `evidenceNodeIds`, `edgeIds`, `verifier`.
   - `graphClosure`: missing nodes, missing edges, unsupported node kinds, unsupported claims.
   - `transparencyState`: `trust_anchored`, `transparency_preview`, or `not_present`.
   - `commerceState`: `authorized`, `fulfilled`, `settled`, `disputed`, `refunded`, `unknown`, each with evidence refs.

5. `TransactionVerifierPolicy`

   Schema: `chio.transaction.verifier-policy.v1`

   Purpose: verifier-owned policy for which claims are required. It should not be global ambient trust. It should specify:

   - accepted passport issuers and lifecycle requirements.
   - required evidence export proof coverage.
   - accepted transparency state.
   - required buyer proof package verification.
   - required runtime proof regeneration.
   - commerce required states, for example `authorized` and `fulfilled` for quote acceptance, `settled` for payment finalization, `disputed` for dispute review.
   - max staleness windows for passport, verifier context, federation policy, proof package, and evidence export.

## Schemas and Registries To Define

Add new schema files:

- `spec/schemas/chio-transaction/v1/transaction-passport.schema.json`
- `spec/schemas/chio-transaction/v1/evidence-graph.schema.json`
- `spec/schemas/chio-transaction/v1/proof-package.schema.json`
- `spec/schemas/chio-transaction/v1/verifier-report.schema.json`
- `spec/schemas/chio-transaction/v1/verifier-policy.schema.json`
- `spec/schemas/chio-transaction/v1/negative-fixture-corpus.schema.json`

Register those schemas in:

- `spec/schemas/registry.json`, alongside the existing `chio.attest.*` and `chio.federation.*` signed artifacts (`spec/schemas/registry.json:14-72`, `spec/schemas/registry.json:104-175`).

Add claim registry rows:

- `claim.transaction.graph_closed`: every required node and edge class for the selected policy is present, hash-bound, and reachable from the transaction passport.
- `claim.transaction.identity_bound`: buyer, provider, and optional subcontractor passports/presentations bind to the transaction subjects.
- `claim.transaction.authorization_bound`: every paid or destructive step is authorized by capability, policy, admission, and receipt.
- `claim.transaction.receipts_included`: required tool receipts have valid signatures, action hashes, checkpoint inclusion proofs, and no unexplained uncheckpointed receipts under the policy.
- `claim.transaction.runtime_proof_regenerated`: runtime evidence manifest, proof regeneration input, proof regeneration report, proof package, and verifier report are mutually hash-bound and accepted.
- `claim.transaction.buyer_packet_verified`: buyer attestation review package verifies packet semantics, lineage closure, strict DSSE, runtime reports, proof package, and verifier report.
- `claim.transaction.fulfillment_bound`: fulfillment artifact, provider receipt, and workflow receipt agree on transaction id and output hash.
- `claim.transaction.settlement_bound`: payment proof and settlement reconciliation agree on amount, currency, rail, order id, and receipt ids.
- `claim.transaction.dispute_bound`: dispute, refund, or remediation records bind to the same transaction and relevant receipts.

Add proof manifest rows mapping those claims to:

- existing evidence export verifier tests and functions.
- attest buyer verifier functions and fixtures.
- runtime harness proof regeneration and parity reports.
- Internet of Agents commerce example verifier.
- new negative fixtures for graph closure, stale identity, stale proof, missing settlement, forged payment proof, and cross-tenant leakage.

Add failure codes to the runtime or transaction failure-code registry:

- `transaction_passport_schema_unsupported`
- `transaction_passport_hash_mismatch`
- `transaction_graph_not_closed`
- `transaction_graph_cycle`
- `transaction_required_claim_missing`
- `transaction_artifact_hash_mismatch`
- `transaction_identity_not_bound`
- `transaction_authorization_not_bound`
- `transaction_receipt_uncheckpointed`
- `transaction_runtime_proof_rejected`
- `transaction_buyer_review_rejected`
- `transaction_settlement_unverified`
- `transaction_dispute_unbound`
- `transaction_transparency_preview_not_allowed`

## Verifier Workflow

1. Load the transaction proof package manifest.

   Validate schema, safe relative paths, unique artifact roles where required, file hashes, byte counts, and package root containment. Reuse the evidence export path rules (`crates/chio-control-plane/src/evidence_export.rs:866-884`) and buyer review role/path/hash discipline (`crates/chio-runtime-core/src/buyer/review_package.rs:62-171`).

2. Load registries and verifier policy.

   Load schema registry, claim registry, proof manifest, and transaction verifier policy. Reject unknown required claims. Reject signed artifacts whose schema is not in the signed-artifact registry, following the current registry posture (`spec/schemas/registry.json:1-6`).

3. Verify embedded evidence exports.

   For each evidence export package, run the existing offline verifier logic. Preserve its limitations exactly: if child receipts were omitted due to no join path, the graph may record an explicit gap node, but may not claim closure over child receipts (`crates/chio-kernel/src/evidence_export.rs:39-50`).

4. Verify runtime evidence packages.

   Check `RuntimeEvidenceManifest` entries, file hashes, proof regeneration report, workflow run report, and proof regeneration input. Require the proof regeneration report to be accepted when the verifier policy requires runtime proof regeneration (`crates/chio-runtime-core/src/types.rs:540-579`).

5. Verify buyer proof and buyer review packages.

   Run `verify_proof_package_json` for proof packages and `verify_buyer_attestation_review_package_with_proof_replay_json` for buyer review packages. Confirm the buyer packet hashes match graph nodes for admission, continuation, lineage, bilateral invocation, DSSE, workflow receipt, proof package, and verifier report (`crates/chio-runtime-core/src/buyer/packet.rs:92-131`).

6. Verify passports.

   For native passports, apply `PassportVerifierPolicy` and lifecycle rules. For portable passports, verify issuer, signature, and validity window with `chio-kernel-core` and then feed the authenticated payload into the native verifier when available (`crates/chio-kernel-core/src/passport_verify.rs:125-196`). The transaction policy decides whether portable-only verification is acceptable.

7. Build and check the evidence graph.

   Parse all nodes. Recompute node ids from canonical artifact hashes. Check that all manifest refs point to nodes, all edge endpoints exist, no cycles violate the DAG requirement, and every required edge kind is present for the selected claim set.

8. Evaluate transaction claims.

   For each required claim, run the deterministic predicate over the graph. Example: `claim.transaction.settlement_bound` requires a settlement artifact, a payment proof, amount/currency agreement, transaction id agreement, and a receipt edge from budget exposure or spend reconciliation.

9. Emit `TransactionVerifierReport`.

   The report is accepted only if all required claims pass, every required package verifier accepts, graph closure holds, and no unsupported claim is required by policy.

## CLI and API Surface

Add a new command group instead of overloading `receipt`, `evidence`, or `passport`:

```text
chio transaction passport build \
  --transaction-id <id> \
  --evidence-export <dir> \
  --runtime-evidence <dir> \
  --buyer-review-package <path> \
  --passport <path> \
  --commerce-artifact <role=path> \
  --verifier-policy <path> \
  --out <dir>

chio transaction passport verify \
  --input <dir> \
  --verifier-policy <path> \
  --claim-registry spec/registries/claim-registry.v1.json \
  --proof-manifest spec/registries/proof-manifest.v1.json \
  --report <path>

chio transaction graph inspect \
  --input <dir> \
  --format json|dot \
  --out <path>

chio transaction claim explain \
  --report <path> \
  --claim <claim.transaction.*> \
  --format text|json \
  --out <path>
```

Add trust-control endpoints only after the CLI verifier is deterministic:

- `POST /v1/transactions/proof-packages/build`
- `POST /v1/transactions/proof-packages/verify`
- `GET /v1/transactions/{transaction_id}/passport`
- `GET /v1/transactions/{transaction_id}/graph`
- `GET /v1/transactions/{transaction_id}/claims`

Do not allow agents to choose tenant scope, trust boundary, or accepted claim policy. Existing evidence export already documents that tenant scope must be derived from operator auth, not agent input (`crates/chio-kernel/src/evidence_export.rs:27-36`).

## Tests and Gates

Unit and schema tests:

- Schema roundtrip tests for all new `chio.transaction.*` schemas.
- Registry coverage test: every new transaction schema appears in `spec/schemas/registry.json`.
- Claim registry test: every required transaction claim has a proof manifest row.
- Failure-code registry test: every transaction verifier rejection has a registered code.
- Relative path negative tests matching runtime evidence path constraints.

Verifier tests:

- Accept a minimal transaction package with one passport, one capability, one signed allow receipt, one checkpoint inclusion proof, one evidence export manifest, and one accepted verifier report.
- Reject tampered file hash in transaction proof package.
- Reject a tool receipt whose signature is invalid even when package manifest hash is updated, mirroring current evidence verify behavior.
- Reject graph edge to missing node.
- Reject graph cycle.
- Reject duplicate node id with different artifact hash.
- Reject transaction claim that depends on child receipt closure when evidence export declares `OmittedNoJoinPath`.
- Reject stale passport lifecycle when policy requires active lifecycle.
- Reject uncheckpointed receipt when policy requires checkpoint coverage.
- Reject settlement claim until transaction settlement artifacts are defined and verified.
- Reject preview-only transparency when policy requires trust-anchored publication.
- Reject buyer review package when artifact role, path, hash, or byte count mismatch.
- Reject runtime proof regeneration report that is not accepted.

Integration gates:

- Extend `examples/internet-of-agents-web3-network/smoke.sh` to produce one transaction passport after its existing bundle is generated.
- Add a good fixture under the example app with `transaction-passport.json`, `transaction-evidence-graph.json`, and `transaction-verifier-report.json`.
- Add negative fixture corpus for missing passport, forged passport, wrong provider, missing payment proof, wrong amount, missing dispute binding, unmediated default path, and unsupported claim.
- Add a workspace script `scripts/check-chio-transaction-passport.sh` that validates schemas, registry rows, fixtures, CLI verify, and negative corpus.

Release gates:

- `scripts/check-chio-schema-registry.sh` must fail if a transaction artifact schema is not registered.
- `scripts/check-proof-report.sh` or successor must include transaction claims once proof manifest rows are added.
- `cargo test --package chio-runtime-core transaction_`
- `cargo test --package chio-control-plane transaction_`
- `cargo test --package chio-cli transaction_`
- `examples/internet-of-agents-web3-network/smoke.sh` plus transaction verifier on its generated bundle.

## Open Questions

1. Should the transaction passport be signed by the buyer, the verifier, the local kernel, or all three? Recommendation: the passport body should be verifier-signed first, with optional buyer/provider countersignatures in v2. Confidence: moderate.

2. Is settlement required for the first launch passport? Recommendation: no. MVP should support `settlementState: not_claimed` and explicitly reject `settled` unless settlement artifacts are supplied and verified. This aligns with the current buyer packet rejection for settlement claims. Confidence: high.

3. Should transaction graph edges be signed individually? Recommendation: no for MVP. Sign the graph root through the transaction passport and package manifest. Add edge-level signatures later only for cross-operator graph merge. Confidence: moderate.

4. Should the graph use JSON-LD? Recommendation: no. Chio already uses canonical JSON and deny-unknown-fields schemas. JSON-LD would add context fetch and canonicalization risk. Confidence: high.

5. Should the transaction passport import Mercury trust-network packages? Recommendation: treat Mercury packages as optional evidence nodes, not as the transaction passport model. Mercury is a specific counterparty review exchange surface, while transaction passports need a general commerce proof surface. Confidence: high.

6. How should child receipt join gaps be represented? Recommendation: represent gaps as explicit `gap` nodes with `scope: child_receipts` and `reason: omitted_no_join_path`, and make closure claims fail if policy requires those receipts. Confidence: high.

7. How public is the trust network? Recommendation: the trust network is a verifier-composable proof exchange and discovery layer, not ambient public admission, not a global mutable score, and not a permissionless runtime trust oracle. Confidence: high.

## Phased Implementation Plan

### Phase 0: Contract and inventory

- Finalize product language: "transaction passport" means a verifier-accepted proof root for one autonomous commerce transaction.
- Decide MVP commerce states: `authorized`, `fulfilled`, `settlement_not_claimed`, `disputed_not_claimed`.
- Freeze required artifact roles for MVP.
- Mark child receipt closure as explicitly non-goal until the join path exists.

Exit gate: one accepted architecture decision note and no schema/code changes yet.

### Phase 1: Schemas and registries

- Add `spec/schemas/chio-transaction/v1/*`.
- Register schemas in `spec/schemas/registry.json`.
- Add transaction claim rows to `spec/registries/claim-registry.v1.json`.
- Add proof manifest rows to `spec/registries/proof-manifest.v1.json`.
- Add negative fixture corpus schema.

Exit gate: schema registry check, proof manifest check, and fixture schema validation pass.

### Phase 2: Verifier core

- Implement pure verifier functions in a core crate, preferably `chio-runtime-core` or a new `chio-transaction-proof-core` if dependency boundaries require it.
- Reuse existing evidence export verification, buyer proof verification, and passport verification instead of duplicating semantics.
- Add graph closure, claim predicate, and report generation logic.

Exit gate: unit tests cover good package, hash tamper, graph gap, stale passport, uncheckpointed receipt, runtime proof rejection, buyer review rejection, and unsupported claim.

### Phase 3: CLI package builder and verifier

- Add `chio transaction passport build`.
- Add `chio transaction passport verify`.
- Add `chio transaction graph inspect`.
- Add `chio transaction claim explain`.
- Keep build deterministic: it should assemble existing artifacts, not invent missing claims.

Exit gate: CLI tests prove path safety, manifest hash binding, deterministic report output, and failure-code stability.

### Phase 4: Commerce example integration

- Extend Internet of Agents web3 smoke to emit transaction passport artifacts after existing review bundle verification.
- Add good and negative fixtures to the reviewer UI bundle contract.
- Update the example verifier to require transaction passport acceptance for the launch path.

Exit gate: example smoke generates a transaction passport and the verifier rejects all negative fixtures.

### Phase 5: Trust-network exchange

- Add optional discovery and exchange APIs for verifier-accepted transaction passports.
- Keep runtime admission local and explicit. Imported passports can inform policy, but cannot become ambient trust.
- Add revocation/supersession story for transaction passports if disputes or refunds later change state.

Exit gate: imported passport is visible as evidence, not as automatic runtime admission, and policy must explicitly opt into using it.

## Top Recommendations

1. Build the transaction passport as a signed root over a typed evidence graph, not as a larger evidence export bundle.

2. Make transaction claims first-class registry entries before implementing CLI commands. Otherwise "proof layer" becomes marketing copy over unregistered assertions.

3. Keep settlement out of MVP acceptance unless real settlement artifacts are verified. Current buyer packet logic already rejects settlement claims, so accepting them would be a regression.

4. Preserve evidence export's explicit child receipt gap. A transaction graph that claims complete lineage while exports say `OmittedNoJoinPath` would be false.

5. Anchor the launch demo in `examples/internet-of-agents-web3-network`, because it already exercises passports, federation, evidence export/import, payment proof, settlement, runtime degradation, disputes, telemetry, and adversarial denials.
