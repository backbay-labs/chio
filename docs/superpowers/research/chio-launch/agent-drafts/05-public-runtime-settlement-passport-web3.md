# Public Runtime Settlement Passport + Web3 Proof Architecture

Agent: E
Worktree: `research/chio-launch-trust-network`
Scope: research and planning only
Confidence: high for source inventory and architectural gaps, moderate for rollout sequencing because no live chain or CI run was executed for this draft.

## Position

Chio has the core ingredients for a credible public web3 settlement proof, but they are still scattered across separate artifact families. The public runtime settlement passport should not be a marketing wrapper over the existing IOA bundle. It needs to be a strict verifier-facing object that composes runtime proof, identity binding, anchor inclusion, deployment provenance, escrow state, bond state, dispute state, finality, oracle evidence, and public witness evidence into one canonical JSON bundle with a fail-closed verifier.

The sharp boundary is this: chain activity is not Chio truth, and Chio receipts are not external execution. The passport must prove the join. The protocol spec already states that `chio.web3-settlement-dispatch.v1` may bind a capital instruction to one escrow and bond-vault lane, but observed settlement must reconcile through explicit proof artifacts. The new bundle should be that explicit reconciliation layer.

## Current Assets

### Contract Layer

- `contracts/src/ChioIdentityRegistry.sol`
  - Registers active operators with an Ed25519 key hash, a settlement key, and opaque `bindingProof` bytes.
  - Registers Chio entity ids to settlement addresses through the active operator.
  - Gap-sensitive detail: `bindingProof` is emitted, not typed or queryable as a certificate hash.
- `contracts/src/ChioRootRegistry.sol`
  - Publishes strictly increasing checkpoint roots per operator.
  - Verifies detailed RFC6962 inclusion proofs through `verifyInclusionDetailed`.
  - Supports up to three active delegate publishers per operator.
- `contracts/src/ChioEscrow.sol`
  - Creates ERC-20 escrows from capability-bound terms.
  - Releases by detailed Merkle proof or by operator settlement-key signature.
  - Refunds after deadline.
  - The signature release digest binds `chainid`, escrow contract address, escrow id, receipt hash, and settled amount.
- `contracts/src/ChioBondVault.sol`
  - Locks collateral, releases with proof, impairs with proof, and expires after the bond deadline.
  - Preserves reserve requirement metadata in terms but only moves collateral on-chain.
- `contracts/src/ChioPriceResolver.sol`
  - Reads configured Chainlink-compatible feeds with sequencer and staleness checks.
  - It is a reference reader only; `chio-link` remains the receipt-side FX authority.
- `contracts/deployments/base-sepolia.template.json`
  - Public testnet deterministic deployment template for `eip155:84532`.
  - Still has review placeholders for feed addresses and role addresses.
- `contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md`
  - Confirms fail-closed proof entrypoints, no admin override on fund release, bounded delegate publication, and residual risks.
- `contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md`
  - Captures local-devnet gas for root publication, escrow release, bond release, and related operations.

### Web3 Type Layer

- `crates/chio-web3/src/identity.rs`
  - Defines `chio.key-binding-certificate.v1` with Chio identity, public key, chain scope, purpose list, settlement address, validity interval, nonce, and signature.
- `crates/chio-web3/src/anchors.rs`
  - Defines `chio.anchor-inclusion-proof.v1`, checkpoint statements, chain anchor records, Bitcoin OTS metadata, super-root inclusion, oracle conversion evidence validation, and proof verification.
  - Enforces receipt signature, checkpoint signature, key binding, Merkle inclusion, and chain-anchor binding.
- `crates/chio-web3/src/settlement.rs`
  - Defines `chio.web3-settlement-dispatch.v1` and `chio.web3-settlement-execution-receipt.v1`.
  - Enforces real dispatch support, explicit custody boundary, web3 rail, amount equality, lifecycle state rules, optional anchor proof, and `chio_link_runtime_v1` oracle evidence when FX-sensitive.
- `crates/chio-web3/src/trust_profile.rs`
  - Defines settlement paths, dispute policies, finality modes, regulated roles, dispute windows, and finality rules.
- `crates/chio-web3/src/chain.rs`
  - Defines chain deployments and gas profiles with strict EVM address validation.
- `crates/chio-web3/src/qualification.rs`
  - Defines the web3 qualification matrix shape.
- `docs/standards/CHIO_WEB3_PROFILE.md`
  - Freezes the official web3 surface as artifact-driven, Base-first, local-policy activated, and not permissionless.

### Anchor And Public Witness Layer

- `crates/chio-anchor/src/evm.rs`
  - Prepares EVM root publication, delegate registration, publication guards, confirmation, chain-anchor records, and on-chain inclusion verification.
- `crates/chio-anchor/src/bundle.rs`
  - Defines `chio.anchor-proof-bundle.v1` across primary EVM proof and optional Bitcoin OTS or Solana memo lanes.
- `crates/chio-anchor/src/witness.rs`
  - Defines public-witness receipt state and policy.
  - Important invariant: self-carried `Witnessed` state is not sufficient when `require_public_witness=true`; the verifier must call a witness client or use verifier-owned stale cache.
- `crates/chio-anchor/src/discovery.rs`
  - Defines `chio.anchor-discovery.v1` and proof-bundle verification against discovery, publication policy, and freshness.
- `docs/standards/CHIO_ANCHOR_PROOF_BUNDLE_EXAMPLE.json`
  - Example full anchor proof bundle with receipt, inclusion proof, checkpoint statement, chain anchor, Bitcoin OTS, super-root inclusion, and key-binding certificate.
- `docs/standards/CHIO_ANCHOR_DISCOVERY_EXAMPLE.json`
  - Example discovery record with operator binding, root publication ownership, chain endpoint, and optional secondary lanes.

### Settlement Runtime And Finality Layer

- `crates/chio-settle/src/evm/prepare.rs`
  - Prepares ERC-20 approval, escrow dispatch, Merkle release, dual-sign release, refund, and bond calls.
  - Computes the escrow id from contract truth through `deriveEscrowId`.
- `crates/chio-settle/src/evm/finalize.rs`
  - Finalizes escrow and bond identities from on-chain transaction receipts.
  - Builds failure and reversal receipts.
- `crates/chio-settle/src/observe.rs`
  - Reads escrow snapshots and bond snapshots.
  - Computes finality status: awaiting confirmations, awaiting dispute window, finalized, or reorged.
  - Projects observed chain state back into `chio.web3-settlement-execution-receipt.v1`.
- `crates/chio-kernel/src/kernel/settlement_observer.rs`
  - Settlement observation is post-dispatch and observer-only relative to signed receipt bytes.
  - The observer is intentionally unable to mutate the receipt path.
- `crates/chio-kernel/tests/settlement_observer_byte_identity.rs`
  - Enforces byte identity between receipts generated with and without the settlement observer.
- `docs/standards/CHIO_SETTLE_FINALITY_REPORT_EXAMPLE.json`
  - Example finality report with confirmations, dispute window, status, and recovery action.
- `docs/standards/CHIO_SETTLE_QUALIFICATION_MATRIX.json`
  - Names runtime-devnet Merkle release, timeout refund, dual-sign release, bond lifecycle, finality recovery, evidence substrate, and partner e2e recovery cases.

### Runtime Harness And Buyer/Auditor Proof Layer

- `crates/chio-runtime-harness/src/proof_assembly.rs`
  - Assembles runtime loopback outputs, proof packages, verifier trust bundles, verification context, verifier reports, workflow receipts, per-step receipts, DSSE envelopes, and parity reports.
- `crates/chio-runtime-harness/src/proof_parity.rs`
  - Compares runtime proof package semantics against static proof package semantics.
- `crates/chio-attest-buyer-core/src/proof_package.rs`
  - Defines `chio.attest.proof-package.v1`: claims, peer ladder bindings, vendor keys, tool receipts, workflow receipt, DSSE envelopes, leases, governance receipts, workflow intersection, and selective disclosure proof.
- `crates/chio-runtime-core/src/buyer/proof_package.rs`
  - Verifies buyer review lineage, proof package completeness, embedded workflow hash, verifier report binding, and signed receipt presence.
- `examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json`
  - Concrete buyer/auditor package fixture with signed tool receipts, workflow receipt, vendor signatures, DSSE, leases, and governance evidence.

### IOA Web3 Network And Explorer Assets

- `examples/internet-of-agents-web3-network/README.md`
  - Defines the flagship four-organization web3 scenario and artifact contract.
  - The example attaches Base Sepolia evidence when `target/web3-live-rollout/base-sepolia/base-sepolia-smoke.json` exists.
- `examples/internet-of-agents-web3-network/app/README.md`
  - Defines the offline-first Next.js evidence console and fail-closed manifest hash checks.
- `examples/internet-of-agents-web3-network/app/lib/bundle.ts`
  - Loads and verifies `bundle-manifest.json`, `summary.json`, `review-result.json`, and `chio/topology.json`.
  - Important limitation: `review-result.json` is intentionally excluded from the manifest hash because it is written after manifest sealing, so the UI treats it as advisory.
- `examples/internet-of-agents-web3-network/app/components/Explorer.tsx`
  - Renders artifact tree, JSON viewer, cross refs, and a simple Base Sepolia transaction pane.
- `examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/web3/base-sepolia-deployment.json`
  - Concrete Base Sepolia reviewed rollout fixture with contract addresses, deployment tx hashes, feed registration tx hashes, CREATE2 factory, manifest hash, approval hash, and USDC address.
- `examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/web3/base-sepolia-smoke.json`
  - Concrete Base Sepolia smoke fixture with 15 transactions, active operator registration, entity registration, root publications, USDC approval, primary escrow create, partial release, final release, refund escrow create, and timeout refund.
- `examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/contracts/web3-settlement-dispatch.json`
  - IOA settlement dispatch fixture for `eip155:84532`, Merkle proof path, USDC, escrow id, contract addresses, denied rails, and source capital instruction.
- `examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/contracts/web3-settlement-receipt.json`
  - IOA settlement receipt fixture with settlement status, observed execution tx hash, oracle price readback map, and compact anchor/release summary.
- `examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/disputes/*.json`
  - Example weak deliverable, partial payment, refund, remediation, dispute packet, dispute audit, and reputation downgrade artifacts.
- `examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/bundle-manifest.json`
  - Hash manifest for the IOA bundle.

### Qualification Gates

- `scripts/qualify-web3-local.sh`
  - Runs runtime, promotion, and example qualification.
- `scripts/qualify-web3-runtime.sh`
  - Runs web3 evidence tests, contract parity, anchor tests, settle tests, runtime devnet, e2e, ops controls, standards JSON validation, and `git diff --check`.
- `scripts/qualify-web3-e2e.sh`
  - Generates partner qualification with FX dual-sign settlement, timeout refund, reorg recovery, bond impairment, and bond expiry scenarios.
- `scripts/qualify-web3-promotion.sh`
  - Compiles contracts, qualifies review prep, and qualifies promotion.
- `scripts/check-chio-runtime-proof-parity.sh`
  - Validates runtime proof regeneration, schema, fixture, and parity flows.
- `scripts/check-chio-proof-package.sh`
  - Validates proof package, selective disclosure proof, trust bundle, context, report, negative cases, and schema registry coverage.

## Exact Gaps

1. There is no single public settlement passport schema. Current artifacts prove pieces: runtime proof package, web3 dispatch, execution receipt, anchor proof bundle, finality report, deployment report, IOA manifest, and dispute packet. No artifact binds them into one verifier contract.

2. The IOA fixture receipt is not the typed `AnchorInclusionProof` expected by `chio-web3`. `contracts/web3-settlement-receipt.json` carries a compact `reconciled_anchor_proof` with a chain id, contract address, tx hash, escrow release tx hashes, and refund tx hash. It omits the full receipt, inclusion proof, checkpoint statement, block hash, block number, anchored root, anchored checkpoint sequence, operator address, and key-binding certificate required by `AnchorInclusionProof`.

3. The IOA fixture `oracle_evidence` is a price readback map, not `chio.oracle-conversion-evidence.v1`. `crates/chio-web3/src/settlement.rs` expects `OracleConversionEvidence` when the dispatch marks FX evidence as required. The public passport must carry both raw feed readbacks and the typed conversion envelope, with the typed envelope as the verifier input.

4. Identity binding is split between an off-chain certificate and opaque on-chain `bindingProof` bytes. `ChioIdentityRegistry` stores operator key hash and settlement key, but the registry read API does not expose a typed certificate hash, DID document hash, expiry, purpose, or chain scope. Public verifiers can compare the off-chain certificate to registry fields, but cannot query a first-class on-chain certificate commitment.

5. Beneficiary identity is ambiguous in the IOA dispatch fixture. The dispatch field `beneficiary_address` is a 64-hex Chio-like subject value, while the EVM escrow call path requires a 20-byte EVM beneficiary address. The passport needs separate `beneficiary_chio_identity`, `beneficiary_settlement_address`, and `beneficiary_binding_proof` fields.

6. Dispute artifacts are not attached to on-chain settlement state. The example dispute packet proves a resolved narrative, partial payment, refund, and audit digest, but it is not typed as a web3 dispute lifecycle and is not bound to escrow events, bond impairment events, finality windows, or receipt inclusion proofs.

7. Bond posture is not first-class in the IOA public proof. `ChioBondVault` and `chio-settle` support lock, release, impairment, expiry, and observation. The IOA dispatch fixture has a bond vault contract address but no bond id, vault id, bond snapshot, reserve requirement terms, impairment proof, or expiry proof.

8. Finality is available but not passport-bound. `SettlementFinalityAssessment` and `CHIO_SETTLE_FINALITY_REPORT_EXAMPLE.json` exist, but the IOA bundle does not bind finality status, current confirmations, dispute window close, recovery action, and reorg readback to the settlement receipt.

9. Public witness policy is mature for anchor batches, but settlement passports do not consume it. The proof bundle should use the same fail-closed principle: a producer-supplied witnessed state is not enough; verifier-owned public-witness verification or cache is required.

10. The explorer can show tx hashes but cannot verify a settlement. `Explorer.tsx` displays JSON and cross refs, plus Base Sepolia tx snippets. It does not decode contract events, run `eth_call` against root registry, verify receipt inclusion, compare escrow snapshots, validate bond snapshots, check finality, or explain identity binding.

11. The Base Sepolia deployment template and the Base Sepolia fixture are not presented as one rollout chain. The template in `contracts/deployments/base-sepolia.template.json` is still a review template, while the IOA fixture has a reviewed rollout record and smoke report. The passport needs to bind template hash, reviewed manifest hash, approval hash, deployed addresses, deployment txs, smoke txs, and explorer links.

12. Mainnet gates are implicit in docs and examples, not enforced by the passport. The IOA summary says `mainnet_blocked: true`, but the public verifier should enforce chain allow-lists, chain role, required live evidence class, and external publication hold.

## Web3SettlementProofBundle Design

Introduce a new artifact family:

```text
schema: chio.web3-settlement-proof-bundle.v1
canonicalization: RFC 8785 canonical JSON
signature: Chio SignedExportEnvelope or explicit DSSE envelope
primary verifier: chio web3 settlement passport verify
```

The bundle should be strict, deny unknown fields, and be hash-addressed. It should be acceptable as a standalone file and as a member of the IOA `bundle-manifest.json`.

### Top-Level Shape

```json
{
  "schema": "chio.web3-settlement-proof-bundle.v1",
  "bundle_id": "chio.web3-settlement-proof.<chain>.<escrow_id>.<receipt_id>",
  "generated_at": 1776995581,
  "claim_boundary": "public_testnet_runtime_settlement",
  "chain_role": "public-testnet-primary",
  "network": {
    "chain_id": "eip155:84532",
    "network_name": "Base Sepolia",
    "settlement_token": {"symbol": "USDC", "address": "..."}
  },
  "identity": {},
  "deployment": {},
  "runtime": {},
  "settlement": {},
  "anchor": {},
  "witness": {},
  "escrow": {},
  "bond": {},
  "oracle": {},
  "finality": {},
  "dispute": {},
  "manifest": {},
  "verifier_policy": {},
  "signatures": []
}
```

### Required Components

- `identity`
  - `operator_binding`: full `SignedWeb3IdentityBinding`.
  - `registry_operator_record`: operator address, Ed25519 key hash, settlement key, active flag, observed block.
  - `entity_bindings`: Chio entity id to settlement address bindings for depositor, beneficiary, operator, and optional auditor.
  - `binding_proof_refs`: hashes or manifest paths for DID/passport/provenance files.
- `deployment`
  - Contract package id, reviewed manifest hash, approval hash, CREATE2 factory address, planned addresses, deployed addresses, deployment tx hashes, and config tx hashes.
  - Contract bytecode/artifact refs from `contracts/artifacts/*.json`.
  - Explorer URLs or CAIP-2/CAIP-10 references are display fields only; verifier uses chain reads.
- `runtime`
  - Runtime proof package hash and path.
  - Verifier report hash and path.
  - Workflow receipt hash and path.
  - Runtime parity report hash and path when available.
  - Settlement observer status frame if the settlement originated from a kernel observer path.
- `settlement`
  - Full `Web3SettlementDispatchArtifact`.
  - Full `Web3SettlementExecutionReceiptArtifact`.
  - Capital instruction hash, governed receipt id, completion-flow row id, and amount equality proof.
  - Prepared call identities: approval tx, escrow create tx, release txs, refund txs.
- `anchor`
  - Full `AnchorProofBundle`, not the compact IOA summary.
  - On-chain root registry readback for `getRoot`, `getLatestSeq`, and `verifyInclusionDetailed`.
  - Chain anchor record with block number, block hash, root, checkpoint sequence, operator, and tx hash.
- `witness`
  - Public witness state for the anchor batch or super-root.
  - Verifier-owned witness verification report, not just producer-provided `WitnessState::Witnessed`.
  - Rekor UUID or OTS proof metadata when used.
- `escrow`
  - Escrow terms, derived escrow id, create tx hash, event log proof, current snapshot, released amount, remaining amount, refunded flag, and proof of amount equality to dispatch.
  - Event sequence: `EscrowCreated`, `EscrowPartialRelease`, `EscrowReleased`, `EscrowRefunded` as applicable.
- `bond`
  - Bond terms if a bond backs the dispatch.
  - Vault id, lock tx, release or impairment tx, expiry tx, current snapshot, slashed amount, remaining amount, reserve requirement metadata, and proof evidence hash.
  - If no bond is present, require an explicit `bond_policy: none_for_lane` with the trust-profile reason.
- `oracle`
  - Typed `OracleConversionEvidence` when FX-sensitive.
  - Raw feed readback and price resolver readback may be included as supporting evidence, but cannot replace the typed conversion envelope.
- `finality`
  - Settlement finality assessment: required confirmations, current confirmations, dispute window, close time, block hash comparison, and recovery action.
  - The verifier should recompute this with a chain RPC snapshot when online.
- `dispute`
  - Typed dispute lifecycle object, even when no dispute exists.
  - Fields: dispute id, status, opened_at, challenge window, linked escrow events, linked bond events, receipt ids, remediation packet hash, refund or reversal receipt, and finality interaction.
- `manifest`
  - IOA bundle manifest hash, member file hashes, and selected file refs.
  - Because `review-result.json` is advisory in the existing UI, a public passport must sign its own verifier report or include a sealed verifier-report artifact.
- `verifier_policy`
  - Chain allow-list, expected contract addresses, required lanes, minimum confirmations, dispute windows, public witness policy, certificate validity rules, and maximum artifact age.

### Verification Algorithm

The verifier should run these steps in order and stop at first hard failure:

1. Parse bundle with strict schema and canonicalize bytes.
2. Verify bundle signature or DSSE envelope.
3. Verify every manifest hash and referenced artifact hash.
4. Verify runtime proof package, verifier report, workflow receipt, DSSE, leases, governance receipts, and parity hashes.
5. Verify `SignedWeb3IdentityBinding` signature and validity interval.
6. Read `ChioIdentityRegistry.getOperator` and compare active flag, key hash, and settlement key.
7. Read entity bindings for depositor, beneficiary, and operator when present.
8. Verify deployment manifest hash, approval hash, planned/deployed address equality, and chain id.
9. Verify dispatch schema, capital instruction signature, web3 rail, completion-flow row id, amount, chain, escrow contract, bond vault contract, custody boundary, and required support flags.
10. Verify anchor proof bundle locally: receipt signature, checkpoint signature, Merkle inclusion, key binding, chain scope, purpose, and optional secondary lanes.
11. Read `ChioRootRegistry.getRoot` for the checkpoint and compare root, tree size, batch range, operator key hash, and checkpoint sequence.
12. Call `verifyInclusionDetailed` or reproduce the call data and compare expected true result.
13. Verify escrow id derivation from terms and chain.
14. Decode escrow event logs and compare to `getEscrow` snapshot.
15. Verify release amount equals dispatch amount for settled state, or partial amount rules for partially settled state.
16. Verify bond vault state if bond-backed, or validate explicit no-bond policy.
17. Verify typed oracle evidence if required by dispatch.
18. Verify execution receipt lifecycle rules.
19. Recompute finality from current chain head, tx block hash, required confirmations, and dispute window.
20. Verify dispute lifecycle state, including no-open-dispute proof or resolved dispute evidence.
21. Emit a signed verifier report with stable check codes.

## Public Witness And Anchor Verification

The passport should reuse the anchor subsystem's strict public-witness principle. A producer can include a witness receipt, but a public verifier must not treat that as enough when the policy says `require_public_witness=true`.

Required witness modes:

- `live`: verifier calls Rekor, OTS, Solana RPC, or the configured witness client and records the returned verification transcript.
- `verified_cache`: verifier uses its own previously verified cache keyed by recomputed body hash and bounded by stale window.
- `advisory`: allowed only for local preview or internal smoke lanes, never for public release claims.

For Base Sepolia settlement passports, the minimal public anchor proof should include:

- full `AnchorProofBundle`
- root registry address from reviewed deployment
- checkpoint sequence
- root publication tx hash
- block number and block hash
- operator address
- operator key hash
- on-chain `getRoot` result
- `verifyInclusionDetailed` result
- public witness verification report if the proof claims a public witness lane

The IOA fixture currently has only enough data for a human narrative. It should be upgraded to include the typed proof and independent verification transcript before it is used as a public trust claim.

## Escrow, Bond, Dispute, And Finality Architecture

### Escrow

Escrow should be treated as the public money-state spine:

- `createEscrow` proves funds were locked to exact terms.
- `partialReleaseWithProofDetailed` proves partial payment by anchored receipt.
- `releaseWithProofDetailed` or `releaseWithSignature` proves final payment.
- `refund` proves timeout recovery.
- `getEscrow` proves final state.

The passport should display both event history and current state. Event history proves what happened; current state proves what remains true.

### Bond

Bond vaults should be treated as risk backing, not settlement itself:

- A bond-backed settlement must include bond id, facility id, vault id, collateral, reserve requirement amount, reserve ratio, expiry, principal, operator, and token.
- `BondLocked` proves collateral was posted.
- `BondReleased`, `BondImpaired`, or `BondExpired` proves the risk state.
- If a dispute resolves with impairment, the impairment evidence hash must be an anchored Chio receipt or dispute audit digest.

The passport should reject an implied bond. Either the dispatch includes a signed active bond and current vault state, or it explicitly says the selected lane has no bond backing.

### Dispute

Add a typed `chio.web3-settlement-dispute.v1` object:

- `dispute_id`
- `settlement_reference`
- `escrow_id`
- `vault_id`
- `opened_at`
- `challenge_window_secs`
- `status`: none, open, resolved, rejected, timed_out
- `reason_code`
- `claim_hash`
- `evidence_receipt_ids`
- `linked_artifacts`
- `resolution`: none, partial_payment, refund, reversal, bond_impairment, remediation_only
- `resolution_receipt_id`
- `onchain_effects`: escrow release/refund txs and bond impairment txs

This object should not claim automatic arbitration. It should prove that the dispute state and resulting chain effects line up with signed Chio receipts and the finality window.

### Finality

Finality must be recomputed, not copied from the producer:

- For each settlement tx, compare stored block hash to current block hash at that number.
- Count confirmations from current head.
- Apply trust-profile finality rule and amount tier.
- Apply dispute window.
- Return `awaiting_confirmations`, `awaiting_dispute_window`, `finalized`, or `reorged`.
- Map recovery action to wait, retry, refund, manual review, bond expiry, or reorg resubmission.

The public passport can include a producer finality report, but the verifier report is the authoritative public status.

## Identity Binding

The identity model should bind four layers:

1. Chio runtime key
   - Ed25519 public key used on receipts and checkpoint statements.
2. Web3 key-binding certificate
   - Chio identity, Chio public key, chain scope, purposes `anchor` and `settle`, settlement address, validity interval, nonce, signature.
3. On-chain operator record
   - Operator EVM address, Ed25519 key hash, settlement key, active status.
4. Entity/passport presentation
   - Provider or agent passport, challenge, presentation, verdict, runtime appraisal, and reputation/federation context.

Required checks:

- Receipt kernel key equals checkpoint statement kernel key.
- Binding certificate Chio public key equals receipt kernel key.
- Binding certificate settlement address equals chain anchor operator address.
- Binding certificate chain scope contains settlement chain.
- Binding certificate purpose contains `anchor` for anchors and `settle` for settlement.
- Registry Ed25519 key hash equals keccak256 of the Ed25519 public key bytes used by the binding.
- Registry settlement key equals the EVM key used for dual-sign settlement when dual-sign is used.
- Entity binding maps Chio subject ids to settlement addresses without overloading the dispatch `beneficiary_address` field.

Recommended contract evolution after this planning phase: emit and expose a `bindingProofHash` or `certificateHash` in `ChioIdentityRegistry`, while keeping the full certificate off-chain. That gives public verifiers a stable on-chain commitment without putting large DID material in storage.

## Chain Rollout Gates

### Base Sepolia Public Testnet

Gate Base Sepolia passport publication on:

- Reviewed manifest generated from `contracts/deployments/base-sepolia.template.json`.
- Approval artifact binding manifest hash, release id, deployment policy id, CREATE2 factory, and salt namespace.
- Deployed address equality: planned address equals deployed address for identity registry, root registry, escrow, bond vault, and price resolver.
- Operator registration and entity registration txs observed.
- Fresh price feed readback and sequencer status readback.
- Root publication tx observed and `getRoot` readback matches checkpoint.
- Escrow create, partial release, final release, and timeout refund smoke txs observed.
- Full typed anchor proof bundle included.
- Public verifier report signs chain readback, not just fixture JSON.

### Base Mainnet

Gate Base mainnet on all Base Sepolia gates plus:

- Live Chainlink feed addresses reviewed against current official inventory.
- No mock feed dependencies.
- Independent bytecode verification and source artifact hash comparison.
- Mainnet USDC blacklist or address-screening policy decision documented as either implemented or explicitly excluded with risk acceptance.
- Emergency controls and rollback plan reviewed.
- Minimum public witness lane required, not advisory.
- External release qualification hosted and signed.
- No mainnet claim if any artifact still depends on local devnet, mock feed, or fixture-only evidence.

### Arbitrum Secondary

Gate Arbitrum only after Base passport verifier is stable:

- Chain configuration has exact deployed addresses and gas profile.
- Trust profile has explicit secondary chain finality rule.
- Operator binding chain scope covers `eip155:42161`.
- Anchor discovery declares secondary chain and freshness.
- CCIP coordination remains state coordination only unless a separate live fund transport proof exists.

## Explorer And Verifier UX

The evidence console should gain a dedicated `Settlement Passport` view instead of forcing reviewers through raw JSON.

### Reviewer Path

1. Passport overview
   - Verdict, chain, escrow id, amount, lifecycle, finality, dispute status, bond status, and identity status.
2. Runtime proof
   - Proof package hash, verifier report hash, workflow receipt, buyer/auditor proof status, and parity status.
3. Identity
   - Chio identity, runtime key, settlement address, registry status, passport verdict, runtime appraisal, and expiry warnings.
4. Anchor
   - Receipt, checkpoint, Merkle proof, root registry readback, public witness verification, and explorer tx.
5. Settlement
   - Escrow terms, event timeline, current snapshot, release/refund txs, amount reconciliation.
6. Bond
   - Bond terms, vault snapshot, release/impair/expire timeline, reserve metadata.
7. Finality
   - Confirmations, dispute window, reorg check, recovery action.
8. Dispute
   - No-open-dispute proof or resolved dispute packet, with linked receipts and chain effects.
9. Raw artifacts
   - Existing JSON tree and manifest hash view.

### UX Requirements

- Show a check as verified only when the verifier computed it.
- Label producer-provided evidence as supplied until verified.
- Make explorer links secondary to decoded evidence.
- Keep `review-result.json` advisory unless sealed by the passport or replaced by a signed verifier report.
- Add copyable canonical bundle hash, verifier report hash, and settlement reference.
- Add fail-closed red states for chain mismatch, stale witness, reorg, expired certificate, amount mismatch, missing full anchor proof, missing oracle envelope, and unresolved dispute.

## Tests And Gates

Add these gates when implementation begins:

1. Schema gate
   - Add `spec/schemas/chio-web3/v1/web3-settlement-proof-bundle.schema.json`.
   - Register it in `spec/schemas/registry.json`.
   - Validate strict object shape, no unknown fields, and all referenced schema ids.

2. Rust verifier gate
   - Add a verifier crate or module that composes `chio-web3`, `chio-anchor`, `chio-settle`, `chio-attest-buyer-core`, and registry readback.
   - Unit tests for every hard failure listed in the verification algorithm.

3. Fixture upgrade gate
   - Replace IOA compact `reconciled_anchor_proof` with full typed `AnchorProofBundle`.
   - Add typed `OracleConversionEvidence`.
   - Add finality assessment.
   - Add explicit bond policy.
   - Add typed dispute lifecycle.
   - Restamp `bundle-manifest.json`.

4. Public chain readback gate
   - Base Sepolia verifier runs against `https://sepolia.base.org` or a configured RPC.
   - It confirms root registry, escrow, bond, identity registry, price resolver, event logs, and tx block hashes.

5. Negative corpus gate
   - Mutate each high-risk binding: wrong chain id, wrong root, wrong leaf index, wrong tree size, missing checkpoint, stale witness, wrong operator, inactive operator, wrong settlement key, wrong escrow amount, mismatched escrow id, missing finality, reorged block hash, unresolved dispute, missing oracle envelope, and advisory-only witness.

6. Existing qualification integration
   - Extend `scripts/qualify-web3-runtime.sh` to run the passport verifier after existing web3 runtime and e2e gates.
   - Extend `scripts/qualify-web3-examples.sh` to require the IOA passport artifact.
   - Keep `scripts/check-chio-runtime-proof-parity.sh` and `scripts/check-chio-proof-package.sh` as prerequisites, not substitutes.

7. UI e2e gate
   - Add Playwright coverage for the `Settlement Passport` view.
   - Verify a good bundle passes.
   - Verify corrupted manifest hash, missing anchor proof, stale witness, chain mismatch, amount mismatch, and unresolved dispute render fail-closed.

## Phased Plan

### Phase 1: Passport Contract

- Write the schema for `chio.web3-settlement-proof-bundle.v1`.
- Define the verifier report schema with stable check codes.
- Define `chio.web3-settlement-dispute.v1`.
- Decide whether the bundle signature is Chio `SignedExportEnvelope`, DSSE, or both.
- Add fixture-only example using existing docs/standards examples plus IOA Base Sepolia fixture data.

Exit gate: schema validates and a static verifier can reject malformed bundles without chain RPC.

### Phase 2: Typed IOA Bundle

- Upgrade IOA fixture to carry full `AnchorProofBundle`.
- Replace price-map-only `oracle_evidence` with typed `OracleConversionEvidence` plus supporting price readback.
- Split Chio identities from EVM addresses.
- Add finality report and explicit bond policy.
- Add typed dispute lifecycle.

Exit gate: IOA good bundle verifies offline, and negative fixture mutations fail.

### Phase 3: Chain Readback Verifier

- Add online verification against Base Sepolia.
- Read registry, root, escrow, bond, block, tx, event log, and price resolver state.
- Compare every readback to the bundle.
- Produce a signed verifier report.

Exit gate: the existing Base Sepolia smoke fixture can be checked against live chain state or clearly fail as stale.

### Phase 4: Explorer

- Add `Settlement Passport` view to the IOA app.
- Show computed verification status per section.
- Keep raw JSON tree for audit.
- Add public chain explorer links only after computed verification passes.

Exit gate: Playwright proves good and bad bundles render the correct public status.

### Phase 5: Release Gates

- Wire passport verification into `qualify-web3-runtime`, `qualify-web3-examples`, and hosted release qualification.
- Require Base Sepolia passport before any public launch claim.
- Require stronger chain and witness gates before Base mainnet.

Exit gate: release qualification includes a signed settlement passport verifier report and no unresolved hard failures.

## Top 5 Strongest Recommendations

1. Build `chio.web3-settlement-proof-bundle.v1` as a strict composition layer, not a replacement for existing artifacts. The value is the join across runtime proof, anchor proof, identity, escrow, bond, finality, and dispute.

2. Upgrade IOA evidence from compact summaries to typed verifier inputs. The current Base Sepolia fixture is useful evidence, but it is not yet a public proof because the settlement receipt omits the full anchor proof and typed oracle conversion envelope.

3. Make public verification recompute chain state. A passport verifier must read registry, root, escrow, bond, tx receipt, block hash, and finality state. Explorer URLs and tx hashes are display aids, not proof.

4. Split identity fields cleanly. Do not overload Chio subject ids and EVM addresses in `beneficiary_address`. Add explicit Chio identity, settlement address, binding certificate, and registry readback fields.

5. Treat dispute and bond state as first-class. Settlement proof without dispute window, no-open-dispute or resolved-dispute evidence, and bond/no-bond posture is incomplete for a public trust network.
