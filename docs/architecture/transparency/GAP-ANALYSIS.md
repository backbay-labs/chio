# Transparency gap analysis: the itemized work behind the program

- Status: Reference (citations verified against the tree, 2026-07-26)
- Program: [README.md](./README.md) is the five-stage summary of this analysis
- Decision context: [../../adr/ADR-0018-radicle-carrier-not-authority.md](../../adr/ADR-0018-radicle-carrier-not-authority.md)
- Substrate evidence: [../../research/radicle/EVALUATION.md](../../research/radicle/EVALUATION.md)

This document decomposes the `spec/PROTOCOL.md` section 6.5 append-only gate
into items small enough to schedule, with per-item citations, so the plan can
be audited and re-planned without re-deriving the analysis. Nothing here
changes the program's ordering; it is the arithmetic underneath it.

## 1. The gate has no definition

The four gate terms (claim-complete, child-receipt-complete,
anti-equivocation-capable, qualified under the declared verifier policy)
appear in `spec/PROTOCOL.md` section 6.5 and in this program's documents, and
nowhere else in the tree. No registry entry defines them, no conformance test
exercises them, and the claim registry contains no checkpoint or transparency
claim of any kind. Promotion therefore cannot be evaluated mechanically; the
first work item is to write the definitions down where the registry integrity
tests can see them.

## 2. What the tree commits today

Checkpoints are built over `claim_receipt_log_entries`, which is populated by
exactly two triggers, `chio_tool_receipts_project_claim_log_entry` and
`chio_child_receipts_project_claim_log_entry`
(`crates/platform/chio-store-sqlite/src/receipt_store/bootstrap/open.rs:866,901`).
The leaf encoder accepts exactly those two kinds and rejects every other kind
fail-closed (`canonical_bytes_from_claim_log_row`,
`crates/platform/chio-store-sqlite/src/receipt_store/support/checkpoint_projection.rs:654`).

The signed-artifact registry (`spec/schemas/registry.json`, 339 artifact
schemas) defines fifteen receipt-family schema names. Classifying their wire
form before counting coverage produces this inventory:

| Registry schema | Form | Current checkpoint coverage |
| --- | --- | --- |
| `chio.receipt.v1` | standalone canonical receipt | direct leaf |
| `chio.receipt_lineage_statement.v1` | standalone signed statement | none |
| `chio.federation.receipt-lineage-statement.v1` | standalone signed statement | none |
| `chio.federation.receipt-lineage-bundle.v1` | derived aggregate over standalone statements | none |
| `chio.governance-receipt.v1` | standalone signed receipt | none |
| `chio.admission-receipt.v1` | embedded metadata in `chio.receipt.v1` | covered by its parent leaf |
| `chio.policy.activation-receipt.v1` | standalone signed receipt | none |
| `chio.runtime.terminal-receipt.v1` | standalone signed receipt | none |
| `chio.swarm.join-receipt.v1` | standalone signed receipt | none |
| `chio.swarm.route-plan-receipt.v1` | standalone signed receipt | none |
| `chio.swarm.terminal-graph-receipt.v1` | standalone signed receipt | none |
| `chio.web3-settlement-execution-receipt.v1` | standalone signed receipt | none |
| `chio.web3-settlement-execution-receipt.v2` | standalone signed receipt | none |
| `chio.risk.adjudication-jurisdiction-receipt.v1` | standalone signed receipt | none |
| `chio.proof-room.receipt-evidence.v1` | derived receipt projection with its own signature | none |

Child request receipts (`ChildRequestReceipt`,
`crates/core/chio-core-types/src/receipt/lineage.rs`) are the second committed
leaf kind; they are an in-tree type rather than a registry schema of their
own.

The store makes the same gap visible from below. The bootstrap creates forty
tables; two receipt tables project into the claim log that checkpoints commit
to. The rest hold signed or evidentiary state committed to no root, including
`receipt_lineage_statements`, `session_anchors`, `request_lineage`,
`capability_lineage`, `settlement_reconciliations`,
`metered_billing_reconciliations`, `liability_claim_adjudications`,
`liability_claim_payout_receipts`, `liability_claim_settlement_receipts`,
`credit_facilities`, `credit_bonds`, `credit_loss_lifecycle`,
`underwriting_decisions`, `underwriting_appeals`, and the `federated_*` share
tables.

The classification removes one false gap: `chio.admission-receipt.v1` is
`AdmissionReceiptMetadataV1` stored under `ADMISSION_RECEIPT_METADATA_KEY`
inside `ChioReceipt.metadata`, which is part of `ChioReceiptIdInput`, signed
with the receipt, and already inside the canonical bytes used as a checkpoint
leaf. Derived aggregates and projections also must not be counted as additional
source receipts without first deciding whether committing their inputs is
sufficient under the claim-completeness definition.

Which remaining standalone artifacts must be committed is a protocol decision,
not a coding task (item 2 below), and that decision sizes item 3. The earlier
80-to-85-percent estimate is therefore withdrawn rather than reusing
registry-name counts as an effort estimate.

## 3. The uncheckpointed tail

Checkpointing is count-triggered only (the ADR-0008 trigger), and a zero
batch size disables it entirely:

```2013:2015:crates/platform/chio-store-sqlite/src/receipt_store.rs
    if signer.max_batch == 0 {
        return Ok(false);
    }
```

The export surface models the consequence honestly: `EvidenceExportBundle`
carries `uncheckpointed_receipts`
(`crates/kernel/chio-kernel/src/evidence_export.rs:223`), and nothing bounds
how large that suffix can grow. An append-only claim needs a time-based flush
so the uncommitted tail is a bounded, declared quantity.

## 4. Child receipts: committed but not provable

The commitment exists (section 2). The proof surface does not.

- Inclusion proofs are generated from tool receipts only:
  `collect_inclusion_proofs_for_export` takes `tool_receipts`
  (`crates/platform/chio-store-sqlite/src/evidence_export.rs:281`), and
  checkpoint selection has the same bias
  (`collect_checkpoints_for_export(&tool_receipts)`, same file, lines 37 and
  220). A bundle can carry a child receipt as a record while offering no way
  to prove it sits under any root.
- Scoped exports drop child receipts silently. `chio_child_receipts` has
  session, parent-request, and request columns but no tenant or capability
  column (`bootstrap/open.rs:795`), so tenant- or capability-scoped exports
  return `EvidenceChildReceiptScope::OmittedNoJoinPath`
  (`crates/kernel/chio-kernel/src/evidence_export.rs:42-51`): zero child
  receipts, and nothing in the Merkle evidence saying anything is missing.
- The bounded operational profile already records the deferral: "child
  receipt inclusion-proof export remains deferred unless an evidence package
  explicitly exports child receipt proof rows"
  (`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`).

## 5. Anti-equivocation: present machinery, missing halves

What exists in `crates/kernel/chio-kernel/src/checkpoint.rs`:

- Predecessor witnessing: `previous_checkpoint_sha256` in the signed body,
  `build_checkpoint_witness` (line 323), and
  `validate_checkpoint_predecessor` (line 881) enforcing contiguous sequence,
  contiguous entry range, and digest match.
- Equivocation detection: `CheckpointEquivocationKind` with
  `ConflictingCheckpointSeq`, `ConflictingLogTreeSize`, and
  `ConflictingPredecessorWitness` (lines 195-201), detected by
  `detect_checkpoint_equivocation` (line 440).

Fixed on 2026-07-26 (program finding F1, items 8 and 20 below): `merkle.rs`
implements RFC 6962 consistency proofs, the signed body carries a
`chain_root` committing the checkpoint chain, and
`verify_checkpoint_consistency_proof` verifies real node hashes against the
two signed commitments.

What is missing:

- Detection only compares checkpoints the caller already holds. Detecting
  that an operator showed one history to auditor X and another to auditor Y
  needs independent parties each holding a view, plus a protocol for
  comparing views. That monitor half does not exist anywhere.
- The strongest ordering primitive is unwired. The EVM root registry
  (`crates/economy/chio-anchor/src/evm/publication.rs`) can publish a
  checkpoint root on-chain and confirm the event, but `AnchorBatch` is
  referenced only inside `chio-anchor` and the conformance suite; no kernel,
  store, control-plane, or CLI path invokes the pipeline. Checkpoint issuance
  and public witnessing are disconnected programs today.

## 6. External witness lanes, audited

- Rekor (`crates/economy/chio-anchor/src/witness/rekor.rs`): signed-entry
  timestamps verified against a pinned P-256 key, plus RFC 6962 root
  recomputation from the stapled inclusion proof
  (`rfc6962_root_from_inclusion_proof`, line 453; `verify_inclusion_proof`,
  line 546). Two gaps keep this short of anti-equivocation. The proof is
  optional by design:

```542:545:crates/economy/chio-anchor/src/witness/rekor.rs
/// When the entry carries no `verification.inclusionProof`, this is a
/// no-op: the SET remains the authoritative authentication. Rekor
/// responses are not guaranteed to inline an inclusion proof, and the
/// pinned-key SET already binds the (body, logIndex) tuple.
```

  And the recomputed root is compared against the proof's own asserted
  `rootHash` (lines 589-623). There is no signed tree head pinned across
  observations and no consistency check between successive tree heads, so a
  log presenting an internally consistent forked view passes.
- OpenTimestamps: advisory by design; `verify_inclusion` fails closed and OTS
  never satisfies `require_public_witness`.
- Solana memo and the EVM root registry: real code, unwired (section 5).
- Three places still describe the Rekor inclusion-proof work as unimplemented
  and are stale: `spec/PROTOCOL.md:1452` ("does not yet verify Rekor's Merkle
  inclusion path"), the `claim.anchor.batch_continuity` summary in
  `spec/registries/claim-registry.v1.json`, and
  `docs/security/public-witness-semantics.md` ("until Rekor inclusion-proof
  verification lands"). Item 19 fixes the text.

## 7. Qualification surfaces disagree with each other

Three unsynchronized definitions of the continuity classes exist.

The kernel exports two states and cannot express `append_only`:

```138:142:crates/kernel/chio-kernel/src/evidence_export.rs
pub enum EvidencePublicationState {
    #[default]
    TransparencyPreview,
    TrustAnchored,
}
```

The declared verifier policy accepts three states, none of them `append_only`
(`spec/schemas/chio-transaction/v1/verifier-policy.schema.json:47-54`):

```18:18:crates/platform/chio-transaction-passport/src/verifier_policy.rs
const TRANSPARENCY_STATES: &[&str] = &["trust_anchored", "transparency_preview", "not_present"];
```

Mercury proof packages are the only surface with all three classes
(`crates/products/chio-mercury-core/src/proof_package.rs:23-25`), and their
`append_only` gate is structural: a non-empty `trust_anchor` string,
publication records present, and `is_trust_anchored()`, which reduces to an
enum comparison (`chio-kernel/src/evidence_export.rs:206-209`). Nothing
verifies the anchor.

Feeding all of it, the transparency state itself was asserted from a string
match (program finding F2, fixed 2026-07-26: promotion to `trust_anchored`
now requires a verified inclusion proof against a pinned-key checkpoint, and
surfaces without artifacts or pinned keys cannot reach the anchored tier).
The enum gaps above remain item 10.

## 8. Registry promotion mechanics

Chio's claim-boundary system requires that an enforced claim reference a
proof-manifest row referencing live tests and proven theorems.
`spec/registries/claim-registry.v1.json` holds 79 enforced and 3 proposed
claims; none is a checkpoint or transparency claim (the nearest is
`claim.anchor.batch_continuity`). The two theorems the anchor lane names,
`theorem.anchor.merkle_inclusion` and
`theorem.anchor.public_witness_anti_equivocation`, are both `proposed` in
`spec/registries/theorem-inventory.v1.json` with no corresponding file in
`formal/lean4/Chio/Chio/Proofs/` (ten proof files exist; none covers Merkle
or anchoring). The integrity tests
(`crates/core/chio-core-types/tests/claim_registry_integrity.rs`:
`enforced_claims_reference_live_proof_manifests`,
`proof_manifest_rust_test_refs_point_to_live_files`) check that referenced
tests exist, so promotion evidence cannot be faked, and every step here is
mandatory rather than ceremonial.

Conformance coverage today: the transparency surface consists of six
anchor-batch negative tests (five `anchor_batch_*` files plus
`b3_anchor_batch_sync_path_rejected_under_public_witness.rs`) plus
`checkpoint_consistency_forged_chain_root_rejected.rs` and
`checkpoint_statement_unknown_field_rejected.rs` in
`crates/tooling/chio-conformance/tests/`. The forged-root and signed-body
parser boundaries are covered. Split-view equivocation, predecessor
continuity, missing child proofs, incomplete receipt families, and
continuity-class qualification still need conformance negatives.

## 9. Retention against append-only

`crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs:1593`
deletes `claim_receipt_log_entries` at or below the retention watermark. The
deletion runs behind append-only guard triggers
(`support/checkpoint_projection.rs:29,35`) through a sanctioned, audited path
(RFC-0007), which is a defensible design for an audit-only log. A public
append-only claim additionally requires a written contract: what is retained,
for how long, and what a verifier can still check after pruning (program
finding F4).

## 10. Boundaries the program must respect

- The roadmap item this serves (October 2026): "A federated,
  anti-equivocation transparency log for agent action: a public, searchable
  commons of proofs with independent monitors, so any claim about any agent
  can be checked by anyone" (`README.md`).
- The explicit-gaps list keeps "permissionless mirror/indexer publication as
  automatic trust, sanction, or market-penalty authority" out of scope
  (`spec/PROTOCOL.md:3645`). Monitors surface evidence; they do not acquire
  authority.

## 11. Ordered work breakdown

Sizes: S is days, M is one to three weeks, L is one to three months. Item
numbers are stable identifiers for cross-reference, not a priority order; the
Stage column carries scheduling, and the program README defines stage order.

| # | Item | Stage | Kind | Size | Where |
| --- | --- | --- | --- | --- | --- |
| 1 | Define the four gate terms normatively, in a registry the integrity tests can see | 1 | internal | S | `spec/PROTOCOL.md` 6.5, `spec/registries/` |
| 2 | Enumerate which receipt-family schemas must be committed (protocol decision; sizes item 3) | 2 | internal | S | `spec/schemas/registry.json` |
| 3 | Extend the claim-log projection to the full family: a projection path per kind, canonical-bytes encoders, ordering, backfill, migration | 2 | internal | L | `bootstrap/open.rs:865-906`, `support/checkpoint_projection.rs:654`, `support/claim_log/` |
| 4 | Resolve retention against append-only: frozen-prefix or tombstone contract | 2 | internal | M | `evidence_retention.rs`, RFC-0007 |
| 5 | Bound the uncheckpointed tail: time-based flush; forbid `max_batch == 0` under an append-only profile | 2 | internal | M | `receipt_store.rs:2008-2067`, `evidence_export.rs:223` |
| 6 | Child-receipt inclusion proofs in evidence exports | 2 | internal | M | `chio-store-sqlite/src/evidence_export.rs:281` |
| 7 | Tenant and capability join paths for `chio_child_receipts`, so omission becomes impossible rather than silent | 2 | internal | M | `bootstrap/open.rs:795`, `chio-kernel/src/evidence_export.rs:42-51` |
| 8 | Real RFC 6962 consistency proofs: node-hash proofs in `merkle.rs`, carried and verified by the checkpoint layer (done 2026-07-26) | 1 | internal | M | `checkpoint.rs`, `merkle.rs` |
| 9 | Verifier-side qualification: replace presence-based transparency state with cryptographic verification (done 2026-07-26) | 1 | internal | M | `minimal.rs` |
| 10 | Continuity-class plumbing: `append_only` in every enum, one reconciled definition across the three surfaces | 3 | internal | M | `evidence_export.rs:138-142`, `verifier-policy.schema.json:47-54`, `verifier_policy.rs:18`, `proof_package.rs:23-25` |
| 11 | Witness tree-head pinning and consistency: mandatory inclusion proofs, pinned tree heads, head-to-head consistency checks | 4 | internal | M | `rekor.rs:546-624` |
| 12 | Wire checkpoint issuance to publication: the checkpoint to `AnchorBatch` to witness pipeline gains a production caller and becomes mandatory under an append-only profile | 4 | internal | M | `chio-anchor/src/batch.rs`, `chio-anchor/src/automation.rs` |
| 13 | Prove the two anchor theorems | 4 | internal | M-L | `theorem-inventory.v1.json`, `formal/lean4/Chio/Chio/Proofs/` |
| 14 | Register the claim and proof-manifest rows | 5 | internal | S | `claim-registry.v1.json`, `proof-manifest.v1.json` |
| 15 | Finish conformance negatives: split view, predecessor continuity, missing child proof, incomplete family, unqualified policy (forged consistency root and checkpoint parser negatives landed 2026-07-27) | 1-5 | internal | M | `crates/tooling/chio-conformance/tests/` |
| 16 | Substrate publisher behind the existing witness seam | 5 | substrate | M | `chio-anchor/src/witness.rs` |
| 17 | Replication and availability operations: topology, freshness windows, service levels | 5 | substrate | M | ops, `docs/security/public-witness-semantics.md` |
| 18 | Independent monitors and cross-view comparison: exchange observed heads, run detection across views | 5 | mixed | L | `checkpoint.rs:440-508`, new federation surface |
| 19 | Spec and docs update: section 6.5 language, bounded-profile guarantee classes, and the stale Rekor text in three files | 5 | internal | S | `spec/PROTOCOL.md`, `CHIO_BOUNDED_OPERATIONAL_PROFILE.md`, `public-witness-semantics.md` |
| 20 | `deny_unknown_fields` on the signed checkpoint body, with a rejection test (program finding F3; done 2026-07-26) | 1 | internal | S | `checkpoint.rs` |

## 12. The tally

Weighting S=1, M=3, L=8, counting item 13 as M and splitting item 18 evenly
between kinds: internal work is roughly 50 points and substrate work roughly
10, so the substrate share stays under 20 percent however the judgment calls
fall. The largest single item (3, the receipt-family projection) is purely
internal and larger than any substrate integration on its own. This is the
arithmetic behind the program's ordering: the substrate decision comes last
because it is the smallest and least-blocking part of the gate.

Items 8, 9, and 20 (program Stage 1) landed on 2026-07-26.
