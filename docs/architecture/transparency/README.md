# Transparency program: closing the section 6.5 append-only gate

- Status: Living index (proposed program, not yet scheduled)
- Date: 2026-07-25
- Scope: what Chio must build before it may describe its receipt log as
  append-only or claim strong non-repudiation
- Origin: the Radicle evaluation ([../../research/radicle/EVALUATION.md](../../research/radicle/EVALUATION.md)),
  which resolved into this program
- Decision context: [../../adr/ADR-0018-radicle-carrier-not-authority.md](../../adr/ADR-0018-radicle-carrier-not-authority.md)
- Full decomposition: [GAP-ANALYSIS.md](./GAP-ANALYSIS.md), the itemized work
  breakdown with per-item citations that this program summarizes

## 1. Why this document exists

`spec/PROTOCOL.md` section 6.5 caps Chio's transparency claims against itself:

> Chio MUST NOT use public append-only or strong non-repudiation language until
> the published surface is claim-complete, child-receipt-complete,
> anti-equivocation-capable, and qualified under the declared verifier policy.

That cap is honest and it should stay until it is earned. A ten-agent
evaluation went looking for an external substrate that would lift it and found
that no substrate can. Most of the required categories are internal to Chio
and are identical whether checkpoints are published to a peer-to-peer git
network, a C2SP witness quorum, a TUF repository, or a directory served over
HTTPS. The earlier percentage estimate was based on registry-name counts and
is withdrawn now that the gap analysis distinguishes standalone, embedded, and
derived artifacts. Substrate selection is the last decision in this program,
not the first.

The single most consequential finding was item F1 below: the function named
`verify_checkpoint_consistency_proof` did not verify a consistency proof, so
any publication or witnessing scheme built on top of it would have cosigned a
root whose relationship to its predecessor was unconstrained. F1 through F3
were fixed on 2026-07-26 (Stage 1 below); the remaining stages build on
primitives that are now real.

## 2. What the four gate conditions actually require

Section 6.5 names four conditions. Each decomposes into concrete, verifiable
work.

**Anti-equivocation-capable.** A verifier must be able to reject a log that
shows different histories to different parties, using only the artifact in hand
plus pinned keys. This needs a real Merkle consistency proof (F1), a witness
quorum that refuses to cosign a root inconsistent with the last root it signed,
and offline quorum verification. Publication alone does not achieve it:
publication makes equivocation *discoverable* by someone who looks and who
retained the contradiction; witnessing makes it *unpresentable*.

**Claim-complete.** Every claim that a receipt asserts must be covered by the
committed tree, with no silent omissions. Today the claim-log projection
commits exactly two receipt kinds (tool receipts and child request receipts),
while the signed-artifact registry defines fifteen receipt-family schemas, so
the honest description of what a checkpoint proves is far narrower than what
the word "complete" implies.

**Child-receipt-complete.** Nested and delegated flows must have their child
receipts provable, not merely committed. The commitment already exists: child
receipts are projected into the claim log and become Merkle leaves exactly
like tool receipts. What is missing is the proof surface: inclusion proofs are
exported for tool receipts only, and tenant- or capability-scoped exports omit
child receipts entirely. The omission itself is declared outward
(`EvidenceExportBundle` serializes `child_receipt_scope`, and
`OmittedNoJoinPath` appears as `omitted_no_join_path`), so the gap is not a
hidden omission but the absence of child inclusion proofs and of any
per-parent completeness or enumeration commitment. A verifier confirming a
parent receipt still cannot prove which children the flow had.

**Qualified under the declared verifier policy.** The declared verifier policy
exists (`chio.transaction.verifier-policy.v1`), but it must be able to state
which keys, which quorum, which freshness window, and which failure modes
deny, and a verifier must actually check those statements. Today the artifact
can express none of them, its transparency-state enum has no `append_only`
value, and the state feeding it is the string match of F2, so "qualified" is
unfalsifiable.

## 3. Findings

Each finding was verified against the tree at authoring time, cited by file and
line. F1 through F3 are standalone defects that are worth fixing on their own
merits, independent of whether this program is ever scheduled.

### F1 (critical): the consistency proof is a tautology, not a proof

`build_checkpoint_consistency_proof` returns a metadata struct containing
sequence numbers, body digests, and tree sizes, and no Merkle node hashes at
all:

```378:389:crates/kernel/chio-kernel/src/checkpoint.rs
    Ok(CheckpointConsistencyProof {
        schema: CHECKPOINT_CONSISTENCY_PROOF_SCHEMA.to_string(),
        log_id: current_log_id,
        from_checkpoint_seq: previous.body.checkpoint_seq,
        to_checkpoint_seq: current.body.checkpoint_seq,
        from_checkpoint_sha256: checkpoint_body_sha256(&previous.body)?,
        to_checkpoint_sha256: checkpoint_body_sha256(&current.body)?,
        from_log_tree_size: checkpoint_log_tree_size(&previous.body),
        to_log_tree_size: checkpoint_log_tree_size(&current.body),
        appended_entry_start_seq: current.body.batch_start_seq,
        appended_entry_end_seq: current.body.batch_end_seq,
    })
```

The verifier recomputes that same struct and compares it for equality:

```393:399:crates/kernel/chio-kernel/src/checkpoint.rs
pub fn verify_checkpoint_consistency_proof(
    previous: &KernelCheckpoint,
    current: &KernelCheckpoint,
    proof: &CheckpointConsistencyProof,
) -> Result<bool, CheckpointError> {
    Ok(*proof == build_checkpoint_consistency_proof(previous, current)?)
}
```

This establishes that the caller holds the two checkpoints it already holds and
that their sequence numbers line up. It places no cryptographic constraint on
tree growth whatsoever. A log that rewrote history and published a `merkle_root`
with no append-only relationship to its predecessor would produce a
"consistency proof" that verifies. The name promises RFC 6962 section 2.1.2 and
the implementation delivers a structural equality check.

The root cause was one layer down: `crates/core/chio-core-types/src/merkle.rs`
implemented RFC 6962 leaf and node hashing and `inclusion_proof`, and
contained no consistency-proof code at all.

*Fixed (2026-07-26).* `merkle.rs` implements RFC 6962 consistency proofs
(`MerkleTree::consistency_proof` and the pure verifier
`verify_consistency_proof`), cross-checked against an independent reference
generator for every size pair up to 48. Because per-batch receipt trees share
no leaves, there was nothing between two batch roots to prove, so the signed
body now carries a `chain_root`: an RFC 6962 root over one leaf per checkpoint
binding its sequence, entry range, and batch root, which transitively commits
every checkpointed entry and is rebuildable forever from retained checkpoint
rows. `CheckpointConsistencyProof` now carries the node hashes plus an
inclusion proof binding EACH endpoint's own chain leaf to its own root
(binding only the later one would let a key holder commit an arbitrary tree as
the earlier root for any pair starting after checkpoint 1), and
`verify_checkpoint_consistency_proof` verifies them against the two signed
commitments; a pair without commitments is unverifiable (an error), never
true. New statements use `chio.checkpoint_statement.v2`, and real
cryptographic proofs use `chio.checkpoint_consistency_proof.v2`. Explicit v1
parsers and legacy verification remain for old statements and metadata-only
records, while v2 fields cannot be smuggled under a v1 schema. This version
boundary is required for rolling verifiers because both records are signed or
security-interpreted wire formats. The store cross-checks every commitment
against the persisted chain on the operator path and rejects divergent
clock-skew siblings. Issuance stays batch-bounded: the writer keeps an
append-only Merkle frontier of the chain on its verified head, so a checkpoint
costs O(log n) chain hashes and rebuilds the frontier from the database only
after a resync or restart, while still reproducing the predecessor's signed
`chain_root` before signing. A rewritten history that re-signs with the real
kernel key is rejected in
`crates/tooling/chio-conformance/tests/checkpoint_consistency_forged_chain_root_rejected.rs`.

### F2 (high): `trust_anchored` is asserted from a string match

`evidence_graph_transparency_state` promotes an evidence graph to
`trust_anchored` on the presence of a node whose `role` or `schema` names an
inclusion proof, without verifying that the proof is valid, that it commits to
this receipt, or that anything signed it:

```641:653:crates/platform/chio-transaction-passport/src/minimal.rs
fn evidence_graph_transparency_state(nodes: &[Value]) -> &'static str {
    let mut has_transparency_preview = false;
    for node in nodes {
        let role = node.get("role").and_then(Value::as_str).unwrap_or_default();
        let schema = node
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if role == "transparency-inclusion-proof"
            || schema == "chio.transparency.inclusion-proof.v1"
        {
            return "trust_anchored";
        }
```

Anyone able to influence the evidence graph could obtain the strongest
transparency state Chio reports by supplying a node with the right label and
no valid contents, inverting the fail-closed posture: an unverifiable input
produced the *most* trusted output.

*Fixed (2026-07-26).* A labeled node is now a promotion candidate, never a
promotion. The anchored tier requires the node's digest-bound artifact to
carry a Merkle inclusion proof whose recomputed root is committed by a
checkpoint statement signed by one of the verifier's pinned keys, with the
proven leaf equal to the RFC 6962 leaf hash of this transaction's receipt.
A candidate this verifier cannot judge (no pinned checkpoint keys, artifact
bytes absent, or no anchoring checkpoint statement) degrades to the preview
tier; a candidate it can judge and that fails is an error, because reporting
preview would let malformed transparency evidence ride through a policy that
accepts the preview tier. Every candidate is evaluated before promotion, and
the signed checkpoint body is parsed with all required fields and unknown-field
rejection before it qualifies. `chio proof verify` and Proof Room accept
separate checkpoint signer pins through
`CHIO_TRANSACTION_TRUSTED_CHECKPOINT_KEYS`; the passport root set remains a
different trust role. Surfaces without artifact bytes or pinned keys (including
the bytes-only `transaction_evidence_graph_transparency_state`) can no longer
return `trust_anchored` at all. The label-only, untrusted-signer,
tampered-root, partial-body, field-smuggling, multiple-candidate, and
unbound-subject cases are pinned by tests in
`crates/platform/chio-transaction-passport/tests/transaction_passport.rs`.
The registered `chio.transparency.inclusion-proof.v1` remains the
selective-disclosure format, whose subject-digest leaf and unprefixed node
hashing are not RFC 6962 receipt-tree semantics. It remains preview-only.
Checkpoint-anchored receipt proofs use
`chio.transparency.inclusion-proof.v2`, whose schema requires the signed
checkpoint statement and whose leaf is the RFC 6962 hash of the receipt bytes.
Web3 projections preserve the same rolling-reader boundary:
`chio.anchor-inclusion-proof.v1` embeds only v1 checkpoint statements, while
`chio.anchor-inclusion-proof.v2` embeds v2 statements and preserves their
optional chain commitment. Sequence 1 statements must carry `chain_root`, and
later v2 statements carry a signature-bound chain commitment only when
`chain_root` is present. Cross-checkpoint consistency requires the checkpoint
transparency verifier or a consistency proof.

### F3 (medium): the signed checkpoint body accepts unknown fields

`KernelCheckpointBody` is signed but does not reject unknown fields:

```59:61:crates/kernel/chio-kernel/src/checkpoint.rs
/// The signed body of a kernel checkpoint statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelCheckpointBody {
```

Compare the anchor batch body, which gets this right:

```44:46:crates/economy/chio-anchor/src/batch.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchorBatchBody {
```

Signed artifacts that tolerate unknown fields invite version-skew and
field-smuggling ambiguity between producers and verifiers.

*Fixed (2026-07-26).* `KernelCheckpointBody` and the `KernelCheckpoint`
wrapper both deny unknown fields, with rejection tests in the kernel and a
conformance negative
(`crates/tooling/chio-conformance/tests/checkpoint_statement_unknown_field_rejected.rs`).
Legacy v1 bodies without `chain_root` still parse and re-serialize
byte-identically, so stored signatures survive. New bodies carrying the field
use v2.

### F4: retention deletes checkpointed log entries

`crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs`
issues `DELETE FROM claim_receipt_log_entries WHERE entry_seq <= ?` for
checkpointed entries. An immutability trigger protects against unaudited
mutation, and pruning entries whose commitments are retained is a legitimate
design, but "append-only" as a public claim requires stating precisely what is
retained, for how long, and what a verifier can still check after pruning.

*Required:* a written retention contract that a verifier can reason about, not
a code change by default.

### F5: the verifier policy cannot express the append-only qualification

The declared verifier policy artifact exists and is enforced:
`chio.transaction.verifier-policy.v1`
(`spec/schemas/chio-transaction/v1/verifier-policy.schema.json`, implemented
in `crates/platform/chio-transaction-passport/src/verifier_policy.rs`)
declares required claims, omitted claims, and accepted transparency states.
But its `accepted_transparency_states` enum stops at `trust_anchored`, with no
`append_only` value, so a policy cannot require the property this program
exists to deliver. It carries no checkpoint key set, no witness quorum, no
freshness window, and no per-failure denial behavior, and the transparency
state feeding it is the string match of F2. The fourth gate condition cannot
be evaluated until the artifact can express it.

## 4. Ordered work breakdown

Strictly ordered. Each stage is independently valuable and none of stages 1
through 3 depends on a substrate choice.

**Stage 1: make the primitives real (blocks everything). Complete
(2026-07-26).**
Implement RFC 6962 consistency proofs in `merkle.rs` with test vectors; carry
node hashes in `CheckpointConsistencyProof` and verify them (F1); fix the
`trust_anchored` promotion to require cryptographic verification (F2); add
`deny_unknown_fields` to the signed checkpoint body (F3); and reject checkpoint
sets whose predecessor chain does not reach checkpoint 1. Scoped exports carry
that prefix instead of presenting an unresolved predecessor. Exit criterion,
met:
a tampered successor root fails verification in
`checkpoint_consistency_forged_chain_root_rejected.rs`, which fails loudly
against the pre-fix verifier.

**Stage 2: complete the commitment.**
Close claim-completeness and child-receipt-completeness. Child receipts are
already committed; the work is the proof surface and the projection scope:
emit inclusion proofs for child leaves (`collect_inclusion_proofs_for_export`
takes tool receipts only), add the tenant and capability join paths whose
absence makes scoped exports silently drop child receipts
(`OmittedNoJoinPath`), extend the claim-log projection beyond the two receipt
kinds it commits today, and bound the uncheckpointed tail with a time-based
flush (`max_batch == 0` currently disables checkpointing entirely). Write the
retention contract (F4). Exit criterion: a verifier holding a parent receipt
can enumerate and check every child commitment, or the parent is explicitly
marked incomplete.

**Stage 3: make the verifier policy able to express the gate.**
Extend `chio.transaction.verifier-policy.v1` with the qualification surface:
an `append_only` transparency state, accepted checkpoint keys, quorum
threshold, freshness window, and the denial behavior for each failure mode,
all fail-closed (F5). Exit criterion: two independent implementations reach
the same accept or deny verdict from artifact plus policy alone.

**Stage 4: witness cosigning.**
Adopt C2SP `tlog-checkpoint` and `tlog-cosignature`. This is the step that
converts discoverable equivocation into unpresentable equivocation. C2SP is the
only candidate evaluated that specifies a post-quantum cosignature at all
(ML-DSA-44, signed-note type 0x06), which is why it is preferred over Sigsum's
hard-wired Ed25519.

That is a direction, not a floor claim. `ReceiptCryptoFloor::PqRequired` admits
only `SigningAlgorithm::Hybrid`, which this tree defines as a classical
signature plus ML-DSA-65, and no ML-DSA-44 signer or verifier exists here;
checkpoints themselves are still issued through an Ed25519 keypair. Stage 4
therefore owes an explicit witness-algorithm policy and a checkpoint-signing
migration, and must not assume C2SP's standalone ML-DSA-44 already satisfies
the receipt floor. Exit criterion: a verifier rejects a checkpoint lacking a
valid quorum, offline.

**Stage 5: choose a publication substrate.**
Only now does this decision have consequences, and by this point stages 1
through 4 have made it cheap and reversible. Radicle remains a deferred
candidate under ADR-0018 with a documented carrier spec.

## 5. Standing invariants

These hold for anything built under this program, regardless of substrate.

- **The kernel signature is the only source of authority.** No substrate's
  native identity, threshold, or merge outcome is an input to a Chio accept
  decision.
- **Absence is never evidence.** Missing means unknown, never "does not exist"
  and never "not revoked".
- **Withholding degrades to denial.** Stale past the freshness window denies.
  Unavailability is never a silent accept.
- **Claims track capability, not roadmap.** The section 6.5 language relaxes
  only when a gate condition is actually met and tested, one tier at a time.
