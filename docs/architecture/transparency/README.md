# Transparency program: closing the section 6.5 append-only gate

- Status: Living index (proposed program, not yet scheduled)
- Date: 2026-07-25
- Scope: what Chio must build before it may describe its receipt log as
  append-only or claim strong non-repudiation
- Origin: the Radicle evaluation ([../../research/radicle/EVALUATION.md](../../research/radicle/EVALUATION.md)),
  which resolved into this program
- Decision context: [../../adr/ADR-0017-radicle-carrier-not-authority.md](../../adr/ADR-0017-radicle-carrier-not-authority.md)

## 1. Why this document exists

`spec/PROTOCOL.md` section 6.5 caps Chio's transparency claims against itself:

> Chio MUST NOT use public append-only or strong non-repudiation language until
> the published surface is claim-complete, child-receipt-complete,
> anti-equivocation-capable, and qualified under the declared verifier policy.

That cap is honest and it should stay until it is earned. A ten-agent
evaluation went looking for an external substrate that would lift it and found
that no substrate can: roughly 80 to 85 percent of the required work is
internal to Chio and is identical whether checkpoints are published to a
peer-to-peer git network, a C2SP witness quorum, a TUF repository, or a
directory served over HTTPS. Substrate selection is the last decision in this
program, not the first.

The single most consequential finding is item F1 below: the function named
`verify_checkpoint_consistency_proof` does not verify a consistency proof.
Until that is real, no publication or witnessing scheme built on top of it can
mean anything, because a witness would be cosigning a root whose relationship
to its predecessor is unconstrained.

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
committed tree, with no silent omissions. Today the checkpoint commits to a
batch range, and the honest description of what that proves is narrower than
what the word "complete" implies.

**Child-receipt-complete.** Nested and delegated flows must have their child
receipts committed, not just the parent. Otherwise a verifier confirming a
parent receipt learns nothing about what the flow actually did.

**Qualified under the declared verifier policy.** There must *be* a declared
verifier policy: a machine-readable statement of which keys, which quorum,
which freshness window, and which failure modes deny. Absent that, "qualified"
is unfalsifiable.

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

The root cause is one layer down: `crates/core/chio-core-types/src/merkle.rs`
implements RFC 6962 leaf and node hashing and `inclusion_proof`, and contains no
consistency-proof code at all. The word "consistency" does not appear in the
file.

*Required:* implement RFC 6962 `PROOF(m, D[n])` and its verifier in
`merkle.rs`, carry the node hashes in `CheckpointConsistencyProof`, and make
`verify_checkpoint_consistency_proof` check them against the two roots. Treat
the schema change as breaking and version it. Until this lands, F1 blocks every
other item in this program.

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

Anyone able to influence the evidence graph can obtain the strongest
transparency state Chio reports by supplying a node with the right label and no
valid contents. This inverts the fail-closed posture: an unverifiable input
produces the *most* trusted output.

*Required:* verify the inclusion proof against a checkpoint root signed by a
pinned key before returning `trust_anchored`; on any failure return the
preview tier, never the anchored tier.

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

*Required:* add `deny_unknown_fields` and add a round-trip rejection test.

### F4: retention deletes checkpointed log entries

`crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs`
issues `DELETE FROM claim_receipt_log_entries WHERE entry_seq <= ?` for
checkpointed entries. An immutability trigger protects against unaudited
mutation, and pruning entries whose commitments are retained is a legitimate
design, but "append-only" as a public claim requires stating precisely what is
retained, for how long, and what a verifier can still check after pruning.

*Required:* a written retention contract that a verifier can reason about, not
a code change by default.

### F5: no declared verifier policy artifact exists

There is no machine-readable statement of accepted keys, required quorum,
freshness window, or denial behavior. The fourth gate condition cannot be
evaluated without one.

## 4. Ordered work breakdown

Strictly ordered. Each stage is independently valuable and none of stages 1
through 3 depends on a substrate choice.

**Stage 1: make the primitives real (blocks everything).**
Implement RFC 6962 consistency proofs in `merkle.rs` with test vectors; carry
node hashes in `CheckpointConsistencyProof` and verify them (F1); fix the
`trust_anchored` promotion to require cryptographic verification (F2); add
`deny_unknown_fields` to the signed checkpoint body (F3). Exit criterion: a
tampered successor root fails verification in a conformance test that fails
loudly before the fix.

**Stage 2: complete the commitment.**
Close claim-completeness and child-receipt-completeness: commit child receipts
of nested and delegated flows, and specify exactly what the tree commits to.
Write the retention contract (F4). Exit criterion: a verifier holding a parent
receipt can enumerate and check every child commitment, or the parent is
explicitly marked incomplete.

**Stage 3: declare the verifier policy.**
Define the policy artifact: accepted keys, quorum threshold, freshness window,
and the denial behavior for each failure mode, all fail-closed (F5). Exit
criterion: two independent implementations reach the same accept or deny verdict
from artifact plus policy alone.

**Stage 4: witness cosigning.**
Adopt C2SP `tlog-checkpoint` and `tlog-cosignature`. This is the step that
converts discoverable equivocation into unpresentable equivocation. C2SP is the
only candidate evaluated that natively defines ML-DSA-44 cosignatures and
therefore survives `ReceiptCryptoFloor::PqRequired`; Sigsum is hard-wired to
Ed25519 and fails the same floor Radicle fails. Exit criterion: a verifier
rejects a checkpoint lacking a valid quorum, offline.

**Stage 5: choose a publication substrate.**
Only now does this decision have consequences, and by this point stages 1
through 4 have made it cheap and reversible. Radicle remains a deferred
candidate under ADR-0017 with a documented carrier spec.

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
