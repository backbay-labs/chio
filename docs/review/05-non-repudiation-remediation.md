# Hole 5 Remediation Memo: Non-Repudiation and Transparency Log

## Problem

ARC currently presents signed receipts, Merkle checkpoints, and inclusion proofs
as if they jointly establish non-repudiation and an append-only transparency
log. They do not.

The current implementation proves a narrower statement:

- a receipt body was signed by the key embedded in that same receipt
- a batch of tool receipts was committed to a batch-local Merkle root
- a receipt can be shown to belong to that batch

That is useful operator-local audit evidence. It is not yet a trustworthy
transparency substrate with externally anchored key identity, append-only
continuity, anti-equivocation, global ordering, full child-receipt coverage, or
publication semantics strong enough to justify the current claims.

The gap matters because the repo and docs frequently speak in stronger terms:

- "non-repudiation"
- "append-only ledger"
- "every decision is signed and checkpointed"
- "Merkle-committed append-only log"

Those claims become defensible only after ARC grows from a signed audit log
into a real transparency system.

## Current Evidence

ARC already has several useful building blocks:

- `ArcReceipt` and `ChildRequestReceipt` are signed over canonical JSON.
- Tool receipts are persisted with monotonic local `seq` values in SQLite, and
  tool plus child receipts are projected into a unified local claim-log surface.
- `KernelCheckpoint` signs a Merkle root over a contiguous batch of tool
  receipts, and checkpoint persistence is now locally immutable and append-only.
- ARC derives local `log_id`, `log_tree_size`, predecessor-witness, consistency
  proof, and same-size fork-detection summaries from persisted checkpoints.
- Evidence export and Mercury proof packages now distinguish `audit` from
  `transparency_preview` claims and reject `append_only` claims without a
  declared trust anchor.
- Checkpoint publication records can now carry typed trust-anchor bindings, and
  `arc-anchor` verifies that a publication is backed by either a declared
  trust-anchor path or a successor witness chain.
- `arc-anchor` discovery now projects publication policy, current freshness,
  per-chain runtime state, and active conflict visibility for the bounded
  publication lanes.
- Inclusion proofs exist for receipts inside a checkpointed batch.
- Evidence export can bundle receipts, checkpoints, and inclusion proofs.
- Archive flows preserve tool-receipt checkpoints when the covered batch is
  fully archived.

The implementation also already exposes the main limitations:

- receipt verification trusts the embedded `kernel_key` instead of an external
  trust anchor
- checkpoint verification does the same
- checkpoint leaves and inclusion proofs now derive from the local claim log;
  child receipts with persisted canonical bytes can be sequenced into local
  checkpoints, but child receipt inclusion-proof export remains deferred unless
  the evidence package includes explicit child proof rows, and this still does
  not make the log public or independently anchored
- checkpoints now provide local prefix-growth continuity over checkpointed
  tool-receipt batches, not one externally anchored append-only log over the
  full claimed receipt family
- the distributed control plane is not a linearizable global sequencer
- the standards profile explicitly excludes witness networks and multi-region
  consensus
- the gap analysis explicitly says the receipt plane is still an operational
  audit plane, not a transparency service

In short: the repo has integrity primitives, not yet the full trust
distribution and append-only semantics implied by the stronger language.

## Why Claims Overreach

### 1. Embedded-key verification is not non-repudiation

If a verifier accepts a receipt because the receipt contains a public key that
matches its own signature, the verifier has only learned that "some holder of
this key signed this body." The verifier has not learned:

- whether the key belonged to an authorized ARC kernel
- which operator controlled that key
- whether the key was valid at the receipt timestamp
- whether the key was later revoked for compromise
- whether the same operator issued conflicting histories under different keys

Non-repudiation requires a trust chain. Embedded-key self-authentication is not
that chain.

### 2. Inclusion proofs are weaker than append-only proofs

The current Merkle path proves membership in one batch. It does not prove:

- that later checkpoints extend earlier checkpoints
- that no intermediate entries were deleted
- that the operator did not fork the log and show different histories to
  different verifiers
- that the checkpoint seen by one verifier is the canonical public checkpoint

Inclusion is necessary. It is not sufficient.

### 3. Batch checkpoints are not a global transparency log

ARC now derives local tree-head identity, tree-size, and consistency proofs
across checkpoint progression, but that is still not the same thing as a public
append-only log over the full claim tree. Without a single externally anchored,
claim-complete prefix-growing tree, ARC cannot honestly claim
Certificate-Transparency-like semantics.

### 4. No anti-equivocation story means no portable public truth

Today ARC can sign immutable local checkpoints and derive same-size fork and
continuity summaries, but it still does not publish checkpoints in a way that
lets external parties detect:

- same-size different-root forks
- conflicting successor chains
- missing publication intervals
- selective disclosure of one history to one verifier and another history to a
  different verifier

Without a witness or immutable external publication step, the system remains
operator-controlled audit evidence.

### 5. No strong global ordering means no strong ledger statement

The HA/control-plane story is not a consensus log. If ARC wants to claim one
append-only ledger across nodes, it needs one authoritative sequencing surface
with linearizable append semantics. Local SQLite order plus async replication
does not establish a globally ordered log.

### 6. Child-receipt coverage remains local-only

The repo signs child receipts and can now include persisted child-receipt
canonical bytes in local checkpoint ranges. That improves nested-work audit
coverage, but claims like "every decision is globally non-repudiable" remain too
strong until the checkpoint log is externally anchored and independently
reviewable.

### 7. Audit semantics are being described as transparency semantics

An audit log can be private, partially published, operator-controlled, and still
useful. A transparency log is stronger: it requires public or independently
reviewable continuity, verifiable trust anchors, and equivocation detection.
ARC should not claim the latter while only shipping the former.

## Target End-State

The correct target is not "slightly stronger checkpoints." The correct target
is a two-tier evidence model with explicit boundaries.

### Tier A: Audit Log Mode

This is the honest description of what ARC mostly ships today:

- signed local receipts
- local durable persistence
- batch-local checkpoints
- inclusion proofs
- operator-controlled exports and archives

This mode supports internal audit, compliance evidence, and bounded
operator-to-operator sharing. It does not justify strong public
non-repudiation or transparency claims.

### Tier B: Transparency Log Mode

This is the end-state required for the stronger claims:

- one named `log_id`
- one globally ordered append stream per `log_id`
- log sequence numbers assigned by a linearizable sequencer, not by eventual
  merge
- signed tree heads over the full prefix of the log, not just independent
  batches
- inclusion proofs and consistency proofs for every published checkpoint
- external trust anchors and signer-cert chains
- key rotation and revocation material in the verifier contract
- witness or immutable publication outside operator-only control
- anti-equivocation detection and proof
- full receipt-family coverage, including child receipts and other claimed
  decision artifacts
- proof packages that carry enough material for offline independent
  verification

When Tier B is implemented and qualified, ARC can truthfully claim something
like:

> ARC can prove that a trusted ARC log admitted a particular captured event into
> a published append-only checkpoint chain, that the chain is consistent with
> earlier published checkpoints, and that the event remained included in the
> observed history under the declared trust anchors and publication policy.

Even then, ARC should still not claim to prove real-world side effects beyond
its capture boundary.

## Required Ledger/Publication Changes

### 1. Replace batch-only checkpoint semantics with log-wide tree-head semantics

Introduce a canonical transparency checkpoint object, effectively a signed tree
head:

- `log_id`
- `tree_size`
- `root_hash`
- `issued_at`
- `signer_key_id`
- `signer_cert_ref`
- `prev_checkpoint_hash`
- `publication_profile_version`

This object must commit to the entire prefix `[1..tree_size]` of a single
logical log, not merely one isolated batch. Batch roots may remain as an
internal optimization, but they cannot be the primary public proof object.

### 2. Add consistency proofs between checkpoints

ARC needs a first-class proof family for append-only continuity:

- `consistency_proof(old_tree_size, new_tree_size)`
- verifier checks that checkpoint `new` is an append-only extension of
  checkpoint `old`
- proof APIs and proof-package formats must include this material where policy
  requires continuity

Without consistency proofs, ARC has membership proofs, not log-continuity
proofs.

### 3. Introduce one authoritative sequencer per `log_id`

To claim a global append-only log, ARC must pick one of two honest models:

- a single-writer transparency sequencer with documented availability limits
- an HA sequencer cluster with consensus-backed ordering

What ARC should not do is claim one global ledger while deriving ordering from
independent local writers plus background reconciliation.

Recommended path:

- implement a dedicated transparency sequencer service
- back it with Raft or another linearizable consensus substrate
- assign `entry_seq` and `tree_size` only after durable quorum commit
- treat locally created receipts as provisional until the sequencer admits them
  to the log

If this is too large for the near term, narrow the claim to per-node audit
evidence until the sequencer exists.

### 4. Unify all claim-bearing receipt types into one log-entry model

Introduce a canonical `LogEntry` envelope with a discriminated payload:

- `tool_receipt`
- `child_request_receipt`
- `control_event`
- future claimed artifacts only when they are also sequenced into the same log

This closes the current completeness hole. If ARC says every decision is signed
and checkpointed, every such decision must become a log entry with:

- one global `entry_seq`
- one inclusion proof
- one coverage rule in proof packages and archives

### 5. Make checkpoint persistence immutable

Checkpoint storage is now locally immutable and fail closed on conflicting reuse
of `checkpoint_seq`. That closes one prerequisite for stronger claim language,
but immutability alone is still insufficient for transparency semantics.

Required floor:

- inserting a different object for an existing `checkpoint_seq` is an integrity
  violation
- any replay or restore flow must use explicit recovery procedures and preserve
  prior publication facts

### 6. Separate local signing from public trust anchoring

Receipts may still contain the public key used to sign them, but verification
must not trust that key merely because it appears in the receipt.

Required trust-chain structure:

- offline or HSM-backed operator root
- log certificate for each `log_id`
- short-lived signer certificates for receipt/checkpoint issuance
- signed rotation records
- signed revocation records
- explicit validity intervals and key roles

Proof packages and verifier APIs must carry or resolve:

- the trust anchor
- the signer cert chain
- the applicable rotation/revocation state

### 7. Add publication records and external witness or immutable anchors

A checkpoint is not publicly meaningful until ARC can show how it was
published.

Add a canonical publication object:

- `log_id`
- `checkpoint_hash`
- `published_at`
- `publication_seq`
- `publication_location`
- `witness_record_ref` or immutable-anchor reference
- freshness window

Required externality:

- at least one publication or witness step outside operator-only mutable
  storage
- witness rejects conflicting checkpoints for the same `(log_id, tree_size)`
- verifiers can inspect witness material offline

Acceptable early forms:

- independent witness service with signed witness records
- immutable timestamping service
- blockchain anchor over checkpoint hashes or super-roots

What matters is not the specific anchor. What matters is that equivocation and
silent omission become externally detectable.

### 8. Add explicit anti-equivocation machinery

ARC should treat equivocation as a first-class protocol event.

Needed artifacts:

- `EquivocationProof` for two conflicting checkpoints under the same `log_id`
  and `tree_size`
- witness-side fork detection
- verifier-side fork rejection
- operator report and emergency pause on detected fork

Operational rule:

- no freshness or non-repudiation claim remains healthy while unresolved
  equivocation exists for that log

### 9. Add continuity and completeness semantics to proof packages

`Proof Package v1` or its successor should include:

- receipt or log entry
- checkpoint
- inclusion proof
- signer chain and trust-anchor material
- publication record
- witness or immutable-anchor record
- optional consistency proof from a pinned prior checkpoint
- explicit completeness declaration

For parent-child flows, the package must either:

- include all relevant child entries plus proofs, or
- include a signed completeness manifest that commits to the child-entry set
  and can itself be verified against the same log

### 10. Add archive-renewal and long-term verification rules

Long-lived evidence needs more than local SQLite retention.

ARC should define:

- archive package format with trust material included
- periodic re-anchoring or timestamp renewal policy
- crypto-agility migration rules
- verifier behavior for expired but historically valid signing certs

Otherwise the transparency story decays as keys rotate and external references
age out.

## Spec/Proof Changes

### 1. Split the spec into Audit Profile and Transparency Profile

The spec should stop collapsing these into one claim surface.

Recommended split:

- `ARC Receipts Audit Profile`
- `ARC Transparency Log Profile`

The audit profile covers:

- canonical receipt syntax
- local signatures
- local persistence
- batch exports

The transparency profile covers:

- trusted key bootstrap
- signer-chain validation
- log identity
- sequence and tree-head semantics
- inclusion and consistency proof algorithms
- publication and witness rules
- anti-equivocation rules
- freshness and completeness requirements

### 2. Narrow the meaning of non-repudiation

The spec should define the strongest honest statement:

- ARC proves what the trusted ARC capture and sequencing boundary observed and
  published
- ARC does not prove external world truth merely by hashing a payload

That wording should appear in the README, vision docs, compliance docs, and
proof-package docs.

### 3. Formalize the exact append-only proof model

The formal work should cover the log semantics actually claimed:

- RFC 6962-style inclusion proofs
- consistency proof soundness
- checkpoint hash chaining
- equivocation proof validity
- signer-chain validation model
- rotation/revocation admissibility rules

The main proof target should be a statement like:

> if the verifier trusts the declared trust anchor, accepts the signer chain,
> accepts the witness/publication policy, and validates inclusion plus
> consistency, then the verified entry belongs to the observed append-only
> history for that `log_id` and checkpoint set

This is a meaningful systems theorem. It is much narrower and more defensible
than claiming to formally verify the whole economic or operational stack.

### 4. Add machine-readable standards artifacts

Ship example artifacts for:

- tree head / checkpoint
- inclusion proof
- consistency proof
- publication record
- witness record
- equivocation proof
- trust-anchor record
- key rotation record

Verifiers and qualification suites should consume those fixtures directly.

## Validation Plan

### 1. Unit and property tests

Add deterministic tests for:

- tree-head construction over prefix-growing logs
- inclusion proof verification
- consistency proof verification
- equivocation proof detection
- immutable checkpoint persistence
- signer-chain validation
- key rotation and revocation handling

Add property tests for:

- append-only extension correctness
- proof rejection on reordered, omitted, or duplicated entries
- fork detection for same-size different-root checkpoints

### 2. End-to-end verifier tests

Build a standalone verifier contract and test:

- fresh proof package passes offline
- stale witness or missing publication fails closed
- embedded key without trusted chain fails closed
- child-receipt completeness failures fail closed
- archive packages remain verifiable after rotation

### 3. Distributed/fault-injection tests

If ARC claims HA transparency:

- sequencer failover preserves monotonic order
- no two leaders can assign conflicting `entry_seq`
- partitioned nodes cannot publish conflicting checkpoints
- stale leader publication is fenced off
- recovery does not rewrite published checkpoints

### 4. Adversarial transparency tests

Add explicit red-team scenarios:

- same `tree_size`, different `root_hash`
- hidden gap in publication
- checkpoint replaced after publication
- child receipt emitted but omitted from proof package
- witness sees one fork, verifier sees another
- revoked signer cert used after revocation cutoff

### 5. Operational qualification

Define qualification gates for:

- trust-anchor bootstrap
- key rotation and compromise drill
- witness outage behavior
- publication lag detection
- archive-recovery verification
- emergency pause on equivocation

No public non-repudiation claim should ship without passing that qualification
bundle.

## Milestones

### M0. Claim Containment

- Narrow README/spec/compliance language to audit-log semantics until stronger
  features land.
- Add an explicit "Transparency mode required" note wherever non-repudiation or
  append-only public ledger language appears.

### M1. Log Model Refactor

- Introduce `LogEntry` and unify tool receipts plus child receipts into one
  append stream.
- Add immutable checkpoint storage.
- Add `log_id`, `entry_seq`, and `tree_size` semantics.

### M2. Prefix Tree Heads and Consistency Proofs

- Replace batch-only public checkpoint semantics with log-wide signed tree
  heads.
- Implement consistency proofs and APIs.
- Update proof/export package formats accordingly.

### M3. Key Anchoring and Trust Distribution

- Add operator root, log certs, signer certs, rotation records, and revocation
  records.
- Update verifier to reject embedded-key-only verification.

### M4. Publication and Witness Layer

- Ship `Publication Profile v1`.
- Add external witness or immutable publication step.
- Add witness records and publication-gap monitoring.

### M5. Anti-Equivocation and HA Sequencing

- Add fork detection and `EquivocationProof`.
- If HA is claimed, move sequencing to a consensus-backed service.
- Fence off stale leaders and block conflicting publication.

### M6. Verifier, Formalization, and Release Qualification

- Ship the standalone verifier and machine-readable fixtures.
- Formalize inclusion/consistency/key-chain semantics.
- Gate strong public claims on passing the transparency qualification suite.

Current repo state:

- `M1` is partially real: the claim-log projection, immutable checkpoint
  storage, and local `log_id` / `tree_size` semantics exist, but the checkpoint
  tree is still driven by tool-receipt sequences rather than one unified
  claim-entry stream.
- `M2` is partially real: derived publications, predecessor witnesses,
  consistency proofs, and proof/export contract updates ship, but they still
  describe a local checkpoint chain over tool-receipt batches rather than a
  claim-complete public log.
- `M3` is only boundary-real: proof packages refuse `append_only` claims
  without a trust anchor, but ARC still verifies receipts and checkpoints with
  embedded keys and does not yet ship signer chains, rotation, or revocation
  material.
- `M4` is partially real: `audit` versus `transparency_preview` claims now
  exist, trust-anchor-bound publication records ship, and the bounded
  `arc-anchor` path now exposes publication policy, freshness, and witness or
  immutable-anchor requirements for the shipped lanes.
- `M5` is partially real: local same-log same-tree-size fork detection exists,
  and the bounded `arc-anchor` verifier now rejects conflicting publication
  chains for the same local log/tree-size view, but no broader externally
  reviewable anti-equivocation or HA sequencing story ships.

## Acceptance Criteria

ARC may truthfully use strong non-repudiation and transparency-log claims only
when all of the following are true:

- every claimed decision artifact, including child receipts, is sequenced into
  one named append-only log
- each log entry has a globally unique monotonic `entry_seq`
- published checkpoints are signed tree heads over full log prefixes
- verifiers can validate inclusion and consistency proofs offline
- checkpoint verification requires a trusted key chain, not an embedded key
  alone
- key rotation and revocation are part of the proof contract
- published checkpoints are immutable and externally witnessed or immutably
  anchored
- equivocation is detectable, representable, and fail-closed
- proof packages include publication and completeness semantics strong enough
  for offline review
- distributed deployments use a linearizable sequencer if they claim one global
  ledger
- the qualification suite includes fork, omission, replay, rotation, archive,
  and failover adversarial tests
- public docs distinguish captured-event truth from real-world side-effect truth

## Risks/Non-Goals

### Risks

- Stronger transparency semantics increase latency, operational complexity, and
  key-management burden.
- HA sequencing may require consensus infrastructure that materially changes the
  deployment model.
- Witness and publication services create new availability and recovery
  dependencies.
- Historical receipts may need migration or dual-format support.
- Long-term archive verification requires ongoing crypto-agility and renewal
  investment.

### Non-Goals

- Proving that a downstream tool really caused an external side effect in the
  physical or legal world
- Building a permissionless public gossip network in the first remediation
  phase
- Solving general multi-region Byzantine consensus beyond the needs of one
  bounded transparency sequencer
- Standardizing every downstream analytics or billing export on top of the log

The end-state should be a bounded, technically honest transparency system. If
ARC does not build that system, it should keep the current evidence plane and
describe it as an operator-local signed audit log rather than a full
non-repudiation substrate.
