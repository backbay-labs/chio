# Chio Research Memo: ZK Verification Over Signed Receipt Chains

Date: 2026-04-16

Related roadmap docs:
- `docs/POST_ROADMAP_ADDENDUM.md`
- `docs/POST_31_EXTERNAL_PROGRAMS.md`
- `spec/PROTOCOL.md`

## Scope

This memo covers a post-31 research track for layering zero-knowledge proofs over
Chio's existing signed receipts, receipt-lineage statements, and Merkle
checkpoints. It does not change Chio's current non-research thesis. The working
constraint is to keep signed receipts and checkpoint semantics authoritative,
then add ZK as an optional proof layer over that evidence.

## Bottom Line

ZK over Chio receipt chains is technically plausible, but only as a layer on top
of Chio's existing receipt and checkpoint plane. The most credible near-term
pattern is not a new signature scheme or a new receipt format. It is a proof
that an existing Chio verifier accepted a private set of signed receipts,
lineage edges, and checkpoint proofs, then produced a narrow public claim.

That makes this a research track, not a Phase 26 through 31 prerequisite:

- Chio's current thesis is already expressible through signed receipts,
  checkpointing, runtime correctness, qualification, and external evidence.
- ZK can compress or selectively disclose those results, but it does not create
  the non-research Chio thesis by itself.
- The hardest open work is not "can a proof be generated at all". It is how to
  bind Chio's current receipt semantics, append-only semantics, and verifier
  costs without introducing a second source of truth.

## 1. Feasible Architecture Patterns

### Pattern A: Proof over existing checkpoint membership and receipt validity

Keep Chio's signed receipts and checkpoint statements unchanged. A prover
privately holds:

- one or more signed Chio receipts
- any receipt-lineage statements or continuation tokens needed for the claim
- Merkle inclusion proofs into a Chio checkpoint or receipt-log view
- consistency proofs that connect a later checkpoint root to an earlier one

The ZK proof exposes only narrow public outputs such as:

- checkpoint root or checkpoint statement ID
- log size or checkpoint epoch
- a policy result such as "a valid receipt chain exists"
- a bounded aggregate such as count, amount cap, or rule satisfaction

This is the cleanest fit with the current Chio spec because it treats ZK as a
private verifier for already-issued evidence. It also matches the roadmap
boundary: Chio first needs stronger claim-complete checkpoint and receipt-family
semantics, then can prove predicates over them.

### Pattern B: zkVM proof of Chio verifier execution

Compile Chio's existing receipt verifier logic into a zkVM flow and prove that
the verifier:

- canonicalized receipt payloads correctly
- verified the receipt signatures
- checked lineage constraints
- verified checkpoint membership and consistency proofs
- evaluated a narrow predicate over the verified receipts

This is the strongest prototype path because it maximizes code reuse and avoids
hand-writing large custom circuits for JSON canonicalization, signature
verification, and proof checking. Recursive composition or aggregation can then
compress many receipt checks into one succinct proof.

### Pattern C: Dual-commitment acceleration without replacing signed receipts

Keep signed canonical-JSON receipts authoritative, but add a secondary
zk-friendly commitment index for proving efficiency. For example:

- the signed receipt remains the source of truth for normal Chio verification
- Chio derives a second commitment from the signed receipt payload
- the ZK proof works primarily over the secondary commitment tree
- the proof also binds that secondary commitment back to the signed receipt or
  checkpoint root

This can reduce proving cost, especially if Chio's existing JSON-plus-signature
pipeline is expensive inside a custom proof system. The risk is conceptual:
Chio would now have an authoritative signed form and an auxiliary proving form,
so the binding between them becomes security-critical.

### Pattern D: Aggregate proof bundles over receipt windows

Instead of proving one receipt chain at a time, Chio could prove statements over
bounded receipt windows:

- all receipts in a checkpoint window satisfy a policy predicate
- an aggregate metric was computed from included receipts only
- a disclosed report row came from a hidden but valid receipt subset

This is most useful for external proof bundles, privacy-preserving audit packs,
or regulator-facing reports. It is less useful for core product milestones,
because it depends on stable report semantics and claim-complete checkpointing.

## 2. Prerequisites And Unresolved Research Questions

### Hard prerequisites

- Chio needs claim-complete receipt and checkpoint semantics first.
  `spec/PROTOCOL.md` currently says checkpoints support `audit` and
  `transparency_preview` style claims, not full public append-only or strong
  non-repudiation semantics.
- Chio needs stable verifier inputs first.
  If receipt canonicalization, lineage rules, checkpoint leaf layout, or signed
  claim surfaces keep moving, any circuit or zkVM image will churn with them.
- Chio needs a precise public statement language first.
  The proof target has to be explicit: membership, continuity, bounded sum,
  policy satisfaction, or report derivation.

### Open research questions

- Should Chio prototype with a zkVM, a custom circuit, or a folding-based
  recursive system?
- Is proving receipt signature verification directly acceptable, or should Chio
  derive an auxiliary proving commitment after normal receipt issuance?
- How should Chio treat proof freshness, revocation, and receipt supersession?
- What privacy model is actually desired: selective disclosure, hidden
  aggregates, hidden lineage, or hidden counterparty details?
- What must be public for independent verification: checkpoint root, log size,
  verifier key, proof-system version, trusted-kernel set, and report schema?
- How does Chio prove completeness of a family or window instead of just
  membership of selected receipts?
- How should Chio handle algorithm agility without invalidating prior proofs or
  forcing verifier fragmentation?

## 3. Operational Risks And Verifier-Cost Tradeoffs

### zkVM route

Pros:

- reuses Chio verifier logic
- avoids bespoke circuit engineering for JSON and signature handling
- aligns well with proving "Chio verified this evidence" rather than inventing a
  new proof relation

Costs and risks:

- higher prover latency and hardware cost
- operational dependence on proof-generation infrastructure
- larger proofs unless recursively compressed
- more moving parts in CI, release qualification, and long-term reproducibility

### Custom-circuit route

Pros:

- potentially smaller proofs and cheaper verification
- more control over public outputs and disclosure boundaries

Costs and risks:

- highest engineering risk
- brittle under Chio protocol evolution
- JSON canonicalization, signature verification, and SHA-style hashing are poor
  places to start if the goal is fast iteration

### Dual-commitment route

Pros:

- may materially reduce proving cost
- can preserve the existing signed receipt as authoritative

Costs and risks:

- creates a new binding invariant that can fail
- raises claim-discipline risk if auxiliary commitments are described as if they
  were the same thing as signed receipt truth
- complicates qualification and external reviewer packs

### Append-only and witness risks

- A ZK proof can hide receipt contents, but it does not solve equivocation by
  itself. Chio still needs publication, witness-sharing, or monitor semantics for
  stronger append-only claims.
- Inclusion-proof fetching can leak verifier interest if the log or publication
  surface learns what specific receipt is being checked.
- Proof systems and recursion layers add version-management risk. If verifier
  keys, image IDs, or proving parameters churn, external review gets harder.

## 4. Why This Must Stay A Post-31 Research Track

- It is not required to establish the non-research Chio thesis.
  The addendum and post-31 program docs already separate product closure,
  external evidence, and research.
- ZK does not replace the need for claim-complete receipt semantics,
  qualification, portability evidence, or operator reliance evidence.
- The research surface crosses proof-system choice, hardware economics, privacy
  design, and long-term verifier maintenance. Those are poor milestone
  prerequisites for product closure.
- Chio should first prove the stronger non-research story with ordinary signed
  receipts, bounded checkpoint claims, external qualification harnesses, and
  external proof bundles.
- After that, ZK can strengthen privacy and compression properties over the
  evidence Chio already knows how to produce and qualify.

## 5. Doc-Ready Bullets

- ZK receipt proofs should layer over Chio's signed receipts and checkpoints, not
  replace them.
- The cleanest prototype path is a zkVM proof that Chio's existing verifier
  accepted a private receipt set and produced a narrow public claim.
- Recursive aggregation is relevant because Chio will likely need to compress
  many receipt checks into one verifier-friendly proof.
- Chio should not make ZK a roadmap prerequisite before Phases 26 through 31
  finish the non-research receipt, checkpoint, and qualification story.
- Chio's current checkpoint model is still bounded. Proving over it does not
  automatically upgrade Chio into a full public append-only transparency system.
- If Chio adds zk-friendly commitments for proving speed, the signed receipt must
  remain authoritative and the binding between the two forms must be explicit.
- The biggest risks are verifier-cost inflation, proof-system churn,
  equivocation not solved by ZK alone, and accidental creation of dual truth
  surfaces.

## Primary Sources

- Chio protocol and roadmap context:
  - `spec/PROTOCOL.md`
  - `docs/POST_ROADMAP_ADDENDUM.md`
  - `docs/POST_31_EXTERNAL_PROGRAMS.md`
- RFC 9162, Certificate Transparency Version 2.0:
  - https://www.rfc-editor.org/rfc/rfc9162
- RFC 8785, JSON Canonicalization Scheme:
  - https://www.rfc-editor.org/rfc/rfc8785
- Nova: Recursive Zero-Knowledge Arguments from Folding Schemes:
  - https://eprint.iacr.org/2021/370
- Halo Infinite: Recursive zk-SNARKs from any Additive Polynomial Commitment
  Scheme:
  - https://eprint.iacr.org/2020/1536
- Poseidon: A New Hash Function for Zero-Knowledge Proof Systems:
  - https://eprint.iacr.org/2019/458
- RISC Zero proof-system paper:
  - https://dev.risczero.com/proof-system-in-detail.pdf
- RISC Zero zkVM repository documentation:
  - https://github.com/risc0/risc0
- RISC Zero recursion module docs:
  - https://docs.rs/risc0-zkvm/latest/risc0_zkvm/recursion/
- SP1 documentation and crate docs:
  - https://docs.succinct.xyz/
  - https://docs.rs/crate/sp1-recursion-core/1.0.1
