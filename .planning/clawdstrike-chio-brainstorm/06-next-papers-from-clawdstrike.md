# Next Papers Chio Gains from Clawdstrike

The five-paper pipeline is derivable from the parent substrate alone. An OS-grounded sensor, executor, and deception layer changes what is provable. This memo proposes three new papers whose load-bearing claims require empirical OS material, then audits the existing pipeline for strengthening and redundancy.

## The papers that only exist because clawdstrike exists

### Paper N1. Programmable Sovereignty Over Reversible Action

**Target venue.** USENIX Security 2027 (full track, Feb 2027). CCS 2027 backup. The load-bearing artifact is a kernel-level executor with cryptographic bounds; this belongs at a systems-security venue, not a PL venue.

**Headline theorem.** Bounded executive action: for every response action enacted at an endpoint polity, the receipt subgraph rooted at the enactment contains a TTL declaration, a rollback receipt, and an acknowledgement receipt; absence of any within the declared TTL window forces denial under the polity's constitution.

**Supporting theorems.**
- Reversibility composition: rollback receipts compose with amendment-refinement, so the polity's history after rollback is admissible under both the pre- and post-amendment constitutions.
- Two-sided quorum on destructive class: enactment of a destructive action (process-tree termination, network isolation, irreversible quarantine) is admissible only as a treaty intersection between the device polity and an operator polity. The proof reduces human-in-the-loop EDR to bilateral admission.
- TTL monotonicity under partition: under a degraded sensor witness, the upper bound on TTL extension is bounded by the partition-contingency rank and never widens silently.

**What clawdstrike contributes.** A real response engine with twelve action variants, four of which already have OS executors (file quarantine via rename, persistence disable via rename, process-tree suspension via SIGSTOP, egress restriction via NE policy file). The receipt taxonomy distinguishes ResponseRequest, ResponseExecution, ResponseRollback, and ResponseAcknowledgement as separate families; the four-receipt grammar is the empirical anchor.

**What chio contributes.** The amendment-refinement theorem, the predicate language, the bilateral DSSE accept-set theorem, and the treaty-intersection construction. The bounded-executive grammar lifts to the substrate as a constitutional axiom plus three response-receipt predicates. Two-sided destructive-action quorum is exactly treaty intersection between a device polity and an operator polity, which the substrate already supports.

**Pipeline relation.** Replaces nothing; slots between Paper 2 (bilateral receipts) and Paper 4 (trajectory invariance). It is the missing systems-security paper that anchors the substrate to mutating-action semantics rather than read-only attestation.

**Hostile-reviewer risk.** A reviewer says: "you have re-stated an EDR vendor's response-engine design as five theorems." The defense: bilateral two-organization quorum on destructive action is a real reduction (human-in-the-loop is treaty intersection, not policy heuristic), and the rollback-amendment composition theorem is not in any prior EDR paper. Lead with the bilateral structure and the composition theorem; treat the TTL grammar as the operational instantiation. If the paper is led by the TTL grammar, it becomes a survey.

### Paper N2. Sensor-State-Conditioned Admission Under Partition Contingency

**Target venue.** NDSS 2028 (Jun 2027). NSDI 2027 backup if the network-extension verdict path is framed as distributed-systems rather than security.

**Headline theorem.** Sensor-degradation soundness: for every admitted receipt produced under a non-healthy sensor witness, the receipt evidence set contains a `ProviderDegradation` co-witness, and any replayer reaches the same verdict iff that witness is in the evidence set. Degraded admissions are never silent and never retroactively upgrade.

**Supporting theorems.**
- Decidable partition: the admission predicate on a healthy sensor state is constructibly distinct from the predicate on a degraded state under the same constitution. The two inhabit different ladder ranks.
- Quorum-degradation composition: under a degraded sensor witness, the partition-contingency mode never accepts an action that the quorum-required mode would reject under a healthy witness. Ladder ranks are mutually exclusive on the destructive class.
- Replay-stability under degradation: a receipt produced under degradation replays to the same verdict under a verifier without access to the original sensor, provided the degradation witness is in the envelope. This operationalizes the parent paper's manifest-stability claim for the degraded case.

**What clawdstrike contributes.** Every receipt carries an `EndpointSensorState` field and a separate `ProviderDegradation` family. The sensor-state field is empirical: macOS Endpoint Security and Network Extension both report runtime state. The four-mode privacy lattice (LocalOnly, HashesFeatures, SummaryWithReceipts, RawArtifactPermitted) is the second axis; selective disclosure projections compose with sensor degradation. Without the EDR's sensor model, "the kernel attests its own sensor state" is a theoretical posture; with it, the theorem is grounded in a struct that already exists in shipped code.

**What chio contributes.** The five-mode ladder, the ladder-floor stability theorem, and the bilateral admission grammar. The partition-contingency rank was a placeholder before the EDR existed; this paper turns it into a formal admission class with its own decidability obligation.

**Pipeline relation.** Slots between Paper 1 (v2) and Paper 4 (trajectory invariance). The current paper's threat model assumes the kernel is honest; this paper formalizes the next-stronger model where the kernel attests its own sensor state and the verifier can refuse on degraded.

**Hostile-reviewer risk.** A reviewer says: "your paper proves that a struct field saying `degraded=true` cannot be misread." The defense: the contribution is the partition between two admission predicates over the same constitution, plus the replay-stability theorem for the degraded case. Lead with the bilateral partition and the quorum-degradation composition, not the receipt-field inventory.

### Paper N3. Tripwire Predicates: Admission Whose Construction Is a Violation

**Target venue.** POPL 2028 (cycle ending Jul 2027) or OOPSLA 2027 (cycle ending Apr 2027). The contribution is a new predicate class with composition theorems, which belongs at a PL venue. CCS or USENIX Security backup if the empirical evaluation on real deception artifacts dominates the writeup.

**Headline theorem.** Tripwire collapse: any chain of capability attenuation that admits a tripwire predicate collapses to denial under the polity's constitution, regardless of the attenuation lattice. A tripwire admission is by construction a violation, not a finding to be ranked.

**Supporting theorems.**
- Tripwire-monotonicity: the tripwire set grows monotonically under admissible amendments. No amendment that preserves backward refinement can remove a tripwire from the constitution.
- Non-rollback of tripwire receipts: a tripwire admission receipt is amendment-invariant; rolling back a tripwire admission requires a constitutional axiom-set change, not a constitutional amendment.
- Deception faithfulness: for any honey-artifact placement and any actor that touches the honey artifact, the resulting receipt is admissible under the constitution if and only if it is a tripwire admission. The deception primitive and the predicate class agree on every receipt.

**What clawdstrike contributes.** Real deception primitives: HoneyArtifact placement, TouchedHoney receipt family, DeceptionMaterialization, DeceptionCleanup, and DeceptionRotation receipt families. The deception lifecycle is a separately-modeled set of receipt families with rotation and cleanup as first-class operations. Without an EDR substrate, "tripwire predicates" is a name for a predicate class with no extensional anchor. With the EDR substrate, every tripwire predicate corresponds to a placed artifact, a rotation cadence, and a cleanup obligation.

**What chio contributes.** The predicate ADT with a `denote` interpreter, the refinement relation, and the four refinement theorems in `PredicateLang.lean`. The new predicate class is an inductive extension of `Predicate` with a `Tripwire` constructor, plus three composition theorems. The amendment-refinement machinery from V4 and V5 lifts to monotonicity of the tripwire set.

**Pipeline relation.** Slots between Paper 4 (trajectory invariance) and Paper 5 (adversarial-replay benchmark). Tripwire predicates are an extension of trajectory invariance: the tripwire set is a particular kind of essential predicate that is preserved monotonically across amendments. The paper sharpens Paper 4 from "essential predicates are preserved" to "this particular essential-predicate subclass has a constructive correspondence to OS-level deception artifacts."

**Hostile-reviewer risk.** A reviewer says: "honey-tokens are forty years old; you have given them a Greek letter." The defense is that the contribution is not the deception primitive but the predicate class that makes a deception-artifact touch into a constitutional violation rather than a heuristic alert, plus the monotonicity theorem under amendment, plus the deception-faithfulness bridge between extensional and intensional admission. The paper must not lead with the deception engineering; it must lead with the predicate class and prove that the engineering is its faithful instantiation.

## Papers from the existing pipeline that get stronger because of clawdstrike

**Paper 1 (v2 of the current paper, NDSS 2027).** Gains a real evaluation section. The threat model section gains a sensor-degradation paragraph that names Paper N2 as the companion. The evaluation gains a real OS-grounded replay corpus (clawdstrike's existing 50-fixture corpus becomes a 1000-fixture corpus once endpoint receipts are translated into bilateral DSSE envelopes). The "buyer-closure" demonstration becomes a "buyer-closure plus endpoint-decision" demonstration where the bilateral receipts span vendor, endpoint, and verifier.

**Paper 2 (bilateral-receipt short paper, USENIX Security 2027 short).** Gains a second deployment example beyond MCP tool calls: cross-vendor endpoint admission. The accept-set theorem in `BilateralAccept.lean` is unchanged, but the short paper can cite both the agent-tool deployment and the endpoint-decision deployment as instances of the same theorem. The two-deployment framing pre-empts the reviewer who would say "your theorem applies to one deployment."

**Paper 4 (trajectory invariance, POPL 2028).** Gains a real example of an essential predicate that survives many real amendments. Clawdstrike's policy bundle has historical revisions (audit-mode to staged to block); the trajectory-invariance theorem becomes provable on a real amendment chain rather than a synthetic one. The empirical anchor strengthens the contribution from "this composes inductively" to "this composes inductively on a five-year policy history that exists."

**Paper 5 (adversarial-replay benchmark, USENIX Security 2027 full / NSDI 2027).** Gains a real adversarial-replay engine. Clawdstrike already operates a replay engine over receipt fixtures, with denial paths exercised on the same canonical schema. The benchmark paper now has a real adversarial corpus (degraded sensors, rotated deception artifacts, conflicting amendments under a colluding cosigner) rather than a synthetic one.

## Papers from the existing pipeline that get weakened or made redundant

**Paper 5 risk.** The adversarial-replay benchmark is the most exposed. If clawdstrike's replay engine is the empirical anchor, a reviewer may say the benchmark is a write-up of an EDR's replay test harness, not an academic contribution. The defense is to frame the benchmark as an evaluation methodology with statistical claims (corpus-coverage, theorem-discrimination, adversarial-resistance) that the EDR's replay harness does not make; the benchmark is the analysis of the harness, not the harness itself. If that framing cannot hold, fold Paper 5 into the v2 evaluation section of Paper 1 and drop it as a standalone.

**Paper 3 (Hart conditions (b)+(c)).** Unaffected. The Hart sociological study is about whether officials apply the rule of recognition and whether private citizens follow it; no EDR substrate changes that question. The paper's empirical anchor is qualitative interviews with operators and cosigners, not OS sensor data.

**No other paper is materially weakened.** Paper 1, Paper 2, and Paper 4 are each strengthened.

## The single highest-leverage paper to write

**Paper N1 (Programmable Sovereignty Over Reversible Action).** Three reasons.

First, it is the only paper in the union that fills a gap the parent paper explicitly names as future work: the bounded-executive-action grammar. Paper N2 and Paper N3 are useful extensions, but Paper N1 closes a structural hole the substrate has already declared.

Second, the bilateral two-organization quorum on destructive action is a real reduction. Human-in-the-loop EDR is the central operational practice of every existing endpoint product, and no existing paper expresses it as treaty intersection. The reduction is novel; the supporting theorems are not.

Third, the empirical evaluation is achievable. Four of twelve response-action variants have OS executors today; the remaining eight have either documented executor designs or rollback receipts. The paper does not require any new clawdstrike implementation, only a faithful formalization of what already exists, plus the bilateral construction on the substrate side.

Paper N1 is also the cleanest defense against the "this is just rebranding" critique. The bilateral construction is a contribution that the EDR alone cannot make: the formal substrate is required to express two-organization quorum as treaty intersection.

## Sequencing recommendation

The right order, given an estimated thirteen-month writing budget and the deadline calendar:

1. **Paper 2** (bilateral-receipt short paper) - USENIX Security 2027 short track, Feb 2026 deadline. Already gated by `BilateralAccept.lean`. The clawdstrike substrate adds a second deployment example with minimal cost. Ship first.
2. **Paper N1** (Programmable Sovereignty Over Reversible Action) - USENIX Security 2027 full track, Feb 2027 deadline. Twelve months of writing, including formalization of the rollback-amendment composition theorem.
3. **Paper 1** (v2 of current paper) - NDSS 2027, Aug 2026 deadline. Slots in parallel with Paper N1 writing. The v2 evaluation section cites Paper N1 as concurrent work; the threat-model section cites Paper N2 as future work.
4. **Paper N2** (Sensor-State-Conditioned Admission) - NDSS 2028, Jun 2027 deadline. Builds on Paper N1's bilateral grammar and Paper 1's v2 threat model.
5. **Paper 4** (trajectory invariance) - POPL 2028, Jul 2027 deadline. Already has a Lean proof and a real amendment chain from clawdstrike.
6. **Paper N3** (tripwire predicates) - POPL 2029 or OOPSLA 2028, depending on the deception-engineering writeup quality. Builds on Paper 4.
7. **Paper 3** (Hart conditions (b)+(c)) - Yale/Harvard JOLT, Q1 2027. Independent of the others; written in parallel by a single author.
8. **Paper 5** (adversarial-replay benchmark) - reconsider as standalone. Likely better as a v2 evaluation section of Paper 1.

Total: seven publications over thirteen months, three of them new because of clawdstrike, one of them (Paper 5) absorbed into another. The clawdstrike substrate increases the publishable surface by two papers net.
