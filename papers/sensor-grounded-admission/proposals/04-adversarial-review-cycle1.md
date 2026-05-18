# Adversarial Review (Cycle 1)

## Single most damaging finding

**§4 prose claims the headline proof "inducts on the provider list" and "discharges the membership check." The Lean proof does no such thing.** Line 36 of `04-model.tex` states: "The case analysis on the attestation constructor is not definitional unfolding; it requires inducting on the provider list and discharging the membership check." The Lean (lines 350-378) destructs the body hypothesis, instantiates the existential with two fixed witnesses (`healthyWitness decl` and `degradedWitness`), and discharges each branch with `unfold + rw + rfl` or `unfold + rw + simp`. The "induction on the provider list" lives inside two supporting lemmas, both of which are one-step (`List.all_eq_true`, a `cases h` split on nil/cons). The headline itself does not induct.

Worse: the headline is structurally a Σ-construction that fixes the empty attestation as the degraded witness. The §1 promise of "two receipts sharing identical body bytes whose distinct attestations discharge to opposite verdicts under one constitution" is true but vacuous (the trivial choice of all-healthy vs empty suffices). The interesting claim, that the predicate reliably separates the healthy and degraded space across realistic attestations, is not proved. A formal-methods reviewer opens the Lean and walks away.

Companion: §9 line 25 says "the proofs require finishing case analyses on the attestation constructor and a worked example for the headline theorem." STATUS.md says the proofs compile with no `sorry`. §9 lies about proof status.

## Critical findings (formal-methods reviewer)

**F1. Σ-construction theorem framed as separation.** The headline existential over `(r, a_h, a_d)` is satisfied by `(any body, healthyWitness decl, empty)`. It tells the reader nothing the prose definition does not already promise. The stronger separation ("for every degraded attestation that fails coverage, some healthy attestation discharges to true on the same body") is not stated and not proved.

**F2. `h_body` premise is unconstructable.** `bodyPredicates : List (ReceiptId -> Bool)` (line 130) carries opaque function values. The headline premises `∃ r, bodyAdmits c r = true`. For any concrete constitution with a non-trivial body predicate, this existential is opaque to construction; the theorem holds vacuously when `c.bodyPredicates = []`. The same constructor-preconditions-as-theorem trap from the parent paper survives.

**F3. Theorem 3 is still inert.** `_h_destructive` (line 468): the underscore is the giveaway, and STATUS.md admits it. §4 line 53's prose ("a destructive admission predicate that fires under a degraded substrate is not well-formed") is not what the Lean proves: the Lean proves any admitted receipt has required-set coverage, destructive or not.

**F4. Theorem 4 admits trivial relaxation amendments as "structural improvement."** A polity that amends to an empty required set trivially makes every prior-partition-contingency attestation discharge to non-partition-contingent. The theorem says nothing about why the amendment itself was sound. The parent paper's `amendment_admissible_iff_backward_refinement` is invoked in §8 but not composed with the re-attestation theorem anywhere.

## Critical findings (systems reviewer)

**S1. Bilateral cosignature party-independence problem.** §3 line 18: "the attestation is signed by the same key that signs the receipt body." §3 line 21: "every cosigner's attestation [must] cover the required set." If both cosigners use one signing key for both body and attestation, the cosigner attestation provides no marginal trust over the body-signing one. §9 acknowledges single-key signing for the unilateral case but does NOT acknowledge that quorum-required admission is admission-theatrical when neither cosigner's attestation key is independent of its body-signing key. New attack the prior review did not flag.

**S2. §3 binary-state model has no flapping paragraph.** The research note `sensor-flapping-models.md` lays out the patch (cite Cardenas-Amin-Sastry 2008, Hayashibara phi-accrual 2004, Mitchell-Chen 2014, SAIN USENIX Security 2024; add discretization-choice paragraph in §3; add within-window-flapping limitation row in §9). Neither has been applied. §3 still presents the four-flag model as if a 99.7%-delivery sensor maps cleanly to healthy/degraded. The decision window is not in the schema; the contribution does not narrow the gap an ICS/SCADA reviewer cares about.

**S3. §6 empirical chapter exercises validator self-consistency, not substrate behavior.** The load-bearing test signs a synthetic receipt with hand-constructed flags, perturbs each, asserts denial. The mutation rejection rate is a property of the validator code; it does not measure real-world admission rates, drop counts, or latency. §6 contains zero numbers about real substrate operation. That is not an evaluation.

**S4. §5 emitter-population paragraph is fatal to the headline framing if a reviewer cross-reads.** §3 line 4 reads "every receipt embeds a signed attestation" but §5 line 19 admits 13 of 19 emitter sites use a one-record `single_active_agent("agent-api")` constant. The placeholder is "admitted under identical rules." Either §4 needs a theorem that the admission predicate can reject the placeholder class (and a constitution that does so), or §3 needs to retract "every receipt." Neither has been done. The polity is, on the §5 admission, admitting receipts whose sensor-state claim is vacuous.

## Critical findings (threat-model reviewer)

**T1. Cross-vendor treaty admission is unresolved.** §7 line 11 claims the headline composes with bilateral admission; §9 line 22 recommends the union of required sets as the structural default. Two polities with disjoint required sets produce a union no single kernel can satisfy. The prior review flagged this (finding 16); §9 names the dilemma but does not resolve it. "Use the union" is not an operational answer when the union is empty of feasible kernels.

**T2. Out-of-band auditor remains unnamed; strict-strengthening claim hangs on its existence.** §1 line 12 / §10 line 8 claim the strict strengthening unconditionally; §3 / §9 condition it on an unnamed auditor whose disagreement is itself a signed artifact. Promise/delivery gap. The honest fix is to state in §1: "the strengthening is conditional on the existence of an out-of-band sensor-coverage auditor; the auditor is the structural complement of this work."

**T3. Clock attestation is kernel-controlled, full stop.** A kernel can backdate the captured-at timestamp to a moment when a since-decayed sensor was healthy. The constitution can declare a max age, but the constitution-evaluator reads the kernel's own captured-at. Self-referential. §9 hedges; no out-of-band timestamp witness is proposed. Same single-key failure mode at the time axis.

## Critical findings (related-work reviewer)

**R1. The eBPF / auditd / eAudit research has not landed in §8.** The §8 EDR paragraph names auditd and Apple ES as "data sources EDR systems consume" but does not cite Sekar 2024 eAudit (IEEE S&P), Falco / Tetragon, or Sadeghi-Stüble NSPW 2004 property-based attestation. The research note's recommended bibtex stubs sit unused. A kernel-observability reviewer sees a gap.

**R2. §8 TEE paragraph still cites secondary anchors, not primary specs.** The research note `tee-attestation-delta.md` recommended primary-source bibkeys (Intel TDX 348549-002US, AMD 56860 r1.58, Apple security-pcc proto Oct 2024, RFC 9334, NIST SP 800-155, Arm CCA realm token draft). §8 still cites `chengTDXDemystified2024`, `amdSEVSNP2020`, `applePRA2024`, `armCCA2023` (secondary surveys). The recommended framing pivot from "code vs sensors" to "what surveyed wire formats structurally cannot express" (per section 9 of the TEE note) has not been applied. The §8 framing is one phase behind the research.

**R3. `draft-moriarty-rats-posture-assessment-00` not engaged.** The IETF RATS posture-assessment draft is more directly competitive with the paper's runtime-state attestation claim than any TEE wire format. Not citing it leaves the paper open to a "you missed the most adjacent IETF work" objection.

## Voice leaks

**V1. "The previous arrangement" persists across §3, §4, §7 (three instances), §10.** Prior review flagged this (line 49 of `01-adversarial-review.md`). Project-history phrasing dressed as theory talk. Survives.

**V2. §6 line 9 cites the test by project-internal path: `endpoint_sensor_state_receipt_binds_provider_health` in `clawdstrike-policy-event::edr`.** A reviewer asks what `clawdstrike-policy-event::edr` is and why it is load-bearing; the name is internal. Describe the verifier discipline without naming the test file.

**V3. §5 line 10 and §6 line 18 cite filesystem paths inside the paper** (`crates/chio-chiodos-runtime/src/admission_hook.rs`, `apps/agent/src-tauri/macos/system-extension/endpoint-security`). Engineering-meta. A research paper does not cite filesystem paths.

**V4. §9 line 25 ("Lean proofs require finishing case analyses") is stale and engineering-meta.** STATUS.md says the proofs compile.

**V5. §9 line 31 ("the substrate's schema is published") survives unchanged.** Prior review flagged. Either name where or remove.

## Novel attacks I'm adding

**N1. Wire-compatibility amendment-cycle paradox.** §5 line 22 introduces a compatibility predicate that admits pre-extension receipts in observation mode only. §9 line 19 says this should be retired by an amendment narrowing admission to extension-bearing receipts. But the parent paper's `amendment_admissible_iff_backward_refinement` requires every amendment to be a refinement of the old predicate. The wire-compatibility predicate's introduction is itself an amendment that ADDED admission lanes (pre-extension receipts that the post-amendment predicate denies). Either the parent-paper amendment-refinement was violated, or the compatibility predicate was always implicitly present. The paper does not address this.

**N2. The empty-attestation degraded witness is not producible on the wire.** §3 line 4 ("every receipt embeds an attestation") plus §5 line 22 (the compatibility predicate denies attestation-block-absent receipts) mean the empty-list attestation never reaches the validator on the wire. The Lean's `degradedWitness = ∅` is a mathematical witness, not a producible counterexample. The headline theorem proves separation between a body-pair the polity admits (full attestation) and one it rejects (empty attestation that cannot be wire-emitted). Trivial. A real reviewer wants: an attestation whose three healthy and one degraded providers produce a denial against the same body that two healthy and zero degraded admits. Not stated, not proved.

**N3. §7 alignment-evaluation paragraph is contribution drift.** "An attested model that reports its own activation profile" introduces a different topic in a different field, no model, no citation. Recommend cut.

## What survives the worst critique

After everything:

1. The §3 four-flag schema with drop and miss counts plus a clock record is a coherent wire format, defensible against RFC 9334 framing.
2. Theorem 2 (`partition_contingency_mode_iff_degraded_subset`) is a real proper-sublist biconditional with real list-induction work (`filter_sublist` + `length_le` + `eq_of_length`). Cleanest piece of the contribution; survives all scrutiny.
3. The §4 worked example with `endpointSecurity` + `networkExtension` is concrete enough that a reader follows the predicate evaluation by hand.
4. The §8 placement argument vs TEE attestation survives, modulo the citation upgrade R2 requires.

Everything else is conditional. The headline existential survives but the surrounding prose overpromises what it shows. The empirical chapter survives only as a verifier-self-consistency note.

## Minimum patch to make the paper publishable now

**Priority 1, headline framing honesty pass.** Rewrite §1 line 18 / §10 line 6 from a structural-separation claim to a Σ-construction claim. Cut or qualify §4 line 36's "induction on the provider list" claim. Delete §9 line 25 (stale per STATUS.md). Add the stronger separation as a corollary, not the headline.

**Priority 2, land deferred research-note patches.** Add §3 discretization-choice paragraph (Hayashibara 2004 / Cardenas 2008 / Mitchell-Chen 2014). Add §9 within-window-flapping limitation row. Add Sekar 2024 / Falco / Tetragon / Sadeghi-Stüble to §8 EDR paragraph. Swap §8 TEE secondary citations for primary-source bibkeys (Intel TDX 348549-002US, AMD 56860 r1.58, Apple PCC proto, Arm CCA draft, RFC 9334, NIST SP 800-155, draft-moriarty-rats-posture-assessment-00). Rewrite TEE framing from "code vs sensors" to "what surveyed wire formats structurally cannot express."

**Priority 3, voice leak pass.** Strip "the previous arrangement" from §3, §4, §7, §10. Cut filesystem-path citations in §5 / §6. Cut §9 line 31 stale "schema published" hedge. Cut or rewrite §7 alignment-evaluation paragraph.

After Priority 1+2+3 the paper is honestly framed, has its research-note patches applied, and ships as a 16-page CSF / RAID / HotSec submission with one substantive theorem, one worked example, and a defensible contribution boundary. The remaining structural gaps (single-key signing, no out-of-band auditor, placeholder emitter class) are honest limitations that survive the patch but do not block submission.

---

(1) Single most damaging finding: §4 prose claims the headline proof inducts on the provider list; the Lean proof instantiates two fixed witnesses and discharges with `unfold + rw + rfl`. The headline is a Σ-construction over the trivial witnesses, not a structural separation. (2) Verdict: needs patch. Structural contribution is real but the headline is overclaimed. (3) Top-3 priority items: rewrite §1/§4/§10 headline framing as Σ-construction not separation; land the deferred research-note patches (§3 discretization, §9 flapping, §8 primary-source TEE/eBPF citations); voice leak pass on "previous arrangement", path citations, and §7 alignment-evaluation paragraph.
