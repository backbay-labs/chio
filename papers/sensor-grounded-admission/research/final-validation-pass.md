# Final Validation Pass (cycle 3 RESEARCH)

End-to-end audit of the paper against its supporting evidence. The strongest residual is documented under "Top finding"; secondary findings appear in their pass sections and are ranked at the end.

## Top finding

**The N1 amendment-cycle disambiguation sentence promised by cycle-2 REVIEW priority 3 was never added.** Cycle-3 FIX deleted §5's wire-compatibility paragraph and §9's schema-versioning row (the visible symptom), but never added the one disambiguating sentence cycle-2 review called for: "The sensor-attestation construction is a fresh constitution, not an amendment of the parent paper's body-only constitution; the backward-refinement obligation applies to amendments within the new constitution, not to its introduction."

What remains in the paper is §8:23, which reads the construction AS an amendment of the parent: "\thm{amendment_admissible_iff_backward_refinement} gains a paired re-attestation obligation, as Section~\ref{sec:model} establishes." If the new construction is an amendment to the parent's body-only constitution, then by the parent's `BackwardRefines` predicate it must not widen admission. Adding a required-set conjunct strictly narrows admission so backward-refinement holds, but the paper never says this. A reviewer who knows the parent's amendment ledger reads §8:23 and asks "where is the backward-refinement witness?" Cycle-3 fixed the visible symptom and left the underlying construction-vs-amendment ambiguity unresolved.

This is the strongest cycle-3 hit because it survives all four cycle-2 closure items and lives at the inheritance boundary with the parent paper.

## Theorem-name consistency

Strict scope (paper.tex + sections/*.tex + lean/*.lean): zero hits for the old name `admission_under_degraded_state_distinguishable_from_healthy`. Publication-targeted artifacts are clean.

Broader scope: `lean/STATUS.md:15`, `lean/build-log.md:88`, `theorems.lean:229`, `README.md:17` still carry the old name. STATUS.md is the audit anchor for the formal claims; its section title contradicts its own body discussion. `theorems.lean` at paper root is a `:= sorry`-stubbed draft pre-dating `lean/SensorGroundedAdmission.lean`, still with old name and `sorry`. Two Lean files in the same directory, one stubbed and one proven, with different theorem names, is a packaging hazard. If `lean/` ships as supplementary material (USENIX norm), this drift is visible.

## Arithmetic consistency

All four mentions agree: §1:21 ("six host-snapshot emitter sites out of nineteen surveyed, with the remaining thirteen covered by a placeholder"), §5:19, §6:12, §10:6. 6 + 13 = 19 is internally consistent. §5's enumeration of 8 placeholder receipt families across 13 sites is plausible and not separately auditable from the paper alone.

## Citation grounding (12 spot-checks)

1. **sailerTCGIMA2004 (§2:18, §2:21).** §2:21's "load-time integrity measurement on a TCG root" matches precisely. §2:18's "kernel callouts and code-signature evidence" is loose; IMA is load-time hash-chain, not runtime kernel callouts. Joint cite with `linuxAuditSubsystem` (which covers callouts) is defensible.

2. **haldarSemanticRemoteAttestation2004 (§2:21).** Exact match for "lifts attested object from which code to which property."

3. **cokerPrinciplesRemoteAttestation2011 (§2:12, §2:21).** Five principles including trustworthy mechanism; matches.

4. **intelTDXSpec2023 (§3:21, §9:22).** Bib entry is "TDX Module Base Architecture Specification 348549-002US." §3:21 claims this anchors "Intel TDX Quoting Enclave keys are signed by a Provisioning Certification Key derived from fused secrets." Spec covers TDREPORT generation inside the TD module; the QE/PCK signing flow is in Intel's separate Quoting Service / DCAP documents. Citation half-covers the claim. **Minor finding.**

5. **amdSEVSNPSpec2025 (§3:21, §9:22).** Pub 56860 r1.58 does describe VCEK and ATTESTATION_REPORT signing. Correct.

6. **applePlatformSecurity2024 (§3:21).** SEP/UIK/PKA discussion exists in the platform-security guide. Correct.

7. **rfc9334RATS (§3:21, §9:22).** RATS Architecture covers Attester/Verifier and key-certification chain. Correct.

8. **saroiuTrustedSensors2010 (§8:8).** Founding hardware-sensor-signs-reading construction. Correct.

9. **liuTrustedSensors2012 (§8:8).** OS abstractions for trusted sensor consumers. Correct.

10. **asokanSEDA2015 (§8:8).** Collective embedded-device attestation. Correct.

11. **sekarEAudit2024 (§8:14).** Audit-pipeline event-loss motivation, eBPF replacement. Correct.

12. **chioProgrammableSovereignty2027 (§8:23).** Parent paper. Composition claim holds at Lean type signatures. The "amendment_admissible_iff_backward_refinement gains a paired re-attestation obligation" framing is the N1 source (top finding).

Lean theorem ↔ STATUS.md / paper prose consistency: §4:36 honestly says "headline does not induct over the provider list; it instantiates two fixed witnesses." §4:53 acknowledges Theorem 3's destructive-family hypothesis "does not appear in the proof body." §4:56 (Theorem 4) describes the structural-improvement claim but does NOT acknowledge that `_h_prev_decl` is also inert (per STATUS.md line 129); §9:28 mentions only Theorem 3's inert hypothesis. Cycle-2 F-C2-2 (two-of-four inert binders) is half-closed.

## Inherited limitations audit (parent paper §9 rows)

- **Trust-store-honest / substrate-honest**: §1:6 inherits and reframes as the retired row. Acknowledged.
- **Cosignature party-independence ("two-key DSSE under a single actor collapses to one-of-one")**: §3:27 and §4:53 invoke cosigner attestations under quorum-required admission, but §9 never acknowledges that the parent's cosigner-collapse residual carries through. Cycle-2 S-C2-2 (heterogeneous-trust cosignature) is downstream. **Inherited and unacknowledged.**
- **Lean theorem inventory maintained with code**: No inventory-mapping paragraph in the paper. The parent's "stale inventory" residual implicitly carries. **Inherited and unacknowledged.** Minor.
- **Public witness verification**: Out of scope.
- **Backward-refinement amendment**: §3:15, §4:55-56, §8:23 invoke it. Partially acknowledged, but the N1 ambiguity (top finding) leaves the residual unresolved.
- **Schema evolution across vendor kernels**: Parent paper line 44. Cycle-3 FIX deleted §5's wire-compatibility paragraph and §9's schema-versioning row. The sensor-grounded paper adds new wire fields (provider records, clock records) with no schema-evolution discussion. The parent-paper inheritance was not transferred. **Inherited and now silently unacknowledged.**
- **Cryptographic-suite migration / PQC**: Adding a new attestation field widens the PQC migration surface. §9 does not acknowledge. Minor.
- **Operational observability**: §9:30-31 explicitly acknowledges. Correct.

## §1 ↔ §10 audit

§1:14-22 promises five contributions; §10:6 delivers all five in matching order.

- Bullet 1 (headline) → §10 sentences 1-3. Match.
- Bullet 2 (partition-contingency biconditional) → §10 sentence 4. Match.
- Bullet 3 (destructive-admission projection) → §10 sentence 5. Match BUT §10 drops "three-conjunct shape" qualifier present in §1:19, reading slightly stronger. Minor stylistic drift.
- Bullet 4 (amendment-improvement) → §10 sentence 6. Match.
- Bullet 5 (six-of-nineteen implementation) → §10 sentence 7. Match.

§10 does not claim anything §1 does not promise. §1:12's future-work pointer to `Section~\ref{sec:conclusion}` for the sensor-coverage auditor resolves obliquely: §10:8 acknowledges the auditor as future work but §10:10's "natural continuation" bullet lists per-tenant, time-windowed, and behavioral-attestation extensions without explicit auditor mention. Resolved but not tight.

## Findings ranked by severity

**Blocker**: none. All cycle-2 priority-1 items closed.

**Major**:
1. N1 amendment disambiguation sentence missing (top finding). Cycle-2 REVIEW priority 3 half-addressed; symptom deleted, cause remains in §8:23.
2. Cosignature party-independence inheritance unacknowledged in §9. Parent §9 has the residual; sensor-grounded §9 inherits silently.

**Minor**:
3. `lean/STATUS.md:15`, `lean/build-log.md:88`, `theorems.lean:229`, `README.md:17` still carry the old Theorem 1 name. Companion-doc drift; reviewer with formal-methods background reads STATUS.md.
4. Theorem 4's `_h_prev_decl` inert binder undisclosed in §9:28. Cycle-2 F-C2-2 half-closed.
5. `theorems.lean` at paper root: old name and `sorry`-stubs. Either mark stale or delete.
6. Schema-evolution inheritance from parent §9 line 44 not transferred after cycle-3 deletion of local wire-compat paragraph.
7. Theorem-inventory discipline (parent §9 line 22) not acknowledged.
8. intelTDXSpec2023 citation half-covers the §3:21 PCK/QE signing claim; full claim is in Intel's adjacent Quoting Service / DCAP docs.

**Nit**:
9. §10:6 drops "three-conjunct shape" qualifier present in §1:19; same theorem, slightly stronger framing in §10.
10. §1:12 future-work pointer to §10 resolves obliquely rather than exactly.
11. §6:18's "ES does not call es_new_client; ... drop and miss counts present" reads as an internal contradiction at first scan (resolved as synthetic in-memory recorder, but the resolution is one sentence later).

## What the paper genuinely does well

The §4 mechanized model is honest about what each theorem proves. The cycle-3 honesty pass at §4:36 ("the headline itself does not induct over the provider list; it instantiates two fixed witnesses and rewrites") is the kind of self-correction reviewers reward. STATUS.md's per-theorem inert-binder disclosure carries through to §4:53 ("does not appear in the proof body"). The Lean file compiles, axioms are standard, every theorem has a worked proof.

The §3 TEE-rooted attestation paragraph and §9 attestation-key-isolation row (cycle-3 additions) close S1 cleanly at the prose level. The hardware-root-of-trust extension axis is named with primary-source citations (Intel TDX, AMD SEV-SNP, Apple SEP, TPM 2.0); the §9 row reads as contribution boundary rather than self-criticism precisely because §3 has the parallel TEE paragraph.

The §8 TEE-vs-sensor-attestation framing ("what surveyed wire formats structurally cannot express") is novel and well-supported. Five primary-source wire-format citations ground the claim that no surveyed format expresses per-sensor drop/miss counts.

The §3:24 within-window-discretization paragraph and §9:16 flapping row honestly bound the categorical-state assumption. Phi-accrual is cited as the future-work alternative.

The §4 worked example (response-execution family with `endpointSecurity` + `networkExtension` providers, healthy attestation vs empty attestation against same body) is concrete enough that a reader can hand-evaluate the predicate.

Theorem 2 is real structural work in both directions of a biconditional. `List.filter_sublist` + `Sublist.length_le` + `Sublist.eq_of_length` is the load-bearing formal piece of the paper and survives any hostile reading.

## Recommended REVIEW phase intake

The cycle-3 adversarial REVIEW should attack first:

1. **The N1 amendment ambiguity (top finding).** §8:23 reads the construction as an amendment of the parent's `amendment_admissible_iff_backward_refinement`. Either the construction is an amendment (and needs a backward-refinement witness somewhere) or it is a fresh constitution (and §8:23 needs rewording). Cycle-3 deleted the visible inconsistency but did not add the disambiguating sentence cycle-2 prescribed. Single strongest hit a final adversarial reviewer can land.

2. **Cosignature party-independence inheritance.** §3:27 and §4:53 invoke cosigner attestations under quorum-required admission. Parent §9 carries "two-key DSSE under a single actor collapses to one-of-one." Sensor-grounded paper inherits the collapse silently. A heterogeneous bilateral treaty between a TEE-rooted polity and a single-key polity gets weakest-cosigner strength; §7:11's "strictly tighter" claim does not address the asymmetric case.

3. **Theorem 4 inert binder.** §9:28 mentions Theorem 3's `destructiveAdmissionFamily` is inert; does not mention Theorem 4's `_h_prev_decl` is also inert (per STATUS.md). Two of four supporting theorems carry decorative hypotheses; the paper acknowledges one.

4. **Companion-document drift.** STATUS.md, build-log.md, README.md, and theorems.lean still carry the old theorem name. If `lean/` ships as supplementary material, the rename is visibly incomplete.

A REVIEW agent that lands all four has strong cycle-3 closure material. None individually is a blocker; together they document residual structural debt at the boundary between paper-targeted prose and companion artifacts, and at the inheritance boundary with the parent paper.

---

Top finding, count, verdict: (1) **N1 amendment-cycle disambiguation sentence missing — cycle 3 deleted the symptom but §8:23 still reads the construction as an amendment of the parent, and no backward-refinement witness is supplied or excused.** (2) **0 blocker, 2 major, 6 minor, 3 nit.** (3) **Verdict: paper is close but not yet ready for cycle-3 REVIEW termination.** The arithmetic and theorem rename are clean in publication-targeted scope; the two major findings (N1 unresolved, cosignature inheritance unacknowledged) and the companion-doc drift are real residuals a careful reviewer catches. A final FIX cycle adding one N1 disambiguation sentence, one §9 cosignature-inheritance row, one §9 Theorem 4 binder disclosure, and propagation of the Theorem 1 rename through STATUS.md / build-log.md / README.md / theorems.lean would close the remaining gaps. Estimate one short FIX cycle (sub-day) followed by termination.
