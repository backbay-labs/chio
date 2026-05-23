# Sensor-Grounded Admission — Swarm State

## Cycle structure

Each cron fire executes ONE phase. Phases cycle: FIX -> WRITE -> RESEARCH -> REVIEW -> FIX -> ...

After 3 complete cycles, the cron fires a fresh adversarial review. If that review returns zero substantive findings, write `execution-complete.md` and self-CronDelete.

## Current state

- **EXECUTION COMPLETE** (see `execution-complete.md`)
- Cycles run: 3 + closeout + final adversarial REVIEW
- Final adversarial REVIEW returned 0 substantive findings, build clean (18 pages, 0 errors / 0 undefined / 0 BibTeX warnings)
- Cron `f5c76fa9` terminated via CronDelete
- Paper ready for human action: template conversion + anonymization + optional appendix + co-author outreach

## FIX phase log (this cycle, completed)

- FIX-A: Theorem 2 + 4 reformulation landed substantively. Theorem 2 now asserts a proper-sublist relation requiring `List.Sublist.length_le` + `Sublist.eq_of_length` work in both biconditional directions. Theorem 4 promoted to a structural-improvement claim using a new `partitionContingencyMode_false_of_covered` lemma. All four theorems compile cleanly with `lake build` against `formal/lean4/Chio/`, no `sorry`, `#print axioms` shows only standard kernel axioms.
- FIX-B: §6 reduced to 478 words, "multi-month deployment" and "every signed receipt" framing removed. Validate-side rejection rate from `endpoint_sensor_state_receipt_binds_provider_health` is the chapter's empirical anchor; 6-of-13 host-snapshot-vs-placeholder breakdown stated honestly.
- FIX-C: `bib.bib` created with 37 entries, all cited, 0 BibTeX warnings, 0 undefined citations. §8 rewritten on the property-attestation lineage (Sailer 2004 / Haldar 2004 / Coker 2011) + trusted-sensors (Saroiu 2010 / Liu 2012 / Asokan SEDA 2015), TEE attestation explicitly framed as "adjacent but distinct" to refute the rebadge critique.
- FIX-D: §2 gained two bridge paragraphs (OS-level referents naming auditd / Apple ES framework / ETW; property-attestation lineage citing Sailer/Coker/Haldar). Redundant canonical-JSON framing cut to make room.
- Build-gate residue: a pre-existing `\thm{...}`-with-underscore issue in §01 / §02 was flagged by FIX-C as the only blocker to pdflatex success. Falls into the next WRITE phase as item 0.

## Active queue updates

## Active findings (from prior REVIEW phase)

Source: `proposals/01-adversarial-review.md`, `proposals/02-evaluation-strengthening.md`, `proposals/03-related-work-depth.md`, `lean/STATUS.md`.

### FIX queue (this cycle)

1. **Theorem 2 + 4 reformulation.** `partition_contingency_mode_iff_degraded_subset` collapses to `Bool.decide_eq_true` (essentially `rfl`); `degraded_sensor_admission_requires_re_attestation` doesn't use its claimed partition-contingency premise. Either restate to be substantive (real list-induction over providers, real use of the partition premise) or update §4 prose to describe what was actually proven.
2. **§6 evaluation cut + Monday measurement.** Strip "multi-month deployment" framing; the macOS ES sensor is stubbed and 13 of 19 emitter sites use a hard-coded healthy placeholder. Land the validate-side rejection rate measurement (extension of `endpoint_sensor_state_receipt_binds_provider_health`) as the chapter's empirical anchor.
3. **§8 related work + new bib.bib.** Resolve all `TODO_*` citation placeholders. Add must-have citations: Sailer/Zhang/Jaeger/van Doorn 2004 (TCG IMA), Coker et al. 2011 (Principles of Remote Attestation), Haldar et al. 2004 (Semantic Remote Attestation), Saroiu 2010 (trusted sensors), Liu 2012 (sensor attestation). Reuse parent paper's bib entries where applicable.
4. **§2 background bridges.** Add EDR-bridge paragraph naming Linux auditd / macOS Endpoint Security / Windows ETW as the provider-category referents. Add property-attestation-lineage paragraph anchored on Sailer / Coker / Haldar. Cut redundancy with §3 if needed.

### WRITE queue (status)

- [x] **Item 0**: `\thm{}` and `\codepath{}` macros wrapped in `\detokenize{}` in paper.tex. Build gate now clean (4-pass pdflatex + bibtex all exit 0).
- [x] **Item 1**: §4 worked example landed (~165 words). Concrete constitution with `endpointSecurity` + `networkExtension` providers, healthy attestation pairs with empty degraded attestation against same body bytes, predicate discharges to opposite verdicts. Net §4 word delta: +10 (trims compensated for adds).
- [x] **Item 2**: §5 emitter-populations paragraph landed (~128 words). 6 real-host-snapshot sites vs 13 `single_active_agent` placeholder sites; verifier distinguishes syntactically; empirical posture covers only the first class. Net §5 word delta: 0 (compensating trims elsewhere).
- [x] **Item 3**: §4 Theorem 2 / Theorem 4 prose verified to integrate with the new worked example. Tightened consolidation of doubled "structural improvement" framing.
- [ ] **Item 4 (deferred)**: §A appendix with full Lean theorem statements. Camera-ready material; not blocking. Defer to a later WRITE cycle once the page budget is settled.

Build state: 16 pages, 0 errors, 0 undefined citations, 0 BibTeX warnings.

### RESEARCH queue (status, this cycle)

- [x] eBPF / Linux observability analogs surveyed in `research/os-observability-analogs.md`. Headline finding: §8 underweights the eBPF lineage (auditd, eAudit Sekar 2024 IEEE S&P, Falco / Tetragon drop telemetry); IMA is correctly cited but the runtime-observability anchor is missing. Sadeghi-Stüble 2004 NSPW property-based attestation is the deeper anchor the lineage paragraph should add.
- [x] TEE attestation deep dive completed in `research/tee-attestation-delta.md`. Headline finding: §8 "adjacent but distinct" framing SURVIVES and SHARPENS. No surveyed TEE format (TDX Quote v4/v5, SEV-SNP `ATTESTATION_REPORT` v2, Apple PCC `AttestationBundle`, Arm CCA realm token, AWS Nitro COSE_Sign1, NVIDIA H100, MAA TDX EAT) carries per-sensor drop/miss counts or distinguishes installed-vs-degraded at the wire level. Tighten §8 framing on "what wire formats structurally cannot express" rather than "code vs sensors".
- [x] Sensor-flapping models surveyed in `research/sensor-flapping-models.md`. Headline finding: §3 should add one paragraph on binary-state discretization choice; §9 should add within-window-flapping as a known limitation. Anchors: Cardenas-Amin-Sastry HotSec 2008, Mitchell-Chen ACM Computing Surveys 2014, Hayashibara phi-accrual SRDS 2004, SAIN USENIX Security 2024. Bonus: paper's "sign the flapping as a first-class field" is novel relative to aerospace literature (Yeh 1996 / ARINC 653).

### FIX queue (cycle 2; next cron fire executes this)

Source: `proposals/04-adversarial-review-cycle1.md`, `proposals/05-constructive-review-cycle1.md`.

1. **Headline framing honesty pass (highest priority — adversarial agent's #1).** §4 prose currently claims the headline proof "inducts on the provider list" and "discharges the membership check." The Lean at `lean/SensorGroundedAdmission.lean:350-378` actually destructs the body hypothesis, instantiates the existential with two fixed witnesses (`healthyWitness decl` + empty), and discharges with `unfold + rw + rfl` / `unfold + rw + simp`. The induction-on-providers work lives inside ONE-step supporting lemmas. Rewrite: §1 line 18 + §10 line 6 from structural-separation claim to Σ-construction-over-fixed-witnesses claim; cut or qualify §4 line 36's "induction on the provider list" claim. **Also delete §9 line 25's stale claim that Lean proofs are unfinished — `lean/STATUS.md` contradicts it (all four theorems compile with `#print axioms` clean).**

2. **§3 binary-state-discretization paragraph (constructive agent's #1).** Draft ~135 words acknowledging the implicit assumption that sensor state is discrete (installed / active / healthy / degraded) within a decision window. Real sensors flap; the model assumes attestation captures the dominant state. Cite Cardenas-Amin-Sastry HotSec 2008, Hayashibara phi-accrual SRDS 2004. Concrete prose draft in `proposals/05-constructive-review-cycle1.md`.

3. **§9 within-window-flapping limitation row.** Three-column format (Assumption / Used for / Residual risk) matching the existing §9 table. The row text: "Sensor state is the dominant state across the decision window / Discretization of sensors into four flags / Within-window flapping is out of scope; a sensor that toggles healthy<->degraded N times in the decision window is attested by whichever state dominated, with the others as collateral noise."

4. **§8 TEE reframing + 7 primary-source bibkeys.** Pivot from "code vs sensors" to "what surveyed wire formats structurally cannot express." Add bibkeys: Intel TDX 348549-002US Jan 2023, AMD 56860 r1.58 May 2025, Apple security-pcc proto Oct 2024, Arm CCA draft-ffm-rats-cca-token-03 March 2026, AWS Nitro NSM, MAA TDX EAT profile Feb 2026, RFC 9334 (RATS architecture).

5. **§8 eBPF observability lineage additions.** Add Sekar 2024 eAudit (IEEE S&P), Sadeghi-Stüble 2004 NSPW property-based attestation; reference Falco / Tetragon as project artifacts. Position as the runtime-observability anchor (currently underweight — IMA is the only correctly-cited anchor).

6. **§1 + §10 contribution bullets revised to map 1:1 to the four Lean theorems plus the implementation instance.** Theorem 3 is currently invisible to skim-readers. Revise both bookends in the same edit so they mirror.

7. **Voice leak pass.** Strip filesystem-path citations (`crates/chio-chiodos-runtime/...` in §5:10; `apps/agent/src-tauri/...` in §6:18; the `clawdstrike-policy-event::edr` test-path citation in §6:9). Strip "the previous arrangement" pattern from §3, §4, §7 (three instances), §10. Cut §9 line 31 ("the substrate's schema is published"). Cut or rewrite §7 "Connection to alignment-evaluation work" (undefended contribution drift).

8. **(Lower priority, defer if FIX cycle fills) Novelty-vs-aerospace claim placement.** Paper's "sign the flapping as a first-class field" is novel relative to aerospace TMR voting (Yeh 1996 Boeing 777 PFC, ARINC 653 health monitoring). Likely a §1 or §8 sentence.

9. **(Lower priority) Signing-key isolation question.** Should the attestation key differ from the receipt-signing key? If yes, that's a new theorem candidate (`sensor_attestation_marginal_trust_requires_separate_key`). If no, acknowledge that single-key signing makes attestation a structural-not-cryptographic guarantee. Decide in this FIX cycle or punt.

### Novel attacks logged for future cycles

From adversarial review:
- S1: Bilateral cosignature party-independence fails when both cosigners' attestation keys equal their body-signing keys.
- N1: Wire-compatibility amendment-cycle paradox — the compatibility predicate's introduction is itself an amendment that adds admission lanes, potentially violating the parent's backward-refinement obligation.
- N2: The empty-attestation degraded witness is not producible on the wire — the headline separation is between two body-pairs the polity admits/rejects but where one cannot be wire-emitted under the §3 + §5 schema rules.

### WRITE queue (cycle 2; status after fire 6)

- [x] **§8 tightening**: 1263 → 735 words. Preserved: TEE wire-format-gap framing, primary-source bibkeys (TDX 348549-002US, AMD 56860 r1.58, RFC 9334), eBPF lineage (Sekar 2024 eAudit), aerospace TMR (Yeh 1996, ARINC 653). 21 bibkeys dropped from §8 citations; 18 orphan bib entries removed from bib.bib.
- [x] **§3 + §9 tightening**: §3 863 → 779 (-84), §9 854 → 783 (-71). Within-window-discretization paragraph and within-window-flapping row preserved verbatim; Lean honesty paragraph in §9 also intact.
- [x] **§4 tightening**: 1288 → 1094 (-194 words). Real redundancy found with §1's expanded contribution bullets — headline-theorem, ladder-structuring, amendment-re-admission paragraphs each opened with prose-form restatements of §1 bullets that immediately preceded the formal theorem. Statements + math + worked example specifics + Σ-construction honest framing all preserved.
- [defer] **Item 9 (signing-key isolation)**: re-queued to cycle 3 if relevant.
- [defer] **Lean-statement appendix**: still deferred — adds pages, not load-bearing for the submission target.

Combined cuts: ~877 words / ~2 pages. Build clean: 0 errors, 0 undefined citations, 0 BibTeX warnings.

### RESEARCH queue (cycle 2; status after fire 7)

Four files in `research/`:

- [x] **S1 single-key collapse — CONFIRMED DAMAGING** (`single-key-collapse.md`, 2032 words). Paper at §3:18 and §4:59 explicitly signs both attestation and body under the same kernel key. Every surveyed TEE/HRoT (Intel TDX PCE/QE, AMD SEV-SNP VCEK/VLEK, Apple SEP UIK, Microsoft Pluton AK, TPM 2.0 AK/EK, OpenTitan, OP-TEE) structurally separates attestation-signing from app-signing keys. Parent paper §9:20 already names the collapse. Threshold-signing complement (FROST / MuSig2 / threshold-BBS+ — Doerner 2023) is signature-syntax-compatible with Ed25519/Schnorr.
- [x] **N2 empty-witness wire-producibility — NON-FINDING** (`empty-witness-wire-producibility.md`, 1342 words). The Lean witness at `lean/SensorGroundedAdmission.lean:243-246` is literally `providers := []`. The §3 schema doesn't require non-empty providers. The §5 evaluator has separate `attestation_parse_failed` (parser) and `required_set_uncovered` (predicate) failure codes; the empty-providers attestation passes parser, discharges via predicate path. Adversarial review's claim was misreading §5. Headline theorem survives.
- [x] **N1 amendment-cycle paradox — AMBIGUOUS** (`amendment-cycle-paradox.md`, 1349 words). Wire-compatibility predicate is concrete prose at §5:21-22 (not deferred future work) and referenced at §9:21-22. Case A reading (sensor-attestation construction amends parent's body-only constitution) → violates `BackwardRefines`. Case B (fresh constitution, not amendment) → no violation. Paper's framing fits Case B but never says so explicitly.
- [x] **Headline theorem candidates** (`headline-theorem-candidates.md`, 1767 words). Theorem 2 is structurally strongest (Π-biconditional, real list-induction proof work via `List.filter_sublist` + `Sublist.length_le` + `Sublist.eq_of_length`). Theorem 3 would be quotable but has inert `_h_destructive` premise (STATUS.md confirms). Theorem 1 is Σ-construction (weakest). Recommended action: rename Theorem 1 to `admission_predicate_separates_healthy_and_degraded_witnesses` — smallest change that makes the name match the post-honesty-pass prose.

### FIX-closeout queue (status after fire 13)

All 9 items addressed in parallel by 4 agents. Combined build gate: 0 errors, 0 undefined citations, 0 BibTeX warnings, 18 pages.

- [x] **Major 1**: N1 disambiguation sentence appended to §8:23 (38 words). Closes the amendment-cycle paradox by declaring the construction a fresh constitution.
- [x] **Major 2**: New §9 `Cosignature party-independence.` paragraph (117 words) between Attestation-key-isolation and Cross-polity-required-sets, mirroring parent §9's two-key DSSE collapse row.
- [x] **Minor 3 + NF1**: Theorem 1 rename propagated to STATUS.md:15, build-log.md:88, README.md:17. Stale `theorems.lean` at paper root DELETED (298-line v0 draft with all sorry'd theorems; conflicted with proven `lean/SensorGroundedAdmission.lean`). README.md updated to remove stale references, reflect mechanized Lean state, and point at `lean/SensorGroundedAdmission.lean`.
- [x] **Minor 4 (Option A)**: Theorem 4 `_h_prev_decl` inert-binder disclosed in §9 `Theorem coverage.` paragraph (48 words).
- [x] **Minor 5**: New §9 `Schema evolution inherited from parent.` paragraph (68 words) acknowledging the inheritance after cycle-3 wire-compatibility deletion.
- [x] **Minor 6**: §9 theorem-inventory discipline sentence (32 words) folded into the `Theorem coverage.` paragraph; cites `lean/SensorGroundedAdmission.lean` as the inventory anchor.
- [x] **Minor 7**: §3:21 rewrote QE/PCK overclaim to "Intel TDX binds quote signing to a hardware-rooted attestation-key path the TD cannot extract, with the TDREPORT and Quote flow specified by Intel" (matches what intelTDXSpec2023 actually covers). §9:22 swapped `Intel TDX QE/PCK` for `Intel TDX TDREPORT path`. No new bibkey.
- [x] **Nit 8**: §6:18 reworded — "real in shape but synthetic in content" lexically distinguishes the synthetic-counts claim from the real-source claim; first-scan contradiction resolved.
- [x] **Nit 10**: §1:12 future-work pointer verified to resolve cleanly to §10:8 (verbatim "structural complement" + "named as future work" phrases match); no change needed.

### Cycle-3 closeout REVIEW intake (consumed)

Source: `proposals/08-adversarial-review-cycle3.md` (R-3 confirmation), `proposals/09-constructive-review-cycle3.md` (drop-in drafts).

Priority order from constructive agent; ~1.5-2 person-hours estimated:

1. **Major 1**: Append N1 disambiguation sentence to §8 (end of parent-admission paragraph). Drop-in draft: "The sensor-attestation construction is a fresh constitution rather than an amendment of the parent body-only constitution; the backward-refinement obligation applies to amendments within the new constitution, not to its introduction."
2. **Major 2**: Insert §9 cosignature-inheritance paragraph between `Attestation-key isolation.` and `Cross-polity required sets.` Mirrors parent paper's §9 cosignature row, specialized for sensor-grounded context.
3. **Minor 3 + NF1**: Theorem 1 rename propagation to STATUS.md:15, build-log.md:88, theorems.lean:229 (paper-root stale draft), README.md:17,51. AND delete or stale-banner `theorems.lean` at paper root (the 298-line v0 draft with all theorems `sorry`; conflicts with proven `lean/SensorGroundedAdmission.lean`). Constructive agent recommends deletion.
4. **Minor 4 (Option A)**: Theorem 4 inert-binder disclosure in §9 `Theorem coverage.` paragraph (combined edit with Minor 6).
5. **Minor 6**: §9 sentence acknowledging theorem-inventory discipline parent row.
6. **Minor 5**: §9 sentence acknowledging schema-evolution inheritance from parent (after cycle-3 wire-compat deletion).
7. **Minor 7**: §3:21 and §9:22 `intelTDXSpec2023` clause tightening — remove QE/PCK overclaim (the cite is the TDX Module Base Architecture Spec, not the separate Quoting Service / DCAP docs).
8. **Nit 8**: §6:18 ES synthetic-counts sentence reorder.
9. **Nit 10**: §1:12 future-work pointer to §10 — verify it resolves cleanly.

Nits 9 and 11 (3-conjunct qualifier, others) skipped — already addressed or subsumed.

After this FIX, next phase = final adversarial REVIEW (skipping WRITE/RESEARCH). If that returns zero substantive findings AND build clean, write `execution-complete.md` + CronDelete `f5c76fa9`.

### Cycle-3 closeout REVIEW intake (now consumed)

From cycle-3 RESEARCH (final-validation-pass.md + venue-fit-submission-readiness.md):

**Major (require FIX before termination):**
1. **N1 amendment-disambiguation sentence never added.** Cycle-3 FIX deleted the symptom (wire-compatibility paragraph in §5, schema-versioning row in §9) but §8:23 still reads the sensor-attestation construction as an amendment of the parent's `amendment_admissible_iff_backward_refinement` without disambiguation. The cycle-2-prescribed sentence "The sensor-attestation construction is a fresh constitution, not an amendment of the parent body-only constitution" must land in §8 or §3.
2. **Cosignature party-independence inheritance from parent §9 unacknowledged.** §3:27 and §4:53 invoke cosigner attestations; the parent paper's §9 has the cosignature-party-independence assumption as an operational-discipline row. The sensor-grounded paper inherits this but §9 doesn't say so. Add a §9 row or inline acknowledgement.

**Minor (worth landing before termination):**
3. Companion-document drift: STATUS.md, build-log.md, README.md, theorems.lean still carry old Theorem 1 name. Propagate the rename through these working files.
4. Theorem 4's `_h_prev_decl` inert binder undisclosed in §9 (§9:28 mentions only Theorem 3's inert hypothesis). Either disclose or remove the inert binder.
5. Schema-evolution inheritance: parent paper has a schema-evolution row that the sensor-grounded paper inherits; after cycle-3's wire-compatibility deletion, this inheritance is now unacknowledged.
6. Theorem-inventory discipline: parent §9 has a row about Lean theorem inventory maintenance; sensor-grounded paper doesn't acknowledge this analogous discipline.
7. `intelTDXSpec2023` only half-covers the §3:21 PCK/QE signing claim — verify the citation supports both parts or add a supplementary cite.

**Nit:**
8. §10:6 drops "three-conjunct shape" qualifier — minor reading drift vs §1:19.
9. §1:12 future-work pointer to §10 resolves obliquely.
10. §6:18 ES synthetic-counts framing reads as an internal contradiction at first scan.

REVIEW agents (adversarial + constructive) take these as intake plus do their own fresh-eye sweep. If they confirm the findings AND find nothing substantively new, the next FIX cycle is a short sub-day pass that addresses the 2 majors + 4-5 minors, then a final adversarial-only REVIEW triggers termination.

### FIX queue (cycle 3; status after fire 9)

- [x] **Arithmetic fix** (item 1): §1:17 and §10:6 now read "six out of nineteen surveyed, remaining thirteen placeholder" matching §5:19 + §6:12. All four sections now agree.
- [x] **S1 closure** (item 2):
  - §9 attestation-key-isolation paragraph landed (137 words, cites `intelTDXSpec2023`, `amdSEVSNPSpec2025`, `applePlatformSecurity2024`, `rfc9334RATS`; all 4 bibkeys pre-existed).
  - §3 TEE-rooted attestation-key separation paragraph landed (168 words, same bibkey reuse, names HRoT separation as structural-fix path, names threshold-Schnorr (FROST, MuSig2) as cryptographic complement).
  - `sensor_attestation_marginal_trust_requires_separate_key` candidate stated as PROSE in §9 (per recommendation; not a Lean theorem this fire).
- [x] **Theorem 1 rename** (item 3): `admission_under_degraded_state_distinguishable_from_healthy` → `admission_predicate_separates_healthy_and_degraded_witnesses` at `lean/SensorGroundedAdmission.lean:12,352`, `sections/01-introduction.tex:17`, `sections/10-conclusion.tex:6`. §4 prose-only reference required no edit. `lake build` verified 24-job clean (no new sorry, no warnings). Reverted temporary copy to substrate root after verification (substrate at prior 23-job baseline).
- [x] **N1 deletion** (item 4): §5 wire-compatibility paragraph deleted (~65 words); §9 schema-versioning row deleted (~78 words). Total -143 words. Both flows read cleanly across the gaps.
- [x] **N2 sentence** (item 5): Added to §5 failure-modes paragraph (~42 words) making the empty-providers attestation wire-producibility explicit.
- [defer] **§A Lean appendix** (item 6): page count still high (17); defer to cycle-3 WRITE if needed, or skip entirely if cycle-3 REVIEW finds nothing else.

Combined build gate after cycle 3 FIX: 17 pages, 0 errors, 0 undefined citations, 0 BibTeX warnings. Net word delta +208 (§3 +172, §5 -23 net, §9 +59 net) but page count held steady.

Termination criterion check (after this cycle's REVIEW): if final adversarial review returns zero substantive findings AND build gate clean, write `execution-complete.md` and CronDelete `f5c76fa9`.

### Novel attacks logged for future cycles (cumulative)

From cycle-1 adversarial review:
- S1: Bilateral cosignature party-independence fails when both cosigners' attestation keys equal their body-signing keys. (Cycle-2 research confirmed damaging; cycle-3 FIX addresses)
- N1: Wire-compatibility amendment-cycle paradox. (Cycle-2 research found ambiguous; cycle-3 FIX resolves via Path A deletion)
- N2: Empty-attestation degraded witness not producible on wire. (Cycle-2 research found NON-FINDING; optional §5 sentence to make wire-producibility explicit)

## Log

- 2026-05-18 fire 1: FIX phase. 4 parallel fix agents addressed Theorem 2 + 4 reformulation (substantive paths, no `sorry`), §6 evaluation rewrite (478 words, anchored on validate-side rejection rate), §8 + bib.bib (37 entries, 0 BibTeX warnings), §2 background bridges (OS referents + property-attestation lineage). One pre-existing `\thm{}`-with-underscore build blocker passed to WRITE phase as item 0.
- Recurring cron `f5c76fa9` scheduled to fire :07 and :37 (30-min cadence). Next fire = WRITE phase.
- 2026-05-18 fire 2: WRITE phase. `\thm{}` and `\codepath{}` macros wrapped in `\detokenize{}` (item 0 blocker resolved); 4-pass build now clean. 2 parallel write agents landed: §4 worked example (`endpointSecurity` + `networkExtension` constitution with healthy vs empty attestation pairs against same body bytes, predicate to opposite verdicts) + Theorem 2/4 prose polish, and §5 emitter-populations paragraph (6 real-host-snapshot sites vs 13 `single_active_agent` placeholder sites, syntactically distinguishable). Net page impact neutral (16 pages). Item 4 (Lean-statement appendix) deferred. Next fire = RESEARCH phase.
- 2026-05-18 fire 3: RESEARCH phase. 2 parallel research agents surveyed (a) OS observability literature + sensor-flapping models and (b) TEE attestation deep dive across seven families. Three new files in `research/`: `os-observability-analogs.md`, `sensor-flapping-models.md`, `tee-attestation-delta.md`. Top findings: §8 framing of TEE attestation as "adjacent but distinct" survives and sharpens; §8 underweights the eBPF observability lineage; §3 should add binary-state discretization paragraph; §9 should add within-window-flapping limitation row. Contribution boundary holds with cheap defensive patches. Next fire = REVIEW phase.
- 2026-05-18 fire 4: REVIEW phase (cycle 1 closeout). 2 parallel agents: adversarial (proposals/04) found §4 prose overclaims what the Lean shows (headline is Σ-construction not list-induction; §9 line 25 stale about Lean proof status); constructive (proposals/05) drafted concrete prose for §3 discretization paragraph, §1+§10 contribution-bullet revision, §8 TEE reframing. 9 FIX items queued for cycle 2; 3 novel attacks logged for future cycles (single-key collapse, wire-compatibility amendment paradox, empty-attestation-not-wire-producible). Constructive agent estimates 70% of paper's potential realized. Next fire = FIX phase (cycle 2 opens).
- 2026-05-18 fire 5: FIX phase (cycle 2). 4 parallel fix agents on non-overlapping file scopes. FIX-1 (§1/§4/§10): headline-framing honesty pass (Σ-construction over fixed witnesses, not list-induction), §1 expanded to 5 contribution bullets mapping 1:1 with Theorems 1-4 + impl instance, §10 mirrored, 5 voice leaks removed. FIX-2 (§3/§9): added within-window-discretization paragraph (~127 words, cites `hayashibaraPhiAccrual2004` and `cardenasICS2008`), §9 within-window-flapping limitation row + Lean honesty rewrite replacing the line-25 stale claim, 7 voice leaks scrubbed. FIX-3 (§8/bib.bib): 13 new bibkeys landed (7 TEE primary sources, 4 eBPF lineage, 2 aerospace), TEE framing pivoted to "what surveyed wire formats structurally cannot express", aerospace-novelty sentence landed in §8; §8 grew from ~750 to 1263 words. FIX-4 (§5/§6/§7): filesystem-path citations stripped from §5/§6, §7 alignment-evaluation drift paragraph CUT entirely, net -77 words. 2 missing bibkeys (hayashibara, cardenas) added in post-FIX bridge. Combined build gate: 0 errors, 0 undefined citations, 0 BibTeX warnings; but page count jumped to 19 (target 11-13). Next fire = WRITE phase with TIGHTENING as priority (not adding content).
- 2026-05-18 fire 6: WRITE phase (cycle 2) — pure tightening run. 3 parallel agents trimmed ~877 words across §3 (-84), §4 (-194), §8 (-528), §9 (-71). 18 orphan bib entries removed after §8 dropped duplicate TEE secondary anchors. §4 trim found real redundancy with §1's expanded contribution bullets (headline-theorem / ladder / amendment paragraphs each restated their §1 bullet in prose before the formal statement). Load-bearing additions from fire 5 preserved verbatim (§3 within-window-discretization, §9 within-window-flapping, §9 Lean honesty paragraph, §1 contribution bullets, §4 Σ-construction honest framing). Build clean: 17 pages (down from 19), 0 errors, 0 undefined citations, 0 BibTeX warnings. Conference template would put this around 12. Next fire = RESEARCH phase with three threads on novel attacks S1/N1/N2 surfaced by cycle 1 adversarial review.
- 2026-05-18 fire 7: RESEARCH phase (cycle 2). 2 parallel research agents produced 4 files in `research/`. Findings: S1 (single-key collapse) CONFIRMED damaging — every surveyed TEE/HRoT structurally separates attestation key from app-signing key, parent paper acknowledges the collapse, sensor-grounded paper inherits it twice; threshold-signing complement (FROST/MuSig2/threshold-BBS+) is signature-syntax-compatible. N2 (empty-witness wire-producibility) NON-FINDING — adversarial review's claim was misreading §5 failure-mode enumeration; Lean witness is literally `providers := []`, §3 schema admits it, §5 evaluator discharges via predicate path. N1 (amendment-cycle paradox) AMBIGUOUS — Case A (amendment) violates `BackwardRefines`, Case B (fresh constitution) doesn't; paper's framing fits Case B but is silent. Headline candidates: Theorem 2 is structurally strongest (real list-induction work), Theorem 3 has inert hypothesis, Theorem 1 is Σ-construction. Recommended rename of Theorem 1 to `admission_predicate_separates_healthy_and_degraded_witnesses` for prose-name alignment. Next fire = REVIEW phase (cycle 2 closeout).
- 2026-05-18 fire 8: REVIEW phase (cycle 2 closeout). 2 parallel agents. Adversarial (proposals/06) found a NEW most-damaging issue: §1:21 and §10:6 say "six host-snapshot emitter sites out of thirteen surveyed, with the remaining seven covered by a placeholder" — arithmetically incompatible with §5:19 + §6:12 which correctly state 6 + 13 = 19 total. Introduced by cycle-2 FIX-1's §1 bullet expansion. ANY REVIEWER CATCHES IN 30 SECONDS. Plus reaffirmed S1 needs §9 row + §3 paragraph, Theorem 1 rename hasn't happened. Constructive (proposals/07) drafted concrete prose for all S1 closure pieces, recommended N1 Path A (delete wire-compatibility paragraphs net -130 words), estimated 80% of potential realized (up from 70%). Cycle-3 FIX queue: 6 items (arithmetic fix + S1 three-piece + Theorem 1 rename + N1 deletion + optional N2 sentence + optional appendix). Next fire = FIX phase (cycle 3 opens; final cycle per termination criterion).
- 2026-05-18 fire 9: FIX phase (cycle 3). 3 parallel fix agents on non-overlapping file scopes. FIX-A (§1/§4/§10/Lean): arithmetic fixed (six-out-of-nineteen across all four sections), Theorem 1 renamed to `admission_predicate_separates_healthy_and_degraded_witnesses` across Lean + §1 + §10 (§4 was prose-only, no edit needed), `lake build` verified 24-job clean. FIX-B (§3/§9): §3 TEE-rooted-attestation paragraph landed (168 words), §9 attestation-key-isolation row landed (137 words), §9 schema-versioning row deleted (78 words). FIX-C (§5): wire-compatibility paragraph deleted (65 words), N2 wire-producibility sentence added (42 words). Net +208 words total across paper; page count held steady at 17 (probably bib.bib's previous orphan cleanup absorbed the growth). Combined build gate: 0 errors, 0 undefined citations, 0 BibTeX warnings. All 5 required FIX items landed; appendix (item 6) deferred. Next fire = WRITE phase (cycle 3) or directly to RESEARCH/REVIEW if WRITE queue is empty.
- 2026-05-18 fire 10: WRITE phase (cycle 3) — polish run. 2 parallel agents tightened cycle-3 FIX additions. WRITE-A (§3/§9): tightened §3 TEE-rooted paragraph 168→139, tightened §9 attestation-key row 137→105, audited §3/§9 cross-redundancy and cut a duplicating sentence from §9:7 with a one-sentence cross-pointer. WRITE-B (§1/§10): verified arithmetic consistency across §1/§5/§6/§10 (all agree on 6 + 13 = 19), verified §1↔§10 1:1 bullet mirror across all 5 bullets, added a +4-word qualifier to §10:6 restoring the "three-conjunct shape" hedge to match §1:19. Net -66 words across paper, 4 paragraphs polished; page count held at 17. Build clean: 0 errors, 0 undefined, 0 BibTeX warnings.
- 2026-05-18 fire 11: RESEARCH phase (cycle 3). 2 parallel research agents. R-3 (final-validation-pass.md) found 2 major + 6 minor + 3 nit findings. Top finding: cycle-3 FIX deleted the N1 amendment-cycle SYMPTOM (the wire-compatibility paragraph in §5, schema-versioning row in §9) but the CAUSE — §8:23 still reading the construction as an amendment of the parent's backward-refinement obligation — remains; the cycle-2-prescribed N1 disambiguation sentence was never added. Second major: cosignature party-independence inheritance from parent §9 unacknowledged in this paper. R-4 (venue-fit-submission-readiness.md) recommends USENIX Security 2027 Cycle 1 (Aug 25, 2026 deadline), 2-3 person-weeks gap to ready-to-submit, NDSS 2027 Summer and CSF 2027 as backups. Termination prognosis: NOT yet — a sub-day FIX cycle addressing the 2 majors + 4-5 minors is required before the final adversarial REVIEW can return zero substantive findings. Next fire = REVIEW phase (cycle 3 closeout, which will distill the validation-pass findings into a final FIX queue for fire 13).
- 2026-05-18 fire 12: REVIEW phase (cycle 3 closeout). 2 parallel agents. Adversarial (proposals/08) confirmed 10 of 11 R-3 findings by direct verification, refuted 1 (cycle-3 WRITE-B already fixed it), added 1 new (NF1: stale 298-line `theorems.lean` at paper root is a packaging hazard alongside the real 583-line proven `lean/SensorGroundedAdmission.lean`; README.md:51 still references it). Termination call: READY after one final FIX cycle with no hidden cycle-4 gotcha (bib spot-checks clean, §4 math matches Lean, no voice leaks, §6 arithmetic consistent, §8 wire-format primary-source anchored). Constructive (proposals/09) drafted drop-in prose for Major 1 (N1 sentence) and Major 2 (§9 cosignature paragraph) plus dispatch order for the remaining 9 items. Estimated 1.5-2 person-hours. Next fire = FIX-closeout phase. After that, a final adversarial-only REVIEW triggers termination if zero findings.
- 2026-05-18 fire 13: FIX-closeout phase. 4 parallel agents on non-overlapping file scopes addressed all 9 prioritized items. Agent A (§9): cosignature party-independence paragraph landed (Major 2, 117 words), Theorem 4 inert-binder disclosed + theorem-inventory sentence folded into Theorem coverage paragraph (Minor 4 + 6), schema-evolution inheritance paragraph landed (Minor 5, 68 words), §9:22 intelTDXSpec2023 clause tightened (Minor 7). Agent B (§3 + §8): N1 disambiguation sentence appended to §8:23 (Major 1, 38 words declaring fresh constitution not amendment), §3:21 intelTDXSpec2023 overclaim rewritten to match what the cite actually covers (Minor 7). Agent C (companion docs): Theorem 1 rename propagated to STATUS.md:15, build-log.md:88, README.md:17; stale `theorems.lean` v0 draft at paper root DELETED (NF1 closed); README.md rewritten to reflect mechanized Lean state. Agent D (§1 + §6): §6:18 ES synthetic-counts framing reworded ("real in shape but synthetic in content"); §1:12 future-work pointer verified clean (no change needed). Combined build gate: 0 errors, 0 undefined citations, 0 BibTeX warnings, 18 pages (up 1 from cycle-3 closeout additions). All 9 items closed. Next fire = final adversarial REVIEW (termination check).
- 2026-05-18 fire 14: **FINAL ADVERSARIAL REVIEW — termination triggered.** Single adversarial agent returned 0 substantive findings, all 7 specific verifications passed (N1 sentence at §8:23, §9 cosignature paragraph between attestation-key-isolation and cross-polity-required-sets, Theorem 1 rename zero hits in publication-targeted artifacts, stale `theorems.lean` deleted, arithmetic 6+13=19 consistent across §1/§5/§6/§10, build clean 18 pages with 0/0/0 errors-undefined-BibTeX-warnings, Lean STATUS.md confirms 4 theorems compile with no sorry). Fresh-eye sweep surfaced no structural reviewer-grade finding. `execution-complete.md` written, `CronDelete f5c76fa9` called. Paper ready for human-action items: conference-template conversion, anonymization, optional appendix, Anthropic co-author outreach.
