# Wave 3C: Final adversarial re-certification

Fresh hostile USENIX PC pass on the paper after three swarm cycles plus Wave 1B / Wave 2 close-outs. Scope: the ten body sections of `paper-usenix.tex` (the actual submission target). Appendices, Lean substrate, and PDF rendering are out of scope per the brief. The paper compiles clean on both targets: 16 pages USENIX, 24 pages article, zero undefined citations (per `paper-usenix.blg` and `paper.blg`), zero bib misses.

## 1. Did Wave 2 actually land

Each Wave 2 claim has a corresponding artifact in the source.

- **§1 threat-model paragraph.** Present at `sections/01-introduction.tex:14-15`, headed `\paragraph{Threat model.}`. The paragraph names the adversary's in-scope capabilities ("controls the agent that produces the receipt body ... may replay signed receipts and attestations ... may attempt to forge attestation contents"), the out-of-scope capabilities ("cannot compromise the attestation signing key ... cannot suppress sensor-level reporting from a sensor that is itself healthy"), and the protection target ("the verifier of a receipt rather than the operator of the signing kernel"). Cross-cites `chioProgrammableSovereignty2027` and forward-cites `sec:limits`. Substantive, not a citation paste.
- **§2 five-mode ladder.** All five modes appear with one-line definitions at `sections/02-background.tex:11-19` under `\paragraph{The five-mode trust ladder.}`. Observation, Receipt-backed, Partition-contingency, Guarded, Quorum-required each receive a one-line semantic gloss naming the admission floor and intended use. A sixth "refuse" case is named as the empty admission relation rather than a mode. Concrete evidence: "Partition-contingency. Admission proceeds under a degraded substrate whose attested-healthy providers form a strict sublist of the constitution's required set, with an explicit reconciliation obligation attached to the admitted receipt."
- **§9 TEE-compromise paragraph.** Present at `sections/09-limitations.tex:24-25`, headed `\paragraph{TEE compromise reduces the construction to single-key signing.}`. Cites Plundervolt (`murdockPlundervolt2020`), Foreshadow (`vanbulckForeshadow2018`), Downfall (`moghimiDownfall2024`), and Half-Double (`koglerHalfDouble2022`). All four resolve through bibtex (verified at `bib.bib:410,420,432,442`). Closes by naming three candidate mitigations as future work.
- **§7 structural reframe.** §7 now opens with the structural argument, follows with three positive subsections ("What sensor-grounded admission reveals ... ", "Composition with the parent paper's ladder," "Boundary against TEE-compromise"), and closes with "The downstream claim the placement choice unlocks." The defensive "what about kernels that lie?" / "what this paper does not claim" material is gone. Voice in §7 is structural throughout.
- **§8 NVIDIA-CC, GCP, CoCo, Pluton.** Each is engaged at `sections/08-related-work.tex:11` with a specific wire-format claim, not a bibliography drop. NVIDIA-CC is named with "SPDM-tunnelled GPU attestation reports binding the on-chip firmware version, secure-boot state, and a workload-supplied nonce." GCP is named with "Confidential Space attestation token, signed by Google's Attestation Verifier, that carries TEE measurements and a workload identity claim." CNCF CoCo is named with "Remote Attestation Service whose Reference Value Provider supplies policy-side acceptance rules." Pluton is briefer (one sentence) but mapped to Microsoft Azure Attestation.
- **Figure 1 (§3).** TikZ figure at `sections/03-substrate.tex:9-42` showing the DSSE envelope with body, attestation block, four-row sensor table, clock record, and the brace covering body and attestation jointly. Referenced once in prose at line 7.
- **Figure 2 (§4).** TikZ `figure*` at `sections/04-model.tex:62-92` showing the three-decision spine with verdict boxes. Referenced once in prose at line 60.

Voice cleanup verified: `grep -nP '\x{2014}'` returns nothing in `sections/*.tex`, `paper.tex`, or `paper-usenix.tex`. `grep -n "this paper\|the paper\|we extend\|we introduce\|we propose\|we present"` against `sections/*.tex` returns one hit, and that hit is in `sections/11-appendix-open-science.tex` (out of scope per the brief).

## 2. First-five-pages impression

Title is informative and concrete ("Sensor-Grounded Admission: Polity Receipts with Attested Substrate State"). The abstract makes a falsifiable claim: "The headline result is the existence of two receipts sharing identical body bytes whose distinct sensor attestations discharge the admission predicate to opposite verdicts." A reviewer can extract the experiment in one sentence.

§1 motivates the gap in the first paragraph ("A receipt produced under a partial substrate looks identical, on the wire, to a receipt produced under a complete one") and pinpoints why a systems-security reviewer should care ("the silent-degradation path becomes a signed-false-attestation path"). The threat model is legible on first encounter: agent-control in-scope, attestation-key compromise out-of-scope, verifier-side protection target. The five contributions are crisply listed at lines 19-25.

§2 onboards a USENIX-only reader cleanly: ladder definitions in lines 11-19, honest-substrate assumption in lines 22-23, sensor-state referents on Linux / macOS / Windows in lines 28-29. Figure 1 lands on USENIX page 4 and reads as a wire-format diagram a reviewer can scan in seven seconds.

Confidence I would read past page 5: **8/10**. The paper is legible cold, the contribution is clear, the threat model is stated, and the figure pays for itself. One point off for §2's "ladder" prose density (the bulleted list is good but the paragraph that precedes it on monotone admission stability is dense in the first read), one point for the "this is not heuristic substitution" framing that surfaces only at §7 (a strong reviewer wants to know that defense earlier).

## 3. Headline-theorem promise

Theorem name `admission_predicate_separates_healthy_and_degraded_witnesses` paired with abstract phrase "existence of two receipts ... discharge to opposite verdicts." Wave 1B flagged "separates" as universal-quantifier-flavored against the abstract's existential.

The resolution Wave 2 chose is editorial rather than structural: the §4 theorem statement at lines 33-37 is now stated as an existential ("there exist attestations $A_h, A_d$ such that..."), and §10's headline theorem summary at line 6 is also stated existentially. The §4 prose at line 39 still hedges ("the stronger separation that the predicate reliably rejects any short-falling attestation is the required-set-coverage projection (Theorem~3)"), which keeps the reader oriented. The theorem name remains "separates" but the abstract, §4, and §10 all read as existential. A reviewer who reads only the abstract and §4 will not see the universal-quantifier tension. A reviewer who reads only the theorem name and the contribution list will see a small overclaim ("separates" suggests "for all witness pairs," the proof delivers "two existence witnesses") but the §4 prose immediately disambiguates. This is acceptable for submission; a stronger version would rename the Lean theorem to `*_witnesses_*` or `*_exhibits_*`, but that is a polish item not a blocker.

## 4. Threat-model coherence

§1 lines 14-15 partition the cases cleanly: agent-control is in-scope (in line with the prior §1:6 "the threat model controls the agent"), attestation-key compromise is out-of-scope with the residual named in §9 (which closes the §7:17 "compromised attestation lane" gap by routing it to §9's TEE-compromise paragraph). The §4 threat-model paragraph at lines 99-100 echoes the same partition and explicitly notes "Attestation and body are signed by the same kernel key in the construction here; a separate attestation key, rooted in a TEE platform's quote-signing identity, would make the strengthening cryptographic in addition to structural." The §7 boundary-against-TEE-compromise paragraph at line 17 is consistent with both: "Where the TEE root holds, the construction strictly improves observability ... Where the TEE root fails, the construction collapses to single-key signing as the parent paper assumed."

The three statements compose without contradiction. Wave 1B finding #2 is closed.

## 5. §6 evaluation honesty

§6 lines 17-18 is explicit: "The macOS \codepath{EndpointSecurity} system extension shipped with the substrate sources events from an in-memory recorder rather than calling \codepath{es\_new\_client} or \codepath{es\_subscribe}. The host-snapshot path's ES provider record is therefore real in shape but synthetic in content." The empirical scope is then named: "The sensor input layer the empirical claim covers is the network-extension filter (real on the egress reload path), the package-manager hooks, and the tool-preflight surface; ES-derived telemetry is out of scope." §6 lines 19-20 also flags what is not measured (deployment-rate partition-contingency rate, false-attestation rate, Criterion latency bench). §5 line 19 names the placeholder-vs-host-snapshot split: "Thirteen sites consume the constant ... The empirical claim covers the first class; the second class is a placeholder population whose admission under the same predicate is a structural limitation, recorded as such in Section~\ref{sec:limits}."

This is hedged honestly. A USENIX reviewer who suspects an overclaimed empirical chapter will check §6 first, find the stub admission, and move on satisfied.

## 6. Citation density and depth

Sampled ten citations across the paper:

- `chioProgrammableSovereignty2027` (§1, §2, §8 close): used as the parent-paper anchor for inherited assumptions and theorem composition; primary.
- `cokerPrinciplesRemoteAttestation2011` (§2, §8): used to anchor the "trustworthy mechanism" requirement and the formal-models-of-attestation positioning; primary.
- `sailerTCGIMA2004` / `sailerIMA2004` (§2, §8): used for the IMA load-time anchor; primary (two separate keys to the same work, see finding 8).
- `intelTDXSpec2023`, `amdSEVSNPSpec2025`, `awsNitroNSM`, `applePCC2024`, `armCCAToken2026`, `nvidiaHopperCC2024`, `googleConfidentialComputing2024`, `cncfConfidentialContainers2024`, `microsoftPluton2023`: all in §8's wire-format paragraph with specific claims about each platform's attestation surface; primary or institutional.
- `murdockPlundervolt2020`, `vanbulckForeshadow2018`, `moghimiDownfall2024`, `koglerHalfDouble2022` (§9): each anchored to a specific attack family with the paper's structural collapse claim; primary venues (S&P, USENIX Security).
- `haldarSemanticRemoteAttestation2004` / `haldarSemanticAttestation2004` (§2, §8): used for the "property attestation" lineage shift; primary.
- `hayashibaraPhiAccrual2004` (§3, §9): used for the continuous-suspicion alternative; primary.
- `sekarEAudit2024` (§8): used for the eBPF audit-replacement lineage; primary, current.
- `rfc8785` (§2, §5): used for canonical-JSON discipline; primary standard.
- `rfc9334RATS` (§2, §3, §9): used for the IETF RATS attester / target distinction; primary standard.

Citation density is good, all sampled cites support specific claims, and the TEE-compromise primary sources are properly anchored. One redundancy: `sailerIMA2004` (§8) and `sailerTCGIMA2004` (§2) appear to point to the same work under different keys; same for `haldarSemanticAttestation2004` / `haldarSemanticRemoteAttestation2004`. This is a citation-hygiene polish item, not a content gap.

## 7. Voice integrity

Final greps:

- `grep -nP '\x{2014}'` returns zero hits across `sections/*.tex`, `paper.tex`, and `paper-usenix.tex`. Em-dash discipline is clean.
- `grep -n "this paper\|the paper\|we extend\|we introduce\|we propose\|we present"` against `sections/*.tex` returns one hit, in `sections/11-appendix-open-science.tex` (out of scope). The body is clean.
- `grep -niE "(v0|v1|wave|iteration|cycle|branch|fixture)"` against `sections/*.tex` returns four hits, all of them domain uses of "amendment cycle" (the substrate's amendment workflow concept) rather than project-history voice. Examples: "as in the parent paper's amendment cycle" (§3:50), "connected to the parent paper's amendment cycle" (§7:11). No "this iteration," no "v0 substrate," no "branch," no "wave," no "fixture matrix." Project-history voice is clean.

Voice integrity is high. The README rule that the paper describes what the substrate is, not how the project produced it, is honored.

## 8. What is still wrong that prior waves missed

After Waves 1-2 the paper is materially improved. Three new issues become visible only after the fixes:

**(a) Citation-key duplication.** The bib carries two keys for Sailer 2004 (`sailerTCGIMA2004` and `sailerIMA2004`) and two for Haldar 2004 (`haldarSemanticRemoteAttestation2004` and `haldarSemanticAttestation2004`). Both pairs cite the same primary work under different ids. The article renders both as separate entries in the bibliography section, which a careful reviewer will notice. The fix is to unify each pair under one key and update §2 / §8 references. Polish-grade, not a blocker.

**(b) Inherited-vs-novel modes confusion.** The §2 ladder block at lines 11-19 introduces all five modes as "inherited from the parent construction" (line 12 explicitly: "are inherited from the parent construction"). But the §2:20 paragraph then claims the construction extends the partition-contingency and receipt-backed rows: "The construction extends the partition-contingency row by making its trigger condition structurally decidable on a substrate-attested field, and extends the receipt-backed row by binding admission to coverage of the constitution-required sensor set." A reader who reads only §2 may conclude that two of the five rows are inherited-with-modification and three are inherited-as-is, but §3's "Ladder reading" paragraph at lines 61-62 also touches observation, guarded, and quorum-required ("Observation and guarded modes are below the destructive-admission floor and are decidable on the body alone; they do not consult the attestation. Quorum-required admission additionally requires that every cosigner's attestation cover the required set"). The §2 framing of all five as "inherited" understates the construction's reach on quorum-required. A one-sentence cross-reference between §2:20 and §3:61-62 would resolve this. Editorial.

**(c) Figure 2 fits its width with effort and its prose anchor is thin.** Figure 2 is a `figure*` (full text width) in two-column USENIX, which fits the three-decision spine but pushes the in-line theorem prose down a column. The cross-reference at §4:60 is only one sentence ("Figure~\ref{fig:admission-decision-tree} renders the resulting three-way verdict as a single traversal over the attestation"), and the figure caption carries the load. A reviewer who skims will read the figure and the caption and move on without reading §4's three-conjunct math. This is the correct trade-off for a systems-security audience (the figure is the artifact the reviewer remembers), but it is worth a sentence in §4 saying "the predicate's three-conjunct structure (Figure~\ref{fig:admission-decision-tree}) reduces to a decision tree on the attestation field," which would weld the prose and the figure together at the reader's first encounter. Polish, not a blocker.

The §7 reframe did not leave orphan defensive material; the limitations went to §9 cleanly. The §8 NVIDIA-CC / GCP / CoCo / Pluton additions sit in one paragraph that grew by about 60% in length but still fits as one paragraph and does not push related work out of proportion. The new threat-model paragraph in §1 does not introduce inconsistency with §4 or §9. No new structural blockers emerged.

## FINAL VERDICT

**READY**. The paper is at submission-grade for USENIX Security 2027 Cycle 1.

The strongest section is **§4 (Formal Model)**: it states the four theorems cleanly, sketches the proof structures honestly (instantiated witnesses, sublist biconditional, `Bool.and_eq_true` decomposition, partition-contingency-improvement), grounds the worked example concretely (`endpointSecurity` and `networkExtension` providers with explicit thresholds), and now welds the decision-tree figure to the prose. A reviewer who reads §4 will leave knowing what the contribution is, what is proved, and what is hedged. The §6 evaluation chapter is also strong for the right reason: it is honest about the macOS Endpoint Security stub and names what is not measured.

Three optional polish items, none blocking submission:

1. Unify the duplicate bib keys (`sailerTCGIMA2004` / `sailerIMA2004` and `haldarSemanticRemoteAttestation2004` / `haldarSemanticAttestation2004`).
2. Add one sentence in §2:20 cross-referencing §3:61-62 to clarify that the construction also tightens the quorum-required floor on cosigner attestation, not only receipt-backed and partition-contingency.
3. Add one anchor sentence in §4 just before Figure 2 saying "the predicate's three-conjunct structure reduces to a decision tree on the attestation field," to weld the figure to the prose at the reader's first encounter.

Wave 2 closed Wave 1B's three structural blockers and four of five editorial gaps. The remaining editorial gap (the theorem-name "separates" vs the existential abstract) is resolved adequately by the §4 statement and the §10 summary, and a USENIX reviewer reading the paper in order will not see the tension. The paper ships.
