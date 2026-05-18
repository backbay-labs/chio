# Wave 1.c: Parent-Paper Venue Decision Memo

Date prepared: 2026-05-18
Author: subagent W1.c, dispatched by the parent-paper swarm orchestrator
Decision owner: human (this memo prepares the choice; the human picks)
Output type: single recommendation with reversal triggers

## 1. Inputs

**Paper.** `papers/programmable-sovereignty/paper.tex`. Title: "Programmable Sovereignty: Lean-Attestable Constitutions Over Capability-Bounded Federated Receipts".

**Contribution.** The paper defines a polity as a triple `(T, C, K)`: closed receipt-admission scope, Merkle-rooted citizenship roster, and a constitution expressed as a finite list of predicates. Admission, capability attenuation, treaty intersection, and constitutional amendment are decidable operations on that triple; each emits a canonically signed receipt only when the constitution and scope accept. The construction is implemented in Rust with companion machine-checked proofs in Lean 4. Theorems cover treaty predicate intersection, ladder-floor stability, and amendment refinement. A three-vendor buyer-closure worked example backed by replay fixtures supports an evaluation over dispatch admission, treaty intersection, selective disclosure, and replay-corpus stability.

**Current build state.** 13 pages, acmart `sigconf,anonymous,review,nonacm`, 4-pass pdflatex clean, 0 errors / 0 undefined / 0 BibTeX warnings. Anonymous title-page block already in place ("Anonymous for external review"). A sibling `paper-usenix.tex` shell exists at 16 pages article-class but has not been polished.

**Evaluation type.** Mixed: formal (machine-checked theorems in Lean 4), systems (Rust substrate with canonical-signed receipt emission), and worked example (three-vendor buyer-closure with replay fixtures). No production deployment, no large-scale measurement study.

## 2. Venue 1: NDSS 2027 Fall

**Deadline.** Submission Wednesday August 19, 2026 at 23:59 AoE (UTC-12). Abstract / paper registration is on the same date per the call. Early-reject notification September 25, 2026; full notification November 4, 2026; major-revision resubmission December 2, 2026; camera-ready January 6, 2027. Conference March 22-26, 2027, Seoul.

**Calendar pressure from 2026-05-18.** 13 weeks and 2 days to the August 19 deadline.

**Important correction to the playbook.** The playbook names "NDSS 2027 Summer (July 2026)" as a candidate; the actual NDSS 2027 Summer deadline was Wednesday May 6, 2026, which is 12 days in the past as of this memo. Summer is gone. Fall is the only NDSS 2027 round still in play.

**Page budget.** 13 pages excluding Ethics Considerations, references, and appendices. Two-column 10-point Times minimum on U.S. letter. The current 13-page acmart `sigconf` build is already at the NDSS body limit and uses the same family of typesetting; expected to fit with light tightening.

**Template.** NDSS publishes its own LaTeX template (the call references the NDSS 2026 templates as the basis for 2027). Conversion from acmart `sigconf` is a one-to-two-day mechanical pass.

**Fit with the contribution.** NDSS publishes formal-spine-plus-systems papers in the attestation, secure-execution, and policy-enforcement lineages (SEDA / Sigstore / IMA / capability-OS neighborhoods). The paper's shape (typed substrate, machine-checked theorems, worked dispatch example) is a recognizable NDSS shape. The empirical chapter is not a measurement study, which the sensor-grounded venue-fit research flagged as a weak axis at NDSS; the parent paper offsets this with a stronger formal core than sensor-grounded carries.

**Reviewer pool.** NDSS PCs draw on attestation, secure-systems, and applied-formal-methods reviewers. Acceptance-rate prior roughly 16-21 percent.

**Simultaneous-submission policy.** Standard prohibition on parallel submission to other venues with proceedings.

**Anonymization.** Double-blind. The paper.tex already uses anonymous author/affiliation/email placeholders; W1.b is the live audit.

**Risks.**

1. The worked example is not a measurement study; NDSS reviewers who weight measurement strongly may grade the evaluation thin.
2. The August 19 deadline is six days earlier than USENIX Cycle 1; the smaller calendar buffer is at NDSS.
3. Notification November 4, 2026 puts the response cycle into Wave 5 / Wave 6 territory on the synthesis-plan calendar.

## 3. Venue 2: USENIX Security 2027 Cycle 1

**Deadline.** Paper registration Tuesday August 18, 2026; paper submission Tuesday August 25, 2026 at 23:59 AoE. Conference August 11-13, 2027, Denver. Cycle 2 fallback: January 26, 2027.

**Calendar pressure from 2026-05-18.** 14 weeks and 1 day to the August 25 submission deadline; 13 weeks to the August 18 abstract.

**Page budget.** Body limit 13 pages excluding Ethics Considerations and Open Science required appendices (each up to one page), references, and appendices. Two-column 10-point Times on U.S. letter, 7-by-9 text block. The current acmart 13-page build fits the body envelope.

**Template.** USENIX paper template (style files published with the call). The repo already has a `paper-usenix.tex` shell at 16 pages article-class form, which is a partial head start; the page count at 16 article-class compresses to roughly 12-13 under the USENIX two-column template.

**Fit with the contribution.** USENIX Security has historically taken formal-spine-plus-thin-empirical work in the band the sensor-grounded venue-fit research identified. The parent paper is empirically stronger than sensor-grounded (three-vendor buyer-closure plus replay-corpus stability, not just a single mutation-rejection test) and carries a substantial Lean formal spine. USENIX is also a recognized home for typed-runtime and capability-system papers.

**Reviewer pool.** USENIX Security has the broadest reviewer pool of the top-tier security venues; more variance in who reads the formal sections. Acceptance-rate prior roughly 17-19 percent. Cycle 2 (January 26, 2027) is a same-family re-roll.

**Simultaneous-submission policy and anonymization.** Standard prohibition. Double-blind.

**Risks.**

1. The sensor-grounded paper is targeted to the same cycle. Two distinct papers from the same author to the same conference cycle is allowed by USENIX, but it concentrates risk: a single PC reading both can develop reviewer fatigue or cross-contaminate committee discussion. Acceptance probabilities are not independent if both compete for shared author-pool slots.
2. Cycle 1 reviewer load is historically high; thin-empirical papers in dense cycles get triaged on first pass.
3. The Open Science requirement interacts with the project's pre-disclosure constraint (Walch letter not yet sent). The artifact appendix can be written; whether the substrate code is publicly linked at submission time is a separate decision.

## 4. Cross-cuts

**Calendar.** From 2026-05-18: NDSS Fall 13.3 weeks; USENIX Cycle 1 14.1 weeks. Six-day spread, same window. The playbook's earlier framing (NDSS a month earlier than USENIX) is not the configuration on the table.

**Simultaneous-submission.** Both venues prohibit parallel submission of the same paper. The parent paper picks one.

**Second paper, same cycle.** The sensor-grounded paper is targeted to USENIX Security 2027 Cycle 1 per its README, swarm-state, and venue-fit research. Two distinct papers from the same author at the same conference cycle is allowed, but it concentrates exposure to a single PC. NDSS Fall would split the two papers across different PCs and reduce that concentration.

**Reviewer overlap.** NDSS and USENIX Security PCs share a noticeable fraction (attestation, applied formal methods, capability-systems). Splitting venues does not eliminate overlap, but program chairs and the bulk of the reading load are distinct.

**Template conversion cost.** Acmart to NDSS: roughly one-to-two days. Acmart to USENIX: roughly two-to-three days, with the partial `paper-usenix.tex` shell saving roughly half a day.

**Pre-disclosure status.** Walch letter drafted, unsent. Affects only Paper N2's cross-disciplinary tier, not parent venue fit.

## 5. Recommendation

**Submit the parent paper to USENIX Security 2027 Cycle 1 (deadline 2026-08-25).**

Dominant factors, in order:

- The NDSS 2027 Summer cycle the playbook recommended has already closed. The real choice is NDSS Fall versus USENIX Cycle 1, and the deadlines now sit 6 days apart. The "NDSS Summer is earlier than USENIX Cycle 1" calendar advantage that motivated the playbook's recommendation no longer exists.
- The parent paper's contribution shape (formal core + systems substrate + worked example, no large-scale measurement) is closer to the band USENIX Security has historically accepted than to the empirically-anchored band NDSS weights. The sensor-grounded venue-fit research reached the same conclusion for the sibling paper; the parent paper sits in the same neighborhood with stronger empirical content but the same formal-spine emphasis.
- A USENIX submission preserves Cycle 2 (January 26, 2027) as a re-roll on the same venue family if the first attempt misses. NDSS Fall's only re-roll path is NDSS 2028 Summer, which is a longer calendar burn.
- The `paper-usenix.tex` shell at 16 pages already exists, reducing template-conversion cost by roughly half a day. Acmart-to-NDSS conversion would start from `paper.tex` with no head start.
- The sensor-grounded paper at the same cycle is the only material concentration risk; it is a real risk but is mitigable by spacing the abstract-registration submissions and by the two papers having genuinely distinct contributions (substrate-and-constitutions vs. attested-substrate-state admission). The acceptance-probability concentration is real but smaller than the venue-fit advantage.

## 6. Reversal triggers

Flip the recommendation to **NDSS 2027 Fall** if any of the following becomes true before submission:

- A PC-chair or area-chair conflict-of-interest at USENIX Cycle 1 is discovered that does not apply to NDSS Fall.
- A co-author addition (Walch / Anthropic / IC3 reply with co-author offer) before mid-July materially shifts framing toward law or measurement; anonymization and venue-fit then reopen.
- The V2 tier-1 federation work somehow lands measurement results before August 19. Unlikely (synthesis plan puts V2 in Weeks 7-10) but would push the paper toward the NDSS-weighted axis.
- The sensor-grounded paper slips to USENIX Cycle 2 for reasons independent of this memo and a new exogenous USENIX risk emerges. Otherwise, slippage alone does not flip the call.

Flip to **NDSS 2027 Fall** as a tiebreaker if the human prefers the NDSS reviewer pool on grounds outside this memo's enumeration. The two venues are close enough that operator-side preferences are not unreasonable.

## 7. Out of scope

Not decided here: artifact-appendix scope, Open Science statement wording, co-author additions, anonymization completeness (W1.b), template-conversion sequencing within Wave 2, Walch letter timing. The venue pick is sufficient to unlock Wave 2.
