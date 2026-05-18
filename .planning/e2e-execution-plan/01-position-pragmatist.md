# Pragmatist Position

## Headline argument (one paragraph)

The parent paper is done. The sensor-grounded admission paper is done. Both have been polished past the point of marginal returns - the parent has accumulated 5 polish passes plus 8 swarm iterations plus 4 post-execution reviews, and the sensor paper just closed a final adversarial review with zero substantive findings. Continuing to iterate is a tax on shipping, not on quality. The single most valuable thing this project can do between now and November 2026 is convert two completed manuscripts into one peer-reviewed submission receipt and one second-venue submission receipt. Everything else - V2/V6/V7/V8 engineering, Papers N1/N2/N3, cross-disciplinary expansion, additional co-author recruitment - is a distraction with a payoff horizon that exceeds the realistic patience window for solo unfunded research. Ship now or ship never.

## The 6-month plan

**June 2026 (weeks 1-4): Parent paper submission cycle.**
- Week 1: Send the Walch pre-disclosure letter. Send the IC3/Paradigm/GovAI pre-Slack. Do not wait for responses to gate downstream work.
- Week 1-2: Decide the M2 title. Lock the title. Stop deferring. The "deferred until Walch response" pattern is procrastination dressed as politeness; pick a title that does not depend on Walch and amend later if needed.
- Week 2-3: Pick the parent paper venue. Recommendation: **IEEE S&P 2027 (deadline early June 2026 first cycle, late November 2026 second cycle)** or **CCS 2027 (April 2026 first deadline, May second)**. If CCS first-cycle is gone, target CCS second-cycle May 2026 or S&P 2027 first-cycle June 2026. S&P is the better fit for the substrate framing; CCS accepts more receipt/protocol work.
- Week 3-4: Anonymize, finalize Appendix C inclusion decision (include if page budget permits, drop if not - do not re-architect the paper around it), submit.

**July-August 2026 (weeks 5-12): Sensor-grounded admission submission.**
- Convert to USENIX Security 2027 Cycle 1 template. The deadline is 2026-08-25.
- Anonymize.
- Submit. Realistic acceptance probability at USENIX: 18-22% per cycle for this kind of work. The optional Lean appendix is the single highest-leverage addition because reviewers reward mechanization; include it.

**September-October 2026 (weeks 13-20): Response cycles, not new papers.**
- Author response windows for both submissions land here.
- Use surplus time to draft the **Paper N3 (Agentic Tool Safety)** workshop submission. NeurIPS Safe-AI workshop deadlines typically fall in September-October; ICML AI Safety workshop in February. This is the **cheapest possible third submission** - 2-3 weeks from current v0, workshop tier acceptance bar, leverages Anthropic relationships if Perez engages, but does not require him.
- Do NOT start Paper N1 (Reversible Action). Do NOT start Paper N2 (Delegated Emergency Authority). Do NOT touch V2/V6/V7/V8.

**November 2026 (weeks 21-24): Decision point.**
- By mid-November, expect: parent paper decision (S&P round 1) or revision-and-resubmit instruction (CCS round 2). Sensor-grounded admission: decision late Q1 2027.
- If parent paper accepts: cycle resources to Paper 3 (Hart conditions) for JOLT Q1 2027.
- If parent paper rejects: revise from review and resubmit immediately to the next venue. Do not write a new paper.

## What gets shipped vs sacrificed

**Ships in the next 6 months:**
1. Parent paper submission (June)
2. Sensor-grounded admission submission (August)
3. Paper N3 (Agentic Tool Safety) workshop submission (October)

**Sacrificed entirely:**
- **V2 real two-kernel federation.** This is a 2-3 week engineering investment for tier-1 alone, with no clear paper output. The parent paper already claims and proves federation properties at the protocol layer. A live demo does not change reviewer behavior at top venues for formal protocol work. Cut.
- **V6 Chiodos buyer-closure replay fixtures.** This is product-quality infrastructure work. It does not appear in any paper. Cut.
- **V7 FROST threshold cosigning.** Cryptographic engineering that strengthens an already-strong threat model. Reviewers do not reject papers for using single-key DSSE if the threat model honestly describes its assumptions. Cut.
- **V8 issuer-rotation BBS binding.** Schema-v2 wire bump is a future-paper hook, not a current-paper requirement. Cut.
- **Paper N1 (Reversible Action).** The rollback-amendment composition theorem has not been verified non-`rfl`. If it is `rfl`, the paper has no real content. Solo author should not invest 4-5 months gating on an unverified theorem. Cut until parent ships.
- **Paper N2 (Delegated Emergency Authority).** Cross-disciplinary risk is real. Law journals run slow (12-18 month timeline). Requires legal co-author who has not yet been recruited. The Weimar Article 48 framing is rhetorically strong but the failure mode if a legal reviewer reads it as CS overclaim into constitutional theory is reputational damage that taints the parent. Cut, hard.
- **Paper 3 (Hart conditions sociological study).** Cut until after parent acceptance signal. JOLT Q1 2027 is reachable post-acceptance.
- **Paper 4 (trajectory-invariant constitutions POPL).** POPL 2028 deadline is July 2027. Out of scope for the 6-month window. Defer.
- **Paper 5 (adversarial-replay benchmark).** Note says "potentially subsumed by clawdstrike's replay engine if integration happens" - this is the worst kind of paper to start, one whose existence depends on an upstream integration decision not made. Cut.
- **Clawdstrike deeper integration.** Already extracted the highest-leverage steal (sensor-grounded admission). Stay in formal-model lane. Engineering integration with a production EDR is product work, not research output.

## Risk profile

**Best case (probability ~15%):** Parent paper accepts at IEEE S&P or CCS round 1. Sensor-grounded admission accepts at USENIX Security cycle 1. Agentic Tool Safety accepts at NeurIPS Safe-AI workshop. Three submission receipts in 12 months. Parent acceptance unlocks Paper 3, Paper 4, and legitimate Anthropic co-author conversations for follow-on work. The substrate has citation gravity.

**Expected case (probability ~55%):** Parent paper revise-and-resubmit at first venue; clean accept at second venue (8-12 month delay). Sensor-grounded admission accepts at USENIX or revise-and-resubmit. Agentic Tool Safety accepts at workshop. By May 2027, project has one accepted top-venue paper, one workshop paper, one in-flight resubmission. This is a real publication track record.

**Worst case if plan is followed (probability ~25%):** Both top-venue submissions reject in round 1. Workshop accepts. Author has spent 6 months getting reviewer feedback rather than building. By May 2027, project has one workshop paper and two rejection-with-reviews. Reviewer comments are themselves valuable; the revision is now informed by adversarial reading. Resubmit cycle 2 with informed revision. Expected acceptance by end of 2027.

**Worst case if plan is NOT followed (probability ~50% of the alternative-path universe):** Author spends 6 months on V2/V6/V7/V8 and Papers N1/N2/N3, produces zero submitted manuscripts, the parent paper drifts another 5 polish passes, the substrate becomes year-and-a-half-old work without a peer-review receipt, Anthropic safety team focus shifts, Walch never receives the letter, and the entire enterprise enters the gray zone of "interesting working-directory research" that never accumulates citation gravity. This is the silent failure mode. It is the one that has destroyed more solo research projects than any reviewer panel.

## The single most important blocker to remove

**Send the Walch pre-disclosure letter this week.** Not next week. Not after the M2 title decision. Not after one more polish pass. This week. The letter is drafted. It needs a signature and a send action. Every day it does not get sent is a day the parent paper's submission is gated on an upstream notification that has not been initiated. The downstream effects compound: title decision is gated on Walch response; venue selection has soft dependencies on whether the paper enters Walch's awareness before or after public submission; the legal-co-author conversation for Paper N2 (if it ever happens) starts only after the relationship is established. The letter is a 30-second send. Send it.

Secondary: pick the parent paper venue and write the deadline on a wall. Public, dated commitment beats private optionality.

## Anticipated counter-arguments and rebuttals

**Substrate-builder will argue: "V2/V6/V7/V8 are what make the formal claims credible. Without real federation, threshold signing, and rotation binding, reviewers will see a paper-tiger system."**

Rebuttal: The parent paper's claims are protocol-level and Lean-mechanized. Reviewers at S&P, CCS, and USENIX evaluate formal protocol work on the formalism, not the demo. 130 theorems in the substrate is a stronger reviewer signal than a federation demo. The paper-tiger risk is real for systems-tier venues (NSDI, OSDI); we are not targeting those. The substrate-builder argument is correct in a 24-month horizon and wrong in a 6-month one.

**Scholar will argue: "The Hart conditions sociological study and the trajectory-invariant POPL paper are where the deep contributions live. Workshop papers and sensor-grounded admission are second-tier."**

Rebuttal: Workshop papers and second-tier submissions are how a solo author builds the citation graph that makes the deep contributions legible. POPL 2028 with no prior published substrate work is a much harder sell than POPL 2028 with one S&P/CCS/USENIX paper already cited. The scholarly path requires shipping the foundation first. Skipping ahead to the cathedral while the foundation sits unbuilt is the opposite of scholarly.

**Strategist will argue: "Cross-disciplinary expansion into law journals and the Anthropic co-author relationship are network-effect bets that compound. Cutting Paper N2 cuts the law-journal entry point."**

Rebuttal: Network-effect bets compound from a base. The base is a peer-reviewed substrate paper. Without it, the Anthropic conversation is "look at my preprint" and the law journal conversation is "I have an idea." With it, the Anthropic conversation is "I have an accepted S&P paper, let's co-author the follow-on" and the law journal conversation is "my CS substrate is peer-reviewed, would you co-author the legal-theoretic extension." The strategist path is correct. The strategist's timing is wrong. Build the base first.

**On the Anthropic co-author question specifically:** Skip it for the parent paper submission. The outreach memo is drafted; do not send it before parent submission. Reasoning: (a) Adding a co-author from a frontier lab introduces a 4-8 week negotiation cycle on framing, claims, and review rights, which delays submission past the S&P/CCS first-cycle deadlines; (b) The parent paper does not need an industry co-author to land at top venues - the formalism is the credential; (c) Sending the outreach after the paper is on arXiv and under review is strictly better positioning for the Paper N3 (Agentic Tool Safety) conversation because Perez/Bowman can engage with a fixed artifact rather than a moving target; (d) The asymmetric upside of an Anthropic co-author is on the follow-on papers, not the substrate paper. Save the ask for the moment it has maximum leverage.

## Report

**Specific paper + venue + deadline to ship first:** Parent paper ("Programmable Sovereignty") to **IEEE S&P 2027 first-cycle deadline (early June 2026)**, or **CCS 2027 second-cycle (May 2026)** if S&P timing slips. Realistic acceptance probability at first venue ~22%, at first OR second venue within 12 months ~55%.

**Single most important cut:** **Paper N2 (Delegated Emergency Authority).** Cross-disciplinary law-journal expansion is the single highest-risk, lowest-near-term-payoff thread, and cutting it removes the largest distraction from a 6-month shipping window. V2-V8 engineering is also cuttable but Paper N2 is the cut that removes the most cognitive load per word killed.

**One-sentence risk assessment:** The dominant risk is not paper rejection - it is paper non-submission, and every week of additional polish or parallel-thread expansion is a week of compounding non-submission risk against a finite operator patience budget.
