# Strategist Position

## Headline argument

The other three positions are arguing about taste. The binding constraint isn't strategy, it's the calendar. A solo author at 15 hours/week has roughly 780 hours over twelve months, minus illness, travel, holidays, day-job spikes, and the inevitable two-week stretch where nothing moves. That's 600-650 usable hours. The Programmable Sovereignty paper is already in the bank. The Sensor-Grounded paper is approximately one cycle away from submittable. Everything else is speculation against that hour budget. The right plan ships those two, lands one engineering tier (V2 or V6, not both), opens one cross-disciplinary relationship without committing to its paper, and stops there. Anything more is a wish list. The decision that kills the project is not "which papers" — it's whether the author treats the next three months as a polish-and-submit phase or as a new-drafting phase. Drafting is what destroys finishing.

## Resource budget assumptions

**Hours/week**: 15 is the honest number for a solo author with any other primary obligation. Some weeks will be 25, most will be 10, and roughly six weeks of the year will be zero. Plan to the median, not the peak.

**Calendar months**: 12, but only ~10 are useful. Subtract end-of-year holidays, a summer slowdown, and one unforeseen life event (illness, family, move, deadline at the day job). Build the plan against 10 working months.

**Attention pool**: This is the harder budget than hours. Paper-finishing is high-attention work that competes directly with engineering work. You cannot meaningfully polish a USENIX submission in the same week you're debugging gRPC TLS handshakes across two hosts. The author has one "deep work" mode per day, maybe two on a good day. Context-switching between Lean, Rust, and academic prose halves throughput. Assume any week mixing categories loses 30% of its nominal output.

**Calendar burn from external dependencies**: Walch outreach is a six-to-twelve week round trip even if the reply is fast. Anthropic co-author negotiation is eight-to-sixteen weeks. Conference review cycles are 12-16 weeks blind. None of these consume large hour counts, but they consume calendar slots that the plan cannot ignore.

**Realistic submission cost**: From "paper is done" to "paper is submitted" at USENIX-tier polish: 80-120 hours. Template conversion, anonymization, abstract polish, supplementary materials, artifact submission, author response prep. That's six to eight weeks at the assumed cadence. The Sensor-Grounded paper alone, even though it's "shipped" internally, will burn 80+ hours of polish before the USENIX 2027 Cycle 1 deadline on 2026-08-25.

## The 3-month / 6-month / 12-month plans

### 3 months (now through 2026-08-18)

**Total available**: ~180 hours, minus 30 for slippage = 150.

**Single objective**: Submit Sensor-Grounded Admission to USENIX Security 2027 Cycle 1 (deadline 2026-08-25, eight days after this window closes).

**Concrete deliverables**:
- USENIX conference-template conversion (15-20 hours)
- Anonymization pass and self-citation audit (10 hours)
- Optional Lean appendix integration (20 hours)
- Abstract and intro polish to USENIX taste (15 hours)
- Artifact submission preparation (15 hours)
- Adversarial pre-read by one external reader (calendar burn, 5 hours author time)
- Walch pre-disclosure letter SENT (3 hours plus weeks of waiting)
- Anthropic outreach for Sensor-Grounded co-author (5 hours plus weeks of waiting)
- Submission and 24-hour post-submission sanity hold (5 hours)

Subtotal: ~90 hours. Remainder of the 150 goes to: Programmable Sovereignty venue decision and submission prep (paper is already done, but it needs a target), one engineering tier started but explicitly not finished, and slack for the Walch reply if it comes.

**Engineering**: Begin V2 tier-1 (Docker localhost two-kernel). Do not begin tier-2. V6, V7, V8 are deferred entirely.

**Papers NOT touched in this window**: Reversible Action, Delegated Emergency Authority, Agentic Tool Safety, Paper 3-5 from the pipeline. None.

### 6 months (through 2026-11-18)

**Total available since start**: ~360 hours, minus 60 = 300.

**Cumulative objectives by end of month 6**:
1. Sensor-Grounded submitted (done by month 3) and either accepted/rejected/in-revision by USENIX.
2. Programmable Sovereignty submitted to a chosen venue. Recommended: skip the simultaneous-submission gymnastics and target one venue, probably USENIX Security 2027 Cycle 2 or a workshop derivative.
3. One agentic tool safety workshop submission (NeurIPS Safe-AI or ICML AI Safety workshop). v0 exists. Two to three weeks of focused work gets it to workshop-ready. This is the lowest-risk, highest-momentum addition.
4. V2 tier-1 complete and documented. V6 not begun.
5. Walch reply received and processed. Either she's interested (then the Delegated Emergency Authority paper enters a co-author negotiation phase that takes 6+ months) or she isn't (then DEA is shelved or repositioned as a CS-only paper).

**What gets dropped at month 6**: Reversible Action. v0 exists but the rollback-amendment composition theorem gate is unverified. If the theorem is `rfl`, the paper has no contribution. Testing that gate is 20-40 hours of Lean work. If you don't have a clean answer by month 6, drop it.

### 12 months (through 2027-05-18)

**Total available**: ~720 hours, minus 120 = 600.

**Cumulative shipped**:
- Sensor-Grounded: through one USENIX cycle (accepted, rejected, or in revision).
- Programmable Sovereignty: submitted, likely in review.
- Agentic Tool Safety: workshop-published (low venue, but a publication).
- V2 tier-1 + tier-2 (two-host LAN) complete. V6 begun.
- Either Reversible Action drafted to v2 (if gate cleared) OR formally dropped.
- Either Delegated Emergency Authority in active co-author phase with Walch (if she said yes) OR shelved.

**Realistic paper count over 12 months**: 2 submitted to top conferences, 1 workshop, 0-1 in revision/resubmission. So 2-3 papers in submission state, 0-2 published depending on cycle luck.

This is not three full papers in twelve months. Anyone telling you otherwise is fantasizing about hours that don't exist.

## The decision that kills the project

**Starting Paper 3 (Hart conditions sociology) or Paper 4 (trajectory-invariant POPL 2028) before Sensor-Grounded is submitted.**

The pipeline list at the bottom of the state inventory is the project-killer. Each pipeline paper carries a draft cost of 100-200 hours before it even reaches v1. The author has already shown a pattern of drafting under autonomous swarms — that's how Reversible Action and Delegated Emergency Authority both ended up as v0 drafts. Drafting is cheap. Finishing is not.

If the author opens a sixth or seventh draft thread before closing the first two submissions, the calendar collapses. The autonomous swarms are extraordinary at producing v0 drafts and worthless at the submission-grade polish that takes 80+ hours of human attention per paper. You can draft ten papers in twelve months and submit none. The single decision that prevents this: a hard rule that no new paper enters drafting state until Sensor-Grounded and Programmable Sovereignty are both at "in review" or "rejected, repositioning" status.

Secondary project-killers, ranked:
1. Investing in V7 (FROST threshold cosigning) or V8 (issuer-rotation epoch binding) before V2 lands. Both are deep crypto-engineering rabbit holes. Neither converts to a paper without 6+ months of operational deployment data.
2. Letting Walch outreach block paper submissions. The Walch letter is "drafted, needs human signature." If the author waits for Walch to anchor the legal-CS hybrid before submitting CS-only papers, the calendar slips by a quarter.
3. Cross-disciplinary co-author negotiation without a deadline. Anthropic outreach without a "if no response by X, proceed solo" rule converts a six-week ask into an eight-month delay.

## What automation can absorb

The autonomous swarm has shown it can do:
- v0 drafting from a memo (5700-10000 words in a fire)
- Polish passes with quality close to human-led iteration (5 polish passes + 8 swarm iterations on the parent paper)
- Lean theorem statement and proof development at the V1-V5 level
- Adversarial pre-reads and findings consolidation
- BibTeX hygiene, build cleanliness, anonymization audits
- Design memo authoring for engineering tiers (V2/V6/V7/V8 memos already exist)

The autonomous swarm cannot do:
- Venue selection with awareness of the political landscape (which PC chair, which line of work to cite favorably, which adversarial reviewer to anticipate)
- Cross-disciplinary judgment about how a CS claim will land in a law journal
- Conversation with a human co-author about authorship order, contribution split, or institutional fit
- Strategic patience: knowing when to NOT submit
- The author's voice. The repeated complaint about "engineering-meta narration" shows the swarm drifts into project-history voice unless human-pulled back to subject-matter voice.

**Implication**: Use the swarm aggressively for everything except submission decisions, venue strategy, and co-author negotiation. Those three categories must remain human-driven and should be batched (one venue-decision session per month rather than per-paper anguish).

## Anticipated counter-arguments

**Scholar will argue**: "Five papers is a real pipeline; the substrate is rich enough to support it." Counter: yes, the substrate is rich. No, the author's hours are not. The pipeline list is a research agenda, not a 12-month plan. A research agenda is fine. Confusing it with an execution plan is fatal. The scholar position implicitly assumes drafting equals publication, when the drafting-to-submission ratio is closer to 1:5 in hours.

**Substrate-builder will argue**: "V7 and V8 unlock new paper claims; the engineering compounds." Counter: V7 (FROST threshold cosigning) and V8 (issuer-rotation epoch binding) compound only if they reach production deployment with operational data. That's a 12+ month runway each. Neither converts to a publication inside the 12-month window. Engineering effort spent on them in the next year produces no submissions. V2 tier-1 is the only engineering with a paper-relevant payoff (it backs claims already made in the parent paper).

**Pragmatist will argue**: "Just ship one paper well." Counter: closer to right, but missing the momentum cost. Shipping only one paper in twelve months when two are already at "ready to submit" or "near-ready" is a missed opportunity. The pragmatist undershoots because they're protecting against burnout. The strategist plan ships 2 papers plus 1 workshop because the marginal cost of the second paper, once the first submission machinery is set up, is genuinely lower.

**All three will argue**: "You're being too conservative; the autonomous swarms have changed what's possible." Counter: the autonomous swarms have changed drafting throughput, not submission throughput. Submission is where the bottleneck lives. The swarms have demonstrably produced more v0 drafts than the calendar can convert to submissions. The strategist position is the only one that takes this asymmetry seriously.

---

## Report-back

**Realistic paper count over 12 months**: 2 papers submitted to top venues (Sensor-Grounded + Programmable Sovereignty), 1 workshop paper submitted (Agentic Tool Safety), 0-2 actually published depending on review-cycle outcomes. Anything claiming more is calendar fantasy.

**Single project-killer decision**: Starting any new paper draft (Paper 3 Hart sociology, Paper 4 POPL trajectory, Paper 5 adversarial-replay) before Sensor-Grounded reaches "submitted" status. The autonomous swarms make this temptation acute; resist it.

**One-sentence advice to the other three agents**: Stop arguing about which papers to write and start counting the hours required to submit the ones already drafted, because the binding constraint is submission throughput, not idea generation.
