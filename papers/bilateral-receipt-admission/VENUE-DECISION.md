# Bilateral Receipt Admission - Venue Decision

Date: 2026-05-18
Author: swarm subagent A (venue research + double-blind audit)
Output type: single recommendation with reversal triggers
Scope: this memo does not edit `paper.tex` or any section file; it prepares the venue choice for the human

## Recommendation

Submit the short paper to **USENIX Security 2027 Cycle 2 (paper submission deadline 2027-01-26, 23:59 AoE)**, after the parent paper has cleared early-reject at USENIX Security 2027 Cycle 1 (early-reject notification roughly 2026-10-06 per the SEC26 calendar). Fall-back: ACSAC 2026 (deadline 2026-05-26) if the human wants a venue with a shorter calendar burn and is willing to accept tier-B venue prestige.

## Venue survey

### 1. USENIX Security 2027 Cycle 1 (paper submission 2026-08-25)

Source: `https://www.usenix.org/conference/usenixsecurity27`, cross-checked against `https://sec-deadlines.github.io/`.

- Page limit: 13 pages body, excluding Ethical Considerations and Open Science required appendices (each up to 1 page), references, and unlimited optional appendices. Camera-ready max 20 pages.
- No separate short paper track. The CFP has only one paper class.
- Per-author cap: 7 submissions per cycle.
- Anonymity: double-blind, "must not reveal the identity of the authors," third-person self-references.
- Simultaneous submission: tolerated with anonymized citation in the body and non-anonymous notification to `sec26chairs@usenix.org` (SEC27 PC chairs will publish their address when CFP is finalized; precedent rule applies).
- Fit for a 6-8 page short paper: weak. Reviewers expect a full-length contribution at the 13-page envelope. A 7-8 page submission will look thin against the cycle's median submission.

### 2. USENIX Security 2027 Cycle 2 (paper submission 2027-01-26)

Source: same. Cycle 2 deadline confirmed by sec-deadlines.github.io as 2027-01-26 23:59 AoE, registration 2027-01-19. These dates are inferred-from-SEC26 cadence; the SEC27 CFP page on usenix.org was 403-blocked at the time of this memo (server returns 403 to WebFetch), so the dates should be re-verified once usenix.org publishes the formal SEC27 CFP.

- Page limit and policies identical to Cycle 1.
- Cycle 2 is the same venue, same PC pool (with cycle-2 additions), same proceedings.
- Critical fact: USENIX prohibits resubmission of a Cycle 1 reject into Cycle 2 of the same year. But submitting a different paper (the short paper) into Cycle 2 after submitting the parent paper into Cycle 1 is allowed.

### 3. NDSS 2027 Fall (paper submission 2026-08-19)

Source: `https://www.ndss-symposium.org/ndss2027/submissions/call-for-papers/`.

- Page limit: 13 pages body, excluding Ethics Considerations, references, appendices.
- No short paper track.
- Per-author cap: 6 submissions per cycle.
- Anonymity: double-blind.
- Simultaneous submission: "Technical papers must not substantially overlap with papers that have been published or that are simultaneously submitted to a journal or a conference/workshop with proceedings. Double-submissions will result in immediate rejection." Also: "Major overlap between a rejected paper from the first cycle and a submission to the second cycle is disallowed."
- Fit for the short paper: forbidden in combination with the parent paper. The short paper is by construction substantially overlapping with the parent (it shares the bilateral-DSSE construction, the rejection-code taxonomy, the three-vendor evaluation). NDSS forbids this configuration.

### 4. NDSS 2027 Summer (paper submission 2026-05-06)

Source: same. Deadline 12 days in the past as of 2026-05-18. Closed.

### 5. ACM CCS 2026 Cycle 2 (paper submission 2026-04-29)

Source: `https://www.sigsac.org/ccs/CCS2026/call-for/call-for-papers.html`.

- Page limit: 12 pages excluding bibliography and well-marked appendices.
- No short paper track. CCS 2026 has nine specialized tracks but each takes the same full-paper format.
- Per-author cap: 7 papers per cycle.
- Anonymity: double-blind.
- Simultaneous submission: substantially-overlap prohibition similar to NDSS.
- Cycle 2 submission deadline (2026-04-29) is 19 days in the past. Closed for 2026.
- CCS 2027 Cycle 1 deadline is not yet posted but historically lands in January 2027.

### 6. IEEE EuroS&P 2026 (paper submission 2025-11-20)

Source: `https://eurosp2026.ieee-security.org/cfp.html`.

- Page limit: 13 pages body, unlimited references and appendices. No short paper track.
- Anonymity: double-blind.
- Simultaneous submission: forbidden ("substantially similar paper to another venue with proceedings or a journal is not allowed and will be grounds for automatic rejection").
- Deadline 6 months in the past. Closed.

### 7. HotSec 2027

Source: searches against usenix.org. HotSec has not been held since 2020 (last edition `HotSec '20`). The historical workshop accepted 1-2 page lightning talk abstracts only, not 6-8 page short papers. There is no HotSec 2026 or 2027 CFP visible. This venue is effectively dormant for the purpose of this paper.

### 8. WOOT 2026 (academic-track paper submission 2026-03-03)

Source: `https://www.usenix.org/conference/woot26/call-for-papers`.

- Conference: August 10-11, 2026 in Baltimore.
- Deadline 2026-03-03 is 76 days in the past. Closed for 2026.
- WOOT 2027 CFP not yet posted. By the cadence WOOT 2026 deadline was March 2026, WOOT 2027 deadline will likely be in February or March 2027 (inferred).
- Scope: offensive security research. The bilateral-receipt-admission paper is a defensive primitive ("how the receiving kernel admits an action"); it is a poor fit for an offensive-technologies venue. Even if WOOT 2027 opens, the topic alignment is weak.

### 9. ACSAC 2026 (paper submission 2026-05-26)

Source: `https://www.acsac.org/2026/submissions/papers/`.

- Page limit: 11 double-column pages, plus references and up to 5 pages of appendices (16 total max).
- No separate short paper track. The 11-page limit is tighter than NDSS/USENIX/CCS; an 8-page submission would not look out of place.
- Anonymity: double-blind.
- Simultaneous submission: substantially-overlap prohibition.
- Deadline: 2026-05-26, 8 days from this memo. Tight but reachable for a 6-8 page paper that is already largely drafted.
- Tier: ACSAC is a respected applied-security venue (CORE rank A, acceptance ~20 percent), one tier below USENIX/CCS/NDSS/Oakland but considerably above workshop tier. The "Applications" framing aligns with the paper's three-vendor closure evaluation.

### 10. ACM SecDev 2026 (paper submission 2026-02-05)

Source: `https://conf.researchr.org/track/secdev-2026/secdev-2026-papers`.

- Has an explicit short paper class: long (10 pages), short (6 pages, may be shorter), excluding references and appendices.
- Deadline: 2026-02-05, 102 days in the past. Closed for 2026.
- SecDev 2027 CFP not yet posted; historical cadence puts the deadline in late January 2027.
- Fit for the short paper: very strong on format (explicit 6-page short class). Tier is significantly lower than USENIX (CORE rank not in A, acceptance ~35 percent). The audience is secure-software-engineering practitioners, which aligns reasonably with the supply-chain-provenance framing.

### Other (Sigstore-aligned, OpenSSF)

SigstoreCon (CNCF, co-located with KubeCon Europe 2026, April 2026) is a one-day vendor-neutral conference; CFP was earlier in 2026 and is closed. OpenSSF Community Day NA (May 21, 2026, Minneapolis) is a community-day program, not a peer-reviewed proceedings venue. Neither is a viable target for an academic short paper because (a) no formal proceedings, (b) no double-blind review, and (c) the paper does not need community-day reach in May 2026.

## PC-overlap risk analysis

The parent paper targets USENIX Security 2027 Cycle 1 (deadline 2026-08-25) per `wave1-venue-decision.md`. The decision to make about the short paper hinges on three combinations:

### Combination A: Parent USENIX SEC27 Cycle 1, short USENIX SEC27 Cycle 1

Both papers in the same cycle of the same PC.

- USENIX policy: explicitly allowed. The simultaneous-submission paragraph in `sec26_cfp_011226.pdf` covers this: "Citations to simultaneously submitted papers should be anonymized; non-anonymous versions of these citations must, however, be emailed to the program co-chairs at sec26chairs@usenix.org."
- Anonymity risk: high. The same PC reads both papers. A reviewer who is assigned both will see the construction sharing (DSSE predicate, five rejection codes, three-vendor buyer-closure). The paper's anonymity rests on the construction itself being non-uniquely-identifying. The construction is, in fact, distinctive: bilateral DSSE with treaty-bound subject digest is not yet in the literature outside this project. A reviewer who reads both papers, even anonymized, can connect them via the shared primitive.
- Bias risk: real. Reviewer fatigue, or a strong reaction to one paper, will color the other. A reviewer who finds the polity framing in the parent paper unconvincing may discount the short paper's claim that the primitive stands without the polity framing.
- Resource-pull risk: real. A PC discussion that decides "this is one contribution split across two papers" will reject the second.
- Verdict: **risky**. Allowed by policy, but the concentration risk is large enough to recommend against.

### Combination B: Parent USENIX SEC27 Cycle 1, short USENIX SEC27 Cycle 2

Parent submitted 2026-08-25, short submitted 2027-01-26. Five-month gap.

- Cycle 1 early-reject notification arrives roughly 2026-10-06 (six weeks after submission per the SEC26 calendar). By the time the short paper is submitted, Cycle 1's first-round triage outcome is known.
- USENIX policy: allowed. Cycle 1 and Cycle 2 share a PC pool but Cycle 2 reviewers are assigned different papers; PC overlap is partial, not complete.
- Anonymity risk: moderate. A reviewer who saw the parent paper in Cycle 1 and happens to be assigned the short paper in Cycle 2 can connect them. The probability that any individual reviewer overlaps is low (PC sizes are 150-200; random assignment is sparse). The probability across the full review committee is non-negligible but bounded.
- Bias risk: lower than Combination A. The papers are not in active discussion at the same PC meeting. If the parent paper is accepted at Cycle 1, the short paper can cite it as a non-anonymized parent and the situation simplifies (the short paper becomes a "see also" of a published work). If the parent is rejected at Cycle 1 and resubmitted to Cycle 2 elsewhere, the short paper's Cycle 2 submission is independent.
- Resource-pull risk: low. The two papers are in different cycles, so PC discussion is not jointly framed.
- Verdict: **safe**. This is the recommended configuration.

### Combination C: Parent USENIX SEC27 Cycle 1, short different venue

Different conference for the short paper:

- ACSAC 2026 (deadline 2026-05-26, 8 days from this memo): tight but reachable. Different PC, different proceedings.
- NDSS 2027 Fall (deadline 2026-08-19): forbidden by the substantially-overlap policy.
- CCS 2027 Cycle 1 (deadline likely Jan 2027): different PC, different proceedings, allowed.
- SecDev 2027 (deadline likely Jan 2027): different PC, has an explicit short paper class.
- Verdict: **safe** for ACSAC, CCS 2027, SecDev 2027; **forbidden** for NDSS.

## Final recommendation

Submit the short paper to **USENIX Security 2027 Cycle 2 (paper registration 2027-01-19, paper submission 2027-01-26)**.

Reasoning:

1. **Tier prestige matches the parent.** Both papers land in the same top-tier proceedings line, which is the right place for the cryptographic-primitive short paper's audience.
2. **PC concentration risk is mitigated by the cycle gap.** Five months between Cycle 1 and Cycle 2 lets the parent paper either land or fail before the short paper enters review, removing joint-discussion bias.
3. **Calendar slack.** The bilateral-receipt-admission paper has §4 (formal sketch) still to draft per the iter-3 comparator's salami-slice escape requirement. Targeting January 2027 gives 8 months to finish the freestanding accept-set theorem and complete a tight 6-8 page draft.
4. **Simultaneous-submission policy is the most permissive.** USENIX explicitly allows the configuration, with the requirement that the parent paper be cited (anonymized in body, non-anonymous to PC chairs).
5. **Re-roll path preserved.** If the short paper misses Cycle 2, the SEC28 Cycle 1 deadline (~August 2027) is the next attempt at the same venue tier.

## What sleeps if this venue is picked

- **No 2026 conference attendance from the short paper.** USENIX Sec 2027 papers are presented at the conference in August 2027 at the earliest. If the user wants something at a 2026 conference (which would help validate the construction publicly before the parent paper lands), ACSAC 2026 (Honolulu, December 2026) is the only viable 2026 academic venue still open.
- **No NDSS reviewer pool.** The NDSS 2027 Fall PC includes a different reviewer set (more measurement-oriented, less applied-formal-methods). The short paper does not get that audience.
- **No 6-page short paper format.** USENIX Sec accepts up to 13 pages but does not have an explicit short paper class. The paper will need to be at least 8-10 pages to look like a "real" submission rather than a thin one. The README's 6-8 page target is too tight for this venue; the draft should expand to 8-10.
- **No early signal on the construction.** A pre-print to arXiv at submission time can substitute for early signal, but reviewers may treat the construction as known by the time the short paper enters review.

## Open questions for the user

1. **Page count.** USENIX SEC27 has no short paper class. The README targets 6-8 pages. Is the user willing to expand the draft to 8-10 pages to fit the venue, or does the user prefer a venue with an explicit 6-page short class (SecDev 2027) at lower prestige?
2. **Audience.** Does the user want the short paper read by the USENIX PC (broad systems-security audience) or the SecDev PC (secure-software-engineering audience)?
3. **Two-paper concentration.** Is the user comfortable with the moderate concentration risk of two papers from the same author at the same venue across two cycles, or does the user prefer the cleaner "different venue" split (ACSAC 2026 in May, or CCS 2027 Cycle 1 in January)?
4. **Walch / Anthropic co-author timing.** If a co-author is added before January 2027, the anonymity audit (W1.b of the parent paper) reopens and the venue calculation may shift.
5. **Pre-print policy.** USENIX permits pre-prints. Does the user want to post the short paper to arXiv at submission time (January 2027) or wait until conditional acceptance?

## Reversal triggers

Flip the recommendation to **ACSAC 2026 (deadline 2026-05-26)** if:

- The user wants a 2026 conference appearance.
- The parent paper's Cycle 1 trajectory becomes uncertain and the user wants the short paper to land independently.
- The Walch co-author offer arrives in time to register an ACSAC submission by May 26.

Flip to **SecDev 2027 (deadline ~late January 2027)** if:

- The user prefers an explicit 6-page short paper class to a 10-page expanded format.
- The user wants the secure-software-engineering audience rather than the academic systems-security audience.

Flip to **CCS 2027 Cycle 1 (deadline ~mid January 2027)** if:

- The user wants a non-USENIX top-tier venue specifically to avoid PC overlap with the parent paper.
- The user accepts the substantially-overlap risk being scrutinized harder at CCS than at USENIX Cycle 2.

Do **not** target NDSS 2027 for the short paper. NDSS's substantial-overlap prohibition makes the two-paper plan a desk-reject candidate.

## Sources verified

- USENIX Security 2026 CFP PDF: `https://www.usenix.org/sites/default/files/sec26_cfp_011226.pdf` (read in full)
- USENIX Security 2027 deadlines: `https://sec-deadlines.github.io/` (Cycle 1: 2026-08-25, Cycle 2: 2027-01-26)
- NDSS 2027 CFP: `https://www.ndss-symposium.org/ndss2027/submissions/call-for-papers/`
- ACM CCS 2026 CFP: `https://www.sigsac.org/ccs/CCS2026/call-for/call-for-papers.html`
- IEEE EuroS&P 2026 CFP: `https://eurosp2026.ieee-security.org/cfp.html`
- WOOT 2026 CFP: `https://www.usenix.org/conference/woot26/call-for-papers`
- ACSAC 2026 CFP: `https://www.acsac.org/2026/submissions/papers/`
- ACM SecDev 2026 CFP: `https://conf.researchr.org/track/secdev-2026/secdev-2026-papers`

USENIX Security 2027 CFP page (`https://www.usenix.org/conference/usenixsecurity27`) returns HTTP 403 to programmatic fetch; the cycle dates above are from the sec-deadlines aggregator and are inferred-from-prior-year cadence pending the formal SEC27 CFP publication. Re-verify once the formal CFP is posted.
