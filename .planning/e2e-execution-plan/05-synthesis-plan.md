# E2E Execution Plan (synthesis)

Date: 2026-05-18
Source: 4 position papers (`01-pragmatist.md`, `02-substrate-builder.md`, `03-scholar.md`, `04-strategist.md`)

## Where the four agents agree

1. **Walch pre-disclosure letter is the single highest-leverage human action and should ship this week.** Pragmatist, scholar, strategist all name it explicitly. It's a 6-12 week calendar burn that gates everything cross-disciplinary; starting now means the response window closes inside the parent paper's review cycle, not after.
2. **Sensor-grounded admission is the second paper to ship.** It's 18 pages, 4-theorem mechanized Lean, zero substantive findings on adversarial review, primary venue USENIX Security 2027 Cycle 1 (deadline 2026-08-25). Days of mechanical work, not weeks.
3. **The project-killer is thread overload, not paper rejection.** Strategist's framing is correct: solo-author + 5 active paper threads = none ships. Submission throughput is the binding constraint, not idea generation.
4. **V2 tier-1 (Docker localhost two-kernel federation) is the engineering investment that converts.** Strategist endorses (the only V-item that pays off inside 12 months), substrate-builder champions it. V6/V7/V8 don't convert to publications inside the window.
5. **Paper N1 reversible-action has an unresolved `rfl` gate.** Don't commit to writing it until the rollback-amendment composition theorem is shown non-`rfl` in Lean.

## Where the four agents disagree (and resolution)

| Disagreement | Pragmatist | Substrate Builder | Scholar | Strategist | **Resolution** |
|---|---|---|---|---|---|
| Hold parent for V2? | Submit now | Hold 3 weeks | Submit now | Submit now | **Submit now**. The 3-week delay buys at most a "we improved §6" claim against reviewers, but the parent's §9 already names "federation tests are in-process" as v2 work. Reviewers reading §9 see the honest caveat. The hold is risk-asymmetric. |
| Papers in 24 months | 2-3 submitted | 1-2 submitted | 6 submitted | 2 submitted + 1 workshop | **3 submitted + 1 workshop**. Splits the difference; aligns with strategist's 600-hour realistic budget. |
| Clawdstrike integration depth | Skip | Full | Skip / formal-model lane | Light | **Light + opportunistic**. Continue the pattern that worked for sensor-grounded: when a clawdstrike artifact strengthens a paper's empirical chapter, pull it in; don't pursue product-merger framing. |
| Anthropic co-author for parent | Skip | N/A | After Walch | N/A | **Skip for parent**. Pursue for agentic-tool-safety workshop submission only (Perez recommended primary). |
| Paper N2 delegated-emergency-authority | Cut | N/A | Pursue with Walch co-author | Calendar-gated by Walch | **Conditional on Walch response**. Don't draft further until Walch accepts the embargo; if she declines / delays, this paper sleeps. |

## The plan (24-month horizon)

### Weeks 1-2 (now through 2026-05-31): clear human-action backlog

- **Send Walch letter** (drafted at `papers/programmable-sovereignty/swarm-notes/walch-invitation-draft.md`). Human action. Highest-leverage single decision.
- **Pick parent-paper target venue**: NDSS 2027 Summer (deadline July 2026) or USENIX Security 2027 Cycle 1 (deadline 2026-08-25). NDSS is the systems-fit venue per the title; USENIX has higher author-pool capacity. Recommended: **NDSS 2027 Summer**.
- Begin parent-paper anonymization audit (no co-author additions yet, so anonymization is a 1-2 day pass).

### Weeks 3-6 (June 2026): ship parent paper

- Convert parent-paper to NDSS template (1-2 days).
- Anonymization (1-2 days).
- Final abstract polish.
- Submit. Parent paper goes out.

### Weeks 7-10 (July 2026): V2 tier-1 + sensor-grounded prep

- Engineering: V2 tier-1 (Docker localhost two-kernel federation) — 2-3 weeks. `tonic` gRPC over TLS, mTLS kernel identity, smoke-test runner. Strengthens sensor-grounded §3 if it lands before sensor-grounded ships.
- Sensor-grounded paper: template conversion + anonymization.

### Weeks 11-13 (August 2026): ship sensor-grounded

- Submit sensor-grounded to USENIX Security 2027 Cycle 1 (deadline 2026-08-25).

### Weeks 14-20 (September-October 2026): workshop submission + response cycles begin

- Agentic-tool-safety paper polish (2-3 weeks per its README).
- Submit to NeurIPS Safe-AI workshop or ICML AI Safety. Single venue, low ceremony.
- Anthropic outreach (Perez primary; the existing `anthropic-coauthor-outreach.md` memo).
- Begin handling parent-paper reviewer responses.

### Weeks 21-30 (November 2026 - January 2027): conditional execution

Two branches based on parent-paper outcome:

**If parent accepted at NDSS 2027 Summer:**
- Pursue Paper N1 reversible-action — but first, write the rollback-amendment composition theorem in Lean. If it discharges to `rfl`, kill the paper. If non-`rfl`, develop and target USENIX Security 2027 Cycle 2 (early 2027 deadline).
- Continue V6 (replay corpus expansion) as background engineering.

**If parent rejected:**
- Revise based on reviews, resubmit to USENIX Security 2027 Cycle 2 or CCS 2027.
- Hold Paper N1 until parent lands.

### Weeks 31-52 (February-May 2027): cross-disciplinary expansion (conditional)

**If Walch accepted the embargo and is open to co-authorship:**
- Develop Paper N2 delegated-emergency-authority. Legal academy cadence (12-18 month timeline). Target Yale JOLT or Stanford Law Review Online Q1-Q2 2027.

**If Walch declined or didn't respond:**
- This paper sleeps. Don't try to write a law paper without a legal co-author.

### Months 12-24: pipeline continuation (conditional, depends on above outcomes)

- Hart sociological study (Paper 3) — only if Walch co-author OR another legal-academy partner lands
- Trajectory-invariant POPL paper (Paper 4) — only if Anthropic / FM collaborator lands
- Paper 5 adversarial-replay: subsume into V2 + V6 engineering work; skip as standalone submission

## CUTS

The plan does NOT include:

- **Full clawdstrike integration** (substrate-builder's "merge as empirical chapter for next 24 months"). The light/opportunistic version is enough.
- **V7 (FROST/ROAST threshold cosigning)** and **V8 (BBS issuer-rotation epoch)** as standalone work. Address in §9 of papers as "future work" instead.
- **Paper 5 (adversarial-replay benchmark)** as a standalone paper. Roll into V2/V6 engineering.
- **Cross-region WAN federation (V2 tier 3)**. Tier 1 is enough.
- **Lean appendix for sensor-grounded paper** unless page budget after template conversion supports it.

## The one decision that resolves everything

**Has the Walch letter been sent?**

- If yes: the cross-disciplinary tier (Paper N2, Paper 3) is alive, the program has a co-author unlock, the 24-month arc is real.
- If no: the cross-disciplinary tier sleeps until it is, the program shrinks to 2 papers + 1 workshop, and the engineering work absorbs the freed attention.

The other three agents all flagged this. The strategist made it explicit: every week the letter doesn't go out is a week the program is one week shorter.

## Risk register

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Parent paper rejected at first venue | ~75% (typical 22-25% accept rate) | Medium | Hold a backup-venue plan ready; sensor-grounded ships independently |
| Sensor-grounded rejected | ~70% | Low (parent stands alone) | Backup: NDSS 2027 Spring or CSF 2027 |
| Walch declines / doesn't respond | ~40% | High (kills cross-disciplinary tier) | Have legal-academy backup list ready (Huq, Sunstein, Scheppele, Keller, Jaffer per cycle-3 RESEARCH) |
| Reversible-action `rfl` gate fails | ~50% (per cycle-2 adversarial review) | Medium | Substitute by promoting an agentic-tool-safety arm |
| Anthropic co-author declines | ~60% | Low (workshop submission still works without) | Submit without and revisit at acceptance |
| Time budget collapses (life event, day-job intensification) | ~30% inside 24 months | High | The plan has natural stop points after weeks 13 and 30; ship-and-pause is fine |

## Single-sentence summary

Send the Walch letter this week, submit the parent paper to NDSS 2027 Summer in 4-6 weeks, ship sensor-grounded to USENIX Security 2027 Cycle 1 in August, drop agentic-tool-safety at a NeurIPS workshop in fall, and gate everything else on whether Walch responds and whether parent lands its first venue.
