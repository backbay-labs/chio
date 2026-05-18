# Wave Execution Log

Tracks per-wave orchestrator state for the programmable-sovereignty paper swarm. Source-of-truth playbook: `06-execution-playbook.md`. Strategic rationale: `05-synthesis-plan.md`.

Conventions:
- One entry per wave dispatch and per wave close.
- Timestamps are local (Pacific, per repo).
- HUMAN GATES are called out explicitly; the swarm halts on them.

---

## Wave 1: dispatch start

Timestamp: 2026-05-18 (orchestrator session start).

Trigger: orchestrator invocation. PR 684 on `bb-connor/arc` is the working base; local `main` is 48 commits behind `origin/main` and is NOT being rebased per standing rules.

Dispatched (parallel, single message, three Agent calls):

- W1.a: Walch letter polish. Skill: brainstorming. Scope: `papers/programmable-sovereignty/swarm-notes/walch-invitation-draft.md`. Deliverable: final-form letter ready for human signature.
- W1.b: Anonymization audit of parent paper. Skill: requesting-code-review (applied to prose). Scope: read-only sweep of `papers/programmable-sovereignty/sections/*.tex` + `paper.tex`. Deliverable: `.planning/e2e-execution-plan/wave1-anonymization-findings.md`.
- W1.c: Venue-selection decision memo. Skill: brainstorming. Scope: writes `.planning/e2e-execution-plan/wave1-venue-decision.md`. Deliverable: NDSS 2027 Summer vs USENIX Security 2027 Cycle 1 comparison with one recommendation.

Pending HUMAN GATES at wave close:
1. Sign and send the Walch letter (W1.a deliverable).
2. Pick the parent-paper target venue (W1.c deliverable).

Wave 2 cannot dispatch until both gates resolve.

## Wave 1: deliverables landed

Timestamp: 2026-05-18 (same orchestrator session).

W1.a (Walch letter polish) -- COMPLETE.
- File: `papers/programmable-sovereignty/swarm-notes/walch-invitation-draft.md`.
- Voice: 351 words letter body, em-dash-clean, banned-phrase-clean.
- Material edit: subagent caught and corrected a section-reference error in the prior draft (Walch is cited in §8, not §2 as the draft claimed). Two `<!-- CHECK: ... -->` comments flag points for the human to verify before signing.
- Format 2 ("private comments only") sharpened so it reads as a credible standalone offer rather than a fallback to format 1.

W1.b (anonymization audit) -- COMPLETE.
- File: `.planning/e2e-execution-plan/wave1-anonymization-findings.md`.
- Verdict: fixes queued (0 critical, 1 major, 1 minor).
- Finding 1 (major): `paper.tex:21` has `\affiliation{\institution{Chio Project}}`. Should be redacted to "Anonymous Institution" or omitted under acmart anonymous mode. The project name "Chio" is fine everywhere else as artifact name; metadata slot only.
- Finding 2 (minor): `sections/07-discussion.tex:20` lists "ARC Evals" alongside METR. Routine external-org cite, but residual ambiguity given the ARC -> Chio internal rename. Suggested fix: drop "ARC Evals" or rewrite "METR (formerly ARC Evals)".
- Wave 2.b will apply both fixes.

W1.c (venue decision memo) -- COMPLETE.
- File: `.planning/e2e-execution-plan/wave1-venue-decision.md`.
- Headline recommendation: USENIX Security 2027 Cycle 1 (deadline 2026-08-25).
- Material finding: the playbook's premise of "NDSS 2027 Summer (July 2026)" is wrong. NDSS Summer closed Wednesday May 6, 2026 (12 days before this memo). The real choice is NDSS Fall (deadline August 19, 2026) vs USENIX Cycle 1 (August 25, 2026). Six-day spread; the NDSS calendar advantage that motivated the playbook's recommendation no longer exists.
- Dominant factor in the recommendation: paper contribution shape (formal core + systems substrate + worked example, no measurement) fits USENIX historically better than NDSS, and Cycle 2 (January 26, 2027) preserves a same-family re-roll.
- Risk: the sensor-grounded paper is also targeted to USENIX Cycle 1. Two distinct papers from the same author at the same conference cycle is allowed by USENIX, but concentrates PC exposure. NDSS Fall for the parent would split the two papers across different PCs.
- Reversal triggers: PC-chair conflict, co-author addition that reshapes framing, measurement results landing before deadline, or sensor-grounded slipping cycles.

## Wave 1: open HUMAN GATES

Two gates remain. The swarm halts on both. Wave 2 dispatches only after both resolve.

GATE 1 -- Walch letter: human reads the polished letter, verifies the two `<!-- CHECK: ... -->` comments against the current manuscript, signs, and sends. Subsequent waves do NOT block on Walch's reply (Wave 7's cross-disciplinary tier is the only thing conditional on it).

GATE 2 -- Venue selection: human picks USENIX Security 2027 Cycle 1 (subagent's recommendation) or NDSS 2027 Fall (the only credible alternative now that Summer is closed). The choice locks the Wave 2 template-conversion target.

When both gates resolve, the orchestrator dispatches Wave 2 (four subagents + final assembly, per playbook §"Wave 2").
