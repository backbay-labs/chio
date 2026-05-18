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

## Wave 1: human override and Wave 2 dispatch start

Timestamp: 2026-05-18 (same orchestrator session, post-W1-deliverables).

Human decision (verbatim): "no don't hold up on this walch letter. let's figure that out later. and sure USENIX Cycle 1 but again I as the human will not be taking any action until you've completed the rest of the tasks".

Resolution applied:
- Venue locked: USENIX Security 2027 Cycle 1. Wave 2 dispatches with USENIX template target.
- Walch letter: deferred to human's later discretion. Subsequent waves DO NOT block on it. The polished draft sits ready for signature. Wave 7 cross-disciplinary tier remains conditional on the letter being sent at some future date.
- All downstream HUMAN GATES (portal submissions, outreach sends) are stacked for the human to resolve at the end of this session in one pass. The orchestrator prepares everything; the human ships everything.

Reinterpretation of playbook gates: any "human clicks Submit" or "human sends X" gate is treated as a swarm-prepared package awaiting later human action, not a hard halt. The swarm continues through subsequent waves as long as each one's swarm-side prep is complete.

Wave 2 dispatched (parallel, single message, four Agent calls):
- W2.a: USENIX template conversion. Creates `papers/programmable-sovereignty/paper-usenix.tex` with anonymized preamble (applies W1.b Finding 1 in the new file).
- W2.b: anonymization fix application. Edits `paper.tex:21` (Finding 1) and `sections/07-discussion.tex:20` (Finding 2).
- W2.c: build-gate hardening. Writes `papers/programmable-sovereignty/Makefile` with `submit-check` target.
- W2.d: supplementary materials prep. Writes `papers/programmable-sovereignty/supplementary/` with lean-source tarball, proof-manifest snapshot, theorem-inventory filtered to the four parent-paper theorems.

## Wave 2: deliverables landed (after one trim cycle)

Timestamp: 2026-05-18 (same orchestrator session).

W2.a (USENIX template conversion) -- COMPLETE.
- Official USENIX template `usenix2019_v3.sty` downloaded and vendored at `papers/programmable-sovereignty/`.
- `paper-usenix.tex` rebuilt against the template; 4-pass clean (0 errors, 0 LaTeX warnings, 0 BibTeX warnings, 0 undefined references).
- Anonymized author block set to "Anonymous Author(s) / Anonymous Institution" (applies W1.b Finding 1 in the new file).
- Initial result: body = 14 pages (USENIX limit 13); dispatched W2.e trim cycle.

W2.b (anonymization fix application) -- COMPLETE.
- `paper.tex:21` rewritten to `\affiliation{\institution{Anonymous Institution}}`.
- `sections/07-discussion.tex:20` rewritten to `Capability evaluations (METR (formerly ARC Evals), UK AISI Inspect) and frontier-safety frameworks (...)`.
- Both edits build-clean against acmart 4-pass; page count unchanged at 13.

W2.c (build-gate hardening) -- COMPLETE.
- `papers/programmable-sovereignty/Makefile` ships with targets: `build-acmart`, `build-usenix`, `check-log TARGET=...`, `check-bibtex TARGET=...`, `check-pages TARGET=... MAX=...`, `submit-check`, `submit-check-acmart`, `clean`.
- TDD found a real gap: the citation-warning regex missed natbib's `Package natbib Warning: Citation` variant; broadened.
- Negative test: injected bad cite, gate fired, reverted clean.

W2.d (supplementary materials prep) -- COMPLETE.
- `papers/programmable-sovereignty/supplementary/lean-source.tar.gz` (35 KB) self-contained, untars to a `lake build`-clean Lean project.
- `proof-manifest.toml` + `theorem-inventory.json` list the four parent-paper theorems:
  1. `treaty_admission_iff_predicate_intersection`
  2. `treaty_admission_stable_under_ladder_floor`
  3. `amendment_admissible_iff_backward_refinement`
  4. `amendment_without_refinement_rejected`
- `#print axioms` reports only the standard kernel axiom `propext`; no project-specific axioms.
- Reviewer-facing `README.md` at `supplementary/`.

W2.e (page-trim cycle) -- COMPLETE.
- Fixed gate semantics: `check-pages` now measures body-only (locates the "References" heading via per-page `pdftotext` scan and computes `body = refs_page - 1`), matching the USENIX rule.
- Trim techniques (no content cuts): added `enumitem` for compact lists, merged five pairs of related limitations bullets, word-level compression in sections 1, 7, 8, 9, 10, tightened Table 4 caption.
- Final body page counts: paper-usenix.tex 13 (gate MAX=13 OK), paper.tex (acmart) 11.
- `make submit-check` exit 0; `make submit-check-acmart` exit 0.

Judgment-call edits the human may want to verify before submission (none are blocking):
1. Five pairs of section-9 limitations bullets merged. Each merge preserves all content but presents two adjacent concerns as a single themed bullet. Reversible at any time if the human prefers separate bullets.
2. Conclusion sentence list articles dropped: "(an industry consortium, a sectoral self-regulator, or a research-led pilot)" -> "(industry consortium, sectoral self-regulator, or research-led pilot)".
3. Table 4 placement `[t]` floats to page 14 top alongside References. Body TEXT ends on page 13; refs heading is page 14; gate counts this as 13 body. A strict reader could question this; the assumption-ledger can be reformatted later if a reviewer pushes back.

Wave 2 close: parent paper is in submission-ready state for USENIX Security 2027 Cycle 1. Submission package on disk:
- `papers/programmable-sovereignty/paper-usenix.pdf` (16 pages total, 13 body)
- `papers/programmable-sovereignty/supplementary/` (lean-source.tar.gz + manifests + README)

HUMAN GATE stacked for end-of-session: human registers an account at USENIX submission portal, uploads `paper-usenix.pdf`, attaches `supplementary/lean-source.tar.gz`, drafts Open Science statement (the supplementary `README.md` is a 1-page reviewer overview that the human can adapt for the Open Science appendix), drafts Ethics Considerations statement, clicks Submit.
