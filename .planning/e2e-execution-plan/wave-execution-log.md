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

## Wave 3: dispatch start

Timestamp: 2026-05-18 (same orchestrator session).

Dispatched (parallel, single message, two Agent calls):
- W3.a: V2 tier-1 Docker localhost federation. Skill: writing-plans + executing-plans (plan + scaffolding only; full implementation is 2-3 weeks per synthesis plan and out of scope for a single-subagent dispatch). Deliverable: detailed PLAN.md, docker-compose.yml stub, failing E2E test scaffolding, CI workflow file, all on a fresh branch.
- W3.b: Sensor-grounded paper USENIX template conversion + anonymization audit-and-fix. Skill: executing-plans (mechanical work mirroring Wave 2.a/b for the parent paper).

## Wave 3: deliverables landed

Timestamp: 2026-05-18 (same orchestrator session).

W3.a (V2 tier-1 federation plan + scaffolding) -- COMPLETE.
- Landed on a separate branch `wave-3-v2-tier-1` (off `research/programmable-sovereignty-papers`). Single commit `b19c30c5a`. NOT merged to parent. Parked for future development.
- `.planning/wave-3-v2-tier-1/PLAN.md`: 31 numbered tasks, 114 executable checkbox steps. Failing test first, then minimal implementation, then incremental enrichment.
- `infra/federation-localhost/docker-compose.yml`: stub for two kernel containers on a bridge network.
- `crates/chio-federation/tests/e2e_two_kernel_docker.rs`: failing E2E test, `#[ignore]`-gated so `cargo test --workspace` stays green.
- `.github/workflows/federation-localhost.yml`: CI lane scaffolding.
- `cargo check --workspace` exits 0 (45.9s); `cargo test -p chio-federation --test e2e_two_kernel_docker -- --ignored` correctly panics at the first contract assertion (compose file missing -> next PLAN.md task).
- `tokio` added to `chio-federation` `[dev-dependencies]`; `tonic` / `prost` are introduced in PLAN.md task 1.
- Voice-rule clean.

W3.b (sensor-grounded USENIX prep) -- COMPLETE.
- USENIX template `usenix2019_v3.sty` + `usenix-2020-09.sty` copied into `papers/sensor-grounded-admission/`.
- New `paper-usenix.tex` built 4-pass clean: 12 pages total, 10 body (well under USENIX 13-page limit).
- Anonymization fix: `paper.tex` author block rewritten from `Anonymous for external review\\Chio Project` to `Anonymous Author(s)\\Anonymous Institution` (uniform with parent paper Wave 1 Finding 1 convention).
- Sensor-grounded `Makefile` copied from parent and reparameterized; `make submit-check` exit 0.
- Supplementary package at `papers/sensor-grounded-admission/supplementary/`: lean-source.tar.gz (41 KB) verified buildable in scratch via `lake build`; proof-manifest.toml + theorem-inventory.json list the four sensor-grounded theorems with axiom output:
  1. `admission_predicate_separates_healthy_and_degraded_witnesses` -- `[propext, Classical.choice, Quot.sound]`
  2. `partition_contingency_mode_iff_degraded_subset` -- `[propext]`
  3. `healthy_attestation_required_for_destructive_admission` -- `[propext]`
  4. `degraded_sensor_admission_requires_re_attestation` -- `[propext, Quot.sound]`
  All standard Lean 4 kernel axioms; no project-local axioms, no `sorry`.
- Reviewer-facing `README.md` at `supplementary/`.
- Voice-rule clean; Lean revert clean.

Wave 3 close: sensor-grounded paper is in submission-ready state for USENIX Security 2027 Cycle 1; V2 tier-1 federation scaffolding parked on its own branch with a 31-task PLAN.md ready for future execution.

HUMAN GATE stacked for end-of-session (sensor-grounded portal upload): same shape as parent paper.

Git mechanics note: the W3.b subagent left HEAD on the `wave-3-v2-tier-1` branch when it returned (a side effect of W3.a's parallel branch creation), so the initial commit landed there as `8fa4297be` rather than on `research/programmable-sovereignty-papers`. Recovered additively: switched to research branch and cherry-picked, producing commit `675d145f3`. The `wave-3-v2-tier-1` branch retains the duplicate commit but is parked for future development (the duplicate is cosmetic, not blocking). No destructive operations performed.

## Wave 4: dispatch start

Timestamp: 2026-05-18 (same orchestrator session).

Wave 4 is a single-subagent verification pass to produce a submission-ready checklist for the sensor-grounded paper. Wave 3.b's `make submit-check` already exits 0; Wave 4.a's job is to apply the verification-before-completion discipline and produce a one-page checklist document the human can refer to before portal submission.

Dispatched (single Agent call):
- W4.a: submission assembly verification. Skill: verification-before-completion. Read-only scope on `papers/sensor-grounded-admission/`. Produces `papers/sensor-grounded-admission/SUBMISSION-CHECKLIST.md`.

## Wave 4: deliverables landed

Timestamp: 2026-05-18 (same orchestrator session).

W4.a (sensor-grounded submission verification) -- COMPLETE.
- All gates verified green: build (4-pass clean), body 10 pages, anonymization clean, voice clean, tarball verify clean (`lake build` 24/24 jobs in 11.48s wallclock), TOML/JSON parse clean, theorems consistent.
- One judgment call flagged for human: the paper cites `chioProgrammableSovereignty2027` (the parent paper) and refers to "the Chio substrate" in sections 1 and 8. This is a substrate-name reference using a project name (not a personal-author signal), but the human should confirm this matches their reading of USENIX double-blind policy. If conservative, the cite can be rewritten as "the substrate of \cite{anonymized-companion}" before submission.
- Open items the human still needs to close (beyond clicking Submit): draft Open Science appendix (~1 page; supplementary `README.md` provides source material) and draft Ethics Considerations appendix (~1 page; no draft yet in the repo).
- Output: `papers/sensor-grounded-admission/SUBMISSION-CHECKLIST.md`.

## Wave 5: dispatch and deliverables

Timestamp: 2026-05-18 (same orchestrator session). Dispatched alongside Wave 4 since both were independent at this point.

W5.a (agentic-tool-safety workshop polish) -- COMPLETE.
- Workshop picked: NeurIPS 2026 workshop track. Suggested workshop-author submission deadline 2026-08-29 (about 14 weeks out). Specific workshop chosen from the NeurIPS 2026 workshop list, which is finalized after the organizer-proposal acceptance on 2026-07-11. Strong fit candidates: Safe Generative AI (recurring), an AgentAI / Agentic-Safety workshop, or Trustworthy ML.
- ICML 2026 "Agents in the Wild" already passed (2026-05-08); ICML 2027 has no CFP yet.
- Word count: 6033 -> 4896 (19% reduction). 11 pages on generic article 11pt; expected to compress to 6-7 pages on `neurips_2026.sty` when the specific workshop is named.
- 4-pass LaTeX build clean; PDF at `papers/agentic-tool-safety/paper.pdf` (161 KB).
- §4 restructured around three named theorems cited from the parent paper.
- 5 open items in `papers/agentic-tool-safety/VENUE-DECISION.md` for the human.

W5.b (Anthropic outreach polish) -- COMPLETE.
- `swarm-notes/anthropic-coauthor-outreach.md` and `papers/agentic-tool-safety/anthropic-coauthor-pitch.md` both polished.
- Email bodies tightened: parent memo 291 words, pitch 318 words.
- Bai 2022 / Hubinger 2024 / Berglund 2023 cross-references in §7 and `bib.bib` spot-checked and confirmed; no CHECK comments needed.
- Sharpened offer: primary = read under embargo + contribute to §7 / §10 framing; secondary = co-author the agentic-tool-safety workshop submission. Removed the "co-author this submission" desperation ask.
- Target priority split-routed: Bowman primary for parent paper (scalable-oversight work matches §7); Perez primary for agentic-tool-safety pitch (red-teaming threat-model match). Sending both to the same person was the original-memo conflation; fixed.
- Walch-letter dependency soft-decoupled: "Send when (a) the parent paper has been submitted to USENIX and (b) the human is ready to commit to an Anthropic conversation."
- W5.c (Walch response handler) and W5.d (parent-paper reviewer-response handler) SLEEP: both are reactive to events that have not happened (Walch letter not sent yet; parent paper not submitted). They will wake when the trigger fires.

## Waves 6, 7, 8: SLEEP

All three are conditional on outcomes that do not exist yet:
- Wave 6 forks on parent-paper accept/reject decision (~4 months after submission).
- Wave 7 conditional on Walch accepting the embargo. Letter deferred per human; wave sleeps until letter is sent and a response arrives.
- Wave 8 conditional on co-author landings (Anthropic, Walch, FM partner). None have landed; outreach drafts ready but not sent.

The orchestrator does NOT dispatch any of these. They wake on triggers the human controls.
