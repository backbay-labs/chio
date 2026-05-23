# E2E Execution Playbook (agent-executable)

Date: 2026-05-18
Source: this playbook converts `05-synthesis-plan.md` into a wave-by-wave executable spec for swarm dispatch.

## How this playbook works

- Each WAVE is a parallel batch of subagents with non-overlapping file scope.
- Waves run sequentially; each closes with a gate that hands off to the next.
- Subagents invoke `obra/superpowers` skills explicitly (see https://github.com/obra/superpowers). Skills referenced: `brainstorming`, `using-git-worktrees`, `writing-plans`, `subagent-driven-development`, `executing-plans`, `test-driven-development`, `requesting-code-review`, `dispatching-parallel-agents`, `finishing-a-development-branch`, `systematic-debugging`, `verification-before-completion`.
- Orchestrator (Claude) reads this playbook, dispatches wave N, waits for gate, dispatches wave N+1.
- HUMAN-GATED steps are marked with `[HUMAN]` and stop the swarm until the human acts. The swarm should NEVER auto-send external email, never sign as a human, never submit a paper without human approval.

## Wave naming convention

`W{n}.{letter}` where n is wave number and letter is the agent identifier within the wave. Example: `W3.b` is "wave 3, agent b".

## Branch and commit conventions

- One worktree per wave-group, named `research/wave-{n}-{shortname}` (the `using-git-worktrees` skill creates these).
- Conventional commits: `feat(papers):`, `fix(papers):`, `docs(papers):`, `chore(papers):`. Co-Authored-By: Claude trailer required.
- Each wave ends with one of: merge to `research/programmable-sovereignty-papers`, open PR for human review, or discard with reason.
- Build gate after every paper-text or Lean change (pdflatex 4-pass clean + lake build clean).

---

## Wave 1: Backlog clearance and venue selection (calendar weeks 1-2)

**Trigger**: orchestrator invocation. Preconditions: PR 684 merged to `research/programmable-sovereignty-papers` or treated as base.

**Parallelism**: 3 subagents in parallel + 1 human gate.

### W1.a: Walch letter polish

- Superpowers skill: `brainstorming` (Socratic refinement of the draft).
- File scope: `papers/programmable-sovereignty/swarm-notes/walch-invitation-draft.md`.
- Deliverable: final-form letter ready for the human to sign and send.
- **HUMAN GATE**: human reads polished letter, signs, sends. Subsequent waves do NOT block on Walch's reply, but cross-disciplinary tier in Wave 7 is conditional on it.

### W1.b: Anonymization audit of parent paper

- Superpowers skill: `requesting-code-review` (applied to prose; agent checks for author identifying signals).
- File scope: read-only sweep of `papers/programmable-sovereignty/sections/*.tex` + `paper.tex`.
- Deliverable: `.planning/e2e-execution-plan/wave1-anonymization-findings.md` listing per-section author signals (institution mentions, "we previously" pattern, github usernames, IRB references, etc.).
- Gate: zero findings or every finding has a queued fix.

### W1.c: Venue-selection decision memo

- Superpowers skill: `brainstorming`.
- File scope: writes `.planning/e2e-execution-plan/wave1-venue-decision.md`.
- Inputs: parent paper's title, contribution claims, page count (13 pages acmart), and `research/venue-fit-submission-readiness.md` (parent of the sensor-grounded paper has analogous content; reuse pattern).
- Deliverable: comparison of NDSS 2027 Summer (Jul 2026 deadline) vs USENIX Security 2027 Cycle 1 (Aug 2026 deadline) for the parent paper, with one recommendation. Tradeoffs: deadline distance, page-budget fit, simultaneous-submission policy (already checked for sensor-grounded; reverify for parent).
- **HUMAN GATE**: human picks one venue.

### Wave 1 close

Orchestrator confirms:
- Walch letter signed and (per human report) sent
- Anonymization findings either zero or queued
- Venue selected

Hands off to Wave 2 with target venue locked.

---

## Wave 2: Parent paper submission (calendar weeks 3-6)

**Trigger**: Wave 1 complete + venue selected.

**Parallelism**: 4 subagents in parallel + final assembly.

### W2.a: Template conversion

- Superpowers skill: `using-git-worktrees` + `executing-plans`.
- Creates worktree `wave-2/template-conversion`.
- File scope: `papers/programmable-sovereignty/paper.tex` + new sibling `paper-ndss.tex` (or `paper-usenix.tex` if USENIX was picked; the latter already exists in shell form).
- Deliverable: target-venue-template build clean, 4-pass pdflatex green, 0 BibTeX warnings, page count within target.

### W2.b: Apply anonymization findings

- Superpowers skill: `subagent-driven-development` with two-stage review (spec compliance + code quality, applied to prose).
- File scope: `papers/programmable-sovereignty/sections/*.tex` per Wave 1 findings list.
- Deliverable: zero author-identifying signals; commit per finding.

### W2.c: Build-gate hardening

- Superpowers skill: `test-driven-development` applied to the build pipeline.
- Writes `papers/programmable-sovereignty/Makefile` (if absent) or shell script that runs the 4-pass build gate and reports exit codes per pass, page count, BibTeX warning count, undefined citation count. Equivalent of a CI lane.
- File scope: build infrastructure only; no paper-text changes.
- Deliverable: `make submit-check` exits 0 iff the paper is submission-ready by the documented criteria.

### W2.d: Supplementary materials prep

- Superpowers skill: `executing-plans`.
- File scope: `papers/programmable-sovereignty/supplementary/` (create the directory).
- Deliverable: Lean source tarball (`lean-source.tar.gz` containing `formal/lean4/Chio/Chio/Treaty/` + `Chio.lean`), `proof-manifest.toml` snapshot, `theorem-inventory.json` filtered to the four parent-paper theorems. Each artifact named per venue convention.

### Wave 2 close

Orchestrator runs `make submit-check`. If green, packages submission. If red, dispatches `systematic-debugging` agent on the failure mode.

**HUMAN GATE**: human reviews the assembled package and clicks Submit on the venue submission portal. Swarm cannot auto-submit.

Wave 3 starts after human reports submission ID.

---

## Wave 3: V2 engineering and sensor-grounded prep (weeks 7-10, parallel)

**Trigger**: parent paper submission confirmed.

**Parallelism**: 2 subagents.

### W3.a: V2 tier-1 Docker localhost federation

- Superpowers skill: `using-git-worktrees` + `writing-plans` + `subagent-driven-development` + `test-driven-development`.
- Creates worktree `wave-3/v2-tier-1` on a new branch.
- File scope: `infra/federation-localhost/docker-compose.yml` (new), `crates/chio-federation/tests/e2e_two_kernel_docker.rs` (new), `.github/workflows/federation-localhost.yml` (new).
- Design source: `papers/programmable-sovereignty/swarm-notes/v2-two-kernel-federation-design.md`.
- Skill discipline: `writing-plans` produces task list with 2-5 minute tasks; `subagent-driven-development` dispatches a fresh subagent per task; `test-driven-development` writes failing E2E first.
- Deliverable: two `chio-cli` containers communicating over bridge network; 3-receipt admit/deny scenario converging; CI lane green.
- Wave 3 close-out gate: `cargo test -p chio-federation --test e2e_two_kernel_docker` exits 0; smoke test runs in CI on every PR.

### W3.b: Sensor-grounded paper template conversion + anonymization

- Superpowers skill: `executing-plans`.
- Creates worktree `wave-3/sensor-grounded-prep`.
- File scope: `papers/sensor-grounded-admission/paper.tex` + `paper-usenix.tex` (sibling for USENIX target).
- Deliverable: USENIX-template build clean, anonymization findings applied, supplementary `lean-source.tar.gz` packed.

### Wave 3 close

Both subagents merge to `research/programmable-sovereignty-papers`. Sensor-grounded paper is now submission-ready; V2 tier-1 is a deployed primitive that strengthens the next paper.

---

## Wave 4: Sensor-grounded submission (weeks 11-13)

**Trigger**: Wave 3 complete.

**Parallelism**: 1 subagent + human gate.

### W4.a: Submission assembly

- Superpowers skill: `verification-before-completion`.
- File scope: read-only verification of `papers/sensor-grounded-admission/`.
- Deliverable: `make submit-check` (Wave 2's harness, reused) returns green for sensor-grounded.

### Wave 4 close

**HUMAN GATE**: human clicks Submit at USENIX Security 2027 Cycle 1 portal (deadline 2026-08-25). Swarm records submission ID in `.planning/e2e-execution-plan/wave4-submission-receipt.md`.

---

## Wave 5: Workshop paper + outreach + review handling (weeks 14-20, parallel)

**Trigger**: Wave 4 closed.

**Parallelism**: 3 subagents + 1 reactive subagent dispatched on parent-paper review arrival.

### W5.a: Agentic-tool-safety polish for workshop

- Superpowers skill: `brainstorming` (refine the workshop pitch) + `executing-plans`.
- File scope: `papers/agentic-tool-safety/`.
- Deliverable: workshop-ready 4-6 page draft, clean build. Target venue: NeurIPS Safe-AI workshop or ICML AI Safety workshop (whichever has the closer deadline).

### W5.b: Anthropic outreach draft polish

- Superpowers skill: `brainstorming`.
- File scope: `papers/programmable-sovereignty/swarm-notes/anthropic-coauthor-outreach.md` and `papers/agentic-tool-safety/anthropic-coauthor-pitch.md`.
- Deliverable: ready-to-send email for human signature. Primary target: Perez (agentic-tool-safety) and Bowman (programmable sovereignty).
- **HUMAN GATE**: human sends.

### W5.c: Walch response handler (reactive)

- Superpowers skill: `brainstorming`.
- Trigger: Walch response arrives (human-reported).
- Deliverable: classified response (accept embargo / decline / no response / partial); branch-decision memo for Wave 7.
- If decline / no response by week 20: Wave 7 cross-disciplinary tier sleeps.

### W5.d: Parent-paper reviewer-response handler (reactive)

- Superpowers skill: `systematic-debugging` (applied to reviewer critiques).
- Trigger: parent-paper reviews arrive (typically 3-4 months after submission, so possibly later than week 20).
- Deliverable: structured response per reviewer with rebuttal / revision plan / "out of scope" verdict.
- If revisions requested by reviewers: launches mini-FIX cycle following the same swarm pattern as cycle 1-3 of the sensor-grounded paper.

### Wave 5 close

Workshop submission filed; outreach sent; reviewer responses tracked.

---

## Wave 6: Conditional fork on parent-paper outcome (week 21+)

**Trigger**: parent-paper accept/reject decision in hand.

### W6.a: ACCEPT branch — Reversible-action paper

- Superpowers skill: `brainstorming` + `test-driven-development` (applied to Lean).
- File scope: `papers/reversible-action/theorems.lean` first — write the rollback-amendment composition theorem statement and check whether it discharges to `rfl`.
- **GATE**: if `rfl` discharges trivially after definitional unfolding, KILL this paper. Report to human and pivot freed attention to Wave 7 if Walch in, else to engineering.
- If non-`rfl`: proceed with full paper development under `subagent-driven-development`, target USENIX Security 2027 Cycle 2.

### W6.b: REJECT branch — Revise and resubmit parent

- Superpowers skill: `receiving-code-review` (applied to PC reviews).
- File scope: `papers/programmable-sovereignty/`.
- Deliverable: revision per PC reviews + cover letter; resubmission target USENIX Security 2027 Cycle 2 or CCS 2027.

---

## Wave 7: Cross-disciplinary expansion (months 6-12, conditional)

**Trigger**: Wave 5 closed AND Walch accepted embargo (per Wave 5.c).

**Else**: this wave SLEEPS. Don't try to write a law paper without a legal co-author. Freed attention goes to engineering or Wave 8.

### W7.a: Delegated-emergency-authority paper development

- Superpowers skill: `brainstorming` (Socratic with Walch loops) + `writing-plans`.
- File scope: `papers/delegated-emergency-authority/`.
- Target: Yale JOLT or Stanford Law Review Online Q1-Q2 2027.
- Estimated timeline: 12-18 months.
- Wave-internal cadence: monthly check-ins with Walch; one paper-internal swarm cycle every 6 weeks (FIX -> WRITE -> RESEARCH -> REVIEW).

---

## Wave 8: Pipeline continuation (months 12-24)

**Trigger**: Wave 7 in flight or completed.

### W8.a: Hart sociological paper (Paper 3)

- Superpowers skill: `brainstorming`.
- Conditional on legal-academy co-author (Huq, Sunstein, Scheppele, Keller, Jaffer per the e2e plan).
- Target: Yale/Harvard JOLT Q1 2027.

### W8.b: Trajectory-invariant POPL paper (Paper 4)

- Superpowers skill: `writing-plans` + `subagent-driven-development` + `test-driven-development`.
- Conditional on formal-methods co-author (de Moura / Avigad / Sandholm-Ailios). Develops V5's `essential_preserved_chain` into a full paper.
- Target: POPL 2028 (deadline Jul 2027).

### W8.c: Adversarial-replay benchmark (Paper 5) — SUBSUMED

Per the e2e plan, this is rolled into V2/V6 engineering work and does NOT ship as a standalone paper.

---

## Orchestrator responsibilities

The orchestrator (Claude in the active session, or a successor) holds these responsibilities across all waves:

1. **State tracking**: append per-wave status to `.planning/e2e-execution-plan/wave-execution-log.md`. Entry per wave: trigger, dispatched agents, deliverables shipped, gate result, handoff to next wave.
2. **Worktree hygiene**: at wave close, run `finishing-a-development-branch` skill on each wave-group worktree (merge / PR / keep / discard).
3. **Build gate enforcement**: NEVER let a wave close without the build gate (or `make submit-check`) returning green. If red, dispatch `systematic-debugging` agent.
4. **Voice / engineering-meta discipline**: every paper-text-modifying subagent MUST be told (in its dispatch prompt) about the user's standing rule against engineering-meta voice. The rule has been flagged 4+ times across the parent paper's history; it is not optional.
5. **No-auto-send**: external outreach (Walch, Anthropic, IC3, conference submission portals) is HUMAN-only. The swarm prepares; the human ships.
6. **Termination**: the swarm has DONE conditions per wave (not per cycle). When all conditional branches resolve (Wave 6 accept or reject decided, Wave 7 alive or asleep, Wave 8 in flight or rolled into engineering), the orchestrator writes `.planning/e2e-execution-plan/execution-complete.md` and stops dispatching new waves.

## Cron and self-paced wakeup

For autonomous between-wave continuation, the orchestrator uses `ScheduleWakeup` (dynamic mode; the parent-paper autonomous cron pattern is the model) with cadence matched to the wave's nature:

- Daily / hourly cadence is wrong: waves are not paper-polish cycles; they have weekly-to-monthly natural rhythm.
- Calendar cadence: weekly check-in at Mondays 09:00 local. The orchestrator reads `wave-execution-log.md`, advances any wave whose gate has resolved, dispatches new subagents as needed.
- Event-driven cadence: the orchestrator arms `Monitor` (persistent) on the Walch-response file and on the parent-paper-review file (whichever filesystem location the human writes to when responses arrive). Either event wakes the orchestrator to advance the gated wave.

## What's deliberately NOT a wave

- Full clawdstrike integration: not a wave. Light/opportunistic per the e2e plan; subagents may pull clawdstrike artifacts into paper empirical chapters but the integration itself is not a deliverable.
- V7 (FROST) / V8 (BBS rotation): not a wave. In-paper `\section{Future work}` content only.
- Paper 5 standalone: subsumed.
- Cross-region WAN federation (V2 tier 3): out of scope.

## Single decision the plan still rests on

Has the Walch letter been sent? Wave 7 is alive iff yes. The wave cadence after Wave 5 forks here.

---

## Quick-reference dispatch table

| Wave | Calendar | Agents | Skills | Deliverable | Gate |
|---|---|---|---|---|---|
| 1 | weeks 1-2 | 3 + human | brainstorming, requesting-code-review | Walch letter signed-and-sent, anonymization findings list, venue picked | human |
| 2 | weeks 3-6 | 4 + human | using-git-worktrees, executing-plans, test-driven-development, subagent-driven-development, verification-before-completion | parent paper submitted | human submit |
| 3 | weeks 7-10 | 2 | using-git-worktrees, writing-plans, subagent-driven-development, test-driven-development | V2 tier-1 deployed; sensor-grounded ready | build gates |
| 4 | weeks 11-13 | 1 + human | verification-before-completion | sensor-grounded submitted | human submit |
| 5 | weeks 14-20 | 3 + reactive | brainstorming, executing-plans, systematic-debugging, receiving-code-review | workshop submitted, outreach sent | response arrival |
| 6 | week 21+ | 1 (branch) | brainstorming OR test-driven-development OR receiving-code-review | reversible-action proceeds-or-killed; OR revised parent | rfl gate / venue decision |
| 7 | months 6-12 | 1 (conditional) | brainstorming, writing-plans | delegated-emergency-authority drafted | Walch monthly check-ins |
| 8 | months 12-24 | 1-3 (conditional) | brainstorming, writing-plans, subagent-driven-development, test-driven-development | papers 3-4 drafted IF co-authors land | co-author landings |
