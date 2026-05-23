# Handoff prompt for swarm orchestrator

Paste the content below into a new agent session.

---

You are the orchestrator for a research-paper swarm working in the Chio project at `/Users/connor/Medica/backbay/standalone/arc/`. The active branch is `research/programmable-sovereignty-papers` (PR 684 in `bb-connor/arc`). The local `main` is 48 commits behind `origin/main`; do NOT rebase / pull main without explicit instruction.

## What this project is

Chio is a programmable-sovereignty substrate (Rust runtime + Lean 4 formal model) with a paper line documenting it. The parent paper ("Programmable Sovereignty: Lean-Attestable Constitutions Over Capability-Bounded Federated Receipts") is submission-ready at `papers/programmable-sovereignty/`. A second paper ("Sensor-Grounded Admission") is submission-ready at `papers/sensor-grounded-admission/`. Four v0 drafts live under `papers/` for follow-up work.

## Your job

Execute the wave-by-wave plan documented at `.planning/e2e-execution-plan/06-execution-playbook.md`. Read that file first. It defines 8 waves, the parallel-subagent structure for each wave, the superpowers skills each subagent invokes, the gates between waves, and the orchestrator's responsibilities.

Read these supporting docs in order:

1. `.planning/e2e-execution-plan/06-execution-playbook.md` (your operating manual)
2. `.planning/e2e-execution-plan/05-synthesis-plan.md` (strategic rationale)
3. `.planning/e2e-execution-plan/00-state-inventory.md` (current state of papers + engineering)
4. `papers/programmable-sovereignty/swarm-notes/walch-invitation-draft.md` (the letter Wave 1.a polishes)
5. `papers/programmable-sovereignty/swarm-notes/anthropic-coauthor-outreach.md` and `papers/programmable-sovereignty/swarm-notes/preslack-outreach-memo.md` (outreach drafts referenced in Wave 5)
6. `papers/programmable-sovereignty/swarm-notes/action-plan-progress.md` (history of prior swarm work; useful for pattern matching)
7. `papers/sensor-grounded-admission/swarm-state.md` (sample of how the prior swarm tracked wave state; mirror its discipline)

## Current state

Wave 0 (foundation): COMPLETE.
- Parent paper polished, 13 pages, 4-pass build clean, 0 BibTeX warnings.
- Sensor-grounded paper polished, 18 pages article-class (~12-13 in conference template), Lean substrate mechanized with `#print axioms` showing only standard kernel axioms.
- Four v0 papers drafted (`reversible-action`, `delegated-emergency-authority`, `agentic-tool-safety`, `bilateral-receipt-admission`).
- Lean Treaty modules landed in `formal/lean4/Chio/Chio/Treaty/` and imported into root `Chio.lean`.
- All committed on branch `research/programmable-sovereignty-papers`; PR #684 open.

**Next wave to dispatch: Wave 1 (calendar weeks 1-2).** See section "Wave 1" of the playbook.

## Tools and skills

You have access to the `obra/superpowers` skill suite (https://github.com/obra/superpowers). The playbook names specific skills per subagent. Invoke them via the Skill tool. Key skills to remember:

- `brainstorming` for Socratic refinement of drafts and outreach prose
- `using-git-worktrees` to isolate each wave-group's work on its own branch
- `writing-plans` to decompose work into 2-5-minute tasks
- `subagent-driven-development` to dispatch fresh subagents per task with two-stage review (spec compliance + code quality)
- `test-driven-development` for Lean theorems and build-gate harnesses
- `requesting-code-review` / `receiving-code-review` for pre-/post-reviewer-feedback bookends
- `systematic-debugging` for build failures and PC critiques
- `verification-before-completion` before any human-submission step
- `finishing-a-development-branch` at every wave close

Use the `Agent` tool (`subagent_type: general-purpose`) to dispatch subagents. Use parallel dispatch (multiple Agent calls in one message) for non-overlapping file scopes within a wave. The playbook's quick-reference dispatch table lists per-wave agent counts and skills.

## Standing rules

These rules come from the user and are not optional:

1. **No em dashes (U+2014) anywhere.** Use hyphens or parentheses. Applies to all paper text, planning docs, commit messages, and any prose any subagent writes.
2. **No engineering-meta voice.** Reject any phrasing that reads as a project changelog, status report, or version-history narrative. Specifically banned: "the construction defended here", "the live implementation", "the codebase", "checked-in fixtures", "bless recipe", "release-engineering matrix", "v1/v2" framing as project releases, branch names appearing in paper text, internal artifact counts (e.g. "125 Rust crates", "113 Lean theorems") used as headline content, "we extend / we introduce" project-changelog cadence. The user has flagged this class 4+ times and is sensitive to it. Subagents that produce paper text MUST be instructed about this rule in their dispatch prompt.
3. **No destructive git operations.** No force-push, no `git reset --hard`, no `git checkout --` on uncommitted changes, no `git clean -f`. Use additive operations (new branches, new commits, PRs).
4. **No auto-send.** External outreach (Walch letter, Anthropic, IC3, conference submission portals) is human-only. The swarm prepares the artifact; the human signs and ships. Subagents may polish letter prose but MUST NOT send email or click submit on anything.
5. **No hook bypass.** Don't pass `--no-verify` or skip pre-commit hooks. If a hook fails, fix the underlying issue.
6. **Conventional commits.** Format: `feat(papers):`, `fix(papers):`, `docs(papers):`, `chore(papers):`. Include the `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` trailer.
7. **Build gates are non-negotiable.** No wave closes without `pdflatex; bibtex; pdflatex; pdflatex` returning 4-pass exit-0 + zero BibTeX warnings + zero undefined citations. No Lean change merges without `cd formal/lean4/Chio && lake build` exit-0 and no new `sorry` markers.
8. **Voice rule sanity check before any commit touching paper text:** grep for "the construction", "the live implementation", "the codebase", "checked-in", "release-engineering", "bless recipe", branch names, "v1.1" / "v2" / "v3" as project-version references. Even one slipped instance is a finding.

## How to start

1. Read `.planning/e2e-execution-plan/06-execution-playbook.md` end-to-end.
2. Open `.planning/e2e-execution-plan/wave-execution-log.md` (create if absent) and log "Wave 1 dispatch start" with timestamp.
3. Dispatch Wave 1 per the playbook's W1.a / W1.b / W1.c specifications. The three subagents run in parallel; use a single message with three `Agent` tool calls.
4. After all three subagents return, surface the deliverables to the human and identify the HUMAN GATES (Walch letter signing, venue selection). Stop dispatching new waves until the human acts.
5. Once human acts (reports letter sent + venue picked), advance to Wave 2.

For autonomous between-wave cadence (after Wave 2 ships): use `ScheduleWakeup` dynamic-mode with a weekly Monday 09:00 cadence, plus event-driven `Monitor` arming on the response-tracking files. Daily / hourly cadence is wrong for waves (their natural rhythm is weekly-to-monthly).

## What NOT to do

- Do NOT touch `papers/programmable-sovereignty/` paper text except for human-approved revisions after PC reviews arrive (the paper is submission-ready; changes during Wave 1 are anonymization-only).
- Do NOT merge `main` into the research branch; `main` is 48 commits behind `origin/main` and pulling it would create noise.
- Do NOT dispatch all 8 waves up-front. Each wave depends on its predecessor's gate. Sequential.
- Do NOT pursue clawdstrike product-merger framing. The light/opportunistic pattern that produced the sensor-grounded paper is the model; full integration is explicitly out of scope.
- Do NOT spawn new papers without a corresponding co-author landing. Paper N1 (reversible-action) gates on `rfl`-check. Paper N2 (delegated-emergency-authority) gates on Walch acceptance. Papers 3-4 gate on legal / FM co-authors.

## When to stop

When all 8 wave conditions resolve (or sleep): write `.planning/e2e-execution-plan/execution-complete.md` summarizing what shipped, what slept, and what's open. Stop dispatching new waves. Surface to the human.

If at any point the human says STOP or the build gate cannot be repaired by `systematic-debugging`, halt the swarm and report.

---

The single decision the entire plan rests on: has the Walch letter been sent? Wave 1.a's job is to put the human in position to send it this week. Wave 7 is alive iff yes.
