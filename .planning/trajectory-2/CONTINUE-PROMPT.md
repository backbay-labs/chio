# Chio Trajectory-2 Continue From Pause-Point

Paste this into a fresh Claude Code session at the repo root
(`/Users/connor/Medica/backbay/standalone/arc/`). You are picking up a
trajectory-2 autonomous run at a specific pause-point. Read this in
full, then act.

This document is a **template**. Before running it, the operator must
fill in the `<EDIT>...</EDIT>` markers in section 1 and section 4 with
the live state at the moment the prior session paused. Grep for
`<EDIT>` to find every fill-me-in spot.

For the general-purpose continuation prompt (no pause-point known),
use `.planning/trajectory-2/HANDOFF-PROMPT.md` instead.

---

## 1. Where you are

<EDIT> origin/<trajectory-2-integration-branch> HEAD: X of 319 tickets merged. </EDIT>

<EDIT> Open PRs: N. </EDIT>

<EDIT> Ready unblocked tickets (deps merged, no scope issues, no freeze
collision): N (enumerated below in section 4 or in chat context). </EDIT>

<EDIT> Blocked tickets needing scope/API decisions: N (enumerated in
section 4). </EDIT>

<EDIT> Last merged PR: #NNN (M{nn}.P{p}.T{k}). </EDIT>

<EDIT> Current wave: W{1-4}. Trust-boundary freezes active:
<list of freeze ids from freezes.yml that are currently between
start_trigger and end_trigger>. </EDIT>

The prior orchestrator paused at <EDIT> first clean stop point /
operator request / canonical halt trigger <NN> </EDIT> because
<EDIT> short prose: every remaining pending ticket either has an
undersized owner_glob, a missing soft-dep, or a structural design
question the YAML doesn't resolve / executor billing budget renewal /
operator-requested checkpoint review. </EDIT>

**Your job: <EDIT> unblock the N blockers in section 4. Make
judgment calls per section 5. Keep shipping until the next clean stop
point or until trajectory-2 closes. </EDIT>**

## 2. Authorization (the user said: "keep pushing autonomously")

The prior session was conservative on certain authorities. The user
has explicitly upgraded that authority for this run. The standing
authorizations from `HANDOFF-PROMPT.md` section 6 are all in force,
plus:

### You may, without further confirmation:

- **Expand `owner_glob`** when the milestone narrative clearly
  anticipates the path. Document the expansion in the PR body under
  `## Scope expansion` with a one-line citation
  (`.planning/trajectory-2/{NN}-{slug}.md` filename + line range).
- **Add a workspace dep** when `decisions.yml` names the primitive
  (e.g. D08 names `fips204` for ML-DSA-65, D15 names the bounded
  mpsc channel shape, D17 names the five new providers). Pin to a
  workspace-stable version. Note the dep + rationale in
  `## Dependency added`.
- **Narrow a gate-check** when the canonical command exercises code
  outside the ticket's true scope. Substitute a tighter
  `cargo test -p <crate> --test <suite>` that exercises the same
  contract. Note in `## Gate-check adapted`.
- **Land a small predecessor crate change** when a ticket's soft-dep
  mentions an existing crate's hook that turns out not to exist. The
  fix lives in the dependent ticket's PR; document under
  `## Predecessor change`.
- **Admin-merge** every PR via
  `gh pr merge <N> --repo bb-connor/arc --squash --admin --delete-branch`
  while CI billing remains exhausted (carry-over from trajectory-1
  PR #188 onward).
- **Rebase + force-with-lease** to resolve `Cargo.lock` and workspace
  `Cargo.toml` `[workspace] members` conflicts. Prefer cargo-regenerated
  `Cargo.lock`; for added/added files (`wit/`, fixtures), prefer the
  upstream-merged version with `git checkout --ours`.

### You must still halt for:

- The seventeen canonical halt triggers in section 6 below.
- Any executor proposal that contradicts a `decisions.yml` D-entry.
- Cross-doc invariant violations (the eleven artifacts in
  `EXECUTION-BOARD.md` section 3).
- Forbidden actions (bumping crate versions minor/major,
  dropping/`#[ignore]`-ing passing tests, adding
  `#[allow(clippy::...)]`, force-pushing shared commits).
- Workspace one-liner failure post-merge.
- Three consecutive executor failures on the same ticket.

For halts, post a chat message and continue scheduling other unblocked
work. Halts are per-ticket unless trigger 2, 12, 13, or 17 fires.

## 3. Per-wave status check

Before scheduling, recompute remaining tickets per wave from
`tickets/manifest.yml` and the integration-branch git log. Recipe:

```bash
# Count merged trajectory-2 tickets on the integration branch.
INTEGRATION=<EDIT>origin/project/roadmap-trajectory-2-2026-04-29</EDIT>
git log --oneline main..$INTEGRATION \
  | grep -oE '\[M(0[1-9]|10)\.P[0-9.]+\.T[0-9a-z.]+\]' \
  | sort -u > /tmp/merged.txt
wc -l /tmp/merged.txt   # expected: <EDIT>X</EDIT>

# Count open PRs against trajectory-2 wave/* branches.
gh pr list --repo bb-connor/arc --state open --limit 200 \
  --json number,title,headRefName \
  | jq -r '.[] | select(.headRefName | startswith("wave/W"))
                 | (.title | capture("\\[(?<id>M[^\\]]+)\\]") | .id)' \
  | sort -u > /tmp/in_pr.txt
wc -l /tmp/in_pr.txt    # expected: <EDIT>N</EDIT>

# Pending = total minus merged minus in-PR.
yq -N ea '.[] | .id' .planning/trajectory-2/tickets/M*/P*.yml \
  | sort -u > /tmp/all_ids.txt
comm -23 /tmp/all_ids.txt <(cat /tmp/merged.txt /tmp/in_pr.txt | sort -u) \
  > /tmp/pending.txt
wc -l /tmp/pending.txt
```

Per-wave pending breakdown (fill in after running the recipe above):

| Wave | Milestones | Total | Merged | In-PR | Pending |
|------|------------|-------|--------|-------|---------|
| W1   | M01, M02, M06 | 90  | <EDIT> | <EDIT> | <EDIT> |
| W2   | M03, M04, M05 | 89  | <EDIT> | <EDIT> | <EDIT> |
| W3   | M07, M08      | 68  | <EDIT> | <EDIT> | <EDIT> |
| W4   | M09, M10      | 71  | <EDIT> | <EDIT> | <EDIT> |
| **Sum** |          | 319 | <EDIT> | <EDIT> | <EDIT> |

(W1 = 29+30+31, W2 = 31+32+26, W3 = 34+34, W4 = 38+33; per
`EXECUTION-BOARD.md` section 1 row counts.)

## 4. Currently blocked tickets (template)

For each blocked ticket the prior session identified, fill in one
sub-section. When you spawn the executor for that ticket, paste the
unblock block into the prompt's `## Source-of-truth references` and
`## Task` sections so the executor doesn't re-discover the issue.

### 4.1 <EDIT> M{NN}.P{p}.T{k} </EDIT> - <EDIT> short title </EDIT>

**Block:** <EDIT> short statement of why this ticket cannot run as
authored. Examples: needs primitive choice X; soft-dep on Y doesn't
exist on integration branch; owner_glob too narrow for real wiring;
gate-check pulls in unrelated work; freeze-guard blocks because path
overlaps an active freeze; depends_on a ticket the prior session
deferred. </EDIT>

**Unblock:**
- <EDIT> Specific decision: choice of primitive, owner_glob expansion,
  dep addition, soft-dep landing as predecessor change. Cite the
  decisions.yml D-entry, the milestone narrative section + line
  range, and the freeze register entry where relevant. </EDIT>
- <EDIT> Citations:
  `.planning/trajectory-2/{NN}-{slug}.md` Phase {n} Task {m},
  `decisions.yml` D{NN},
  `freezes.yml` {freeze_id}. </EDIT>

(Repeat 4.1 for every blocked ticket. trajectory-1 had 13 blockers at
its CONTINUE-PROMPT pause-point; trajectory-2 will likely accumulate a
different number at each pause. Common pattern is for blocked tickets
to cluster around freeze-guard collisions in M03/M04/M05/M10 and
around `Cargo.lock` ordering at wave-opener boundaries.)

### 4.N <EDIT> M{NN}.P{p}.T{k} </EDIT> - <EDIT> short title </EDIT>

(... continue for each remaining blocker ...)

## 5. Decision authority

When to make judgment calls vs ping the user:

**Make the call yourself if:**
- The ambiguity is resolved by `decisions.yml` (D01..D24). Cite the
  D-entry in the PR body.
- The ambiguity is resolved by the milestone narrative
  (`{NN}-{slug}.md`). Cite section + line range.
- The choice is between two primitives in the same family the
  workspace already uses (RustCrypto, tokio ecosystem, serde
  ecosystem) and `decisions.yml` does not name a specific choice.
  Document the choice in the PR body.
- A ticket's gate-check command pulls in unrelated work. Substitute a
  narrower invocation; document in PR body.
- An owner_glob is one path short of what the narrative anticipates.
  Expand and document.

**Ping the user if:**
- The choice contradicts a `decisions.yml` D-entry. (This is halt
  trigger 9.)
- The choice would require waking a dormant crate not named in D21.
- The choice would add a new Kani harness beyond the four in M04 P4
  (D11 caps the trajectory-2 Kani surface).
- The choice would promote arena-generated scenarios into the M04
  corpus directly (D20 forbids; they land in
  `tests/replay/fixtures/arena/`).
- The choice would in-browser-sign anything (D23 forbids; passkey is
  authn, not signing material).
- The narrative does not cover the case AND `decisions.yml` does not
  cover the case.

When in doubt, halt and ping. The trajectory-2 ticket count is high
enough that one missed halt costs more than two unnecessary halts.

## 6. The seventeen halt triggers

The eleven canonical (carried from trajectory-1) and the five
trajectory-2-specific (from `EXECUTION-BOARD.md` section 7 plus the
decisions register) plus the operator-discretion catch:

1. Soft-dep contract failure.
2. Workspace one-liner failure post-merge.
3. Three consecutive executor failures on the same ticket.
4. Divergence-class violation (hallucinated symbols, fabricated test
   results, em-dash drift, banned-API drift).
5. Cross-doc invariant violation (the eleven invariants in
   `EXECUTION-BOARD.md` section 3).
6. Two ready tickets locked in mutual deadlock via shared_paths +
   depends_on cycle.
7. Forbidden actions (version bumps, test drops, clippy allows,
   force-push, releases.toml edits).
8. Cross-trajectory invariant violation (touching frozen trajectory-1
   paths without a documented amendment).
9. Decisions-register conflict (executor proposes contradicting D{NN}
   without a `superseded_by` amendment).
10. Genuinely ambiguous design question the milestone narrative does
    not resolve.
11. Operator-discretion request from an executor that you cannot
    fold into one of the documented authorities.
12. **Lean theorem fails CI** (M04 P4 gate). Open
    `formal/lean4/counterexamples/<sha>.lean`; revert.
13. **Apalache trace fails CI.** Persist the trace at
    `formal/tla/counterexamples/<sha>.tla`; revert.
14. **Mutation kill-rate regresses below 80%** (M02 P3 gate; six-crate
    set per D06: chio-policy, chio-credentials, chio-attest-verify,
    chio-kernel-core, chio-guards, chio-anchor).
15. **Threat-model gate fails on uncovered threat ID** (M05 P5 gate).
16. **Cross-SDK verdict-matrix divergence** (M02 P5 gate; five
    primary kernels per D07).
17. **WASM guard escape-class panic** (M05 P3 nightly libFuzzer P0
    incident).

When any of these fires, halt the affected ticket, post a chat
message, then continue scheduling tickets in unaffected milestones.
Triggers 2, 12, 13, and 17 are trajectory-wide and pause all
scheduling.

## 7. Scheduling order recommendation

Pick this order when resuming, modulated by the live <EDIT>blockers in
section 4</EDIT> and the active freezes:

**Wave A (parallel, no shared paths, no active freeze conflicts):**
- <EDIT> list of READY tickets that touch disjoint `owner_glob` sets
  AND are not blocked. </EDIT>

**Wave B (after Wave A merges; serialized for `Cargo.lock`):**
- <EDIT> list of tickets that touch `Cargo.lock` directly; serialize
  one at a time per `EXECUTION-BOARD.md` section 5. </EDIT>

**Wave C (serialized for `bun.lock` if any TS/SDK tickets):**
- <EDIT> list of M07 / M08 / M10 tickets that touch
  `sdks/typescript/.../package.json` or `bun.lock` (M07 P5 templates,
  M10 passkey TS package). Serialize one at a time. </EDIT>

**Wave D (parallel after their deps land):**
- <EDIT> list of secondary-phase tickets unblocked by Wave A/B/C
  closes. </EDIT>

After each wave merges, recompute READY (section 3 recipe). Many
downstream tickets in M03/M04/M05 unblock as M01 P0 closes;
M07/M08/M09/M10 unblock as their respective Wave 1 / Wave 2 deps
close.

## 8. Executor prompt template

For every ready ticket, spawn `gsd-executor` with a self-contained
prompt:

```
Execute ticket **<TICKET_ID>** for Chio at /Users/connor/Medica/backbay/standalone/arc/.
End-to-end: worktree -> implement -> gate-check -> push -> open PR.

## Spec
<paste YAML from .planning/trajectory-2/tickets/M{NN}/P{n}.yml>

## Scope expansion (authorized this run)
<paste the unblock block from CONTINUE-PROMPT.md section 4 for this ticket
if applicable; else "none"; cite decisions.yml D-entry where relevant>

## Source-of-truth references
- Milestone narrative: .planning/trajectory-2/{NN}-{slug}.md Phase {n} Task {m}
- Decisions register: .planning/trajectory-2/decisions.yml D{NN} (if applicable)
- Freeze register: .planning/trajectory-2/freezes.yml {freeze_id} (if applicable)
- House rules: no em dashes (U+2014), unwrap_used/expect_used clippy-banned, conventional commits

## Worktree
git worktree add /tmp/arc-m{nn}p{p}-t{k} -b <worktree_branch> origin/<trajectory-2-integration-branch>
cd /tmp/arc-m{nn}p{p}-t{k}

## Task
<numbered steps; reference the milestone narrative rather than inlining its content>

## Gate check
<from YAML gate_check.cmd, possibly adapted per section 2 / section 4>

## Commit + push + PR
- Subject: <conventional-commit prefix>(<scope>): <imperative summary> [<TICKET_ID>]
- gh pr create --base <trajectory-2-integration-branch> --repo bb-connor/arc \
    --title "<title> [<TICKET_ID>]" --body "<heredoc>"
- Body sections (in order):
  ## Summary
  ## Scope expansion        (cite milestone narrative lines)
  ## Dependency added       (if applicable; cite decisions.yml D{NN})
  ## Gate-check adapted     (if applicable)
  ## Gate-check output      (verbatim)
  ## Test count             (vs baseline if applicable)
  ## Em-dash scan           (verbatim)
  ## Freeze acknowledgement (if ticket touches a freeze path; cite freezes.yml)
  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

## Report back
PR URL/number, branch + SHA, gate-check output, scope-expansion summary, deviations.

## Deviation policy
- If a soft-dep doesn't exist, STOP and report (don't fabricate).
- If owner_glob is too narrow, STOP and report.
- If the path collides with an active freeze and you don't own the
  freeze's milestone, STOP and report.
- If a decision-register D-entry contradicts the implementation choice,
  STOP and report.
- Forbidden: todo!(), unimplemented!(), bare panic!() in trust-boundary
  paths.

Self-contained brief. Begin.
```

Spawn with `subagent_type: gsd-executor` and `run_in_background: true`.

## 9. Reporting cadence

- **On each batch dispatch:** one-line "launched N agents:
  M{nn}.P{p}.T{k}, ...".
- **On each merge:** silent unless wave-gate close.
- **At every ~10 PRs merged this run:** brief progress (merged count,
  in-flight count, current wave).
- **On wave-gate close:** wave summary.
- **On halt:** full halt message per section 6.

## 10. Stop and report at clean stop points

A clean stop point is any of:
- All tickets in the current wave have merged AND the wave's gates are
  green.
- A trust-boundary freeze closes (one of the six in `freezes.yml`).
- All 319 tickets are merged AND the four close gates land green
  (mutation, threat-model, verdict-matrix, lean-build per
  `EXECUTION-BOARD.md` section 9).
- A canonical halt trigger fires that pauses the trajectory globally
  (triggers 2, 12, 13, 17).

At every clean stop point, post a status summary in chat including:
- Merged count this run vs total (X of 319).
- Wave gates closed this run.
- Halts encountered (one line per).
- Scope expansions performed (one line per, with citation).
- Decision-register references invoked (D{NN} per scope expansion).
- Any deferrals flagged for follow-up.

If trajectory-2 closes during your run, archive
`EXECUTION-STATE.json` to
`.planning/trajectory-2/archive/EXECUTION-STATE-CLOSED.json` and bump
`.planning/STATE.md` to record trajectory-2 completion per
`EXECUTION-BOARD.md` section 9.

## 11. Local working tree note

The user notes the working tree at
`/Users/connor/Medica/backbay/standalone/arc/` may contain pre-existing
untracked files (catalog files, prior trajectory worktrees, build
artifacts). Leave them. Specifically: do not reuse `/tmp/arc-*`
worktrees from killed prior-session executors without checking
`git worktree list` and `git branch -a` first.

The blocker analysis in section 4 is durable on disk because you
filled in the `<EDIT>` markers before pasting this in. The prior
session's chat-context analysis is gone.

---

End of continue prompt. You are clear to begin once section 1 and
section 4 have been filled in.
