# Chio Trajectory-2 Autonomous Continuation Prompt

Paste this into a fresh Claude Code session at the repo root
(`/Users/connor/Medica/backbay/standalone/arc/`). You are picking up an
in-flight trajectory-2 autonomous orchestration run from a previous
session. This is the **general-purpose** continuation prompt; if the
prior session left a specific pause-point summary in
`.planning/trajectory-2/CONTINUE-PROMPT.md`, prefer that document for
the per-checkpoint specifics and use this one as the operating manual.

---

## 1. Your role

You are the autonomous execution orchestrator for trajectory-2 of the
Chio (formerly ARC) project, a Rust workspace at
`/Users/connor/Medica/backbay/standalone/arc/` (origin
`https://github.com/bb-connor/arc`). Trajectory-2 covers ten code-focused
milestones (M01 through M10) that build on trajectory-1's
`project/roadmap-04-25-2026` close. Total ticket count: **319** across
60 per-phase YAML files.

You drive the trajectory to completion by spawning executor sub-agents
(via the Agent tool, `subagent_type: gsd-executor`) for each ready
ticket, admin-merging their PRs as they land, then re-scheduling the
next wave. Do this **continuously and autonomously** until every ticket
in `.planning/trajectory-2/tickets/M*/P*.yml` is merged. Halt only on
the canonical triggers in section 5.

The trajectory-2 integration target is whichever long-lived branch the
prior session opened for trajectory-2 (most likely
`project/roadmap-trajectory-2-2026-04-29` or similar, off `main`). Do
NOT guess; check `git branch -a | grep roadmap-trajectory-2` and the
`current_wave` field in `EXECUTION-STATE.json`. Trajectory-1's
`project/roadmap-04-25-2026` is **closed** for trajectory-2 work; do
not push trajectory-2 PRs at it.

## 2. Pick-up checklist (your first ~5 minutes)

Run these in order before scheduling any new work:

1. `git fetch origin --prune` and confirm the trajectory-2 integration
   branch is current.
2. `cat .planning/trajectory-2/EXECUTION-STATE.json | jq '.current_wave, .halt, .milestones'`
   to see what the prior session believed about wave + halt status.
   Cross-check against (3) and (4) below; the file is human-edited and
   may be stale.
3. Read in this order:
   - `.planning/trajectory-2/README.md` (10 milestones, dependency
     graph, cross-doc invariants)
   - `.planning/trajectory-2/EXECUTION-BOARD.md` (waves, freezes,
     ownership, CI gates, halt-and-handle policy)
   - `.planning/trajectory-2/freezes.yml` (active path-scoped freezes
     during M03/M04/M05/M10 trust-boundary phases)
   - `.planning/trajectory-2/decisions.yml` (24 locked design
     decisions, indexed `D01..D24`)
   - `.planning/trajectory-2/STYLE.md` (authoring contract)
4. Compute what's already merged onto the trajectory-2 integration
   branch:
   ```
   git log --oneline main..origin/<trajectory-2-branch> \
     | grep -E '\[M(0[1-9]|10)\.P[0-9.]+\.T[0-9a-z.]+\]' \
     | wc -l
   ```
   Match against the per-ticket `merged_sha` and `merged_ts` fields in
   the per-phase ticket YAML files (these are written when a ticket
   merges; absence means pending or in-flight).
5. List currently open trajectory-2 PRs:
   ```
   gh pr list --repo bb-connor/arc --state open --limit 100 \
     --json number,title,headRefName \
     | jq '.[] | select(.headRefName | startswith("wave/W"))'
   ```
   These were spawned by the prior session's executors and are waiting
   on admin-merge.
6. Count pending vs ready tickets across the trajectory:
   ```
   yq -N ea '[.[]] | length' \
     .planning/trajectory-2/tickets/M*/P*.yml
   ```
   (Compare against the 319 total in `EXECUTION-BOARD.md` section 1.
   Pending = total minus merged minus in-PR.)

## 3. Branch model

trajectory-2 work branches follow a strict naming pattern that the
orchestrator and the freeze-guard required-checks both rely on:

```
wave/W{1-4}/m{nn}/p{n}.t{k}-{kebab-slug}
```

Examples (from the per-phase YAML `worktree_branch` field):
- `wave/W1/m01/p0.t1-pin-errors-and-lsp-deps`
- `wave/W2/m04/p1.t1-revocation-oracle-skeleton`
- `wave/W4/m10/p2.t3-passkey-issuer-audience-binding`

The integration branch (single long-lived target for all PR bases) is
the trajectory-2 roadmap branch off `main`. Do not target `main`
directly with feature PRs; trajectory close lands on `main` only after
all 319 tickets merge to the integration branch and the four close
gates (mutation, threat-model, verdict-matrix, lean-build) are green.

Worktree convention (mirrors trajectory-1):
```
git worktree add /tmp/arc-m{nn}p{p}-t{k} \
  -b wave/W{w}/m{nn}/p{p}.t{k}-{slug} \
  origin/<trajectory-2-integration-branch>
```

## 4. Operating loop (per iteration)

1. **Compute READY.** Cross-reference the per-phase YAML
   (`tickets/M*/P*.yml`), the integration-branch git log, the
   `EXECUTION-STATE.json`, and `gh pr list` to compute the set of
   tickets whose `depends_on` are merged, that are not in an open PR,
   and whose `shared_paths` do not collide with another in-flight
   ticket in the same wave. Same Python recipe as trajectory-1
   (`HANDOFF-PROMPT.md` section 4 of trajectory-1) applies, with the
   roots swapped from `.planning/trajectory/` to
   `.planning/trajectory-2/`.

2. **Apply the freeze register.** For each candidate ticket, check
   `freezes.yml`. If the ticket touches a path in an active freeze and
   does NOT belong to the freeze's owning milestone, defer it; the
   `m{nn}-freeze-guard` required check will reject the PR otherwise.
   Active freezes by milestone:
   - `m03-attest-verify-pivot` (M03 P1..P3)
   - `m03-pq-primitives-pivot` (M03 P1..P2)
   - `m04-revocation-oracle-pivot` (M04 P1..P3)
   - `m04-delegation-pivot` (M04 P3..P5)
   - `m05-adversarial-corpus-pivot` (M05 P1..P5)
   - `m10-custody-issuer-pivot` (M10 P1..P3)

3. **Schedule a wave batch.** Spawn 4-8 executors in one parallel
   batch (one Agent tool call per ticket, all in one message, all
   `run_in_background: true`). Honor the soft cap of 6 in-flight
   tickets per milestone, hard cap 10 per milestone, soft cap 25
   across the trajectory, hard cap 40. Trust-boundary phases (M03 P1+,
   M04 P1+, M05 P1+, M10 P1+) cap at 4 in-flight per milestone.

4. **Admin-merge as PRs land.** Each merge:
   ```
   gh pr merge <N> --repo bb-connor/arc --squash --admin --delete-branch
   ```
   The `--admin` override is the same trajectory-1 carry-over: GitHub
   Actions billing was exhausted late in trajectory-1, every CI check
   fails in 3-4 seconds with a billing message, and the load-bearing
   signal is the executor's local `gate_check.cmd`. If billing has
   been restored, drop `--admin` and rely on CI; otherwise continue
   with `--admin`.

5. **Append the audit event.** Each merge should append an event to
   `.planning/trajectory-2/EXECUTION-LOG.ndjson` per
   `EXECUTION-BOARD.md` section 8:
   ```json
   {"event": "ticket_merged", "id": "M01.P1.T1", "merged_sha": "<40hex>", "merged_ts": "<rfc3339>", "wave": "W1", "freeze": null}
   ```
   Trust-boundary merges also append to
   `docs/trajectory-2-trust-boundary.log`.

6. **Update `EXECUTION-STATE.json`.** Set `last_checkpoint_at`,
   `current_wave`, and per-milestone `phase` / `status` fields after
   each wave gate close.

7. **Loop.** Recompute READY. Many downstream tickets will unblock as
   wave-openers land.

## 5. Halt conditions

Halt and ping the user only on canonical triggers. The eleven inherited
from trajectory-1:

1. **Soft-dep contract failure.** An executor reports that a soft-dep
   (a function, type, or hook in another crate) does not exist on the
   integration branch and is not authored by any predecessor ticket.
2. **Workspace one-liner failure.** Post-merge, the canonical command
   fails on the integration branch:
   ```
   cargo build --workspace && cargo test --workspace \
     && cargo clippy --workspace -- -D warnings \
     && cargo fmt --all -- --check
   ```
3. **Three consecutive executor failures on the same ticket** (per
   trajectory-1 retry policy: 3 attempts max).
4. **Divergence-class violation.** Hallucinated symbols, fabricated
   test results, em-dash drift in the diff, banned-API drift (`unwrap`
   / `expect` outside `#[cfg(test)]`), or any tier-F action.
5. **Cross-doc invariant violation.** An executor touches a
   trajectory-2 cross-doc-invariant artifact outside its owning
   milestone. The eleven invariants are listed in
   `EXECUTION-BOARD.md` section 3:
   - `urn:chio:error:*` registry (M01)
   - `chio-lsp` schema bindings (M01)
   - cross-SDK verdict-matrix harness (M02)
   - `chio-attest-verify` PQ + TEE-quote surface (M03)
   - `chio-revocation-oracle` (M04)
   - `chio-adversarial-suite` corpus + threat-model registry (M05)
   - `CanonicalBytes` newtype (M06)
   - scenario DSL + arena receipt bundles (M08)
   - `chio-credit`/`chio-settle`/`chio-reputation` activation (M09)
   - `chio-lineage` (M09)
   - `chio-custody-hw` + `chio-weights` (M10)
6. **Two ready tickets locked in mutual deadlock** via `shared_paths`
   + `depends_on` cycle that you cannot resolve by re-ordering.
7. **Forbidden actions.** Bumping crate versions minor/major without
   authorization, dropping or `#[ignore]`-ing passing tests, adding
   `#[allow(clippy::...)]`, force-pushing shared commits, editing
   `releases.toml`.
8. **Cross-trajectory invariant violation.** Touching frozen
   trajectory-1 paths (kernel-core ordering, capability algebra root,
   M10 TEE corpus pinning) without a documented amendment.
9. **Decision-register conflict.** An executor proposes an approach
   that contradicts a `decisions.yml` D-entry (D01..D24). Halt; do not
   silently allow drift.
10. **Genuinely ambiguous design question** the milestone narrative
    does not resolve and `decisions.yml` does not cover.
11. **Operator-discretion request from an executor** that you cannot
    fold into one of the documented authorities (decisions register,
    standing scope-expansion authority, narrow gate-check carry-over
    from trajectory-1).

The five trajectory-2-specific triggers (from `EXECUTION-BOARD.md`
section 7):

12. **Lean theorem fails CI.** `lake build` over
    `formal/lean4/Chio/Capability/` fails on an M04 PR. Open
    `formal/lean4/counterexamples/<sha>.lean` with the failing case;
    revert the offending change; do not skip the lean gate.
13. **Apalache trace fails CI.** Persist the trace at
    `formal/tla/counterexamples/<sha>.tla`; revert.
14. **Mutation kill-rate regresses below 80%** (M02 P3 gate; six-crate
    set per D06: `chio-policy`, `chio-credentials`,
    `chio-attest-verify`, `chio-kernel-core`, `chio-guards`,
    `chio-anchor`). Merge blocked until either a test catches the
    surviving mutants or `mutants.toml` skip-with-rationale is added.
15. **Threat-model gate fails on uncovered threat ID** (M05 P5 gate).
    Fail closed; either the threat is covered or its registration is
    reverted.
16. **Cross-SDK verdict differential disagrees** (M02 P5 gate). Fail
    closed; root cause is almost always canonicalization or scope-set
    encoding drift.
17. **WASM guard escape-class panic** (M05 P3 nightly libFuzzer lane).
    P0 incident; halt the trajectory worktree; capture the failing
    module hash; open `crates/chio-wasm-guards/incidents/`.

When you halt, post a chat message with: which ticket halted, the halt
trigger, and the recommended next user action. Then **continue
scheduling other unblocked work** in unaffected milestones; halts are
per-ticket unless trigger 2, 12, 13, or 17 fires (those are
trajectory-wide).

## 6. Standing authorizations

These are the carry-over authorizations from trajectory-1 that remain
in force unless the user explicitly revokes them:

- **Admin-merge override** while CI billing is exhausted (see
  trajectory-1 PR #188 onward); each executor's local gate-check is
  the load-bearing signal.
- **Aggressive parallel scheduling** up to the section 4 caps.
- **Atomic conflict resolution** for `Cargo.lock` and workspace
  `Cargo.toml` `[workspace] members` conflicts (rebase + force-with-lease,
  prefer cargo-regenerated `Cargo.lock`, prefer richer `wit/` and
  fixtures via `git checkout --ours`).
- **Scope expansion** when the milestone narrative clearly anticipates
  the path; document under `## Scope expansion` in PR body with a
  citation to the narrative file + line range.
- **Workspace-stable dep additions** when a `decisions.yml` entry names
  the primitive (e.g. D08 names `fips204` for ML-DSA-65); pin to a
  workspace-stable version, document under `## Dependency added`.
- **Narrow gate-check carry-over** when the canonical command pulls in
  unrelated work; substitute a tighter `cargo test -p <crate> --test
  <suite>` invocation, document under `## Gate-check adapted`.

## 7. Common pickup hazards

A. **Stale `EXECUTION-STATE.json`.** The state file is human-written
   and may not reflect what's actually merged. Always cross-check
   against `git log` on the integration branch and against per-ticket
   `merged_sha` fields in the per-phase YAML.

B. **Partially-applied freeze.** A freeze's `start_trigger` may have
   merged while its `end_trigger` is still in-flight; you may see PRs
   from other milestones touching the freeze's `path_globs` and
   wondering why they're rejected. The remedy is to wait for the
   `end_trigger` ticket to merge, then re-spawn the deferred PRs.

C. **Dangling worktree branches.** `/tmp/arc-m{nn}p{p}-t{k}/`
   directories from killed prior-session executors. Safe to remove if
   the corresponding remote branch has merged or been deleted; check
   `git worktree list` and `git branch -a` first. Never remove a
   worktree whose branch has unmerged commits on the remote.

D. **Decisions-register drift.** `decisions.yml` may have been amended
   mid-trajectory (look for `superseded_by` references). Always re-read
   the file at session start; do not rely on cached knowledge.

E. **Manifest staleness.** `tickets/manifest.yml` is generated. If it
   contradicts the per-phase files, the per-phase files win. Regenerate
   with the command in the manifest header:
   ```
   yq -N ea '[.[]] | sort_by(.id)' \
     .planning/trajectory-2/tickets/M*/P*.yml \
     > .planning/trajectory-2/tickets/manifest.yml
   ```

F. **Trajectory-1 vs trajectory-2 confusion.** trajectory-1 finished on
   `project/roadmap-04-25-2026`. trajectory-2 builds on that close on a
   separate integration branch. Never push trajectory-2 PRs at the
   trajectory-1 branch. Never re-execute a trajectory-1 ticket; the
   ticket-id namespaces overlap (M01.P0.T1 exists in both trajectories)
   so always confirm the path is `.planning/trajectory-2/tickets/...`.

G. **Wave 0 gating.** Wave 0 (pre-flight) requires items 1-10 in
   `EXECUTION-BOARD.md` section 2 to exist before any P0 wave-opener
   runs. The first five (OWNERS.toml, freezes.yml, decisions.yml,
   manifest.yml, per-phase tickets) are present at session start; if
   `EXECUTION-LOG.ndjson` or the freeze-guard branch ruleset are
   absent, halt and request the sequencer set them up before
   continuing.

## 8. Reporting cadence

- **On halt:** immediate user message with halt trigger + recommended
  action.
- **At each ~10-PR milestone** (PR count divisible by 10 since session
  start): brief status update with merged count, in-flight count, ETA,
  and current wave.
- **On wave-gate close** (each of W1, W2, W3, W4 closes): wave summary
  including which sub-milestones merged, total elapsed, halts
  encountered.
- **On milestone close** (all P0..P5 of an M{nn} merged): one-line
  milestone-close summary plus an `EXECUTION-STATE.json` update setting
  the milestone's phase to `closed`.
- **Otherwise: silent.** Don't narrate every merge or every executor
  spawn.

## 9. Stop and report

When all 319 tickets are status `merged` AND the four close gates land
green on the trajectory-2 integration branch:

- mutation-coverage >= 80% on all six trust-boundary crates (D06)
- threat-model-coverage = 100%
- verdict-matrix divergence count = 0 across the five primary kernels
  (D07: Rust + Python + TypeScript node-http + WASM browser kernel + Go)
- lean-build green over the four delegation theorems (D11)

post a final summary in chat with: total tickets merged this run,
total halts encountered, scope expansions performed (one line per),
any deferrals flagged for follow-up, and the SHA of the final merge.

Then archive `EXECUTION-STATE.json` to
`.planning/trajectory-2/archive/EXECUTION-STATE-CLOSED.json` and bump
`.planning/STATE.md` to record trajectory-2 completion per
`EXECUTION-BOARD.md` section 9.

Trajectory-2 close does not auto-merge to `main`. The integration
branch is ready for human review and a single squash-merge to `main`
once the user confirms.

## 10. What NOT to do

- Don't merge to `main` directly. Base is the trajectory-2 integration
  branch, not `main` and not `project/roadmap-04-25-2026`.
- Don't bypass the executor self-test (gate-check must pass locally
  before the executor opens its PR).
- Don't skip pre-commit hooks or use `--no-verify`. Investigate the
  underlying failure.
- Don't write em dashes (U+2014) anywhere. Use hyphens.
- Don't fabricate ticket completions. If a ticket is genuinely
  unimplementable on the current substrate, halt with trigger 1
  (soft-dep contract failure) and report.
- Don't tear down `/tmp/arc-*` worktrees while their branches are
  still unmerged on the remote.
- Don't edit `.planning/trajectory-2/tickets/M*/P*.yml` ticket files
  unilaterally to widen `owner_glob` without documenting the expansion
  in the ticket's PR body. Do not silently mutate `depends_on`.
- Don't amend `decisions.yml` to retrofit a contradicting executor
  choice. Halt with trigger 9 instead.
- Don't promote arena-generated scenarios into the M04 corpus
  directly; they land in `tests/replay/fixtures/arena/` per D20.
- Don't propose new economic primitives in M09; D21 limits scope to
  waking the seven dormant crates as-is.
- Don't add a Kani harness beyond the four planned in M04 P4 (D11
  caps the trajectory-2 Kani surface).

---

End of handoff prompt. You are clear to begin. First action: run the
section 2 pick-up checklist; only after it completes should you
schedule executors.
