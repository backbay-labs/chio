# Trj5 Timeline

Gantt-style ASCII timeline for the three-lane shape from `debate/00-SYNTHESIS.md`.

**Tagline**: release work is the **honesty trajectory**. Three coupled lanes, no separate brand from the trj4 wave plan, one ship-bar visible from outside.

**Estimated duration**: 8 weeks. Lane A is parallelizable across its full duration; Lane B has a 2-week architectural prerequisite (B0) gating its four primitives (B1/B2/B3/B4); Lane C unlocks progressively as Lane B primitives land (C1/C2 scaffolding can begin in week 5 alongside B4; full demo waits on B4 by week 6).

## Master timeline

```
              W1     W2     W3     W4     W5     W6     W7     W8
              |------|------|------|------|------|------|------|------|
Lane A     [==A1=========================A7][==A2========================]
Lane A     [==A3=================][==A4=========][==A5=================]
Lane A     [.................................][==A6==================]
              .                                              .
Lane B     [==B0========][==B1=================][==B1.E=]    .
Lane B                  [==B2========][..............][==B2.E=]
Lane B                  [==B3========][..............][==B3.E=]
Lane B                              [========B4=========][==B4.E=]    (NEW per R4)
              .                                              .
Lane C                                .  [==C1====][==C2-C5====][==C6==]
              .                                              .
Bars                                                              [B1]
                                                                  [B2]
                                                                  [B3]

Legend:
  [==X==]   active work on ticket X
  [.....]   waiting on dependency
  Bn.E      per-primitive Evidence Gate ticket (release work-Bn.E)
  Bx        Bar verification at integration week
```

## Per-lane breakdown

### Lane A -- Realize the floor (weeks 1-8, parallelizable)

```
W1  W2  W3  W4  W5  W6  W7  W8
|---|---|---|---|---|---|---|---|
[========================A1=====]   mutation kill 31% -> 65%/80%
[============A3=================]   Kani harnesses (3 crates)
            [==========A4=======]   TLA+ rewrites (4 items)
[================A2=============]   threat-coverage 20 evidence rows
                  [======A5=====]   Lean negotiation_safety re-prove
                            [A7]    README banner update
```

Note: The earlier draft listed `release work-A5` as `chio-equivalence-tests`
(TRJ4-019). Per Wave 3 review, TRJ4-019 is **deferred to trj6** and
the Lean4 `negotiation_safety` re-proof (originally `release work-A6`) is
renumbered to `release work-A5`. Lane A has 5 work sub-lanes plus the banner
update (A1, A2, A3, A4, A5, A7); see `lane-a-floor/planning docs` for
the per-sub-lane Evidence Gate `.E` ticket.

Lane A has no hard internal week-by-week ordering aside from `A4 depends on A3` (TLA+ rewrites depend on Kani harness landing first to share infrastructure) and `A5 depends on A4` (Lean refinement uses the rewritten TLA+ models as the executable model). Lane A is independent of Lane B and Lane C; it can start on week 1 and finish anywhere from week 7 to week 8.

Lane A closes when Bar 1 verification passes at week 8.

### Lane B -- Wire the spec hot path (weeks 1-7)

```
W1  W2  W3  W4  W5  W6  W7  W8
|---|---|---|---|---|---|---|---|
[==B0=====]                         architectural prerequisite
        [========B1=====]           single-entry verifier
        [========B2=====]           receipt v2 fail-closed
        [========B3=====]           anchor-batch async-only
                [========B4=====]   DSSE-conformant bilateral signing (NEW per R4 BLOCKER 1)
                    [==EG/primitive==]  per-primitive Evidence Gate close
```

Lane B has a hard internal critical path: B0 -> {B1, B2, B3, B4}. B0 is the smallest decomposition cut (`async_trait` on `ToolServerConnection`; sync-helper hop collapse) needed to wire the primitives. B1/B2/B3 run in parallel under B0. B4 (DSSE bilateral signing) starts in week 5 (depends on B0 hard, B1 soft) and lands by end of week 6. Per-primitive Evidence Gate tickets (`release work-B1.E`, `release work-B2.E`, `release work-B3.E`, `bilateral DSSE signing item`) close inline with each fixture landing.

Lane B closes when Bar 2 verification passes at week 8 (each `.E` ticket lands inline; integration week verifies the bar against committed evidence).

### Lane C -- One forcing demo (weeks 5-8)

```
W1  W2  W3  W4  W5  W6  W7  W8
|---|---|---|---|---|---|---|---|
                  [====C1=========]   bilateral cosigned invocation
                          [C2-C5====]  bond, anchor, ZK, MCP wrap
                                [C6]   examples/ fixture + tag
```

Lane C unlocks at end of week 4 once B1/B2/B3 land. C1 (bilateral cosigned invocation skeleton) runs week 5. C2-C5 (capability lease + bond, anchor, selective-disclosure, MCP wrap) run week 6. C6 (`examples/chiodome-bilateral/` fixture + golden file + honest release tag) runs week 7. Integration / ship-bar week is week 8.

Lane C closes when Bar 3 verification passes at week 8.

## Critical path

The single critical path through release work:

```
W1   release work-B0 starts (architectural prerequisite)
W2   release work-B0 lands -> release work-B1, release work-B2, release work-B3 start
W4   release work-B1, release work-B2, release work-B3 land; release work-B4 starts (DSSE bilateral signing)
W5   release work-C1 starts (bilateral cosigned invocation skeleton); release work-B4 progresses
W6   release work-B4 lands; per-primitive `.E` Evidence Gate tickets close; release work-C2..C5 land
W7   release work-C6 lands (examples/ fixture + golden file + tag)
W8   integration / ship-bar week: Bar 1, Bar 2, Bar 3 verification
```

If release work-B0 slips by N weeks, the whole critical path slips by N weeks because Lane C unlock is downstream of B1/B2/B3 which are downstream of B0.

Lane A runs entirely off the critical path; if Lane A slips, Bar 1 slips but Bar 2 and Bar 3 are unaffected (and release work stays open per the close-gate rule).

## Integration / ship-bar week (week 8)

Week 8 is the dedicated verification week. No new feature work lands in week 8. The activities are:

- Run `scripts/check-trj5-ship-bar.sh` against the committed evidence.
- Wave-2 reviewer signs off on each lane PLAN.md.
- `releases.toml` `[trajectory_5]` block updated: `trj5_release_status` transitions from `in_progress` to either `closed` (all three bars DONE) or stays `in_progress` (any bar not DONE).
- If all three bars DONE: cut `v0.1.0-bounded-chiodome` honest release tag.
- If any bar slips: a per-bar continuation note lands under `lane-{a-floor,b-wiring,c-demo}/wave-summary-WK8.md` describing what is missing.

## Slippage policy

Per the synthesis: **if any of the three slips, release work stays open**. No closeout erratum is needed because the bar is the kind a third party can verify.

Lane A slip: Bar 1 stays NONE/PARTIAL. Trj5 stays open. Continuation work tracked under `lane-a-floor/wave-summary-WK<n>.md` per week.

Lane B slip: Bar 2 stays NONE/PARTIAL. Lane C unlock delayed. Trj5 stays open. The architectural prerequisite (release work-B0) is the highest-risk slip point because it gates everything downstream.

Lane C slip: Bar 3 stays NONE/PARTIAL. Trj5 stays open. The synthesis observes: "If Lane C breaks, Lanes A and B are not real either." A Lane C slip therefore reopens the question of whether the substrate composes end-to-end, and the wave-2 reviewer must record what specifically failed to compose.
