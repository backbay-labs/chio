# Trajectory 5 - Lane A: TLA+ Rewrites

This document covers TRJ4-015..018 carry-forwards as sub-lane A4. For
each ticket, it lists current state, target state, file path,
justification, expected proof depth, and the advisory-to-required
promotion plan.

## Reference files

- `formal/tla/RevocationPropagation.tla` (379-line module; current
  property exports verified by grep).
- `formal/tla/MCRevocationPropagation.cfg` (PR-tier safety lane:
  `PROCS=4 CAPS=8 DEPTH_MAX=4`, `INVARIANT SafetyInv`).
- `formal/tla/MCRevocationPropagationTemporal.cfg` (nightly liveness
  lane).
- `formal/tla/DelegationDepthBound.tla` (sibling module, attenuation
  bound).
- `.github/workflows/apalache-safety.yml` (required, PR tier).
- `.github/workflows/apalache-temporal.yml` (advisory today).

## Status check on the property names

Synthesis names `RevocationCutCompleteness`, `ReceiptBeforeAllow`,
`RevocationEventuallySeen` (lines 84-86 of `00-SYNTHESIS.md`). Grep on
`formal/tla/RevocationPropagation.tla` shows:

- `RevocationEventuallySeen` is exported (line 379).
- `RevocationCutCompleteness` does **not** exist yet.
- `ReceiptBeforeAllow` does **not** exist yet.
- `Allow`, `LogReceipt`, `PublishAllow` actions do **not** exist yet.

This means TRJ4-015 and TRJ4-016 are not just rewrites of existing
properties; they introduce new properties and actions. The ticket text
in the trj4 EXECUTION-BOARD ("split", "rewrite") matches this reading.

## TRJ4-015 - `RevocationCutCompleteness` rewrite (release work-A4.2)

### Current state

Not present in the module. The closest existing property is the named
liveness `RevocationEventuallySeen` at line 379, which states that a
revoked capability is eventually observed by every authority.

### Target state

A safety property that says: for every cut of the propagation graph
where authority A has revoked capability `c`, the bounded transitive
closure of A's propagation reaches every authority within depth >= 3.
Operationally:

- The property quantifies over `(a, c) \in ProcSet \times CapSet`.
- For each `(a, c)`, if `state[a][c] = "revoked"`, the union of A's
  outgoing pending messages and the messages those messages will
  generate within depth-3 unrolling covers `ProcSet \ {a}`.
- The unrolling is bounded by a state-machine helper `reachable_set(a,
  c, k)` that takes a depth bound `k = 3`.

### File path

`formal/tla/RevocationPropagation.tla` (extended in place).

### Justification

The Quality Skeptic
(`.planning/trajectory-5/debate/04-quality-verification-skeptic.md` line
44): "TRJ4-015 - `RevocationCutCompleteness` rewrite with bounded
transitive-closure unrolling." The synthesis (line 84) restates the same
ticket. Without bounded transitive-closure unrolling, `apalache` cannot
prove a propagation completeness statement that quantifies over all
graph cuts.

### Expected proof depth

Depth-3 transitive-closure unrolling. Apalache should prove the property
under PR-tier `PROCS=4 CAPS=8 DEPTH_MAX=4`. If the proof times out at
depth 3, the unrolling is reduced to depth 2 with a documented fallback
(captured as release work-A4.2 sub-task).

### Feasibility spike (R2 MAJOR 4.2 addition)

Apalache 0.50.x supports recursive `LET` definitions but has well-known
limitations on recursive operators in temporal contexts. The existing
module `formal/tla/RevocationPropagation.tla:17-25` documents a forced
workaround for an Apalache encoding limit on `WF_vars(\E ...)` --
evidence that this codebase has hit Apalache encoding limits before.

release work-A4.2 includes a feasibility-spike sub-task: write a 20-line TLA
fragment expressing the bounded transitive-closure operator
(`reachable_set(a, c, k)` with `k = 3`) and run Apalache against it
standalone. Capture exit status and a link in
`audits/evidence/release work-A4.2/feasibility-spike.md`.

If Apalache 0.50.x does not handle the encoding, release work-A4.2 escalates.
The only realistic fallback is to inline-unroll the closure into a
hand-written `Reachable_step1`, `Reachable_step2`, `Reachable_step3`
chain, which is ugly but expressible.

## TRJ4-016 - Split `Allow` into `LogReceipt` + `PublishAllow` (release work-A4.1)

### Current state

The module's only verdict-emitting action is `Evaluate(a, c)` at line
194. There is no separate "log a receipt" vs "publish an allow"
distinction; both happen in one atomic step. Per the Quality Skeptic
(line 44): "Split `Allow` into `LogReceipt` + `PublishAllow` so
`ReceiptBeforeAllow` stops being **tautological**."

### Target state

Two actions:

1. `LogReceipt(a, c, t)`: appends to `receipt_log[a]` an entry of
   shape `[cap |-> c, verdict |-> "allow", t |-> t, seen_epoch |->
   rev_epoch[a][c]]`.
2. `PublishAllow(a, c, t)`: enables only when the most recent
   `receipt_log[a]` entry for `c` is the matching log entry. Marks the
   verdict as published; this is the action a downstream verifier
   observes.

The new safety property:

- `ReceiptBeforeAllow == \A a \in ProcSet, c \in CapSet, t \in Nat:
   PublishAllow(a, c, t) was enabled implies LogReceipt(a, c, t)
   already happened.`

The property is non-tautological because it requires the receipt-log
update to precede the publish step in the trace, which is a property of
the action ordering, not of any single action's definition.

### File path

`formal/tla/RevocationPropagation.tla` (extended in place; possibly
factored to a sibling `ReceiptOrdering.tla` if the module gets too
large).

### Justification

Per the trj4 audit `T0.B-substrate-hardening.md` line 20 (cited by
Quality Skeptic line 44), `ReceiptBeforeAllow` was tautological in the
prior shape. The split forces a proof that the verifier actually
observes the receipt before the allow is exposed, which is the property
the spec asserts (PROTOCOL.md section 6 receipt-before-allow ordering).

### Expected proof depth

Trace length 6 (matches the bumped `EpochMax` from release work-A4.3). The
property is provable under apalache safety tier, no temporal lane
needed.

## TRJ4-017 - Bump `EpochMax` from 4 to 6 (release work-A4.3)

### Current state

`MCRevocationPropagation.cfg` has `DEPTH_MAX = 4` (verified by reading
the cfg). The synthesis (line 86) and EXECUTION-BOARD (line 79) describe
the bump as `EpochMax 4 -> 6`. The cfg constant is named `DEPTH_MAX`,
not `EpochMax`. Reading the module, the `rev_epoch` field is per-process
and unbounded (line 99); there is no explicit `EpochMax` constant in
the model. The intent of TRJ4-017 is to extend the apalache run length
budget so the model can express six revocation events in one trace.

### Target state

- `MCRevocationPropagation.cfg` carries `DEPTH_MAX = 6` (or, if the
  intent is a separate epoch ceiling, a new `EPOCH_MAX = 6` is
  introduced and consumed by the module).
- Apalache run uses the full `length=6` budget.
- The two existing tier configs are updated consistently:
  - PR tier: `PROCS=4 CAPS=8 DEPTH_MAX=6`.
  - Nightly tier: `PROCS=6 CAPS=16 DEPTH_MAX=6`.

### File paths

- `formal/tla/MCRevocationPropagation.cfg`
- `formal/tla/MCRevocationPropagationTemporal.cfg`
- `formal/tla/RevocationPropagation.tla` (only if a new `EPOCH_MAX`
  constant is introduced).

### Justification

Per the EXECUTION-BOARD (line 79): "so length=6 fully utilizes apalache
run budget." A length-6 trace is necessary to observe the
`LogReceipt -> PublishAllow` ordering in
non-trivial multi-process scenarios where revocation events interleave.

### Expected proof depth

Length-6 traces, PR tier and nightly tier.

### Wall-clock evidence (R2 MINOR 4.3 addition)

The bump from `DEPTH_MAX = 4` to `DEPTH_MAX = 6` doubles the trace-
length budget, which roughly cubes the apalache state space for a model
with multi-process interleaving. The current PR-tier config is
`PROCS=4 CAPS=8 DEPTH_MAX=4`. A length-6 trace at PROCS=4 CAPS=8 may
fit a 30-minute apalache budget on `apalache-temporal.yml` (timeout-
minutes: 30) but the plan provides no measured baseline today.

release work-A4.3 records the apalache run wall-clock BEFORE and AFTER the
bump, captured in `audits/evidence/release work-A4.3/length-budget.md`. If the
post-bump run exceeds 25 minutes (within 5 minutes of timeout), a
follow-up either sets `DEPTH_MAX=5` or extends the workflow timeout.

## TRJ4-018 - `RevocationEventuallySeen` apalache fix + temporal-lane promotion (release work-A4.4)

### Current state

`RevocationEventuallySeen` is exported at line 379 but the proof has a
forced workaround for an apalache 0.50.x temporal-encoding limitation
(documented in module header lines 17-25): "The named-action form is
required because Apalache's tableau encoding (PDR-017) supports
`WF_vars(<named action>)` but does not support an existential
quantifier nested directly under `WF_vars`."

The `apalache-temporal.yml` workflow is currently advisory (verified
by file-existence; the synthesis line 86 confirms it should be promoted
required).

### Target state

- `RevocationEventuallySeen` is provable under apalache 0.50.x without
  the workaround (or with a documented workaround that no longer
  blocks the proof).
- `apalache-temporal.yml` no longer carries `continue-on-error: true`.
- The workflow is added to required-checks for `main` (configured via
  the GitHub branch-protection rule, captured in the release work-A4.4 PR).

### File paths

- `formal/tla/RevocationPropagation.tla` (only if the property
  definition needs adjustment).
- `.github/workflows/apalache-temporal.yml`.
- Branch-protection configuration (GitHub-level, captured as a PR
  description note since branch protection is not in the repo).
- **Branch-protection evidence** (R2 OBSERVATION 4.4 addition):
  `audits/evidence/release work-A4.4/branch-protection.png` (screenshot of
  GitHub branch-protection settings showing `apalache-temporal` in the
  required list) so future reviewers can verify the workflow is
  actually required without relying on PR archaeology.

### Justification

Per the EXECUTION-BOARD (line 80) and synthesis line 86. Without the
temporal lane being required, a regression on the load-bearing
revocation property would not block CI; that is the failure mode the
Substrate Hardening Hawk flagged
(`.planning/trajectory-5/debate/01-substrate-hardening-hawk.md` line
27).

### Expected proof depth

Liveness lane runs at `PROCS=6 CAPS=16 DEPTH_MAX=6` (after
release work-A4.3 lands). Two consecutive green runs captured to
`audits/evidence/release work-A4/temporal-lane-runs.md`.

## Advisory-to-required promotion plan

1. **release work-A4.1 lands**: split actions and new property in
   `RevocationPropagation.tla`. PR-tier `apalache-safety.yml` continues
   to pass (the new `ReceiptBeforeAllow` invariant is added to the cfg
   `INVARIANT` clause).
2. **release work-A4.2 lands**: `RevocationCutCompleteness` provable at depth
   3.
3. **release work-A4.3 lands**: `DEPTH_MAX = 6` propagation; both cfg files
   updated.
4. **release work-A4.4 lands in two phases**:
   - Phase 1: `apalache-temporal.yml` runs cleanly twice in a row with
     `continue-on-error: true` still set.
   - Phase 2: remove `continue-on-error: true`; configure branch
     protection to require the workflow.
5. **release work-A4.5**: cascade theorem-inventory updates if any
   `mapsTo` references changed property names.

## Cascade-update risk

Per `audits/T0.B-substrate-hardening.md` line 18: "TLA+ split of `Allow`
may invalidate downstream theorems; flag any cascading
theorem-inventory updates." release work-A4.5 is the cascade-update ticket.
Inputs:

- `formal/theorem-inventory.json` rows whose `mapsTo` references the old
  `Allow` property or the old `RevocationCutCompleteness` shape (if any
  exist after the rewrite).
- `formal/MAPPING.md` cross-references between Lean theorems and TLA
  property names.

### Tautology-shortcut audit (R2 OBSERVATION 4.5)

`ReceiptBeforeAllow` is non-tautological IF `PublishAllow` and
`LogReceipt` are independent actions. The risk: if a TLA author writes
`PublishAllow(a,c,t) == LogReceipt(a,c,t) /\ ...`, the property unfolds
tautologically again. release work-A4.5 reviews `theorem-inventory.json` AND
the `PublishAllow` definition for evidence of unfolding shortcuts.

## Anti-pattern guard

Per Lane A's close bar:

- An `apalache-temporal.yml` job that still carries `continue-on-error:
  true` after release work-A4.4 lands fails the close bar.
- A `ReceiptBeforeAllow` proof body that reduces to one-line unfolding
  is the tautological pattern the Quality Skeptic flagged; the close
  bar requires the proof to actually use the action ordering.
- A bumped `DEPTH_MAX = 6` cfg whose apalache run does not exhaust the
  budget (i.e. proof terminates well below length 6) is acceptable, but
  the run log should explicitly note the actual length so reviewers can
  verify the budget headroom.
