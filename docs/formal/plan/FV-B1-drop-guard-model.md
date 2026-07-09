# FV-B1: A real interleaving model of the post-admission drop-guard lifecycle

Status: Proposed (2026-07-09)
Theme: B - Aim the formal tools at the actual bug generator
Effort: M
Depends on: none
Feeds: [FV-B2](FV-B2-regression-negative-tests.md), [FV-B3](FV-B3-budget-conservation-law.md), [FV-C1](FV-C1-receipt-trace-validation.md), [FV-E2](FV-E2-counterexample-regression-pipeline.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G3), [FV-B4](FV-B4-loom-registry-and-dst.md), `formal/apalache/README.md`, `formal/apalache/CONTRACTOR-SIGNOFF.md`

## Summary

The kernel's single largest recent bug generator is the drop/cancel/unwind surface: five production fixes landed against `PostAdmissionDropGuard` in one week (84e98b9d0 through 38cc91471), and none of them changed anything under `formal/`. The only Apalache spec near this surface, `formal/apalache/KernelTransitionCancelSafe.tla`, admits in its own header that its invariant holds by construction and that concurrent commit-vs-cancel interleavings are out of scope. This document proposes `formal/apalache/PostAdmissionDropGuard.tla`, a bounded model in which drop is enabled from every non-terminal phase and each fixed bug class is a named invariant. The model is not evidence until [FV-B2](FV-B2-regression-negative-tests.md) demonstrates that each invariant is falsifiable by a deliberately broken variant; treat FV-B1 and FV-B2 as one unit of proof value.

## Motivation and evidence

Gap G3 in [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md): the drop/cancel unwind surface is under-modeled. The fix history on this branch is the direct evidence (all verified via `git show --stat` this session; none touched `formal/`):

- `84e98b9d0` fix(kernel): mark retained reservations on incomplete-stream tool outputs (`responses/finalization.rs`, `validation.rs`).
- `a6d26dbc4` fix(kernel): complete the pre-dispatch drop unwind. Three findings in one commit: (A) invocation-only budget not reversed, (B) admitted child/delegated capability budget not released, (C) receipt-free exit even when a cleanup step failed (`kernel_drop_guard.rs` +196 lines).
- `58abf33d2` fix(kernel): mark retained reservations on post-invocation block denials (`responses/finalization.rs`).
- `38cc91471` fix(kernel): flush buffered nested child receipts on post-dispatch drop (`kernel_drop_guard.rs`, `evaluation/nested_flow_evaluation.rs`).
- Earlier in the same family: `c201afbd0` (mark retained on aborted unwind paths), `c2e8be7e3` (add `dispatch_started`, split the drop unwind).

Every one of these is a state-machine bug: a phase-dependent transition either skipped a ledger step, skipped a receipt, or applied the wrong terminal disposition to a reservation. That is exactly the bug shape a bounded transition-system model checker finds cheaply, and exactly what `KernelTransitionCancelSafe.tla` does not model: its `Commit` action is guarded on `cancel_pending = FALSE` (`formal/apalache/KernelTransitionCancelSafe.tla:77`), so nothing can mutate state while a cancel is pending and the invariant is vacuous by construction, as the spec header itself states (lines 8-14).

## Current state

- Drop guard implementation: `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs` (read in full this session; ground-truth table below).
- Guard construction and arming happen in the evaluation paths: `mark_dispatch_started` is called immediately before the dispatch await at `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs:525` and `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs:491`; `disarm` on the normal exit at `async_evaluation_core.rs:529` and `nested_flow_evaluation.rs:525`.
- Existing test evidence: an exhaustive 8-cell disposition-table test (`crates/kernel/chio-kernel/src/kernel/tests/drop_guard_proptest.rs:42`, `drop_guard_disposition_table`), runtime tests in `kernel/tests/chio_runtime.rs`, and two loom models of the drop path (`crates/kernel/chio-kernel/tests/loom_concurrency.rs:631` and `:682`). These pin single points; none explore multi-invocation interleavings of the whole lifecycle.
- Existing formal posture: `formal/apalache/` runs 4 specs plus 2 `formal/tla/` specs in `.github/workflows/apalache-safety.yml` (matrix at lines 66-73), on path-scoped PRs and nightly, with apalache-mc 0.50.1 pinned via `tools/install-apalache.sh` and `--length=6` [v]. `Common.tla` hard-pins its bounds with an `ASSUME` (`formal/apalache/Common.tla:19-22`), which constrains how a new spec can share it (see Design).
- `formal/MAPPING.md` has an Apalache invariant table; `KernelTransitionCancelSafe` is a row there.

### Ground-truth table: Rust code paths to model actions

All file:line references below were verified by reading the files this session. Paths are relative to `crates/kernel/chio-kernel/src/kernel/` unless noted.

| Model action | Rust ground truth |
| --- | --- |
| `Admit` | `PostAdmissionDropGuard::new` (`kernel_drop_guard.rs:47-68`): guard armed, `dispatch_started = false`, holds `budget_mutation` (monetary charge or invocation increment), runtime-admission metadata in `receipt_context`, empty child-receipt buffer. |
| `StartDispatch` | `mark_dispatch_started` (`kernel_drop_guard.rs:89-91`), called at `evaluation/async_evaluation_core.rs:525` and `evaluation/nested_flow_evaluation.rs:491`. |
| `StreamChunk` | Dispatch in flight; the nested-flow bridge pushes already-signed child receipts into the guard-owned buffer via `child_receipts_mut` (`kernel_drop_guard.rs:74-76`). |
| `CompleteOk` | Normal exit: `take_child_receipts` drains the buffer (`kernel_drop_guard.rs:81-83`), `disarm` (`kernel_drop_guard.rs:93-95`), allow receipt built in `responses/finalization.rs:55-69`. |
| `DenyPostInvocation` | Post-invocation output guard blocks after dispatch: deny receipt with retained-reservation marking (`responses/finalization.rs:36-52`, marking call at lines 48-50). Fixed by `58abf33d2`. |
| `IncompleteStream` | `ToolServerStreamResult::Incomplete` finalization: incomplete receipt with retained marking, both the non-budgeted arm (`responses/finalization.rs:70-85`, marking at 82-84) and the budgeted arm (`validation.rs:1150`). Fixed by `84e98b9d0`. |
| `DropPreDispatch` | `Drop` with `armed && !dispatch_started` (`kernel_drop_guard.rs:305-312`) runs `handle_pre_dispatch_drop` (`kernel_drop_guard.rs:139-229`): monetary unwind (143-161), invocation-only budget reversal (169-188, Finding A), runtime-admission release (191-205), child budget release (211-222, Finding B), signed fault receipt iff any step failed (226-228, Finding C). Clean unwind is receipt-free. |
| `DropPostDispatch` | `Drop` with `armed && dispatch_started` (`kernel_drop_guard.rs:315-357`): flush buffered child receipts FIRST (321, fixed by `38cc91471`), best-effort monetary unwind folded into metadata (327), mark reservations retained fail-closed (337-339), exactly one cancellation receipt (344-350). |
| `UnwindStep` (failable) | Each pre-dispatch cleanup step is attempted independently and failures are collected into `PreDispatchCleanupFault` entries (`kernel_drop_guard.rs:24-27`, `140`); the model gives each step a nondeterministic fail outcome. |

Ledger-touching primitives the model abstracts: `unwind_aborted_monetary_invocation` (`dispatch.rs:125-160`), `release_runtime_admission_reservations` (`dispatch.rs:393-404`), `mark_runtime_admission_reservations_retained_fail_closed` (`dispatch.rs:412-452`), `release_admitted_capability_budget` (`validation.rs:324`), `reverse_pre_execution_budget_mutation` (`validation.rs:862`).

## Design

New spec pair: `formal/apalache/PostAdmissionDropGuard.tla` + `formal/apalache/MCPostAdmissionDropGuard.cfg`.

Because `Common.tla` pins `Authorities = 1..3`, `CapSet = 1..6`, `EpochMax = 4` with an `ASSUME` (`Common.tla:19-22`), the new module declares its own constants instead of extending `Common` (its domains are invocations and ledger resources, not authorities and caps).

State (per invocation `i \in Invocations`):

- `phase[i]` in `{ "idle", "admitted", "dispatch_started", "streaming", "terminal_ok", "terminal_denied", "terminal_unwound", "terminal_fault" }`. This is the task's six-phase proposal plus `idle` (pre-admission) and `terminal_unwound` (the receipt-free clean pre-dispatch unwind, which must be distinguishable from `terminal_fault` for TerminalReceiptExactlyOne to be stateable). `terminal_denied` covers both the post-invocation block and the incomplete-stream terminals (deny-class receipts with retained lease); `terminal_fault` covers drop-driven terminals (post-dispatch cancellation, pre-dispatch cleanup fault).
- `ledger[i][r]` for `r \in { "hold", "slot", "lease", "child" }` in `{ "none", "reserved", "committed", "released", "retained" }`: monetary hold, invocation-count slot, runtime-admission lease, and the one child budget split. `Admit` sets a nondeterministic subset of resources to `reserved` (monetary and non-monetary grants, lease present or absent, mirroring the 8-cell disposition test).
- `child_buf[i]` in `0..ChildMax`: buffered signed child receipts (only grows while `streaming`).
- `log`: a bounded sequence of records `[inv, kind]` with `kind` in `{ "allow", "deny", "incomplete", "cancel", "fault", "child" }`. A sequence (not counters) so ChildReceiptsFlushed can assert ordering: children precede the parent cancellation.

Actions: `Admit(i)`, `StartDispatch(i)`, `StreamChunk(i)` (may increment `child_buf`), `CompleteOk(i)`, `DenyPostInvocation(i)`, `IncompleteStream(i)`, `DropPreDispatch(i)` (with a nondeterministic set of failed unwind steps; failed steps leave their resource `retained` and force a fault receipt), `DropPostDispatch(i)` (flush `child_buf` to `log` before appending the parent cancel record; lease goes `retained`), `Stutter`. Drop actions are enabled from EVERY non-terminal phase: `DropPreDispatch` from `admitted`, `DropPostDispatch` from `dispatch_started` and `streaming`. Two invocations interleave freely, so the checker explores drop-during-other-invocation orderings the unit tests never do.

Sketch of the two load-bearing actions (final text lands with the spec; shown here so review of this plan can already argue with the semantics):

```tla
DropPreDispatch(i) ==
    /\ phase[i] = "admitted"
    /\ \E failed \in SUBSET { "hold", "slot", "lease", "child" } :
        /\ ledger' = [ledger EXCEPT ![i] =
             [r \in DOMAIN @ |-> IF @[r] /= "reserved" THEN @[r]
                                 ELSE IF r \in failed THEN "retained"
                                 ELSE "released"]]
        /\ IF failed = {}
           THEN /\ phase' = [phase EXCEPT ![i] = "terminal_unwound"]
                /\ UNCHANGED log            \* the receipt-free exit
           ELSE /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
                /\ log' = Append(log, [inv |-> i, kind |-> "fault"])
    /\ UNCHANGED << child_buf_other_vars >>

DropPostDispatch(i) ==
    /\ phase[i] \in { "dispatch_started", "streaming" }
    /\ log' = FlushChildrenThenCancel(log, i, child_buf[i])   \* children BEFORE cancel
    /\ child_buf' = [child_buf EXCEPT ![i] = 0]
    /\ ledger' = [ledger EXCEPT ![i]["lease"] =
         IF @ = "reserved" THEN "retained" ELSE @,
         ![i]["hold"] = IF @ = "reserved" THEN "released" ELSE @]
    /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
```

The `SUBSET failed` quantifier in `DropPreDispatch` is the model form of the fault-collection loop at `kernel_drop_guard.rs:140-228`: each of the four cleanup steps fails independently and the fault receipt fires iff the set is non-empty.

Invariants, each named for the bug class that motivates it:

1. `ReservationConservation` (motivated by `a6d26dbc4` Findings A and B, `c201afbd0`): for every invocation in a terminal phase, every resource that was `reserved` at admission is in exactly one of `{ committed, released, retained }`; no resource of a terminal invocation remains `reserved`. This is the drop-guard face of the [FV-B3](FV-B3-budget-conservation-law.md) conservation law.
2. `TerminalReceiptExactlyOne` (motivated by `a6d26dbc4` Finding C and the F02 closure noted at `kernel_drop_guard.rs:329-336`): `terminal_ok`, `terminal_denied`, and post-dispatch `terminal_fault` invocations each have exactly one terminal record in `log`; `terminal_unwound` has none; pre-dispatch `terminal_fault` has exactly one `fault` record. Equivalently: a fault receipt appears on the pre-dispatch drop path exactly when a cleanup step failed, and never twice.
3. `ChildReceiptsFlushed` (motivated by `38cc91471`): if `phase[i]` is terminal then `child_buf[i] = 0`, every buffered child receipt appears in `log`, and on the post-dispatch drop path every `child` record for `i` precedes `i`'s `cancel` record.
4. `RetainedIffAborted` (motivated by `84e98b9d0`, `58abf33d2`, `c201afbd0`): `ledger[i]["lease"] = "retained"` if and only if `i` terminated in an abort class after dispatch started (`DropPostDispatch`, `IncompleteStream`, `DenyPostInvocation`) or a pre-dispatch unwind step for the lease failed. Never retained on `terminal_ok` or on a clean `terminal_unwound`.

`SafetyInv` is the conjunction plus a `DomainsOK`, matching house style.

Bounds (justified in the style of `formal/apalache/CONTRACTOR-SIGNOFF.md`):

| Bound | Value | Rationale |
| --- | --- | --- |
| `Invocations` | `1..2` | One invocation exercises every per-invocation branch; the second exposes cross-invocation ledger confusion and log interleaving (the loom receipt-store race at `tests/loom_concurrency.rs:631` is a two-guard race). More adds states, not new transition shapes. |
| Children per invocation | `ChildMax = 1` | One buffered child receipt distinguishes flushed-vs-discarded and ordering; the flush loop is shape-identical for n > 1. |
| Ledger resources | 4 fixed | Exactly the four resources the pre-dispatch unwind touches (`kernel_drop_guard.rs:139-229`). |
| Budget domain | statuses only, no amounts | Every motivating bug was a missing or wrong transition, not arithmetic; amounts live in the Kani lane ([FV-B3](FV-B3-budget-conservation-law.md) lane b) where `verify_budget_checked_add_no_overflow` already covers overflow ordering [v]. |
| `--length` | 8 | Admit + StartDispatch + StreamChunk + Drop for two interleaved invocations needs up to 8 steps; existing specs use 6, and the 30-minute per-invariant CI budget [v] has headroom because the state vector here is small. Fall back to 6 if the SMT run regresses. |

### What happens to KernelTransitionCancelSafe.tla

Recommendation: KEEP it, demoted to the narrow snapshot property, and re-point its documentation.

- Keep because it pins a different contract: the Begin -> Cancel snapshot-restoration atomicity that Kani cannot express cross-step (its stated purpose, spec header lines 8-14), and it anchors an existing `formal/MAPPING.md` row and the CONTRACTOR-SIGNOFF record. Deleting it would orphan those references for zero CI savings (it is one cheap matrix row).
- Demote because it must stop being cited as cancel-safety evidence. Its header already concedes the by-construction posture; amend the header comment and its `formal/apalache/README.md` and `formal/MAPPING.md` rows to state that `PostAdmissionDropGuard.tla` is the load-bearing drop/cancel model and `KernelTransitionCancelSafe` is only the snapshot-equality contract.

## Implementation plan

1. Phase 1 - model. Add `formal/apalache/PostAdmissionDropGuard.tla` and `formal/apalache/MCPostAdmissionDropGuard.cfg` (constants, `INVARIANT SafetyInv`). Include the ground-truth table above as the spec's header comment, with file:line anchors, so drift is reviewable.
2. Phase 2 - local check. Run `apalache-mc check --length=8 --config=formal/apalache/MCPostAdmissionDropGuard.cfg formal/apalache/PostAdmissionDropGuard.tla` with the pinned 0.50.1 toolchain; record wall-clock and bound outcomes in a new section of `formal/apalache/CONTRACTOR-SIGNOFF.md` (or a successor record file) using its Attempted/Final/Rationale table format.
3. Phase 3 - falsifiability. Land the [FV-B2](FV-B2-regression-negative-tests.md) Broken variants for all four invariants and confirm each yields a counterexample. The model MUST NOT be cited as evidence (in MAPPING.md prose, README, or audit records) before this phase completes; a by-construction replacement for a by-construction spec would be strictly worse than nothing.
4. Phase 4 - CI and registry wiring. Modify: `.github/workflows/apalache-safety.yml` (matrix row), `formal/apalache/README.md` (invariant table + smoke command), `formal/MAPPING.md` (four rows), `scripts/check-apalache-formal-slice.py` (structural guards, see below), `formal/apalache/KernelTransitionCancelSafe.tla` (header re-point), `scripts/check-mapping.sh` (extend the whitelist so the four new names are enforced; the current whitelist covers only `formal/tla/RevocationPropagation.tla` names and Kani public harnesses, verified by reading the script).

## CI and gating changes

- `.github/workflows/apalache-safety.yml`: add `formal/apalache/MCPostAdmissionDropGuard.cfg|formal/apalache/PostAdmissionDropGuard.tla` to the heredoc matrix (currently 6 rows at lines 66-73). The job is already path-scoped to `formal/apalache/**` on PRs and runs nightly at cron `23 7 * * *`; no trigger changes needed.
- `scripts/check-apalache-formal-slice.py`: add a `check_post_admission_drop_guard()` in the style of `check_receipt_before_allow()` asserting structurally that (a) both Drop actions appear in `Next`, (b) `DropPostDispatch` appends the child records before the cancel record, and (c) `RetainedIffAborted` is a biconditional. This guards against a future edit quietly weakening the spec without tripping the model checker.
- Per-invariant budget: expected to fit well inside the existing 30-minute per-invariant CI timeout [v]; if length 8 does not, drop to 6 and record the reduction in the sign-off record.

## Acceptance criteria

- [ ] `PostAdmissionDropGuard.tla` + cfg exist; header carries the ground-truth table with file:line anchors.
- [ ] All four invariants pass (`NoError`) at the documented bounds with pinned apalache-mc 0.50.1, locally and in the hosted workflow.
- [ ] Each of the four invariants is shown falsifiable by an FV-B2 Broken variant (counterexample reproduced and registered).
- [ ] `apalache-safety.yml` matrix includes the new pair; a green run exists on the PR that lands it.
- [ ] `formal/MAPPING.md` has one row per invariant, naming the Rust paths from the ground-truth table.
- [ ] `KernelTransitionCancelSafe.tla` header, `formal/apalache/README.md`, and its MAPPING row are re-pointed as described (kept, demoted).
- [ ] `scripts/check-apalache-formal-slice.py` structural guards for the new spec pass and are exercised in the same workflow.
- [ ] Bounds table recorded in the internal verification record with attempted/final/rationale columns.

## Risks and mitigations

- Model drifts from the Rust unwind order (duplication drift, gap G4). Mitigation: the ground-truth table lives in the spec header; the slice-check script pins the load-bearing structure; [FV-A4](FV-A4-mirror-drift-hashes.md) mirror-drift hashing can later cover the spec/impl pair.
- State explosion from the log-as-sequence encoding. Mitigation: log length is bounded by `2 * (1 terminal + 1 child + 1 fault)`; if Apalache's `Seq` encoding is slow at these bounds, fall back to per-invocation counters plus a single `children_flushed_before_parent` boolean and record the weakening explicitly in the spec header.
- The model passes because it encodes the fix, not the requirement (self-fulfilling spec). Mitigation: FV-B2 negative variants are a hard gate for evidence status (Phase 3), and each is keyed to a real production commit sha, not to the model's own text.
- Two-invocation bound misses higher-arity races. Mitigation: accepted and documented; true concurrency exploration belongs to the loom lane ([FV-B4](FV-B4-loom-registry-and-dst.md)), which already models the two-guard receipt-store race.

## Open questions

- Should `DropPostDispatch`'s best-effort monetary unwind be allowed to fail in the model (the Rust path logs and continues, `kernel_drop_guard.rs:119-127`)? Proposal: yes, as a nondeterministic outcome leaving `hold = retained`, which makes ReservationConservation's `retained` arm non-vacuous on the post-dispatch path too. Needs a decision before Phase 1.
- Does `RetainedIffAborted` need the marked-in-receipt half (metadata marker present iff retained), or is that better left to the runtime disposition test that already checks it (`drop_guard_proptest.rs:133-150`)? Proposal: model the ledger state only; receipt-metadata fidelity is [FV-C1](FV-C1-receipt-trace-validation.md) territory.
- Whether the internal verification record gains a new file per spec or a new section; follow whatever [FV-C5](FV-C5-proof-coverage-map.md) decides for coverage records.

## Manifest and registry updates

- `formal/MAPPING.md`: add four rows to the Apalache table: `ReservationConservation`, `TerminalReceiptExactlyOne`, `ChildReceiptsFlushed`, `RetainedIffAborted`. Rust paths column: `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/kernel/responses/finalization.rs`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs`. Assumption discharge: `n/a` (structural) for 1, 3, 4; `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY for `TerminalReceiptExactlyOne` (receipt persistence is a single-row append). Update the existing `KernelTransitionCancelSafe` row's description to "snapshot-equality contract; superseded as drop/cancel evidence by PostAdmissionDropGuard.tla".
- `scripts/check-mapping.sh`: extend enforcement to the new invariant names (new whitelist array scoped to `formal/apalache/PostAdmissionDropGuard.tla`).
- `formal/proof-manifest.toml`: no lane changes (Apalache is not a `rust_refinement_lanes` entry); add a `notes` line stating the drop-guard surface is modeled by the new spec and that evidence status is conditional on the FV-B2 negative suite.
- `formal/theorem-inventory.json`: no change (Lean-only registry); the Lean-side ledger model arrives with [FV-B3](FV-B3-budget-conservation-law.md).
- `formal/assumptions.toml`: no change.
- `.kani/harnesses.toml`, `.loom/harnesses.toml`: no change in this doc (see FV-B3 and FV-B4).
