# FV-B1: A real interleaving model of the post-admission drop-guard lifecycle

Status: Implemented (2026-07-10; local evidence complete, hosted verification pending)
Theme: B - Aim the formal tools at the actual bug generator
Effort: M
Depends on: none
Feeds: [FV-B2](FV-B2-regression-negative-tests.md), [FV-B3](FV-B3-budget-conservation-law.md), [FV-C1](FV-C1-receipt-trace-validation.md), [FV-E2](FV-E2-counterexample-regression-pipeline.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G3), [FV-B4](FV-B4-loom-registry-and-dst.md), `formal/apalache/README.md`, `formal/apalache/CONTRACTOR-SIGNOFF.md`

## Summary

The kernel's single largest recent bug generator is the drop/cancel/unwind surface: five production fixes landed against `PostAdmissionDropGuard` in one week (84e98b9d0 through 38cc91471), and none of them changed anything under `formal/`. The only prior Apalache spec near this surface, `formal/apalache/KernelTransitionCancelSafe.tla`, admits in its own header that its invariant holds by construction and that concurrent commit-vs-cancel interleavings are out of scope. This change adds `formal/apalache/PostAdmissionDropGuard.tla`, a bounded model in which drop is enabled from every non-terminal phase and each fixed bug class is a named invariant. Its evidence is paired with [FV-B2](FV-B2-regression-negative-tests.md), which demonstrates that every named invariant is falsifiable by a deliberately broken variant; treat FV-B1 and FV-B2 as one unit of proof value.

## Decisions (2026-07-10)

- Every tool-server error observed after `invoke_stream` or `invoke` is polled
  is outcome-unknown. The model retains monetary exposure, runtime admission,
  credentials, and child budget; the receipt identifies retained state for
  operator reconciliation. There is no post-dispatch unwind branch.
- `RetainedIffAborted` covers ledger disposition only. Receipt metadata
  fidelity remains outside this state model.
- Admission uses budget mutation (none, monetary hold, or invocation slot) x
  runtime lease x child-budget profiles. Impossible hold-plus-slot
  combinations are excluded from the bounded state space.
- Invocation identity is symmetry-reduced: invocation 1 explores every local
  profile and cleanup outcome; invocation 2 uses a fixed maximal non-monetary
  dispatch-to-drop path for arbitrary ordering of independently keyed
  lifecycles. The model has no shared ledger or receipt accumulator.
- The seven calibrated defects select one mutation each through a constant.
  The positive config fixes that constant to `none`, and the structural gate
  enforces the positive setting and each negative singleton setting.
- Bounds and results are recorded in `formal/apalache/CONTRACTOR-SIGNOFF.md`
  because it is already the internal, self-authored Apalache evidence record.
- The initial sequence-log encoding was replaced with exact per-invocation
  receipt counters and a child-before-parent witness after Apalache 0.50.1
  expanded dynamic index scans at every transition. The length-8 bound and all
  four safety obligations remain unchanged.
- Local positive and negative evidence is required before integration. The
  status remains locally implemented until the landing branch has a green
  hosted positive and negative run.

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
- Guard construction and arming happen in the evaluation paths: `mark_dispatch_started` is called immediately before the dispatch await at `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs:545` and `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs:505`; `disarm` runs on the normal exit at `async_evaluation_core.rs:549` and `nested_flow_evaluation.rs:539`.
- Existing test evidence: an exhaustive 8-cell disposition-table test (`crates/kernel/chio-kernel/src/kernel/tests/drop_guard_proptest.rs:42`, `drop_guard_disposition_table`), runtime tests in `kernel/tests/chio_runtime.rs`, and two loom models of the drop path (`crates/kernel/chio-kernel/tests/loom_concurrency.rs:631` and `:682`). These pin single points; none explore multi-invocation interleavings of the whole lifecycle.
- Current formal posture: `formal/apalache/` runs five specs plus two `formal/tla/` specs in `.github/workflows/apalache-safety.yml`, on path-scoped PRs and nightly, with apalache-mc 0.50.1 pinned via `tools/install-apalache.sh`. The original rows run at length 6 and the drop-guard row at length 8. `Common.tla` hard-pins its bounds with an `ASSUME` (`formal/apalache/Common.tla:19-22`), so the drop-guard spec declares its independent domains (see Design).
- `formal/MAPPING.md` has an Apalache invariant table; `KernelTransitionCancelSafe` is a row there.

### Ground-truth table: Rust code paths to model actions

All file:line references below were verified by reading the files this session. Paths are relative to `crates/kernel/chio-kernel/src/kernel/` unless noted.

| Model action | Rust ground truth |
| --- | --- |
| `Admit` | `PostAdmissionDropGuard::new` (`kernel_drop_guard.rs:86-109`): guard armed, `dispatch_started = false`, holds `budget_mutation` (none, monetary charge, or invocation increment), runtime-admission metadata in `receipt_context`, empty child-receipt buffer. |
| `StartDispatch` | `mark_dispatch_started` (`kernel_drop_guard.rs:130-132`), called at `evaluation/async_evaluation_core.rs:545` and `evaluation/nested_flow_evaluation.rs:505`. |
| `StreamChunk` | Dispatch in flight; the nested-flow bridge pushes already-signed child receipts into the guard-owned buffer via `child_receipts_mut` (`kernel_drop_guard.rs:115-117`). |
| `CompleteOk` | Normal exit: `take_child_receipts` drains the buffer (`kernel_drop_guard.rs:122-124`), `disarm` (`kernel_drop_guard.rs:134-136`), allow receipt built in `responses/finalization.rs:54-69`. |
| `DenyPostInvocation` | Post-invocation output guard blocks after dispatch: deny receipt with retained-reservation marking (`responses/finalization.rs`). Fixed by `58abf33d2`. |
| `IncompleteStream` | Successfully returned structured incomplete output follows normal monetary reconciliation, then emits an incomplete receipt with the required runtime-reservation disposition (`responses/finalization.rs`, `validation.rs`). Fixed by `84e98b9d0`. |
| `ServerErrorPostDispatch` | Any error returned after polling `invoke_stream` or `invoke` is outcome-unknown. `retain_post_dispatch_state` preserves budget and payment exposure and combines receipt metadata with a separate trusted `runtime_admission_metadata` value. URL elicitation is a signed `Incomplete` outcome, never a retryable release path. |
| `DropPreDispatch` | `Drop` with `armed && !dispatch_started` (`kernel_drop_guard.rs:385-392`) runs `handle_pre_dispatch_drop` (`kernel_drop_guard.rs:180-308`): monetary unwind, invocation-only budget reversal, runtime-admission release, child-budget release, and one signed fault receipt iff any step failed. Clean unwind is receipt-free. |
| `DropPostDispatch` | `Drop` with `armed && dispatch_started`: flush buffered child receipts first, retain all authorization and monetary state through `retain_post_dispatch_state`, and append one cancellation receipt carrying the retained identifiers. |
| `UnwindStep` (failable) | Each pre-dispatch cleanup step is attempted independently and failures are collected in `handle_pre_dispatch_drop` (`kernel_drop_guard.rs:180-308`); the model gives each step a nondeterministic fail outcome. |

Ledger-touching primitives the model abstracts: pre-dispatch cleanup through `cleanup_pre_dispatch_state`; post-dispatch retention through `retain_post_dispatch_state`; runtime release and retained marking through the trusted `runtime_admission_metadata` channel; and capability-budget reversal/release in `validation.rs`. Receipt metadata supplied by a tool server is never used as trusted input to runtime-admission release or retention.

## Design

New spec pair: `formal/apalache/PostAdmissionDropGuard.tla` + `formal/apalache/MCPostAdmissionDropGuard.cfg`.

Because `Common.tla` pins `Authorities = 1..3`, `CapSet = 1..6`, `EpochMax = 4` with an `ASSUME` (`Common.tla:19-22`), the new module declares its own constants instead of extending `Common` (its domains are invocations and ledger resources, not authorities and caps).

State (per invocation `i \in Invocations`):

- `phase[i]` in `{ "idle", "admitted", "dispatch_started", "streaming", "terminal_ok", "terminal_denied", "terminal_unwound", "terminal_fault" }`. This is the task's six-phase proposal plus `idle` (pre-admission) and `terminal_unwound` (the receipt-free clean pre-dispatch unwind, which must be distinguishable from `terminal_fault` for TerminalReceiptExactlyOne to be stateable). `terminal_denied` covers both the post-invocation block and the incomplete-stream terminals (deny-class receipts with retained lease); `terminal_fault` covers drop-driven terminals (post-dispatch cancellation, pre-dispatch cleanup fault).
- `ledger[i][r]` for `r \in { "hold", "slot", "lease", "child" }` in `{ "none", "reserved", "committed", "released", "retained" }`: monetary hold, invocation-count slot, runtime-admission lease, and the one child budget split. `Admit` chooses among the 12 valid profiles formed by budget mutation (none, hold, or slot) x lease x child; hold plus slot is impossible in production.
- `child_buf[i]` in `0..ChildMax`: buffered signed child receipts (only grows while `streaming`).
- `child_logged`, `parent_receipts`, and `parent_kind_logged`: exact per-invocation receipt cardinality and parent-kind counters. `children_before_parent` is the explicit ordering witness set by the same transition that flushes the child count before incrementing the parent count.

Actions: `Admit(i)`, `StartDispatch(i)`, `StreamChunk(i)` (may increment `child_buf`), `CompleteOk(i)`, `DenyPostInvocation(i)`, `IncompleteStream(i)`, `ServerErrorPostDispatch(i)`, `DropPreDispatch(i)` (with a nondeterministic set of failed cleanup steps; failed steps leave their resource `retained` and force a fault receipt), and `DropPostDispatch(i)` (accounts for buffered children before the parent cancellation and retains every outcome-unknown resource). The server-error action includes URL elicitation, cancellation, incomplete, and generic errors after dispatch. The temporal wrapper supplies stuttering. Drop actions are enabled from every armed non-terminal phase: `DropPreDispatch` from `admitted`, `DropPostDispatch` from `dispatch_started` and `streaming`. Two invocations interleave freely, so the checker covers arbitrary ordering of two independently keyed lifecycles. Because the ledger and receipt counters are per-invocation, this model does not claim a shared-store race result.

Shape of the two load-bearing actions:

```tla
DropPreDispatch(i) ==
    /\ phase[i] = "admitted"
    /\ \E failed \in CleanupFailureProfiles :
        /\ failed \subseteq admitted_resources[i]
        /\ ledger' = [ledger EXCEPT ![i] =
             [r \in DOMAIN @ |-> IF @[r] /= "reserved" THEN @[r]
                                 ELSE IF r \in failed THEN "retained"
                                 ELSE "released"]]
        /\ IF failed = {}
           THEN /\ phase' = [phase EXCEPT ![i] = "terminal_unwound"]
                /\ UNCHANGED parent_receipts
           ELSE /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
                /\ parent_receipts' =
                     [parent_receipts EXCEPT ![i] = @ + 1]

DropPostDispatch(i) ==
    /\ phase[i] \in { "dispatch_started", "streaming" }
    /\ LET flushed_count == child_logged[i] + child_buf[i]
       IN /\ child_buf' = [child_buf EXCEPT ![i] = 0]
          /\ child_logged' = [child_logged EXCEPT ![i] = flushed_count]
          /\ parent_receipts' = [parent_receipts EXCEPT ![i] = @ + 1]
          /\ children_before_parent' =
               [children_before_parent EXCEPT
                    ![i] = flushed_count = child_total[i]]
          /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
```

`CleanupFailureProfiles` is the explicit 12-member valid resource-profile
domain. Filtering it to subsets of `admitted_resources[i]` represents every
independent cleanup-failure combination without asking Apalache 0.50.1 to
expand a dynamic powerset. This is the model form of the fault-collection loop
at `kernel_drop_guard.rs:180-308`: each admitted cleanup step may fail, and the
fault receipt fires iff the failure set is non-empty.

Invariants, each named for the bug class that motivates it:

1. `ReservationConservation` (motivated by `a6d26dbc4` Findings A and B, `c201afbd0`): for every invocation in a terminal phase, every resource that was `reserved` at admission is in exactly one of `{ committed, released, retained }`; no resource of a terminal invocation remains `reserved`. This is the drop-guard face of the [FV-B3](FV-B3-budget-conservation-law.md) conservation law.
2. `TerminalReceiptExactlyOne` (motivated by `a6d26dbc4` Finding C and the F02 closure at `kernel_drop_guard.rs:409-437`): `terminal_ok`, `terminal_denied`, and post-dispatch `terminal_fault` invocations each have exactly one terminal parent receipt; `terminal_unwound` has none; pre-dispatch `terminal_fault` has exactly one fault receipt.
3. `ChildReceiptsFlushed` (motivated by `38cc91471`): if `phase[i]` is terminal then `child_buf[i] = 0`, `child_logged[i] = child_total[i]`, and the child-before-parent ordering witness holds.
4. `RetainedIffAborted` (motivated by `84e98b9d0`, `58abf33d2`, `c201afbd0`): `ledger[i]["lease"] = "retained"` if and only if `i` terminated in an abort class after dispatch started (`DropPostDispatch`, `IncompleteStream`, `DenyPostInvocation`) or a pre-dispatch unwind step for the lease failed. Never retained on `terminal_ok` or on a clean `terminal_unwound`.

`SafetyInv` is the conjunction plus a `DomainsOK`, matching house style.

Bounds (justified in the style of `formal/apalache/CONTRACTOR-SIGNOFF.md`):

| Bound | Value | Rationale |
| --- | --- | --- |
| `Invocations` | `1..2` | Invocation 1 exercises every local branch. Invocation 2 uses a fixed maximal non-monetary dispatch-to-drop path so the checker covers arbitrary ordering of two independently keyed lifecycles. Ledgers and counters remain per-invocation; shared-store races belong to the loom lane. Duplicating every local terminal choice under both identities adds states, not transition shapes. |
| Children per invocation | `ChildMax = 1` | One buffered child receipt distinguishes flushed-vs-discarded and ordering; the flush loop is shape-identical for n > 1. |
| Ledger resources | 4 fixed | Exactly the four resources the pre-dispatch unwind touches (`kernel_drop_guard.rs:180-308`). |
| Budget domain | statuses only, no amounts | Every motivating bug was a missing or wrong transition, not arithmetic. Amount arithmetic is outside this model. `verify_budget_checked_add_no_overflow` is a standalone model-level arithmetic witness, not evidence for production-store overflow ordering. |
| `--length` | 8 | Admit + StartDispatch + StreamChunk + Drop for two interleaved invocations needs up to 8 steps. The workflow enforces a 30-minute timeout without reducing this bound. |

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
- Per-invariant budget: the workflow enforces the existing 30-minute timeout
  at length 8. A timeout fails closed and requires state-space optimization,
  not a silent bound reduction.

## Acceptance criteria

- [x] `PostAdmissionDropGuard.tla` + cfg exist; header carries the ground-truth table with file:line anchors.
- [x] All four invariants pass (`NoError`) at the documented bounds with pinned apalache-mc 0.50.1 locally.
- [ ] A hosted workflow run passes the same positive check.
- [x] Each of the four invariants is shown falsifiable by a registered Broken variant locally.
- [x] `apalache-safety.yml` includes the new pair with its length and timeout.
- [ ] The landing PR has a green hosted positive and negative run.
- [x] `formal/MAPPING.md` has one row per invariant, naming the Rust paths from the ground-truth table.
- [x] `KernelTransitionCancelSafe.tla` header, `formal/apalache/README.md`, and its MAPPING row are re-pointed as described (kept, demoted).
- [x] `scripts/check-apalache-formal-slice.py` structural guards for the new spec pass and are exercised in the same workflow.
- [x] Bounds table recorded in the internal verification record with attempted/final/rationale columns.

## Risks and mitigations

- Model drifts from the Rust unwind order (duplication drift, gap G4). Mitigation: the ground-truth table lives in the spec header; the slice-check script pins the load-bearing structure; [FV-A4](FV-A4-mirror-drift-hashes.md) mirror-drift hashing can later cover the spec/impl pair.
- State explosion from the attempted log-as-sequence encoding. Resolution: the final model uses per-invocation counters plus `children_before_parent`; the spec header and verification record document the abstraction, and the discard-child mutation calibrates it.
- The model passes because it encodes the fix, not the requirement (self-fulfilling spec). Mitigation: FV-B2 negative variants are a hard gate for evidence status (Phase 3), and each is keyed to a real production commit sha, not to the model's own text.
- Two-invocation bound misses higher-arity races. Mitigation: accepted and documented; true concurrency exploration belongs to the loom lane ([FV-B4](FV-B4-loom-registry-and-dst.md)), which already models the two-guard receipt-store race.

## Resolved questions

- Should a tool-server error ever trigger post-dispatch monetary unwind? Decision: no. Once either invoke method is polled, the kernel cannot prove that no side effect occurred. The model therefore retains the hold on every returned-error and dropped-future path; only kernel-owned pre-dispatch failures reverse or release state.
- Does `RetainedIffAborted` need the marked-in-receipt half (metadata marker present iff retained), or is that better left to the runtime disposition test that already checks it (`drop_guard_proptest.rs:133-150`)? Decision: model the ledger state only; receipt-metadata fidelity is [FV-C1](FV-C1-receipt-trace-validation.md) territory.
- Whether the internal verification record gains a new file per spec or a new section. Decision: add a dated section to `formal/apalache/CONTRACTOR-SIGNOFF.md`, which is already explicitly labeled as an internal, self-authored record.

## Manifest and registry updates

- `formal/MAPPING.md`: add four rows to the Apalache table: `ReservationConservation`, `TerminalReceiptExactlyOne`, `ChildReceiptsFlushed`, `RetainedIffAborted`. Rust paths column: `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`, `crates/kernel/chio-kernel/src/kernel/responses/finalization.rs`, `crates/kernel/chio-kernel/src/kernel/dispatch.rs`. Assumption discharge: `n/a` (structural) for 1, 3, 4; `formal/assumptions.toml` ASSUME-SQLITE-ATOMICITY for `TerminalReceiptExactlyOne` (receipt persistence is a single-row append). Update the existing `KernelTransitionCancelSafe` row's description to "snapshot-equality contract; superseded as drop/cancel evidence by PostAdmissionDropGuard.tla".
- `scripts/check-mapping.sh`: extend enforcement to the new invariant names (new whitelist array scoped to `formal/apalache/PostAdmissionDropGuard.tla`).
- `formal/proof-manifest.toml`: no lane changes (Apalache is not a `rust_refinement_lanes` entry); add a `notes` line stating the drop-guard surface is modeled by the new spec and that evidence status is conditional on the FV-B2 negative suite.
- `formal/theorem-inventory.json`: no change (Lean-only registry); the Lean-side ledger model arrives with [FV-B3](FV-B3-budget-conservation-law.md).
- `formal/assumptions.toml`: no change.
- `.kani/harnesses.toml`, `.loom/harnesses.toml`: no change in this doc (see FV-B3 and FV-B4).
