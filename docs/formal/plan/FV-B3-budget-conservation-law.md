# FV-B3: One budget conservation law, four enforcement lanes

Status: Implemented (2026-07-10; local evidence complete, hosted verification pending)
Theme: B - Aim the formal tools at the actual bug generator
Effort: M
Depends on: [FV-B1](FV-B1-drop-guard-model.md) (lane a); [FV-A1](FV-A1-absorb-verified-helpers.md) supplies the scalar-admission baseline but does not link lane b's ledger transitions
Feeds: [FV-D3](FV-D3-economy-conservation.md), [FV-B4](FV-B4-loom-registry-and-dst.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G3, G2), [FV-A3](FV-A3-creusot-dedup.md), [FV-E4](FV-E4-fuzz-plumbing-repair.md)

## Summary

Every drop-guard fix in the recent family is, at bottom, a violation of one law: an admitted reservation must end in exactly one terminal ledger state, and the amounts must balance. This document states that law once (reserved equals committed plus released plus retained, at all times, including across child splits whose sibling sums are bounded by the parent) and enforces it in four lanes that fail differently: (a) an Apalache invariant over interleavings, (b) a pure verified transition function (Kani + Creusot + Lean) over amounts, (c) a debug-assertions audit inside the real kernel, and (d) a stateful proptest driving the real store. One law with four independent witnesses is worth more than four unrelated properties, because a drift in any lane is detected by disagreement with the others.

## Decisions (2026-07-10)

- The counted Apalache ledger retains the resource-status projection used by the negative models and adds an independent amount partition bounded by `BudgetMax = 4`. Active child shares are counted across invocations and admission enforces `ActiveChildShares < ChildMax`; the dedicated child-oversubscription mutation removes only that guard. This preserves the already-validated counterexample vocabulary while strengthening `ReservationConservation` and `ChildSplitsBounded` at every reachable state.
- `ledger_apply` rejects over-disposition, reserve-after-terminal, unknown operation tags, any input state whose aggregate does not fit in `u64`, and every checked-add overflow as an exact no-op. A finalized ledger is absorbing, while partial realization may populate both committed and released amount buckets under one terminal hold classification. Kani covers six-step dense sequences plus forced `u64::MAX - tail`, mixed-bucket aggregate-overflow, and exact-`u64::MAX` terminal-transfer boundary states. Creusot and Lean prove the same pure transition algebra.
- The concrete audit is scoped to `BudgetGuaranteeLevel::SingleNodeAtomic`. It replays every monetary journal event, checks each recorded after-state, and checks the final usage row. Events without hold IDs are conserved as one anonymous pool and do not establish per-hold identity; production reverse and reconcile call sites separately require the expected named hold to terminate exactly once. The journal has no retain mutation. On an outcome-unknown post-dispatch path, the concrete hold therefore remains exposed and counts against the cap, while signed receipt metadata projects that exposure as retained and identifies it for operator reconciliation. Missing journal support is logged and skipped because diagnostics do not turn an otherwise-supported backend into a panic.
- A reconcile of exposure `E` to realized spend `S` classifies `S` as committed and the unused `E - S` as released. The hold has one terminal disposition (`Reconciled`) even though its amount partition can contain both committed and released units.
- `property_reservation_ledger.rs` drives a real `InMemoryBudgetStore` through arbitrary authorize, reverse, release, and reconcile sequences, checking the journal, usage row, and terminal history after every operation; a second randomized sequence checks the sibling-share registry. The separate in-kernel `drop_guard_disposition_table` test exercises the production admission-hook and drop-guard paths over all eight lifecycle cells. It requires pre-dispatch cleanup to reverse or release admitted state, and post-dispatch outcome-unknown cells to perform no monetary reversal while retaining exposure and signed identifiers.
- The deterministic `omitted_release_is_detected_by_terminal_history_replay` dry run marks an authorized hold terminal without recording its release. The store-level oracle must panic with `terminal history has no matching concrete disposition`, demonstrating that an omitted monetary cleanup cannot silently satisfy the journal replay.
- Lean 4 is available in the strict toolchain, so the two new root-imported, sorry-free theorems are registered `proved`, not `assumed`. This is stronger and more accurate than the proposal's toolchain-unavailable fallback.
- Scalar admission is implementation-linked. Production reservation-ledger refinement is not established; the debug replay and stateful test are runtime evidence, not a refinement proof.

## Motivation and evidence

- `a6d26dbc4` (Finding A: invocation slot never reversed on pre-dispatch drop; Finding B: child budget share never released) and `c201afbd0` (aborted unwind paths left reservations unmarked) are conservation violations: value left in `reserved` forever. `84e98b9d0` and `58abf33d2` are misclassification violations: value moved to the wrong terminal state (`released` semantics where `retained` was required). A single ledger law covers all five [commit family verified via `git show --stat` this session].
- The verified budget helpers already in-tree stop short of a ledger. `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` has `budget_precheck` (line 68) and `budget_commit` (line 77) over bounded ints, modeled by Lean, Kani, and Creusot. Shared scalar admission projections now call them from both production budget backends, but they still express a single admit decision, not the reserve/settle/reverse/release lifecycle [v].
- The Kani harness `verify_budget_checked_add_no_overflow` proves fail-closed no-partial-commit, Overflow-before-CapExceeded dispatch order, and retry idempotence for a standalone model of the store's `checked_add` ordering, in two phases (dense u8 bounds, then `current = u64::MAX - tail` to de-vacuate the overflow arm) [v]. Runtime budget tests, not that harness, bind concrete mutations. This is the arithmetic floor this law builds on: FV-B3 adds the lifecycle dimension the overflow harness deliberately does not model.
- The child-split half already has a Lean anchor: `formal/lean4/Chio/Chio/Proofs/SiblingSumBudget.lean` proves `sibling_sum_soundness` (line 82) and `sibling_sum_after_admit_bounded` (line 97) over a `BudgetSplit`/`admitChild` model of `BudgetSplit::try_admit_child` (implementation at `crates/kernel/chio-kernel-core/src/budget_split.rs:184`). The law's clause 3 below composes with those theorems rather than restating them.

## Current state

The real ledger is spread across three surfaces (all verified by reading this session):

- Monetary store: `crates/kernel/chio-kernel/src/budget_store.rs`. `BudgetStore` trait (line 260) with `try_charge_cost` (line 286: atomically check limits and record provisional exposure), `reverse_charge_cost` (line 347: denial-path reversal), `reduce_charge_cost` (line 384: release exposure without realizing spend), `settle_charge_cost` (line 423: move exposure to realized spend, `realized <= exposed`), plus hold-level wrappers `authorize_budget_hold` / `reverse_budget_hold` / `release_budget_hold` / `reconcile_budget_hold` (lines 507-654). The mutation journal vocabulary is exactly the law's alphabet: `BudgetMutationKind` (lines 34-40) = `IncrementInvocation | AuthorizeExposure | ReverseExposure | ReleaseExposure | ReconcileSpend`, and `list_mutation_events` (line 484) exposes the journal. Per-record identity: `committed_cost_units = total_cost_exposed + total_cost_realized_spend`, checked-add guarded (line 664).
- Kernel transition points: `cleanup_pre_dispatch_state` reverses or releases all kernel-owned pre-dispatch mutations; `retain_post_dispatch_state` preserves budget and payment exposure and signs their identifiers after dispatch; `release_runtime_admission_reservations` and `mark_runtime_admission_reservations_retained_fail_closed` operate only on the trusted `runtime_admission_metadata` captured from the hook; and the capability-budget reversal/release primitives live in `validation.rs`. Runtime-admission lease state itself lives behind the `RuntimeAdmissionHook` trait and is tracked via reserved and retained ids, not a kernel-owned table. Untrusted receipt metadata is merged only after the runtime disposition is derived and cannot supply reservation ids to the hook.
- Existing tests: `tests/property_budget_store.rs` (referenced in `crates/kernel/chio-kernel/Cargo.toml` dev-dependency comments, lines 85-87) covers store arithmetic. The strengthened `kernel/tests/drop_guard_proptest.rs::drop_guard_disposition_table` now drives the production runtime-admission hook and real `PostAdmissionDropGuard` over all eight cells, then checks release counts, receipt metadata, the monetary journal, and final usage.

Before this implementation, no artifact stated the four-way partition law and nothing checked it across an arbitrary operation sequence. The four enforcement surfaces below now share the same normative text from `budget_store.rs` while retaining explicit model and runtime boundaries.

## Design

### The law

For every admission `a` with reserved amount `R(a)`:

1. Partition: at every reachable state, `R(a) = committed(a) + released(a) + retained(a) + outstanding(a)`, with `outstanding(a) >= 0`, where committed = settled/realized spend (`ReconcileSpend`), released = exposure reversed or reduced before dispatch or after a known outcome, retained = state deliberately not unwound because a post-dispatch outcome is unknown, and outstanding = exposure awaiting a disposition. The abstract model moves an unknown hold from outstanding to retained. The concrete store has no retain mutation, so it leaves the same amount outstanding and the signed receipt supplies the retained projection. These are two views of one amount, never additive buckets in the same projection.
2. Terminal uniqueness: a known successful output, including a structured output whose terminal decision is incomplete, reconciles the hold normally and leaves no outstanding amount. A post-dispatch error or dropped future is outcome-unknown: credentials, runtime admission, child budget, budget exposure, and payment authorization remain consumed or exposed, and exactly one signed terminal receipt identifies the retained state for operator reconciliation. A hold is never both reversed and settled; a lease is never both released and retained.
3. Child splits: for a parent with share `P`, the sum of admitted child shares never exceeds `P` (this is `sibling_sum_soundness` / `sibling_sum_after_admit_bounded` in `SiblingSumBudget.lean`), and each child's own ledger obeys clauses 1-2 independently.

Mapping from the law's alphabet to the store's journal vocabulary (`BudgetMutationKind`, `budget_store.rs:34-40`) and to the kernel transition points; this table is the normative join and lives verbatim in the `budget_store.rs` doc comment:

| Law term | Store journal event | Kernel transition point |
| --- | --- | --- |
| reserve `R(a)` | `AuthorizeExposure` (+ `IncrementInvocation` for the slot) | admission via `authorize_budget_hold` / `try_charge_cost` |
| commit | `ReconcileSpend` (exposed -> realized, `realized <= exposed`) | normal finalize with reported cost |
| release | `ReverseExposure` (pre-dispatch denial/cleanup) or `ReleaseExposure` (known reduction without spend) | `cleanup_pre_dispatch_state`, `reverse_pre_execution_budget_mutation`, `release_admitted_capability_budget` |
| retain | no journal event; exposure stays outstanding and signed metadata records the retained projection | `retain_post_dispatch_state` on every returned error or dropped future after an invoke method is polled |

The empty journal cell in the retain row is load-bearing. Reversing the hold would reopen spending capacity even though the tool may have committed a side effect. Retention is evidenced jointly by unchanged concrete exposure and signed metadata containing `post_dispatch_outcome_unknown`, the budget hold id, any payment authorization id, and trusted runtime reservation ids. Lane (c) and `drop_guard_disposition_table` enforce that join; the store-only lane (d) cannot inspect receipt metadata.

### Lane (a): Apalache interleaving lane

`ReservationConservation` in [FV-B1](FV-B1-drop-guard-model.md) is the quiescence form. This lane strengthens it in the same spec: promote the per-resource status ledger to a small counted ledger (amounts in `0..BudgetMax`, `BudgetMax = 4`) and assert the partition equation at EVERY state, not just terminals. `ActiveChildShares` counts admitted child reservations across invocations, `Admit` enforces the shared `ChildMax`, and `ChildSplitsBounded` checks that count at every state. Amounts stay tiny because lane (b) owns arithmetic; this lane owns interleavings. Falsifiability uses the child-release, invocation-reversal, and child-oversubscription variants.

### Lane (b): pure verified transition function

Add to `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` (the extraction-safe module, per its header contract of bounded ints and booleans only):

```rust
pub struct ReservationLedger {
    pub reserved: u64,   // outstanding
    pub committed: u64,
    pub released: u64,
    pub retained: u64,
}

// op: 0 = Reserve(amount), 1 = Commit(amount), 2 = Release(amount),
//     3 = Retain(amount). Returns (new_state, valid). Invalid ops
//     (amount > outstanding for 1..3, checked_add overflow anywhere)
//     return the UNCHANGED state with valid = false (fail closed,
//     no partial commit; same posture as budget_commit).
pub fn ledger_apply(state: ReservationLedger, op: u8, amount: u64) -> (ReservationLedger, bool);
```

Witnesses:

- Kani: `verify_reservation_ledger_conservation` in `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`, proving over a bounded op sequence (length ~6, dense small amounts, plus adversarial `u64::MAX - tail`, mixed-bucket aggregate-overflow, and exact-total boundary phases) that: total is invariant (`reserved + committed + released + retained` never changes except by Reserve), no field underflows/overflows, invalid input states and operations are exact no-ops, and terminal uniqueness holds when driven by a disposition tag. Sketch:

  ```rust
  #[kani::proof]
  fn verify_reservation_ledger_conservation() {
      // Phase 1: dense small domain, every op reachable.
      let mut st = ReservationLedger::default();
      let mut total_reserved: u64 = 0;
      for _ in 0..6 {
          let op: u8 = kani::any(); kani::assume(op <= 3);
          let amt: u64 = kani::any(); kani::assume(amt <= 8);
          let (next, valid) = ledger_apply(st, op, amt);
          if !valid { assert!(next == st); }             // exact no-op on rejection
          if valid && op == 0 { total_reserved += amt; }
          st = next;
          assert!(st.reserved + st.committed + st.released + st.retained == total_reserved);
      }
      // Phase 2: de-vacuate the overflow arm (current = u64::MAX - tail pattern).
      // ... force each checked_add to the boundary and assert valid == false, state unchanged.
  }
  ```
- Creusot: `ledger_apply_conservation_contract` in `formal/rust-verification/creusot-core/`, registered in `formal/rust-verification/creusot-contracts.toml` `covered_symbols` and `contract_twin` metadata (pattern verified by the `budget_commit_contract` mapping).
- Lean: new module `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean` (one file per law, following the `SiblingSumBudget.lean` precedent) with `ledgerApply` mirrored, `theorem ledger_conservation` (fold of valid operations preserves the partition sum) and `theorem ledger_terminal_unique`, plus a lemma importing `Chio.Proofs.SiblingSumBudget.sibling_sum_soundness` to state clause 3 as: an admitted child's reserve is bounded by the parent's share. Both the new module and `SiblingSumBudget.lean` are root-imported and checked by the available Lean toolchain, so their inventory status is `proved`.

Implementation-linkage honesty clause: `ledger_apply` starts life uncalled by production. The completed scalar-admission absorption covers only cap admission and does not link reservation conservation or any ledger state transition. Until a separate ledger linkage lands, lanes (c) and (d) are the anti-drift binding between this model and the real store, and the `MAPPING.md` row must say "model-level; production ledger linkage not established" rather than implying refinement.

### Lane (c): debug-assertions conservation audit in the real kernel

New module `crates/kernel/chio-kernel/src/kernel/ledger_audit.rs`, compiled under `#[cfg(debug_assertions)]` (zero release cost), exposing `debug_assert_reservation_conservation(kernel_or_store, capability_id, grant_index)`. It replays `list_mutation_events` (`budget_store.rs:484`) for the (capability, grant) pair and asserts (1) the fold of monetary `BudgetMutationKind` deltas reproduces the stored `total_cost_exposed` / `total_cost_realized_spend` (journal-state agreement), and (2) exposure never goes negative mid-fold (no release/reverse of value never reserved). Because that journal has no retain event, this function does not detect or prove retained monetary holds. `debug_assert_runtime_reservations_retained` separately checks runtime lease IDs and the retention marker in receipt metadata.

Call sites (the exact transition groups, all verified this session):

- End of `PostAdmissionDropGuard::drop`: clean pre-dispatch cleanup audits the reversed/released ledger; post-dispatch drop preserves exposure and signs retained identifiers.
- Every returned error after polling `invoke_stream` or `invoke`, including URL elicitation, calls `retain_post_dispatch_state`; no error variant supplied by a tool server is classified as proof that effects did not occur.
- After `reverse_pre_execution_budget_mutation` and `release_admitted_capability_budget` on kernel-owned pre-dispatch exits.
- Known output finalization reconciles budget/payment state normally. Retained-marking finalize arms assert the metadata half of clause 2 without treating untrusted receipt metadata as runtime-admission metadata.

Backends without a journal (`list_mutation_events` defaults to an `Invariant` error, `budget_store.rs:489-493`) make the audit a no-op with a debug log, never a panic on missing capability: the audit must not convert an unsupported backend into a crash (fail-closed applies to access decisions, not to diagnostics).

### Lane (d): stateful proptest on the real store

New test `crates/kernel/chio-kernel/tests/property_reservation_ledger.rs` (sibling of the existing `tests/property_budget_store.rs`): a proptest strategy generates arbitrary sequences over `{authorize hold, reverse, release, reconcile}` against an `InMemoryBudgetStore`, then asserts the monetary law from the journal, usage row, and terminal history after every step. A second stateful sequence checks admitted sibling shares and releases through `InMemoryBudgetRegistry`. Production kernel lifecycle, runtime hook, drop-guard, and receipt behavior are covered separately by the in-kernel `kernel/tests/drop_guard_proptest.rs::drop_guard_disposition_table`, which drives the real hook and guard over all eight disposition cells and replays the resulting journal and usage. Follow-on option: promote the store operation-sequence interpreter to `fuzz/fuzz_targets/reservation_ledger_ops.rs` (the fuzz tree exists with 26 targets); mechanics, corpus metadata, and plumbing repairs are deferred to the [FV-E4](FV-E4-fuzz-plumbing-repair.md) checklist to avoid inheriting the known G6 leaks here.

## Implementation plan

1. Phase 1 - law text and lane (d). Add the law statement as a doc comment in `budget_store.rs` (single normative location in code) and land `tests/property_reservation_ledger.rs`. No dependencies; catches real regressions immediately.
2. Phase 2 - lane (c). Add `kernel/ledger_audit.rs` plus the call sites listed above; wire `mod ledger_audit;` in `kernel/mod.rs`. Debug-only; run the full kernel test suite to shake out latent violations before any other lane exists (this is where surprises will surface).
3. Phase 3 - lane (b). Add `ledger_apply` to `formal_aeneas.rs`, the Kani harness to `kani_public_harnesses.rs`, the Creusot contract to `formal/rust-verification/creusot-core/`, and `Proofs/ReservationLedger.lean`. Registry rows per the manifest section below.
4. Phase 4 - lane (a). Strengthen the FV-B1 spec's ledger to counted amounts and the every-state partition equation; add/adjust the FV-B2 negative variants that falsify it.
5. Phase 5 - optional fuzz promotion via the FV-E4 checklist.

## CI and gating changes

- Lane (b) rides existing lanes automatically: the Kani harness joins the `kani-public-pr` sweep via a `[[harness]]` row in `.kani/harnesses.toml` (`lane = "pr"`, `default_unwind` sized to the op-sequence length); the Creusot contract joins the strict lanes via `creusot-contracts.toml`; no workflow edits (the manifest-driven design was built for this, `.kani/harnesses.toml` header lines 24-28).
- Lane (c) rides every `cargo test` (debug builds) and therefore the standard PR gate; no new job.
- Lane (d) joins the proptest tiers: default cases on PR, then `PROPTEST_CASES=10000 cargo test -p chio-kernel --test property_reservation_ledger` in the existing `proptest-nightly` job in `.github/workflows/nightly.yml`; shrunk regressions are committed under `proptest-regressions/` per the counterexample template flow [v].
- Lane (a) rides `apalache-safety.yml` via FV-B1's matrix row; no additional job.

## Acceptance criteria

- [x] The law is stated verbatim (clauses 1-3) in exactly four enforcement artifacts: `PostAdmissionDropGuard.tla`, `formal_aeneas.rs::ledger_apply` (+ Kani + Creusot + Lean witnesses), `kernel/ledger_audit.rs`, `tests/property_reservation_ledger.rs`, each cross-referencing the others by path.
- [x] `formal/MAPPING.md` has a mapped row or theorem cross-reference for every artifact, and each entry names the other lanes (the four-lane join is greppable).
- [x] Kani harness green in the manifest sweep; Creusot contract green in the strict lane; the root-imported Lean module builds without `sorry` and its theorems are registered `proved`.
- [x] Lane (c) call sites cover all transition-point groups listed above; the documented `omitted_release_is_detected_by_terminal_history_replay` dry run proves the store oracle rejects missing cleanup for a known pre-dispatch disposition. Outcome-unknown post-dispatch retention is instead checked by unchanged exposure plus signed retained identifiers.
- [x] Lane (d) survives 10k mixed-sequence cases locally and the nightly case count is wired in CI.
- [x] The implementation-linkage caveat ("scalar admission linked; production ledger linkage not established") appears in the `MAPPING.md` rows and proof-manifest note; no doc claims ledger refinement.

## Risks and mitigations

- Lane semantics drift apart (the Apalache ledger, the pure ledger, and the store journal disagree on what "released" means). Mitigation: the law text is written once in `budget_store.rs` with the `BudgetMutationKind` mapping table, and every other artifact quotes it by path; [FV-A4](FV-A4-mirror-drift-hashes.md) hashes can pin the quartet later.
- Lane (c) audit cost distorts debug-profile test time (journal replay per transition). Mitigation: replay is per (capability, grant) and journals are short in tests; add an env kill-switch (`CHIO_LEDGER_AUDIT=0`) if suite time regresses measurably.
- The real store legitimately violates naive conservation (HA overrun bound: split-brain nodes may jointly over-approve up to `max_cost_per_invocation x node_count`, documented at `budget_store.rs:280-285`). Mitigation: the law is scoped to `SingleNodeAtomic` guarantee level in all four lanes; the HA relaxation is exactly the [FV-D3](FV-D3-economy-conservation.md) problem and is out of scope here, stated explicitly in the law text.
- Retained lease state and the retained projection of a monetary hold live in receipt metadata, while concrete monetary exposure remains queryable as outstanding store state. Mitigation: keep trusted `runtime_admission_metadata` separate from untrusted receipt metadata, assert the joined state in lane (c) and `drop_guard_disposition_table`, and require the signed receipt to carry locatable hold, payment, and reservation ids. Lane (d) is deliberately store-only and does not claim this cross-surface property.

## Resolved decisions

- No kernel-owned runtime-admission reservation table is added in this change. Runtime lease IDs remain metadata-backed and are checked at the kernel and receipt boundary; a first-class table would be a separate production design change.
- `ledger_apply` is an aggregate amount model for the Kani, Creusot, and Lean lane. Concrete journal replay and the store property retain per-hold IDs and terminal history where those identifiers exist. This split proves the arithmetic law without claiming a per-hold refinement.
- Aeneas production extraction does not include `ledger_apply` yet. That step is deferred until [FV-A2](FV-A2-aeneas-generated-equivalence.md) can provide generated equivalence evidence, avoiding another unwired extraction artifact.

## Manifest and registry updates

- `formal/MAPPING.md`: mapped entries for every lane: `ReservationConservation` (Apalache, shared with FV-B1), `verify_reservation_ledger_conservation` (Kani section; enforced by `check-mapping.sh`), a Lean cross-reference for `Chio.Proofs.ReservationLedger.*`, and runtime rows for lanes (c) and (d) plus the complementary production drop-guard test.
- `.kani/harnesses.toml`: one `[[harness]]` entry (`crate = "chio-kernel-core"`, `harness = "verify_reservation_ledger_conservation"`, `lane = "pr"`, `default_unwind = 8`, `timeout_secs = 1800`, notes citing this doc).
- `formal/rust-verification/creusot-contracts.toml`: append `formal/rust-verification/creusot-core::ledger_apply_conservation_contract` to `covered_symbols` and map it to `formal_aeneas::ledger_apply` in `contract_twin`.
- `formal/theorem-inventory.json`: new entries `theorem.budget.reservation_conservation` and `theorem.budget.reservation_terminal_unique` (`kind = "theorem"`, `status = "proved"`, `mapsTo = ["P1"]`, notes citing the four enforcement surfaces and the fix-commit family), mirroring the `theorem.budget.sibling_sum_soundness` entry shape.
- `formal/proof-manifest.toml`: add `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean` to `root_modules`; append a `notes` line stating the conservation law, its four lanes, and the implementation-linkage caveat that scalar admission is linked while ledger transitions are not. No `property_matrix` change (P1-P10 are fixed; the law slots under P1's budget clause via `mapsTo`).
- `formal/assumptions.toml`: no change (the law is structural plus ASSUME-SQLITE-ATOMICITY already covering per-row store writes).
