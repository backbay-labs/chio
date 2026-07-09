# FV-B3: One budget conservation law, four enforcement lanes

Status: Proposed (2026-07-09)
Theme: B - Aim the formal tools at the actual bug generator
Effort: M
Depends on: [FV-B1](FV-B1-drop-guard-model.md) (lane a), [FV-A1](FV-A1-absorb-verified-helpers.md) phase 1 (lane b's production linkage)
Feeds: [FV-D3](FV-D3-economy-conservation.md), [FV-B4](FV-B4-loom-registry-and-dst.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G3, G2), [FV-A3](FV-A3-creusot-dedup.md), [FV-E4](FV-E4-fuzz-plumbing-repair.md)

## Summary

Every drop-guard fix in the recent family is, at bottom, a violation of one law: an admitted reservation must end in exactly one terminal ledger state, and the amounts must balance. This document states that law once (reserved equals committed plus released plus retained, at all times, including across child splits whose sibling sums are bounded by the parent) and enforces it in four lanes that fail differently: (a) an Apalache invariant over interleavings, (b) a pure verified transition function (Kani + Creusot + Lean) over amounts, (c) a debug-assertions audit inside the real kernel, and (d) a stateful proptest driving the real store. One law with four independent witnesses is worth more than four unrelated properties, because a drift in any lane is detected by disagreement with the others.

## Motivation and evidence

- `a6d26dbc4` (Finding A: invocation slot never reversed on pre-dispatch drop; Finding B: child budget share never released) and `c201afbd0` (aborted unwind paths left reservations unmarked) are conservation violations: value left in `reserved` forever. `84e98b9d0` and `58abf33d2` are misclassification violations: value moved to the wrong terminal state (`released` semantics where `retained` was required). A single ledger law covers all five [commit family verified via `git show --stat` this session].
- The verified budget helpers already in-tree stop short of a ledger. `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` has `budget_precheck` (line 68) and `budget_commit` (line 77) over bounded ints, modeled by Lean, Kani, and Creusot, but they express a single admit decision, not the reserve/settle/reverse/release lifecycle, and production does not call them (gap G2) [v].
- The Kani harness `verify_budget_checked_add_no_overflow` proves fail-closed no-partial-commit, Overflow-before-CapExceeded dispatch order, and retry idempotence for the `checked_add` ordering in `budget_store.rs`, in two phases (dense u8 bounds, then `current = u64::MAX - tail` to de-vacuate the overflow arm) [v]. That is the arithmetic floor this law builds on: FV-B3 adds the lifecycle dimension the overflow harness deliberately does not model.
- The child-split half already has a Lean anchor: `formal/lean4/Chio/Chio/Proofs/SiblingSumBudget.lean` proves `sibling_sum_soundness` (line 82) and `sibling_sum_after_admit_bounded` (line 97) over a `BudgetSplit`/`admitChild` model of `BudgetSplit::try_admit_child` (implementation at `crates/kernel/chio-kernel-core/src/budget_split.rs:184`). The law's clause 3 below composes with those theorems rather than restating them.

## Current state

The real ledger is spread across three surfaces (all verified by reading this session):

- Monetary store: `crates/kernel/chio-kernel/src/budget_store.rs`. `BudgetStore` trait (line 260) with `try_charge_cost` (line 286: atomically check limits and record provisional exposure), `reverse_charge_cost` (line 347: denial-path reversal), `reduce_charge_cost` (line 384: release exposure without realizing spend), `settle_charge_cost` (line 423: move exposure to realized spend, `realized <= exposed`), plus hold-level wrappers `authorize_budget_hold` / `reverse_budget_hold` / `release_budget_hold` / `reconcile_budget_hold` (lines 507-654). The mutation journal vocabulary is exactly the law's alphabet: `BudgetMutationKind` (lines 34-40) = `IncrementInvocation | AuthorizeExposure | ReverseExposure | ReleaseExposure | ReconcileSpend`, and `list_mutation_events` (line 484) exposes the journal. Per-record identity: `committed_cost_units = total_cost_exposed + total_cost_realized_spend`, checked-add guarded (line 664).
- Kernel transition points: `unwind_aborted_monetary_invocation` (`kernel/dispatch.rs:125-160`), `release_runtime_admission_reservations` (`kernel/dispatch.rs:393-404`), `mark_runtime_admission_reservations_retained_fail_closed` (`kernel/dispatch.rs:412-452`), `release_runtime_admission_reservations_for_pre_dispatch_denial` (`kernel/dispatch.rs:454-483`), `release_admitted_capability_budget` (`kernel/validation.rs:324`), `reverse_pre_execution_budget_mutation` (`kernel/validation.rs:862`), and the drop-guard branches that orchestrate them (`kernel/kernel_drop_guard.rs:139-229` pre-dispatch, `299-358` drop dispatch). Runtime-admission lease state itself lives behind the `RuntimeAdmissionHook` trait (`kernel/mod.rs:87`) and is tracked via receipt metadata (`reserved_*` / `retained_*` ids), not a kernel-owned table; the law's lease clause is therefore stated over the metadata transitions the kernel controls.
- Existing tests: `tests/property_budget_store.rs` (referenced in `crates/kernel/chio-kernel/Cargo.toml` dev-dependency comments, lines 85-87) covers store arithmetic; `kernel/tests/drop_guard_proptest.rs:42` covers the 8-cell disposition table but asserts receipts and release counts, not ledger balance.

No artifact today states the four-way partition law, and nothing checks it across an arbitrary operation sequence.

## Design

### The law

For every admission `a` with reserved amount `R(a)`:

1. Partition: at every reachable state, `R(a) = committed(a) + released(a) + retained(a) + outstanding(a)`, with `outstanding(a) >= 0`, where committed = settled/realized spend (`ReconcileSpend`), released = reversed or reduced exposure (`ReverseExposure` + `ReleaseExposure`), retained = deliberately-not-unwound value on abort classes, outstanding = still-reserved exposure.
2. Terminal uniqueness: when the invocation that owns `a` is terminal, `outstanding(a) = 0` and the disposition history for `a` contains exactly one terminal classification (a hold is not both reversed and settled; a lease is not both released and retained).
3. Child splits: for a parent with share `P`, the sum of admitted child shares never exceeds `P` (this is `sibling_sum_soundness` / `sibling_sum_after_admit_bounded` in `SiblingSumBudget.lean`), and each child's own ledger obeys clauses 1-2 independently.

Mapping from the law's alphabet to the store's journal vocabulary (`BudgetMutationKind`, `budget_store.rs:34-40`) and to the kernel transition points; this table is the normative join and lives verbatim in the `budget_store.rs` doc comment:

| Law term | Store journal event | Kernel transition point |
| --- | --- | --- |
| reserve `R(a)` | `AuthorizeExposure` (+ `IncrementInvocation` for the slot) | admission via `authorize_budget_hold` / `try_charge_cost` |
| commit | `ReconcileSpend` (exposed -> realized, `realized <= exposed`) | normal finalize with reported cost |
| release | `ReverseExposure` (denial/unwind) or `ReleaseExposure` (reduce without spend) | `unwind_aborted_monetary_invocation` (`dispatch.rs:125`), `reverse_pre_execution_budget_mutation` (`validation.rs:862`), `release_admitted_capability_budget` (`validation.rs:324`) |
| retain | no journal event; receipt-metadata marking | `mark_runtime_admission_reservations_retained_fail_closed` (`dispatch.rs:412`) on the abort classes |

The empty journal cell in the retain row is itself a finding this law surfaces: retention is currently observable only via receipt metadata, which is why clause 2's lease half is enforced at the kernel and receipt layers (lanes c and d) rather than the store layer. See Open questions.

### Lane (a): Apalache interleaving lane

`ReservationConservation` in [FV-B1](FV-B1-drop-guard-model.md) is the quiescence form. This lane strengthens it in the same spec: promote the per-resource status ledger to a small counted ledger (amounts in `0..BudgetMax`, `BudgetMax = 4`) and assert the partition equation at EVERY state, not just terminals. Amounts stay tiny because lane (b) owns arithmetic; this lane owns interleavings (a drop between reserve and commit, two invocations sharing the child split). Falsifiability via the FV-B2 variants `DropGuardSkipChildBudgetReleaseBroken` and `DropGuardSkipInvocationReversalBroken`.

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

- Kani: `verify_reservation_ledger_conservation` in `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`, proving over a bounded op sequence (length ~6, dense small amounts, plus an adversarial `u64::MAX - tail` phase copying the two-phase pattern of `verify_budget_checked_add_no_overflow` [v]) that: total is invariant (`reserved + committed + released + retained` never changes except by Reserve), no field underflows/overflows, invalid ops are exact no-ops, and terminal uniqueness holds when driven by a disposition tag. Sketch:

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
- Creusot: `ledger_apply_conservation_contract` in `formal/rust-verification/creusot-core/`, registered in `formal/rust-verification/creusot-contracts.toml` `covered_symbols` (pattern verified: that file already lists `budget_commit_remaining_contract`).
- Lean: new module `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean` (one file per law, following the `SiblingSumBudget.lean` precedent) with `ledger_apply` mirrored, `theorem ledger_conservation` (fold of valid ops preserves the partition sum) and `theorem ledger_terminal_unique`, plus a lemma importing `Chio.Proofs.SiblingSumBudget.sibling_sum_soundness` to state clause 3 as: an admitted child's `Reserve` is bounded by the parent's outstanding share. Same `status = "assumed"` caveat as SiblingSumBudget while the Lean toolchain is CI-unavailable (stated in that file's header, lines 19-21).

G2 honesty clause: like `budget_precheck`/`budget_commit`, `ledger_apply` starts life uncalled by production. Its production linkage is [FV-A1](FV-A1-absorb-verified-helpers.md) phase 1 territory (absorb verified helpers into the call path); until that lands, lanes (c) and (d) are the anti-drift binding between this model and the real store, and the MAPPING.md row must say "model-level; production linkage tracked by FV-A1" rather than implying refinement.

### Lane (c): debug-assertions conservation audit in the real kernel

New module `crates/kernel/chio-kernel/src/kernel/ledger_audit.rs`, compiled under `#[cfg(debug_assertions)]` (zero release cost), exposing `debug_assert_reservation_conservation(kernel_or_store, capability_id, grant_index)`. It replays `list_mutation_events` (`budget_store.rs:484`) for the (capability, grant) pair and asserts (1) the fold of `BudgetMutationKind` deltas reproduces the stored `total_cost_exposed` / `total_cost_realized_spend` (journal-state agreement), and (2) exposure never goes negative mid-fold (no release/reverse of value never reserved).

Call sites (the exact transition points, all verified this session):

- End of `PostAdmissionDropGuard::drop`, both branches (`kernel/kernel_drop_guard.rs:299-358`).
- After `unwind_aborted_monetary_invocation` returns in the deny/unwind paths (`kernel/dispatch.rs:125-160` callee; call sites in `kernel_drop_guard.rs:106` and `:144`).
- After `reverse_pre_execution_budget_mutation` (`kernel/validation.rs:862`) and `release_admitted_capability_budget` (`kernel/validation.rs:324`).
- After the retained-marking finalize arms (`kernel/responses/finalization.rs:48-50` and `:82-84`, `kernel/validation.rs:1150`), asserting the marking-iff-retention half of clause 2 at the metadata level.

Backends without a journal (`list_mutation_events` defaults to an `Invariant` error, `budget_store.rs:489-493`) make the audit a no-op with a debug log, never a panic on missing capability: the audit must not convert an unsupported backend into a crash (fail-closed applies to access decisions, not to diagnostics).

### Lane (d): stateful proptest on the real store

New test `crates/kernel/chio-kernel/tests/property_reservation_ledger.rs` (sibling of the existing `tests/property_budget_store.rs`): a proptest strategy generates arbitrary sequences over `{authorize hold, reverse, release, settle, pre-dispatch drop, post-dispatch drop, complete-ok, deny-post-invocation, incomplete-stream}` against a real kernel with `InMemoryBudgetStore` and a counting `RuntimeAdmissionHook` (constructor pattern from `kernel/tests/drop_guard_proptest.rs:102-117`), then asserts the law from the journal plus the receipt log after every step. Follow-on option: promote the operation-sequence interpreter to `fuzz/fuzz_targets/reservation_ledger_ops.rs` (the fuzz tree exists with 25 targets, listed this session); mechanics, corpus metadata, and plumbing repairs are deferred to the [FV-E4](FV-E4-fuzz-plumbing-repair.md) checklist to avoid inheriting the known G6 leaks here.

## Implementation plan

1. Phase 1 - law text and lane (d). Add the law statement as a doc comment in `budget_store.rs` (single normative location in code) and land `tests/property_reservation_ledger.rs`. No dependencies; catches real regressions immediately.
2. Phase 2 - lane (c). Add `kernel/ledger_audit.rs` plus the call sites listed above; wire `mod ledger_audit;` in `kernel/mod.rs`. Debug-only; run the full kernel test suite to shake out latent violations before any other lane exists (this is where surprises will surface).
3. Phase 3 - lane (b). Add `ledger_apply` to `formal_aeneas.rs`, the Kani harness to `kani_public_harnesses.rs`, the Creusot contract to `formal/rust-verification/creusot-core/`, and `Proofs/ReservationLedger.lean`. Registry rows per the manifest section below.
4. Phase 4 - lane (a). Strengthen the FV-B1 spec's ledger to counted amounts and the every-state partition equation; add/adjust the FV-B2 negative variants that falsify it.
5. Phase 5 - optional fuzz promotion via the FV-E4 checklist.

## CI and gating changes

- Lane (b) rides existing lanes automatically: the Kani harness joins the `kani-public-pr` sweep via a `[[harness]]` row in `.kani/harnesses.toml` (`lane = "pr"`, `default_unwind` sized to the op-sequence length); the Creusot contract joins the strict lanes via `creusot-contracts.toml`; no workflow edits (the manifest-driven design was built for this, `.kani/harnesses.toml` header lines 24-28).
- Lane (c) rides every `cargo test` (debug builds) and therefore the standard PR gate; no new job.
- Lane (d) joins the proptest tiers: default cases on PR, elevated cases in the existing `proptest-nightly` job in `.github/workflows/nightly.yml` (job verified this session); shrunk regressions committed under `proptest-regressions/` per the counterexample template flow [v].
- Lane (a) rides `apalache-safety.yml` via FV-B1's matrix row; no additional job.

## Acceptance criteria

- [ ] The law is stated verbatim (clauses 1-3) in exactly four enforcement artifacts: `PostAdmissionDropGuard.tla`, `formal_aeneas.rs::ledger_apply` (+ Kani + Creusot + Lean witnesses), `kernel/ledger_audit.rs`, `tests/property_reservation_ledger.rs`, each cross-referencing the others by path.
- [ ] `formal/MAPPING.md` has one row per artifact, and the rows name each other in the description column (the four-lane join is greppable).
- [ ] Kani harness green in the manifest sweep; Creusot contract green in the strict lane; Lean module builds when the toolchain is available and is registered `assumed` until then.
- [ ] Lane (c) call sites cover all six transition-point groups listed above; a deliberate ledger bug (e.g. commenting out the child-budget release, reproducing `a6d26dbc4` Finding B) trips lane (c) or lane (d) in a documented dry run.
- [ ] Lane (d) survives 10k mixed-sequence cases locally and the nightly case count in CI.
- [ ] The G2 caveat ("model-level until FV-A1") appears in the MAPPING rows and the proof-manifest note; no doc claims refinement.

## Risks and mitigations

- Lane semantics drift apart (the Apalache ledger, the pure ledger, and the store journal disagree on what "released" means). Mitigation: the law text is written once in `budget_store.rs` with the `BudgetMutationKind` mapping table, and every other artifact quotes it by path; [FV-A4](FV-A4-mirror-drift-hashes.md) hashes can pin the quartet later.
- Lane (c) audit cost distorts debug-profile test time (journal replay per transition). Mitigation: replay is per (capability, grant) and journals are short in tests; add an env kill-switch (`CHIO_LEDGER_AUDIT=0`) if suite time regresses measurably.
- The real store legitimately violates naive conservation (HA overrun bound: split-brain nodes may jointly over-approve up to `max_cost_per_invocation x node_count`, documented at `budget_store.rs:280-285`). Mitigation: the law is scoped to `SingleNodeAtomic` guarantee level in all four lanes; the HA relaxation is exactly the [FV-D3](FV-D3-economy-conservation.md) problem and is out of scope here, stated explicitly in the law text.
- Retained lease state lives in receipt metadata, not a queryable table, so clause 2's lease half is weaker than the monetary half. Mitigation: assert it where the kernel controls it (marking calls, lane c) and at the receipt level (lane d reads the receipt log); a first-class reservation table is an open question below.

## Open questions

- Should the runtime-admission lease get a kernel-owned reservation table (making clause 2 fully checkable) instead of metadata-carried ids? That is a production refactor beyond formal scope; if [FV-C1](FV-C1-receipt-trace-validation.md) receipt-trace validation lands first, the receipt log may be a sufficient oracle.
- Does `ledger_apply` model per-hold granularity (hold ids) or aggregate amounts? Proposal: aggregate for the Kani/Lean lane (bounded, sufficient for conservation), per-hold in lanes (c)/(d) where hold ids exist (`hold_id` threading verified in `budget_store.rs` request structs).
- Whether the Aeneas production extraction (`formal/aeneas/production.toml`) should include `ledger_apply` immediately or wait for [FV-A2](FV-A2-aeneas-generated-equivalence.md) equivalence tooling; leaning wait, to avoid another unwired extraction artifact (G2 again).

## Manifest and registry updates

- `formal/MAPPING.md`: four new rows (one per lane): `ReservationConservation` (Apalache, shared with FV-B1), `verify_reservation_ledger_conservation` (Kani section; `check-mapping.sh` will enforce this row automatically once the `#[kani::proof]` lands, since the script extracts harness names from `kani_public_harnesses.rs`), a Lean cross-reference bullet for `Chio.Proofs.ReservationLedger.*`, and an informational row for the lane (c)/(d) runtime artifacts.
- `.kani/harnesses.toml`: one `[[harness]]` entry (`crate = "chio-kernel-core"`, `harness = "verify_reservation_ledger_conservation"`, `lane = "pr"`, `default_unwind` = op-sequence bound + 1, `timeout_secs = 1800`, notes citing this doc).
- `formal/rust-verification/creusot-contracts.toml`: append `formal/rust-verification/creusot-core::ledger_apply_conservation_contract` to `covered_symbols`.
- `formal/theorem-inventory.json`: new entries `theorem.budget.reservation_conservation` and `theorem.budget.reservation_terminal_unique` (`kind = "theorem"`, `status = "assumed"` until Lean CI exists, `mapsTo = ["P1"]`, notes citing the four lanes and the fix-commit family), mirroring the `theorem.budget.sibling_sum_soundness` entry shape (verified at `formal/theorem-inventory.json:753`).
- `formal/proof-manifest.toml`: add `formal/lean4/Chio/Chio/Proofs/ReservationLedger.lean` to `root_modules`; append a `notes` line stating the conservation law, its four lanes, and the G2/FV-A1 linkage caveat. No `property_matrix` change (P1-P10 are fixed; the law slots under P1's budget clause via `mapsTo`).
- `formal/assumptions.toml`: no change (the law is structural plus ASSUME-SQLITE-ATOMICITY already covering per-row store writes).
