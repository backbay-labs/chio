import Lean.Elab.Tactic.Omega
import Chio.Proofs.SiblingSumBudget

/-!
# Reservation ledger conservation

This module mirrors
`crates/kernel/chio-kernel-core/src/formal_aeneas.rs::ledger_apply`.
The runtime-store correspondence remains test and audit evidence rather than a
proved refinement.
-/

namespace Chio.Proofs.ReservationLedger

def maxU64 : Nat := 2 ^ 64 - 1

structure Ledger where
  outstanding : Nat
  committed : Nat
  released : Nat
  retained : Nat
  deriving DecidableEq, Repr

def Ledger.total (state : Ledger) : Nat :=
  state.outstanding + state.committed + state.released + state.retained

def terminal (state : Ledger) : Prop :=
  state.outstanding = 0 ∧
    (state.committed ≠ 0 ∨ state.released ≠ 0 ∨ state.retained ≠ 0)

instance (state : Ledger) : Decidable (terminal state) := by
  unfold terminal
  infer_instance

def ledgerApply (state : Ledger) (op amount : Nat) : Ledger × Bool :=
  if state.total > maxU64 ∨ op > 3 ∨ (op = 0 ∧ terminal state) then
    (state, false)
  else if op = 0 then
    if state.total + amount ≤ maxU64 ∧ state.outstanding + amount ≤ maxU64 then
      ({ state with outstanding := state.outstanding + amount }, true)
    else
      (state, false)
  else if amount > state.outstanding then
    (state, false)
  else
    match op with
    | 1 =>
        if state.committed + amount ≤ maxU64 then
          ({ state with
              outstanding := state.outstanding - amount
              committed := state.committed + amount }, true)
        else (state, false)
    | 2 =>
        if state.released + amount ≤ maxU64 then
          ({ state with
              outstanding := state.outstanding - amount
              released := state.released + amount }, true)
        else (state, false)
    | 3 =>
        if state.retained + amount ≤ maxU64 then
          ({ state with
              outstanding := state.outstanding - amount
              retained := state.retained + amount }, true)
        else (state, false)
    | _ => (state, false)

theorem ledger_apply_invalid_unchanged
    (state : Ledger) (op amount : Nat)
    (invalid : (ledgerApply state op amount).2 = false) :
    (ledgerApply state op amount).1 = state := by
  by_cases htotal : state.total > maxU64
  · simp [ledgerApply, htotal]
  rcases op with _ | op
  · by_cases hterminal : terminal state <;>
      by_cases hbound :
        state.total + amount ≤ maxU64 ∧ state.outstanding + amount ≤ maxU64 <;>
      simp [ledgerApply, htotal, hterminal, hbound] at invalid ⊢
  rcases op with _ | op
  · by_cases hover : amount > state.outstanding <;>
      by_cases hbound : state.committed + amount ≤ maxU64 <;>
      simp [ledgerApply, htotal, hover, hbound] at invalid ⊢
  rcases op with _ | op
  · by_cases hover : amount > state.outstanding <;>
      by_cases hbound : state.released + amount ≤ maxU64 <;>
      simp [ledgerApply, htotal, hover, hbound] at invalid ⊢
  rcases op with _ | op
  · by_cases hover : amount > state.outstanding <;>
      by_cases hbound : state.retained + amount ≤ maxU64 <;>
      simp [ledgerApply, htotal, hover, hbound] at invalid ⊢
  · have hlarge : Nat.succ (Nat.succ (Nat.succ (Nat.succ op))) > 3 := by omega
    simp [ledgerApply, htotal, hlarge]

theorem ledger_apply_partition
    (state : Ledger) (op amount : Nat)
    (valid : (ledgerApply state op amount).2 = true) :
    (ledgerApply state op amount).1.total =
      state.total + if op = 0 then amount else 0 := by
  by_cases htotal : state.total > maxU64
  · simp [ledgerApply, htotal] at valid
  rcases op with _ | op
  · by_cases hterminal : terminal state <;>
      by_cases hbound :
        state.total + amount ≤ maxU64 ∧ state.outstanding + amount ≤ maxU64 <;>
      simp [ledgerApply, htotal, hterminal, hbound] at valid ⊢ <;>
      (unfold Ledger.total <;> simp <;> omega)
  rcases op with _ | op
  · by_cases hover : amount > state.outstanding <;>
      by_cases hbound : state.committed + amount ≤ maxU64 <;>
      simp [ledgerApply, htotal, hover, hbound] at valid ⊢ <;>
      (unfold Ledger.total <;> simp <;> omega)
  rcases op with _ | op
  · by_cases hover : amount > state.outstanding <;>
      by_cases hbound : state.released + amount ≤ maxU64 <;>
      simp [ledgerApply, htotal, hover, hbound] at valid ⊢ <;>
      (unfold Ledger.total <;> simp <;> omega)
  rcases op with _ | op
  · by_cases hover : amount > state.outstanding <;>
      by_cases hbound : state.retained + amount ≤ maxU64 <;>
      simp [ledgerApply, htotal, hover, hbound] at valid ⊢ <;>
      (unfold Ledger.total <;> simp <;> omega)
  · have hlarge : Nat.succ (Nat.succ (Nat.succ (Nat.succ op))) > 3 := by omega
    simp [ledgerApply, htotal, hlarge] at valid

theorem ledger_terminal_unique
    (state : Ledger) (op amount : Nat)
    (finalized : terminal state) :
    (ledgerApply state op amount).1 = state := by
  by_cases htotal : state.total > maxU64
  · simp [ledgerApply, htotal]
  rcases state with ⟨outstanding, committed, released, retained⟩
  unfold terminal at finalized
  rcases finalized with ⟨houtstanding, finalized⟩
  change outstanding = 0 at houtstanding
  change committed ≠ 0 ∨ released ≠ 0 ∨ retained ≠ 0 at finalized
  subst outstanding
  rcases op with _ | op
  · simp [ledgerApply, htotal, terminal, finalized]
  rcases op with _ | op
  · by_cases hover : amount > 0
    · simp [ledgerApply, htotal, hover]
    · have hzero : amount = 0 := by omega
      subst amount
      by_cases hbound : committed ≤ maxU64 <;>
        simp [ledgerApply, htotal, hbound]
  rcases op with _ | op
  · by_cases hover : amount > 0
    · simp [ledgerApply, htotal, hover]
    · have hzero : amount = 0 := by omega
      subst amount
      by_cases hbound : released ≤ maxU64 <;>
        simp [ledgerApply, htotal, hbound]
  rcases op with _ | op
  · by_cases hover : amount > 0
    · simp [ledgerApply, htotal, hover]
    · have hzero : amount = 0 := by omega
      subst amount
      by_cases hbound : retained ≤ maxU64 <;>
        simp [ledgerApply, htotal, hbound]
  · have hlarge : Nat.succ (Nat.succ (Nat.succ (Nat.succ op))) > 3 := by omega
    simp [ledgerApply, htotal, hlarge]

structure FoldState where
  ledger : Ledger
  admitted : Nat

def foldStep (state : FoldState) (input : Nat × Nat) : FoldState :=
  let result := ledgerApply state.ledger input.1 input.2
  { ledger := result.1
    admitted := state.admitted + if result.2 && input.1 == 0 then input.2 else 0 }

def initial : FoldState :=
  { ledger := { outstanding := 0, committed := 0, released := 0, retained := 0 }
    admitted := 0 }

theorem fold_step_conservation
    (state : FoldState) (input : Nat × Nat)
    (conserved : state.ledger.total = state.admitted) :
    (foldStep state input).ledger.total = (foldStep state input).admitted := by
  unfold foldStep
  generalize h_result : ledgerApply state.ledger input.1 input.2 = result
  cases result with
  | mk next valid =>
      cases valid
      · have unchanged := ledger_apply_invalid_unchanged state.ledger input.1 input.2
        simp [h_result] at unchanged
        simp [unchanged, conserved]
      · have partition := ledger_apply_partition state.ledger input.1 input.2
        simp [h_result] at partition
        simp [partition, conserved]

theorem fold_conservation_from
    (operations : List (Nat × Nat)) (state : FoldState)
    (conserved : state.ledger.total = state.admitted) :
    (operations.foldl foldStep state).ledger.total =
      (operations.foldl foldStep state).admitted := by
  induction operations generalizing state with
  | nil => exact conserved
  | cons input remaining induction_hypothesis =>
      simp only [List.foldl_cons]
      exact induction_hypothesis _ (fold_step_conservation state input conserved)

theorem ledger_conservation (operations : List (Nat × Nat)) :
    (operations.foldl foldStep initial).ledger.total =
      (operations.foldl foldStep initial).admitted := by
  exact fold_conservation_from operations initial rfl

theorem admitted_child_reserve_bounded
    (split : Chio.Proofs.SiblingSumBudget.BudgetSplit)
    (proposed : Nat)
    (admitted : Chio.Proofs.SiblingSumBudget.admitChild split proposed =
      Chio.Proofs.SiblingSumBudget.AdmitVerdict.admitted) :
    proposed ≤ split.parentShare - split.totalChild := by
  have sibling_bound :=
    Chio.Proofs.SiblingSumBudget.sibling_sum_soundness split proposed admitted
  omega

end Chio.Proofs.ReservationLedger
