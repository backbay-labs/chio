import Chio.Proofs.AeneasEquivalence
import Chio.Proofs.ReservationLedger
import Chio.Core.MerkleWalk
import FormalAeneas.Funs

set_option autoImplicit false

namespace Chio.Proofs

open Aeneas Aeneas.Std Result
open Chio.Core

private def mapResult {A B : Type} (function : A -> B) : Result A -> Result B
  | ok value => ok (function value)
  | fail error => fail error
  | div => div

private def generatedBudgetCommitToModel
    (result : Chio.AeneasProduction.BudgetCommitResult) : Option BudgetState :=
  if result.accepted then
    some {
      remainingInvocations := result.remaining_invocations.val,
      remainingUnits := result.remaining_units.val,
    }
  else
    none

private def generatedLedgerToModel
    (state : Chio.AeneasProduction.ReservationLedger) :
    Chio.Proofs.ReservationLedger.Ledger := {
  outstanding := state.reserved.val,
  committed := state.committed.val,
  released := state.released.val,
  retained := state.retained.val,
}

private def generatedLedgerResultToModel
    (result : Chio.AeneasProduction.ReservationLedger × Bool) :
    Chio.Proofs.ReservationLedger.Ledger × Bool :=
  (generatedLedgerToModel result.1, result.2)

private def generatedInclusionStepToModel
    (step : Chio.AeneasProduction.InclusionStep) : StepDecision := {
  consumeSibling := step.consume_sibling
  siblingOnLeft := step.sibling_on_left
  nextIndex := step.next_index.val
  nextSize := step.next_size.val
}

private theorem uscalar_eq_iff_val_eq {scalarType : UScalarTy}
    (left right : UScalar scalarType) :
    left = right ↔ left.val = right.val := by
  constructor
  · exact UScalar.val_eq_of_eq
  · exact UScalar.eq_of_val_eq

#print axioms uscalar_eq_iff_val_eq

private theorem u64_saturating_add_val (left right : U64) :
    (core.num.U64.saturating_add left right).val =
      AeneasMirror.saturatingAdd U64.max left.val right.val := by
  simp only [core.num.U64.saturating_add, UScalar.saturating_add,
    UScalar.val, BitVec.toNat_ofNat, AeneasMirror.saturatingAdd,
    UScalar.max_UScalarTy_U64_eq]
  apply Nat.mod_eq_of_lt
  exact lt_of_le_of_lt (Nat.min_le_left _ _)
    (by rw [U64.max_eq]; norm_num)

#print axioms u64_saturating_add_val

private theorem u64_sub_result (left right : U64)
    (fits : right.val <= left.val) :
    Exists fun difference : U64 =>
      left - right = ok difference ∧
      difference.val = left.val - right.val := by
  have specification := U64.sub_bv_spec fits
  cases resultEq : left - right with
  | ok difference =>
      refine ⟨difference, rfl, ?_⟩
      simp only [WP.spec, WP.theta, WP.wp_return, resultEq] at specification
      exact specification.1
  | fail error =>
      simp [WP.spec, WP.theta, resultEq] at specification
  | div =>
      simp [WP.spec, WP.theta, resultEq] at specification

#print axioms u64_sub_result

private theorem u64_checked_add_some (left right sum : U64)
    (resultEq : U64.checked_add left right = some sum) :
    left.val + right.val <= U64.max ∧
      sum.val = left.val + right.val := by
  have specification := U64.checked_add_bv_spec left right
  rw [resultEq] at specification
  exact ⟨specification.1, specification.2.1⟩

#print axioms u64_checked_add_some

private theorem u64_checked_add_none (left right : U64)
    (resultEq : U64.checked_add left right = none) :
    U64.max < left.val + right.val := by
  have specification := U64.checked_add_bv_spec left right
  simpa [resultEq] using specification

#print axioms u64_checked_add_none

private theorem u64_rem_result (value divisor : U64)
    (nonzero : divisor.val ≠ 0) :
    Exists fun remainder : U64 =>
      value % divisor = ok remainder ∧
      remainder.val = value.val % divisor.val := by
  have specification := U64.rem_spec value nonzero
  cases resultEq : value % divisor with
  | ok remainder =>
      refine Exists.intro remainder (And.intro rfl ?_)
      simpa [WP.spec, WP.theta, resultEq] using specification
  | fail error =>
      simp [WP.spec, WP.theta, resultEq] at specification
  | div =>
      simp [WP.spec, WP.theta, resultEq] at specification

#print axioms u64_rem_result

private theorem u64_div_result (value divisor : U64)
    (nonzero : divisor.val ≠ 0) :
    Exists fun quotient : U64 =>
      value / divisor = ok quotient ∧
      quotient.val = value.val / divisor.val := by
  have specification := U64.div_spec value nonzero
  cases resultEq : value / divisor with
  | ok quotient =>
      refine Exists.intro quotient (And.intro rfl ?_)
      simpa [WP.spec, WP.theta, resultEq] using specification
  | fail error =>
      simp [WP.spec, WP.theta, resultEq] at specification
  | div =>
      simp [WP.spec, WP.theta, resultEq] at specification

#print axioms u64_div_result

private theorem u64_add_result (left right : U64)
    (fits : left.val + right.val <= U64.max) :
    Exists fun sum : U64 =>
      left + right = ok sum ∧
      sum.val = left.val + right.val := by
  have specification := U64.add_spec fits
  cases resultEq : left + right with
  | ok sum =>
      refine Exists.intro sum (And.intro rfl ?_)
      simpa [WP.spec, WP.theta, resultEq] using specification
  | fail error =>
      simp [WP.spec, WP.theta, resultEq] at specification
  | div =>
      simp [WP.spec, WP.theta, resultEq] at specification

#print axioms u64_add_result

private theorem reservation_ledger_max_eq :
    Chio.Proofs.ReservationLedger.maxU64 = U64.max := by
  rw [Chio.Proofs.ReservationLedger.maxU64, U64.max_eq]

#print axioms reservation_ledger_max_eq

theorem generated_ledger_is_terminal_eq_model
    (state : Chio.AeneasProduction.ReservationLedger) :
    Chio.AeneasProduction.ledger_is_terminal state =
      ok (decide (Chio.Proofs.ReservationLedger.terminal
        (generatedLedgerToModel state))) := by
  cases state with
  | mk reserved committed released retained =>
    by_cases reservedZero : reserved.val = 0
    · by_cases committedZero : committed.val = 0
      · by_cases releasedZero : released.val = 0
        · by_cases retainedZero : retained.val = 0 <;>
            simp [Chio.AeneasProduction.ledger_is_terminal,
              generatedLedgerToModel, Chio.Proofs.ReservationLedger.terminal,
              uscalar_eq_iff_val_eq, reservedZero, committedZero, releasedZero,
              retainedZero]
        · simp [Chio.AeneasProduction.ledger_is_terminal,
            generatedLedgerToModel, Chio.Proofs.ReservationLedger.terminal,
            uscalar_eq_iff_val_eq, reservedZero, committedZero, releasedZero]
      · simp [Chio.AeneasProduction.ledger_is_terminal,
          generatedLedgerToModel, Chio.Proofs.ReservationLedger.terminal,
          uscalar_eq_iff_val_eq, reservedZero, committedZero]
    · simp [Chio.AeneasProduction.ledger_is_terminal,
        generatedLedgerToModel, Chio.Proofs.ReservationLedger.terminal,
        reservedZero]

#print axioms generated_ledger_is_terminal_eq_model

theorem generated_ledger_apply_eq_model
    (state : Chio.AeneasProduction.ReservationLedger)
    (op : U8)
    (amount : U64) :
    mapResult generatedLedgerResultToModel
        (Chio.AeneasProduction.ledger_apply state op amount) =
      ok (Chio.Proofs.ReservationLedger.ledgerApply
        (generatedLedgerToModel state) op.val amount.val) := by
  cases state with
  | mk reserved committed released retained =>
    cases firstEq : U64.checked_add reserved committed with
    | none =>
      have overflow := u64_checked_add_none reserved committed firstEq
      have totalOverflow :
          Chio.Proofs.ReservationLedger.maxU64 <
            reserved.val + committed.val + released.val + retained.val := by
        rw [reservation_ledger_max_eq]
        omega
      simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
        generatedLedgerResultToModel, generatedLedgerToModel, mapResult,
        Chio.Proofs.ReservationLedger.ledgerApply,
        Chio.Proofs.ReservationLedger.Ledger.total, totalOverflow]
    | some total =>
      obtain ⟨firstBound, firstVal⟩ :=
        u64_checked_add_some reserved committed total firstEq
      cases secondEq : U64.checked_add total released with
      | none =>
        have overflow := u64_checked_add_none total released secondEq
        have totalOverflow :
            Chio.Proofs.ReservationLedger.maxU64 <
              reserved.val + committed.val + released.val + retained.val := by
          rw [reservation_ledger_max_eq]
          omega
        simp [Chio.AeneasProduction.ledger_apply, lift, firstEq, secondEq,
          generatedLedgerResultToModel, generatedLedgerToModel, mapResult,
          Chio.Proofs.ReservationLedger.ledgerApply,
          Chio.Proofs.ReservationLedger.Ledger.total, totalOverflow]
      | some totalWithReleased =>
        obtain ⟨secondBound, secondVal⟩ :=
          u64_checked_add_some total released totalWithReleased secondEq
        cases thirdEq : U64.checked_add totalWithReleased retained with
        | none =>
          have overflow := u64_checked_add_none totalWithReleased retained thirdEq
          have totalOverflow :
              Chio.Proofs.ReservationLedger.maxU64 <
                reserved.val + committed.val + released.val + retained.val := by
            rw [reservation_ledger_max_eq]
            omega
          simp [Chio.AeneasProduction.ledger_apply, lift, firstEq, secondEq,
            thirdEq, generatedLedgerResultToModel, generatedLedgerToModel,
            mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
            Chio.Proofs.ReservationLedger.Ledger.total, totalOverflow]
        | some totalWithRetained =>
          obtain ⟨thirdBound, thirdVal⟩ :=
            u64_checked_add_some totalWithReleased retained totalWithRetained thirdEq
          have totalBound :
              reserved.val + committed.val + released.val + retained.val <=
                Chio.Proofs.ReservationLedger.maxU64 := by
            rw [reservation_ledger_max_eq]
            omega
          have totalNotOverflow :
              ¬Chio.Proofs.ReservationLedger.maxU64 <
                reserved.val + committed.val + released.val + retained.val := by
            omega
          by_cases opLarge : 3 < op.val
          · simp [Chio.AeneasProduction.ledger_apply, lift, firstEq, secondEq,
              thirdEq, generatedLedgerResultToModel, generatedLedgerToModel,
              mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
              Chio.Proofs.ReservationLedger.Ledger.total, totalNotOverflow,
              opLarge]
          · by_cases opZero : op.val = 0
            · have terminalEq := generated_ledger_is_terminal_eq_model
                ({ reserved, committed, released, retained } :
                  Chio.AeneasProduction.ReservationLedger)
              by_cases terminalState : Chio.Proofs.ReservationLedger.terminal
                  ({
                    outstanding := reserved.val,
                    committed := committed.val,
                    released := released.val,
                    retained := retained.val,
                  } : Chio.Proofs.ReservationLedger.Ledger)
              · simp only [generatedLedgerToModel] at terminalEq
                rw [show decide (Chio.Proofs.ReservationLedger.terminal
                    ({
                      outstanding := reserved.val,
                      committed := committed.val,
                      released := released.val,
                      retained := retained.val,
                    } : Chio.Proofs.ReservationLedger.Ledger)) = true by
                    simp [terminalState]] at terminalEq
                simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                  secondEq, thirdEq, terminalEq, generatedLedgerResultToModel,
                  generatedLedgerToModel, mapResult,
                  Chio.Proofs.ReservationLedger.ledgerApply,
                  Chio.Proofs.ReservationLedger.Ledger.total, totalNotOverflow,
                  opZero, terminalState, uscalar_eq_iff_val_eq]
              · simp only [generatedLedgerToModel] at terminalEq
                rw [show decide (Chio.Proofs.ReservationLedger.terminal
                    ({
                      outstanding := reserved.val,
                      committed := committed.val,
                      released := released.val,
                      retained := retained.val,
                    } : Chio.Proofs.ReservationLedger.Ledger)) = false by
                    simp [terminalState]] at terminalEq
                cases aggregateEq : U64.checked_add totalWithRetained amount with
                | none =>
                  have aggregateOverflow :=
                    u64_checked_add_none totalWithRetained amount aggregateEq
                  have aggregateTooLarge :
                      Chio.Proofs.ReservationLedger.maxU64 <
                        reserved.val + committed.val + released.val + retained.val +
                          amount.val := by
                    rw [reservation_ledger_max_eq]
                    omega
                  simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                    secondEq, thirdEq, aggregateEq, terminalEq,
                    generatedLedgerResultToModel, generatedLedgerToModel,
                    mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
                    Chio.Proofs.ReservationLedger.Ledger.total, totalNotOverflow,
                    aggregateTooLarge, opZero, terminalState,
                    uscalar_eq_iff_val_eq]
                | some aggregate =>
                  obtain ⟨aggregateBound, aggregateVal⟩ :=
                    u64_checked_add_some totalWithRetained amount aggregate aggregateEq
                  have aggregateModelBound :
                      reserved.val + committed.val + released.val + retained.val +
                          amount.val <= Chio.Proofs.ReservationLedger.maxU64 := by
                    rw [reservation_ledger_max_eq]
                    omega
                  cases reserveEq : U64.checked_add reserved amount with
                  | none =>
                    have reserveOverflow := u64_checked_add_none reserved amount reserveEq
                    have reserveModelOverflow :
                        Chio.Proofs.ReservationLedger.maxU64 <
                          reserved.val + amount.val := by
                      rw [reservation_ledger_max_eq]
                      exact reserveOverflow
                    omega
                  | some nextReserved =>
                    obtain ⟨reserveBound, reserveVal⟩ :=
                      u64_checked_add_some reserved amount nextReserved reserveEq
                    have reserveModelBound :
                        reserved.val + amount.val <=
                          Chio.Proofs.ReservationLedger.maxU64 := by
                      rw [reservation_ledger_max_eq]
                      exact reserveBound
                    simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                      secondEq, thirdEq, aggregateEq, reserveEq, terminalEq,
                      generatedLedgerResultToModel, generatedLedgerToModel,
                      mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
                      Chio.Proofs.ReservationLedger.Ledger.total,
                      totalNotOverflow,
                      aggregateModelBound, reserveModelBound,
                      reserveVal, opZero, terminalState,
                      uscalar_eq_iff_val_eq]
            · by_cases overDisposition : reserved.val < amount.val
              · simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                  secondEq, thirdEq, generatedLedgerResultToModel,
                  generatedLedgerToModel, mapResult,
                  Chio.Proofs.ReservationLedger.ledgerApply,
                  Chio.Proofs.ReservationLedger.Ledger.total, totalNotOverflow,
                  opLarge, opZero, overDisposition]
              · have amountFits : amount.val <= reserved.val := by omega
                obtain ⟨outstanding, outstandingEq, outstandingVal⟩ :=
                  u64_sub_result reserved amount amountFits
                by_cases opOne : op.val = 1
                · have opScalar : op = 1#u8 := by
                    apply UScalar.eq_of_val_eq
                    simpa using opOne
                  cases destinationEq : U64.checked_add committed amount with
                  | none =>
                    have destinationOverflow :=
                      u64_checked_add_none committed amount destinationEq
                    have destinationModelOverflow :
                        Chio.Proofs.ReservationLedger.maxU64 <
                          committed.val + amount.val := by
                      rw [reservation_ledger_max_eq]
                      exact destinationOverflow
                    have destinationModelDoesNotFit :
                        ¬committed.val + amount.val <=
                          Chio.Proofs.ReservationLedger.maxU64 := by
                      omega
                    simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                      secondEq, thirdEq, destinationEq, outstandingEq,
                      generatedLedgerResultToModel, generatedLedgerToModel,
                      mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
                      Chio.Proofs.ReservationLedger.Ledger.total,
                      totalNotOverflow,
                      opScalar, overDisposition,
                      destinationModelDoesNotFit]
                    rfl
                  | some nextCommitted =>
                    obtain ⟨destinationBound, destinationVal⟩ :=
                      u64_checked_add_some committed amount nextCommitted destinationEq
                    have destinationModelBound :
                        committed.val + amount.val <=
                          Chio.Proofs.ReservationLedger.maxU64 := by
                      rw [reservation_ledger_max_eq]
                      exact destinationBound
                    simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                      secondEq, thirdEq, destinationEq, outstandingEq,
                      generatedLedgerResultToModel,
                      generatedLedgerToModel, mapResult,
                      Chio.Proofs.ReservationLedger.ledgerApply,
                      Chio.Proofs.ReservationLedger.Ledger.total,
                      totalNotOverflow,
                      opScalar, overDisposition,
                      destinationModelBound]
                    rw [← outstandingVal, ← destinationVal]
                    rfl
                · by_cases opTwo : op.val = 2
                  · have opScalar : op = 2#u8 := by
                      apply UScalar.eq_of_val_eq
                      simpa using opTwo
                    cases destinationEq : U64.checked_add released amount with
                    | none =>
                      have destinationOverflow :=
                        u64_checked_add_none released amount destinationEq
                      have destinationModelOverflow :
                          Chio.Proofs.ReservationLedger.maxU64 <
                            released.val + amount.val := by
                        rw [reservation_ledger_max_eq]
                        exact destinationOverflow
                      have destinationModelDoesNotFit :
                          ¬released.val + amount.val <=
                            Chio.Proofs.ReservationLedger.maxU64 := by
                        omega
                      simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                        secondEq, thirdEq, destinationEq, outstandingEq,
                        generatedLedgerResultToModel, generatedLedgerToModel,
                        mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
                        Chio.Proofs.ReservationLedger.Ledger.total,
                        totalNotOverflow,
                        opScalar,
                        overDisposition, destinationModelDoesNotFit]
                      rfl
                    | some nextReleased =>
                      obtain ⟨destinationBound, destinationVal⟩ :=
                        u64_checked_add_some released amount nextReleased destinationEq
                      have destinationModelBound :
                          released.val + amount.val <=
                            Chio.Proofs.ReservationLedger.maxU64 := by
                        rw [reservation_ledger_max_eq]
                        exact destinationBound
                      simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                        secondEq, thirdEq, destinationEq, outstandingEq,
                        generatedLedgerResultToModel, generatedLedgerToModel,
                        mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
                        Chio.Proofs.ReservationLedger.Ledger.total,
                        totalNotOverflow,
                        opScalar,
                        overDisposition, destinationModelBound]
                      rw [← outstandingVal, ← destinationVal]
                      rfl
                  · have opThree : op.val = 3 := by omega
                    have opScalar : op = 3#u8 := by
                      apply UScalar.eq_of_val_eq
                      simpa using opThree
                    cases destinationEq : U64.checked_add retained amount with
                    | none =>
                      have destinationOverflow :=
                        u64_checked_add_none retained amount destinationEq
                      have destinationModelOverflow :
                          Chio.Proofs.ReservationLedger.maxU64 <
                            retained.val + amount.val := by
                        rw [reservation_ledger_max_eq]
                        exact destinationOverflow
                      have destinationModelDoesNotFit :
                          ¬retained.val + amount.val <=
                            Chio.Proofs.ReservationLedger.maxU64 := by
                        omega
                      simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                        secondEq, thirdEq, destinationEq, outstandingEq,
                        generatedLedgerResultToModel, generatedLedgerToModel,
                        mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
                        Chio.Proofs.ReservationLedger.Ledger.total,
                        totalNotOverflow,
                        opScalar,
                        overDisposition, destinationModelDoesNotFit]
                      rfl
                    | some nextRetained =>
                      obtain ⟨destinationBound, destinationVal⟩ :=
                        u64_checked_add_some retained amount nextRetained destinationEq
                      have destinationModelBound :
                          retained.val + amount.val <=
                            Chio.Proofs.ReservationLedger.maxU64 := by
                        rw [reservation_ledger_max_eq]
                        exact destinationBound
                      simp [Chio.AeneasProduction.ledger_apply, lift, firstEq,
                        secondEq, thirdEq, destinationEq, outstandingEq,
                        generatedLedgerResultToModel, generatedLedgerToModel,
                        mapResult, Chio.Proofs.ReservationLedger.ledgerApply,
                        Chio.Proofs.ReservationLedger.Ledger.total,
                        totalNotOverflow,
                        opScalar,
                        overDisposition, destinationModelBound]
                      rw [← outstandingVal, ← destinationVal]
                      rfl

#print axioms generated_ledger_apply_eq_model

theorem generated_classify_time_window_code_eq_mirror
    (now issuedAt expiresAt : U64) :
    mapResult UScalar.val
        (Chio.AeneasProduction.classify_time_window_code now issuedAt expiresAt) =
      ok (AeneasMirror.classifyTimeWindowCode now.val issuedAt.val expiresAt.val) := by
  by_cases beforeIssue : now.val < issuedAt.val
  · simp [Chio.AeneasProduction.classify_time_window_code,
      AeneasMirror.classifyTimeWindowCode, mapResult, beforeIssue]
  · by_cases afterExpiry : expiresAt.val <= now.val
    · simp [Chio.AeneasProduction.classify_time_window_code,
        AeneasMirror.classifyTimeWindowCode, mapResult, beforeIssue, afterExpiry]
    · simp [Chio.AeneasProduction.classify_time_window_code,
        AeneasMirror.classifyTimeWindowCode, mapResult, beforeIssue, afterExpiry]

#print axioms generated_classify_time_window_code_eq_mirror

theorem generated_time_window_valid_eq_mirror
    (now issuedAt expiresAt : U64) :
    Chio.AeneasProduction.time_window_valid now issuedAt expiresAt =
      ok (AeneasMirror.timeWindowValid now.val issuedAt.val expiresAt.val) := by
  by_cases beforeIssue : now.val < issuedAt.val
  · simp [Chio.AeneasProduction.time_window_valid,
      Chio.AeneasProduction.classify_time_window_code,
      AeneasMirror.timeWindowValid, beforeIssue]
  · by_cases afterExpiry : expiresAt.val <= now.val
    · simp [Chio.AeneasProduction.time_window_valid,
        Chio.AeneasProduction.classify_time_window_code,
        AeneasMirror.timeWindowValid, beforeIssue, afterExpiry]
    · simp [Chio.AeneasProduction.time_window_valid,
        Chio.AeneasProduction.classify_time_window_code,
        AeneasMirror.timeWindowValid, beforeIssue, afterExpiry]
      omega

#print axioms generated_time_window_valid_eq_mirror

theorem generated_exact_or_wildcard_covers_by_flags_eq_mirror
    (parentIsWildcard parentEqualsChild : Bool) :
    Chio.AeneasProduction.exact_or_wildcard_covers_by_flags
        parentIsWildcard parentEqualsChild =
      ok (AeneasMirror.exactOrWildcardCovers parentIsWildcard parentEqualsChild) := by
  cases parentIsWildcard <;> rfl

#print axioms generated_exact_or_wildcard_covers_by_flags_eq_mirror

theorem generated_prefix_wildcard_or_exact_covers_by_flags_eq_mirror
    (parentIsWildcard parentHasPrefixWildcard prefixMatches exactMatches : Bool) :
    Chio.AeneasProduction.prefix_wildcard_or_exact_covers_by_flags
        parentIsWildcard parentHasPrefixWildcard prefixMatches exactMatches =
      ok (AeneasMirror.prefixWildcardOrExactCovers
        parentIsWildcard parentHasPrefixWildcard prefixMatches exactMatches) := by
  cases parentIsWildcard <;> cases parentHasPrefixWildcard <;> cases prefixMatches <;> rfl

#print axioms generated_prefix_wildcard_or_exact_covers_by_flags_eq_mirror

theorem generated_optional_u32_cap_is_subset_eq_mirror
    (childHasCap parentHasCap : Bool)
    (childValue parentValue : U32) :
    Chio.AeneasProduction.optional_u32_cap_is_subset
        childHasCap childValue parentHasCap parentValue =
      ok (AeneasMirror.optionalCapIsSubset
        childHasCap childValue.val parentHasCap parentValue.val) := by
  cases childHasCap <;> cases parentHasCap <;> rfl

#print axioms generated_optional_u32_cap_is_subset_eq_mirror

theorem generated_required_true_is_preserved_eq_mirror
    (parentRequiresTrue childRequiresTrue : Bool) :
    Chio.AeneasProduction.required_true_is_preserved
        parentRequiresTrue childRequiresTrue =
      ok (AeneasMirror.requiredTrueIsPreserved parentRequiresTrue childRequiresTrue) := by
  cases parentRequiresTrue <;> rfl

#print axioms generated_required_true_is_preserved_eq_mirror

theorem generated_monetary_cap_is_subset_by_parts_eq_mirror
    (childHasCap parentHasCap currencyMatches : Bool)
    (childUnits parentUnits : U64) :
    Chio.AeneasProduction.monetary_cap_is_subset_by_parts
        childHasCap childUnits parentHasCap parentUnits currencyMatches =
      ok (AeneasMirror.monetaryCapIsSubsetByParts
        childHasCap childUnits.val parentHasCap parentUnits.val currencyMatches) := by
  cases childHasCap <;> cases parentHasCap <;> cases currencyMatches <;> rfl

#print axioms generated_monetary_cap_is_subset_by_parts_eq_mirror

theorem generated_budget_precheck_eq_mirror
    (remainingInvocations remainingUnits invocationCost unitCost : U64) :
    Chio.AeneasProduction.budget_precheck
        remainingInvocations remainingUnits invocationCost unitCost =
      ok (AeneasMirror.budgetPrecheck
        {
          remainingInvocations := remainingInvocations.val,
          remainingUnits := remainingUnits.val,
        }
        {
          invocationCost := invocationCost.val,
          unitCost := unitCost.val,
        }) := by
  by_cases invocationFits : invocationCost.val <= remainingInvocations.val
  · simp [Chio.AeneasProduction.budget_precheck,
      AeneasMirror.budgetPrecheck, invocationFits]
  · simp [Chio.AeneasProduction.budget_precheck,
      AeneasMirror.budgetPrecheck, invocationFits]

#print axioms generated_budget_precheck_eq_mirror

theorem generated_budget_commit_eq_mirror
    (remainingInvocations remainingUnits invocationCost unitCost : U64) :
    mapResult generatedBudgetCommitToModel
        (Chio.AeneasProduction.budget_commit
          remainingInvocations remainingUnits invocationCost unitCost) =
      ok (AeneasMirror.budgetCommit
        {
          remainingInvocations := remainingInvocations.val,
          remainingUnits := remainingUnits.val,
        }
        {
          invocationCost := invocationCost.val,
          unitCost := unitCost.val,
        }) := by
  by_cases invocationFits : invocationCost.val <= remainingInvocations.val
  · by_cases unitFits : unitCost.val <= remainingUnits.val
    · obtain ⟨remainingInvocationsResult, invocationSub, invocationVal⟩ :=
        u64_sub_result remainingInvocations invocationCost invocationFits
      obtain ⟨remainingUnitsResult, unitSub, unitVal⟩ :=
        u64_sub_result remainingUnits unitCost unitFits
      simp [Chio.AeneasProduction.budget_commit,
        Chio.AeneasProduction.budget_precheck,
        generatedBudgetCommitToModel, mapResult, AeneasMirror.budgetCommit,
        AeneasMirror.budgetPrecheck, invocationFits, unitFits,
        invocationSub, unitSub, invocationVal, unitVal]
    · simp [Chio.AeneasProduction.budget_commit,
        Chio.AeneasProduction.budget_precheck,
        generatedBudgetCommitToModel, mapResult, AeneasMirror.budgetCommit,
        AeneasMirror.budgetPrecheck, invocationFits, unitFits]
  · simp [Chio.AeneasProduction.budget_commit,
      Chio.AeneasProduction.budget_precheck,
      generatedBudgetCommitToModel, mapResult, AeneasMirror.budgetCommit,
      AeneasMirror.budgetPrecheck, invocationFits]

#print axioms generated_budget_commit_eq_mirror

theorem generated_dpop_freshness_valid_eq_mirror
    (now issuedAt ttlSecs maxSkewSecs : U64) :
    Chio.AeneasProduction.dpop_freshness_valid now issuedAt ttlSecs maxSkewSecs =
      ok (AeneasMirror.dpopFreshnessValid
        U64.max now.val issuedAt.val ttlSecs.val maxSkewSecs.val) := by
  by_cases issuedFits :
      issuedAt.val <= (core.num.U64.saturating_add now maxSkewSecs).val
  · have issuedFitsMirror :
        issuedAt.val <= AeneasMirror.saturatingAdd U64.max now.val maxSkewSecs.val := by
      simpa [u64_saturating_add_val] using issuedFits
    simp [Chio.AeneasProduction.dpop_freshness_valid,
      AeneasMirror.dpopFreshnessValid, lift, u64_saturating_add_val,
      issuedFitsMirror]
  · have issuedDoesNotFitMirror :
        ¬issuedAt.val <= AeneasMirror.saturatingAdd U64.max now.val maxSkewSecs.val := by
      simpa [u64_saturating_add_val] using issuedFits
    simp [Chio.AeneasProduction.dpop_freshness_valid,
      AeneasMirror.dpopFreshnessValid, lift, u64_saturating_add_val,
      issuedDoesNotFitMirror]

#print axioms generated_dpop_freshness_valid_eq_mirror

theorem generated_dpop_admits_eq_mirror
    (dpopRequired proofPresent proofValid nonceFresh : Bool) :
    Chio.AeneasProduction.dpop_admits
        dpopRequired proofPresent proofValid nonceFresh =
      ok (AeneasMirror.dpopAdmits dpopRequired proofPresent proofValid nonceFresh) := by
  cases dpopRequired <;> cases proofPresent <;> cases proofValid <;> rfl

#print axioms generated_dpop_admits_eq_mirror

theorem generated_nonce_admits_eq_mirror (alreadyLive : Bool) :
    Chio.AeneasProduction.nonce_admits alreadyLive =
      ok (AeneasMirror.nonceAdmits alreadyLive) := by
  cases alreadyLive <;> rfl

#print axioms generated_nonce_admits_eq_mirror

theorem generated_guard_step_allows_eq_mirror
    (coreAuthorized guardAllows : Bool) :
    Chio.AeneasProduction.guard_step_allows coreAuthorized guardAllows =
      ok (AeneasMirror.guardStepAllows coreAuthorized guardAllows) := by
  cases coreAuthorized <;> rfl

#print axioms generated_guard_step_allows_eq_mirror

theorem generated_revocation_snapshot_denies_eq_mirror
    (tokenRevoked ancestorRevoked : Bool) :
    Chio.AeneasProduction.revocation_snapshot_denies tokenRevoked ancestorRevoked =
      ok (AeneasMirror.revocationSnapshotDenies tokenRevoked ancestorRevoked) := by
  cases tokenRevoked <;> rfl

#print axioms generated_revocation_snapshot_denies_eq_mirror

theorem generated_receipt_fields_coupled_eq_mirror
    (capabilityMatches requestMatches verdictMatches policyHashMatches
      evidenceClassMatches : Bool) :
    Chio.AeneasProduction.receipt_fields_coupled
        capabilityMatches requestMatches verdictMatches policyHashMatches evidenceClassMatches =
      ok (AeneasMirror.receiptFieldsCoupled {
        capabilityMatches,
        requestMatches,
        verdictMatches,
        policyHashMatches,
        evidenceClassMatches,
      }) := by
  cases capabilityMatches <;> cases requestMatches <;> cases verdictMatches <;>
    cases policyHashMatches <;> rfl

#print axioms generated_receipt_fields_coupled_eq_mirror

theorem generated_time_window_valid_eq_model
    (capability : CapabilityToken)
    (modelNow : Timestamp)
    (now issuedAt expiresAt : U64)
    (nowMatches : now.val = modelNow)
    (issuedAtMatches : issuedAt.val = capability.issuedAt)
    (expiresAtMatches : expiresAt.val = capability.expiresAt) :
    Chio.AeneasProduction.time_window_valid now issuedAt expiresAt =
      ok (CapabilityToken.isValidAt capability modelNow) := by
  rw [generated_time_window_valid_eq_mirror]
  congr 1
  simpa [nowMatches, issuedAtMatches, expiresAtMatches] using
    aeneas_timeWindowValid_equiv_model capability modelNow

#print axioms generated_time_window_valid_eq_model

theorem generated_optional_u32_cap_is_subset_preserves_parent_cap
    (childHasCap parentHasCap : Bool)
    (childValue parentValue : U32)
    (subsetGenerated :
      Chio.AeneasProduction.optional_u32_cap_is_subset
        childHasCap childValue parentHasCap parentValue = ok true)
    (parentPresent : parentHasCap = true) :
    childHasCap = true ∧ childValue.val <= parentValue.val := by
  rw [generated_optional_u32_cap_is_subset_eq_mirror] at subsetGenerated
  injection subsetGenerated with subsetMirror
  exact aeneas_optionalCapIsSubset_preserves_parent_cap
    childHasCap parentHasCap childValue.val parentValue.val subsetMirror parentPresent

#print axioms generated_optional_u32_cap_is_subset_preserves_parent_cap

theorem generated_budget_commit_eq_model
    (remainingInvocations remainingUnits invocationCost unitCost : U64) :
    mapResult generatedBudgetCommitToModel
        (Chio.AeneasProduction.budget_commit
          remainingInvocations remainingUnits invocationCost unitCost) =
      ok (Chio.Core.budgetCommit
        {
          remainingInvocations := remainingInvocations.val,
          remainingUnits := remainingUnits.val,
        }
        {
          invocationCost := invocationCost.val,
          unitCost := unitCost.val,
        }) := by
  rw [generated_budget_commit_eq_mirror]
  congr 1

#print axioms generated_budget_commit_eq_model

theorem generated_dpop_admits_eq_model
    (dpopRequired proofPresent proofValid nonceFresh : Bool) :
    Chio.AeneasProduction.dpop_admits
        dpopRequired proofPresent proofValid nonceFresh =
      ok (dpopNonceAdmits {
        dpopRequired,
        proofPresent,
        proofValid,
        nonceFresh,
      }) := by
  rw [generated_dpop_admits_eq_mirror]
  congr 1

#print axioms generated_dpop_admits_eq_model

theorem generated_guard_step_allows_eq_model
    (coreAuthorized : Bool)
    (result : GuardResult) :
    Chio.AeneasProduction.guard_step_allows
        coreAuthorized (guardResultAllows result) =
      ok (guardPipelineAllows coreAuthorized [result]) := by
  rw [generated_guard_step_allows_eq_mirror]
  congr 1
  exact aeneas_guardStep_equiv_model coreAuthorized result

#print axioms generated_guard_step_allows_eq_model

theorem generated_revocation_snapshot_denies_eq_model
    (tokenRevoked ancestorRevoked : Bool) :
    Chio.AeneasProduction.revocation_snapshot_denies tokenRevoked ancestorRevoked =
      ok (revocationSnapshotDenies { tokenRevoked, ancestorRevoked }) := by
  rw [generated_revocation_snapshot_denies_eq_mirror]
  congr 1

#print axioms generated_revocation_snapshot_denies_eq_model

theorem generated_receipt_fields_coupled_eq_model
    (capabilityMatches requestMatches verdictMatches policyHashMatches
      evidenceClassMatches : Bool) :
    Chio.AeneasProduction.receipt_fields_coupled
        capabilityMatches requestMatches verdictMatches policyHashMatches evidenceClassMatches =
      ok (receiptFieldsCoupled {
        capabilityMatches,
        requestMatches,
        verdictMatches,
        policyHashMatches,
        evidenceClassMatches,
      }) := by
  rw [generated_receipt_fields_coupled_eq_mirror]
  congr 1

#print axioms generated_receipt_fields_coupled_eq_model

theorem generated_inclusion_step_eq_model (index size : U64) :
    mapResult generatedInclusionStepToModel
        (Chio.AeneasProduction.inclusion_step index size) =
      ok (inclusionStep index.val size.val) := by
  obtain ⟨indexRemainder, indexRemainderEq, indexRemainderVal⟩ :=
    u64_rem_result index 2#u64 (by norm_num)
  obtain ⟨nextIndex, nextIndexEq, nextIndexVal⟩ :=
    u64_div_result index 2#u64 (by norm_num)
  obtain ⟨sizeQuotient, sizeQuotientEq, sizeQuotientVal⟩ :=
    u64_div_result size 2#u64 (by norm_num)
  obtain ⟨sizeRemainder, sizeRemainderEq, sizeRemainderVal⟩ :=
    u64_rem_result size 2#u64 (by norm_num)
  norm_num at indexRemainderVal nextIndexVal sizeQuotientVal sizeRemainderVal
  have nextSizeFits : sizeQuotient.val + sizeRemainder.val <= U64.max := by
    rw [sizeQuotientVal, sizeRemainderVal]
    scalar_tac
  obtain ⟨nextSize, nextSizeEq, nextSizeVal⟩ :=
    u64_add_result sizeQuotient sizeRemainder nextSizeFits
  cases checkedEq : U64.checked_add index 1#u64 with
  | none =>
      have overflow := u64_checked_add_none index 1#u64 checkedEq
      norm_num at overflow
      have rightAbsent : ¬ index.val + 1 < size.val := by
        scalar_tac
      by_cases remainderZero : indexRemainder.val = 0
      · have indexModZero : index.val % 2 = 0 := by
          rw [← indexRemainderVal]
          exact remainderZero
        simp [Chio.AeneasProduction.inclusion_step, lift, indexRemainderEq,
          indexRemainderVal, checkedEq, nextIndexEq, nextIndexVal,
          sizeQuotientEq, sizeQuotientVal, sizeRemainderEq, sizeRemainderVal,
          nextSizeEq, nextSizeVal, mapResult, generatedInclusionStepToModel,
          inclusionStep, indexModZero, rightAbsent]
      · have indexModOne : index.val % 2 = 1 := by
          have remainderBound : index.val % 2 < 2 := Nat.mod_lt _ (by omega)
          rw [← indexRemainderVal] at remainderBound ⊢
          omega
        simp [Chio.AeneasProduction.inclusion_step, lift, indexRemainderEq,
          indexRemainderVal, checkedEq, nextIndexEq, nextIndexVal,
          sizeQuotientEq, sizeQuotientVal, sizeRemainderEq, sizeRemainderVal,
          nextSizeEq, nextSizeVal, mapResult, generatedInclusionStepToModel,
          inclusionStep, indexModOne, rightAbsent]
  | some sibling =>
      have checked := u64_checked_add_some index 1#u64 sibling checkedEq
      norm_num at checked
      by_cases siblingLess : sibling.val < size.val
      · have rightExists : index.val + 1 < size.val := by
          omega
        by_cases remainderZero : indexRemainder.val = 0
        · have indexModZero : index.val % 2 = 0 := by
            rw [← indexRemainderVal]
            exact remainderZero
          simp [Chio.AeneasProduction.inclusion_step, lift, indexRemainderEq,
            indexRemainderVal, checkedEq, nextIndexEq, nextIndexVal,
            sizeQuotientEq, sizeQuotientVal, sizeRemainderEq, sizeRemainderVal,
            nextSizeEq, nextSizeVal, mapResult, generatedInclusionStepToModel,
            inclusionStep, siblingLess, indexModZero, rightExists]
        · have indexModOne : index.val % 2 = 1 := by
            have remainderBound : index.val % 2 < 2 := Nat.mod_lt _ (by omega)
            rw [← indexRemainderVal] at remainderBound ⊢
            omega
          simp [Chio.AeneasProduction.inclusion_step, lift, indexRemainderEq,
            indexRemainderVal, checkedEq, nextIndexEq, nextIndexVal,
            sizeQuotientEq, sizeQuotientVal, sizeRemainderEq, sizeRemainderVal,
            nextSizeEq, nextSizeVal, mapResult, generatedInclusionStepToModel,
            inclusionStep, siblingLess, indexModOne, rightExists]
      · have rightAbsent : ¬ index.val + 1 < size.val := by
          omega
        by_cases remainderZero : indexRemainder.val = 0
        · have indexModZero : index.val % 2 = 0 := by
            rw [← indexRemainderVal]
            exact remainderZero
          simp [Chio.AeneasProduction.inclusion_step, lift, indexRemainderEq,
            indexRemainderVal, checkedEq, nextIndexEq, nextIndexVal,
            sizeQuotientEq, sizeQuotientVal, sizeRemainderEq, sizeRemainderVal,
            nextSizeEq, nextSizeVal, mapResult, generatedInclusionStepToModel,
            inclusionStep, siblingLess, indexModZero, rightAbsent]
        · have indexModOne : index.val % 2 = 1 := by
            have remainderBound : index.val % 2 < 2 := Nat.mod_lt _ (by omega)
            rw [← indexRemainderVal] at remainderBound ⊢
            omega
          simp [Chio.AeneasProduction.inclusion_step, lift, indexRemainderEq,
            indexRemainderVal, checkedEq, nextIndexEq, nextIndexVal,
            sizeQuotientEq, sizeQuotientVal, sizeRemainderEq, sizeRemainderVal,
            nextSizeEq, nextSizeVal, mapResult, generatedInclusionStepToModel,
            inclusionStep, siblingLess, indexModOne, rightAbsent]

#print axioms generated_inclusion_step_eq_model

end Chio.Proofs
