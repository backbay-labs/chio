/-
  Ordinary-value semantics used to connect generated machine-integer code to
  the handwritten protocol model. This mirror is an internal proof step. The
  generated-equivalence module proves every decision helper agrees with it
  before composing these facts with the model theorems below.
-/

import Chio.Core.Capability
import Chio.Core.Protocol

set_option autoImplicit false

namespace Chio.Proofs

open Chio.Core

namespace AeneasMirror

def classifyTimeWindowCode (now issuedAt expiresAt : Nat) : Nat :=
  if now < issuedAt then 1 else if now >= expiresAt then 2 else 0

def timeWindowValid (now issuedAt expiresAt : Nat) : Bool :=
  issuedAt <= now && now < expiresAt

def exactOrWildcardCovers (parentIsWildcard parentEqualsChild : Bool) : Bool :=
  parentIsWildcard || parentEqualsChild

def prefixWildcardOrExactCovers
    (parentIsWildcard parentHasPrefixWildcard prefixMatches exactMatches : Bool) : Bool :=
  parentIsWildcard || (parentHasPrefixWildcard && prefixMatches) || exactMatches

def optionalCapIsSubset
    (childHasCap : Bool)
    (childValue : Nat)
    (parentHasCap : Bool)
    (parentValue : Nat) : Bool :=
  !parentHasCap || (childHasCap && childValue <= parentValue)

def requiredTrueIsPreserved
    (parentRequiresTrue childRequiresTrue : Bool) : Bool :=
  !parentRequiresTrue || childRequiresTrue

def monetaryCapIsSubsetByParts
    (childHasCap : Bool)
    (childUnits : Nat)
    (parentHasCap : Bool)
    (parentUnits : Nat)
    (currencyMatches : Bool) : Bool :=
  !parentHasCap || (childHasCap && currencyMatches && childUnits <= parentUnits)

def budgetPrecheck (state : BudgetState) (request : BudgetRequest) : Bool :=
  request.invocationCost <= state.remainingInvocations
    && request.unitCost <= state.remainingUnits

def budgetCommit (state : BudgetState) (request : BudgetRequest) : Option BudgetState :=
  if budgetPrecheck state request then
    some {
      remainingInvocations := state.remainingInvocations - request.invocationCost,
      remainingUnits := state.remainingUnits - request.unitCost,
    }
  else
    none

def saturatingAdd (maximum left right : Nat) : Nat :=
  min maximum (left + right)

def dpopFreshnessValid
    (maximum now issuedAt ttlSecs maxSkewSecs : Nat) : Bool :=
  issuedAt <= saturatingAdd maximum now maxSkewSecs
    && saturatingAdd maximum issuedAt ttlSecs >= now

def dpopAdmits
    (dpopRequired proofPresent proofValid nonceFresh : Bool) : Bool :=
  !dpopRequired || (proofPresent && proofValid && nonceFresh)

def nonceAdmits (alreadyLive : Bool) : Bool :=
  !alreadyLive

def guardStepAllows (coreAuthorized guardAllows : Bool) : Bool :=
  coreAuthorized && guardAllows

def revocationSnapshotDenies (tokenRevoked ancestorRevoked : Bool) : Bool :=
  tokenRevoked || ancestorRevoked

def receiptFieldsCoupled (facts : ReceiptCouplingFacts) : Bool :=
  facts.capabilityMatches
    && facts.requestMatches
    && facts.verdictMatches
    && facts.policyHashMatches
    && facts.evidenceClassMatches

end AeneasMirror

theorem aeneas_timeWindowValid_equiv_model (cap : CapabilityToken) (now : Timestamp) :
    AeneasMirror.timeWindowValid now cap.issuedAt cap.expiresAt =
      CapabilityToken.isValidAt cap now := by
  rfl

theorem aeneas_exactOrWildcardCovers_true_for_wildcard
    (parentEqualsChild : Bool) :
    AeneasMirror.exactOrWildcardCovers true parentEqualsChild = true := by
  rfl

theorem aeneas_exactOrWildcardCovers_equiv_exact
    (parentEqualsChild : Bool) :
    AeneasMirror.exactOrWildcardCovers false parentEqualsChild = parentEqualsChild := by
  rfl

theorem aeneas_prefixWildcardOrExactCovers_equiv
    (parentIsWildcard parentHasPrefixWildcard prefixMatches exactMatches : Bool) :
    AeneasMirror.prefixWildcardOrExactCovers
      parentIsWildcard parentHasPrefixWildcard prefixMatches exactMatches =
        (parentIsWildcard || (parentHasPrefixWildcard && prefixMatches) || exactMatches) := by
  rfl

theorem aeneas_optionalCapIsSubset_preserves_parent_cap
    (childHasCap parentHasCap : Bool)
    (childValue parentValue : Nat)
    (h_subset :
      AeneasMirror.optionalCapIsSubset childHasCap childValue parentHasCap parentValue = true)
    (h_parent : parentHasCap = true) :
    childHasCap = true ∧ childValue <= parentValue := by
  cases childHasCap <;> cases parentHasCap <;> simp [AeneasMirror.optionalCapIsSubset] at h_subset h_parent ⊢
  exact h_subset

theorem aeneas_requiredTrueIsPreserved_equiv
    (parentRequiresTrue childRequiresTrue : Bool) :
    AeneasMirror.requiredTrueIsPreserved parentRequiresTrue childRequiresTrue =
      (!parentRequiresTrue || childRequiresTrue) := by
  rfl

theorem aeneas_monetaryCapIsSubset_preserves_parent_cap
    (childHasCap parentHasCap currencyMatches : Bool)
    (childUnits parentUnits : Nat)
    (h_subset :
      AeneasMirror.monetaryCapIsSubsetByParts
        childHasCap childUnits parentHasCap parentUnits currencyMatches = true)
    (h_parent : parentHasCap = true) :
    childHasCap = true ∧ currencyMatches = true ∧ childUnits <= parentUnits := by
  cases childHasCap <;> cases parentHasCap <;> cases currencyMatches
  <;> simp [AeneasMirror.monetaryCapIsSubsetByParts] at h_subset h_parent ⊢
  exact h_subset

theorem aeneas_budgetPrecheck_equiv_model
    (state : BudgetState)
    (request : BudgetRequest) :
    AeneasMirror.budgetPrecheck state request =
      Chio.Core.budgetPrecheck state request := by
  rfl

theorem aeneas_budgetCommit_equiv_model
    (state : BudgetState)
    (request : BudgetRequest) :
    AeneasMirror.budgetCommit state request =
      Chio.Core.budgetCommit state request := by
  rfl

theorem aeneas_dpopAdmits_equiv_model
    (facts : DpopNonceFacts) :
    AeneasMirror.dpopAdmits
      facts.dpopRequired facts.proofPresent facts.proofValid facts.nonceFresh =
        dpopNonceAdmits facts := by
  cases facts <;> rfl

theorem aeneas_nonceAdmits_equiv_model (alreadyLive : Bool) :
    AeneasMirror.nonceAdmits alreadyLive =
      nonceReplayAdmits alreadyLive := by
  rfl

theorem aeneas_guardStep_equiv_model
    (coreAuthorized : Bool)
    (result : GuardResult) :
    AeneasMirror.guardStepAllows coreAuthorized (guardResultAllows result) =
      guardPipelineAllows coreAuthorized [result] := by
  cases coreAuthorized <;> cases result <;> rfl

theorem aeneas_revocationSnapshot_equiv_model
    (facts : RevocationSnapshotFacts) :
    AeneasMirror.revocationSnapshotDenies facts.tokenRevoked facts.ancestorRevoked =
      revocationSnapshotDenies facts := by
  cases facts <;> rfl

theorem aeneas_receiptCoupling_equiv_model
    (facts : ReceiptCouplingFacts) :
    AeneasMirror.receiptFieldsCoupled facts =
      receiptFieldsCoupled facts := by
  cases facts <;> rfl

end Chio.Proofs
