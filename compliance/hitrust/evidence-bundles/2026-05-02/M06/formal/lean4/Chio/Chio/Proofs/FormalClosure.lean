/-
  Closing lemmas for the implementation-linked mediated execution claim.

  These model the remaining runtime-adjacent security properties at the
  boundary where Rust projection tests and audited assumptions take over.
-/

import Chio.Core.Protocol

set_option autoImplicit false

namespace Chio.Core

structure DelegationStepFacts where
  attenuated : Bool
  subjectContinuous : Bool
  expiryMonotone : Bool
  depthWithinLimit : Bool
  ancestorRevoked : Bool
  deriving Repr, BEq

def delegationStepAdmits (facts : DelegationStepFacts) : Bool :=
  facts.attenuated
    && facts.subjectContinuous
    && facts.expiryMonotone
    && facts.depthWithinLimit
    && !facts.ancestorRevoked

def delegationChainAdmits (steps : List DelegationStepFacts) : Bool :=
  steps.all delegationStepAdmits

structure DpopBindingFacts where
  htuMatches : Bool
  htmMatches : Bool
  actionHashMatches : Bool
  capabilityIdMatches : Bool
  subjectKeyMatches : Bool
  nonceFresh : Bool
  timeWindowValid : Bool
  deriving Repr, BEq

def dpopBindingAdmits (facts : DpopBindingFacts) : Bool :=
  facts.htuMatches
    && facts.htmMatches
    && facts.actionHashMatches
    && facts.capabilityIdMatches
    && facts.subjectKeyMatches
    && facts.nonceFresh
    && facts.timeWindowValid

def segmentPrefix : List String → List String → Bool
  | [], _ => true
  | _ :: _, [] => false
  | expected :: prefixRest, actual :: candidateRest =>
      (expected == actual) && segmentPrefix prefixRest candidateRest

end Chio.Core

namespace Chio.Proofs

open Chio.Core

theorem delegation_step_allow_requires_attenuation
    (facts : DelegationStepFacts)
    (h_allowed : delegationStepAdmits facts = true) :
    facts.attenuated = true := by
  cases facts with
  | mk attenuated subjectContinuous expiryMonotone depthWithinLimit ancestorRevoked =>
      cases attenuated <;> cases subjectContinuous <;> cases expiryMonotone
      <;> cases depthWithinLimit <;> cases ancestorRevoked
      <;> simp [delegationStepAdmits] at h_allowed ⊢

theorem delegation_step_allow_requires_subject_continuity
    (facts : DelegationStepFacts)
    (h_allowed : delegationStepAdmits facts = true) :
    facts.subjectContinuous = true := by
  cases facts with
  | mk attenuated subjectContinuous expiryMonotone depthWithinLimit ancestorRevoked =>
      cases attenuated <;> cases subjectContinuous <;> cases expiryMonotone
      <;> cases depthWithinLimit <;> cases ancestorRevoked
      <;> simp [delegationStepAdmits] at h_allowed ⊢

theorem delegation_step_allow_requires_expiry_monotonicity
    (facts : DelegationStepFacts)
    (h_allowed : delegationStepAdmits facts = true) :
    facts.expiryMonotone = true := by
  cases facts with
  | mk attenuated subjectContinuous expiryMonotone depthWithinLimit ancestorRevoked =>
      cases attenuated <;> cases subjectContinuous <;> cases expiryMonotone
      <;> cases depthWithinLimit <;> cases ancestorRevoked
      <;> simp [delegationStepAdmits] at h_allowed ⊢

theorem delegation_revoked_ancestor_denies
    (facts : DelegationStepFacts)
    (h_revoked : facts.ancestorRevoked = true) :
    delegationStepAdmits facts = false := by
  cases facts with
  | mk attenuated subjectContinuous expiryMonotone depthWithinLimit ancestorRevoked =>
      cases attenuated <;> cases subjectContinuous <;> cases expiryMonotone
      <;> cases depthWithinLimit <;> cases ancestorRevoked
      <;> simp [delegationStepAdmits] at h_revoked ⊢

theorem delegation_max_depth_failure_denies
    (facts : DelegationStepFacts)
    (h_depth : facts.depthWithinLimit = false) :
    delegationStepAdmits facts = false := by
  cases facts with
  | mk attenuated subjectContinuous expiryMonotone depthWithinLimit ancestorRevoked =>
      cases attenuated <;> cases subjectContinuous <;> cases expiryMonotone
      <;> cases depthWithinLimit <;> cases ancestorRevoked
      <;> simp [delegationStepAdmits] at h_depth ⊢

theorem dpop_binding_allows_only_when_all_fields_match
    (facts : DpopBindingFacts)
    (h_allowed : dpopBindingAdmits facts = true) :
    facts.htuMatches = true
      ∧ facts.htmMatches = true
      ∧ facts.actionHashMatches = true
      ∧ facts.capabilityIdMatches = true
      ∧ facts.subjectKeyMatches = true
      ∧ facts.nonceFresh = true
      ∧ facts.timeWindowValid = true := by
  cases facts with
  | mk htuMatches htmMatches actionHashMatches capabilityIdMatches subjectKeyMatches nonceFresh timeWindowValid =>
      cases htuMatches <;> cases htmMatches <;> cases actionHashMatches
      <;> cases capabilityIdMatches <;> cases subjectKeyMatches
      <;> cases nonceFresh <;> cases timeWindowValid
      <;> simp [dpopBindingAdmits] at h_allowed ⊢

theorem path_prefix_rejects_sibling_prefix :
    segmentPrefix ["app"] ["application"] = false := by
  rfl

theorem path_prefix_rejects_normalized_traversal_escape :
    segmentPrefix ["app"] ["etc", "passwd"] = false := by
  rfl

theorem path_prefix_allows_descendant :
    segmentPrefix ["app"] ["app", "src", "main.rs"] = true := by
  rfl

end Chio.Proofs
