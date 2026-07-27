import Chio.Treaty.PredicateLang

set_option autoImplicit false

namespace Chio.Treaty.PredicateLang

/-- A polity with a syntactic scope and constitution. -/
structure SyntacticPolity where
  scope : Predicate
  constitution : SyntacticConstitution
  deriving Repr, BEq, DecidableEq, Inhabited

/-- The treaty admission surface consumed by the public intersection model. -/
structure SyntacticBilateralTreaty where
  scope : Predicate
  constitution : SyntacticConstitution
  left : SyntacticPolity
  right : SyntacticPolity
  modeFloor : Chio.Treaty.TrustMode
  deriving Repr, BEq, DecidableEq, Inhabited

def synPolityAdmits
    (polity : SyntacticPolity) (view : AdmissionView) : Bool :=
  denote polity.scope view && admits polity.constitution view

def synTreatyPredicateIntersection
    (treaty : SyntacticBilateralTreaty) (view : AdmissionView) : Bool :=
  denote treaty.scope view &&
    admits treaty.constitution view &&
    denote treaty.left.scope view &&
    admits treaty.left.constitution view &&
    denote treaty.right.scope view &&
    admits treaty.right.constitution view

def synTreatyAdmits
    (treaty : SyntacticBilateralTreaty) (view : AdmissionView) : Bool :=
  denote treaty.scope view &&
    admits treaty.constitution view &&
    synPolityAdmits treaty.left view &&
    synPolityAdmits treaty.right view

def synTreatyAdmitsUnderMode
    (treaty : SyntacticBilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (view : AdmissionView) : Bool :=
  mode.atLeast treaty.modeFloor && synTreatyAdmits treaty view

/-- A successful finite decision carries its exact domain refinement proof. -/
structure ConstitutionalDeltaSyn where
  old : SyntacticConstitution
  new : SyntacticConstitution
  domain : List AdmissionView
  proofTerm : SynBackwardRefines new old domain

namespace ConstitutionalDeltaSyn

/-- Run the finite decision and return a witness only on success. -/
def ofDecide
    (old new : SyntacticConstitution)
    (domain : List AdmissionView) : Option ConstitutionalDeltaSyn :=
  if hCheck : refinesOnConstitution new old domain = true then
    some {
      old := old
      new := new
      domain := domain
      proofTerm :=
        (refinesOnConstitution_complete_on_fragment new old domain).mp hCheck
    }
  else
    none

theorem ofDecide_isSome_iff
    (old new : SyntacticConstitution) (domain : List AdmissionView) :
    (ofDecide old new domain).isSome = true ↔
      SynBackwardRefines new old domain := by
  unfold ofDecide
  by_cases hCheck : refinesOnConstitution new old domain = true
  · simp [hCheck,
      (refinesOnConstitution_complete_on_fragment new old domain).mp hCheck]
  · have hNotRefines : ¬ SynBackwardRefines new old domain := by
      intro hRefines
      exact hCheck
        ((refinesOnConstitution_complete_on_fragment new old domain).mpr
          hRefines)
    simp [hCheck, hNotRefines]

end ConstitutionalDeltaSyn

/-- Amendment input. The evaluator computes proof availability itself. -/
structure AmendmentCandidateSyn where
  old : SyntacticConstitution
  new : SyntacticConstitution
  domain : List AdmissionView
  deriving Repr, BEq, DecidableEq, Inhabited

def amendmentAdmissibleSyn (candidate : AmendmentCandidateSyn) : Prop :=
  SynBackwardRefines candidate.new candidate.old candidate.domain

def enactAmendmentSyn
    (_delta : ConstitutionalDeltaSyn) : Chio.Treaty.AmendmentVerdict :=
  .enacted

def evaluateAmendmentSyn
    (candidate : AmendmentCandidateSyn) : Chio.Treaty.AmendmentVerdict :=
  match ConstitutionalDeltaSyn.ofDecide
      candidate.old candidate.new candidate.domain with
  | some delta => enactAmendmentSyn delta
  | none => .rejected

theorem synTreaty_admission_iff_predicate_intersection
    (treaty : SyntacticBilateralTreaty) (view : AdmissionView) :
    synTreatyAdmits treaty view = true ↔
      synTreatyPredicateIntersection treaty view = true := by
  cases treaty with
  | mk scope constitution left right modeFloor =>
      cases left with
      | mk leftScope leftConstitution =>
          cases right with
          | mk rightScope rightConstitution =>
              simp [synTreatyAdmits, synTreatyPredicateIntersection,
                synPolityAdmits, Bool.and_assoc]

theorem synTreaty_admission_stable_under_ladder_floor
    (treaty : SyntacticBilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (view : AdmissionView)
    (hMode : mode.atLeast treaty.modeFloor = true) :
    synTreatyAdmitsUnderMode treaty mode view =
      synTreatyAdmits treaty view := by
  simp [synTreatyAdmitsUnderMode, hMode]

theorem synAmendment_admissible_iff_backward_refinement
    (candidate : AmendmentCandidateSyn) :
    amendmentAdmissibleSyn candidate ↔
      SynBackwardRefines candidate.new candidate.old candidate.domain := by
  rfl

theorem synAmendment_without_refinement_rejected
    (candidate : AmendmentCandidateSyn)
    (hCheck : refinesOnConstitution
      candidate.new candidate.old candidate.domain = false) :
    evaluateAmendmentSyn candidate = Chio.Treaty.AmendmentVerdict.rejected := by
  simp [evaluateAmendmentSyn, ConstitutionalDeltaSyn.ofDecide, hCheck]

/-- A production-shaped accepted admission fixture. -/
def acceptedAdmission : AdmissionView :=
  {
    scope := {
      schema := treatyScopeSchema
      treatyId := "treaty-1"
      participantKernelIds := ["kernel-a", "kernel-b"]
      ladderManifestSha256s := ["manifest-a", "manifest-b"]
      allowedActionClasses := ["file-read", "file-write"]
      issuedAtUnixMs := 1
      expiresAtUnixMs := 100
    }
    intersection := {
      schema := ladderIntersectionSchema
      treatyId := "treaty-1"
      participantKernelIds := ["kernel-a", "kernel-b"]
      ladderManifestSha256s := ["manifest-a", "manifest-b"]
      actionClassIds := ["file-read", "file-write"]
      generatedAtUnixMs := 2
      expiresAtUnixMs := 90
    }
    invocation := {
      schema := bilateralInvocationSchema
      treatyId := "treaty-1"
      ladderIntersectionSha256 := "ladder-hash"
      continuationSha256 := "continuation-hash"
      actionClassId := "file-read"
      signerKernelIds := ["kernel-a", "kernel-b"]
    }
    nowUnixMs := 10
    computedLadderIntersectionSha256 := "ladder-hash"
    expectedLadderIntersectionSha256 := some "ladder-hash"
    expectedContinuationSha256 := some "continuation-hash"
    resolvedMode := some .receiptBacked
    requiredEvidence := ["bilateral-invocation"]
    presentEvidence := ["bilateral-invocation"]
    verifiedEvidence := [{
      evidenceClass := "bilateral-invocation"
      verified := true
    }]
    jointPolicyAllows := true
  }

/-- Same runtime fields with a verifier-owned deny verdict. -/
def policyDeniedAdmission : AdmissionView :=
  { acceptedAdmission with jointPolicyAllows := false }

/-- The original constitution admits every scope-allowed action. -/
def broadConstitution : SyntacticConstitution :=
  { predicates := [.atom .actionClassAllowed] }

/-- The amendment additionally requires the bilateral policy verdict. -/
def narrowedConstitution : SyntacticConstitution :=
  { predicates := [
      .atom .actionClassAllowed,
      .atom .jointPolicyAllows
    ] }

def exampleDomain : List AdmissionView :=
  [acceptedAdmission, policyDeniedAdmission]

def narrowingCandidate : AmendmentCandidateSyn :=
  {
    old := broadConstitution
    new := narrowedConstitution
    domain := exampleDomain
  }

def wideningCandidate : AmendmentCandidateSyn :=
  {
    old := narrowedConstitution
    new := broadConstitution
    domain := exampleDomain
  }

example : admits broadConstitution policyDeniedAdmission = true := by decide

example : admits narrowedConstitution policyDeniedAdmission = false := by decide

example :
    (ConstitutionalDeltaSyn.ofDecide
      broadConstitution narrowedConstitution exampleDomain).isSome = true := by
  decide

example : evaluateAmendmentSyn narrowingCandidate =
    Chio.Treaty.AmendmentVerdict.enacted := by
  decide

example : evaluateAmendmentSyn wideningCandidate =
    Chio.Treaty.AmendmentVerdict.rejected := by
  decide

#eval (ConstitutionalDeltaSyn.ofDecide
  broadConstitution narrowedConstitution exampleDomain).isSome
#eval evaluateAmendmentSyn narrowingCandidate
#eval evaluateAmendmentSyn wideningCandidate

end Chio.Treaty.PredicateLang

namespace Chio.Treaty.IntersectionSyntactic

open Chio.Treaty.PredicateLang

abbrev Polity := SyntacticPolity
abbrev BilateralTreaty := SyntacticBilateralTreaty
abbrev ConstitutionalDelta := ConstitutionalDeltaSyn
abbrev AmendmentCandidate := AmendmentCandidateSyn

/-- Production-shaped treaty intersection theorem. -/
theorem treaty_admission_iff_predicate_intersection
    (treaty : BilateralTreaty) (view : AdmissionView) :
    synTreatyAdmits treaty view = true ↔
      synTreatyPredicateIntersection treaty view = true :=
  synTreaty_admission_iff_predicate_intersection treaty view

/-- Stability above the declared governance-mode floor. -/
theorem treaty_admission_stable_under_ladder_floor
    (treaty : BilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (view : AdmissionView)
    (hMode : mode.atLeast treaty.modeFloor = true) :
    synTreatyAdmitsUnderMode treaty mode view =
      synTreatyAdmits treaty view :=
  synTreaty_admission_stable_under_ladder_floor treaty mode view hMode

/-- Exact refinement on the supplied finite domain. -/
theorem amendment_admissible_iff_bounded_refinement
    (candidate : AmendmentCandidate) :
    amendmentAdmissibleSyn candidate ↔
      SynBackwardRefines candidate.new candidate.old candidate.domain :=
  synAmendment_admissible_iff_backward_refinement candidate

/-- Fail-closed rejection after a failed decision. -/
theorem amendment_without_refinement_rejected
    (candidate : AmendmentCandidate)
    (hCheck : refinesOnConstitution
      candidate.new candidate.old candidate.domain = false) :
    evaluateAmendmentSyn candidate =
      Chio.Treaty.AmendmentVerdict.rejected :=
  synAmendment_without_refinement_rejected candidate hCheck

end Chio.Treaty.IntersectionSyntactic
