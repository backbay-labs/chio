/-
  Closure-based treaty model retained only as the comparison target for the
  representation bridge. Public treaty definitions live in `Intersection` and
  use the syntactic constitution model.
-/

import Chio.Treaty.PredicateLang

set_option autoImplicit false

namespace Chio.Treaty.Legacy

abbrev AdmissionView := Chio.Treaty.PredicateLang.AdmissionView

structure PolityScope where
  contains : AdmissionView -> Bool

structure Constitution where
  predicates : List (AdmissionView -> Bool)

structure Polity where
  scope : PolityScope
  constitution : Constitution

structure BilateralTreaty where
  scope : PolityScope
  constitution : Constitution
  left : Polity
  right : Polity
  modeFloor : Chio.Treaty.TrustMode

def allPredicates
    (predicates : List (AdmissionView -> Bool))
    (view : AdmissionView) : Bool :=
  predicates.all (fun predicate => predicate view)

def constitutionAllows
    (constitution : Constitution) (view : AdmissionView) : Bool :=
  allPredicates constitution.predicates view

def polityAdmits (polity : Polity) (view : AdmissionView) : Bool :=
  polity.scope.contains view && constitutionAllows polity.constitution view

def treatyPredicateIntersection
    (treaty : BilateralTreaty) (view : AdmissionView) : Bool :=
  treaty.scope.contains view &&
    constitutionAllows treaty.constitution view &&
    treaty.left.scope.contains view &&
    constitutionAllows treaty.left.constitution view &&
    treaty.right.scope.contains view &&
    constitutionAllows treaty.right.constitution view

def treatyAdmits (treaty : BilateralTreaty) (view : AdmissionView) : Bool :=
  treaty.scope.contains view &&
    constitutionAllows treaty.constitution view &&
    polityAdmits treaty.left view &&
    polityAdmits treaty.right view

def treatyAdmitsUnderMode
    (treaty : BilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (view : AdmissionView) : Bool :=
  mode.atLeast treaty.modeFloor && treatyAdmits treaty view

def BackwardRefines
    (new old : Constitution) : Prop :=
  forall view, constitutionAllows new view = true ->
    constitutionAllows old view = true

def BackwardRefinesOn
    (new old : Constitution) (domain : List AdmissionView) : Prop :=
  forall view, view ∈ domain ->
    constitutionAllows new view = true -> constitutionAllows old view = true

structure ConstitutionalDelta where
  old : Constitution
  new : Constitution
  domain : List AdmissionView
  proofTerm : BackwardRefinesOn new old domain

structure AmendmentCandidate where
  old : Constitution
  new : Constitution
  domain : List AdmissionView
  proofPresent : Bool
  proofTerm : proofPresent = true -> BackwardRefinesOn new old domain

def amendmentAdmissible (candidate : AmendmentCandidate) : Prop :=
  candidate.proofPresent = true

def enactAmendment
    (_delta : ConstitutionalDelta) : Chio.Treaty.AmendmentVerdict :=
  .enacted

def evaluateAmendment
    (candidate : AmendmentCandidate) : Chio.Treaty.AmendmentVerdict :=
  if candidate.proofPresent then .enacted else .rejected

theorem treaty_admission_iff_predicate_intersection
    (treaty : BilateralTreaty) (view : AdmissionView) :
    treatyAdmits treaty view = true ↔
      treatyPredicateIntersection treaty view = true := by
  cases treaty with
  | mk scope constitution left right modeFloor =>
      cases left with
      | mk leftScope leftConstitution =>
          cases right with
          | mk rightScope rightConstitution =>
              simp [treatyAdmits, treatyPredicateIntersection,
                polityAdmits, Bool.and_assoc]

theorem treaty_admission_stable_under_ladder_floor
    (treaty : BilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (view : AdmissionView)
    (hMode : mode.atLeast treaty.modeFloor = true) :
    treatyAdmitsUnderMode treaty mode view = treatyAdmits treaty view := by
  simp [treatyAdmitsUnderMode, hMode]

theorem amendment_admissible_iff_backward_refinement
    (candidate : AmendmentCandidate) :
    amendmentAdmissible candidate ↔
      candidate.proofPresent = true ∧
        BackwardRefinesOn candidate.new candidate.old candidate.domain := by
  constructor
  · intro hPresent
    exact ⟨hPresent, candidate.proofTerm hPresent⟩
  · intro hAdmissible
    exact hAdmissible.1

theorem amendment_without_refinement_rejected
    (old new : Constitution) (domain : List AdmissionView) :
    evaluateAmendment {
      old := old
      new := new
      domain := domain
      proofPresent := false
      proofTerm := by
        intro hFalse
        cases hFalse
    } = Chio.Treaty.AmendmentVerdict.rejected := by
  rfl

end Chio.Treaty.Legacy
