/-
  Public bounded treaty and amendment model.

  Treaty admission now uses the decidable syntax and production-shaped input
  projection from `PredicateLang`. The former closure representation is kept
  under `Chio.Treaty.Legacy` and is connected by root-imported equivalence
  proofs in `BridgeEquivalence`.
-/

import Chio.Treaty.IntersectionSyntactic

set_option autoImplicit false

namespace Chio.Treaty

abbrev AdmissionView := PredicateLang.AdmissionView
abbrev PolityScope := PredicateLang.Predicate
abbrev Constitution := PredicateLang.SyntacticConstitution
abbrev Polity := PredicateLang.SyntacticPolity
abbrev BilateralTreaty := PredicateLang.SyntacticBilateralTreaty
abbrev ConstitutionalDelta := PredicateLang.ConstitutionalDeltaSyn
abbrev AmendmentCandidate := PredicateLang.AmendmentCandidateSyn

def allPredicates
    (predicates : List PredicateLang.Predicate)
    (view : AdmissionView) : Bool :=
  predicates.all (fun predicate => PredicateLang.denote predicate view)

def constitutionAllows
    (constitution : Constitution) (view : AdmissionView) : Bool :=
  PredicateLang.admits constitution view

def polityAdmits (polity : Polity) (view : AdmissionView) : Bool :=
  PredicateLang.synPolityAdmits polity view

def treatyPredicateIntersection
    (treaty : BilateralTreaty) (view : AdmissionView) : Bool :=
  PredicateLang.synTreatyPredicateIntersection treaty view

def treatyAdmits (treaty : BilateralTreaty) (view : AdmissionView) : Bool :=
  PredicateLang.synTreatyAdmits treaty view

def treatyAdmitsUnderMode
    (treaty : BilateralTreaty)
    (mode : TrustMode)
    (view : AdmissionView) : Bool :=
  PredicateLang.synTreatyAdmitsUnderMode treaty mode view

abbrev BackwardRefines
    (new old : Constitution) (domain : List AdmissionView) : Prop :=
  PredicateLang.SynBackwardRefines new old domain

def amendmentAdmissible (candidate : AmendmentCandidate) : Prop :=
  PredicateLang.amendmentAdmissibleSyn candidate

def enactAmendment (delta : ConstitutionalDelta) : AmendmentVerdict :=
  PredicateLang.enactAmendmentSyn delta

def evaluateAmendment (candidate : AmendmentCandidate) : AmendmentVerdict :=
  PredicateLang.evaluateAmendmentSyn candidate

theorem treaty_admission_iff_predicate_intersection
    (treaty : BilateralTreaty) (view : AdmissionView) :
    treatyAdmits treaty view = true ↔
      treatyPredicateIntersection treaty view = true := by
  exact PredicateLang.synTreaty_admission_iff_predicate_intersection
    treaty view

theorem treaty_admission_stable_under_ladder_floor
    (treaty : BilateralTreaty)
    (mode : TrustMode)
    (view : AdmissionView)
    (hMode : mode.atLeast treaty.modeFloor = true) :
    treatyAdmitsUnderMode treaty mode view = treatyAdmits treaty view := by
  exact PredicateLang.synTreaty_admission_stable_under_ladder_floor
    treaty mode view hMode

theorem amendment_admissible_iff_backward_refinement
    (candidate : AmendmentCandidate) :
    amendmentAdmissible candidate ↔
      BackwardRefines candidate.new candidate.old candidate.domain := by
  exact PredicateLang.synAmendment_admissible_iff_backward_refinement candidate

theorem amendment_without_refinement_rejected
    (candidate : AmendmentCandidate)
    (hCheck : PredicateLang.refinesOnConstitution
      candidate.new candidate.old candidate.domain = false) :
    evaluateAmendment candidate = AmendmentVerdict.rejected := by
  exact PredicateLang.synAmendment_without_refinement_rejected candidate hCheck

end Chio.Treaty
