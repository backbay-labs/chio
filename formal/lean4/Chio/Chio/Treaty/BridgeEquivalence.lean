import Chio.Treaty.Intersection
import Chio.Treaty.IntersectionLegacy

set_option autoImplicit false

namespace Chio.Treaty.PredicateLang

/-- Lift syntax into the comparison-only closure representation. -/
def toClosure
    (constitution : SyntacticConstitution) : Chio.Treaty.Legacy.Constitution :=
  { predicates := constitution.predicates.map denote }

theorem bridge_pointwise
    (constitution : SyntacticConstitution) (view : AdmissionView) :
    Chio.Treaty.Legacy.constitutionAllows (toClosure constitution) view =
      admits constitution view := by
  unfold Chio.Treaty.Legacy.constitutionAllows
    Chio.Treaty.Legacy.allPredicates toClosure admits
  induction constitution.predicates with
  | nil => rfl
  | cons predicate rest ih => simp [ih]

/-- Domain-scoped refinement agrees in both representations. -/
theorem bridge_refinement_on_iff
    (new old : SyntacticConstitution) (domain : List AdmissionView) :
    SynBackwardRefines new old domain ↔
      Chio.Treaty.Legacy.BackwardRefinesOn
        (toClosure new) (toClosure old) domain := by
  constructor <;> intro hRefines view hMember hNew
  · rw [bridge_pointwise] at hNew ⊢
    exact hRefines view hMember hNew
  · rw [← bridge_pointwise] at hNew ⊢
    exact hRefines view hMember hNew

/-- Global refinement agrees in both representations. -/
theorem bridge_global_iff
    (new old : SyntacticConstitution) :
    GlobalSynBackwardRefines new old ↔
      Chio.Treaty.Legacy.BackwardRefines
        (toClosure new) (toClosure old) := by
  constructor <;> intro hRefines view hNew
  · rw [bridge_pointwise] at hNew ⊢
    exact hRefines view hNew
  · rw [← bridge_pointwise] at hNew ⊢
    exact hRefines view hNew

/-- Global syntactic refinement transports to the closure model. -/
theorem bridge_soundness
    (new old : SyntacticConstitution)
    (hRefines : GlobalSynBackwardRefines new old) :
    Chio.Treaty.Legacy.BackwardRefines
      (toClosure new) (toClosure old) :=
  (bridge_global_iff new old).mp hRefines

/-- A successful finite decision transports to the same closure domain. -/
theorem bridge_decidable_soundness
    (new old : SyntacticConstitution) (domain : List AdmissionView)
    (hCheck : refinesOnConstitution new old domain = true) :
    Chio.Treaty.Legacy.BackwardRefinesOn
      (toClosure new) (toClosure old) domain :=
  (bridge_refinement_on_iff new old domain).mp
    ((refinesOnConstitution_complete_on_fragment new old domain).mp hCheck)

def toClosureScope
    (scope : Predicate) : Chio.Treaty.Legacy.PolityScope :=
  { contains := denote scope }

def toClosurePolity
    (polity : SyntacticPolity) : Chio.Treaty.Legacy.Polity :=
  {
    scope := toClosureScope polity.scope
    constitution := toClosure polity.constitution
  }

def toClosureTreaty
    (treaty : SyntacticBilateralTreaty) :
    Chio.Treaty.Legacy.BilateralTreaty :=
  {
    scope := toClosureScope treaty.scope
    constitution := toClosure treaty.constitution
    left := toClosurePolity treaty.left
    right := toClosurePolity treaty.right
    modeFloor := treaty.modeFloor
  }

theorem toClosure_polityAdmits_agrees
    (polity : SyntacticPolity) (view : AdmissionView) :
    Chio.Treaty.Legacy.polityAdmits (toClosurePolity polity) view =
      synPolityAdmits polity view := by
  simp [Chio.Treaty.Legacy.polityAdmits, toClosurePolity,
    toClosureScope, synPolityAdmits, bridge_pointwise]

theorem toClosure_treatyAdmits_agrees
    (treaty : SyntacticBilateralTreaty) (view : AdmissionView) :
    Chio.Treaty.Legacy.treatyAdmits (toClosureTreaty treaty) view =
      synTreatyAdmits treaty view := by
  simp [Chio.Treaty.Legacy.treatyAdmits, toClosureTreaty,
    toClosureScope, Chio.Treaty.Legacy.polityAdmits, toClosurePolity,
    synTreatyAdmits, synPolityAdmits, bridge_pointwise]

def toClosureAmendmentCandidate
    (candidate : AmendmentCandidateSyn) :
    Chio.Treaty.Legacy.AmendmentCandidate :=
  {
    old := toClosure candidate.old
    new := toClosure candidate.new
    domain := candidate.domain
    proofPresent :=
      refinesOnConstitution candidate.new candidate.old candidate.domain
    proofTerm := fun hPresent =>
      bridge_decidable_soundness
        candidate.new candidate.old candidate.domain hPresent
  }

theorem toClosure_amendmentVerdict_agrees
    (candidate : AmendmentCandidateSyn) :
    Chio.Treaty.Legacy.evaluateAmendment
        (toClosureAmendmentCandidate candidate) =
      evaluateAmendmentSyn candidate := by
  change (if refinesOnConstitution
      candidate.new candidate.old candidate.domain then
        Chio.Treaty.AmendmentVerdict.enacted
      else Chio.Treaty.AmendmentVerdict.rejected) =
    evaluateAmendmentSyn candidate
  cases hCheck : refinesOnConstitution
      candidate.new candidate.old candidate.domain <;>
    simp [evaluateAmendmentSyn, ConstitutionalDeltaSyn.ofDecide,
      enactAmendmentSyn, hCheck]

end Chio.Treaty.PredicateLang

namespace Chio.Treaty.BridgeEquivalence.Legacy

open Chio.Treaty.PredicateLang

/-- Pointwise polity equivalence over an `AdmissionView`. -/
theorem polity_admission_agrees
    (polity : SyntacticPolity) (view : AdmissionView) :
    Chio.Treaty.Legacy.polityAdmits (toClosurePolity polity) view =
      synPolityAdmits polity view :=
  toClosure_polityAdmits_agrees polity view

/-- Pointwise treaty equivalence over an `AdmissionView`. -/
theorem treaty_admission_agrees
    (treaty : SyntacticBilateralTreaty) (view : AdmissionView) :
    Chio.Treaty.Legacy.treatyAdmits (toClosureTreaty treaty) view =
      synTreatyAdmits treaty view :=
  toClosure_treatyAdmits_agrees treaty view

/-- The syntactic and closure treaty models use the same mode-floor gate. -/
theorem treaty_admission_under_mode_agrees
    (treaty : SyntacticBilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (view : AdmissionView) :
    Chio.Treaty.Legacy.treatyAdmitsUnderMode
        (toClosureTreaty treaty) mode view =
      synTreatyAdmitsUnderMode treaty mode view := by
  unfold Chio.Treaty.Legacy.treatyAdmitsUnderMode
    synTreatyAdmitsUnderMode
  rw [toClosure_treatyAdmits_agrees]
  rfl

/-- A checked delta is sound exactly on its supplied finite domain. -/
theorem bounded_amendment_sound
    (delta : ConstitutionalDeltaSyn) :
    Chio.Treaty.Legacy.BackwardRefinesOn
      (toClosure delta.new) (toClosure delta.old) delta.domain :=
  (bridge_refinement_on_iff delta.new delta.old delta.domain).mp
    delta.proofTerm

end Chio.Treaty.BridgeEquivalence.Legacy
