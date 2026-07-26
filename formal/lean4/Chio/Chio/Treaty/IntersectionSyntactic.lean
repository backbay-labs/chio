/-
  Decidable bounded treaty and amendment model.

  Unlike the legacy closure model, this module represents scope and
  constitutional rules with `PredicateLang.Predicate`. Admission is executable
  on an explicit `ReceiptView`. Amendment refinement is decidable on the
  declared finite receipt domain carried by the delta.

  The finite-domain boundary is part of every amendment statement. Nothing in
  this module claims that checking one finite domain proves refinement for all
  possible receipts.
-/

import Chio.Treaty.PredicateLang

set_option autoImplicit false

namespace Chio.Treaty.IntersectionSyntactic

open Chio.Treaty.PredicateLang

/-- Submission polity: receipt scope plus constitutional predicates. -/
structure Polity where
  scope : Predicate
  constitution : SyntacticConstitution
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Bilateral treaty over two independently declared polity predicates. -/
structure BilateralTreaty where
  scope : Predicate
  constitution : SyntacticConstitution
  left : Polity
  right : Polity
  modeFloor : Chio.Treaty.TrustMode
  deriving Repr, BEq, DecidableEq

/-- One polity admits when its scope and constitution both accept. -/
def polityAdmits (polity : Polity) (receipt : ReceiptView) : Bool :=
  denote polity.scope receipt && admits polity.constitution receipt

/-- Fully expanded conjunction used as the treaty-intersection specification. -/
def treatyPredicateIntersection
    (treaty : BilateralTreaty) (receipt : ReceiptView) : Bool :=
  denote treaty.scope receipt &&
    admits treaty.constitution receipt &&
    denote treaty.left.scope receipt &&
    admits treaty.left.constitution receipt &&
    denote treaty.right.scope receipt &&
    admits treaty.right.constitution receipt

/-- Treaty admission grouped through each participant's local admission. -/
def treatyAdmits
    (treaty : BilateralTreaty) (receipt : ReceiptView) : Bool :=
  denote treaty.scope receipt &&
    admits treaty.constitution receipt &&
    polityAdmits treaty.left receipt &&
    polityAdmits treaty.right receipt

/-- Ladder floor composed with treaty admission. -/
def treatyAdmitsUnderMode
    (treaty : BilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (receipt : ReceiptView) : Bool :=
  mode.atLeast treaty.modeFloor && treatyAdmits treaty receipt

/-- Bounded amendment delta carrying its checked receipt domain. -/
structure ConstitutionalDelta where
  old : SyntacticConstitution
  new : SyntacticConstitution
  domain : List ReceiptView
  proofTerm : refinesOnConstitution new old domain = true

namespace ConstitutionalDelta

/-- Smart constructor for a decision-procedure-produced refinement witness. -/
def ofDecide
    (old new : SyntacticConstitution)
    (domain : List ReceiptView)
    (proofTerm : refinesOnConstitution new old domain = true) :
    ConstitutionalDelta :=
  { old, new, domain, proofTerm }

end ConstitutionalDelta

/-- Candidate form used to make rejection without a witness explicit. -/
structure AmendmentCandidate where
  old : SyntacticConstitution
  new : SyntacticConstitution
  domain : List ReceiptView
  proofPresent : Bool
  proofTerm :
    proofPresent = true ->
      refinesOnConstitution new old domain = true

inductive AmendmentVerdict where
  | enacted
  | rejected
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Enactment is constructable only from a bounded refinement delta. -/
def enactAmendment (_delta : ConstitutionalDelta) : AmendmentVerdict :=
  .enacted

/-- A candidate without its bounded witness follows the rejection path. -/
def evaluateAmendment (candidate : AmendmentCandidate) : AmendmentVerdict :=
  if candidate.proofPresent then .enacted else .rejected

def amendmentAdmissible (candidate : AmendmentCandidate) : Prop :=
  candidate.proofPresent = true

/-- Treaty admission equals the explicit six-conjunct intersection. -/
theorem treaty_admission_iff_predicate_intersection
    (treaty : BilateralTreaty)
    (receipt : ReceiptView) :
    treatyAdmits treaty receipt = true ↔
      treatyPredicateIntersection treaty receipt = true := by
  cases treaty with
  | mk scope constitution left right modeFloor =>
      cases left with
      | mk leftScope leftConstitution =>
          cases right with
          | mk rightScope rightConstitution =>
              unfold treatyAdmits treatyPredicateIntersection polityAdmits
              simp [Bool.and_assoc]

/-- A satisfied ladder floor reduces admission to the treaty predicate. -/
theorem treaty_admission_stable_under_ladder_floor
    (treaty : BilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (receipt : ReceiptView)
    (hMode : mode.atLeast treaty.modeFloor = true) :
    treatyAdmitsUnderMode treaty mode receipt =
      treatyAdmits treaty receipt := by
  simp [treatyAdmitsUnderMode, hMode]

/--
  Candidate admissibility supplies semantic no-widening on every receipt in
  the candidate's declared finite domain.
-/
theorem amendment_admissible_iff_bounded_refinement
    (candidate : AmendmentCandidate) :
    amendmentAdmissible candidate ↔
      candidate.proofPresent = true ∧
      SynBackwardRefinesOn candidate.new candidate.old candidate.domain := by
  constructor
  · intro hPresent
    exact ⟨hPresent, bridge_decidable_soundness
      candidate.new candidate.old candidate.domain
      (candidate.proofTerm hPresent)⟩
  · intro h
    exact h.1

/-- Missing proof presence is rejected by construction. -/
theorem amendment_without_refinement_rejected
    (old new : SyntacticConstitution)
    (domain : List ReceiptView) :
    evaluateAmendment {
      old := old,
      new := new,
      domain := domain,
      proofPresent := false,
      proofTerm := by
        intro h
        cases h
    } = AmendmentVerdict.rejected := by
  rfl

private def exampleReceipt : ReceiptView :=
  {
    receiptId := "receipt-example"
    receiptHash := "hash-example"
    actionClass := "destructive"
    participantKernelIds := ["kernel-a", "kernel-b"]
    ladderModeRank := 4
    liveContinuationIds := ["continuation-example"]
    decision := .allow
    failureCode := none
    evidenceDigests := [
      { evidenceClass := "bilateral_dsse", digest := "digest-example" }
    ]
  }

private def exampleOld : SyntacticConstitution :=
  { predicates := [.top] }

private def exampleNarrower : SyntacticConstitution :=
  {
    predicates := [
      .atom (.actionClassIn "destructive"),
      .atom (.ladderModeAtLeastRank 2)
    ]
  }

/-- Executable documentation: a nontrivial bounded narrowing is constructable. -/
example : AmendmentVerdict :=
  enactAmendment <| ConstitutionalDelta.ofDecide
    exampleOld
    exampleNarrower
    [exampleReceipt]
    (by decide)

/-- Executable documentation: widening beyond the old rule fails on-domain. -/
example :
    refinesOnConstitution
      exampleOld
      exampleNarrower
      [{
        exampleReceipt with
        actionClass := "read_only"
      }] = false := by
  decide

end Chio.Treaty.IntersectionSyntactic
