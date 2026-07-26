/-
  Legacy closure model for the programmable-sovereignty paper.

  The production treaty verifier is Rust code. This Lean file captures the
  paper's mathematical core: treaty admission is the intersection of treaty,
  left-polity, and right-polity predicates; ladder-mode checks compose with
  that intersection; amendment enactment requires a backward-refinement proof.

  Constitutions here contain opaque closures. Universal implication between
  such closures is not decidable. New paper claims use
  `Treaty/IntersectionSyntactic.lean`, whose finite predicate language and
  declared receipt domain make the bounded decision procedure explicit. This
  module remains as the semantic target of the pointwise bridge.
-/

set_option autoImplicit false

namespace Chio.Treaty

abbrev ReceiptId := String

structure PolityScope where
  contains : ReceiptId -> Bool

structure Constitution where
  predicates : List (ReceiptId -> Bool)

structure Polity where
  scope : PolityScope
  constitution : Constitution

inductive TrustMode where
  | observation
  | guarded
  | receiptBacked
  | partitionContingency
  | quorumRequired
  deriving Repr, BEq, DecidableEq

def TrustMode.rank : TrustMode -> Nat
  | .observation => 0
  | .guarded => 1
  | .receiptBacked => 2
  | .partitionContingency => 3
  | .quorumRequired => 4

def TrustMode.atLeast (mode floor : TrustMode) : Bool :=
  floor.rank <= mode.rank

structure BilateralTreaty where
  scope : PolityScope
  constitution : Constitution
  left : Polity
  right : Polity
  modeFloor : TrustMode

def allPredicates (predicates : List (ReceiptId -> Bool)) (receipt : ReceiptId) : Bool :=
  predicates.all (fun predicate => predicate receipt)

def constitutionAllows (constitution : Constitution) (receipt : ReceiptId) : Bool :=
  allPredicates constitution.predicates receipt

def polityAdmits (polity : Polity) (receipt : ReceiptId) : Bool :=
  polity.scope.contains receipt && constitutionAllows polity.constitution receipt

def treatyPredicateIntersection (treaty : BilateralTreaty) (receipt : ReceiptId) : Bool :=
  treaty.scope.contains receipt
    && constitutionAllows treaty.constitution receipt
    && treaty.left.scope.contains receipt
    && constitutionAllows treaty.left.constitution receipt
    && treaty.right.scope.contains receipt
    && constitutionAllows treaty.right.constitution receipt

def treatyAdmits (treaty : BilateralTreaty) (receipt : ReceiptId) : Bool :=
  treaty.scope.contains receipt
    && constitutionAllows treaty.constitution receipt
    && polityAdmits treaty.left receipt
    && polityAdmits treaty.right receipt

def treatyAdmitsUnderMode
    (treaty : BilateralTreaty)
    (mode : TrustMode)
    (receipt : ReceiptId) : Bool :=
  mode.atLeast treaty.modeFloor && treatyAdmits treaty receipt

abbrev BackwardRefines (new old : Constitution) : Prop :=
  forall receipt : ReceiptId,
    constitutionAllows new receipt = true -> constitutionAllows old receipt = true

structure ConstitutionalDelta where
  old : Constitution
  new : Constitution
  proofTerm : BackwardRefines new old

structure AmendmentCandidate where
  old : Constitution
  new : Constitution
  proofPresent : Bool
  proofTerm : proofPresent = true -> BackwardRefines new old

def amendmentAdmissible (candidate : AmendmentCandidate) : Prop :=
  candidate.proofPresent = true

inductive AmendmentVerdict where
  | enacted
  | rejected
  deriving Repr, BEq, DecidableEq

/--
  Enactment requires a `ConstitutionalDelta`, which by construction carries
  `proofTerm : BackwardRefines new old`. The type system enforces that
  `.enacted` cannot be produced without the refinement witness; there is no
  Boolean knob for a trusted caller to lie about whether the proof exists.
-/
def enactAmendment (_delta : ConstitutionalDelta) : AmendmentVerdict := .enacted

/--
  Rejection is independent of the refinement witness and is always available:
  an amendment without a constructable `ConstitutionalDelta` is rejected.
-/
def rejectAmendment : AmendmentVerdict := .rejected

def evaluateAmendment (candidate : AmendmentCandidate) : AmendmentVerdict :=
  if candidate.proofPresent then .enacted else .rejected

theorem treaty_admission_iff_predicate_intersection
    (treaty : BilateralTreaty)
    (receipt : ReceiptId) :
    treatyAdmits treaty receipt = true
      ↔ treatyPredicateIntersection treaty receipt = true := by
  cases treaty with
  | mk scope constitution left right modeFloor =>
      cases left with
      | mk leftScope leftConstitution =>
          cases right with
          | mk rightScope rightConstitution =>
              unfold treatyAdmits treatyPredicateIntersection polityAdmits
              simp [Bool.and_assoc]

theorem treaty_admission_stable_under_ladder_floor
    (treaty : BilateralTreaty)
    (mode : TrustMode)
    (receipt : ReceiptId)
    (h_mode : mode.atLeast treaty.modeFloor = true) :
    treatyAdmitsUnderMode treaty mode receipt = treatyAdmits treaty receipt := by
  simp [treatyAdmitsUnderMode, h_mode]

theorem amendment_admissible_iff_backward_refinement
    (candidate : AmendmentCandidate) :
    amendmentAdmissible candidate ↔
      candidate.proofPresent = true ∧ BackwardRefines candidate.new candidate.old := by
  constructor
  · intro h
    exact ⟨h, candidate.proofTerm h⟩
  · intro h
    exact h.1

theorem amendment_without_refinement_rejected
    (old new : Constitution) :
    evaluateAmendment {
      old := old,
      new := new,
      proofPresent := false,
      proofTerm := by
        intro h
        cases h
    } =
      AmendmentVerdict.rejected := by
  rfl

end Chio.Treaty
