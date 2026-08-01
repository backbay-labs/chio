/-
  Executable receipt-predicate model used by the bilateral-admission paper.

  The records and constructors match the bounded Rust evaluator and its
  independent Rust reference model. Parsing, size limits, canonical JSON,
  cryptography, clocks, storage, and construction of the receipt view remain
  outside this Lean model.
-/

set_option autoImplicit false

namespace Chio.Treaty.ReceiptPredicate

inductive AdmissionDecision where
  | allow
  | deny
  deriving Repr, BEq, DecidableEq, Inhabited

structure EvidenceDigest where
  evidenceClass : String
  digest : String
  deriving Repr, BEq, DecidableEq, Inhabited

structure ReceiptView where
  receiptId : String
  receiptHash : String
  actionClass : String
  participantKernelIds : List String
  ladderModeRank : Nat
  liveContinuationIds : List String
  decision : AdmissionDecision
  failureCode : Option String
  evidenceDigests : List EvidenceDigest
  deriving Repr, BEq, DecidableEq, Inhabited

inductive Atom where
  | scopeContains (target : String)
  | participantKernelIdEquals (kernelId : String)
  | actionClassIn (actionClass : String)
  | ladderModeAtLeastRank (rank : Nat)
  | receiptHashEquals (hash : String)
  | continuationLive (continuationId : String)
  | decisionEquals (decision : AdmissionDecision)
  | failureCodeEquals (code : String)
  | evidenceDigestEquals (evidenceClass digest : String)
  deriving Repr, BEq, DecidableEq, Inhabited

inductive Predicate where
  | atom (atom : Atom)
  | top
  | bot
  | conj (left right : Predicate)
  | disj (left right : Predicate)
  | neg (predicate : Predicate)
  deriving Repr, BEq, DecidableEq, Inhabited

def evaluateAtom (atom : Atom) (receipt : ReceiptView) : Bool :=
  match atom with
  | .scopeContains target => receipt.receiptId == target
  | .participantKernelIdEquals kernelId =>
      receipt.participantKernelIds.elem kernelId
  | .actionClassIn actionClass => receipt.actionClass == actionClass
  | .ladderModeAtLeastRank rank => decide (rank ≤ receipt.ladderModeRank)
  | .receiptHashEquals hash => receipt.receiptHash == hash
  | .continuationLive continuationId =>
      receipt.liveContinuationIds.elem continuationId
  | .decisionEquals decision => receipt.decision == decision
  | .failureCodeEquals code => receipt.failureCode == some code
  | .evidenceDigestEquals evidenceClass digest =>
      receipt.evidenceDigests.any (fun evidence =>
        evidence.evidenceClass == evidenceClass &&
          evidence.digest == digest)

def evaluate : Predicate -> ReceiptView -> Bool
  | .atom atom, receipt => evaluateAtom atom receipt
  | .top, _ => true
  | .bot, _ => false
  | .conj left right, receipt =>
      evaluate left receipt && evaluate right receipt
  | .disj left right, receipt =>
      evaluate left receipt || evaluate right receipt
  | .neg predicate, receipt => !(evaluate predicate receipt)

structure Constitution where
  predicates : List Predicate
  deriving Repr, BEq, DecidableEq, Inhabited

def admits (constitution : Constitution) (receipt : ReceiptView) : Bool :=
  constitution.predicates.all (fun predicate => evaluate predicate receipt)

def refinesOn
    (new old : Constitution) (domain : List ReceiptView) : Bool :=
  domain.all (fun receipt =>
    decide (!(admits new receipt) || admits old receipt))

def RefinesOn
    (new old : Constitution) (domain : List ReceiptView) : Prop :=
  forall receipt, receipt ∈ domain ->
    admits new receipt = true -> admits old receipt = true

theorem finite_refinement_sound
    (new old : Constitution)
    (domain : List ReceiptView)
    (hCheck : refinesOn new old domain = true) :
    RefinesOn new old domain := by
  intro receipt hMember hNew
  have hAtReceipt := List.all_eq_true.mp hCheck receipt hMember
  simpa [hNew] using hAtReceipt

theorem finite_refinement_exact
    (new old : Constitution)
    (domain : List ReceiptView) :
    refinesOn new old domain = true ↔ RefinesOn new old domain := by
  constructor
  · exact finite_refinement_sound new old domain
  · intro hRefines
    apply List.all_eq_true.mpr
    intro receipt hMember
    cases hNew : admits new receipt
    · simp
    · simpa using hRefines receipt hMember hNew

end Chio.Treaty.ReceiptPredicate
