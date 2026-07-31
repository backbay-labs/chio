/-
  Bounded delivery-contract settlement admission.

  This model isolates the two evidence gates used by the cognition-market
  delivery path:

  * a purchase-marked call must carry a verified finding purchase before
    delivery; and
  * a digest-constrained call must match the committed output digest after
    delivery.

  The digest domain is deliberately finite. Its four constructors stand for
  opaque, already-validated digest identities. The model does not implement
  SHA-256, canonical JSON, signatures, persistence, or external settlement.
  `SettlementGate.admit` means only that the bounded kernel decision permits
  the existing settlement machinery to continue.

  M3 implements the digest comparison and `deniedAfterDelivery` terminal.
  The finding-purchase input records the composition boundary supplied by M4;
  this module is a bounded decision model, not a refinement proof for either
  Rust implementation.
-/

set_option autoImplicit false

namespace Chio.Proofs.DeliveryContract

/-- Four opaque digest identities keep the decision model finite. -/
inductive Digest
  | d0
  | d1
  | d2
  | d3
deriving DecidableEq, Repr

/-- Evidence requirements recovered from the selected capability grant. -/
structure Requirements where
  requiresFindingPurchase : Bool
  requiresOutputDigest : Bool
deriving DecidableEq, Repr

/-- Kernel-verified evidence available at the delivery boundary. -/
structure Evidence where
  findingPurchaseVerified : Bool
  expectedDigest : Digest
  observedDigest : Digest
deriving DecidableEq, Repr

/-- The bounded terminal classes relevant to delivery settlement. -/
inductive Decision
  | allow
  | denyBeforeDelivery
  | deniedAfterDelivery
deriving DecidableEq, Repr

/-- Whether the bounded decision permits settlement processing to continue. -/
inductive SettlementGate
  | admit
  | block
deriving DecidableEq, Repr

/-- Coupled decision and settlement gate returned by the bounded finalizer. -/
structure Finalization where
  decision : Decision
  settlement : SettlementGate
deriving DecidableEq, Repr

/-- A required purchase is satisfied only by kernel-verified purchase evidence. -/
def findingPurchaseSatisfied (requirements : Requirements) (evidence : Evidence) : Bool :=
  !requirements.requiresFindingPurchase || evidence.findingPurchaseVerified

/-- A required digest is satisfied only when expected and observed identities match. -/
def outputDigestSatisfied (requirements : Requirements) (evidence : Evidence) : Bool :=
  !requirements.requiresOutputDigest || decide (evidence.expectedDigest = evidence.observedDigest)

/--
  Fail-closed bounded finalization. Missing purchase evidence rejects before
  delivery. A digest mismatch reaches the distinct post-delivery denial. Only
  an Allow opens the settlement gate.
-/
def finalize (requirements : Requirements) (evidence : Evidence) : Finalization :=
  if findingPurchaseSatisfied requirements evidence = false then
    { decision := Decision.denyBeforeDelivery, settlement := SettlementGate.block }
  else if outputDigestSatisfied requirements evidence = false then
    { decision := Decision.deniedAfterDelivery, settlement := SettlementGate.block }
  else
    { decision := Decision.allow, settlement := SettlementGate.admit }

/--
  Headline soundness result. Settlement admission is possible only on Allow,
  and every required finding-purchase or output-digest check is satisfied.
-/
theorem settlement_admission_requires_verified_evidence
    (requirements : Requirements) (evidence : Evidence)
    (h_settlement : (finalize requirements evidence).settlement = SettlementGate.admit) :
    (finalize requirements evidence).decision = Decision.allow ∧
      (requirements.requiresFindingPurchase = true ->
        evidence.findingPurchaseVerified = true) ∧
      (requirements.requiresOutputDigest = true ->
        evidence.expectedDigest = evidence.observedDigest) := by
  rcases requirements with ⟨requiresPurchase, requiresDigest⟩
  rcases evidence with ⟨purchaseVerified, expected, observed⟩
  cases requiresPurchase <;>
    cases requiresDigest <;>
      cases purchaseVerified <;>
        cases expected <;>
          cases observed <;>
            simp_all [finalize, findingPurchaseSatisfied, outputDigestSatisfied]

/-- An Allow also implies every evidence requirement is satisfied. -/
theorem allow_requires_verified_evidence
    (requirements : Requirements) (evidence : Evidence)
    (h_allow : (finalize requirements evidence).decision = Decision.allow) :
    (requirements.requiresFindingPurchase = true ->
      evidence.findingPurchaseVerified = true) ∧
    (requirements.requiresOutputDigest = true ->
      evidence.expectedDigest = evidence.observedDigest) := by
  rcases requirements with ⟨requiresPurchase, requiresDigest⟩
  rcases evidence with ⟨purchaseVerified, expected, observed⟩
  cases requiresPurchase <;>
    cases requiresDigest <;>
      cases purchaseVerified <;>
        cases expected <;>
          cases observed <;>
            simp_all [finalize, findingPurchaseSatisfied, outputDigestSatisfied]

/-- A reachable post-delivery denial never opens the settlement gate. -/
theorem denied_after_delivery_cannot_settle
    (requirements : Requirements) (evidence : Evidence)
    (h_denied :
      (finalize requirements evidence).decision = Decision.deniedAfterDelivery) :
    (finalize requirements evidence).settlement = SettlementGate.block := by
  rcases requirements with ⟨requiresPurchase, requiresDigest⟩
  rcases evidence with ⟨purchaseVerified, expected, observed⟩
  cases requiresPurchase <;>
    cases requiresDigest <;>
      cases purchaseVerified <;>
        cases expected <;>
          cases observed <;>
            simp_all [finalize, findingPurchaseSatisfied, outputDigestSatisfied]

/-- Negative case: a missing required purchase rejects before delivery. -/
theorem missing_required_purchase_rejects_before_delivery :
    finalize
      { requiresFindingPurchase := true, requiresOutputDigest := true }
      { findingPurchaseVerified := false
        expectedDigest := Digest.d0
        observedDigest := Digest.d1 } =
      { decision := Decision.denyBeforeDelivery, settlement := SettlementGate.block } := by
  rfl

/-- Negative M3 case: a generic required digest mismatch denies after delivery. -/
theorem generic_required_digest_mismatch_denies_after_delivery :
    finalize
      { requiresFindingPurchase := false, requiresOutputDigest := true }
      { findingPurchaseVerified := false
        expectedDigest := Digest.d0
        observedDigest := Digest.d1 } =
      { decision := Decision.deniedAfterDelivery, settlement := SettlementGate.block } := by
  rfl

/-- Negative case: verified purchase plus digest mismatch denies after delivery. -/
theorem required_digest_mismatch_denies_after_delivery :
    finalize
      { requiresFindingPurchase := true, requiresOutputDigest := true }
      { findingPurchaseVerified := true
        expectedDigest := Digest.d0
        observedDigest := Digest.d1 } =
      { decision := Decision.deniedAfterDelivery, settlement := SettlementGate.block } := by
  rfl

/-- Positive witness: both verified requirements admit settlement. -/
theorem verified_purchase_and_digest_match_admits_settlement :
    finalize
      { requiresFindingPurchase := true, requiresOutputDigest := true }
      { findingPurchaseVerified := true
        expectedDigest := Digest.d0
        observedDigest := Digest.d0 } =
      { decision := Decision.allow, settlement := SettlementGate.admit } := by
  rfl

end Chio.Proofs.DeliveryContract
