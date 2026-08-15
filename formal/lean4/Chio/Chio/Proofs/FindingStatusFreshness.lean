/-
  Finding-status freshness and rollback model.

  This bounded model captures the pure decision rules used by the M6
  finding-status verifier. Cryptographic signature, canonical JSON, sparse
  path, and durable-storage correctness remain implementation checks and
  audited assumptions. The model proves the two roadmap properties:

  * a root that advances a durable feed floor has a strictly greater map
    epoch; and
  * an accepted non-inclusion proof is never checked after `validUntil`.

  It also models same-epoch equivocation and sticky pending/retracted state.
-/

set_option autoImplicit false

namespace Chio.Proofs.FindingStatusFreshness

/-- Opaque signed-root identity projected into the bounded model. -/
structure EpochIdentity where
  mapEpoch : Nat
  epochId : Nat
  rootHash : Nat
deriving DecidableEq, Repr

/-- Result of comparing exact verified signed epoch bytes with a durable
    floor. Exact same-epoch replay is idempotent, while any changed identity
    at the same epoch is equivocation. -/
inductive EpochInstallVerdict
  | advanced
  | replayed
  | rejected
deriving DecidableEq, Repr

/-- Pure model of the durable `(map_epoch, epoch_id, root_hash)` gate. -/
def installEpoch (floor candidate : EpochIdentity) : EpochInstallVerdict :=
  if floor.mapEpoch < candidate.mapEpoch then
    EpochInstallVerdict.advanced
  else if floor = candidate then
    EpochInstallVerdict.replayed
  else
    EpochInstallVerdict.rejected

/-- Any root that advances the floor has a strictly greater map epoch. -/
theorem epoch_advance_is_strict
    (floor candidate : EpochIdentity)
    (h : installEpoch floor candidate = EpochInstallVerdict.advanced) :
    floor.mapEpoch < candidate.mapEpoch := by
  unfold installEpoch at h
  by_cases h_epoch : floor.mapEpoch < candidate.mapEpoch
  · exact h_epoch
  · by_cases h_same : floor = candidate
    · simp [h_same] at h
    · simp [h_epoch, h_same] at h

/-- Reusing a map epoch with another signed id or root is rejected. -/
theorem same_epoch_equivocation_rejected
    (floor candidate : EpochIdentity)
    (h_epoch : floor.mapEpoch = candidate.mapEpoch)
    (h_identity : floor ≠ candidate) :
    installEpoch floor candidate = EpochInstallVerdict.rejected := by
  unfold installEpoch
  have h_not_newer : ¬ floor.mapEpoch < candidate.mapEpoch := by
    omega
  simp [h_not_newer, h_identity]

/-- Sticky local status observed by a kernel or buyer. -/
inductive StickyStatus
  | live
  | pending
  | retracted
deriving DecidableEq, Repr

/-- Security-relevant projection of a portable non-inclusion input after raw
    parsing. Each Boolean represents a production verification boundary. -/
structure NonInclusionInput where
  signedEpochValid : Bool
  operatorAuthorized : Bool
  pathValid : Bool
  bindingsValid : Bool
  generatedAt : Nat
  checkedAt : Nat
  validFrom : Nat
  validUntil : Nat
deriving DecidableEq, Repr

/-- Bounded M6 non-inclusion decision. Pending and retracted observations are
    sticky and therefore cannot be cleared by another absence proof. -/
def admitsNonInclusion
    (sticky : StickyStatus)
    (now maxAge : Nat)
    (proof : NonInclusionInput) : Bool :=
  sticky == StickyStatus.live
    && proof.signedEpochValid
    && proof.operatorAuthorized
    && proof.pathValid
    && proof.bindingsValid
    && decide (0 < maxAge)
    && decide (proof.generatedAt <= proof.checkedAt)
    && decide (proof.validFrom <= proof.checkedAt)
    && decide (proof.checkedAt < proof.validUntil)
    && decide (proof.checkedAt <= now)
    && decide (proof.validFrom <= now)
    && decide (now < proof.validUntil)
    && decide (now <= proof.generatedAt + maxAge)
    && decide (now <= proof.checkedAt + maxAge)

/-- An admitted non-inclusion proof is not accepted past its signed validity
    bound. -/
theorem admitted_non_inclusion_not_past_valid_until
    (sticky : StickyStatus)
    (now maxAge : Nat)
    (proof : NonInclusionInput)
    (h : admitsNonInclusion sticky now maxAge proof = true) :
    now < proof.validUntil := by
  unfold admitsNonInclusion at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  omega

/-- The carrier timestamp is also strictly inside the signed validity
    window, matching the production verifier's half-open interval. -/
theorem admitted_non_inclusion_checked_before_valid_until
    (sticky : StickyStatus)
    (now maxAge : Nat)
    (proof : NonInclusionInput)
    (h : admitsNonInclusion sticky now maxAge proof = true) :
    proof.checkedAt < proof.validUntil := by
  unfold admitsNonInclusion at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  omega

/-- A locally pending retraction always denies a contradictory absence
    proof. -/
theorem pending_never_accepts_non_inclusion
    (now maxAge : Nat) (proof : NonInclusionInput) :
    admitsNonInclusion StickyStatus.pending now maxAge proof = false := by
  simp [admitsNonInclusion]

/-- A locally observed retraction always denies a contradictory absence
    proof. -/
theorem retracted_never_accepts_non_inclusion
    (now maxAge : Nat) (proof : NonInclusionInput) :
    admitsNonInclusion StickyStatus.retracted now maxAge proof = false := by
  simp [admitsNonInclusion]

end Chio.Proofs.FindingStatusFreshness
