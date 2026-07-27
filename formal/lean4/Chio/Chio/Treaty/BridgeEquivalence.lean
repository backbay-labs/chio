/-
  Pointwise equivalence between syntactic treaty admission and the legacy
  closure model.

  The bridge is parameterized by a resolver from legacy receipt identifiers to
  explicit bounded receipt views. It proves that lifting changes
  representation, not the admission decision. Amendment refinement remains
  explicitly bounded in `IntersectionSyntactic`; this module does not convert a
  finite-domain witness into a universal closure witness.
-/

import Chio.Treaty.IntersectionSyntactic

set_option autoImplicit false

namespace Chio.Treaty.BridgeEquivalence

namespace Legacy

open Chio.Treaty.PredicateLang
open Chio.Treaty.IntersectionSyntactic

def toScope
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (scope : Predicate) : Chio.Treaty.PolityScope :=
  { contains := fun receiptId => denote scope (resolve receiptId) }

def toPolity
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (polity : IntersectionSyntactic.Polity) :
    Chio.Treaty.Polity :=
  {
    scope := toScope resolve polity.scope
    constitution := toClosure resolve polity.constitution
  }

def toTreaty
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (treaty : IntersectionSyntactic.BilateralTreaty) :
    Chio.Treaty.BilateralTreaty :=
  {
    scope := toScope resolve treaty.scope
    constitution := toClosure resolve treaty.constitution
    left := toPolity resolve treaty.left
    right := toPolity resolve treaty.right
    modeFloor := treaty.modeFloor
  }

theorem scope_pointwise
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (scope : Predicate)
    (receiptId : Chio.Treaty.ReceiptId) :
    (toScope resolve scope).contains receiptId =
      denote scope (resolve receiptId) := by
  rfl

theorem polity_admission_agrees
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (polity : IntersectionSyntactic.Polity)
    (receiptId : Chio.Treaty.ReceiptId) :
    Chio.Treaty.polityAdmits (toPolity resolve polity) receiptId =
      IntersectionSyntactic.polityAdmits polity (resolve receiptId) := by
  simp [Chio.Treaty.polityAdmits, IntersectionSyntactic.polityAdmits,
    toPolity, toScope, bridge_pointwise]

theorem treaty_admission_agrees
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (treaty : IntersectionSyntactic.BilateralTreaty)
    (receiptId : Chio.Treaty.ReceiptId) :
    Chio.Treaty.treatyAdmits (toTreaty resolve treaty) receiptId =
      IntersectionSyntactic.treatyAdmits treaty (resolve receiptId) := by
  simp [Chio.Treaty.treatyAdmits,
    IntersectionSyntactic.treatyAdmits,
    toTreaty, toScope, polity_admission_agrees, bridge_pointwise]

theorem treaty_admission_under_mode_agrees
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (treaty : IntersectionSyntactic.BilateralTreaty)
    (mode : Chio.Treaty.TrustMode)
    (receiptId : Chio.Treaty.ReceiptId) :
    Chio.Treaty.treatyAdmitsUnderMode
        (toTreaty resolve treaty) mode receiptId =
      IntersectionSyntactic.treatyAdmitsUnderMode
        treaty mode (resolve receiptId) := by
  unfold Chio.Treaty.treatyAdmitsUnderMode
    IntersectionSyntactic.treatyAdmitsUnderMode
  change
    (mode.atLeast treaty.modeFloor &&
      Chio.Treaty.treatyAdmits (toTreaty resolve treaty) receiptId) =
    (mode.atLeast treaty.modeFloor &&
      IntersectionSyntactic.treatyAdmits treaty (resolve receiptId))
  rw [treaty_admission_agrees]

/--
  The decision procedure establishes semantic refinement for every member of
  its declared domain, and no receipt outside that domain is claimed.
-/
theorem bounded_amendment_sound
    (delta : IntersectionSyntactic.ConstitutionalDelta) :
    SynBackwardRefinesOn delta.new delta.old delta.domain :=
  bridge_decidable_soundness
    delta.new delta.old delta.domain delta.proofTerm

end Legacy

end Chio.Treaty.BridgeEquivalence
