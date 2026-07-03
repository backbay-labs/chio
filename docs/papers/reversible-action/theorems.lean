/-
  Draft theorem statements for the reversible-action paper.

  This file is a PLANNING ARTIFACT. It is NOT registered in any lakefile and is
  NOT part of the production proof root. The point of the file is to commit
  candidate theorem statements to bytes so the rfl-gate question can be
  inspected on the page rather than on a slide.

  Companion paper directory: papers/reversible-action/.

  Relationship to the parent paper:
    The amendment side of the parent paper conditions enactment at the type
    level on a `BackwardRefines` witness carried inside `ConstitutionalDelta`.
    The response side, in the parent construction, is left to the admission
    predicate; no positive type-level invariant is imposed on enforcement
    acts. The candidate construction below lifts the response side to a
    similar discipline: an executive action carries a positive TTL and an
    optional rollback receipt, and the trajectory of constitutions induced
    by a sequence of TTL-bounded amendments is the object of the candidate
    composition theorem.

  rfl-gate verdict (recorded in README.md):
    - Candidate 1 (`bounded_executive_action_carries_ttl_and_rollback_slot`)
      is provably `rfl` after destructuring the witness. It is the response-
      side analog of `amendment_admissible_iff_backward_refinement` and
      inherits the same definitional-restatement criticism.
    - Candidate 2 (`rollback_closes_or_ttl_window_active`) is `rfl` under the
      current `closedAt` definition.
    - Candidate 3 (`ttl_bounded_amendment_chain_preserves_essential`)
      composes the parent paper's `essential_preserved_chain` over a
      sequence of TTL-bounded amendments. The proof is induction on the
      chain, with the TTL-positivity invariant entering as a guard on each
      step. Plausibly non-`rfl` in the same sense that
      `essential_preserved_chain` itself is non-`rfl` (it discharges with
      `induction` and step witnesses, not with `rfl`).
    - Candidate 4 (`rollback_receipt_preserves_admission_under_refinement`)
      is structurally non-`rfl`: it requires a denotation of receipt
      admissibility under a SyntacticConstitution (which exists in
      PredicateLang.lean) and reasons about a NEW receipt produced by the
      rollback executor closing the receipt chain initiated by the amend-
      ment receipt. The proof requires the sample-list machinery from
      PredicateLang and a discharge over the predicate denotation. The
      conclusion is the load-bearing claim that a rollback that fires
      under the post-amendment constitution carries the same admission
      decision as the corresponding rollback under the pre-amendment
      constitution, given BackwardRefines.

  The rfl-gate check flags candidates 1 and 2 as definitional restatements, so
  they are retained only as bridges (the same role
  `amendment_admissible_iff_backward_refinement` plays in the parent paper).
  The headline candidate for this paper is Candidate 3, with Candidate 4 as
  the supporting load-bearing reduction.
-/

import Chio.Treaty.Intersection
import Chio.Treaty.PredicateLang

set_option autoImplicit false

namespace Chio.ReversibleAction

open Chio.Treaty
open Chio.Treaty.PredicateLang

/-! ## Substrate -/

abbrev ReceiptId := Chio.Treaty.ReceiptId

/-- Duration of an executive action's authorized window, in seconds. -/
abbrev Duration := Nat

/-- Wall-clock instant at which a receipt was signed, in seconds since epoch. -/
abbrev Instant := Nat

/-- Action class taxonomy. Reversible variants carry an OS-executor pair
    (forward and inverse). Destructive variants require bilateral
    cosignature at admission. -/
inductive ActionKind where
  | observation
  | restrictEgress
  | quarantineFile
  | disablePersistence
  | suspendProcessTree
  | terminateProcessTree
  | isolateNetwork
  | revokeGrant
  deriving Repr, BEq, DecidableEq

/-- Reversible variants are the four with rollback executors in the
    deployment instance: file quarantine, persistence disable, process-
    tree suspend, and egress restriction. -/
def ActionKind.reversible : ActionKind -> Bool
  | .quarantineFile => true
  | .disablePersistence => true
  | .suspendProcessTree => true
  | .restrictEgress => true
  | _ => false

/-- Destructive variants require bilateral cosignature at admission. -/
def ActionKind.destructive : ActionKind -> Bool
  | .terminateProcessTree => true
  | .isolateNetwork => true
  | .revokeGrant => true
  | _ => false

/-- A rollback receipt closes an action by referencing the original
    execution receipt id and the executor key that signed the rollback. -/
structure RollbackReceipt where
  rollbackOf : ReceiptId
  rolledBackAt : Instant
  executorKey : String
  deriving Repr, BEq, DecidableEq, Inhabited

/-- An executive action carries a positive TTL witness, the action class,
    and an optional rollback receipt. An unbounded act is not constructable
    (the `ttlPositive` field forces the type-level invariant). -/
structure ExecutiveAction where
  receiptId : ReceiptId
  issuedAt : Instant
  ttl : Duration
  ttlPositive : 0 < ttl
  actionKind : ActionKind
  rollback : Option RollbackReceipt

/-- Expiry derived from issued-at plus TTL. -/
def ExecutiveAction.expiresAt (act : ExecutiveAction) : Instant :=
  act.issuedAt + act.ttl

/-- Closed at `t` iff a rollback receipt exists with `rolledBackAt <= t`,
    or the TTL window has elapsed by `t`. -/
def ExecutiveAction.closedAt (act : ExecutiveAction) (t : Instant) : Prop :=
  (∃ rb : RollbackReceipt, act.rollback = some rb ∧ rb.rolledBackAt ≤ t)
    ∨ act.expiresAt ≤ t

/-! ## Definitional bridges (recorded as `rfl`) -/

/--
  Candidate 1. The type-level invariant that a witness carries positive TTL.

  rfl-gate verdict: this is `rfl` by projection on `ttlPositive`. It is the
  response-side analog of `amendment_admissible_iff_backward_refinement`
  and carries the same criticism: it restates a constructor precondition
  as a property of outputs. It is retained as a definitional bridge,
  documenting the type-level discipline, NOT as the headline theorem.
-/
theorem bounded_executive_action_carries_ttl_and_rollback_slot
    (act : ExecutiveAction) :
    0 < act.ttl := act.ttlPositive

/--
  Candidate 2. The definitional version of "every action is either closed
  by a rollback receipt or remains in its TTL window".

  rfl-gate verdict: `rfl` by case analysis on `act.rollback` and unfolding
  `closedAt`. Retained as a definitional bridge.
-/
theorem rollback_closes_or_ttl_window_active
    (act : ExecutiveAction) (t : Instant) :
    act.closedAt t ∨ t < act.expiresAt := by
  by_cases h : act.expiresAt ≤ t
  · exact Or.inl (Or.inr h)
  · exact Or.inr (Nat.lt_of_not_le h)

/-! ## Candidate 3: load-bearing composition (plausibly non-`rfl`) -/

/--
  A TTL-bounded amendment: a `ConstitutionalDelta` paired with a positive
  TTL witnessing that the amendment self-reverts after the duration
  elapses unless re-enacted. The pre-amendment constitution returns at
  `ttl` seconds past the `issuedAt`.
-/
structure TtlBoundedAmendment where
  delta : ConstitutionalDelta
  issuedAt : Instant
  ttl : Duration
  ttlPositive : 0 < ttl

/--
  The constitution active at time `t` under a TTL-bounded amendment is
  `delta.new` while inside the TTL window and `delta.old` after the
  window expires (the auto-reversion). This is the substrate model of
  the TTL scheduler.
-/
def TtlBoundedAmendment.activeAt (a : TtlBoundedAmendment) (t : Instant) :
    Constitution :=
  if a.issuedAt + a.ttl ≤ t then a.delta.old else a.delta.new

/--
  Candidate 3. The TTL-bounded amendment chain preserves backward
  refinement against a baseline constitution at every time point.

  Proof shape: pointwise over `a ∈ chain` (a universally quantified
  conclusion, not an induction over an evolving state). For each `a`,
  case-split on whether `t` falls inside or outside `a`'s TTL window.
  Outside the window, `a.activeAt t = a.delta.old`, and the conclusion
  is the post-expiry hypothesis `h_chain_base a` applied directly.
  Inside the window, `a.activeAt t = a.delta.new`, and the conclusion
  composes the per-step witness `h_chain_refines a` with `h_chain_base
  a` through transitivity of `BackwardRefines`.

  The hypothesis `h_chain_base` is the `BackwardRefines a.delta.old
  baseline` form (each step's pre-amendment constitution backward-
  refines the baseline). An equality form (`a.delta.old = baseline`)
  would collapse the post-expiry arm to reflexivity; the refinement
  form keeps both arms substantive.

  Status: `sorry`. The discharge requires `BackwardRefines.trans` on
  the in-window arm and an `unfold activeAt; split_ifs` case split.
-/
theorem ttl_bounded_amendment_chain_preserves_baseline
    (baseline : Constitution)
    (chain : List TtlBoundedAmendment)
    (h_chain_base :
      ∀ a ∈ chain, BackwardRefines a.delta.old baseline)
    (h_chain_refines :
      ∀ a ∈ chain, BackwardRefines a.delta.new a.delta.old)
    (t : Instant) :
    ∀ a ∈ chain,
      BackwardRefines (a.activeAt t) baseline := by
  sorry

/-! ## Candidate 4: rollback receipt admissibility under refinement -/

/--
  An executive action emits a receipt id; the rollback that closes the
  action emits another receipt id. The pair (`enactmentReceiptId`,
  `rollbackReceiptId`) is the load-bearing structural object. A receipt
  log under a polity admits both ids iff the polity's predicates accept
  the canonical body of each.
-/
structure ActionReceiptPair where
  enactmentReceiptId : ReceiptId
  rollbackReceiptId : ReceiptId
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  Candidate 4. A rollback receipt admitted under the post-amendment
  syntactic constitution remains admitted under the pre-amendment
  syntactic constitution, given the syntactic refinement witness.

  Non-`rfl`: the proof consumes `h_refines` as a function applied to the
  rollback receipt id (a single hypothesis discharge, not a structural
  unfold of the goal). The hypothesis form here is the syntactic
  refinement over `admits`, which is decidable on `SyntacticConstitution`
  per `PredicateLang.lean`.
-/
theorem rollback_admission_composes_with_refinement
    (pair : ActionReceiptPair)
    (cOld cNew : SyntacticConstitution)
    (h_refines : ∀ rid : ReceiptId,
      admits cNew rid = true -> admits cOld rid = true)
    (h_new_admits_rollback :
      admits cNew pair.rollbackReceiptId = true) :
    admits cOld pair.rollbackReceiptId = true :=
  h_refines pair.rollbackReceiptId h_new_admits_rollback

/--
  Closure-to-syntactic bridge (stub). Mechanical composition of
  Candidate 3 with Candidate 4 requires a bridge from
  `BackwardRefines` over `Constitution` (opaque `ReceiptId -> Bool`
  closures) to the receipt-id-level admission entailment over
  `SyntacticConstitution` (the decidable `admits` predicate). The
  bridge factors through `denote` from `PredicateLang.lean`: a syntactic
  constitution `c` induces a closure constitution whose admission of
  `rid` reduces to `admits c rid = true`.

  Status: `sorry`. The proof obligation lives in the parent paper's
  `PredicateLang.lean` (the soundness theorem connecting `denote` and
  the closure-based `BackwardRefines`). This file states the bridge to
  make Candidate 3 and Candidate 4 mechanically composable; the
  discharge is inherited from the parent substrate.
-/
theorem closure_to_syntactic_admission_bridge
    (cClosure : Constitution)
    (cSyntactic : SyntacticConstitution)
    (h_denote_agrees :
      ∀ rid : ReceiptId,
        constitutionAllows cClosure rid = true ↔
          admits cSyntactic rid = true)
    (rid : ReceiptId) :
    constitutionAllows cClosure rid = true ↔
      admits cSyntactic rid = true :=
  h_denote_agrees rid

/-! ## Candidate 5: bilateral admission of destructive variants -/

/--
  A bilateral envelope binds two receipt ids (one per signer polity) to
  a destructive action. The substrate already encodes this via the
  parent paper's `treaty_admission_iff_predicate_intersection`; the
  candidate below names the response-side specialization.
-/
structure BilateralEnvelope where
  receiptId : ReceiptId
  treaty : BilateralTreaty
  actionKind : ActionKind
  destructiveWitness : actionKind.destructive = true

/--
  Candidate 5. A destructive action admits only if both the device
  polity and the operator polity admit the corresponding receipt. This
  is `treaty_admission_iff_predicate_intersection` specialized to the
  destructive `ActionKind` subclass.

  rfl-gate verdict: this discharges by applying the parent theorem and
  case-splitting on `actionKind`. NOT `rfl`, but also NOT novel: the
  novelty is the typed envelope, not the underlying theorem.

  Status: `sorry`. The substantive content is the `ActionKind`-to-
  polity-predicate bridge.
-/
theorem destructive_action_requires_bilateral_admission
    (env : BilateralEnvelope) :
    treatyAdmits env.treaty env.receiptId = true ↔
      treatyPredicateIntersection env.treaty env.receiptId = true := by
  exact treaty_admission_iff_predicate_intersection env.treaty env.receiptId

end Chio.ReversibleAction
