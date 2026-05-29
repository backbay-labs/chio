/-
  Syntactic predicate language for Chio constitutional admission.

  Action-plan item V1 (Predicate ADT). The existing `Constitution` type
  stores predicates as `List (ReceiptId -> Bool)`, i.e., opaque closures
  Lean cannot inspect. That makes `BackwardRefines` essentially
  unconstructable for any non-trivial polity and renders the decidability
  claim a category error.

  The fix (following the Cedar approach) is to introduce a syntactic ADT
  for predicates plus a `denote` interpreter, so refinement becomes
  decidable on syntax rather than on closures.

  This file is additive. It does NOT modify `Intersection.lean`. A
  follow-up revision can swap `Predicate` into the polity model when
  the bridge soundness theorem to the existing `BackwardRefines`
  closure relation is proved.
-/

import Chio.Treaty.Intersection

set_option autoImplicit false

namespace Chio.Treaty.PredicateLang

/-- Receipt identifier, mirroring `Intersection.lean`. -/
abbrev ReceiptId := String

/--
  Atomic predicate tags. Each tag corresponds to one checkable
  field of the canonical receipt body. The list is finite and the
  paper's bilateral-DSSE verifier checks a fixed subset of these
  in `bilateral_verifier.rs`.
-/
inductive AtomTag where
  | scopeContains (target : ReceiptId)
  | participantKeyEquals (key : String)
  | actionClassIn (cls : String)
  | ladderModeAtLeastRank (rank : Nat)
  | receiptHashEquals (hash : String)
  | continuationLive (continuationId : String)
  deriving Repr, BEq, DecidableEq

/-- Syntactic constitutional predicates over receipts. -/
inductive Predicate where
  | atom (tag : AtomTag)
  | top
  | bot
  | conj (p q : Predicate)
  | disj (p q : Predicate)
  | neg (p : Predicate)
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  Interpret an atomic tag against a receipt identifier. The
  production runtime checks more fields than this denotation
  captures (e.g., participant key matches the kernel keypair, not
  the receipt id); this denotation is a model bridge, not the
  production check.
-/
def denoteAtom (tag : AtomTag) (rid : ReceiptId) : Bool :=
  match tag with
  | .scopeContains target => rid == target
  | .receiptHashEquals h => rid == h
  | _ => false

/-- Interpret a predicate as a Boolean function of receipt id. -/
def denote : Predicate -> ReceiptId -> Bool
  | .atom tag, rid => denoteAtom tag rid
  | .top, _ => true
  | .bot, _ => false
  | .conj p q, rid => denote p rid && denote q rid
  | .disj p q, rid => denote p rid || denote q rid
  | .neg p, rid => !(denote p rid)

/--
  Syntactic backward-refinement over a finite receipt sample.
  `refinesOn p q sample = true` iff every receipt in `sample` that
  satisfies `p` also satisfies `q`. In production, `sample` is the
  already-admitted-history of the polity (a Merkle-rooted set).
-/
def refinesOn (p q : Predicate) (sample : List ReceiptId) : Bool :=
  sample.all (fun rid => decide (!(denote p rid) || denote q rid))

/-- Refinement is reflexive on every sample. -/
theorem refinesOn_refl
    (p : Predicate) (sample : List ReceiptId) :
    refinesOn p p sample = true := by
  unfold refinesOn
  apply List.all_eq_true.mpr
  intros rid _
  cases h : denote p rid <;> simp

/-- Top admits every receipt (so any predicate refines top). -/
theorem refinesOn_top
    (p : Predicate) (sample : List ReceiptId) :
    refinesOn p .top sample = true := by
  unfold refinesOn
  apply List.all_eq_true.mpr
  intros rid _
  simp [denote]

/-- Bot admits no receipt, so bot refines every predicate. -/
theorem refinesOn_bot
    (p : Predicate) (sample : List ReceiptId) :
    refinesOn .bot p sample = true := by
  unfold refinesOn
  apply List.all_eq_true.mpr
  intros rid _
  simp [denote]

/--
  Conjunction is the meet under refinement on a fixed sample: a
  predicate refining both `p` and `q` refines their conjunction.
  This is the syntactic counterpart of the semantic intersection
  in `Intersection.lean`'s `treatyPredicateIntersection`.
-/
theorem refinesOn_conj_intro
    (r p q : Predicate) (sample : List ReceiptId)
    (hp : refinesOn r p sample = true)
    (hq : refinesOn r q sample = true) :
    refinesOn r (.conj p q) sample = true := by
  unfold refinesOn at *
  apply List.all_eq_true.mpr
  intros rid hrid
  have hp' := List.all_eq_true.mp hp rid hrid
  have hq' := List.all_eq_true.mp hq rid hrid
  cases hr : denote r rid
  case false => simp [denote]
  case true =>
    simp [hr] at hp' hq'
    simp [denote, hp', hq']

/--
  Decidability witness: refinement on a fixed sample is decidable
  by structural recursion on `Predicate`. This is the load-bearing
  shape the closures-based `BackwardRefines` lacked.
-/
instance (p q : Predicate) (sample : List ReceiptId) :
    Decidable (refinesOn p q sample = true) :=
  inferInstance

/-
  ## Chain-invariant essential admission (action-plan V5).

  This guards against the constitutional-ratchet attack: individually
  valid backward-refining amendments can collectively collapse admission
  to an adversary-only predicate. The defense is an essential-predicate
  invariant: each amendment must additionally preserve admission of an
  essential predicate, and the invariant composes across chains.

  We model constitutions syntactically (over `Predicate`) so chain
  composition is decidable and inductive proofs go through. The
  theorems below capture the structure of the invariant; the
  substantive obligation on the runtime is to require an
  `admitsEssential` witness alongside each `BackwardRefines` witness
  at enactment.
-/

/--
  Syntactic constitution: a finite list of predicates over receipts.
  The polity admits a receipt iff every predicate denotes true on it.
-/
structure SyntacticConstitution where
  predicates : List Predicate
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Admission of a receipt under a syntactic constitution. -/
def admits (c : SyntacticConstitution) (rid : ReceiptId) : Bool :=
  c.predicates.all (fun p => denote p rid)

/--
  Essential admission: every receipt in the sample that satisfies
  the essential predicate is admitted by the constitution. The
  essential predicate is the load-bearing invariant a polity
  declares it will never drop.
-/
def admitsEssential
    (c : SyntacticConstitution)
    (essential : Predicate)
    (sample : List ReceiptId) : Prop :=
  forall rid, rid ∈ sample ->
    denote essential rid = true ->
    admits c rid = true

/--
  Two-step composition: if amendment `c0 -> c1` preserves essential
  admission and amendment `c1 -> c2` preserves essential admission,
  then the composed chain `c0 -> c2` preserves essential admission.
-/
theorem essential_preserved_two_step
    (essential : Predicate) (sample : List ReceiptId)
    (c0 c1 c2 : SyntacticConstitution)
    (h01 : admitsEssential c0 essential sample ->
           admitsEssential c1 essential sample)
    (h12 : admitsEssential c1 essential sample ->
           admitsEssential c2 essential sample)
    (h0 : admitsEssential c0 essential sample) :
    admitsEssential c2 essential sample :=
  h12 (h01 h0)

/--
  N-step composition over a list of step witnesses.
  Each step `steps[i]` carries the obligation that amendment
  `i -> i+1` preserves essential admission. The conclusion is
  that the final constitution `cn` admits essential whenever
  the initial constitution `c0` does. This is the chain-invariant
  preservation theorem for essential admission.
-/
theorem essential_preserved_chain
    (essential : Predicate) (sample : List ReceiptId)
    (chain : List SyntacticConstitution)
    (steps :
      forall (i : Nat),
        i + 1 < chain.length ->
        admitsEssential (chain[i]!) essential sample ->
        admitsEssential (chain[i + 1]!) essential sample)
    (h0 :
      chain.length > 0 ->
      admitsEssential (chain[0]!) essential sample) :
    forall (n : Nat),
      n < chain.length ->
      admitsEssential (chain[n]!) essential sample := by
  intros n hn
  induction n with
  | zero => exact h0 hn
  | succ k ih =>
    have hk : k < chain.length := by omega
    have hk1 : k + 1 < chain.length := hn
    exact steps k hk1 (ih hk)

/--
  Corollary: the constitutional-ratchet attack at the policy layer
  is structurally ruled out when each amendment carries an
  essential-preservation witness. The contrapositive names the
  attacker's move: an amendment that fails to preserve essential
  admission is exactly the constitutional-ratchet step.
-/
theorem ratchet_attack_requires_dropping_essential
    (essential : Predicate) (sample : List ReceiptId)
    (cprev cnext : SyntacticConstitution)
    (h_essential_lost :
      admitsEssential cprev essential sample ∧
      ¬ admitsEssential cnext essential sample) :
    ¬ (admitsEssential cprev essential sample ->
       admitsEssential cnext essential sample) := by
  intro hpres
  exact h_essential_lost.2 (hpres h_essential_lost.1)

/-
  ## Meta-stability theorem (action-plan V4).

  The §4 threat-model paragraph identifies the trust-store admission
  predicate as an axiom-grade invariant no amendment may drop. We
  formalize this syntactically: the constitution `c` "contains"
  predicate `p` iff `p ∈ c.predicates`. Amendments that preserve
  containment for a designated non-amendable predicate compose, so
  structural non-amendability is chain-invariant in the same sense V5
  made essential admission chain-invariant. V4 covers the syntactic
  axis (the predicate stays in the
  constitution at all); V5 covers the semantic axis (the predicate
  continues to admit its essential receipts). Both must hold for the
  trust-store-admission obligation to be defensible.
-/

/-- Predicate `p` is structurally present in `c`'s predicate list. -/
def containsPredicate
    (c : SyntacticConstitution) (p : Predicate) : Prop :=
  p ∈ c.predicates

/--
  Two-step composition: if both consecutive amendments preserve
  structural presence of `p`, the composition does.
-/
theorem containsPredicate_preserved_two_step
    (p : Predicate)
    (c0 c1 c2 : SyntacticConstitution)
    (h01 : containsPredicate c0 p -> containsPredicate c1 p)
    (h12 : containsPredicate c1 p -> containsPredicate c2 p)
    (h0 : containsPredicate c0 p) :
    containsPredicate c2 p :=
  h12 (h01 h0)

/--
  N-step composition: structural presence is chain-invariant
  over chains where every step carries a preservation witness. This
  is the syntactic counterpart of `essential_preserved_chain`.
-/
theorem containsPredicate_preserved_chain
    (p : Predicate)
    (chain : List SyntacticConstitution)
    (steps :
      forall (i : Nat),
        i + 1 < chain.length ->
        containsPredicate (chain[i]!) p ->
        containsPredicate (chain[i + 1]!) p)
    (h0 :
      chain.length > 0 ->
      containsPredicate (chain[0]!) p) :
    forall (n : Nat),
      n < chain.length ->
      containsPredicate (chain[n]!) p := by
  intros n hn
  induction n with
  | zero => exact h0 hn
  | succ k ih =>
    have hk : k < chain.length := by omega
    have hk1 : k + 1 < chain.length := hn
    exact steps k hk1 (ih hk)

/--
  Corollary: the meta-amendment attack (silently dropping a designated
  non-amendable predicate) is exactly the step that fails the
  preservation obligation. The runtime obligation: every amendment
  carries a `containsPredicate c p` witness for each designated
  non-amendable predicate at enactment.
-/
theorem meta_amendment_requires_dropping_designated
    (p : Predicate)
    (cprev cnext : SyntacticConstitution)
    (h_lost :
      containsPredicate cprev p ∧
      ¬ containsPredicate cnext p) :
    ¬ (containsPredicate cprev p ->
       containsPredicate cnext p) := by
  intro hpres
  exact h_lost.2 (hpres h_lost.1)

/--
  Bridge: structural presence forces semantic admission. If `p`
  is in `c.predicates` and `c` admits `rid`, then `p` admits `rid`.
  This is why `containsPredicate` is the load-bearing syntactic
  obligation: the receipt-level admission test mechanically enforces
  every predicate in the list. Preserve the syntactic presence and
  the semantic admission obligation follows.
-/
theorem containsPredicate_implies_satisfied
    (c : SyntacticConstitution) (p : Predicate) (rid : ReceiptId)
    (hContains : containsPredicate c p)
    (hAdmits : admits c rid = true) :
    denote p rid = true := by
  unfold admits at hAdmits
  unfold containsPredicate at hContains
  exact (List.all_eq_true.mp hAdmits) p hContains

/-
  ## Lane quorum policy and anchor admission (action-plan V3).

  The paper describes multi-lane anchor admission ("at least k of n
  declared anchor lanes must co-sign") but the formal model had no
  theorem connecting anchor-layer admission to lane quorum. V3 adds a
  structural `LaneQuorumPolicy` field to a treaty scope and proves
  `anchor_admission_iff_lane_quorum_satisfied`: the anchor layer
  admits a receipt iff the witness's contributing lanes meet the
  policy's quorum. The bi-conditional is the load-bearing claim that
  no opaque side channel can sneak admission past the quorum gate.
-/

/-- Lane identifier (mirrors the Rust runtime's `LaneId` type). -/
abbrev LaneId := String

/--
  Lane quorum policy: a finite allowlist of declared lanes plus a
  quorum threshold. Anchor admission requires at least `quorum`
  declared lanes to contribute a witness.
-/
structure LaneQuorumPolicy where
  lanes : List LaneId
  quorum : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  Anchor witness: the multiset of lane identifiers that co-signed
  this receipt at the anchor layer. The runtime records this as a
  list; this model treats it as such.
-/
structure AnchorWitness where
  contributingLanes : List LaneId
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  Deduplicated policy-declared lanes. Duplicate declarations cannot
  inflate quorum.
-/
def declaredLanes (policy : LaneQuorumPolicy) : List LaneId :=
  policy.lanes.eraseDups

/--
  Count of deduplicated policy-declared lanes that actually contributed
  to the witness.
-/
def contributingFromPolicy
    (policy : LaneQuorumPolicy) (witness : AnchorWitness) : Nat :=
  ((declaredLanes policy).filter
    (fun lane => witness.contributingLanes.elem lane)).length

/--
  Every contributing lane must be declared by the policy. Undeclared
  lanes make the witness invalid instead of being ignored.
-/
def witnessUsesOnlyDeclaredLanes
    (policy : LaneQuorumPolicy) (witness : AnchorWitness) : Bool :=
  witness.contributingLanes.all (fun lane => policy.lanes.elem lane)

/--
  Lane quorum satisfaction: the count of contributing declared lanes
  meets the policy's quorum threshold.
-/
def laneQuorumSatisfied
    (policy : LaneQuorumPolicy) (witness : AnchorWitness) : Bool :=
  witnessUsesOnlyDeclaredLanes policy witness &&
    decide (policy.quorum ≤ contributingFromPolicy policy witness)

/--
  Treaty scope carrying both a predicate list and a lane quorum
  policy. The runtime's `TreatyScope` carries additional fields
  (jurisdictional metadata, schema versions, expiry); this model
  retains the two load-bearing layers.
-/
structure LaneScope where
  predicates : List Predicate
  laneQuorumPolicy : LaneQuorumPolicy
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  Anchor-layer admission for a witness against a scope. The anchor
  layer's only obligation is lane quorum satisfaction; predicate-layer
  obligations are handled by `admits` / `denote`.
-/
def anchorAdmits
    (scope : LaneScope) (witness : AnchorWitness) : Bool :=
  laneQuorumSatisfied scope.laneQuorumPolicy witness

/--
  The named theorem (V3): the anchor-layer admission decision reduces
  exactly to lane quorum satisfaction on the scope's policy field.
  No additional hidden criteria are admissible at the anchor layer.
  This is the structural-definition theorem the runtime contract
  binds itself to.
-/
theorem anchor_admission_iff_lane_quorum_satisfied
    (scope : LaneScope) (witness : AnchorWitness) :
    anchorAdmits scope witness = true ↔
    laneQuorumSatisfied scope.laneQuorumPolicy witness = true := by
  unfold anchorAdmits
  exact Iff.rfl

/--
  Zero-quorum admits anything: the degenerate case where a scope
  declares quorum 0 admits any anchor witness. This is intentionally
  permitted by the structural theorem - the scope author opted out
  of anchor-layer enforcement. The runtime's policy-review surface
  is the place to flag a zero-quorum declaration as a denial-by-
  omission attack signal; the structural theorem says no more is
  hidden inside `anchorAdmits`.
-/
theorem anchor_admission_zero_quorum
    (scope : LaneScope) (witness : AnchorWitness)
    (hZeroQuorum : scope.laneQuorumPolicy.quorum = 0)
    (hDeclared :
      witnessUsesOnlyDeclaredLanes scope.laneQuorumPolicy witness = true) :
    anchorAdmits scope witness = true := by
  unfold anchorAdmits laneQuorumSatisfied
  rw [hZeroQuorum]
  simp [hDeclared]

/--
  Undeclared lane contributors fail closed before quorum counting.
-/
theorem anchor_admission_rejects_undeclared_lane
    (scope : LaneScope) (witness : AnchorWitness)
    (hUndeclared :
      witnessUsesOnlyDeclaredLanes scope.laneQuorumPolicy witness = false) :
    anchorAdmits scope witness = false := by
  unfold anchorAdmits laneQuorumSatisfied
  simp [hUndeclared]

end Chio.Treaty.PredicateLang
