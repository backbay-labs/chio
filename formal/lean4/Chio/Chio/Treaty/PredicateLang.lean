/-
  Bounded syntactic predicate language for Chio treaty admission.

  `Intersection.lean` retains the paper's legacy closure model. Arbitrary
  implication between opaque closures is not decidable. This module instead
  defines a finite predicate syntax over an explicit receipt view, an
  interpreter, and a decidable refinement check over a declared finite domain.

  The bridge below lifts syntactic constitutions into the closure model through
  an explicit receipt resolver. It proves pointwise semantic agreement and
  soundness for semantic refinement. It does not claim that a finite domain is
  complete for every possible receipt or that the production Rust verifier is
  extracted from Lean.
-/

import Chio.Treaty.Intersection

set_option autoImplicit false

namespace Chio.Treaty.PredicateLang

/-- Receipt identifier, mirroring the production receipt identity field. -/
abbrev ReceiptId := String

/-- Admission decision recorded by the bounded receipt view. -/
inductive AdmissionDecision where
  | allow
  | deny
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Named evidence digest bound to an admission decision. -/
structure EvidenceDigest where
  evidenceClass : String
  digest : String
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  The finite semantic surface used by the paper model. Cryptographic
  verification, canonicalization, time, storage, and evidence resolution happen
  before this view is constructed and remain explicit assumptions.
-/
structure ReceiptView where
  receiptId : ReceiptId
  receiptHash : String
  actionClass : String
  participantKernelIds : List String
  ladderModeRank : Nat
  liveContinuationIds : List String
  decision : AdmissionDecision
  failureCode : Option String
  evidenceDigests : List EvidenceDigest
  deriving Repr, BEq, DecidableEq, Inhabited

/--
  Atomic predicate tags. Each tag corresponds to one checkable
  field in `ReceiptView`. The language is deliberately finite.
-/
inductive AtomTag where
  | scopeContains (target : ReceiptId)
  | participantKernelIdEquals (kernelId : String)
  | actionClassIn (cls : String)
  | ladderModeAtLeastRank (rank : Nat)
  | receiptHashEquals (hash : String)
  | continuationLive (continuationId : String)
  | decisionEquals (decision : AdmissionDecision)
  | failureCodeEquals (code : String)
  | evidenceDigestEquals (evidenceClass digest : String)
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Syntactic constitutional predicates over receipts. -/
inductive Predicate where
  | atom (tag : AtomTag)
  | top
  | bot
  | conj (p q : Predicate)
  | disj (p q : Predicate)
  | neg (p : Predicate)
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Interpret one atomic predicate against the bounded receipt view. -/
def denoteAtom (tag : AtomTag) (receipt : ReceiptView) : Bool :=
  match tag with
  | .scopeContains target => receipt.receiptId == target
  | .participantKernelIdEquals kernelId =>
      receipt.participantKernelIds.elem kernelId
  | .actionClassIn cls => receipt.actionClass == cls
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

/-- Interpret a predicate as a Boolean function of the bounded receipt view. -/
def denote : Predicate -> ReceiptView -> Bool
  | .atom tag, receipt => denoteAtom tag receipt
  | .top, _ => true
  | .bot, _ => false
  | .conj p q, receipt => denote p receipt && denote q receipt
  | .disj p q, receipt => denote p receipt || denote q receipt
  | .neg p, receipt => !(denote p receipt)

/--
  Syntactic backward-refinement over a finite receipt sample.
  `refinesOn p q sample = true` iff every receipt in `sample` that
  satisfies `p` also satisfies `q`. Selection and completeness of the sample
  are obligations outside this model.
-/
def refinesOn (p q : Predicate) (sample : List ReceiptView) : Bool :=
  sample.all (fun receipt =>
    decide (!(denote p receipt) || denote q receipt))

/-- Refinement is reflexive on every sample. -/
theorem refinesOn_refl
    (p : Predicate) (sample : List ReceiptView) :
    refinesOn p p sample = true := by
  unfold refinesOn
  apply List.all_eq_true.mpr
  intros rid _
  cases h : denote p rid <;> simp

/-- Top admits every receipt (so any predicate refines top). -/
theorem refinesOn_top
    (p : Predicate) (sample : List ReceiptView) :
    refinesOn p .top sample = true := by
  unfold refinesOn
  apply List.all_eq_true.mpr
  intros rid _
  simp [denote]

/-- Bot admits no receipt, so bot refines every predicate. -/
theorem refinesOn_bot
    (p : Predicate) (sample : List ReceiptView) :
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
    (r p q : Predicate) (sample : List ReceiptView)
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
  by structural recursion on `Predicate`, unlike the closures-based
  `BackwardRefines`, which is not.
-/
instance (p q : Predicate) (sample : List ReceiptView) :
    Decidable (refinesOn p q sample = true) :=
  inferInstance

/-
  ## Chain-invariant essential admission.

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
def admits (c : SyntacticConstitution) (receipt : ReceiptView) : Bool :=
  c.predicates.all (fun predicate => denote predicate receipt)

/-- Decidable constitution refinement over the declared finite domain. -/
def refinesOnConstitution
    (new old : SyntacticConstitution)
    (domain : List ReceiptView) : Bool :=
  domain.all (fun receipt =>
    decide (!(admits new receipt) || admits old receipt))

/-- Semantic refinement over every receipt view, not claimed decidable here. -/
def SynBackwardRefines
    (new old : SyntacticConstitution) : Prop :=
  forall receipt : ReceiptView,
    admits new receipt = true -> admits old receipt = true

/-- Semantic refinement restricted to one declared finite domain. -/
def SynBackwardRefinesOn
    (new old : SyntacticConstitution)
    (domain : List ReceiptView) : Prop :=
  forall receipt, receipt ∈ domain ->
    admits new receipt = true -> admits old receipt = true

/--
  A successful Boolean refinement check is sound for every member of the
  declared domain.
-/
theorem bridge_decidable_soundness
    (new old : SyntacticConstitution)
    (domain : List ReceiptView)
    (hRefines : refinesOnConstitution new old domain = true) :
    SynBackwardRefinesOn new old domain := by
  intro receipt hMember hNew
  have hAtReceipt :=
    List.all_eq_true.mp hRefines receipt hMember
  simp [hNew] at hAtReceipt
  exact hAtReceipt

/--
  The Boolean check is complete for its declared finite domain. This theorem
  does not promote a finite domain to all possible receipts.
-/
theorem refinesOnConstitution_iff
    (new old : SyntacticConstitution)
    (domain : List ReceiptView) :
    refinesOnConstitution new old domain = true ↔
      SynBackwardRefinesOn new old domain := by
  constructor
  · exact bridge_decidable_soundness new old domain
  · intro h
    apply List.all_eq_true.mpr
    intro receipt hMember
    cases hNew : admits new receipt
    · simp
    · simpa using h receipt hMember hNew

/--
  Lift a syntactic constitution into the legacy closure model through an
  explicit resolver from receipt identifiers to bounded receipt views.
-/
def toClosure
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (constitution : SyntacticConstitution) :
    Chio.Treaty.Constitution :=
  {
    predicates :=
      constitution.predicates.map (fun predicate receiptId =>
        denote predicate (resolve receiptId))
  }

/-- The syntactic and lifted closure interpreters agree pointwise. -/
theorem bridge_pointwise
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (constitution : SyntacticConstitution)
    (receiptId : Chio.Treaty.ReceiptId) :
    Chio.Treaty.constitutionAllows (toClosure resolve constitution) receiptId =
      admits constitution (resolve receiptId) := by
  cases constitution with
  | mk predicates =>
      induction predicates with
      | nil => rfl
      | cons predicate rest ih =>
          change
            (denote predicate (resolve receiptId) &&
              Chio.Treaty.constitutionAllows
                (toClosure resolve { predicates := rest }) receiptId) =
            (denote predicate (resolve receiptId) &&
              admits { predicates := rest } (resolve receiptId))
          rw [ih]

/-- Global syntactic refinement soundly lifts into the closure relation. -/
theorem bridge_soundness
    (resolve : Chio.Treaty.ReceiptId -> ReceiptView)
    (new old : SyntacticConstitution)
    (hRefines : SynBackwardRefines new old) :
    Chio.Treaty.BackwardRefines
      (toClosure resolve new) (toClosure resolve old) := by
  intro receiptId hNew
  rw [bridge_pointwise] at hNew ⊢
  exact hRefines (resolve receiptId) hNew

/--
  Essential admission: every receipt in the sample that satisfies
  the essential predicate is admitted by the constitution. The
  essential predicate is the load-bearing invariant a polity
  declares it will never drop.
-/
def admitsEssential
    (c : SyntacticConstitution)
    (essential : Predicate)
    (sample : List ReceiptView) : Prop :=
  forall receipt, receipt ∈ sample ->
    denote essential receipt = true ->
    admits c receipt = true

/--
  Two-step composition: if amendment `c0 -> c1` preserves essential
  admission and amendment `c1 -> c2` preserves essential admission,
  then the composed chain `c0 -> c2` preserves essential admission.
-/
theorem essential_preserved_two_step
    (essential : Predicate) (sample : List ReceiptView)
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
    (essential : Predicate) (sample : List ReceiptView)
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
    (essential : Predicate) (sample : List ReceiptView)
    (cprev cnext : SyntacticConstitution)
    (h_essential_lost :
      admitsEssential cprev essential sample ∧
      ¬ admitsEssential cnext essential sample) :
    ¬ (admitsEssential cprev essential sample ->
       admitsEssential cnext essential sample) := by
  intro hpres
  exact h_essential_lost.2 (hpres h_essential_lost.1)

/-
  ## Meta-stability theorem.

  The trust-store admission predicate is an axiom-grade invariant no
  amendment may drop. This is formalized syntactically: the constitution
  `c` "contains" predicate `p` iff `p ∈ c.predicates`. Amendments that
  preserve containment for a designated non-amendable predicate compose,
  so structural non-amendability is chain-invariant, the same way the
  essential-admission invariant above is chain-invariant. This theorem
  covers the syntactic axis (the predicate stays in the constitution at
  all); the essential-admission invariant covers the semantic axis (the
  predicate continues to admit its essential receipts). Both must hold
  for the trust-store-admission obligation to be defensible.
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
    (c : SyntacticConstitution) (p : Predicate) (receipt : ReceiptView)
    (hContains : containsPredicate c p)
    (hAdmits : admits c receipt = true) :
    denote p receipt = true := by
  unfold admits at hAdmits
  unfold containsPredicate at hContains
  exact (List.all_eq_true.mp hAdmits) p hContains

/-
  ## Lane quorum policy and anchor admission.

  Multi-lane anchor admission requires at least k of n declared anchor
  lanes to co-sign. A structural `LaneQuorumPolicy` field on a treaty
  scope carries the quorum, and `anchor_admission_iff_lane_quorum_satisfied`
  proves the anchor layer admits a receipt iff the witness's contributing
  lanes meet the policy's quorum. The bi-conditional is the load-bearing
  claim that no opaque side channel can sneak admission past the quorum
  gate.
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
