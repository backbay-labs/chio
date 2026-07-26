/-
  Decidable treaty predicates over a bounded projection of the production
  federation admission input.

  The projection follows `TreatyScope`, `LadderIntersection`, and
  `BilateralInvocation` in `chio-runtime-core`. It intentionally omits JSON
  parsing, canonical hashing, signature verification, and store lookup. Those
  operations remain Rust-side obligations. The records below are a field
  projection, and the helper gates model only the checks named in this file.

  Unknown syntax and unavailable field interpretations are denied before
  Boolean negation is evaluated. Consequently an unsupported atom cannot be
  turned into an allow decision by wrapping it in `neg`.
-/

set_option autoImplicit false

namespace Chio.Treaty

/-- Ordered governance modes accepted by the production ladder parser. -/
inductive TrustMode where
  | observation
  | guarded
  | receiptBacked
  | partitionContingency
  | quorumRequired
  deriving Repr, BEq, DecidableEq, Inhabited

def TrustMode.rank : TrustMode -> Nat
  | .observation => 0
  | .guarded => 1
  | .receiptBacked => 2
  | .partitionContingency => 3
  | .quorumRequired => 4

def TrustMode.atLeast (mode floor : TrustMode) : Bool :=
  decide (floor.rank <= mode.rank)

inductive AmendmentVerdict where
  | enacted
  | rejected
  deriving Repr, BEq, DecidableEq, Inhabited

namespace PredicateLang

def treatyScopeSchema : String := "chio.federation.treaty-scope.v1"

def ladderIntersectionSchema : String :=
  "chio.federation.ladder-intersection.v1"

def bilateralInvocationSchema : String :=
  "chio.federation.bilateral-invocation.v1"

/-- Fields used from the production `TreatyScope` record. -/
structure TreatyScopeView where
  schema : String
  treatyId : String
  participantKernelIds : List String
  ladderManifestSha256s : List String
  allowedActionClasses : List String
  issuedAtUnixMs : Nat
  expiresAtUnixMs : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Fields used from the production `LadderIntersection` record. -/
structure LadderIntersectionView where
  schema : String
  treatyId : String
  participantKernelIds : List String
  ladderManifestSha256s : List String
  actionClassIds : List String
  generatedAtUnixMs : Nat
  expiresAtUnixMs : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Fields used from the production `BilateralInvocation` record. -/
structure BilateralInvocationView where
  schema : String
  treatyId : String
  ladderIntersectionSha256 : String
  continuationSha256 : String
  actionClassId : String
  signerKernelIds : List String
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Verified evidence projected from `CrossBoundaryEvidenceRef`. -/
structure EvidenceView where
  evidenceClass : String
  verified : Bool
  deriving Repr, BEq, DecidableEq, Inhabited

/-
  Bounded input to the Lean admission algebra. The expected hashes and policy
  verdict are verifier-owned values, not claims trusted from the invocation.
-/
structure AdmissionView where
  scope : TreatyScopeView
  intersection : LadderIntersectionView
  invocation : BilateralInvocationView
  nowUnixMs : Nat
  computedLadderIntersectionSha256 : String
  expectedLadderIntersectionSha256 : Option String
  expectedContinuationSha256 : Option String
  resolvedMode : Option Chio.Treaty.TrustMode
  requiredEvidence : List String
  presentEvidence : List String
  verifiedEvidence : List EvidenceView
  jointPolicyAllows : Bool
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Production-shaped gate tags used by the bounded constitution language. -/
inductive AtomTag where
  | schemasCurrent
  | treatyFresh
  | intersectionMatchesScope
  | intersectionHashBound
  | invocationMatchesScope
  | actionClassAllowed
  | signerPairBound
  | continuationHashBound
  | requiredEvidencePresent
  | requiredEvidenceVerified
  | jointPolicyAllows
  | modeAtLeast (floor : Chio.Treaty.TrustMode)
  | unsupported (name : String)
  deriving Repr, BEq, DecidableEq

/-- Syntactic constitutional predicates. -/
inductive Predicate where
  | atom (tag : AtomTag)
  | top
  | bot
  | conj (p q : Predicate)
  | disj (p q : Predicate)
  | neg (p : Predicate)
  deriving Repr, BEq, DecidableEq, Inhabited

def schemasCurrent (view : AdmissionView) : Bool :=
  view.scope.schema == treatyScopeSchema &&
    view.intersection.schema == ladderIntersectionSchema &&
    view.invocation.schema == bilateralInvocationSchema

def treatyFresh (view : AdmissionView) : Bool :=
  decide (
    view.scope.issuedAtUnixMs <= view.nowUnixMs ∧
    view.nowUnixMs < view.scope.expiresAtUnixMs ∧
    view.intersection.generatedAtUnixMs <= view.nowUnixMs ∧
    view.nowUnixMs < view.intersection.expiresAtUnixMs)

def intersectionMatchesScope (view : AdmissionView) : Bool :=
  view.scope.treatyId == view.intersection.treatyId &&
    view.scope.participantKernelIds == view.intersection.participantKernelIds &&
    view.scope.ladderManifestSha256s == view.intersection.ladderManifestSha256s

def intersectionHashBound (view : AdmissionView) : Bool :=
  view.expectedLadderIntersectionSha256 ==
      some view.computedLadderIntersectionSha256 &&
    view.invocation.ladderIntersectionSha256 ==
      view.computedLadderIntersectionSha256

def invocationMatchesScope (view : AdmissionView) : Bool :=
  view.invocation.treatyId == view.scope.treatyId

def actionClassAllowed (view : AdmissionView) : Bool :=
  view.scope.allowedActionClasses.elem view.invocation.actionClassId &&
    view.intersection.actionClassIds.elem view.invocation.actionClassId

def signerPairBound (view : AdmissionView) : Bool :=
  view.invocation.signerKernelIds.length == 2 &&
    view.invocation.signerKernelIds.eraseDups.length == 2 &&
    view.invocation.signerKernelIds.all
      (fun signer => view.scope.participantKernelIds.elem signer)

theorem action_class_missing_from_intersection_denies
    (view : AdmissionView)
    (hMissing : view.intersection.actionClassIds.elem
      view.invocation.actionClassId = false) :
    actionClassAllowed view = false := by
  unfold actionClassAllowed
  rw [hMissing]
  simp

theorem signer_count_mismatch_denies
    (view : AdmissionView)
    (hCount : (view.invocation.signerKernelIds.length == 2) = false) :
    signerPairBound view = false := by
  unfold signerPairBound
  rw [hCount]
  simp

theorem signer_alias_reuse_denies
    (view : AdmissionView)
    (hDistinct :
      (view.invocation.signerKernelIds.eraseDups.length == 2) = false) :
    signerPairBound view = false := by
  unfold signerPairBound
  rw [hDistinct]
  simp

theorem signer_outside_scope_denies
    (view : AdmissionView)
    (hOutside : view.invocation.signerKernelIds.all
      (fun signer => view.scope.participantKernelIds.elem signer) = false) :
    signerPairBound view = false := by
  unfold signerPairBound
  rw [hOutside]
  simp

def continuationHashBound (view : AdmissionView) : Bool :=
  view.expectedContinuationSha256 == some view.invocation.continuationSha256

def requiredEvidencePresent (view : AdmissionView) : Bool :=
  view.requiredEvidence.all (fun required => view.presentEvidence.elem required)

def evidenceVerified (view : AdmissionView) (required : String) : Bool :=
  view.verifiedEvidence.any
    (fun evidence =>
      evidence.evidenceClass == required && evidence.verified)

def requiredEvidenceVerified (view : AdmissionView) : Bool :=
  view.requiredEvidence.all (evidenceVerified view)

/-- Whether a syntax tag has a semantics in this model. -/
def supportedAtom : AtomTag -> Bool
  | .unsupported _ => false
  | _ => true

/-- Whether all syntax in a predicate is supported. -/
def supported : Predicate -> Bool
  | .atom tag => supportedAtom tag
  | .top => true
  | .bot => true
  | .conj p q => supported p && supported q
  | .disj p q => supported p && supported q
  | .neg p => supported p

/-- Whether the projected input carries every value needed by an atom. -/
def atomDefined : AtomTag -> AdmissionView -> Bool
  | .modeAtLeast _, view => view.resolvedMode.isSome
  | .unsupported _, _ => false
  | _, _ => true

/-- Whether every atom in a predicate is defined for this input. -/
def defined : Predicate -> AdmissionView -> Bool
  | .atom tag, view => atomDefined tag view
  | .top, _ => true
  | .bot, _ => true
  | .conj p q, view => defined p view && defined q view
  | .disj p q, view => defined p view && defined q view
  | .neg p, view => defined p view

/-- Interpret a supported atom against the production-shaped projection. -/
def evalAtom : AtomTag -> AdmissionView -> Bool
  | .schemasCurrent, view => schemasCurrent view
  | .treatyFresh, view => treatyFresh view
  | .intersectionMatchesScope, view => intersectionMatchesScope view
  | .intersectionHashBound, view => intersectionHashBound view
  | .invocationMatchesScope, view => invocationMatchesScope view
  | .actionClassAllowed, view => actionClassAllowed view
  | .signerPairBound, view => signerPairBound view
  | .continuationHashBound, view => continuationHashBound view
  | .requiredEvidencePresent, view => requiredEvidencePresent view
  | .requiredEvidenceVerified, view => requiredEvidenceVerified view
  | .jointPolicyAllows, view => view.jointPolicyAllows
  | .modeAtLeast floor, view =>
      match view.resolvedMode with
      | some mode => mode.atLeast floor
      | none => false
  | .unsupported _, _ => false

/-- Boolean evaluation after syntax and field availability are checked. -/
def eval : Predicate -> AdmissionView -> Bool
  | .atom tag, view => evalAtom tag view
  | .top, _ => true
  | .bot, _ => false
  | .conj p q, view => eval p view && eval q view
  | .disj p q, view => eval p view || eval q view
  | .neg p, view => !(eval p view)

/-- Fail-closed denotation. Unsupported or undefined input always denies. -/
def denote (predicate : Predicate) (view : AdmissionView) : Bool :=
  supported predicate && defined predicate view && eval predicate view

theorem unsupported_predicate_denies
    (predicate : Predicate) (view : AdmissionView)
    (hUnsupported : supported predicate = false) :
    denote predicate view = false := by
  simp [denote, hUnsupported]

theorem undefined_predicate_denies
    (predicate : Predicate) (view : AdmissionView)
    (hUndefined : defined predicate view = false) :
    denote predicate view = false := by
  simp [denote, hUndefined]

theorem negated_unknown_atom_denies
    (name : String) (view : AdmissionView) :
    denote (.neg (.atom (.unsupported name))) view = false := by
  rfl

theorem negated_unknown_mode_denies
    (floor : Chio.Treaty.TrustMode) (view : AdmissionView)
    (hMode : view.resolvedMode = none) :
    denote (.neg (.atom (.modeAtLeast floor))) view = false := by
  simp [denote, supported, defined, atomDefined, hMode]

/-- A finite list of predicates evaluated conjunctively. -/
structure SyntacticConstitution where
  predicates : List Predicate
  deriving Repr, BEq, DecidableEq, Inhabited

def admits (constitution : SyntacticConstitution) (view : AdmissionView) : Bool :=
  constitution.predicates.all (fun predicate => denote predicate view)

/-- Refinement over an explicit, verifier-owned admission domain. -/
def SynBackwardRefines
    (new old : SyntacticConstitution) (domain : List AdmissionView) : Prop :=
  forall view, view ∈ domain ->
    admits new view = true -> admits old view = true

/-- Global semantic refinement, used only for the closure bridge. -/
def GlobalSynBackwardRefines
    (new old : SyntacticConstitution) : Prop :=
  forall view, admits new view = true -> admits old view = true

def refinesOn
    (new old : Predicate) (domain : List AdmissionView) : Bool :=
  domain.all
    (fun view => decide (!(denote new view) || denote old view))

def refinesOnConstitution
    (new old : SyntacticConstitution) (domain : List AdmissionView) : Bool :=
  domain.all
    (fun view => decide (!(admits new view) || admits old view))

theorem refinesOn_complete_on_fragment
    (new old : Predicate) (domain : List AdmissionView) :
    refinesOn new old domain = true ↔
      forall view, view ∈ domain ->
        denote new view = true -> denote old view = true := by
  unfold refinesOn
  constructor
  · intro hCheck view hMember hNew
    have hAt := List.all_eq_true.mp hCheck view hMember
    simpa [hNew] using hAt
  · intro hRefines
    apply List.all_eq_true.mpr
    intro view hMember
    cases hNew : denote new view
    · simp
    · have hOld := hRefines view hMember hNew
      simp [hOld]

theorem refinesOnConstitution_complete_on_fragment
    (new old : SyntacticConstitution) (domain : List AdmissionView) :
    refinesOnConstitution new old domain = true ↔
      SynBackwardRefines new old domain := by
  unfold refinesOnConstitution SynBackwardRefines
  constructor
  · intro hCheck view hMember hNew
    have hAt := List.all_eq_true.mp hCheck view hMember
    simpa [hNew] using hAt
  · intro hRefines
    apply List.all_eq_true.mpr
    intro view hMember
    cases hNew : admits new view
    · simp
    · have hOld := hRefines view hMember hNew
      simp [hOld]

/--
  Compatibility name used by the programmable-sovereignty artifact. The
  decision is exact only on the explicit production-shaped admission domain.
-/
theorem refinesOnConstitution_iff
    (new old : SyntacticConstitution) (domain : List AdmissionView) :
    refinesOnConstitution new old domain = true ↔
      SynBackwardRefines new old domain :=
  refinesOnConstitution_complete_on_fragment new old domain

/-- Exact gate list corresponding to the modeled runtime conjunction. -/
def runtimeAdmissionAtoms : List AtomTag := [
  .schemasCurrent,
  .treatyFresh,
  .intersectionMatchesScope,
  .intersectionHashBound,
  .invocationMatchesScope,
  .actionClassAllowed,
  .signerPairBound,
  .continuationHashBound,
  .requiredEvidencePresent,
  .requiredEvidenceVerified,
  .jointPolicyAllows,
  .modeAtLeast .observation
]

def runtimeAdmissionConstitution : SyntacticConstitution :=
  { predicates := runtimeAdmissionAtoms.map Predicate.atom }

theorem atom_constitution_exact
    (atoms : List AtomTag) (view : AdmissionView) :
    admits { predicates := atoms.map Predicate.atom } view = true ↔
      forall atom, atom ∈ atoms ->
        (supportedAtom atom = true ∧
        atomDefined atom view = true) ∧
        evalAtom atom view = true := by
  constructor
  · intro hAdmits atom hMember
    have hAtom := List.all_eq_true.mp hAdmits
      (.atom atom) (by simp [hMember])
    simpa [denote, supported, defined, eval] using hAtom
  · intro hAtoms
    apply List.all_eq_true.mpr
    intro predicate hMember
    simp only [List.mem_map] at hMember
    obtain ⟨atom, hAtomMember, rfl⟩ := hMember
    have hAtom := hAtoms atom hAtomMember
    simp [denote, supported, defined, eval, hAtom.1.1, hAtom.1.2,
      hAtom.2]

theorem runtime_admission_policy_exact (view : AdmissionView) :
    admits runtimeAdmissionConstitution view = true ↔
      forall atom, atom ∈ runtimeAdmissionAtoms ->
        (supportedAtom atom = true ∧
        atomDefined atom view = true) ∧
        evalAtom atom view = true := by
  exact atom_constitution_exact runtimeAdmissionAtoms view

/-- Essential admission over the same explicit domain as refinement. -/
def admitsEssential
    (constitution : SyntacticConstitution)
    (essential : Predicate)
    (domain : List AdmissionView) : Prop :=
  forall view, view ∈ domain ->
    denote essential view = true -> admits constitution view = true

theorem essential_preserved_two_step
    (essential : Predicate) (domain : List AdmissionView)
    (c0 c1 c2 : SyntacticConstitution)
    (h01 : admitsEssential c0 essential domain ->
      admitsEssential c1 essential domain)
    (h12 : admitsEssential c1 essential domain ->
      admitsEssential c2 essential domain)
    (h0 : admitsEssential c0 essential domain) :
    admitsEssential c2 essential domain :=
  h12 (h01 h0)

theorem essential_preserved_chain
    (essential : Predicate) (domain : List AdmissionView)
    (chain : List SyntacticConstitution)
    (steps : forall (i : Nat), i + 1 < chain.length ->
      admitsEssential (chain[i]!) essential domain ->
      admitsEssential (chain[i + 1]!) essential domain)
    (h0 : chain.length > 0 ->
      admitsEssential (chain[0]!) essential domain) :
    forall (n : Nat), n < chain.length ->
      admitsEssential (chain[n]!) essential domain := by
  intro n hn
  induction n with
  | zero => exact h0 hn
  | succ k ih =>
      have hk : k < chain.length := by omega
      exact steps k hn (ih hk)

theorem ratchet_attack_requires_dropping_essential
    (essential : Predicate) (domain : List AdmissionView)
    (previous next : SyntacticConstitution)
    (hLost : admitsEssential previous essential domain ∧
      ¬ admitsEssential next essential domain) :
    ¬ (admitsEssential previous essential domain ->
      admitsEssential next essential domain) := by
  intro hPreserves
  exact hLost.2 (hPreserves hLost.1)

def containsPredicate
    (constitution : SyntacticConstitution) (predicate : Predicate) : Prop :=
  predicate ∈ constitution.predicates

theorem containsPredicate_preserved_two_step
    (predicate : Predicate)
    (c0 c1 c2 : SyntacticConstitution)
    (h01 : containsPredicate c0 predicate -> containsPredicate c1 predicate)
    (h12 : containsPredicate c1 predicate -> containsPredicate c2 predicate)
    (h0 : containsPredicate c0 predicate) :
    containsPredicate c2 predicate :=
  h12 (h01 h0)

theorem containsPredicate_preserved_chain
    (predicate : Predicate)
    (chain : List SyntacticConstitution)
    (steps : forall (i : Nat), i + 1 < chain.length ->
      containsPredicate (chain[i]!) predicate ->
      containsPredicate (chain[i + 1]!) predicate)
    (h0 : chain.length > 0 -> containsPredicate (chain[0]!) predicate) :
    forall (n : Nat), n < chain.length ->
      containsPredicate (chain[n]!) predicate := by
  intro n hn
  induction n with
  | zero => exact h0 hn
  | succ k ih =>
      have hk : k < chain.length := by omega
      exact steps k hn (ih hk)

theorem meta_amendment_requires_dropping_designated
    (predicate : Predicate)
    (previous next : SyntacticConstitution)
    (hLost : containsPredicate previous predicate ∧
      ¬ containsPredicate next predicate) :
    ¬ (containsPredicate previous predicate ->
      containsPredicate next predicate) := by
  intro hPreserves
  exact hLost.2 (hPreserves hLost.1)

theorem containsPredicate_implies_satisfied
    (constitution : SyntacticConstitution)
    (predicate : Predicate) (view : AdmissionView)
    (hContains : containsPredicate constitution predicate)
    (hAdmits : admits constitution view = true) :
    denote predicate view = true := by
  exact List.all_eq_true.mp hAdmits predicate hContains

abbrev LaneId := String

structure LaneQuorumPolicy where
  lanes : List LaneId
  quorum : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

structure AnchorWitness where
  contributingLanes : List LaneId
  deriving Repr, BEq, DecidableEq, Inhabited

def declaredLanes (policy : LaneQuorumPolicy) : List LaneId :=
  policy.lanes.eraseDups

def contributingFromPolicy
    (policy : LaneQuorumPolicy) (witness : AnchorWitness) : Nat :=
  ((declaredLanes policy).filter
    (fun lane => witness.contributingLanes.elem lane)).length

def witnessUsesOnlyDeclaredLanes
    (policy : LaneQuorumPolicy) (witness : AnchorWitness) : Bool :=
  witness.contributingLanes.all (fun lane => policy.lanes.elem lane)

def laneQuorumSatisfied
    (policy : LaneQuorumPolicy) (witness : AnchorWitness) : Bool :=
  witnessUsesOnlyDeclaredLanes policy witness &&
    decide (policy.quorum <= contributingFromPolicy policy witness)

structure LaneScope where
  predicates : List Predicate
  laneQuorumPolicy : LaneQuorumPolicy
  deriving Repr, BEq, DecidableEq, Inhabited

def anchorAdmits (scope : LaneScope) (witness : AnchorWitness) : Bool :=
  laneQuorumSatisfied scope.laneQuorumPolicy witness

theorem anchor_admission_iff_lane_quorum_satisfied
    (scope : LaneScope) (witness : AnchorWitness) :
    anchorAdmits scope witness = true ↔
      laneQuorumSatisfied scope.laneQuorumPolicy witness = true := by
  rfl

theorem anchor_admission_zero_quorum
    (scope : LaneScope) (witness : AnchorWitness)
    (hZero : scope.laneQuorumPolicy.quorum = 0)
    (hDeclared :
      witnessUsesOnlyDeclaredLanes scope.laneQuorumPolicy witness = true) :
    anchorAdmits scope witness = true := by
  simp [anchorAdmits, laneQuorumSatisfied, hZero, hDeclared]

theorem anchor_admission_rejects_undeclared_lane
    (scope : LaneScope) (witness : AnchorWitness)
    (hUndeclared :
      witnessUsesOnlyDeclaredLanes scope.laneQuorumPolicy witness = false) :
    anchorAdmits scope witness = false := by
  simp [anchorAdmits, laneQuorumSatisfied, hUndeclared]

end Chio.Treaty.PredicateLang
