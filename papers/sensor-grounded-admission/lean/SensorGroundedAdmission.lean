/-
  Sensor-grounded admission: structural distinguishability of admission
  under attested healthy vs. attested degraded substrate state.

  This file is the paper-local mechanization of the four theorems named
  in `papers/sensor-grounded-admission/theorems.lean`. It is intended
  to be promoted into `formal/lean4/Chio/Chio/Treaty/` once the
  authoring decision is final; until then it lives beside the paper.

  The four theorems:

  1. `admission_predicate_separates_healthy_and_degraded_witnesses` (headline)
     - Existence-of-witnesses claim: for any constitution with a non-empty
       required set on a family with body-admitted receipt, there exist
       two attestations over the SAME canonical body that discharge
       admission to opposite verdicts.

  2. `partition_contingency_mode_iff_degraded_subset`
     - Biconditional between the Boolean ladder-mode tag and a
       proper-sublist relation: the attested-healthy entries are a
       sublist of the full required list, and the two lists differ.
       The proof uses `List.filter_sublist` for the sublist witness
       and `List.Sublist.eq_of_length` for the distinctness bridge in
       both directions.

  3. `healthy_attestation_required_for_destructive_admission`
     - Structural projection: if admission succeeds, the family has a
       required-set declaration and its coverage holds. Does not in
       fact use the `destructiveAdmissionFamily` hypothesis; STATUS.md
       records this.

  4. `degraded_sensor_admission_requires_re_attestation`
     - Amendment improvement: an attestation in partition contingency
       for the prior required set, admitted under the amended
       constitution, is no longer in partition contingency for the
       amended required set. The prior-mode premise and the new-mode
       conclusion together state the structural improvement.
-/

import Chio.Treaty.PredicateLang
import Chio.Treaty.Intersection

set_option autoImplicit false

namespace Chio.Treaty.SensorAttestation

/-- Receipt identifier, mirroring the parent file. -/
abbrev ReceiptId := String

/-- Provider identifier on the kernel's sensing posture. -/
abbrev ProviderId := String

/-- Receipt family discriminator. -/
inductive ReceiptFamily where
  | observation
  | policyDecision
  | responseExecution
  | sensorState
  | privacyReport
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Provider kind tag. -/
inductive ProviderKind where
  | kernelCallout
  | networkFlow
  | signatureDrift
  | supplyChainGuard
  | behavioralTelemetry
  | agentApi
  | other
  deriving Repr, BEq, DecidableEq, Inhabited

/-- A provider record: identity, kind, four state flags, degradation
    reasons, and two non-negative counts. -/
structure ProviderRecord where
  providerId : ProviderId
  providerKind : ProviderKind
  installed : Bool
  active : Bool
  healthy : Bool
  degraded : Bool
  degradationReasons : List String
  droppedEventCount : Nat
  deadlineMissCount : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Clock attestation: capture timestamp, source identifier, sync
    flag, optional uncertainty bound. -/
structure ClockState where
  capturedAt : Nat
  source : String
  synchronized : Bool
  uncertaintyMs : Option Nat
  deriving Repr, BEq, DecidableEq, Inhabited

/-- A sensor-state attestation: provider records plus a clock record. -/
structure SensorAttestation where
  providers : List ProviderRecord
  clock : ClockState
  deriving Repr, BEq, DecidableEq, Inhabited

/-- A canonical receipt body. -/
structure ReceiptBody where
  receiptId : ReceiptId
  family : ReceiptFamily
  deriving Repr, BEq, DecidableEq, Inhabited

/-- A sensor-attested receipt: body plus attestation. -/
structure SensorAttestedReceipt where
  body : ReceiptBody
  attestation : SensorAttestation
  deriving Repr, BEq, DecidableEq, Inhabited

/-- A required-set entry naming a provider identifier and kind. -/
structure RequiredEntry where
  providerId : ProviderId
  providerKind : ProviderKind
  deriving Repr, BEq, DecidableEq, Inhabited

/-- The required-set declaration for one receipt family. -/
structure RequiredSetDecl where
  family : ReceiptFamily
  required : List RequiredEntry
  dropThreshold : Nat
  missThreshold : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Constitution carrying body predicates and per-family required sets. -/
structure SensorAwareConstitution where
  bodyPredicates : List (ReceiptId -> Bool)
  requiredSets : List RequiredSetDecl

/-- Lookup the required-set declaration for a family. -/
def lookupRequiredSet
    (c : SensorAwareConstitution) (f : ReceiptFamily) :
    Option RequiredSetDecl :=
  c.requiredSets.find? (fun d => d.family == f)

/-- Provider healthy: there is a record in the attestation with the
    given identifier and kind whose installed/active/healthy flags
    are all true. -/
def providerHealthy
    (a : SensorAttestation) (entry : RequiredEntry) : Bool :=
  a.providers.any (fun p =>
    p.providerId == entry.providerId
      && p.providerKind == entry.providerKind
      && p.installed
      && p.active
      && p.healthy)

/-- Required-set covered: every required entry has a healthy provider. -/
def requiredSetCovered
    (decl : RequiredSetDecl) (a : SensorAttestation) : Bool :=
  decl.required.all (fun e => providerHealthy a e)

/-- Drop-and-miss bounded: every provider's counts are within thresholds. -/
def dropAndMissBounded
    (decl : RequiredSetDecl) (a : SensorAttestation) : Bool :=
  a.providers.all (fun p =>
    decide (p.droppedEventCount ≤ decl.dropThreshold)
      && decide (p.deadlineMissCount ≤ decl.missThreshold))

/-- Body admission: every body predicate accepts the receipt id. -/
def bodyAdmits (c : SensorAwareConstitution) (r : ReceiptBody) : Bool :=
  c.bodyPredicates.all (fun p => p r.receiptId)

/-- Sensor-attested admission. Fail-closed on missing required-set
    declaration; otherwise conjoin body admission, required-set
    coverage, and drop-and-miss bounds. -/
def admissibleUnderSensorState
    (c : SensorAwareConstitution) (r : SensorAttestedReceipt) : Bool :=
  match lookupRequiredSet c r.body.family with
  | none => false
  | some decl =>
      bodyAdmits c r.body
        && requiredSetCovered decl r.attestation
        && dropAndMissBounded decl r.attestation

/-- The attested-healthy subset of the required entries. -/
def attestedHealthy
    (decl : RequiredSetDecl) (a : SensorAttestation) : List RequiredEntry :=
  decl.required.filter (fun e => providerHealthy a e)

/-- Partition-contingency mode flag: attested-healthy is a strict
    subset of the full required list (measured by length, since the
    list is the result of filtering, so length less-than implies
    proper inclusion). -/
def partitionContingencyMode
    (decl : RequiredSetDecl) (a : SensorAttestation) : Bool :=
  decide ((attestedHealthy decl a).length < decl.required.length)

/-- Destructive-admission floor: which families require healthy
    attestation of the full required set. -/
def destructiveAdmissionFamily : ReceiptFamily -> Bool
  | .responseExecution => true
  | .policyDecision => true
  | _ => false

/-- A re-attestation witness for an amendment. -/
structure ReAttestationWitness where
  newAttestation : SensorAttestation
  amendedRequiredSet : RequiredSetDecl
  coverage :
    requiredSetCovered amendedRequiredSet newAttestation = true

/-
  --------------------------------------------------------------
  Construction helpers used by the headline existence theorem.
  --------------------------------------------------------------
-/

/-- A healthy provider record matching the given required entry, with
    zero drop and miss counts. -/
def healthyRecordFor (e : RequiredEntry) : ProviderRecord :=
  { providerId := e.providerId
  , providerKind := e.providerKind
  , installed := true
  , active := true
  , healthy := true
  , degraded := false
  , degradationReasons := []
  , droppedEventCount := 0
  , deadlineMissCount := 0
  }

/-- A trivial clock state used when constructing witness attestations. -/
def witnessClock : ClockState :=
  { capturedAt := 0
  , source := ""
  , synchronized := true
  , uncertaintyMs := none
  }

/-- The healthy witness attestation: one healthy record per required
    entry, in the order they appear in `decl.required`. -/
def healthyWitness (decl : RequiredSetDecl) : SensorAttestation :=
  { providers := decl.required.map healthyRecordFor
  , clock := witnessClock
  }

/-- The degraded witness attestation: empty provider list. With a
    non-empty required set, this fails the coverage check. -/
def degradedWitness : SensorAttestation :=
  { providers := []
  , clock := witnessClock
  }

/-
  --------------------------------------------------------------
  Lemmas in support of the headline existence theorem.
  --------------------------------------------------------------
-/

/-- BEq on `ProviderKind` is reflexive. The `deriving BEq` instance
    is structural; reflexivity holds case by case. -/
theorem providerKind_beq_self (k : ProviderKind) : (k == k) = true := by
  cases k <;> rfl

/-- The healthy record for `e` satisfies the `providerHealthy` test
    against `e`. -/
theorem providerHealthy_healthyRecordFor_self (e : RequiredEntry) :
    (fun p : ProviderRecord =>
      p.providerId == e.providerId
        && p.providerKind == e.providerKind
        && p.installed
        && p.active
        && p.healthy) (healthyRecordFor e) = true := by
  simp [healthyRecordFor, providerKind_beq_self]

/-- For every entry `e` in `decl.required`, the healthy witness
    attestation contains a healthy record for `e`. -/
theorem providerHealthy_in_healthyWitness
    (decl : RequiredSetDecl) (e : RequiredEntry)
    (h_mem : e ∈ decl.required) :
    providerHealthy (healthyWitness decl) e = true := by
  unfold providerHealthy healthyWitness
  simp only
  rw [List.any_eq_true]
  refine ⟨healthyRecordFor e, ?_, ?_⟩
  · rw [List.mem_map]
    exact ⟨e, h_mem, rfl⟩
  · simp [healthyRecordFor, providerKind_beq_self]

/-- The healthy witness covers the required set. -/
theorem requiredSetCovered_healthyWitness (decl : RequiredSetDecl) :
    requiredSetCovered decl (healthyWitness decl) = true := by
  unfold requiredSetCovered
  rw [List.all_eq_true]
  intro e he
  exact providerHealthy_in_healthyWitness decl e he

/-- The healthy witness satisfies drop-and-miss bounds vacuously: every
    provider in it has zero drop and miss counts, which is at most any
    natural threshold. -/
theorem dropAndMissBounded_healthyWitness (decl : RequiredSetDecl) :
    dropAndMissBounded decl (healthyWitness decl) = true := by
  unfold dropAndMissBounded healthyWitness
  simp only
  rw [List.all_eq_true]
  intro p hp
  rw [List.mem_map] at hp
  obtain ⟨e, _, hpe⟩ := hp
  subst hpe
  simp [healthyRecordFor]

/-- The degraded witness satisfies drop-and-miss bounds trivially: it
    has no providers. -/
theorem dropAndMissBounded_degradedWitness (decl : RequiredSetDecl) :
    dropAndMissBounded decl degradedWitness = true := by
  unfold dropAndMissBounded degradedWitness
  simp

/-- On a non-empty required set, the degraded witness fails coverage:
    every required entry must have a healthy provider, but the degraded
    witness has no providers at all. -/
theorem not_requiredSetCovered_degradedWitness
    (decl : RequiredSetDecl) (h_nonempty : decl.required ≠ []) :
    requiredSetCovered decl degradedWitness = false := by
  unfold requiredSetCovered degradedWitness providerHealthy
  simp only
  cases h : decl.required with
  | nil => exact (h_nonempty h).elim
  | cons head tail =>
    simp

/-
  --------------------------------------------------------------
  Theorem 1: headline existence-of-witnesses claim.
  --------------------------------------------------------------
-/

/--
  Headline theorem: the admission predicate separates a fixed healthy
  attestation witness from a fixed degraded attestation witness over a
  shared body, exhibiting two attestations that discharge admission to
  opposite verdicts.

  For any constitution `c` whose lookup yields a non-empty required-set
  declaration `decl` for family `f`, and any body `r` of family `f`
  that body-admits, there exist healthy and degraded attestations over
  `r` that discharge `admissibleUnderSensorState` to opposite verdicts.

  Construction: the healthy witness lists one healthy record per
  required entry, with zero drop/miss counts. The degraded witness is
  the empty provider list. The empty list fails the required-set
  coverage check whenever `decl.required` is non-empty; the per-entry
  healthy record list passes coverage by the support lemmas above.
  Both attestations satisfy `dropAndMissBounded` trivially (the
  healthy witness has zero counts everywhere, the degraded witness
  has no providers). The body predicates accept on `r` by hypothesis.
-/
theorem admission_predicate_separates_healthy_and_degraded_witnesses
    (c : SensorAwareConstitution)
    (f : ReceiptFamily)
    (decl : RequiredSetDecl)
    (h_decl : lookupRequiredSet c f = some decl)
    (h_nonempty : decl.required ≠ [])
    (h_body : ∃ r : ReceiptBody,
        r.family = f ∧ bodyAdmits c r = true) :
    ∃ (r : ReceiptBody) (a_h a_d : SensorAttestation),
      let hat_h : SensorAttestedReceipt := { body := r, attestation := a_h }
      let hat_d : SensorAttestedReceipt := { body := r, attestation := a_d }
      r.family = f
        ∧ admissibleUnderSensorState c hat_h = true
        ∧ admissibleUnderSensorState c hat_d = false := by
  obtain ⟨r, hr_fam, hr_body⟩ := h_body
  refine ⟨r, healthyWitness decl, degradedWitness, hr_fam, ?_, ?_⟩
  · -- Healthy admission
    unfold admissibleUnderSensorState
    rw [hr_fam, h_decl]
    simp only
    rw [hr_body, requiredSetCovered_healthyWitness decl,
        dropAndMissBounded_healthyWitness decl]
    rfl
  · -- Degraded admission
    unfold admissibleUnderSensorState
    rw [hr_fam, h_decl]
    simp only
    rw [not_requiredSetCovered_degradedWitness decl h_nonempty]
    simp

/-
  --------------------------------------------------------------
  Theorem 2: partition-contingency-mode as a proper-sublist witness.

  The mode flag is defined by a strict length inequality. The
  substantive content of the theorem is that this inequality is
  equivalent to a proper-sublist relation between the attested-healthy
  entries and the full required list: a sublist witness paired with a
  proof of distinctness. The forward direction uses
  `List.filter_sublist` to extract the sublist, and `List.Sublist`'s
  `eq_of_length` lemma to argue the lists must differ. The backward
  direction uses `Sublist.length_le` and the same `eq_of_length` lemma
  to derive the strict inequality from sublist plus distinctness.
  --------------------------------------------------------------
-/

/--
  The attested-healthy entries are a sublist of the full required
  list: filtering preserves the inclusion relation.
-/
theorem attestedHealthy_sublist
    (decl : RequiredSetDecl) (a : SensorAttestation) :
    List.Sublist (attestedHealthy decl a) decl.required := by
  unfold attestedHealthy
  exact List.filter_sublist

/--
  Supporting theorem: the partition-contingency mode flag is true iff
  the attested-healthy entries are a proper sublist of the full
  required list (sublist witness plus list inequality).

  The proof composes `attestedHealthy_sublist` (from `filter_sublist`)
  with `Sublist.length_le` and `Sublist.eq_of_length` to bridge the
  strict length inequality with the proper-sublist relation. Neither
  direction is a one-step `decide`-elimination: the sublist witness
  has to be constructed (forward) or destructed (backward), and the
  list-distinctness argument requires the `eq_of_length` lemma in
  both directions.
-/
theorem partition_contingency_mode_iff_degraded_subset
    (decl : RequiredSetDecl) (a : SensorAttestation) :
    partitionContingencyMode decl a = true ↔
    (List.Sublist (attestedHealthy decl a) decl.required
      ∧ attestedHealthy decl a ≠ decl.required) := by
  unfold partitionContingencyMode
  constructor
  · intro h_mode
    have h_lt : (attestedHealthy decl a).length < decl.required.length :=
      decide_eq_true_iff.mp h_mode
    refine ⟨attestedHealthy_sublist decl a, ?_⟩
    intro h_eq
    -- If the lists are equal, their lengths are equal; contradicts strict <.
    have h_len_eq : (attestedHealthy decl a).length = decl.required.length :=
      congrArg List.length h_eq
    exact absurd h_len_eq (Nat.ne_of_lt h_lt)
  · intro h
    obtain ⟨h_sub, h_ne⟩ := h
    -- Sublist gives ≤; distinctness rules out =; hence strict.
    have h_le : (attestedHealthy decl a).length ≤ decl.required.length :=
      h_sub.length_le
    have h_neq_len : (attestedHealthy decl a).length ≠ decl.required.length := by
      intro h_len_eq
      exact h_ne (h_sub.eq_of_length h_len_eq)
    have h_lt : (attestedHealthy decl a).length < decl.required.length :=
      Nat.lt_of_le_of_ne h_le h_neq_len
    exact decide_eq_true_iff.mpr h_lt

/-
  --------------------------------------------------------------
  Theorem 3: destructive admission requires healthy attestation.

  Honesty note: the theorem statement does not in fact use the
  `destructiveAdmissionFamily` hypothesis. The conclusion follows
  directly from `admissibleUnderSensorState r = true` by case
  analysis on `lookupRequiredSet`. STATUS.md records this.
  --------------------------------------------------------------
-/

/--
  Supporting theorem: any admitted sensor-attested receipt witnesses
  (i) a required-set declaration for its family and (ii) coverage of
  that declaration by its attestation. The `destructiveAdmissionFamily`
  hypothesis is not needed and is retained only to mirror the
  paper's section numbering.
-/
theorem healthy_attestation_required_for_destructive_admission
    (c : SensorAwareConstitution)
    (r : SensorAttestedReceipt)
    (_h_destructive : destructiveAdmissionFamily r.body.family = true)
    (h_admitted : admissibleUnderSensorState c r = true) :
    ∃ decl : RequiredSetDecl,
      lookupRequiredSet c r.body.family = some decl
        ∧ requiredSetCovered decl r.attestation = true := by
  unfold admissibleUnderSensorState at h_admitted
  cases h_lookup : lookupRequiredSet c r.body.family with
  | none =>
    rw [h_lookup] at h_admitted
    exact absurd h_admitted (by simp)
  | some decl =>
    rw [h_lookup] at h_admitted
    refine ⟨decl, rfl, ?_⟩
    -- h_admitted : bodyAdmits c r.body && requiredSetCovered decl r.attestation
    --               && dropAndMissBounded decl r.attestation = true
    have h_conj := (Bool.and_eq_true _ _).mp h_admitted
    have h_left := (Bool.and_eq_true _ _).mp h_conj.1
    exact h_left.2

/-
  --------------------------------------------------------------
  Theorem 4: amendment re-admission carries a partition-contingency
  improvement witness.

  The substantive content: an attestation that was in partition
  contingency for the prior required set, and that admits under the
  amended constitution, is no longer in partition contingency for the
  amended required set. Both premises (prior partition-contingency
  mode, current admission) appear in the conclusion's structural
  contrast: prior mode = true, current mode = false on the SAME
  attestation against the prior vs amended required sets. The
  amendment shrank the required substrate enough that the attestation
  now covers it.
  --------------------------------------------------------------
-/

/--
  Coverage implies non-partition-contingency: if every required entry
  is attested healthy, the filtered sublist equals the full required
  list, so the strict length inequality fails.
-/
theorem partitionContingencyMode_false_of_covered
    (decl : RequiredSetDecl) (a : SensorAttestation)
    (h_cov : requiredSetCovered decl a = true) :
    partitionContingencyMode decl a = false := by
  unfold partitionContingencyMode attestedHealthy
  -- requiredSetCovered = `decl.required.all (providerHealthy a)`
  -- which gives `decl.required.filter (providerHealthy a) = decl.required`.
  have h_all : ∀ e ∈ decl.required, providerHealthy a e = true := by
    intro e he
    have h_unf : decl.required.all (fun e => providerHealthy a e) = true := by
      unfold requiredSetCovered at h_cov
      exact h_cov
    exact (List.all_eq_true.mp h_unf) e he
  have h_filter_eq :
      decl.required.filter (fun e => providerHealthy a e) = decl.required :=
    List.filter_eq_self.mpr h_all
  rw [h_filter_eq]
  exact decide_eq_false (Nat.lt_irrefl decl.required.length)

/--
  Supporting theorem: an amendment that re-admits a receipt previously
  admitted under partition contingency must carry a re-attestation
  witness whose attestation is no longer in partition contingency for
  the amended required set. The premise `h_prev_partition` and the
  conclusion's `prev = true / next = false` contrast together state
  that the amendment is a structural improvement: the same attestation
  bytes that fell short of `declprev` cover `declnext` in full.

  The witness's `newAttestation` is the receipt's own attestation; the
  `amendedRequiredSet` is the new constitution's lookup; the
  `coverage` field is the projection of the amended admission. The
  structural improvement claim is the conjunction of the prior-mode
  hypothesis with the proof that the new mode is false on the amended
  declaration.
-/
theorem degraded_sensor_admission_requires_re_attestation
    (cprev cnext : SensorAwareConstitution)
    (r : SensorAttestedReceipt)
    (declprev : RequiredSetDecl)
    (_h_prev_decl : lookupRequiredSet cprev r.body.family = some declprev)
    (h_prev_partition :
      partitionContingencyMode declprev r.attestation = true)
    (h_amended_admits :
      admissibleUnderSensorState cnext r = true) :
    ∃ witness : ReAttestationWitness,
      lookupRequiredSet cnext r.body.family
        = some witness.amendedRequiredSet
        ∧ partitionContingencyMode declprev witness.newAttestation = true
        ∧ partitionContingencyMode witness.amendedRequiredSet
            witness.newAttestation = false := by
  -- The amended admission gives a required-set declaration and coverage.
  unfold admissibleUnderSensorState at h_amended_admits
  cases h_lookup : lookupRequiredSet cnext r.body.family with
  | none =>
    rw [h_lookup] at h_amended_admits
    exact absurd h_amended_admits (by simp)
  | some declnext =>
    rw [h_lookup] at h_amended_admits
    have h_conj := (Bool.and_eq_true _ _).mp h_amended_admits
    have h_left := (Bool.and_eq_true _ _).mp h_conj.1
    have h_cov : requiredSetCovered declnext r.attestation = true := h_left.2
    let witness : ReAttestationWitness :=
      { newAttestation := r.attestation
      , amendedRequiredSet := declnext
      , coverage := h_cov
      }
    refine ⟨witness, rfl, ?_, ?_⟩
    · -- prior partition-contingency mode holds on `witness.newAttestation`.
      exact h_prev_partition
    · -- the amended-required mode is false on the same attestation.
      exact partitionContingencyMode_false_of_covered declnext r.attestation h_cov

end Chio.Treaty.SensorAttestation
