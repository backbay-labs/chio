# SensorGroundedAdmission.lean: proof status

This file records the proof status of the four theorems that accompany
the sensor-grounded admission paper. The Lean source is in
`SensorGroundedAdmission.lean` beside this note. The full file
compiles under Lean 4.28.0-rc1 with Lake 5.0.0-src+3b0f286 against the
`Chio.Treaty.PredicateLang` and `Chio.Treaty.Intersection` modules of
the deployed substrate's Lean root. Reproduction instructions are in
`build-log.md`.

All four theorem statements are non-`sorry` and depend only on the
standard kernel axioms `propext`, `Classical.choice`, `Quot.sound`.
`#print axioms` results are reproduced in `build-log.md`.

## Theorem 1: `admission_predicate_separates_healthy_and_degraded_witnesses`

- Compiles: yes.
- Proof complete: yes.
- Honest `rfl` assessment: not `rfl`. The proof is constructive. It
  extracts the witness body from the body-admission hypothesis,
  instantiates a healthy attestation `healthyWitness decl` whose
  provider list is `decl.required.map healthyRecordFor`, instantiates
  a degraded attestation `degradedWitness` with an empty provider
  list, and discharges the admission predicate at both attestations
  with the body unchanged.
- Load-bearing supporting lemmas:
  - `providerHealthy_in_healthyWitness` (one-step `List.any_eq_true`
    against `List.mem_map`),
  - `requiredSetCovered_healthyWitness` (lifts the per-entry result
    over the required list via `List.all_eq_true`),
  - `dropAndMissBounded_healthyWitness` (every provider in the
    mapped list has zero drop and miss counts, so the threshold is
    trivially met),
  - `not_requiredSetCovered_degradedWitness` (case-splits on the
    `decl.required` list; the cons case discharges by `simp`, the
    nil case is ruled out by the non-emptiness hypothesis),
  - `dropAndMissBounded_degradedWitness` (empty provider list is
    vacuously bounded).
- Verdict: the v0 README's claim that this theorem is non-`rfl` and
  requires structural construction is correct. The proof needs five
  supporting lemmas; it does not unfold to a definitional equality.

## Theorem 2: `partition_contingency_mode_iff_degraded_subset`

- Compiles: yes.
- Proof complete: yes.
- Honest `rfl` assessment: not `rfl`. The theorem is restated to
  assert a proper-sublist relation between `attestedHealthy decl a`
  and `decl.required`: a `List.Sublist` witness paired with list
  inequality. Both directions require structural work.
  - Forward direction: extract the sublist witness via
    `attestedHealthy_sublist` (which is `List.filter_sublist`
    specialised to the attested-healthy filter); recover list
    inequality from the strict length inequality by `congrArg
    List.length` on the assumed equality, contradicted by
    `Nat.ne_of_lt`.
  - Backward direction: take the sublist witness, derive `length L
    ≤ length R` via `Sublist.length_le`, rule out equality via
    `Sublist.eq_of_length` (sublists of equal length are equal),
    and combine via `Nat.lt_of_le_of_ne` to obtain the strict
    length inequality.
- Load-bearing supporting lemma: `attestedHealthy_sublist`
  (`List.filter_sublist` applied to the attested-healthy filter).
- Verdict: the theorem now expresses what the v0 README's prose
  suggested (a structural subset relation, not merely a length
  comparison) and proves it with the two `Sublist` lemmas
  (`length_le` and `eq_of_length`) plus `filter_sublist`. The
  biconditional is no longer a one-step `decide`-elimination.

## Theorem 3: `healthy_attestation_required_for_destructive_admission`

- Compiles: yes.
- Proof complete: yes.
- Honest `rfl` assessment: not `rfl`. The proof case-splits on
  `lookupRequiredSet c r.body.family`; the `none` branch is closed
  by contradiction with the admission-true hypothesis (since
  `admissibleUnderSensorState` returns `false` on `none`); the
  `some decl` branch extracts the coverage Boolean from a
  three-conjunct `Bool.and_eq_true` decomposition.
- Honesty note: the `destructiveAdmissionFamily` hypothesis is
  not used by the proof. The theorem holds for any admitted
  receipt, not only for destructive-class ones. The hypothesis is
  retained in the signature only to mirror the paper's section
  numbering and to leave a hook for a strengthened statement
  (e.g., "for destructive receipts, the required-set declaration
  exists and lists at least one entry"; that would force the
  hypothesis into the proof body). The current signature carries
  an underscore-prefixed unused binder. If the paper claims this
  theorem connects destructive admission to required-set coverage
  in a way the headline theorem does not, the prose either needs
  to strengthen the statement or back the claim down. Recommend
  the paper text describe what the theorem actually proves: that
  admission witnesses required-set coverage as a structural
  consequence of the admission predicate's three-conjunct shape.
- Verdict: provable as stated, with the caveat that the
  destructive-class hypothesis is currently inert.

## Theorem 4: `degraded_sensor_admission_requires_re_admission_witness`

- Compiles: yes.
- Proof complete: yes.
- Honest `rfl` assessment: not `rfl`. The theorem is restated as a
  partition-contingency improvement claim: under the premises that
  the prior constitution's lookup returns `declprev`, that the
  attestation is in partition contingency for `declprev`, and that
  the amended constitution admits the receipt, the conclusion
  carries a `ReAdmissionWitness` whose new attestation is in
  partition contingency mode = false for `declnext`. The premise
  `h_prev_partition` appears in the conclusion's first conjunct
  (still true on `witness.newAttestation`); the
  `partitionContingencyMode declnext = false` clause is the
  substantive new claim.
- Load-bearing supporting lemma: `partitionContingencyMode_false_of_covered`,
  which derives `partitionContingencyMode decl a = false` from
  `requiredSetCovered decl a = true`. The proof uses
  `List.all_eq_true` to extract a pointwise healthy claim from the
  coverage Boolean, applies `List.filter_eq_self` to identify the
  attested-healthy list with the full required list, and discharges
  the residual `decide (n < n)` by `Nat.lt_irrefl`.
- Verdict: the premise `h_prev_partition` is now structurally
  load-bearing. The conclusion's contrast between
  `partitionContingencyMode declprev = true` and
  `partitionContingencyMode declnext = false` on the same
  attestation states the amendment's structural-improvement
  semantics: the amendment shrank the required substrate enough
  that the same attestation now covers it. The `_h_prev_decl`
  binder remains underscore-prefixed (it constrains how `declprev`
  was obtained but does not appear in the conclusion's
  structural-improvement claim).

## Aggregate honesty assessment

Theorems 1, 2, and 4 each carry substantive structural content:

- Theorem 1 (headline) constructs healthy and degraded witnesses
  over a shared body and proves opposite admission verdicts.
- Theorem 2 establishes a proper-sublist biconditional via
  `List.filter_sublist`, `Sublist.length_le`, and
  `Sublist.eq_of_length`. The proper-sublist witness is no longer
  a one-step decision-procedure call.
- Theorem 4 binds the prior partition-contingency premise to a
  structural improvement claim: the same attestation that was in
  partition contingency for `declprev` is no longer in partition
  contingency for `declnext`. The premise is load-bearing in the
  conclusion's first conjunct.

Theorem 3 remains the one supporting theorem whose
`destructiveAdmissionFamily` hypothesis is currently inert; its
verdict above describes the structural-projection content the
theorem does carry.

The four theorems compile cleanly under Lean 4.28.0-rc1 with no
`sorry`. Axiom dependencies after the strengthenings:

- Theorem 1: `propext`, `Classical.choice`, `Quot.sound`.
- Theorem 2: `propext`.
- Theorem 3: `propext`.
- Theorem 4: `propext`, `Quot.sound`.

All three are standard Lean kernel axioms.
