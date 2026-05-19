# Wave 1D: Lean substrate audit

Independent verification of the README's claims about
`lean/SensorGroundedAdmission.lean`: theorem count, no-`sorry`,
kernel-only axioms, 583 lines, and the non-`rfl` headline. The
substrate's git state was restored after the build check.

## 1. Theorem count

The README and STATUS.md both name four headline / supporting
theorems. The file contains thirteen `theorem` declarations; four are
the named ones and nine are support lemmas declared with `theorem`
rather than `lemma`:

1. `providerKind_beq_self` (256)
2. `providerHealthy_healthyRecordFor_self` (261)
3. `providerHealthy_in_healthyWitness` (272)
4. `requiredSetCovered_healthyWitness` (285)
5. `dropAndMissBounded_healthyWitness` (295)
6. `dropAndMissBounded_degradedWitness` (308)
7. `not_requiredSetCovered_degradedWitness` (316)
8. `admission_predicate_separates_healthy_and_degraded_witnesses` (352)
9. `attestedHealthy_sublist` (402)
10. `partition_contingency_mode_iff_degraded_subset` (421)
11. `healthy_attestation_required_for_destructive_admission` (467)
12. `partitionContingencyMode_false_of_covered` (511)
13. `degraded_sensor_admission_requires_re_attestation` (546)

The README's "four theorems mechanized" refers to items 8, 10, 11, 13.
A strict reader doing `grep -c '^theorem '` will get 13. STATUS.md
calls items 1-7, 9, 12 "supporting lemmas," which is accurate prose
even though they are declared with the `theorem` keyword.

## 2. `sorry` audit

`grep -n "sorry" lean/SensorGroundedAdmission.lean` returns nothing.
Zero textual occurrences in any context (proof body, comment, string
literal). Verified.

## 3. Line count

`wc -l` returns `583`. Exact.

## 4. Axiom audit

I reproduced the `#print axioms` audit independently by copying the
file into `formal/lean4/Chio/Chio/Treaty/`, building, and running
`#print axioms` from a fresh `SGAxioms.lean`:

```
admission_predicate_separates_healthy_and_degraded_witnesses :
  [propext, Classical.choice, Quot.sound]
partition_contingency_mode_iff_degraded_subset : [propext]
healthy_attestation_required_for_destructive_admission : [propext]
degraded_sensor_admission_requires_re_attestation : [propext, Quot.sound]
```

This matches `build-log.md` byte-for-byte. Only the three standard
Lean 4 kernel axioms appear; no `sorryAx`. Individual theorems use
subsets: theorem 1 uses all three, theorem 4 uses two, theorems 2 and
3 use only `propext`. The "kernel-only" claim is verified.

## 5. Headline theorem statement

`admission_predicate_separates_healthy_and_degraded_witnesses`:

```
(c : SensorAwareConstitution) (f : ReceiptFamily)
(decl : RequiredSetDecl)
(h_decl : lookupRequiredSet c f = some decl)
(h_nonempty : decl.required ≠ [])
(h_body : ∃ r : ReceiptBody, r.family = f ∧ bodyAdmits c r = true) :
∃ (r : ReceiptBody) (a_h a_d : SensorAttestation),
  ...
  r.family = f
    ∧ admissibleUnderSensorState c hat_h = true
    ∧ admissibleUnderSensorState c hat_d = false
```

This is a genuine existence-of-witnesses claim. The conclusion
existentially quantifies a body and two attestations sharing that
body, then asserts opposite admission verdicts. The README's
description ("separates a fixed healthy attestation witness from a
fixed degraded attestation witness over a shared body") matches.

## 6. Supporting theorem statements

`partition_contingency_mode_iff_degraded_subset` (421):

```
partitionContingencyMode decl a = true ↔
  (List.Sublist (attestedHealthy decl a) decl.required
    ∧ attestedHealthy decl a ≠ decl.required)
```

The README calls this a biconditional between a ladder mode and a
structural set-subset relation. Accurate (the relation is technically
`List.Sublist`, but the proper-sublist content matches).

`healthy_attestation_required_for_destructive_admission` (467) concludes

```
∃ decl, lookupRequiredSet c r.body.family = some decl
  ∧ requiredSetCovered decl r.attestation = true
```

from an admission-true hypothesis. STATUS.md openly records that the
`destructiveAdmissionFamily` premise is inert (underscore-prefixed
binder). The README's prose ("case analysis on the class predicate
bites") slightly overstates the structural load that premise carries:
it carries none.

`degraded_sensor_admission_requires_re_attestation` (546) concludes

```
∃ witness : ReAttestationWitness,
  lookupRequiredSet cnext r.body.family = some witness.amendedRequiredSet
    ∧ partitionContingencyMode declprev witness.newAttestation = true
    ∧ partitionContingencyMode witness.amendedRequiredSet
        witness.newAttestation = false
```

The `h_prev_partition` premise feeds the first mode-true conjunct, so
it is load-bearing. `_h_prev_decl` is underscore-prefixed and unused;
STATUS.md flags this honestly.

## 7. rfl-gate check

The four named theorems' proof closers:

1. Theorem 1 (352-380): the healthy branch closes with `rfl` after
   three `rw` steps identify each conjunct with `true`; the degraded
   branch closes by `simp`. The `rfl` collapses `true && true && true
   = true`, a genuine definitional bridge, not a structural overclaim.
   The substantive work is in five support lemmas feeding the
   rewrites.

2. Theorem 2 (421-447): uses `decide_eq_true_iff`, `Nat.ne_of_lt`,
   `Sublist.length_le`, `Sublist.eq_of_length`, `Nat.lt_of_le_of_ne`.
   No `rfl` closer. Genuinely structural in both directions.

3. Theorem 3 (467-487): `cases` on `lookupRequiredSet`, then
   `refine ⟨decl, rfl, ?_⟩` uses `rfl` to discharge the
   `lookupRequiredSet ... = some decl` conjunct (correct: the `cases`
   branch introduced `h_lookup` of that exact form). The coverage
   conjunct comes from `Bool.and_eq_true` decomposition. Definitional
   bridge, not an overclaim.

4. Theorem 4 (546-581): `cases`, `Bool.and_eq_true` decomposition,
   witness construction, then `refine ⟨witness, rfl, ?_, ?_⟩` with
   `rfl` again discharging the `some declnext` equation from the
   `cases` branch. Closes with
   `partitionContingencyMode_false_of_covered`. Definitional bridge.

None of the four named theorems is a single-step `rfl` discharge of
the parent paper's `amendment_admissible_iff_backward_refinement`
shape. The four uses of `rfl` are local definitional bridges inside
larger structural proofs. The non-`rfl` headline claim is verified.

## 8. Substrate dependencies

The file's `import` block (lines 40-41):

```
import Chio.Treaty.PredicateLang
import Chio.Treaty.Intersection
```

Both modules exist at `formal/lean4/Chio/Chio/Treaty/PredicateLang.lean`
and `formal/lean4/Chio/Chio/Treaty/Intersection.lean`. Consistent with
the README.

## 9. Build attempt

The deployed Chio Lean root is a valid Lake project (`lakefile.lean`,
`lake` binary at `~/.elan/bin/lake`). I built the two dependencies
(`lake build Chio.Treaty.PredicateLang Chio.Treaty.Intersection`),
copied `SensorGroundedAdmission.lean` into
`Chio/Chio/Treaty/SensorGroundedAdmission.lean`, and ran
`lake build Chio.Treaty.SensorGroundedAdmission`:

```
Build completed successfully (4 jobs).
```

No warnings, no errors. The section-4 `#print axioms` output was
produced from the same build artifact. After the audit, the temporary
file was removed and the substrate's git state was verified clean.
The build-log.md "compiles under Lean 4.28.0-rc1 with Lake
5.0.0-src+3b0f286" claim is verified end-to-end on this host.

## Mechanization-claim verdict

All five claims are verified:

- Four named theorems mechanized: verified. The file carries nine
  additional support lemmas declared with the `theorem` keyword; a
  strict `grep -c '^theorem '` returns 13. The README's prose about
  the four load-bearing theorems is accurate, but a reader counting
  declarations will see a higher total.
- No `sorry`: verified (zero textual occurrences).
- Kernel axioms only: verified. Theorem 1 uses all three, theorem 4
  uses two, theorems 2 and 3 use only `propext`. No `sorryAx`.
- 583 lines: exact.
- Non-`rfl` headline: verified. The headline uses five support lemmas
  plus a Boolean-collapse `rfl` as the final step on one branch; the
  other branch closes by `simp`. The four uses of `rfl` across the
  four named theorems are all local definitional bridges, not
  structural overclaims.

Honesty caveats the README does not surface but STATUS.md does:
`_h_destructive` (theorem 3) and `_h_prev_decl` (theorem 4) are
underscore-prefixed unused binders. Theorem 3's
`destructiveAdmissionFamily` premise is currently inert; the
README's "case analysis on the class predicate bites" slightly
overstates the situation for that theorem. The mechanization
claim itself is intact; the narrative tightness of one supporting
theorem could be improved.
