# Headline Theorem Candidates (Cycle-2 Investigation)

## Question

The cycle-1 adversarial review (finding F1) charged that the current
headline theorem
(`admission_under_degraded_state_distinguishable_from_healthy`) is
structurally a Σ-construction over two fixed witnesses, weaker than the
"structural separation" promised by the prose before the honesty pass. The
reviewer suggested Theorem 3
(`healthy_attestation_required_for_destructive_admission`) may be the
natural headline: a universal claim that destructive admission requires
healthy attestation. This note compares the four theorems by structural
strength and proposes a verdict.

## The four theorems

### Theorem 1: `admission_under_degraded_state_distinguishable_from_healthy`

`lean/SensorGroundedAdmission.lean:350-378`. Statement:

```
∀ c f decl r, lookupRequiredSet c f = some decl ∧ decl.required ≠ [] ∧
              (∃ r, r.family = f ∧ bodyAdmits c r = true)
  → ∃ r a_h a_d, r.family = f ∧
                  admissibleUnderSensorState c (r, a_h) = true ∧
                  admissibleUnderSensorState c (r, a_d) = false
```

This is a Σ-construction. The witnesses are `healthyWitness decl` (one
healthy record per required entry) and `degradedWitness` (empty provider
list). The proof instantiates these two fixed witnesses and discharges
each branch via the support lemmas
(`requiredSetCovered_healthyWitness`,
`not_requiredSetCovered_degradedWitness`, plus
`dropAndMissBounded_*Witness`).

Structural shape: existence of two specific attestations that witness
opposite verdicts on a shared body. The body-admission premise is
existential and opaque (the `bodyPredicates` field carries function
values, so for any concrete constitution with a non-trivial predicate the
existential is unconstructable at the headline call site; the theorem
holds vacuously when `bodyPredicates = []`).

### Theorem 2: `partition_contingency_mode_iff_degraded_subset`

`lean/SensorGroundedAdmission.lean:419-445`. Statement:

```
∀ decl a, partitionContingencyMode decl a = true ↔
          (List.Sublist (attestedHealthy decl a) decl.required ∧
           attestedHealthy decl a ≠ decl.required)
```

This is a universally-quantified biconditional. The forward direction
extracts the sublist witness via `List.filter_sublist` and bridges to
list inequality via `Nat.ne_of_lt`. The backward direction uses
`Sublist.length_le` and `Sublist.eq_of_length` to derive the strict
length inequality from sublist plus distinctness.

Structural shape: a biconditional whose proof composes three named list
lemmas. STATUS.md flags this as the load-bearing inductive content of
the four theorems.

### Theorem 3: `healthy_attestation_required_for_destructive_admission`

`lean/SensorGroundedAdmission.lean:465-485`. Statement:

```
∀ c r, destructiveAdmissionFamily r.body.family = true →
       admissibleUnderSensorState c r = true →
       ∃ decl, lookupRequiredSet c r.body.family = some decl ∧
               requiredSetCovered decl r.attestation = true
```

This is a universally-quantified implication: any admitted receipt
witnesses a required-set declaration and coverage of that declaration.
The proof case-splits on `lookupRequiredSet`; the `none` branch is closed
by contradiction with `admissibleUnderSensorState = false`; the `some`
branch extracts coverage via a three-conjunct `Bool.and_eq_true`
decomposition.

Structural shape: universal projection of the admission predicate's
three-conjunct shape. **The destructive-admission-family premise is
inert.** STATUS.md and the proof both note the `_h_destructive` binder
is underscore-prefixed and not consumed by the proof body. The
conclusion holds for any admitted receipt, not only destructive-family
ones.

### Theorem 4: `degraded_sensor_admission_requires_re_attestation`

`lean/SensorGroundedAdmission.lean:544-579`. Statement:

```
∀ cprev cnext r declprev, lookupRequiredSet cprev r.body.family = some declprev →
                          partitionContingencyMode declprev r.attestation = true →
                          admissibleUnderSensorState cnext r = true →
  ∃ witness, lookupRequiredSet cnext r.body.family = some witness.amendedRequiredSet ∧
             partitionContingencyMode declprev witness.newAttestation = true ∧
             partitionContingencyMode witness.amendedRequiredSet
                                       witness.newAttestation = false
```

A universally-quantified amendment-improvement claim. The witness's
`newAttestation` is the receipt's own attestation; the
`amendedRequiredSet` is the new constitution's lookup; the
partition-contingency contrast (prev = true, next = false) on the same
attestation is the structural improvement. The proof composes
`partitionContingencyMode_false_of_covered` (which uses
`List.filter_eq_self` and `Nat.lt_irrefl`) with the
`Bool.and_eq_true`-extracted coverage from the amended admission.

Structural shape: universal claim that an amendment that re-admits a
partition-contingency receipt produces a structurally-improved
attestation state on the same bytes.

## Structural strength ranking

From weakest to strongest:

1. **Theorem 1** (existence of two opposite-verdict witnesses): a Σ-claim
   satisfied by fixed witnesses. The witnesses are concrete and the
   discharge is mechanical. As a structural claim, this says only "the
   admission predicate is not constant on attestation" -- weaker than
   the prose suggested before the cycle-1 honesty pass.

2. **Theorem 3** (admission witnesses required-set coverage): a Π-claim
   over admitted receipts. Stronger than Theorem 1 because it
   quantifies over all admitted receipts rather than constructing
   two. But the destructive-admission hypothesis is inert (so the
   claim is really "any admitted receipt witnesses coverage" rather than
   "destructive admission requires healthy attestation"). And the
   proof is mechanical: it is a Bool.and projection.

3. **Theorem 4** (amendment-improvement): a Π-claim over admitted
   amendments. The premise (prior partition-contingency mode) is
   structurally load-bearing in the conclusion's first conjunct, and the
   conclusion's contrast (prev = true, next = false) is substantive.
   But the proof exposes the construction: the "witness" is the
   receipt's own attestation bytes, repackaged as a `ReAttestationWitness`
   record. The substantive claim is the
   `partitionContingencyMode_false_of_covered` lemma.

4. **Theorem 2** (partition-contingency biconditional): a Π-claim
   that is a biconditional, with both directions requiring three named
   list lemmas (`filter_sublist`, `length_le`, `eq_of_length`). This is
   the only theorem whose proof does real structural list work in both
   directions. STATUS.md, the limitations section, and the cycle-1
   reviewer's "what survives the worst critique" section all converge
   on Theorem 2 as the load-bearing piece.

## Which is the strongest headline candidate?

**Theorem 2 is structurally the strongest.** It is a biconditional, a Π
over all attestations, and its proof composes three list lemmas in both
directions. STATUS.md confirms it is the only theorem whose proof does
non-trivial inductive work.

**Theorem 3 is the second strongest** if and only if its statement is
revised to remove the inert destructive-admission-family hypothesis. As
currently written, the hypothesis is decoration; the conclusion holds for
any admitted receipt. If the hypothesis is dropped (or strengthened so it
appears in the proof body), Theorem 3 becomes "any admitted receipt
witnesses required-set coverage" -- a clean universal projection. Even
then the proof is a Bool.and decomposition rather than substantive
structural work.

**Theorem 1** is the weakest, structurally. Its discharge is mechanical
once the support lemmas are in hand, and the witnesses are fixed at the
boundary of the construction.

## Most quotable in an abstract

A headline theorem must (a) read in plain prose, (b) make a claim a
non-formalist reader can recall, and (c) carry the paper's contribution
in one sentence. By that test:

- **Theorem 1**: "Admission under degraded substrate is distinguishable
  from admission under healthy substrate." Reads well, but the cycle-1
  review showed the formal claim is weaker than the prose. The current
  abstract (`paper.tex:23`) carries this framing.

- **Theorem 2**: "Partition-contingency mode holds iff the attested-healthy
  providers are a proper sublist of the required providers." Reads well
  to a formalist; weaker for a non-formalist who has to track what
  "partition-contingency" means.

- **Theorem 3**: "Destructive admission requires healthy attestation of
  every required provider." This is the quotable headline. It is a
  universal claim, it ties the contribution directly to admission
  semantics, and a non-formalist reader recalls it. The catch is that the
  Lean does not actually prove this claim: it proves "any admitted
  receipt witnesses required-set coverage" with destructive admission as
  an inert decoration.

- **Theorem 4**: "An amendment that re-admits a partition-contingency
  receipt produces a structurally-improved attestation state." Reads
  well, but the partition-contingency framing requires the reader
  already understand Theorem 2.

The most quotable, **if it were what the Lean actually proves**, would
be Theorem 3.

## Rewrite cost analysis

### Option A: Keep Theorem 1 as headline, rename for honesty

Rename Theorem 1 to
`existence_of_healthy_and_degraded_admission_witnesses` or
`admission_predicate_separates_healthy_and_degraded_witnesses`. The
existing prose in section 1, section 4, and section 10 already (post
cycle-1 honesty pass) describes the result as a Σ-construction. Rewrite
cost: rename in three places, update prose in section 4's headline
paragraph if any residual "structural separation" phrasing remains.
Estimate: half-day of paper editing, no Lean changes.

### Option B: Promote Theorem 3 to headline, strengthen the statement

Strengthen Theorem 3 so the destructive-admission hypothesis is load-bearing.
The natural strengthening: the conclusion mentions
`destructiveAdmissionFamily` somewhere it must, e.g., "for destructive
families the required-set list must be non-empty, and the attestation
covers every entry" -- requires a constitution-level invariant linking
destructive families to non-empty required sets, plus a proof that the
admission predicate enforces it. This is real structural work, not a
rename.

Rewrite cost: write a new constitution-level invariant
(`destructive_families_have_nonempty_required_sets`), prove the
admission predicate enforces it, restate Theorem 3 with this invariant
as a premise, replace abstract claim and section 1 contributions
bullet. Estimate: one day of Lean work plus one day of paper editing.

### Option C: Promote Theorem 2 to headline

Theorem 2 already does the structural work. Promote its biconditional
to the headline of section 1's contributions list, restate the abstract
around it, retain Theorem 1 as a supporting Σ-existence result.

Rewrite cost: rewrite abstract (one paragraph), rewrite section 1
contributions list (~5 bullets), rewrite section 4's headline
discussion, rewrite section 10's conclusion paragraph. Estimate: one
day of paper editing, no Lean changes.

The downside of Option C: Theorem 2's biconditional is about the
partition-contingency mode tag, which is a smaller claim than the
paper's main contribution (sensor-grounded admission). A reader looking
for "what does this paper add" would not be satisfied by "we make the
partition-contingency mode decidable." The contribution is broader.

## Recommendation

**Option A (rename Theorem 1 honestly, keep as headline) is the
recommended action.** The cycle-1 honesty pass already adjusted the prose
to call this a Σ-construction. The remaining work is making the theorem
name match the prose -- a one-day rename plus light prose touch-up.

The rationale:

1. Theorem 1 is the right *contribution shape* for the paper: it ties the
   admission predicate to the substrate attestation, and the existence of
   opposite-verdict witnesses is the minimum mathematical fact that
   justifies the construction.

2. Theorem 2 is the *load-bearing inductive content* but it is too narrow
   to carry the paper's headline. It is correctly framed as a supporting
   theorem.

3. Theorem 3 *would* be the strongest headline if its inert hypothesis
   were removed. The cycle-1 reviewer's F3 critique on this is correct.
   The fix is either to drop the destructive-family hypothesis (and
   restate the theorem as a general admission projection) or to
   strengthen it (and pay the day of Lean work). Either is reasonable v2
   work; neither is required for the present cycle.

4. The rename is the smallest change that makes the paper's claims and
   the Lean's content agree. Names like
   `admission_under_degraded_state_distinguishable_from_healthy` invite
   the misreading that the theorem proves a general separation; the
   actual theorem proves existence of two witnesses. A name like
   `admission_predicate_separates_healthy_and_degraded_witnesses` or
   `exists_admission_pair_on_shared_body_with_opposite_verdicts` is
   honest about the shape.

**Recommended name for Theorem 1:**
`admission_predicate_separates_healthy_and_degraded_witnesses`. The verb
`separates` is honest about what the witnesses do; the noun `witnesses`
flags the Σ-construction; the existing prose (post cycle-1) already
matches this framing.

If the authors want a stronger headline and are willing to pay the Lean
cost, Option B (strengthen Theorem 3) is the second-best stance. Option C
(promote Theorem 2) is structurally clean but narrows the paper's
apparent contribution.
