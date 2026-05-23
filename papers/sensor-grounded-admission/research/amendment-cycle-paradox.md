# Wire-Compatibility Amendment-Cycle Paradox (Cycle-2 N1 Investigation)

## Question

Does the current paper draft commit a wire-compatibility amendment violation
against the parent paper's `amendment_admissible_iff_backward_refinement`
theorem? The cycle-1 reviewer's N1 finding flagged that adding a
schema-compatibility predicate would itself be an amendment, and that the
predicate as drafted appears to add admission lanes rather than restrict them.

## Does the paper currently introduce a compatibility predicate?

Yes. `sections/05-implementation.tex:21-22` carries a paragraph titled
"Wire compatibility":

> The receipt schema is versioned. Receipts without an attestation block are
> admitted under a separate compatibility predicate that fails closed on every
> destructive admission and admits only observation-mode receipts. The
> compatibility predicate is a constitution-level declaration, removable by an
> amendment that narrows the admission predicate. Upgraded kernels produce
> receipts with an attestation block; downgraded kernels are denied at the
> schema-version check before the predicate evaluator runs.

`sections/09-limitations.tex:21-22` then references this paragraph:

> The wire-compatibility predicate from Section [implementation] admits
> pre-extension receipts under the observation mode only. A polity that
> operates a fleet of kernels at mixed schema versions must declare the
> compatibility predicate as a constitutional commitment; the admission
> predicate denies destructive actions on pre-extension receipts as a
> structural matter rather than as a heuristic. The mixed-version operating
> point is a transient and should be retired by an amendment that narrows
> admission to extension-bearing receipts; the parent paper's
> amendment-refinement discipline applies.

So the predicate is concrete prose in the implementation and is referenced
again in limitations. It is not deferred future work.

## Parent paper's backward-refinement obligation

From `papers/programmable-sovereignty/sections/04-model.tex:69-72` and
`formal/lean4/Chio/Chio/Treaty/Intersection.lean:80-90`:

```lean
abbrev BackwardRefines (new old : Constitution) : Prop :=
  forall receipt : ReceiptId,
    constitutionAllows new receipt = true -> constitutionAllows old receipt = true
```

The obligation is universally quantified over receipts. Every receipt admitted
by the new constitution must already be admitted by the old constitution. The
`ConstitutionalDelta` structure (`Intersection.lean:84-87`) carries
`proofTerm : BackwardRefines new old`, and `enactAmendment` is type-conditioned
on a constructable delta. The amendment path that does not carry the witness
does not type-check.

## Does the paper commit the violation?

This is the critical question. Two cases.

### Case A: read the compatibility predicate as an amendment to a pre-existing parent constitution

Under this reading, the parent paper's constitution had a single admission
predicate over body fields. The sensor-attestation paper introduces a new
admission predicate (the attestation-bearing one) plus a compatibility
predicate that admits pre-extension receipts in observation mode only.

The compatibility predicate's admission lane is over receipts that lack an
attestation block. The parent constitution admitted those receipts under its
body-only predicate. The new constitution admits them under the compatibility
lane. The new admission set on this class is a subset of the old admission set
(the compatibility predicate is strictly narrower: it caps mode at observation
and denies every destructive action). On the attestation-bearing class, the
old constitution rejects (the old parser had no attestation-block field, and
the parent constitution had no required-set predicate, so the receipt either
parses without the field or fails parsing; either way the old admission set on
this class is fixed). The new constitution admits attestation-bearing receipts
under the sensor-attested predicate.

The hard case is the attestation-bearing class. If the old constitution
denied all attestation-bearing receipts (because they fail the canonical-JSON
field-set check), then the new constitution admits a class that was previously
denied. This widens admission, violating backward refinement.

So under Case A, the amendment that introduces the sensor-attested predicate
appears to violate backward refinement on the attestation-bearing class.

### Case B: read the compatibility predicate as an amendment within the sensor-attestation paper's own constitution genealogy

Under this reading, the sensor-attestation paper introduces a fresh
constitution. The compatibility predicate is part of the initial constitution,
not a later amendment. The retirement path (`section 9 limitations`) is the
later amendment, and that amendment narrows admission (the new constitution
denies pre-extension receipts that the old constitution admitted in
observation mode). The narrowing amendment is a backward refinement.

Under Case B, the initial introduction of the compatibility predicate is
not an amendment at all. It is the initial constitution, and backward
refinement applies only to subsequent amendments. The paper's prose
("removable by an amendment that narrows the admission predicate") and the
limitation note ("should be retired by an amendment that narrows admission to
extension-bearing receipts") both fit Case B.

## Which reading is correct?

The paper does not commit to either reading explicitly. The cycle-1 reviewer's
N1 charge was implicitly Case A: that the compatibility predicate appears to
widen admission relative to a pre-existing parent constitution.

The paper's own framing in section 1 and section 7 is Case B: the
sensor-attestation paper introduces a new constitution that supersedes the
body-only construction; the compatibility predicate is part of the initial
constitution's design, not a subsequent amendment.

The Case B reading is defensible structurally, but it has a quiet cost: the
transition from the parent paper's constitution to the sensor-attestation
paper's constitution is not itself a backward-refining amendment. It is a
constitutional change of a kind the parent paper's amendment cycle does not
cover. The paper does not say this. The cycle-1 reviewer's N1 finding lands
on this silence.

## Recommended paper response

There are three coherent stances.

1. **Adopt Case B explicitly.** Add one sentence to section 5 wire
   compatibility paragraph or section 9 limitations: "The sensor-attestation
   constitution is a new constitution, not an amendment of the parent
   paper's body-only constitution. A deployment that migrates from
   body-only to sensor-attested operation must treat the transition as a
   constitutional change outside the amendment cycle, with whatever
   governance discipline that change requires." This makes the Case B
   reading textual rather than implicit.

2. **Adopt Case A and prove the refinement.** Restate the compatibility
   predicate as a fresh predicate that is the conjunction of the parent
   body-only predicate and a new destructive-mode-denial predicate. The new
   admission relation on the attestation-bearing class is then: body-only
   admission AND (attestation present AND attested required-set covered) OR
   (attestation absent AND mode below destructive floor). The first disjunct
   on its own is the new sensor-attested predicate; the second disjunct on
   its own is the compatibility predicate. The whole disjunction is narrower
   than the parent body-only predicate because every admitted receipt must
   either present a healthy attestation or accept the observation-only mode
   cap. This is a backward refinement of the parent and the amendment
   discharges. This stance requires either a new Lean proof obligation or a
   prose-only declaration with the structural argument shown.

3. **Defer to v2.** Strike the wire-compatibility paragraph from section 5
   and the corresponding limitation row from section 9. State in the paper
   that the construction is over a fresh substrate with no schema-version
   migration in scope. The mixed-version operating point becomes deployment
   work outside the paper's scope. This is the cleanest stance for the
   present submission and the one with the smallest rewrite cost. The
   schema-version question can be re-engaged in a future paper on
   deployment migration, where the amendment-cycle obligations have proper
   weight.

## Recommendation

Stance 3 (defer to v2) is the cleanest for the present submission. The
wire-compatibility paragraph adds two sentences of operational discussion at
a cost of opening a real amendment-cycle question the paper does not address.
The contribution is the sensor-attestation predicate over a fresh substrate;
migration from a non-attesting predecessor is genuinely outside the paper's
formal scope.

If the authors want to keep the wire-compatibility discussion, stance 1
(adopt Case B explicitly) is the second-best option and requires a single
sentence. Stance 2 (adopt Case A and prove the refinement) is the most
intellectually honest but the most expensive: it forces a new Lean theorem
on the disjunctive admission predicate and a corresponding refinement
witness. That work is reasonable for a v2 paper but disproportionate for
the present cycle.

The cycle-1 N1 charge is real but recoverable: the paper does not currently
commit a clear violation under either reading, but it does leave a question
under Case A that the prose does not answer. The fix is either a one-sentence
disambiguation (stance 1) or removal of the offending paragraph (stance 3).
