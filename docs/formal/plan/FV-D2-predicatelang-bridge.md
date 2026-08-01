# FV-D2: PredicateLang Bridge and Bounded Treaty Model

Status: Completed (2026-07-25)
Theme: D - Widen the verified frontier
Depends on: none
Feeds: [FV-C4](FV-C4-policy-smt-analyzer.md)

## Result

The treaty proof surface now contains two models with an explicit relationship
between them:

- `Intersection.lean` retains the general closure model. Its predicates have
  type `ReceiptId -> Bool`, and its refinement relation quantifies over all
  receipt identifiers. It remains useful as the semantic specification, but it
  is not a decision procedure.
- `PredicateLang.lean` defines a finite predicate syntax over a structured
  `ReceiptView`. Every atom has executable semantics for receipt identifiers,
  receipt hashes, action classes, participant kernel IDs, ladder ranks, live
  continuations, decisions, failure codes, and evidence digests.
- `IntersectionSyntactic.lean` defines treaty admission with syntactic scope and
  constitution predicates. Its amendment witness is explicitly bounded by the
  finite receipt domain stored in the delta.
- `BridgeEquivalence.lean` proves pointwise agreement between syntactic
  admission and the closure model after resolving a legacy receipt identifier
  to a `ReceiptView`.

This closes the representation gap that made the former decidability wording
incorrect. The result is bounded decidability, not universal decidability.
A finite-domain refinement witness says nothing about a receipt outside the
declared domain.

## Formal boundary

For a predicate `p` and receipt view `r`, `denote p r` is executable. For
syntactic constitutions `new` and `old` and a finite list `D`,
`refinesOnConstitution new old D` is executable and decidable.

The soundness statement is:

```text
refinesOnConstitution new old D = true
  implies
for every r in D, admits new r = true implies admits old r = true.
```

There is deliberately no theorem that promotes this finite result to
`forall r`. The legacy relation `BackwardRefines` remains universally
quantified, and `bridge_soundness` reaches it only from an independently
supplied universal syntactic witness.

The submission polity is `P = (T, K)`: receipt scope `T` and constitutional
predicates `K`. Citizenship is not represented in this model and cannot appear
as a formal contribution claim.

## Shipped declarations

`PredicateLang.lean` supplies:

- `bridge_pointwise`
- `bridge_soundness`
- `bridge_decidable_soundness`
- `refinesOnConstitution_iff`

`IntersectionSyntactic.lean` supplies:

- `treaty_admission_iff_predicate_intersection`
- `treaty_admission_stable_under_ladder_floor`
- `amendment_admissible_iff_bounded_refinement`
- `amendment_without_refinement_rejected`
- executable examples for a nontrivial narrowing and a rejected widening

`BridgeEquivalence.lean` supplies:

- `Legacy.scope_pointwise`
- `Legacy.polity_admission_agrees`
- `Legacy.treaty_admission_agrees`
- `Legacy.treaty_admission_under_mode_agrees`
- `Legacy.bounded_amendment_sound`

All declarations are imported through `Chio.lean`, listed in
`formal/proof-manifest.toml`, and recorded in
`formal/theorem-inventory.json`. The legacy module is retained with a header
that states its non-decidable status.

## Rust handoff

The Rust mirror must preserve the following conditions:

1. The receipt projection contains exactly the fields interpreted by
   `denoteAtom`.
2. Predicate recursion and list membership reproduce Lean's Boolean semantics.
3. The production evaluator and the independent reference evaluator do not
   share an implementation helper.
4. Differential generators cover every atom, constructor, empty collection,
   absent optional field, duplicate entry, and bounded nesting.
5. Any amendment result is reported as finite-domain evidence. The Rust mirror
   must not describe it as a universal proof or as Lean verification of Rust.

## Verification

The required proof gate is:

```bash
./scripts/check-formal-proofs.sh
```

The completed gate builds 25 Lean jobs, scans the shipped source for
placeholders, and validates the proof manifest, declared namespace opens,
assumptions, root imports, and theorem inventory.

## Residual limitations

- The bridge proves semantic agreement for the modeled syntax; it does not
  prove that the production Rust admission path is equivalent to Lean.
- The finite amendment domain is supplied by the caller. Domain completeness
  is an operational obligation outside this model.
- Concrete signature verification, canonical JSON, storage, clocks, and
  network delivery remain outside these treaty theorems.
- No production amendment-enactment state machine is claimed.
