# FV-D2: PredicateLang bridge soundness and the treaty-model swap

Status: Proposed (2026-07-09)
Theme: D - Widen the verified frontier
Effort: M
Depends on: none
Feeds: [FV-C4](FV-C4-policy-smt-analyzer.md) (shared decidable predicate algebra)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G2, in its Lean-internal form), `formal/lean4/Chio/Chio/Treaty/PredicateLang.lean`, `formal/lean4/Chio/Chio/Treaty/Intersection.lean`

## Summary

`PredicateLang.lean` names its own missing theorem. Its header (L13-16) states: "`Predicate` is not yet wired into the polity model: that swap requires a bridge soundness theorem to the existing `BackwardRefines` closure relation, which is not proved here." This document specifies that bridge theorem precisely, decides the completeness scope (full completeness is provable on the currently modeled atom fragment via a small-model argument; the general case is documented incomplete with a counterexample family), and plans the migration of the treaty model in `Intersection.lean` onto the syntactic language so refinement witnesses become decidability-backed instead of unconstructable closures. The old closure module stays in place until the swap is proven equivalent through `denote` transport lemmas. The end state unlocks a Rust-side executable treaty check (a mirror of `denote`), which is the shared algebra [FV-C4](FV-C4-policy-smt-analyzer.md) builds its decidable-fragment analyzer on.

## Motivation and evidence

- The closure representation makes the headline treaty claims weaker than they look. `Intersection.lean` stores constitutions as `List (ReceiptId -> Bool)` (L19-20) and defines `BackwardRefines new old` as a universally quantified implication over all receipts (L80-82). `ConstitutionalDelta` carries `proofTerm : BackwardRefines new old` (L84-87), so `.enacted` is unconstructable without a real witness - good - but for any non-trivial polity no one can construct that witness either, because Lean cannot inspect closures. The PredicateLang header calls this out as rendering "the decidability claim a category error" (L5-8).
- The syntactic side already exists and is proved sound in isolation. Verified this session in `PredicateLang.lean`: the `Predicate` ADT (L44-51), `denote` (L67-73), decidable `refinesOn` (L81-82, instance at L138-140), the lattice lemmas (`refinesOn_refl` L85, `refinesOn_top` L94, `refinesOn_bot` L103, `refinesOn_conj_intro` L117), the essential-preservation chain theorems (L190, L209), the ratchet contrapositive (L238), the meta-amendment layer (`containsPredicate_preserved_chain` L287, `meta_amendment_requires_dropping_designated` L316, `containsPredicate_implies_satisfied` L335), and the lane-quorum layer (`anchor_admission_iff_lane_quorum_satisfied` L438, `anchor_admission_zero_quorum` L454, `anchor_admission_rejects_undeclared_lane` L467). What is missing is exactly one hop: nothing connects `refinesOn`/`admits` to `BackwardRefines`/`constitutionAllows`.
- Both modules are already release surface. `formal/proof-manifest.toml` `root_modules` lists `Treaty/Intersection.lean` and `Treaty/PredicateLang.lean` (L32-33), so theorems in both are inventory-tracked; a bridge theorem lands in the same evidence regime with no new plumbing.

## Current state

- `Intersection.lean` (165 lines, read in full): closure-based `Constitution`, `BilateralTreaty`, `TrustMode` ladder (L26-42), `treatyPredicateIntersection` (L60), `treatyAdmits` (L68), `treatyAdmitsUnderMode` (L74), and four theorems: `treaty_admission_iff_predicate_intersection` (L120), `treaty_admission_stable_under_ladder_floor` (L134), `amendment_admissible_iff_backward_refinement` (L142), `amendment_without_refinement_rejected` (L152).
- `PredicateLang.lean` (475 lines, read in full): everything listed above, plus the honesty note at L53-59 that `denoteAtom` is "a model bridge, not the production check": only `scopeContains` and `receiptHashEquals` denote non-trivially (both as `rid == constant`, L60-64); the other four atom tags currently denote `false`.
- No file imports `PredicateLang` except itself importing `Intersection` (L19); the runtime treaty verifier is Rust and consumes neither.

## Design

### The bridge theorems, stated precisely

Define the lift from syntax to the closure world, plus the constitution-level decidable check:

```
def toClosure (c : SyntacticConstitution) : Constitution :=
  { predicates := c.predicates.map denote }

def refinesOnConstitution
    (new old : SyntacticConstitution) (sample : List ReceiptId) : Bool :=
  sample.all (fun rid => decide (!(admits new rid) || admits old rid))
```

Three theorems, in increasing strength:

1. `bridge_pointwise` (transport lemma): `constitutionAllows (toClosure c) rid = admits c rid`. Proof is `List.all` over `map` fusion; this is the workhorse every re-proof routes through.
2. `bridge_soundness` (the theorem the header asks for): define the syntactic semantic refinement `SynBackwardRefines new old : Prop := forall rid, admits new rid = true -> admits old rid = true`; then `SynBackwardRefines new old -> BackwardRefines (toClosure new) (toClosure old)`. With `bridge_pointwise` this is definitional unfolding. The content is that a witness produced in the syntactic world is a legitimate `ConstitutionalDelta.proofTerm` for the lifted constitutions, i.e. `refinesOn`-backed enactment implies closure-level backward refinement over the polity domain.
3. `bridge_decidable_soundness` (what makes witnesses constructable): `refinesOnConstitution new old sample = true -> forall rid, rid ∈ sample -> admits new rid = true -> admits old rid = true`. This scopes the decidable check to the sample (the polity's admitted history, per the L76-80 comment), which is the domain the runtime actually adjudicates.

Proposed theorem-inventory rows (ids follow the existing `core.scope.*` naming pattern, verified in `formal/theorem-inventory.json` this session):

| Proposed id | Lean name | File |
| --- | --- | --- |
| `treaty.bridge.pointwise` | `bridge_pointwise` | `Treaty/PredicateLang.lean` |
| `treaty.bridge.soundness` | `bridge_soundness` | `Treaty/PredicateLang.lean` |
| `treaty.bridge.decidable_soundness` | `bridge_decidable_soundness` | `Treaty/PredicateLang.lean` |
| `treaty.bridge.mentioned_small_model` | `denote_depends_only_on_mentioned` | `Treaty/PredicateLang.lean` |
| `treaty.bridge.fragment_completeness` | `refinesOn_complete_on_fragment` | `Treaty/PredicateLang.lean` |
| `treaty.syntactic.admission_iff_intersection` | `synTreaty_admission_iff_predicate_intersection` | `Treaty/IntersectionSyntactic.lean` |
| `treaty.syntactic.ladder_floor_stable` | `synTreaty_admission_stable_under_ladder_floor` | `Treaty/IntersectionSyntactic.lean` |
| `treaty.syntactic.amendment_iff_refinement` | `synAmendment_admissible_iff_backward_refinement` | `Treaty/IntersectionSyntactic.lean` |
| `treaty.syntactic.no_witness_rejected` | `synAmendment_without_refinement_rejected` | `Treaty/IntersectionSyntactic.lean` |
| `treaty.bridge.equivalence_admits` | `toClosure_treatyAdmits_agrees` | `Treaty/BridgeEquivalence.lean` |
| `treaty.bridge.equivalence_verdict` | `toClosure_amendmentVerdict_agrees` | `Treaty/BridgeEquivalence.lean` |

### Completeness scope: prove it on the modeled fragment, document the boundary

The general statement "`refinesOn p q sample = true` for some finite sample implies semantic refinement over ALL receipts" is false, and no sample choice fixes it for arbitrary denotations. But the CURRENT atom denotation is equality-with-a-constant or constant-false (L60-64), which gives a small-model property:

- Define `mentioned : Predicate -> List ReceiptId` collecting the `scopeContains`/`receiptHashEquals` constants.
- Theorem `denote_depends_only_on_mentioned`: if `rid1` and `rid2` agree on membership in `mentioned p` (in particular, both are fresh: not mentioned), then `denote p rid1 = denote p rid2`. Structural induction; the atom case is the constant-equality observation.
- Theorem `refinesOn_complete_on_fragment`: with `sample = mentioned p ++ mentioned q ++ [fresh]` for any `fresh` not in either list, `refinesOn p q sample = true <-> (forall rid, denote p rid = true -> denote q rid = true)`. Freshness of a `String` outside a finite list is constructable (e.g. concatenation-length argument), so the right-to-left direction makes the decidable check COMPLETE, not just sound, on this fragment.
- Counterexample family for the general case, recorded as a named negative example in the file (not a theorem about production): any atom tag whose denotation inspects more receipt structure than identity (which is precisely what the production verifier does for `participantKeyEquals`, `actionClassIn`, `ladderModeAtLeastRank`, `continuationLive`) breaks `denote_depends_only_on_mentioned`, and a two-receipt sample distinguishing them shows `refinesOn` can be true while semantic refinement fails on an unsampled receipt. This documents that once `denoteAtom` is enriched toward the production semantics, completeness must be re-derived per atom (equality-like atoms keep it; ordered atoms like `ladderModeAtLeastRank` need their threshold values in the sample) - that re-derivation obligation is inherited by [FV-C4](FV-C4-policy-smt-analyzer.md).

### The swap: IntersectionSyntactic, proved equivalent, then adopted

New module `formal/lean4/Chio/Chio/Treaty/IntersectionSyntactic.lean` (the existing `Intersection.lean` is NOT edited in place):

- `SyntacticPolity` / `SyntacticBilateralTreaty` mirror the closure structures with `Constitution` replaced by `SyntacticConstitution` and `PolityScope.contains` replaced by a `Predicate` (scope-as-predicate; `top` recovers the always-true scope). The `TrustMode` ladder and `modeFloor` field carry over unchanged (they are already syntactic: an enum with a `rank`, `Intersection.lean` L26-42).
- `ConstitutionalDeltaSyn` carries `proofTerm : SynBackwardRefines new old`; a smart constructor `ConstitutionalDeltaSyn.ofDecide` produces it from `refinesOnConstitution ... = true` via `bridge_decidable_soundness` plus (on the modeled fragment) `refinesOn_complete_on_fragment`, so witnesses are now built by `decide`, which was the entire point. The `AmendmentCandidate` / `evaluateAmendment` pair migrates the same way; `amendmentAdmissible` remains proof-presence, now with a constructable proof.
- Re-prove the treaty theorem set over the syntactic types, transported through `bridge_pointwise`:
  - the intersection iff (`treaty_admission_iff_predicate_intersection`),
  - ladder-floor stability (`treaty_admission_stable_under_ladder_floor`),
  - amendment backward-refinement iff (`amendment_admissible_iff_backward_refinement`),
  - refusal without witness (`amendment_without_refinement_rejected`).
  Most transfer mechanically: each closure-side proof already proceeds by `unfold` plus Boolean algebra (verified in-file this session at `Intersection.lean` L120-163), and `bridge_pointwise` rewrites every `constitutionAllows (toClosure c)` occurrence into `admits c`.
- The essential-preservation, ratchet, meta-amendment, and lane-quorum theorems already live on the syntactic side in `PredicateLang.lean` (verified names: `essential_preserved_chain`, `ratchet_attack_requires_dropping_essential`, `containsPredicate_preserved_chain`, `meta_amendment_requires_dropping_designated`, `anchor_admission_iff_lane_quorum_satisfied`) and need only re-export or thin wrappers over the new treaty structure.
- Equivalence module `formal/lean4/Chio/Chio/Treaty/BridgeEquivalence.lean`: for every syntactic treaty, `treatyAdmits (toClosureTreaty t) rid = synTreatyAdmits t rid`, and the amendment verdict functions agree under the lift. This is the proof that the swap changed representation, not meaning.

The payoff, concretely. Today no non-trivial `ConstitutionalDelta` can be built (its `proofTerm` quantifies over all `String` receipts against opaque closures). After the swap, this compiles, with the refinement witness produced by `decide` on the relevant sample:

```
-- new constitution narrows the old (conjunction adds a predicate):
example : AmendmentVerdict :=
  enactAmendmentSyn <| ConstitutionalDeltaSyn.ofDecide
    (old := { predicates := [.atom (.scopeContains "rcpt-1")] })
    (new := { predicates := [.atom (.scopeContains "rcpt-1"),
                             .atom (.receiptHashEquals "h-77")] })
    (h := by decide)   -- checks refinesOnConstitution over the mentioned-ids sample
```

An `example` of exactly this shape (plus a rejected widening amendment) ships in `IntersectionSyntactic.lean` as executable documentation; it is the acceptance-criteria demonstration below.

### Deprecation step

Only after `BridgeEquivalence` is root-imported and green: mark `Intersection.lean` with a header note ("legacy closure model; kept because `ConstitutionalDelta` documents the unconstructability critique; new work targets `IntersectionSyntactic`"), keep it in `root_modules` (deleting it would orphan inventory rows), and point `PredicateLang.lean`'s header at the now-proved bridge instead of the "not proved here" disclaimer. Removal, if ever, is a separate PR that also retires the corresponding `theorem-inventory.json` rows; this plan does not remove anything.

### The Rust-side unlock (scoped out, but named)

`denote` is 7 lines of structural recursion; a Rust mirror over a serialized `Predicate` (serde enum) gives the federation runtime an executable treaty admission and refinement check whose semantics are the Lean model's. That mirror plus the decidable-fragment completeness theorem is exactly the algebra [FV-C4](FV-C4-policy-smt-analyzer.md) assumes; this plan delivers the Lean side only and hands the pair (ADT shape, completeness conditions per atom) to FV-C4.

## Implementation plan

1. Bridge lemmas in place. Modify `formal/lean4/Chio/Chio/Treaty/PredicateLang.lean`: add `toClosure`, `bridge_pointwise`, `SynBackwardRefines`, `bridge_soundness`, `bridge_decidable_soundness`. No existing theorem statements change.
2. Fragment completeness. Same file: `mentioned`, `denote_depends_only_on_mentioned`, `refinesOn_complete_on_fragment`, plus the named negative example documenting the incompleteness boundary for enriched atoms.
3. Syntactic treaty module. Add `formal/lean4/Chio/Chio/Treaty/IntersectionSyntactic.lean` with the structures, `ofDecide` smart constructor, and the four re-proved treaty theorems; add the module to `formal/lean4/Chio/Chio.lean` imports and to `proof-manifest.toml` `root_modules`.
4. Equivalence and header swap. Add `formal/lean4/Chio/Chio/Treaty/BridgeEquivalence.lean`; update the `PredicateLang.lean` header (L13-16) and add the legacy note to `Intersection.lean`'s header (header comment only; no definition edits).
5. Registry sweep. Update `formal/theorem-inventory.json` (new ids under `treaty.bridge.*`, `treaty.syntactic.*`, each with `leanName`, `file`, `rootImported: true`, `claimClass: bounded_model`, and `mapsTo` following the existing Treaty rows' convention - verify the convention in-file at edit time), and `formal/proof-manifest.toml` `root_modules` (two new files).

## CI and gating changes

- None structurally: the Lean tree is gated by `./scripts/check-formal-proofs.sh` (a `gate_commands` entry, `proof-manifest.toml` L38), which builds root-imported modules sorry-free. The two new modules ride that gate once listed in `root_modules`.
- The known G1 caveat applies (no PR-time `lake build`; see [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) G1): until [FV-E3](FV-E3-pr-formal-smoke-tier.md) lands, breakage of these proofs surfaces nightly/at release qualification. This plan does not add its own workflow; it becomes another beneficiary of FV-E3.
- `scripts/check-proof-report.sh` and the theorem-inventory consistency checks must pass with the new rows (same PR).

## Acceptance criteria

- [ ] `bridge_soundness` and `bridge_decidable_soundness` are proved, sorry-free, root-imported, and the `PredicateLang.lean` header no longer claims the bridge is unproved.
- [ ] `refinesOn_complete_on_fragment` is proved for the current atom denotation, and the incompleteness boundary for enriched atoms is documented in-file with the counterexample family.
- [ ] `IntersectionSyntactic.lean` re-proves all four `Intersection.lean` treaty theorems over `Predicate`-based constitutions, with witnesses constructable via `ofDecide` (demonstrated by at least one `#eval`/`example` enacting a non-trivial amendment through `decide`).
- [ ] `BridgeEquivalence.lean` proves admission and amendment-verdict agreement under `toClosure`; the legacy module is untouched except its header note.
- [ ] `formal/theorem-inventory.json` and `proof-manifest.toml` `root_modules` are updated in the same PR; `./scripts/check-formal-proofs.sh` and `./scripts/check-proof-report.sh` pass.
- [ ] A short handoff note in the FV-C4 doc's terms: the serialized `Predicate` shape and the per-atom completeness conditions are recorded for the Rust mirror.

## Risks and mitigations

- Scope-as-predicate is a modeling change, not just a representation change (`PolityScope.contains` was an arbitrary closure). Mitigation: `BridgeEquivalence` quantifies over syntactic treaties only; the legacy module keeps the fully general statement, and the equivalence theorem's hypothesis set documents exactly what generality was traded for decidability.
- Enriching `denoteAtom` later (toward the production verifier's checks) silently invalidates fragment completeness. Mitigation: `refinesOn_complete_on_fragment` is stated per the `mentioned`-based sample construction, so any atom change that breaks `denote_depends_only_on_mentioned` fails the build at the theorem, not in prose.
- Re-proof drift: two treaty modules could diverge while both are root-imported. Mitigation: the equivalence module is the tripwire; a change to either side that breaks agreement fails `check-formal-proofs.sh`.
- `List.all`/`decide` proof fragility across Lean toolchain bumps. Mitigation: keep proofs in the same simp-vocabulary as the existing file (which already leans on `List.all_eq_true`), and prefer `omega`/structural induction over fragile `simp` closure.

## Open questions

- Should `ladderModeAtLeastRank` get a real denotation in this wave (receipts do not carry a mode in the `ReceiptId`-only model, so it would need a richer receipt model), or stay `false` until the receipt model grows fields? Proposal: stay, and let the counterexample family document it.
- Does the lane-quorum layer migrate into `IntersectionSyntactic`'s treaty structure now (a `laneQuorumPolicy` field on the syntactic treaty), or remain a parallel layer as in `PredicateLang.lean` today? Proposal: parallel now; merging is mechanical once FV-C4 fixes the Rust shape.
- Naming: `SynBackwardRefines` vs overloading `BackwardRefines` in a new namespace; pick whichever keeps `theorem-inventory.json` ids stable.

## Manifest and registry updates

- `formal/proof-manifest.toml`: add `formal/lean4/Chio/Chio/Treaty/IntersectionSyntactic.lean` and `formal/lean4/Chio/Chio/Treaty/BridgeEquivalence.lean` to `root_modules`. No property-matrix change: treaty theorems are inventory-tracked but are not P1-P10 rows today, and this plan follows that existing convention.
- `formal/theorem-inventory.json`: new rows for the bridge lemmas, fragment-completeness theorems, syntactic treaty theorems, and equivalence theorems (`id`, `leanName`, `file`, `kind`, `rootImported`, `claimClass`, `mapsTo`, `notes` - the established schema, verified this session).
- `formal/assumptions.toml`: no changes (the bridge is internal to the bounded model; no new audited assumption).
- `formal/MAPPING.md`: no changes (no TLA invariant or Kani harness is added).
- `docs/reference/CLAIM_REGISTRY.md`: no new claim in this wave; if release prose ever states "treaty refinement witnesses are decidable", that claim must cite `bridge_decidable_soundness` plus the fragment-completeness scope, and adding it goes through the registry's normal approval flow.
