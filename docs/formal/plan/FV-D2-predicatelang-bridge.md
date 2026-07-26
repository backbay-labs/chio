# FV-D2: PredicateLang bridge soundness and the treaty-model swap

Status: Implemented (2026-07-11)
Theme: D - Widen the verified frontier
Effort: M
Depends on: none
Feeds: [FV-C4](FV-C4-policy-smt-analyzer.md)

## Result

The public treaty model now uses a decidable predicate language over a bounded
projection of Chio's production federation admission records. The former
closure representation remains available only in
`Treaty/IntersectionLegacy.lean`. Root-imported equivalence theorems prove
pointwise admission, domain-scoped refinement, global refinement, treaty
admission, and amendment-verdict agreement for every value produced by the
syntax-to-closure lift.

This is not a Rust refinement proof. The projection excludes parsing,
canonical hashing, signature verification, store lookup, and IO. Two
`abstraction_anchor` mirror entries bind the relevant Rust records and
validators so source drift requires explicit review without calling the Lean
file a transliteration.

## Decisions

- `AdmissionView` projects fields from `TreatyScope`, `LadderIntersection`,
  `BilateralInvocation`, and `CrossBoundaryEvidenceRef`, plus verifier-owned
  expected hashes, resolved mode, time, and joint policy result.
- `AtomTag` names production-shaped admission gates. There are no
  constant-false placeholders for supported atoms.
- `supported` rejects any predicate containing `.unsupported`, before `neg` or
  any other Boolean connective is evaluated.
- `defined` rejects a supported predicate when a required projected value is
  unavailable. In particular, an unknown governance mode remains denied under
  negation.
- Finite refinement is complete only on the exact, explicit `AdmissionView`
  domain supplied to the decision. No small-sample claim is made for all
  possible production inputs.
- `ConstitutionalDeltaSyn.ofDecide` is an actual decision procedure. It accepts
  old, new, and domain values and returns `Option ConstitutionalDeltaSyn`; the
  caller cannot provide the proof result.
- `Intersection.lean` is the public syntactic model. The closure model moved to
  namespace `Chio.Treaty.Legacy`, so the representation migration is not a
  parallel unused model.
- Treaty admission and amendment evidence map to P3 (fail-closed evaluation),
  not P7 (receipt-lineage soundness).

## Production correspondence

| Lean projection or gate | Production source | Scope |
| --- | --- | --- |
| `TreatyScopeView` | `crates/kernel/chio-runtime-core/src/types.rs::TreatyScope` | Schema, treaty id, participants, ladder hashes, action classes, and validity window |
| `LadderIntersectionView` | `types.rs::LadderIntersection` | Schema, treaty id, participants, ladder hashes, action classes, and validity window |
| `BilateralInvocationView` | `types.rs::BilateralInvocation` | Schema, treaty id, intersection and continuation hashes, action class, and signer ids |
| evidence fields | `types.rs::CrossBoundaryEvidenceRef` and `CrossBoundaryAdmissionInput` | Required, present, and verified evidence projection |
| schema, time, intersection, action, and evidence gates | `crates/kernel/chio-runtime-core/src/treaty.rs::validate_treaty_scope`, `validate_ladder_intersection`, `evaluate_cross_boundary_admission`, `validate_bilateral_invocation`, `ladder_mode_rank` | Bounded post-validation abstraction |

The two mirror entries use ordered per-symbol hashes. A matching hash proves
only that the reviewed Rust token stream has not changed. It does not prove
that Rust enforces a Lean theorem.

## Proof surface

| Theorem | Established boundary |
| --- | --- |
| `unsupported_predicate_denies` | Any syntax tree containing an unsupported atom denies before Boolean evaluation |
| `undefined_predicate_denies` | Missing projected semantics deny before Boolean evaluation |
| `negated_unknown_atom_denies` | Direct regression for unknown syntax under negation |
| `negated_unknown_mode_denies` | Direct regression for an unavailable mode under negation |
| `runtime_admission_policy_exact` | Admission is exactly support, definition, and truth of every registered modeled gate |
| `refinesOn_complete_on_fragment` | Predicate refinement decision is complete on its explicit finite domain |
| `refinesOnConstitution_complete_on_fragment` | Constitution refinement decision is complete on its explicit finite domain |
| `ConstitutionalDeltaSyn.ofDecide_isSome_iff` | The decision returns a proof-carrying delta exactly when domain refinement holds |
| `bridge_refinement_on_iff` | Domain refinement agrees in both representations |
| `bridge_global_iff` | Global refinement agrees in both representations |
| `toClosure_treatyAdmits_agrees` | Treaty admission agrees pointwise after lifting |
| `toClosure_amendmentVerdict_agrees` | Computed amendment verdict agrees after lifting |

`IntersectionSyntactic.lean` re-proves the four treaty results and includes an
executable non-trivial amendment. The old constitution accepts a policy-denied
but action-allowed input; the new constitution rejects it. The narrowing is
enacted by `ofDecide`, while the reverse widening is rejected.

## Completeness boundary

The earlier proposed equality-only receipt-id fragment was rejected because it
did not correspond to the production schema, and constant-false atom semantics
became fail-open under negation. The implemented theorem deliberately says:

```
refinesOn new old domain = true <->
  forall input, input in domain -> new input -> old input
```

The domain must therefore be verifier-owned and must contain every admission
input covered by the amendment decision. Generalization beyond that set needs
either a finite-domain construction for every projected field or a separate
symbolic completeness proof.

## Mutation calibration

The Lean mutation allowlist includes the fail-closed predicate and amendment
decision definitions. The mutation runner accepts only explicitly approved
`Core` and `Treaty` source roots, retains the global activation threshold, and
records per-source outcomes. Direct negative theorems for unsupported syntax,
undefined mode interpretation, and rejected widening remain root-imported even
when mutation sampling rotates.

## Acceptance evidence

- [x] `bridge_soundness`, `bridge_decidable_soundness`, and both reverse
  equivalence theorems are root-imported and sorry-free.
- [x] Finite refinement completeness is proved on the exact admission domain;
  the broader completeness exclusion is documented in code and here.
- [x] `IntersectionSyntactic.lean` re-proves all four treaty theorems and runs a
  genuinely non-trivial narrowing and widening example through `ofDecide`.
- [x] `Intersection.lean` now exposes the syntactic model; the closure model is
  isolated under `Chio.Treaty.Legacy`.
- [x] The theorem inventory, proof manifest, P3 property matrix, Rust drift
  anchors, mapping notes, and generated coverage are updated together.
- [x] The C4 handoff records the serialized-shape boundary, unsupported syntax
  behavior, and domain-scoped completeness contract.
- [x] `scripts/check-formal-proofs.sh`, `scripts/check-proof-report.sh`, formal
  mirror tests, mutation checks, mapping checks, and coverage checks pass.

## Exclusions

- No claim that `Predicate` is a production wire format.
- No claim that Lean parses JSON Schema or RFC 8785 canonical JSON.
- No cryptographic or store-refinement claim.
- No completeness claim outside the explicit admission domain.
- No inverse conversion from arbitrary closures to syntax. Bidirectionality is
  semantic equivalence on the image of `toClosure`, not representation
  isomorphism for arbitrary functions.

## Manifest and registry updates

- `formal/proof-manifest.toml` registers the syntactic PredicateLang modules,
  bridge theorems, runtime admission symbols, and mirror relationships.
- `formal/theorem-inventory.json` records the domain-scoped soundness and
  completeness results without widening them into parser or wire-format
  claims.
- `formal/MAPPING.md` binds the explicit finite admission domain and the
  fail-closed unsupported-syntax behavior to the runtime projection.
- `formal/assumptions.toml` gains no new trust dependency; the bridge scope is
  an explicit exclusion rather than an assumption.
