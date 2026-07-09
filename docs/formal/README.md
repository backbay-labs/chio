# Formal Verification Documentation

Planning and review set for the Chio formal verification estate, authored
2026-07-09 from a full repository survey at commit `dbb4639e1`. The living
verification artifacts themselves are under [`formal/`](../../formal/) at the
repository root (proof manifest, Lean project, TLA+/Apalache specs, Aeneas
lanes, Creusot contracts, diff-tests) with in-crate counterparts in
`crates/kernel/chio-kernel-core` and registries in `.kani/`,
`formal/rust-verification/`, and `fuzz/`. This tree is the map and the plan;
`formal/` is the territory.

## Reading order

1. [CURRENT_STATE.md](CURRENT_STATE.md) - what exists today: the six evidence
   lanes (Lean 4, Aeneas, Creusot, Kani, TLA+/Apalache, differential tests),
   the adjacent fuzzing/mutation/loom estates, the governance layer, and CI
   cadence. Descriptive only.
2. [GAP_ANALYSIS.md](GAP_ANALYSIS.md) - the six load-bearing gaps (G1-G6)
   with evidence and consequences, plus the staleness inventory.
3. [HYGIENE_PASS.md](HYGIENE_PASS.md) - fifteen mechanical fixes (H1-H15)
   with exact edits and verification steps. Wave 0 of the roadmap.
4. [ROADMAP.md](ROADMAP.md) - sequencing of all 23 plan specs into waves,
   the dependency sketch, claims impact, and standing execution rules.
5. The plan specs under [plan/](plan/), one architecture spec and
   implementation plan per work item.

## Plan spec index

Theme A - make the proven code the running code:

- [FV-A1: Absorb verified helpers into production call paths](plan/FV-A1-absorb-verified-helpers.md)
- [FV-A2: Prove equivalence against generated Aeneas output](plan/FV-A2-aeneas-generated-equivalence.md)
- [FV-A3: De-duplicate the Creusot contract bodies](plan/FV-A3-creusot-dedup.md)
- [FV-A4: Content-hash the model/code mirror seams](plan/FV-A4-mirror-drift-hashes.md)

Theme B - aim the formal tools at the actual bug generator:

- [FV-B1: Post-admission drop-guard state-machine model](plan/FV-B1-drop-guard-model.md)
- [FV-B2: Fixed production bugs as formal negative tests](plan/FV-B2-regression-negative-tests.md)
- [FV-B3: The budget conservation law in four lanes](plan/FV-B3-budget-conservation-law.md)
- [FV-B4: Loom lane registry and deterministic simulation](plan/FV-B4-loom-registry-and-dst.md)

Theme C - turn verification into product surface:

- [FV-C1: Receipt-log trace validation against the specs](plan/FV-C1-receipt-trace-validation.md)
- [FV-C2: Verify the inclusion-proof verifier relying parties run](plan/FV-C2-verified-inclusion-verifier.md)
- [FV-C3: Canonical JSON injectivity (shrink the single axiom)](plan/FV-C3-canonical-json-injectivity.md)
- [FV-C4: Policy analyzer as a customer feature](plan/FV-C4-policy-smt-analyzer.md)
- [FV-C5: Generated proof coverage map](plan/FV-C5-proof-coverage-map.md)

Theme D - widen the verified frontier:

- [FV-D1: Distributed revocation propagation model](plan/FV-D1-distributed-revocation-model.md)
- [FV-D2: PredicateLang bridge soundness theorem](plan/FV-D2-predicatelang-bridge.md)
- [FV-D3: Economy conservation lane](plan/FV-D3-economy-conservation.md)
- [FV-D4: Wasm guard boundary non-interference](plan/FV-D4-wasm-noninterference.md)
- [FV-D5: Protocol state machines as generated typestates](plan/FV-D5-protocol-typestates.md)

Theme E - verify the verification, make lanes bite:

- [FV-E1: Spec and proof-lane mutation testing](plan/FV-E1-spec-mutation-testing.md)
- [FV-E2: Counterexample-to-regression pipeline](plan/FV-E2-counterexample-regression-pipeline.md)
- [FV-E3: PR-time formal smoke tier](plan/FV-E3-pr-formal-smoke-tier.md)
- [FV-E4: Fuzz plumbing repair](plan/FV-E4-fuzz-plumbing-repair.md)
- [FV-E5: Lane ratchets and strictness recording](plan/FV-E5-lane-ratchets.md)

## Conventions

- IDs: gaps are G1-G6 ([GAP_ANALYSIS.md](GAP_ANALYSIS.md)), hygiene items
  H1-H15 ([HYGIENE_PASS.md](HYGIENE_PASS.md)), plan specs FV-<Theme><N>.
- Every plan spec carries a status header (all start as Proposed
  (2026-07-09)), an effort tag (S days, M one to two weeks, L a month or
  more), dependencies, and a "Manifest and registry updates" section listing
  the `formal/proof-manifest.toml`, `formal/MAPPING.md`,
  `formal/theorem-inventory.json`, `formal/assumptions.toml`, and
  `docs/reference/CLAIM_REGISTRY.md` changes the work implies.
- Adopting a spec: move its status to Accepted with a date and owner (owners
  default to the team in `formal/OWNERS.md`), open the tracking issue, and
  keep the spec updated as the design meets reality. Specs are plans, not
  normative protocol text; wire-level changes must still agree with
  `spec/PROTOCOL.md`.
- A future generated artifact, `COVERAGE.md` (the proof coverage matrix), is
  specified by [FV-C5](plan/FV-C5-proof-coverage-map.md) and will live in
  this directory once the generator lands.

## Relationship to claims

Nothing in this tree changes what Chio may claim publicly. Claims remain
governed by `docs/reference/CLAIM_REGISTRY.md` and the rules in
`docs/release/RISK_REGISTER.md`; several plan specs list the claim upgrades
their completion would justify (summarized in
[ROADMAP.md](ROADMAP.md#claims-impact)).
