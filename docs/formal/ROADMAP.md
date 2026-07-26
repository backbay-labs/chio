# Formal Verification: Roadmap

- Status: Executed (2026-07-16; local gates complete)
- Companion docs: [CURRENT_STATE.md](CURRENT_STATE.md),
  [GAP_ANALYSIS.md](GAP_ANALYSIS.md), [HYGIENE_PASS.md](HYGIENE_PASS.md),
  plan specs under [plan/](plan/)

This roadmap records the execution order for the 23 plan specs plus the
hygiene pass. All fifteen hygiene items and 22 plan specs are implemented.
The economy collection proof remains blocked because its required netting
surface is not present on this branch; scalar conservation helpers and Kani
groundwork are implemented without claiming the absent collection behavior.
One further spec, [FV-B5](plan/FV-B5-verus-concurrency-evaluation.md), was
executed on 2026-07-23 as a time-boxed evaluation: the concurrent
conservation artifact and both falsification variants verified as
specified, and no lane was created because the FV-E5 enforcement
precondition (one promoted lane) is unmet. The spec records the outcome
and the experiment claims nothing.

Local toolchain-backed evidence is complete. Hosted history is a separate
advisory signal: ten scheduled gates and five pull-request gates are
registered, with six path-scoped gates frozen until qualifying workflow runs
exist. No hosted success streak is inferred from local execution.
Implementation was fixed at commit
`d292f14df1c493873199f4f9d969ade00472ff28` on 2026-07-15. The retained
proof-model report was refreshed against prerequisite commit
`a871396bffd010500f680c035e7b52c1867f38e2` on 2026-07-16, while the v1 schema
migration and refreshed specification report are bound to
`7b24142e8523fe08e501063dbf3d4f6cea3397be` on 2026-07-16.

Effort scale: S is days, M is one to two weeks, L is a month or more of
focused work. The waves below preserve the implemented dependency order and
the rationale used during execution.

## Execution outcome

- Implemented: hygiene H1-H15 and 22 of 23 plan specs.
- Blocked: FV-D3 collection conservation beyond the scalar groundwork because
  the M2 netting surface is absent. Property P11 is not registered or claimed.
- Local evidence: all required Rust workspace, Lean, Aeneas, Creusot, Kani,
  Apalache, differential, concurrency, and mutation gates completed against
  the implementation commit.
- Hosted evidence: workflow definitions and ratchets are implemented, while
  promotion streaks remain open and advisory.
- Assumption posture: distributed revocation is modeled and locally checked,
  but no transport assumption is retired until hosted execution and the
  modeled transport boundary justify that change.

## The whole portfolio at a glance

| ID | Title | Theme | Effort | Gaps | Wave |
| --- | --- | --- | --- | --- | --- |
| [Hygiene](HYGIENE_PASS.md) | 15 mechanical fixes | - | S | G4 | 0 |
| [FV-E3](plan/FV-E3-pr-formal-smoke-tier.md) | PR formal smoke tier | E | S | G1 | 0 |
| [FV-E4](plan/FV-E4-fuzz-plumbing-repair.md) | Fuzz plumbing repair | E | S | G6 | 0 |
| [FV-A3](plan/FV-A3-creusot-dedup.md) | Creusot dedup | A | S | G4 | 1 |
| [FV-A4](plan/FV-A4-mirror-drift-hashes.md) | Mirror drift hashes | A | S-M | G4, G1 | 1 |
| [FV-C5](plan/FV-C5-proof-coverage-map.md) | Proof coverage map | C | S | G4 | 1 |
| [FV-E2](plan/FV-E2-counterexample-regression-pipeline.md) | Counterexample-to-regression pipeline | E | S-M | G5 | 1 |
| [FV-B1](plan/FV-B1-drop-guard-model.md) | Drop-guard state-machine model | B | M | G3 | 2 |
| [FV-B2](plan/FV-B2-regression-negative-tests.md) | Fixed bugs as negative tests | B | S | G3, G5 | 2 |
| [FV-B3](plan/FV-B3-budget-conservation-law.md) | Budget conservation law, four lanes | B | M | G3, G2 | 2 |
| [FV-A1](plan/FV-A1-absorb-verified-helpers.md) | Absorb verified helpers | A | M (rolling) | G2 | 2 |
| [FV-E5](plan/FV-E5-lane-ratchets.md) | Lane ratchets and strictness recording | E | S-M | G1, G5 | 2 |
| [FV-E1](plan/FV-E1-spec-mutation-testing.md) | Spec mutation testing | E | M | G5 | 3 |
| [FV-A2](plan/FV-A2-aeneas-generated-equivalence.md) | Aeneas generated-code equivalence | A | M | G4 | 3 |
| [FV-C1](plan/FV-C1-receipt-trace-validation.md) | Receipt-log trace validation | C | M | - | 3 |
| [FV-C2](plan/FV-C2-verified-inclusion-verifier.md) | Verified inclusion verifier | C | M | G2 | 3 |
| [FV-B4](plan/FV-B4-loom-registry-and-dst.md) | Loom registry (part 1) | B | M | G3 | 3 |
| [FV-D2](plan/FV-D2-predicatelang-bridge.md) | PredicateLang bridge theorem | D | M | - | 3 |
| [FV-C3](plan/FV-C3-canonical-json-injectivity.md) | Canonical JSON injectivity (axiom shrink) | C | M-L | - | 4 |
| [FV-D3](plan/FV-D3-economy-conservation.md) | Economy conservation lane | D | M | - | 4 |
| [FV-D5](plan/FV-D5-protocol-typestates.md) | Protocol typestates | D | M | - | 4 |
| [FV-B4](plan/FV-B4-loom-registry-and-dst.md) | Deterministic simulation (part 2) | B | L | G3 | 5 |
| [FV-D1](plan/FV-D1-distributed-revocation-model.md) | Distributed revocation model | D | L | - | 5 |
| [FV-D4](plan/FV-D4-wasm-noninterference.md) | Wasm boundary non-interference | D | M-L | - | 5 |
| [FV-C4](plan/FV-C4-policy-smt-analyzer.md) | Policy analyzer feature | C | L | - | 5 |
| [FV-B5](plan/FV-B5-verus-concurrency-evaluation.md) | Verus concurrency evaluation | B | M | G3 | Evaluated |

## Dependency sketch

```
Wave 0   Hygiene   FV-E3 (PR tier)   FV-E4 (fuzz repair)
                        |                  |
Wave 1   FV-A3   FV-A4   FV-C5   FV-E2     |
                                  |        |
Wave 2   FV-B1 ----> FV-B2        |   (new targets follow E4 checklist)
           |  \----> FV-B3 <---- FV-A1 (phase 1: budget)
           |            \             \
Wave 3     |             \             +--> FV-C2 (absorption pattern)
         FV-C1 (uses B1 spec too)      FV-A2
         FV-E1 (stronger after B2)     FV-B4 part 1 (loom registry)
         FV-D2 --------------------+
                                   |
Wave 4   FV-C3   FV-D3   FV-D5     +--> FV-C4 (shared refinement algebra)
Wave 5   FV-B4 part 2 (DST, needs B1/B3 invariants)   FV-D1   FV-D4   FV-C4
```

FV-E5 (ratchets) starts in Wave 2 and then runs continuously. Its eleven
registered lanes remain advisory until a qualifying post-reset streak and the
runbook requirements justify promotion. No hosted streak is claimed here.

## Wave rationale

### Wave 0: make the existing estate honest and fast (days)

[HYGIENE_PASS.md](HYGIENE_PASS.md) removes every known contradiction.
[FV-E3](plan/FV-E3-pr-formal-smoke-tier.md) is pure wiring with outsized
effect: the measured 2.2-minute Kani sweep and a mathlib-free lake build move
from next-morning feedback to PR feedback.
[FV-E4](plan/FV-E4-fuzz-plumbing-repair.md) recovers fuzzing effectiveness
that is already paid for (13 unused rich seeds, unwired smoke tests).

### Wave 1: cheap structural guards (days each)

[FV-A3](plan/FV-A3-creusot-dedup.md) and
[FV-A4](plan/FV-A4-mirror-drift-hashes.md) convert the two hand-sync surfaces
(Creusot bodies, Lean mirrors) from discipline to mechanism.
[FV-C5](plan/FV-C5-proof-coverage-map.md) joins the registries into one
generated coverage page, which then drives all later prioritization.
[FV-E2](plan/FV-E2-counterexample-regression-pipeline.md) is small and makes
every future counterexample durable through content-addressed ITF fixtures,
active production replays, and deletion guarding.

### Wave 2: aim at the bug generator, wire proofs into production (the core wave)

The B package ([FV-B1](plan/FV-B1-drop-guard-model.md),
[FV-B2](plan/FV-B2-regression-negative-tests.md),
[FV-B3](plan/FV-B3-budget-conservation-law.md)) models the drop/cancel unwind
surface where the 2026-07 bug family lived, validates the model against the
five fixed bugs, and states the reservation conservation law in four
independent lanes. [FV-A1](plan/FV-A1-absorb-verified-helpers.md) begins the
rolling absorption of proven helpers into production call paths (budget first,
so it composes with FV-B3).
[FV-E5](plan/FV-E5-lane-ratchets.md) records strictness and bounded job history
so later promotion to required checks can be evidence-based.

### Wave 3: deepen the chains

[FV-E1](plan/FV-E1-spec-mutation-testing.md) measures the proof lanes
themselves (strongest once FV-B2's negative tests exist as calibration).
[FV-A2](plan/FV-A2-aeneas-generated-equivalence.md) upgrades the Aeneas hop
from symbol-presence to machine-checked equivalence.
[FV-C1](plan/FV-C1-receipt-trace-validation.md) and
[FV-C2](plan/FV-C2-verified-inclusion-verifier.md) are the first two
product-facing deliverables. [FV-B4](plan/FV-B4-loom-registry-and-dst.md)
part 1 gives the existing loom model a registry and a lane.
[FV-D2](plan/FV-D2-predicatelang-bridge.md) finishes the theorem the treaty
model names for itself.

### Wave 4: widen with the established patterns

[FV-C3](plan/FV-C3-canonical-json-injectivity.md) shrinks the single axiom to
pure hash collision resistance (headline: zero software axioms).
[FV-D3](plan/FV-D3-economy-conservation.md) applies the whole pipeline to the
M2 netting surface; note its hard prerequisite: the netting code lives on the
`chio/m2-build` branch today, so the spec cites branch-qualified paths and
re-verifies after that branch merges.
[FV-D5](plan/FV-D5-protocol-typestates.md) makes illegal protocol sequences
uncompilable in SDK cores.

### Wave 5: the long arcs

Deterministic simulation ([FV-B4](plan/FV-B4-loom-registry-and-dst.md) part
2), the distributed revocation model that can narrow
ASSUME-NETWORK-TRANSPORT ([FV-D1](plan/FV-D1-distributed-revocation-model.md)),
the wasm boundary non-interference statement
([FV-D4](plan/FV-D4-wasm-noninterference.md)), and the policy analyzer as a
customer feature ([FV-C4](plan/FV-C4-policy-smt-analyzer.md)). Each is
independently valuable and none blocks the others.

## Claims impact

Work that changes what `docs/reference/CLAIM_REGISTRY.md` may approve:

- FV-A1, FV-C2: grow the implementation-linked boundary
  (`FORM-IMPLEMENTATION-LINKED` scope, `covered_rust_symbols`).
- FV-A2: strengthens the `aeneas_production` evidence class from
  symbol-presence to proved equivalence over generated code.
- FV-C3: replaces the only Lean axiom with a theorem plus ASSUME-SHA256;
  enables a "no software axioms" claim (exact wording proposed in the spec).
- FV-D1: narrows ASSUME-NETWORK-TRANSPORT via the assumptions.toml
  retirement protocol.
- FV-B1/B2/B3: new P-property candidate for the unwind surface; FV-D3: new
  P-property candidate for economy conservation (both require the
  registry/manifest/inventory approval flow described in the specs).
- FV-E5: makes the RISK_REGISTER strict-lane claim rule mechanically
  enforceable (mode recorded in the proof report).

## Standing rules while executing

1. Falsifiability first: no new invariant or theorem counts as evidence until
   a broken variant or mutation demonstrably trips it (FV-B2/FV-E1
   discipline).
2. Absorption over parallel models: when verified logic exists, production
   should call it rather than mirror it (FV-A1 pattern); where a mirror is
   unavoidable, it gets a drift hash (FV-A4).
3. Registries stay authoritative: every new lane ships with its registry
   entry, MAPPING rows, and coverage-map integration in the same PR.
4. Honest posture: advisory lanes are labeled advisory; promotion to
   required goes through the FV-E5 ratchet with recorded streaks, and
   metadata-only runs can never masquerade as strict.

## Lane posture promotion runbook

1. Run `scripts/lane-gate.sh <lane> --report`. Promotion requires at least the
   configured consecutive-success streak, evidence newer than
   `evidence_after_run_id`, and a latest run inside `max_age_hours`. Dispatch
   runs are excluded. A strict-mode lane also requires an unexpired strict
   proof-report artifact for every counted run. Pull-request evidence must
   target the configured base branch and carry the exact per-attempt real-work
   marker artifact.
2. Change only `releases.toml`: set the lane's `posture` to `required` and add
   `promotion_evidence = { run_ids = [...], report_sha256 = "..." }`. The run
   IDs must be the exact configured streak after the reset. Paste the exact
   report output, including attempts, dates, job name, and freshness, in the
   pull request so reviewers can verify its SHA-256. The existing CODEOWNERS
   rule applies to that file; promotion does not require an enforcement-test
   edit.
3. Pull-request lanes are frozen. Before promotion, make the workflow run on
   every pull request, add a stable aggregator, and upload the configured
   execution marker only after the real proof job succeeds. Successful no-op
   runs must report the aggregator but must not upload the marker. Remove the
   freeze in the same reviewed change.
4. After the posture change merges, an administrator adds the exact job display
   name from `releases.toml` to the GitHub ruleset. Repository configuration is
   a separate manual step; changing the TOML file cannot update a ruleset.
5. Scheduled-only lanes use required posture only in the release-fleet sense.
   `scripts/lane-gate.sh --fleet` blocks release qualification when their latest
   qualifying job is missing, stale, non-strict when strict evidence is
   required, or unsuccessful. They are not pull-request checks.
6. Demotion changes `posture` back to `advisory`, removes
   `promotion_evidence` and the ruleset context where applicable, and links the
   incident record. A frozen lane cannot be promoted until the same reviewed
   change removes `frozen` and resolves its stated reason.
7. Set a new `evidence_after_run_id` whenever job semantics, proof mode, or
   evidence collection changes materially. Evidence before the reset never
   supports a later promotion.
