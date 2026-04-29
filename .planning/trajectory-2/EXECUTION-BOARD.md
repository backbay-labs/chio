# trajectory-2 Execution Board

Operations document for executing the ten trajectory-2 milestones with
massive parallelism across execution + review + integration waves on
`main`. This is the canonical operations doc; per-milestone narratives are
the source of truth for scope.

Genesis: 2026-04-29 (parallel ten-agent authoring run; see section 1).
House rules: no em dashes, fail-closed, conventional commits, clippy
`unwrap_used = "deny"` and `expect_used = "deny"`.

---

## 0. Scope

This board operationalizes the ten milestones in
`.planning/trajectory-2/01-*.md` through `10-*.md`. It does not repeat
their content; it adds the layer that lets a swarm of executor + reviewer
agents land them concurrently on `main` without corrupting state.

Inputs:
- Ten milestone narrative docs + `README.md` + `STYLE.md`
- Sixty per-phase ticket files at `tickets/M{nn}/P{n}.yml`
- Generated `tickets/manifest.yml` (id-sorted concatenation of all phase files)

Outputs:
- All ten milestones merged to `main`
- `tickets/manifest.yml` reflecting `merged` for every ticket
- `EXECUTION-LOG.ndjson` audit trail
- Conformance, mutation, and threat-model gates green
- No regressions on existing trajectory-1 tests

Non-goals: releases, design partner work, certifications. Pure engineering.

---

## 1. Authoring provenance

Authored 2026-04-29 by ten parallel milestone agents, each receiving the
synthesis brief for one milestone slot. The agents produced:

| Milestone | Tickets | Effort (days) | Phases | Narrative LoC |
|-----------|--------:|-------------:|-------:|--------------:|
| M01 error-taxonomy-doctor-lsp           | 29 | 38.00 | P0..P5 | 467 |
| M02 mutation-and-cross-sdk-differential | 30 | 40.00 | P0..P5 | 400 |
| M03 pq-hybrid-and-tee-quote-verifier    | 32 | 40.00 | P0..P5 | 429 |
| M04 recursive-delegation-revocation     | 32 | 44.25 | P0..P5 | 514 |
| M05 adversarial-escape-threat-model     | 26 | 32.75 | P0..P5 | 148 |
| M06 performance-hardening-pack          | 31 | 36.75 | P0..P5 | 379 |
| M07 adoption-beachhead-pack             | 40 | 57.00 | P0..P6 | 506 |
| M08 chio-arena-replay-coliseum          | 34 | 43.50 | P0..P5 | 506 |
| M09 economic-layer-and-lineage          | 38 | 47.00 | P0..P5 | 483 |
| M10 hardware-custody-and-model-cards    | 33 | 41.00 | P0..P5 | 539 |
| **TOTAL**                               | **325** | **420.25** | 61 files | 4,371 |

Mean ticket effort: 1.29 days. Median ticket effort: 1.0 days. No ticket
exceeds the 2-day STYLE.md sizing ceiling. M07 P6 (six tickets, 8.0
effort-days) was added 2026-04-29 to close the D07 deferral identified
in `RECONCILE-NEEDED.md`; see decisions.yml D07 consequences.

---

## 2. Wave plan

A wave is a saturation-of-parallelism cohort: the maximal set of tickets
whose dependency closure is satisfied AND whose file-ownership write-sets
are mutually disjoint, capped by the per-wave concurrency ceiling. Waves
mirror trajectory-1's four-wave pattern.

### Wave 0: pre-flight

Before any P0 wave-opener runs, these artifacts must exist:

| # | Artifact | Path | Owner | Blocking |
|---|----------|------|-------|----------|
| 1 | Ownership manifest | `.planning/trajectory-2/OWNERS.toml` | sequencer | yes |
| 2 | Freeze register | `.planning/trajectory-2/freezes.yml` | sequencer | yes |
| 3 | Decisions register | `.planning/trajectory-2/decisions.yml` | sequencer | yes |
| 4 | Generated CODEOWNERS regen for trust-boundary paths | `CODEOWNERS` | sequencer | yes |
| 5 | Ticket manifest (generated) | `.planning/trajectory-2/tickets/manifest.yml` | sequencer | yes |
| 6 | Per-phase ticket files | `.planning/trajectory-2/tickets/M{nn}/P{n}.yml` | per-milestone agents | yes |
| 7 | Execution-state seed | `.planning/trajectory-2/EXECUTION-STATE.json` | orchestrator | yes |
| 8 | Audit-log path | `.planning/trajectory-2/EXECUTION-LOG.ndjson` | orchestrator | created on first append |
| 9 | `m05-freeze-guard` style branch ruleset rewritten for trajectory-2 freezes | GitHub branch ruleset | infra | M03/M04/M05/M10 P1 start |
| 10 | manifest query toolchain pinned (yq v4 + jq) | `scripts/install-orchestrator-tools.sh` | sequencer | yes |
| 11 | Audit-doc skeletons seeded for all ten milestones with starting hard counts copied from each narrative | `.planning/audits/M{NN}-<slug>.md` | sequencer | each milestone P0 audit-doc ticket |

Items 1, 3, 5, 7 ship in this initial commit. Items 2, 4, 8, 9 land in the
Wave 0 follow-up before any feature work opens.

### Wave 1: foundation (parallel)

Independent milestones that unblock everything downstream.

| Milestone | Phases | Approx tickets | Notes |
|-----------|--------|----------------|-------|
| **M01** error/doctor/LSP | P0..P5 | 29 | Unblocks every other milestone's error reporting path |
| **M02** mutation + cross-SDK differential | P0..P5 | 30 | Calibrates the trajectory-1 test mass; gates M07 SDK regressions |
| **M06** performance hardening pack | P0..P5 | 31 | Lands `CanonicalBytes` early; M03 and M09 declare it in `soft_deps` |

Wave 1 sustained concurrency: bounded by `Cargo.lock` sequencing,
`shared_paths` collisions, and the dependency DAG. Aim for 6-10
concurrent in-flight tickets per milestone in Wave 1.

`Cargo.lock` ordering across Wave 1 P0 wave-openers:
M06 -> M02 -> M01. (M06 lands `dhat` and `dashmap` upgrades that the other
two consume.)

### Wave 2: trust-boundary regression nets (parallel after Wave 1)

| Milestone | Phases | Tickets | Trust-boundary | Notes |
|-----------|--------|---------|---------------|-------|
| **M03** PQ + TEE quote | P0..P5 | 31 | yes | Extends `chio-attest-verify` (does not fork) |
| **M04** delegation + revocation | P0..P5 | 32 | yes | Re-attacks the v3.18 bounded retreat; signs roots via M03 |
| **M05** adversarial + escape + threat-model | P0..P5 | 26 | yes | Threat-model registry is the CI gate every later milestone hits |

Wave 2 trust-boundary discipline: every PR receives security x2 review
(two independent reviewer instances with different seeds and no shared
scratchpad), in addition to `@bb-connor`.

### Wave 3: breadth (parallel)

| Milestone | Phases | Tickets | Notes |
|-----------|--------|---------|-------|
| **M07** adoption beachhead | P0..P6 | 40 | Five new provider adapters + Vercel AI SDK + `arc mcp wrap` + four deployment-shape SDK drivers (closes D07) |
| **M08** chio-arena | P0..P5 | 34 | Adversarial corpus generator; cross-pollinates M02 + M05 |

### Wave 4: capstones

| Milestone | Phases | Tickets | Notes |
|-----------|--------|---------|-------|
| **M09** economic layer + lineage | P0..P5 | 38 | Wakes six dormant crates; consumes M04 delegation + M06 CanonicalBytes |
| **M10** hardware custody + model cards | P0..P5 | 33 | Trust-boundary; satisfies the M08.P3 (trajectory-1) verdict promise |

### Wave gate sequencing

```
Wave 0 -> Wave 1 (M01 || M02 || M06)
                    |        |        |
                    v        v        v
                Wave 2 (M03 || M04 || M05)  -- trust-boundary
                    |        |        |
                    v        v        v
                Wave 3 (M07 || M08)
                    |        |
                    v        v
                Wave 4 (M09, then M10)
```

M09 and M10 in Wave 4 may overlap if M03/M04/M07 are all merged. The
recommended order is M09 first (lineage + economic layer activation
unblocks anchoring used in M10 P5).

#### Wave 4 sub-gate: M09-must-precede-M10 ticket-level dependencies

Even within the optional overlap, the orchestrator MUST observe the
following ticket-level precedences (per cold-reader cross-cutting #2):

| Predecessor | Successor | Reason |
|-------------|-----------|--------|
| `M09.P5.T6` (lineage anchor pinning) merged | `M10.P5.T1` (lineage anchoring of model cards) opens | M10 P5.T1 publishes cards into the M09 anchor proof surface |
| `M07` (Wave 3) merged | `M10.P5.T2` (cross-provider equivalence) opens | M10 P5.T2 consumes the M07 verdict-equality oracle |
| `M05.P5.T4` (threat-model-coverage CI gate) merged | `M10.P5.T3` (M10 threat-id coverage) opens | M10 P5.T3 writes into the schema M05 P5.T1 owns |

#### Wave 0 preflight: credential / account inventory

Per cold-reader cross-cutting #3, several trajectory-2 gates require
credentials or external accounts. Before any Wave 1 ticket opens, the
sequencer MUST confirm visibility into the following (one preflight
ticket, ownership: `infra`):

- npm `@chio` org publish token (consumed by M07 P5.T6 and M10 P3.T1).
- Provider live-API keys for the nightly conformance lane:
  `OLLAMA_HOST`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
  `BEDROCK_ACCESS_KEY` + `BEDROCK_SECRET_KEY`, `GROQ_API_KEY`,
  `MISTRAL_API_KEY`, `GEMINI_API_KEY`, `COHERE_API_KEY` (M07 P3-P4
  expects these as repository secrets; PR CI uses recorded fixtures).
- AWS Nitro NSM fixture-collection account (M03 P3 quote backend
  collateral feed; non-blocking if collateral is statically pinned).
- Intel TDX collateral feed access if non-public (M03 P3-P4).

Missing credentials surface as a Wave 0 BLOCK; the orchestrator does
not open Wave 1 until the inventory ticket merges with each entry
either confirmed-present or marked `deferred-with-rationale`.

---

## 3. Cross-milestone artifact ownership

Single source of truth, never duplicated. (Mirrors trajectory-1
`README.md` cross-doc invariants table; reproduce here for orchestrator
visibility.)

| Artifact | Owner | Consumers | Notes |
|----------|-------|-----------|-------|
| `urn:chio:error:*` registry (`spec/errors/registry.yaml`) | M01 | M07, M02, all CLI surfaces | Every `Err(_)` in `dispatch.rs` carries a code; SDKs codegen from registry. |
| `chio-lsp` schema bindings + editor extensions | M01 | M07 editor support, all `chio.yaml` consumers | Server at `crates/chio-lsp/`; VSCode + Zed in `editors/`. |
| Cross-SDK verdict-matrix harness | M02 | M07, M05, M08 | At `crates/chio-conformance/verdict_matrix/`; corpus hash-pinned. |
| `chio-attest-verify` PQ + TEE-quote surface | M03 | M04, M09, M10 | Single verifier crate; M03 must NOT fork. |
| `chio-revocation-oracle` sparse-Merkle CRL-Lite | M04 | M09, M10 | Epoch-stamped roots signed via M03. |
| `chio-adversarial-suite` corpus | M05 | M02 (mutants), M08 (arena auto-promotes per D14) | One JSON file per attack class under `crates/chio-adversarial-suite/cases/`. |
| Threat-model registry (`spec/security/chio-threat-model.v1.json`) | M05 | M03 (adds 2 IDs in P0), M04 (delegation/revocation rows), M10 (adds 3 IDs in P0) | Producers append rows in P0; M05 owns the load-bearing CI coverage gate. |
| `CanonicalBytes` newtype | M06 | M03, M09 | Lives in `chio-core-types`; existing receipt path migrates with byte-equivalence proofs against trajectory-1 M01 vectors. |
| Scenario DSL + arena receipt bundles | M08 | M02 verdict matrix, M05 corpus, M09 reputation | Scenarios under `arena/scenarios/`; receipt bundles at `tests/replay/fixtures/arena/`. |
| `chio-credit`/`chio-settle`/`chio-reputation` activation | M09 | M10 (model card economics if shipped) | Wakes the dormant economic layer atop M06 OCI registry. |
| `chio-lineage` provenance graph | M09 | M10 P5 anchoring | Indexes trajectory-1 M10 OTEL stream + M04 corpus. |
| `chio-custody-hw` passkey envelope + `chio-weights` model card schema | M10 | end of trajectory | Satisfies trajectory-1 M08.P3 verdict promise. |

---

## 4. Freezes

See `freezes.yml` for the canonical freeze register. Summary:

| Freeze id | Milestone(s) | Path glob | Window | Hard-lock |
|-----------|--------------|-----------|--------|-----------|
| `m03-attest-verify-pivot` | M03 P1..P3 | `crates/chio-attest-verify/**` | from M03 P1 start | trust-boundary |
| `m03-pq-primitives-pivot` | M03 P1..P2 | `crates/chio-core/src/signature*.rs`, `crates/chio-core-types/src/canonical*.rs` | from M03 P1 start | trust-boundary |
| `m04-revocation-oracle-pivot` | M04 P1..P3 | `crates/chio-revocation-oracle/**`, `crates/chio-credentials/src/revocation*.rs` | from M04 P1 start | trust-boundary |
| `m04-delegation-pivot` | M04 P3..P5 | `crates/chio-core-types/src/capability*.rs`, `crates/chio-kernel/src/delegation*.rs` | from M04 P3 start | trust-boundary |
| `m05-adversarial-corpus-pivot` | M05 P1..P5 | `crates/chio-adversarial-suite/**`, `spec/security/chio-threat-model.v1.json` | from M05 P1 start | trust-boundary |
| `m10-custody-issuer-pivot` | M10 P1..P3 | `crates/chio-custody-hw/**`, issuer service paths | from M10 P1 start | trust-boundary |

Overlap windows (both freezes simultaneously active; the
`m{nn}-freeze-guard` required-check unions the listed `path_globs` for
the duration of the overlap; canonical source is the `overlap_with`
field on each row in `freezes.yml`):

| Milestone | Window | Freezes simultaneously active |
|-----------|--------|-------------------------------|
| M03 | P1..P2 (M03.P1.T1 through M03.P2.T6) | `m03-attest-verify-pivot` + `m03-pq-primitives-pivot` |
| M04 | P3 (M04.P3.T1 through M04.P3.T5) | `m04-revocation-oracle-pivot` (closing) + `m04-delegation-pivot` (opening) |

During each overlap window the `m{nn}-freeze-guard` GitHub
required-check unions the path globs of both rows; non-owner PRs that
touch any unioned path fail closed.

Hot-fix lane for trust-boundary freezes: `hotfix/<slug>` branches with
the `[trajectory-2]` bypass label and a single-reviewer override
documented in the milestone audit doc.

---

## 5. Concurrency policy

- **In-flight tickets per milestone:** soft cap 6, hard cap 10.
- **In-flight tickets across the trajectory:** soft cap 25, hard cap 40.
- **Trust-boundary phases:** soft cap 4 in-flight per milestone.
- `Cargo.lock` is always serialized via wave-opener tickets; no two
  tickets may write `Cargo.lock` in the same wave.
- `shared_paths` overlapping write-sets within a wave force sequencing.

---

## 6. CI budget assumptions

trajectory-2 inherits trajectory-1 CI minutes. The new gates added are:

- `mutation-coverage` (M02 P3): runs `cargo-mutants` on the trust-boundary
  set. Nightly only on PRs that touch those crates; full nightly run.
- `verdict-matrix` (M02 P5): cross-SDK semantic differential. Required on
  any SDK PR.
- `threat-model-coverage` (M05 P5): fails if any threat ID has no green
  test. Required on every PR.
- `adversarial-suite` (M05 P1): fails on `DENY-expected -> ALLOW`.
  Required on every kernel-core or attest-verify PR.
- `wasm-guard-escape` (M05 P3): nightly libFuzzer lane against the escape
  surface.
- `dhat-allocations` (M06 P5): heap-allocation budget gate. Required.
- `cold-start-budget` (M06 P5): browser kernel cold-start budget. Required
  on browser-kernel touches.
- `lean-build` (M04 P4): `lake build` over `formal/lean4/Chio/Capability/`.
  Required on capability-algebra PRs.
- `apalache-delegation` (M04 P4): `apalache check formal/tla/DelegationDepthBound.tla`.
  Required on PRs that touch capability or delegation crates.

Roughly +25-35% CI minutes vs trajectory-1 steady state. Budget review
before Wave 2 starts.

---

## 7. Failure-mode handling

- **Lean theorem fails CI:** open a `formal/lean4/counterexamples/<sha>.lean`
  with the failing case; revert offending change; do not skip the lean
  gate.
- **Apalache trace fails CI:** persist the trace at
  `formal/tla/counterexamples/<sha>.tla`; revert.
- **Mutation kill-rate regresses below 80%:** PR comment lists surviving
  mutants; merge blocked until either a test catches them or
  `mutants.toml` skip-with-rationale is added.
- **Threat-model gate fails on uncovered threat ID:** fail closed; the PR
  is the gate; either the threat is covered or its registration is
  reverted.
- **Cross-SDK verdict differential disagrees:** fail closed; root cause is
  almost always canonicalization or scope-set encoding drift.
- **WASM guard escape-class panic:** P0 incident; halt the trajectory
  worktree; capture the failing module hash; open `crates/chio-wasm-guards/incidents/`.

---

## 8. Audit trail

Every ticket merge appends an event to
`.planning/trajectory-2/EXECUTION-LOG.ndjson`:

```json
{"event": "ticket_merged", "id": "M01.P1.T1", "merged_sha": "<40hex>", "merged_ts": "<rfc3339>", "wave": "W1", "freeze": null}
```

Trust-boundary trajectory-2 events also append to a separate
`docs/trajectory-2-trust-boundary.log` for compliance review.

---

## 9. Trajectory close

trajectory-2 closes when all 325 tickets are status `merged` and the four
gates land green on `main`:

- mutation-coverage >= 80% on all six trust-boundary crates
- threat-model-coverage = 100% (where `coverage_state: covered` and
  `coverage_state: partial` both count as PASS per M05 P5.T1; any
  `coverage_state: pending` entry without an explicit `deferred_to`
  field fails the gate closed)
- verdict-matrix divergence count = 0 across 5 SDK languages
- lean-build green over the four delegation theorems; theorem 3
  (`revocation_is_cut`) MAY ship as `axiom` per D11 with a
  documented assumption entry in `formal/assumptions.toml` and
  the assumption file MUST be machine-checkable so a future
  re-attack closes the assumption without an axiom flip-flop

At close, archive `EXECUTION-STATE.json` to
`.planning/trajectory-2/archive/EXECUTION-STATE-CLOSED.json` and bump
`.planning/STATE.md` to record trajectory-2 completion.
