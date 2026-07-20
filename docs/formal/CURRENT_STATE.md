# Formal Verification: Current State

- Status: Execution snapshot updated 2026-07-16
- Audience: maintainers, formal-methods contributors, auditors
- Companion docs: [GAP_ANALYSIS.md](GAP_ANALYSIS.md), [HYGIENE_PASS.md](HYGIENE_PASS.md), [ROADMAP.md](ROADMAP.md), plan specs under [plan/](plan/)

This document records the executed formal verification estate: six evidence
lanes, governance that binds them to release claims, and the adjacent
concurrency, fuzzing, and mutation programs. It is descriptive, not
aspirational; remaining boundaries are catalogued separately in
[GAP_ANALYSIS.md](GAP_ANALYSIS.md).

## 2026-07-16 evidence snapshot

- Production extraction covers 20 functions across four semantic targets and
  two Rust sources. Eighteen functions are in the kernel-only extraction
  scope; the two inclusion functions bind the relying-party verifier path.
- Kani registers 14 internal model harnesses, 25 core public harnesses, and 16
  non-core public harnesses. All 41 public harnesses are in the pull-request
  tier.
- Apalache passed nine positive safety models, sixteen registered negative
  models, receipt-trace validation, the distributed refinement model, and the
  three bounded temporal obligations. The measured temporal runs were
  811.737 seconds at length 5, 1.991 seconds at length 3, and 429.525 seconds
  at length 24. The legacy unbounded eventuality run reached its 3,602-second
  timeout without an invariant or tool error and is not counted as a proof.
- Mirror validation covers 57 registered mirrors over 171 bindings, including
  seven Lean module hashes and seven TLA+ module hashes. The proof manifest
  contains 35 root imports, 14 gates, 12 model modules, 43 Rust symbols, and 15
  shell-bound checks.
- Lean contains 149 catalogued declarations, one cryptographic axiom, thirteen
  registered assumptions, and no placeholders.
- Concurrency evidence includes all ten Loom models under three preemptions
  (229.86 seconds) and 10,000 deterministic schedules (63.24 seconds).
- The specification campaign enumerated 33 mutants, killed 32, timed out one,
  and left no survivor or unviable result, for 96.97 percent activation. The
  retained Lean campaign enumerated 45 mutants, killed 33, and left 12
  survivors with no timeout, for 73.333 percent activation. The retained Rust
  proof campaign enumerated 166 mutants, killed 160, left one survivor,
  classified five as unviable, and had no timeout, for 99.379 percent
  activation and 96.988 percent viability. Issues #999 through #1010 track
  the Lean survivors, and issue #1019 tracks the Rust survivor.
- Fifteen formal gates are registered: ten scheduled and five pull-request
  gates. Six path-scoped gates remain frozen pending qualifying hosted runs.
- All roadmap items are implemented except collection-level economy
  conservation, which remains blocked on the absent netting surface. No P11
  claim is made.

## Architecture in one picture

The system is hub-and-spoke. The hub is a single production Rust module whose
function bodies are simultaneously executed, extracted, contracted, and
model-checked:

```
                       crates/kernel/chio-kernel-core/src/formal_aeneas.rs
                       (20 registered extraction-safe functions; production code)
                                          |
          +----------------+--------------+---------------+------------------+
          |                |              |               |                  |
   formal_core.rs    Charon->Aeneas   Creusot         Kani harnesses    Lean models
   (typed facade;    extraction to    contracts       (12 model +       (hand mirrors
   called by real    Lean under       (9 contracts)   24 public-API     with "Mirrors:"
   verify/subset     target/formal/   bodies in       in kernel-core)   headers)
   paths)            aeneas-production formal/rust-
                     + equivalence     verification/
                     check)            creusot-core)
```

Around the hub sit the system-level models (TLA+/Apalache), the executable
drift gates (`formal/diff-tests`), and the governance manifests that decide
what may be claimed publicly.

## Lane 1: Lean 4 (`formal/lean4/Chio`)

- Toolchain: `leanprover/lean4:v4.28.0`, lake, the vendored Aeneas support
  library, and an exact Mathlib dependency closure recorded in
  `lake-manifest.json`.
- 35 root-imported modules (all imported by `Chio.lean`; "root-imported" is a
  release-evidence precondition), 149 catalogued theorems, exactly one
  axiom, zero `sorry` (enforced by `scripts/check-formal-proofs.sh`: lake
  build plus a sorry scan plus manifest cross-ref sanity).
- Core models: `Core/Capability.lean`, `Core/Scope.lean`, `Core/Receipt.lean`
  (symbolic Merkle tree, `applyProof`, `membershipProof`),
  `Core/Revocation.lean` (six-step `evalToolCall` pipeline),
  `Core/Protocol.lean` (budget, DPoP, guard pipeline, evidence labels), and
  `Core/MerkleWalk.lean` (checked index-directed inclusion traversal).
- Headline theorems by property id: P1 `capability_monotonicity` and
  `delegate_no_widen` (subset transitivity through a middle scope), P2
  `revocation_is_cut`, P3 `evalToolCall_total` plus six deny theorems and
  guard-pipeline domination, P4 `membership_proof_sound`,
  `stepFold_eq_applyProof`, `boundedWalkGeometry_decodes`,
  `bounded_stepFold_sound`,
  `receipt_sign_then_verify`, `receipt_immutability`, P5 delegation-step
  closure theorems, P8 DPoP binding, P10 report truthfulness. A treaty lane
  (`Treaty/Intersection.lean`, `Treaty/PredicateLang.lean`,
  `Treaty/IntersectionSyntactic.lean`, `Treaty/IntersectionLegacy.lean`,
  `Treaty/BridgeEquivalence.lean`, `Treaty/BilateralAccept.lean`) supports the
  governance/paper surface.
- `Guards/WasmBoundary.lean` models the core-module dispatch boundary and proves
  typed-output confinement, no allow amplification, blocking resource-failure
  closure, and advisory-mode nonblocking behavior. It relies on the scoped
  `ASSUME-WASM-ENGINE` trust dependency and does not claim to verify wasmtime's
  interpreter, compiler, JIT, sandbox, or full information flow.
- The single axiom is the registered cryptographic idealization
  `Chio.Json.hash_collision_resistant`. The mechanized canonical renderer is
  injective on its modeled domain, and the receipt-id collision property is a
  theorem derived from that proof and the symbolic hash assumption. The axiom
  is allowlisted by exact name in `formal/proof-manifest.toml` and tied to
  `ASSUME-SHA256`.
- Model gaps are documented in-file rather than hidden: signature verification
  is trusted-issuer membership and receipt signatures are symbolic
  (`signature := body`). The treaty predicate model is a bounded projection of
  validated runtime records; parsing, canonical hashing, signature checks,
  store lookups, and completeness beyond the explicit admission domain are not
  proved by its bridge.
- `Proofs/ReservationLedger.lean` proves pure reservation-fold conservation,
  terminal absorption, and the sibling-share bound. It is model-level evidence;
  concrete store linkage remains runtime-tested.

## Lane 2: Aeneas (`formal/aeneas/`)

Two lanes, one diagnostic fixture and one production lane:

- Toolchain-upgrade fixture (`pilot.toml`, status
  `toolchain_upgrade_fixture`): a standalone 56-line extraction input with 6
  symbols, retained to diagnose Aeneas and Charon upgrades independently of
  the production module.
- Production (`production.toml`, status `generated_equivalence`) has two
  manifest-registered in-crate sources. The kernel source
  `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` contributes 18
  functions and three targets: 15 decision helpers, two reservation-ledger
  helpers, and `inclusion_step`. The economy source
  `crates/economy/chio-credit/src/formal_economy.rs` contributes two scalar
  conversion functions and one target.
  `scripts/check-aeneas-production.sh` drives authenticated Charon to LLBC to
  Aeneas to Lean under `target/formal/aeneas-production/lean/`, then checks the
  result byte-for-byte against the committed `FormalAeneas` and
  `FormalEconomy` snapshots.
  `scripts/check-aeneas-equivalence.sh` validates exact source, type, function,
  and theorem inventories and hashes the authenticated tools, source,
  generated output, snapshots, proof module, and compiled equivalence `.olean`
  into `equivalence-artifacts.json`.
- The main Lean project imports the committed generated snapshots directly.
  `Chio/Proofs/AeneasEquivalence.lean` remains the model layer for the 15
  decision helpers, while `Chio/Proofs/AeneasGeneratedEquivalence.lean` proves
  every registered generated function against its target. The economy
  theorems `generated_convert_ceil_scalar_eq_model` and
  `generated_convert_floor_scalar_eq_model` establish the registered scalar
  rounding models. The Merkle theorem
  `generated_inclusion_step_eq_model` projects the generated machine-integer
  result directly to `Chio.Core.inclusionStep`. There is no handwritten
  external implementation or semantic escape hatch in that path.
- Aeneas and Charon binaries are pinned (release tag plus sha256) in
  `.github/workflows/nightly.yml`.

The registered extraction sources use bounded, safe Rust surfaces without
traits, generics, borrows, strings, slices, vectors, or heap allocation at the
proof boundary. Checked scalar arithmetic uses `Option` results that Charon
lowers explicitly. Kernel callers project strings and structs to booleans and
bounded integers before crossing the boundary. `formal_core.rs` (341 lines) is
the typed, `pub(crate)` facade that performs those kernel projections.

## Lane 3: Creusot (`formal/rust-verification/creusot-core`)

- A standalone mini-crate (its own `[workspace]`), `creusot-std` pinned by git
  rev, proved through Why3find with alt-ergo/z3/cvc5/cvc4.
- 9 contract functions carrying `#[requires]`/`#[ensures]` specs. Their bodies
  delegate to an unconditional include of the production `formal_aeneas.rs`;
  the body-sync gate pins the include shape, wrapper bodies, and all 9
  `contract_twin` rows.
- Gate scripts: `check-creusot-smoke.sh`, `check-creusot-core.sh`, bundled
  into `check-rust-verification-gates.sh`.

## Lane 4: Kani

- Registry-driven. `.kani/harnesses.toml` (schema `chio.kani.multi-crate.v1`)
  covers six crates: chio-kernel-core (24 public harnesses), chio-anchor (5,
  behind a `kani = ["web3"]` feature), chio-attest-verify (4), chio-credit
  (2), chio-web3 (1), and chio-weights (4). kernel-core additionally has 12
  internal model-level harnesses in `kani_harnesses.rs`. Kani is version-pinned
  (`CHIO_KANI_VERSION=0.67.0`).
- The public kernel-core lane (`kani_public_harnesses.rs`, ~1600 lines) calls
  the real public API and shared public projections (`verify_capability`,
  `evaluate`, `NormalizedScope::is_subset_of`, `resolve_matching_grants`,
  `sign_receipt`, the budget admission projections, and the lazy revocation
  projection) with deterministic key fixtures and a signing-backend stub.
  Highlights:
  - `verify_delegation_chain_step`: a 22-axis symbolic one-step attenuation
    predicate proved reflexive, non-widening, and expiry-monotone, then bound
    to the real `NormalizedToolGrant::is_subset_of` with `assert_eq`, so a
    runtime regression trips the proof.
  - `verify_budget_checked_add_no_overflow`: a two-phase standalone model of
    the kernel budget store's checked-add ordering (dense small bounds, then
    `current = u64::MAX - tail` so the overflow arm is non-vacuous), proving
    fail-closed no-partial-commit and retry idempotence for that model. It does
    not execute either concrete store.
  - `verify_budget_admission_projection`: verifies the exact shared scalar
    projections called by both InMemory and SQLite budget backends, including
    optional caps and total-cost overflow. Store mutation and reservation
    conservation are outside this harness.
  - `verify_reservation_ledger_conservation`: proves six-step pure reservation
    sequences preserve the amount partition, invalid operations are exact
    no-ops, arithmetic boundaries fail closed, and finalized ledgers are
    absorbing. Production store transitions are bound by debug replay and a
    stateful real-store test rather than a refinement proof.
  - `verify_revocation_admission_projection`: verifies the exact shared lazy
    token/ancestor projection called by both production revocation paths.
    Store IO and view freshness are outside this harness.
  - `verify_receipt_roundtrip`: an explicit EUF-CMA-style algebraic signature
    model with documented rationale for why real ed25519/RFC 8785 is
    intractable under CBMC.
  - `verify_inclusion_step_equivalence` and
    `verify_oracle_inclusion_walk_parity`: bind the production scalar step to its
    extraction mirror and compare the real bounded audit-path walk with an
    independent fold while node hashing remains abstract under ASSUME-SHA256.
  - Where a harness is model-only (for example the anchor witness-policy
    harness), the module docs state the honesty boundary and name the runtime
    tests covering the gap.
- Cadence: `formal-pr-smoke.yml` runs the 25 public kernel-core `lanes.pr`
  harnesses and the 16 non-core manifest PR harnesses on scoped pull-request
  changes. `kani-public-nightly` in `nightly.yml` runs the union of core PR and
  nightly-only lanes plus every non-core PR and nightly manifest entry.

## Lane 5: TLA+ and Apalache (`formal/tla`, `formal/apalache`)

- Checker: Apalache 0.50.1 (pinned via `tools/install-apalache.sh`).
- TLC-shaped models in `formal/tla/`:
  - `RevocationPropagation.tla` (378 lines): multi-authority revocation with
    four safety invariants (`NoAllowAfterRevoke`, `MonotoneLog`,
    `AttenuationPreserving`, `RevocationFreshness`) and one liveness property
    (`RevocationEventuallySeen`, checked nightly via `--temporal=`, with a
    documented Apalache PDR-017 workaround lifting an existential into the
    named action `PropagateAny`).
  - `DistributedRevocation.tla`: bounded signer-pinned root gossip with lossy,
    duplicating, reordering counting channels, independent skew-bounded clocks,
    repeated partition safety, target-specific revocation, and conditional
    post-heal liveness. PR behavioral bounds use two authorities and three
    epochs; scheduled behavioral safety expands to three authorities and four
    epochs. Exact function domains and relational shape are checked in the
    concrete initial state. `DistributedRevocationTemporal.tla` separately
    checks conditional eventual observation for one arbitrary ordered pair
    with a primitive-temporal expansion of weak fairness. A bounded refinement
    check maps one selected pair from the full temporal relation into that
    scalar spec, and an executable witness reaches a fair observation state.
    Neither check establishes unbounded refinement across all pairs. The
    executable gate checks exact one-origin scalar production projections and
    does not claim full-state or multi-origin Rust refinement.
  - `DelegationDepthBound.tla` (234 lines): depth-bounded delegation and
    revocation-as-cut observation (`DepthBoundedByRoot`,
    `AttenuatedAtEachStep`, `RevokedSubtreeNotObservable`).
- Bounded kernel-state subset in `formal/apalache/` (Authorities 1..3, CapSet
  1..6, EpochMax 4, length 6, with enforced per-configuration CI timeouts):
  `MonotoneLogApalache`, `ReceiptBeforeAllow` (modeled ordering evidence,
  deliberately split into persist and publish actions so the invariant is not
  tautological; concrete cross-row crash recovery remains excluded),
  `RevocationCutCompleteness` (bounded transitive closure maintained
  incrementally as state, keeping SMT depth at 1),
  `KernelTransitionCancelSafe` (clean pre-dispatch snapshot equality; header
  candidly states that the invariant holds by construction, does not model the
  Rust reversal transition, and excludes post-dispatch, fault, and
  commit-vs-cancel paths), and `PostAdmissionDropGuard`, whose
  `ReservationConservation` invariant checks a counted partition and shared
  child capacity at every bounded state.
- Negative-test discipline: `formal/apalache/_negative_tests/REGISTRY.toml`
  registers deliberately broken variants and rejected-claim witnesses. The
  separate `apalache-negative` job requires the pinned checker to reproduce
  each exact invariant violation and a structurally valid ITF trace.
- `CONTRACTOR-SIGNOFF.md` is explicitly an internal self-authored record, not
  an external review; hosted-run evidence is tracked as CI debt.

## Lane 6: Differential tests (`formal/diff-tests`, crate `chio-formal-diff-tests`)

The only lane that runs in full on every PR (as part of
`cargo test --workspace` in the required check job, 256 proptest cases; 4096
nightly).

- `tests/scope_diff.rs`: three-way differential of scope attenuation
  semantics: an independent reference reimplementation (`src/spec.rs`) vs the
  production `chio-core` structs vs the normalized proof-facing AST, on
  paired generators built from the same seeds, plus proptest properties
  (reflexivity, transitivity, remove-grant, reduce-budget, wildcard,
  different-server).
- `tests/canonical_json_diff.rs`: canonical JSON dual-implementation byte gate
  with 12 named invariants. The U+007F regression pins Chio's historical
  control escape across production, cross-binding, and Lean fixtures;
  supplementary-plane cases pin UTF-16 surrogate key ordering.
- `tests/receipt_encoding_diff.rs`: cross-language receipt canonical bytes
  through a triple-blessed frozen corpus
  (`tests/bindings/vectors/receipt/v1.json`) that the Rust, Python, and
  TypeScript suites all assert against, with optional live-subprocess
  differential tests.
- `tests/anchored_root.rs` and `anchored_root_tamper.rs`: Rust vs TypeScript
  anchored-root tuples over 50 replay fixtures with a hardcoded canary leaf
  hash, plus single-byte-flip tamper rejection on both sides.
- `tests/browser_canonical_json_diff.rs`: the same canonical vector corpus
  re-run under wasm-bindgen-test in headless Chrome (or Node fallback).

## Adjacent estates

- Fuzzing: 27 libFuzzer targets in `fuzz/` (standalone workspace) spanning
  canonical JSON, envelopes (MCP/A2A/ACP-Client), attestation, DIDs, federation
  trust, receipts and Merkle checkpoints, policy parse/compile, SQL and tool
  action guards, and wasm boundaries (`wasm_guard_escape` with 8 escape-class
  seeds plus the structure-aware `wasm_guard_smith` target). A structure-aware
  canonical-JSON mutator is wired into 6 targets.
  Three CI lanes (ClusterFuzzLite change-scoped on PRs; nightly single-target
  rotation; nightly native sweep) plus automated crash triage (tmin, sha
  dedupe, auto-filed issues with SLOs) and weekly corpus sync. OSS-Fuzz
  integration files are complete; acceptance is pending.
- Mutation testing: cargo-mutants runs path-scoped PR sweeps and full nightly
  sweeps across 6 crates. The PR matrix stops untouched packages before tool
  installation and remains advisory through the `releases.toml` ratchet, which
  is at 0 observed consecutive green nights against an 80% activation target.
  A nightly co-coverage lane replays the fuzz corpus against surviving mutants
  (`mutants-fuzz-cocoverage.yml`). The formal modules themselves are excluded
  from unit-test mutation because the measured proof-mutation lane scores the
  two production models with Kani, while the Kani harness files are oracle
  controls and remain outside the mutated system boundary.
- Concurrency: the checked registry names 10 Loom harnesses, and deterministic
  simulation registers five drop-injection scenarios with replayable seeds.
  Pull-request and nightly lanes enforce the registered scope; the hosted
  nightly activation streak remains advisory until its release ratchet matures.
- Timing: nightly dudect harnesses with a two-consecutive-nightly threshold
  rule before auto-filing a `timing-leak` issue (wholly advisory).

## Governance layer

Per-surface evidence attribution is generated in
[`COVERAGE.md`](COVERAGE.md). The matrix joins registry artifacts without
turning artifact presence into a completeness claim; unresolved theorem and
differential-test joins, theorem status, and model-only Kani scope remain
explicit there.

- `formal/proof-manifest.toml` (schema `chio.proof-manifest.v1`) is the hub:
  `root_modules` (35 Lean files), `gate_commands` (15 commands), 12
  `covered_rust_modules`, 41 `covered_rust_symbols`, 14 `shell_entrypoints`,
  the P1-P10 `property_matrix` with per-property evidence-lane tags,
  `rust_refinement_lanes`, `allowed_axioms` (exactly one),
  `excluded_surfaces`, and `discharged_assumptions`. Forty-six `[[mirror]]`
  entries bind 118 parser-resolved Rust symbol references to seven Lean models
  and seven TLA+ models with ordered rollup and per-symbol hashes. Lean entries
  are labeled as transliterations or abstraction anchors; TLA+ entries are
  abstraction anchors. `cargo xtask check formal-mirrors` enforces those hashes
  in required PR CI.
- `formal/theorem-inventory.json` (149 theorem entries plus a separate
  assumptions block): per-theorem id, Lean name,
  file, kind, `rootImported` flag, claim class, `mapsTo` property ids.
- `formal/MAPPING.md`: the cross-reference table from required model safety
  leaves, TLA and drop-guard invariants, Kani, Loom, and DST harnesses, and Lean
  delegation theorems to Rust call sites. `scripts/check-mapping.sh` discovers
  each enforced registry and source entry and fails CI unless every one has a
  literal row.
- `formal/assumptions.toml`: 13 required audited assumptions. SQLite
  atomicity is scoped to single-row commits; cross-row recovery remains outside
  the formal claim boundary until implementation trace validation and
  crash-reopen conservation establish refinement.
- `docs/reference/CLAIM_REGISTRY.md`: evidence classes and approved claims
  (`FORM-BOUNDARY`, `FORM-IMPLEMENTATION-LINKED`, `TRACE-VALIDATED`,
  `FORM-NO-SOFTWARE-AXIOMS`, and P1-P10 approved with scope), and explicitly
  disallowed claims (`FORM-OVERALL`,
  `LEAN-4-VERIFIED`, `P2-END-TO-END`, `P3-END-TO-END`, `P4-END-TO-END`,
  `P5-ACYCLICITY`, `P2-DISTRIBUTED-END-TO-END`).
- `docs/release/RISK_REGISTER.md` claim rules, including: do not say the
  Creusot/Kani production refinement is complete unless the strict lane has
  actually passed in CI.
- Issue templates (`formal/issue-templates/`): counterexample triage with
  spec-bug/implementation-bug/harness-bug classification, and a liveness
  template with severity tiers mapped to release-gate posture. Counterexample
  silencing by invariant widening requires written justification
  (`formal/OWNERS.md`).
- `scripts/generate-proof-report.sh` and `check-proof-report.sh` record gate
  results, tool versions, and artifact hashes into
  `target/formal/proof-report.json` (nightly and release qualification).

## CI cadence summary

| Cadence | Formal content |
| --- | --- |
| Every PR (required) | diff-tests via workspace tests; `cargo xtask check crate-paths` (manifest path integrity); `cargo xtask check formal-mirrors` (Rust-to-model review tripwire); proptest invariant-naming gate; regression-test deletion gate; threat-model coverage gate; registry status ban (`implementation_backed`) |
| PR, path-scoped | Apalache safety (9 spec/cfg pairs) plus registered negative witnesses and the distributed production projection; Lean build plus sorry and manifest checks; 25 core and 16 non-core Kani PR harnesses; Rust verification metadata with no Creusot proofs; ClusterFuzzLite change-scoped fuzzing; cargo-mutants for touched trust-boundary crates |
| Nightly | Kani (all lanes), Lean/Aeneas/Creusot proof report (`formal-qualification`), Apalache temporal (liveness; known-unreliable), proptest 4096-case tier plus a 10000-case reservation-ledger sequence target, mutants full sweeps (advisory), mutants-fuzz co-coverage, dudect, fuzz rotation and native sweep |
| Push to main / release | `release-qualification.yml` runs the full gate battery: `check-formal-proofs.sh`, both Aeneas checks, equivalence, Creusot and Kani strict lanes, adapter no-bypass, portable kernel, proof report |

## Strengths worth preserving

1. Registered production sources: extraction inputs are production code, not
   copies.
2. Honest scoping everywhere: by-construction admissions in spec headers,
   model-only harnesses that name the runtime tests covering their gap,
   in-file model-gap documentation, disallowed-claim lists.
3. Negative-test discipline and the falsifiability mindset.
4. An assumption lifecycle that requires concrete refinement evidence before
   retirement.
5. Registry-driven harness execution (adding a harness is data, not YAML).
6. Executable drift gates with committed evidence of real catches.
7. A single registered cryptographic idealization with an explicit claim
   boundary.
