# Formal Verification: Current State

- Status: Survey snapshot (2026-07-09, commit `dbb4639e1`)
- Audience: maintainers, formal-methods contributors, auditors
- Companion docs: [GAP_ANALYSIS.md](GAP_ANALYSIS.md), [HYGIENE_PASS.md](HYGIENE_PASS.md), [ROADMAP.md](ROADMAP.md), plan specs under [plan/](plan/)

This document records what the Chio formal verification estate actually is
today: six evidence lanes, the governance layer that binds them to release
claims, and the adjacent fuzzing and mutation estates. It is descriptive, not
aspirational; known weaknesses are catalogued separately in
[GAP_ANALYSIS.md](GAP_ANALYSIS.md).

## Architecture in one picture

The system is hub-and-spoke. The hub is a single production Rust module whose
function bodies are simultaneously executed, extracted, contracted, and
model-checked:

```
                       crates/kernel/chio-kernel-core/src/formal_aeneas.rs
                       (15 pure, extraction-safe functions; production code)
                                          |
          +----------------+--------------+---------------+------------------+
          |                |              |               |                  |
   formal_core.rs    Charon->Aeneas   Creusot         Kani harnesses    Lean models
   (typed facade;    extraction to    contracts       (12 model +       (hand mirrors
   called by real    Lean under       (7 duplicated   20 public-API     with "Mirrors:"
   verify/subset     target/formal/   bodies in       in kernel-core)   headers)
   paths)            aeneas-production formal/rust-
                     + equivalence     verification/
                     check)            creusot-core)
```

Around the hub sit the system-level models (TLA+/Apalache), the executable
drift gates (`formal/diff-tests`), and the governance manifests that decide
what may be claimed publicly.

## Lane 1: Lean 4 (`formal/lean4/Chio`)

- Toolchain: `leanprover/lean4:v4.28.0-rc1` (a release candidate pin), lake,
  zero external packages (`lake-manifest.json` has `packages: []`; no mathlib).
- 21 root-imported modules (all imported by `Chio.lean`; "root-imported" is a
  release-evidence precondition), roughly 80 catalogued theorems, exactly one
  axiom, zero `sorry` (enforced by `scripts/check-formal-proofs.sh`: lake
  build plus a sorry scan plus manifest cross-ref sanity).
- Core models: `Core/Capability.lean`, `Core/Scope.lean`, `Core/Receipt.lean`
  (symbolic Merkle tree, `applyProof`, `membershipProof`),
  `Core/Revocation.lean` (six-step `evalToolCall` pipeline),
  `Core/Protocol.lean` (budget, DPoP, guard pipeline, evidence labels).
- Headline theorems by property id: P1 `capability_monotonicity` and
  `delegate_no_widen` (subset transitivity through a middle scope), P2
  `revocation_is_cut`, P3 `evalToolCall_total` plus six deny theorems and
  guard-pipeline domination, P4 `membership_proof_sound`,
  `receipt_sign_then_verify`, `receipt_immutability`, P5 delegation-step
  closure theorems, P8 DPoP binding, P10 report truthfulness. A treaty lane
  (`Treaty/Intersection.lean`, `Treaty/PredicateLang.lean`,
  `Treaty/BilateralAccept.lean`) supports the governance/paper surface.
- The single axiom: `receipt_id_collision_resistant`
  (`Chio/Proofs/Receipt.lean`, near L140). Whitelisted by name in
  `formal/proof-manifest.toml` `allowed_axioms`, justified in-file (the
  bounded model has no JCS canonicalizer or hash to prove injectivity
  against), and tied to `ASSUME-SHA256`.
- Model gaps are documented in-file rather than hidden: signature verification
  is trusted-issuer membership, receipt signatures are symbolic
  (`signature := body`), and `Treaty/PredicateLang.lean` names its own missing
  bridge-soundness theorem.

## Lane 2: Aeneas (`formal/aeneas/`)

Two lanes, one legacy and one live:

- Pilot (`pilot.toml`, status `active_pilot`): a standalone 56-line teaching
  file `formal/aeneas/verified_core.rs` with 6 extracted symbols. Predates the
  production lane.
- Production (`production.toml`, status `production_extraction`): the source
  is the real in-crate `crates/kernel/chio-kernel-core/src/formal_aeneas.rs`
  (15 symbols). `scripts/check-aeneas-production.sh` drives Charon to LLBC to
  Aeneas to Lean under `target/formal/aeneas-production/lean/`.
  `scripts/check-aeneas-equivalence.sh` asserts every expected `def <symbol>`
  exists in the generated `Funs.lean` (plus `BudgetCommitResult` in
  `Types.lean`) and hashes source and output into
  `equivalence-artifacts.json`.
- The Lean project does not import the generated code. Instead
  `Chio/Proofs/AeneasEquivalence.lean` hand-restates the extracted semantics
  in a namespace `AeneasMirror` and proves 14 equivalence theorems against the
  handwritten models. The chain from production Rust to proved Lean therefore
  has one mechanical hop (symbol check) and one manual-but-proved hop (the
  mirror restatement).
- Aeneas and Charon binaries are pinned (release tag plus sha256) in
  `.github/workflows/nightly.yml`.

The extraction discipline in `formal_aeneas.rs` is strict: no traits, no
generics, no borrows, no `Option`/`Result`, no strings or slices or `Vec`, no
heap; callers project strings and structs to booleans and bounded integers
before crossing the boundary. `formal_core.rs` (214 lines) is the typed,
`pub(crate)` facade that does those projections.

## Lane 3: Creusot (`formal/rust-verification/creusot-core`)

- A standalone mini-crate (its own `[workspace]`), `creusot-std` pinned by git
  rev, proved through Why3find with alt-ergo/z3/cvc5/cvc4.
- 7 contract functions carrying `#[requires]`/`#[ensures]` specs. The bodies
  are hand-duplicated copies of `formal_aeneas.rs` bodies (a known drift
  surface; the registry `creusot-contracts.toml` currently lists only 6 of
  the 7, see [HYGIENE_PASS.md](HYGIENE_PASS.md)).
- Gate scripts: `check-creusot-smoke.sh`, `check-creusot-core.sh`, bundled
  into `check-rust-verification-gates.sh`.

## Lane 4: Kani

- Registry-driven. `.kani/harnesses.toml` (schema `chio.kani.multi-crate.v1`)
  covers four crates: chio-kernel-core (20 public harnesses), chio-anchor (5,
  behind a `kani = ["web3"]` feature), chio-attest-verify (4), chio-weights
  (4). kernel-core additionally has 12 internal model-level harnesses in
  `kani_harnesses.rs`. Kani is version-pinned (`CHIO_KANI_VERSION=0.67.0`).
- The public kernel-core lane (`kani_public_harnesses.rs`, ~1280 lines) calls
  the real public API (`verify_capability`, `evaluate`,
  `NormalizedScope::is_subset_of`, `resolve_matching_grants`, `sign_receipt`)
  with deterministic key fixtures and a signing-backend stub. Highlights:
  - `verify_delegation_chain_step`: a 22-axis symbolic one-step attenuation
    predicate proved reflexive, non-widening, and expiry-monotone, then bound
    to the real `NormalizedToolGrant::is_subset_of` with `assert_eq`, so a
    runtime regression trips the proof.
  - `verify_budget_checked_add_no_overflow`: a two-phase model of the kernel
    budget store's checked-add ordering (dense small bounds, then
    `current = u64::MAX - tail` so the overflow arm is non-vacuous), proving
    fail-closed no-partial-commit and retry idempotence.
  - `verify_receipt_roundtrip`: an explicit EUF-CMA-style algebraic signature
    model with documented rationale for why real ed25519/RFC 8785 is
    intractable under CBMC.
  - Where a harness is model-only (for example the anchor witness-policy
    harness), the module docs state the honesty boundary and name the runtime
    tests covering the gap.
- Cadence: all Kani lanes execute nightly only (`kani-public-nightly` in
  `nightly.yml`). The `lanes.pr` name inside
  `formal/rust-verification/kani-public-harnesses.toml` is aspirational; see
  [GAP_ANALYSIS.md](GAP_ANALYSIS.md) G1.

## Lane 5: TLA+ and Apalache (`formal/tla`, `formal/apalache`)

- Checker: Apalache 0.50.1 (pinned via `tools/install-apalache.sh`).
- TLC-shaped models in `formal/tla/`:
  - `RevocationPropagation.tla` (378 lines): multi-authority revocation with
    four safety invariants (`NoAllowAfterRevoke`, `MonotoneLog`,
    `AttenuationPreserving`, `RevocationFreshness`) and one liveness property
    (`RevocationEventuallySeen`, checked nightly via `--temporal=`, with a
    documented Apalache PDR-017 workaround lifting an existential into the
    named action `PropagateAny`).
  - `DelegationDepthBound.tla` (234 lines): depth-bounded delegation and
    revocation-as-cut observation (`DepthBoundedByRoot`,
    `AttenuatedAtEachStep`, `RevokedSubtreeNotObservable`).
- Bounded kernel-state subset in `formal/apalache/` (Authorities 1..3, CapSet
  1..6, EpochMax 4, length 6, 30-minute per-invariant CI timeout):
  `MonotoneLogApalache`, `ReceiptBeforeAllow` (the formal discharge evidence
  for the retired SQLite cross-row assumption; deliberately split into
  persist and publish actions so the invariant is not tautological),
  `RevocationCutCompleteness` (bounded transitive closure maintained
  incrementally as state, keeping SMT depth at 1),
  `KernelTransitionCancelSafe` (snapshot rollback; header candidly admits the
  invariant holds by construction and defers commit-vs-cancel races).
- Negative-test discipline: `formal/apalache/_negative_tests/` holds
  deliberately-broken spec variants that must produce counterexamples, run
  locally only, with a written rationale for staying out of CI (a green CI
  run would require a counterexample, inverting the signal).
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
- `tests/canonical_json_diff.rs`: RFC 8785 dual-implementation byte gate with
  12 named invariants. The committed proptest-regression seeds are receipts
  of real historical catches (U+007F control escaping beyond the RFC letter;
  UTF-16 surrogate key ordering).
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

- Fuzzing: 25 libFuzzer targets in `fuzz/` (standalone workspace) spanning
  canonical JSON, envelopes (MCP/A2A/ACP), attestation, DIDs, federation
  trust, receipts and Merkle checkpoints, policy parse/compile, SQL and tool
  action guards, and wasm boundaries (`wasm_guard_escape` with 8 escape-class
  seeds). A structure-aware canonical-JSON mutator is wired into 6 targets.
  Three CI lanes (ClusterFuzzLite change-scoped on PRs; nightly single-target
  rotation; nightly native sweep) plus automated crash triage (tmin, sha
  dedupe, auto-filed issues with SLOs) and weekly corpus sync. OSS-Fuzz
  integration files are complete; acceptance is pending.
- Mutation testing: cargo-mutants across 6 crates nightly (advisory;
  `releases.toml` ratchet at 0 observed consecutive green nights; measured
  trust-boundary kill rate 30.7% against an 80% activation target), plus a
  novel nightly co-coverage lane replaying the fuzz corpus against surviving
  mutants (`mutants-fuzz-cocoverage.yml`). The formal modules themselves are
  excluded from mutation with the rationale "covered by the proof lane".
- Concurrency: chio-kernel has a loom dev-dependency and a drop-guard race
  model test; there is no loom registry or dedicated CI lane.
- Timing: nightly dudect harnesses with a two-consecutive-nightly threshold
  rule before auto-filing a `timing-leak` issue (wholly advisory).

## Governance layer

- `formal/proof-manifest.toml` (schema `chio.proof-manifest.v1`) is the hub:
  `root_modules` (21 Lean files), `gate_commands` (10 scripts), 7
  `covered_rust_modules`, 22 `covered_rust_symbols`, 2 `shell_entrypoints`,
  the P1-P10 `property_matrix` with per-property evidence-lane tags,
  `rust_refinement_lanes`, `allowed_axioms` (exactly one),
  `excluded_surfaces`, and `discharged_assumptions`. Sync is by symbol name
  plus gate scripts; there are no content hashes.
- `formal/theorem-inventory.json` (83 theorem entries plus a separate
  assumptions block): per-theorem id, Lean name,
  file, kind, `rootImported` flag, claim class, `mapsTo` property ids.
- `formal/MAPPING.md`: the cross-reference table from TLA invariants, Kani
  harnesses, and Lean delegation theorems to Rust call sites.
  `scripts/check-mapping.sh` greps the TLA invariant names and every
  `#[kani::proof]` fn and fails CI unless each has a literal row.
- `formal/assumptions.toml`: 10 required audited assumptions plus a worked
  retirement example (`RETIRED-SQLITE-CROSS-ROW`, discharged by the
  `ReceiptBeforeAllow` invariant, mirrored in the proof manifest with the
  constrained Rust call sites named).
- `docs/reference/CLAIM_REGISTRY.md`: evidence classes and approved claims
  (`FORM-BOUNDARY`, `FORM-IMPLEMENTATION-LINKED`, P1-P10 approved with
  scope), and explicitly disallowed claims (`FORM-OVERALL`,
  `LEAN-4-VERIFIED`, `P2-END-TO-END`, `P3-END-TO-END`, `P4-END-TO-END`,
  `P5-ACYCLICITY`).
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
| Every PR (required) | diff-tests via workspace tests; `cargo xtask check crate-paths` (manifest path integrity); proptest invariant-naming gate; regression-test deletion gate; threat-model coverage gate; registry status ban (`implementation_backed`) |
| PR, path-scoped | Apalache safety (6 spec/cfg pairs) on `formal/apalache/**`, `formal/tla/**`; ClusterFuzzLite change-scoped fuzzing on `crates/**`, `fuzz/**` |
| Nightly | Kani (all lanes), Lean/Aeneas/Creusot proof report (`formal-qualification`), Apalache temporal (liveness; known-unreliable), proptest 4096-case tier, mutants full sweeps (advisory), mutants-fuzz co-coverage, dudect, fuzz rotation and native sweep |
| Push to main / release | `release-qualification.yml` runs the full gate battery: `check-formal-proofs.sh`, both Aeneas checks, equivalence, Creusot and Kani strict lanes, adapter no-bypass, portable kernel, proof report |

## Strengths worth preserving

1. Single-source hub: the extraction source is production code, not a copy.
2. Honest scoping everywhere: by-construction admissions in spec headers,
   model-only harnesses that name the runtime tests covering their gap,
   in-file model-gap documentation, disallowed-claim lists.
3. Negative-test discipline and the falsifiability mindset.
4. The assumption lifecycle with a worked retirement example.
5. Registry-driven harness execution (adding a harness is data, not YAML).
6. Executable drift gates with committed evidence of real catches.
7. A single whitelisted axiom with a written mechanization path.
