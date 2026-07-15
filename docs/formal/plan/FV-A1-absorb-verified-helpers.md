# FV-A1: Absorb verified helpers into production call paths

- Status: Implemented (2026-07-10)
- Theme: A - Make the proven code the running code
- Effort: M (rolling; one helper family per PR)
- Depends on: none (the pattern is already proven in-tree)
- Feeds: [FV-C2](./FV-C2-verified-inclusion-verifier.md), [FV-B3](./FV-B3-budget-conservation-law.md), [FV-D3](./FV-D3-economy-conservation.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G2, G4), [FV-A2](./FV-A2-aeneas-generated-equivalence.md), [FV-A4](./FV-A4-mirror-drift-hashes.md), [FV-E1](./FV-E1-spec-mutation-testing.md)

## Summary

At proposal time, `chio-kernel-core` shipped a proven pure decision core
(`formal_aeneas.rs` behind the `formal_core` facade), but eight helpers had no
production caller while `chio-kernel` implemented the same decisions by hand.
The implementation now projects runtime state into those helpers for budget,
DPoP, nonce replay, guard composition, revocation, and receipt coupling. The
retained properties and public Kani harnesses bind the projections to the
runtime decision shapes.

## Decisions

- The absorption is limited to admission predicates. Budget hold capture,
  release, settlement, and reconciliation remain owned by their runtime
  ledgers.
- All eight helpers plus `BudgetCommitResult` and `GuardStep` are curated
  re-exports from `chio-kernel-core`. The internal facade remains private.
- Both budget backends call the shared `budget_increment_admits` and
  `budget_charge_admits` production projections. Those functions delegate the
  bounded scalar axes to the decrement-form helpers. The SQLite
  invocation-only path in `budget_store/store.rs` is included alongside its
  charge path, and `chio-store-sqlite` now depends directly on
  `chio-kernel-core`.
- The portable sibling-budget split is a distinct allocation law and is not a
  twin of the scalar admission predicate.
- The DPoP verifier is atomic at the requirement-fold boundary, so successful
  verification projects to both proof validity and nonce freshness there.
  Replay admission is independently delegated inside `DpopNonceStore`. Direct
  verification uses `check_and_insert_through`; kernel dispatch uses the
  owner-qualified `reserve_for_dispatch_through` path so a proven
  pre-dispatch failure can roll the reservation back.
- Both guard loops use the type-owned `GuardStep::from` conversion, project
  every result through `guard_step_admits`, require that approval for
  continuation, and independently compare the observed step before allowing.
  Deny, pending, error, and impossible projection/verdict mismatches remain
  fail-closed with the original runtime attribution.
- Both revocation callers use `revocation_lookup_denies`, which preserves lazy
  presented-token and ancestor lookups while delegating each observed branch
  to `revocation_snapshot_denies`.
- Receipt evidence class means a mediated decision at a preventive,
  caller-executed boundary with no observation or redaction downgrade and the
  requested trust level. Capability, request/action, verdict, and policy hash
  are checked separately before signing.
- The budget and revocation projection harnesses are public PR harnesses and
  are registered in both Kani catalogs. They prove the exact shared projection
  functions invoked by both production backends or callers, not storage IO or
  ledger transitions. No new theorem or external assumption was introduced;
  existing theorem notes now identify the production linkage and its limits.
- The implementation-linked claim wording was narrowed to the absorbed
  admission predicates and retains the audited boundary around storage,
  clocks, cryptography, and orchestration.
- The retained equivalence properties passed against parent
  `dc4d3bf2d62dcca2b0a266904bdc5bc1f2ee12a9` before runtime refactoring. The
  test-only patch had SHA-256
  `f5b43876db6d16071c16cb26515cf76e2d05b1ec4df175df4f71f087d5b4126a` and
  ran with `cargo test -p chio-kernel --test budget_decision_equivalence
  --test dpop_admission_equivalence --test revocation_decision_equivalence`.
  The guard and receipt supplement had SHA-256
  `584652520510de873c9cb202550db20f07ab8464c706c106aa7bbae2385b40fd`
  and ran against the same parent with `cargo test -p chio-kernel --test
  guard_decision_equivalence --test receipt_decision_equivalence`.

## Motivation and evidence

- At proposal time, Gap G2 ([../GAP_ANALYSIS.md](../GAP_ANALYSIS.md)) was that verified helpers existed but production did not call them. The following `formal_core` functions then had zero production callers [v]: `budget_precheck`, `budget_commit`, `dpop_freshness_valid`, `dpop_admits`, `nonce_admits`, `guard_pipeline_allows`, `revocation_snapshot_denies`, `receipt_fields_coupled`.
- At proposal time the manifest already overstated linkage. `formal/proof-manifest.toml` listed `formal_core::budget_commit`, `formal_core::dpop_admits`, `formal_core::guard_pipeline_allows`, and `formal_core::receipt_fields_coupled` under `covered_rust_symbols` even though nothing in production executed them. `formal/MAPPING.md` likewise cited `formal_core::revocation_snapshot_denies` as the discharge for the Apalache `RevocationCutCompleteness` row constraining `ChioKernel::check_revocation`. The implemented shared projections now make the bounded decision linkage concrete while keeping surrounding IO and orchestration out of scope.
- The pattern works and costs little. `crates/kernel/chio-kernel-core/src/capability_verify.rs:39` imports `classify_time_window` and uses it in real token verification; `crates/kernel/chio-kernel-core/src/normalized.rs:23-24` imports the five subset helpers and delegates the actual `is_subset_of` decisions to them [v]. Both absorptions kept behavior identical and made the Lean and Kani results statements about running code.
- Mutation testing already excludes `formal_aeneas.rs`, `formal_core.rs`, and the Kani harness files ("covered by the proof lane") while examining their production callers [v]. Every absorption therefore moves the shared scalar decisions into the proof lane. Public Kani and retained properties cover the shared projections, while the mutation lane and runtime tests exercise the remaining caller wiring (see FV-E1).
- The Kani binding precedent exists: `verify_delegation_chain_step` in `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` builds real `NormalizedToolGrant` values from the same symbolic booleans that drive its synthetic predicate and asserts the production `is_subset_of` agrees (binding step around lines 750-810). That is exactly the shape needed to prove a caller-side projection is not vacuous.

## Pre-implementation state

At proposal time, `formal_core` was a `pub(crate)` typed facade (`crates/kernel/chio-kernel-core/src/lib.rs:65-66` declared both `formal_aeneas` and `formal_core` as `pub(crate) mod`, and `formal_core.rs` carried `#![allow(dead_code)]`). The eight model-only helpers and their runtime twins were:

**`budget_precheck` (formal_core.rs:109), `budget_commit` (formal_core.rs:133)**

- Twin: `crates/kernel/chio-kernel/src/budget_store/in_memory.rs`, two decision points:
  - `try_increment` (line 231): invocation-count-only precheck at line 248, `max_invocations.is_none_or(|max| current.invocation_count < max)`, then saturating-add commit.
  - `try_charge_cost_with_ids_and_authority` (line 342): three-part precheck at lines 375-399 (invocation cap, per-invocation cost cap, total-cost cap via `checked_add`), commit at lines 406-449.
- Trait surface: `crates/kernel/chio-kernel/src/budget_store.rs:260` (`BudgetStore`). Second implementation: `crates/platform/chio-store-sqlite/src/budget_store/trait_impl.rs`.
- Semantic delta: the model is decrement-form over `(remaining_invocations, remaining_units)`; the runtime is increment-form over `(invocation_count vs max_invocations, total_cost vs max_total_cost_units)` and adds a third per-invocation cap check (`cost_units > max_per`) that the two-dimensional model does not name.

**`dpop_freshness_valid` (formal_core.rs:154)**

- Twin: `crates/kernel/chio-kernel/src/dpop.rs::verify_dpop_proof_stateless`,
  in its freshness block.
- Semantic delta: the runtime performs three checks where the model has two.
  The third (`issued_at` not older than `now - (ttl + skew)`) is mathematically
  implied by the second and remains defense in depth. The combined TTL and
  skew arithmetic is saturating.

**`dpop_admits` (formal_core.rs:160)**

- Twin: the requirement folds in
  `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`
  and `nested_flow_evaluation.rs`. Each calls
  `verify_dpop_for_permission_preview`, projects the result through
  `dpop_verification_admits`, and leaves single-use mutation to
  `ChioKernel::reserve_dispatch_credentials` at the dispatch boundary.
- Semantic delta: the runtime projects required, present, and statelessly valid
  into `dpop_verification_admits`. Nonce freshness is enforced separately by
  the owner-qualified dispatch reservation so earlier budget or guard failures
  do not consume the proof permanently.

**`nonce_admits` (formal_core.rs:171)**

- Twin: `crates/kernel/chio-kernel/src/dpop.rs::DpopNonceStore::check_and_insert_entry_at`,
  reached by `check_and_insert_through` for direct verification and by
  `reserve_for_dispatch_through` from
  `ChioKernel::reserve_dispatch_credentials` for kernel dispatch.
- Semantic delta: the runtime couples `nonce_admits(already_live)` to atomic
  marker insertion. Signed markers remain live through the inclusive
  `issued_at + proof_ttl_secs` horizon, expired markers are reclaimed, and
  full live capacity denies fail-closed. Dispatch reservations additionally
  carry an owner so only a proven pre-dispatch unwind can remove them.

**`guard_pipeline_allows` (formal_core.rs:186)**

- Twins (two): `crates/kernel/chio-kernel/src/kernel/dispatch.rs::run_guards` (lines 261-323) and the portable-core guard loop in `crates/kernel/chio-kernel-core/src/evaluate.rs` (lines 387-407).
- Semantic delta: both loops short-circuit on first deny and accumulate guard evidence; both handle a fourth verdict (`PendingApproval`, fail-closed) that the model folds into `Error`.

**`revocation_snapshot_denies` (formal_core.rs:194)**

- Twin: `crates/kernel/chio-kernel/src/kernel/validation.rs::check_revocation` (lines 441-453); the delegation-feature `RevocationView` consult sits at line 465.
- Semantic delta: the runtime short-circuits store lookups (ancestors are not queried when the leaf is revoked) and distinguishes `CapabilityRevoked` from `DelegationChainRevoked`.

**`receipt_fields_coupled` (formal_core.rs:200)**

- Twin: `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::build_and_sign_receipt` (lines 5-98; body assembly at lines 37-59; the pure signing delegation to `chio_kernel_core::sign_receipt_with_handle` at line 81).
- Semantic delta: the runtime has no explicit coupling check at all. The fields are coupled by construction, which nothing enforces across refactors; this is the one family where absorption adds a check rather than replacing one.

## Design

### Absorption recipe (applies to every family)

1. Locate and pin the runtime twin. Name the exact function(s) and the decision expression inside them. If two candidate twins exist, absorb the one on the security decision path first and record the other in the phase notes.
2. Write the equivalence property test first, before touching the runtime. A proptest (workspace dep already present in both kernel crates: `crates/kernel/chio-kernel/Cargo.toml:88`, `crates/kernel/chio-kernel-core/Cargo.toml:76`) generates runtime-shaped state, projects it to the helper's inputs, and asserts `runtime_decision == helper_decision` on identical projected inputs. This test must pass against the unmodified runtime; any counterexample is a real model/runtime divergence and gets triaged before refactoring (see FV-E2 for the counterexample pipeline).
3. Refactor the call site: project runtime state to the pure-helper inputs and delegate the decision to the helper. Keep behavior identical, including short-circuiting, IO ordering, and error variants. Use lazy projection where the runtime short-circuits: route each early-return branch through the helper with the flags known at that point rather than forcing eager computation of all flags (concrete shapes per phase below).
4. Keep the equivalence proptest as a permanent regression test; add projection unit tests for each input. The shared projection is Kani-checked where feasible, while extraction of fields from concrete caller state remains runtime-tested.
5. Where feasible, add a Kani harness that runs the same shared projection function the production callers invoke and asserts its booleans/integers match the model semantics. Bind concrete store or caller state to that function with retained runtime properties rather than claiming Kani executes IO-heavy callers.
6. Only then update `formal/proof-manifest.toml`, `formal/MAPPING.md`, and the claim registry (see Manifest section). Manifest updates in the same PR as the refactor, never before.

Sketch of the step-2 test shape, using the budget family (the same skeleton serves all five):

```rust
proptest! {
    fn charge_decision_matches_model(
        count in any::<u32>(), max_inv in proptest::option::of(any::<u32>()),
        total in any::<u64>(), max_total in proptest::option::of(any::<u64>()),
        cost in any::<u64>(), max_per in proptest::option::of(any::<u64>()),
    ) {
        let runtime = store_with(count, total)
            .try_charge_cost("cap", 0, max_inv, cost, max_per, max_total)
            .map_err(|_| ());
        let model = budget_charge_admits(
            count, total, cost, max_inv, max_per, max_total,
        )
        .map_err(|_| ());
        prop_assert_eq!(runtime, model);
    }
}
```

`budget_charge_admits` is the exact shared projection both budget backends call, so the proptest exercises that boundary rather than a test-local reimplementation. Separate overflow tests retain the concrete backend error attribution that the normalized sketch omits.

### Visibility

`formal_core` is `pub(crate)` and `chio-kernel` is a separate crate, so phase 1 requires an export. Two options:

- Make `formal_core` a `pub mod` of `chio-kernel-core`.
- Keep the module `pub(crate)` and re-export only the absorbed helpers (and `BudgetCommitResult`, `GuardStep`) from `chio-kernel-core/src/lib.rs`.

Recommendation: curated re-exports. The facade contains model-only conveniences that should not become public API one PR before their absorption phase lands; exporting per-phase keeps the public surface equal to the absorbed surface. Note `./scripts/check-portable-kernel.sh` (a `proof-manifest.toml` gate command) must stay green; the helpers are dependency-free so this is expected to be free.

### Decision-shape notes per family

- Budget: express all three runtime checks as instances of the model's axis predicate. `remaining_invocations = max_invocations.saturating_sub(invocation_count)` with `invocation_cost = 1`; `remaining_units = max_total_cost_units.saturating_sub(current_total)` with `unit_cost = cost_units`; the per-invocation cap is `budget_precheck` on a third axis (`remaining = max_cost_per_invocation`, `cost = cost_units`). Absent caps project to the accept branch before the helper is consulted (the model has no Option layer; the projection unit tests pin this). The ledger side effects (event log append, seq, holds) stay runtime-owned and run only when the helper accepts.
- DPoP: `verify_dpop_proof_stateless`'s two load-bearing freshness comparisons
  become one call through `dpop_freshness_admits` to `dpop_freshness_valid`.
  The redundant third check stays with saturating `ttl + skew` arithmetic.
  Each requirement fold still performs stateless verification only when
  required, then calls
  `dpop_verification_admits(required, present, verification.is_ok())`. Nonce
  admission occurs at the dispatch boundary through the signed-horizon
  reservation path, so the atomic verifier result and the single-use marker
  remain separate fail-closed decisions.
- Guards: absorb at step granularity, not pipeline granularity. The runtime loops keep evidence accumulation and early exit. Every result projects to `GuardStep`, `guard_step_admits` computes the verified step decision, and `guard_projection_allows_continuation` requires both projected approval and an observed `Allow` before continuation. `PendingApproval` and `Err(_)` project to `GuardStep::Error`, while the original runtime match retains exact reason and evidence attribution.
- Revocation: preserve lookup short-circuiting and error attribution by routing each observed branch through `revocation_lookup_denies`: `PresentedToken` projects to `revocation_snapshot_denies(token_revoked, false)`, and `Ancestor` projects to `revocation_snapshot_denies(false, link_revoked)`. Every deny decision now passes through the proven predicate; no extra store or snapshot IO is introduced.
- Receipts: `build_and_sign_receipt` gains an explicit fail-closed coupling gate between body assembly and `sign_receipt_with_handle` (call at `receipt_persistence.rs:81`): compute the five booleans by comparing the assembled body against the decision inputs in `ReceiptParams` and refuse to sign when `receipt_fields_coupled` is false. Today the comparisons are true by construction; the gate exists to make that an enforced invariant instead of an accident of the current code.

## Implementation plan

Each phase is one PR, independently landable, in this order (cheapest coupling first is not the goal; decision-path value is).

1. Phase 1: budget precheck/commit into the kernel budget store.
   - Modify `crates/kernel/chio-kernel-core/src/lib.rs` (re-export `budget_precheck`, `budget_commit`, the shared increment/charge projections, and their result types).
   - Modify `crates/kernel/chio-kernel/src/budget_store/in_memory.rs` (`try_increment`, `try_charge_cost_with_ids_and_authority`: decision via the shared budget projection, effects unchanged).
   - Modify `crates/platform/chio-store-sqlite/src/budget_store/store.rs` and `trait_impl.rs` (the same increment and charge projections on the SQLite row).
   - Add `crates/kernel/chio-kernel/tests/budget_decision_equivalence.rs` (pre-refactor equivalence proptest, kept as regression) and projection unit tests beside the impls.
   - Add a Kani binding harness in `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` if the projection can be expressed core-side; otherwise document why not (see Open questions).
2. Phase 2: `dpop_admits`/`dpop_freshness_valid`/`nonce_admits` into the DPoP admission path.
   - Modify `crates/kernel/chio-kernel/src/dpop.rs` (`verify_dpop_proof_stateless`
     freshness block; `DpopNonceStore::check_and_insert_entry_at` returns
     `nonce_admits(already_live)`; signed callers use
     `check_and_insert_through` or `reserve_for_dispatch_through`).
   - Modify `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`,
     `nested_flow_evaluation.rs`, and `credential_reservation.rs` (the
     requirement fold routes through `dpop_verification_admits`, then the
     dispatch boundary reserves the signed nonce horizon).
   - Add equivalence proptests in `crates/kernel/chio-kernel/tests/dpop_admission_equivalence.rs`, including the ttl/skew saturation edge cases.
3. Phase 3: `guard_pipeline_allows` into the guard verdict fold.
   - Modify `crates/kernel/chio-kernel-core/src/evaluate.rs` (guard loop, lines 387-407 region) and `crates/kernel/chio-kernel/src/kernel/dispatch.rs::run_guards`.
   - Add fold-equals-pipeline unit tests beside both loops; extend `crates/kernel/chio-kernel/src/kernel/tests/guard_pipeline.rs`.
4. Phase 4: `revocation_snapshot_denies` into the revocation snapshot check.
   - Modify `crates/kernel/chio-kernel/src/kernel/validation.rs::check_revocation` and `crates/kernel/chio-kernel/src/kernel/delegation.rs::consult_revocation_view_at` to call the same target-aware lazy projection.
   - Add equivalence proptest `crates/kernel/chio-kernel/tests/revocation_decision_equivalence.rs`.
5. Phase 5: `receipt_fields_coupled` into receipt assembly.
   - Modify `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::build_and_sign_receipt` (coupling gate before signing).
   - Add unit tests that force each of the five mismatches and assert the signing refusal; wire the refusal into the existing `KernelError::ReceiptSigningFailed` shape.

Every phase also carries its manifest/registry updates (below) and a `graphify update .` run per repo convention.

## CI and gating changes

- No new CI jobs. The equivalence proptests ride `cargo test --workspace`; Kani binding harnesses ride the existing required Kani lane and must be registered in `formal/rust-verification/kani-public-harnesses.toml` plus a `formal/MAPPING.md` row (enforced by `scripts/check-mapping.sh`, which extracts `#[kani::proof]` names [v]).
- The mutation lane configuration keeps excluding the proven bodies but now exercises the projections; no config change expected, but confirm the exclusion list does not accidentally match the new test files.
- `./scripts/check-portable-kernel.sh` and `./scripts/check-adapter-no-bypass.sh` must stay green; the re-exports are additive.
- The PR-time smoke tier discovers the equivalence properties through the
  workspace test command; no separate workflow list is required.

## Acceptance criteria

- [x] All eight helpers have at least one production caller on the security decision path, verified by a grep gate or review checklist per phase.
- [x] For each family, an equivalence proptest existed and passed against the unmodified runtime before the refactor landed (visible in the recorded parent and test-patch evidence).
- [x] Projection unit tests cover every projected flag/integer per family, including absent-cap and saturation edges.
- [x] At least the budget and revocation families carry a Kani projection-binding harness in the `verify_delegation_chain_step` style, registered in `kani-public-harnesses.toml` and `MAPPING.md`.
- [x] No behavior change: full workspace test suite, replay proptests, and guard pipeline tests green with no expectation edits other than new tests.
- [x] `formal/proof-manifest.toml` `covered_rust_symbols` matches reality after each phase (no listed-but-uncalled formal_core symbols remain at the end).
- [x] `docs/reference/CLAIM_REGISTRY.md` `FORM-IMPLEMENTATION-LINKED` scope text reviewed and, if strengthened, re-approved.
- [x] The DPoP `ttl + skew` addition is saturating by the end of phase 2.

## Risks and mitigations

- Projection-boundary bugs (the key risk). A wrong caller-side projection makes the proof vacuous: the helper is proven, the helper is called, and the decision is still wrong because the inputs lied (for example inverting `parent_has_cap`, or projecting `count <= max` where the runtime meant `count < max`). Mitigations: the projection unit tests are mandatory, not optional; the pre-refactor equivalence proptest pins the composite decision; and the Kani binding harness asserts caller projection equals helper input semantics on symbolic inputs, following the `verify_delegation_chain_step` precedent.
- Behavior drift during refactor: short-circuiting, store IO counts, and error variant attribution are observable (receipts, logs, budget mutation events). Mitigation: lazy projection shapes above; each phase's PR includes a "no new IO, no changed error variants" review checklist item. Budget tests compare semantic mutation fields and sequencing across both backends, excluding backend-generated event IDs and timestamps. The in-memory test pins `u64` arithmetic overflow, while SQLite pins its signed INTEGER storage boundary; both assert unchanged usage and event history after failure.
- Model dimensionality mismatch: the budget model is two-dimensional and decrement-form; forcing the three runtime checks through it invites a subtly wrong encoding. Mitigation: per-axis application as designed; if FV-B3's conservation law needs a richer model, extend `formal_aeneas.rs` there rather than bending projections here.
- Visibility widening leaks a half-finished API. Mitigation: curated per-phase re-exports; doc comments state the export exists for kernel absorption, not for external consumers.
- Twin misidentification: absorbing a lookalike (for example the execution-nonce path instead of the DPoP nonce store) wastes a phase and can double-wire a decision. Mitigation: each phase PR opens with the twin citation and its call-graph justification; ambiguities recorded below rather than guessed at.

## Resolved questions

- Budget authorization absorbs the bounded predicate. Hold capture, release,
  settlement, and reconciliation retain their ledger-owned decisions.
- `budget_split.rs` enforces sibling allocation rather than scalar admission,
  so it is not another twin of `budget_precheck`.
- Receipt evidence class combines `receipt_kind`, `boundary_class`,
  `observation_outcome`, `tool_origin`, `redaction_mode`, `actor_chain`, and
  `trust_level`. The other four model flags bind capability, request/action,
  verdict, and policy hash independently.
- Both the portable core guard loop and the hosted kernel guard loop delegate
  their per-step projection. Neither twin is deferred.
- Projection-binding harnesses live in the public kernel-core harness module.
  They symbolically bind the scalar projection and are registered in the
  public-core and multi-crate catalogs.

## Manifest and registry updates

Per phase, in the same PR as the code change:

- `formal/proof-manifest.toml`: the original missing helpers and the exact
  shared production projections are now in `covered_rust_symbols`; absorbed
  runtime boundaries, including both signed-horizon DPoP entrypoints, are
  named in `shell_entrypoints`. The projection entries do not claim storage or
  ledger verification.
- `formal/MAPPING.md`: new rows for every added Kani harness (enforced by `scripts/check-mapping.sh`); update the "Rust path constrained" column of existing rows that currently point at pre-absorption paths (for example the Apalache `RevocationCutCompleteness` and `KernelTransitionCancelSafe` rows).
- `docs/reference/CLAIM_REGISTRY.md`: `FORM-IMPLEMENTATION-LINKED` (line 57) may strengthen from "subject to strict Rust verification gates" toward naming the absorbed decision points; any wording change goes through the claim-gate inputs check (`proof-manifest.toml` `claim_gate_inputs`).
- `formal/rust-verification/kani-public-harnesses.toml` (or `kani-harnesses.toml`, per the open question): register new harnesses.
- `formal/theorem-inventory.json`: no new Lean theorems expected from this doc alone, but if phase 5 tightens the `ReceiptCouplingFacts` projection, the touched theorem notes should say so.
- Visibility change note: `crates/kernel/chio-kernel-core/src/lib.rs:65-66` currently declares `formal_aeneas` and `formal_core` as `pub(crate)`; the curated re-exports land in phase 1 and grow per phase.
