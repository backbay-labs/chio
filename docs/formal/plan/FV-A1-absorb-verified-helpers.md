# FV-A1: Absorb verified helpers into production call paths

- Status: Proposed (2026-07-09)
- Theme: A - Make the proven code the running code
- Effort: M (rolling; one helper family per PR)
- Depends on: none (the pattern is already proven in-tree)
- Feeds: [FV-C2](./FV-C2-verified-inclusion-verifier.md), [FV-B3](./FV-B3-budget-conservation-law.md), [FV-D3](./FV-D3-economy-conservation.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G2, G4), [FV-A2](./FV-A2-aeneas-generated-equivalence.md), [FV-A4](./FV-A4-mirror-drift-hashes.md), [FV-E1](./FV-E1-spec-mutation-testing.md)

## Summary

`chio-kernel-core` ships a proven pure decision core (`formal_aeneas.rs` behind the `formal_core` facade), but eight of its helpers are model-only: no production code path ever calls them, while `chio-kernel` implements the same decisions a second time by hand. This is gap G2: the theorems are true statements about functions the kernel does not run. The fix is mechanical and already proven twice in-tree (`classify_time_window` in capability verification, the five subset helpers in scope normalization): locate the runtime twin, pin runtime-vs-helper equivalence with a property test, then refactor the runtime call site to project its state into the helper's inputs and delegate the decision. This document sequences that absorption over five phases, one helper family at a time, and defines the recipe, the projection-boundary safeguards, and the manifest updates each phase must carry.

## Motivation and evidence

- Gap G2 ([../GAP_ANALYSIS.md](../GAP_ANALYSIS.md)): verified helpers exist but production does not call them. The following `formal_core` functions have zero production callers today [v]: `budget_precheck`, `budget_commit`, `dpop_freshness_valid`, `dpop_admits`, `nonce_admits`, `guard_pipeline_allows`, `revocation_snapshot_denies`, `receipt_fields_coupled`.
- The manifest already overstates. `formal/proof-manifest.toml` lists `formal_core::budget_commit`, `formal_core::dpop_admits`, `formal_core::guard_pipeline_allows`, and `formal_core::receipt_fields_coupled` under `covered_rust_symbols` (lines 73-76) even though nothing in production executes them. `formal/MAPPING.md` likewise cites `formal_core::revocation_snapshot_denies` as the discharge for the Apalache `RevocationCutCompleteness` row constraining `ChioKernel::check_revocation`. Absorption is what makes those existing registry claims true rather than aspirational.
- The pattern works and costs little. `crates/kernel/chio-kernel-core/src/capability_verify.rs:39` imports `classify_time_window` and uses it in real token verification; `crates/kernel/chio-kernel-core/src/normalized.rs:23-24` imports the five subset helpers and delegates the actual `is_subset_of` decisions to them [v]. Both absorptions kept behavior identical and made the Lean and Kani results statements about running code.
- Mutation testing already excludes `formal_aeneas.rs`, `formal_core.rs`, and the Kani harness files ("covered by the proof lane") while examining their production callers [v]. Every absorption therefore moves logic from mutation-blind hand-rolled twins into the proof lane, and leaves only thin projections behind for the mutation lane to chew on (see FV-E1).
- The Kani binding precedent exists: `verify_delegation_chain_step` in `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` builds real `NormalizedToolGrant` values from the same symbolic booleans that drive its synthetic predicate and asserts the production `is_subset_of` agrees (binding step around lines 750-810). That is exactly the shape needed to prove a caller-side projection is not vacuous.

## Current state

`formal_core` is a `pub(crate)` typed facade (`crates/kernel/chio-kernel-core/src/lib.rs:65-66` declares both `formal_aeneas` and `formal_core` as `pub(crate) mod`, and `formal_core.rs` carries `#![allow(dead_code)]`). The eight model-only helpers and their runtime twins, all verified this session:

**`budget_precheck` (formal_core.rs:109), `budget_commit` (formal_core.rs:133)**

- Twin: `crates/kernel/chio-kernel/src/budget_store/in_memory.rs`, two decision points:
  - `try_increment` (line 231): invocation-count-only precheck at line 248, `max_invocations.is_none_or(|max| current.invocation_count < max)`, then saturating-add commit.
  - `try_charge_cost_with_ids_and_authority` (line 342): three-part precheck at lines 375-399 (invocation cap, per-invocation cost cap, total-cost cap via `checked_add`), commit at lines 406-449.
- Trait surface: `crates/kernel/chio-kernel/src/budget_store.rs:260` (`BudgetStore`). Second implementation: `crates/platform/chio-store-sqlite/src/budget_store/trait_impl.rs`.
- Semantic delta: the model is decrement-form over `(remaining_invocations, remaining_units)`; the runtime is increment-form over `(invocation_count vs max_invocations, total_cost vs max_total_cost_units)` and adds a third per-invocation cap check (`cost_units > max_per`) that the two-dimensional model does not name.

**`dpop_freshness_valid` (formal_core.rs:154)**

- Twin: `crates/kernel/chio-kernel/src/dpop.rs::verify_dpop_proof_stateless`, freshness block at lines 272-303.
- Semantic delta: the runtime performs three checks where the model has two. The third (issued_at not older than `now - (ttl + skew)`, lines 295-301) is mathematically implied by the second and is defense in depth. Line 297 also contains an unchecked `proof_ttl_secs + max_clock_skew_secs` addition that the absorption should convert to saturating arithmetic.

**`dpop_admits` (formal_core.rs:160)**

- Twin: the requirement fold in `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs:180-182` and `nested_flow_evaluation.rs:150-152` (`.any(|m| m.grant.dpop_required == Some(true))`, then `verify_dpop_for_request`), landing in `crates/kernel/chio-kernel/src/kernel/dispatch.rs::verify_dpop_for_request` (line 180).
- Semantic delta: the runtime expresses `!required || (present && valid && fresh)` as early-return control flow spread across two files; no single expression computes the model's predicate.

**`nonce_admits` (formal_core.rs:171)**

- Twin: `crates/kernel/chio-kernel/src/dpop.rs::DpopNonceStore::check_and_insert` (lines 190-210).
- Semantic delta: the runtime couples the admit decision to the LRU insert and to TTL expiry of stale entries; `already_live` is implicit in the peek-plus-elapsed branch at lines 199-203.

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
4. Keep the equivalence proptest as a permanent regression test; add projection unit tests for each flag (the projection is now the only unverified code between state and decision).
5. Where feasible, add a Kani harness that binds the caller projection to the helper input semantics, following the `verify_delegation_chain_step` precedent: build the real runtime input type from symbolic primitives, run the real projection, and assert the helper sees the same booleans/integers the model reasons about.
6. Only then update `formal/proof-manifest.toml`, `formal/MAPPING.md`, and the claim registry (see Manifest section). Manifest updates in the same PR as the refactor, never before.

Sketch of the step-2 test shape, using the budget family (the same skeleton serves all five):

```rust
proptest! {
    fn charge_decision_matches_model(
        count in any::<u32>(), max_inv in proptest::option::of(any::<u32>()),
        total in any::<u64>(), max_total in proptest::option::of(any::<u64>()),
        cost in any::<u64>(), max_per in proptest::option::of(any::<u64>()),
    ) {
        let runtime = store_with(count, total).try_charge_cost(
            "cap", 0, max_inv, cost, max_per, max_total)?;
        let model = project_budget_axes(count, max_inv, total, max_total, cost, max_per)
            .all(|(remaining, axis_cost)| budget_precheck(remaining.0, remaining.1, axis_cost.0, axis_cost.1));
        prop_assert_eq!(runtime, model);
    }
}
```

The projection function under test (`project_budget_axes` here) is the exact function the refactor will install at the call site, so the proptest exercises the projection itself, not a test-local reimplementation of it.

### Visibility

`formal_core` is `pub(crate)` and `chio-kernel` is a separate crate, so phase 1 requires an export. Two options:

- Make `formal_core` a `pub mod` of `chio-kernel-core`.
- Keep the module `pub(crate)` and re-export only the absorbed helpers (and `BudgetCommitResult`, `GuardStep`) from `chio-kernel-core/src/lib.rs`.

Recommendation: curated re-exports. The facade contains model-only conveniences that should not become public API one PR before their absorption phase lands; exporting per-phase keeps the public surface equal to the absorbed surface. Note `./scripts/check-portable-kernel.sh` (a `proof-manifest.toml` gate command) must stay green; the helpers are dependency-free so this is expected to be free.

### Decision-shape notes per family

- Budget: express all three runtime checks as instances of the model's axis predicate. `remaining_invocations = max_invocations.saturating_sub(invocation_count)` with `invocation_cost = 1`; `remaining_units = max_total_cost_units.saturating_sub(current_total)` with `unit_cost = cost_units`; the per-invocation cap is `budget_precheck` on a third axis (`remaining = max_cost_per_invocation`, `cost = cost_units`). Absent caps project to the accept branch before the helper is consulted (the model has no Option layer; the projection unit tests pin this). The ledger side effects (event log append, seq, holds) stay runtime-owned and run only when the helper accepts.
- DPoP: `verify_dpop_proof_stateless`'s two load-bearing freshness comparisons become one call to `dpop_freshness_valid`. The redundant third check either stays (with a comment citing the implication) or is deleted with the equivalence proptest as the witness; the unchecked `ttl + skew` addition at `dpop.rs:297` gets fixed to saturating arithmetic either way. The requirement fold keeps its shape: `if dpop_required { ... if !dpop_admits(true, present, valid, fresh) { deny } }`, so proof verification work is still only done when required.
- Guards: absorb at step granularity, not pipeline granularity. The runtime loops keep evidence accumulation and early exit, but the running `allowed` flag becomes `formal_core` logic per step (`guard_step_allows` via the facade), with a unit test asserting the loop equals `guard_pipeline_allows` over the projected `GuardStep` sequence (`PendingApproval` and `Err(_)` both project to `GuardStep::Error`). This preserves behavior exactly, including which guard's name lands in the deny message.
- Revocation: preserve lookup short-circuiting and error attribution by routing each deny branch through the helper with lazily computed flags: `revocation_snapshot_denies(token_revoked, false)` for the presented token, then `revocation_snapshot_denies(false, link_revoked)` per chain link. Every deny decision now passes through the proven predicate; no extra store IO is introduced.
- Receipts: `build_and_sign_receipt` gains an explicit fail-closed coupling gate between body assembly and `sign_receipt_with_handle` (call at `receipt_persistence.rs:81`): compute the five booleans by comparing the assembled body against the decision inputs in `ReceiptParams` and refuse to sign when `receipt_fields_coupled` is false. Today the comparisons are true by construction; the gate exists to make that an enforced invariant instead of an accident of the current code.

## Implementation plan

Each phase is one PR, independently landable, in this order (cheapest coupling first is not the goal; decision-path value is).

1. Phase 1: budget precheck/commit into the kernel budget store.
   - Modify `crates/kernel/chio-kernel-core/src/lib.rs` (re-export `budget_precheck`, `budget_commit`, `BudgetCommitResult`).
   - Modify `crates/kernel/chio-kernel/src/budget_store/in_memory.rs` (`try_increment`, `try_charge_cost_with_ids_and_authority`: decision via helper, effects unchanged).
   - Modify `crates/platform/chio-store-sqlite/src/budget_store/trait_impl.rs` (same decision predicate on the projected row).
   - Add `crates/kernel/chio-kernel/tests/budget_decision_equivalence.rs` (pre-refactor equivalence proptest, kept as regression) and projection unit tests beside the impls.
   - Add a Kani binding harness in `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs` if the projection can be expressed core-side; otherwise document why not (see Open questions).
2. Phase 2: `dpop_admits`/`dpop_freshness_valid`/`nonce_admits` into the DPoP admission path.
   - Modify `crates/kernel/chio-kernel/src/dpop.rs` (`verify_dpop_proof_stateless` freshness block; `DpopNonceStore::check_and_insert` returns `nonce_admits(already_live)`).
   - Modify `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs` and `nested_flow_evaluation.rs` (requirement fold routes through `dpop_admits`).
   - Add equivalence proptests in `crates/kernel/chio-kernel/tests/dpop_admission_equivalence.rs`, including the ttl/skew saturation edge cases.
3. Phase 3: `guard_pipeline_allows` into the guard verdict fold.
   - Modify `crates/kernel/chio-kernel-core/src/evaluate.rs` (guard loop, lines 387-407 region) and `crates/kernel/chio-kernel/src/kernel/dispatch.rs::run_guards`.
   - Add fold-equals-pipeline unit tests beside both loops; extend `crates/kernel/chio-kernel/src/kernel/tests/guard_pipeline.rs`.
4. Phase 4: `revocation_snapshot_denies` into the revocation snapshot check.
   - Modify `crates/kernel/chio-kernel/src/kernel/validation.rs::check_revocation` (and the delegation-view consult path in `crates/kernel/chio-kernel/src/kernel/delegation.rs` if its deny shape matches; verify during the phase).
   - Add equivalence proptest `crates/kernel/chio-kernel/tests/revocation_decision_equivalence.rs`.
5. Phase 5: `receipt_fields_coupled` into receipt assembly.
   - Modify `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs::build_and_sign_receipt` (coupling gate before signing).
   - Add unit tests that force each of the five mismatches and assert the signing refusal; wire the refusal into the existing `KernelError::ReceiptSigningFailed` shape.

Every phase also carries its manifest/registry updates (below) and a `graphify update .` run per repo convention.

## CI and gating changes

- No new CI jobs. The equivalence proptests ride `cargo test --workspace`; Kani binding harnesses ride the existing required Kani lane and must be registered in `formal/rust-verification/kani-public-harnesses.toml` plus a `formal/MAPPING.md` row (enforced by `scripts/check-mapping.sh`, which extracts `#[kani::proof]` names [v]).
- The mutation lane configuration keeps excluding the proven bodies but now exercises the projections; no config change expected, but confirm the exclusion list does not accidentally match the new test files.
- `./scripts/check-portable-kernel.sh` and `./scripts/check-adapter-no-bypass.sh` must stay green; the re-exports are additive.
- FV-E3's PR-time formal smoke tier, when it lands, should include the equivalence proptests in its fast set; note the dependency there, not here.

## Acceptance criteria

- [ ] All eight helpers have at least one production caller on the security decision path, verified by a grep gate or review checklist per phase.
- [ ] For each family, an equivalence proptest existed and passed against the unmodified runtime before the refactor landed (visible in PR history as a separate commit).
- [ ] Projection unit tests cover every projected flag/integer per family, including absent-cap and saturation edges.
- [ ] At least the budget and revocation families carry a Kani projection-binding harness in the `verify_delegation_chain_step` style, registered in `kani-public-harnesses.toml` and `MAPPING.md`.
- [ ] No behavior change: full workspace test suite, replay proptests, and guard pipeline tests green with no expectation edits other than new tests.
- [ ] `formal/proof-manifest.toml` `covered_rust_symbols` matches reality after each phase (no listed-but-uncalled formal_core symbols remain at the end).
- [ ] `docs/reference/CLAIM_REGISTRY.md` `FORM-IMPLEMENTATION-LINKED` scope text reviewed and, if strengthened, re-approved.
- [ ] The `dpop.rs:297` unchecked `ttl + skew` addition is saturating by the end of phase 2.

## Risks and mitigations

- Projection-boundary bugs (the key risk). A wrong caller-side projection makes the proof vacuous: the helper is proven, the helper is called, and the decision is still wrong because the inputs lied (for example inverting `parent_has_cap`, or projecting `count <= max` where the runtime meant `count < max`). Mitigations: the projection unit tests are mandatory, not optional; the pre-refactor equivalence proptest pins the composite decision; and the Kani binding harness asserts caller projection equals helper input semantics on symbolic inputs, following the `verify_delegation_chain_step` precedent.
- Behavior drift during refactor: short-circuiting, store IO counts, and error variant attribution are observable (receipts, logs, budget mutation events). Mitigation: lazy projection shapes above; each phase's PR includes a "no new IO, no changed error variants" review checklist item; budget phase asserts the mutation-event log shape is byte-identical in tests.
- Model dimensionality mismatch: the budget model is two-dimensional and decrement-form; forcing the three runtime checks through it invites a subtly wrong encoding. Mitigation: per-axis application as designed; if FV-B3's conservation law needs a richer model, extend `formal_aeneas.rs` there rather than bending projections here.
- Visibility widening leaks a half-finished API. Mitigation: curated per-phase re-exports; doc comments state the export exists for kernel absorption, not for external consumers.
- Twin misidentification: absorbing a lookalike (for example the execution-nonce path instead of the DPoP nonce store) wastes a phase and can double-wire a decision. Mitigation: each phase PR opens with the twin citation and its call-graph justification; ambiguities recorded below rather than guessed at.

## Open questions

- Budget twin surface: this doc targets the store implementations' accept/deny predicate (`in_memory.rs` and the sqlite trait impl). Should the hold lifecycle (`authorize_budget_hold` at `budget_store.rs:507` and the capture/release/reconcile family) absorb the same helper in phase 1, or is that FV-B3 territory? Current lean: authorize-time decision only in phase 1; holds move with FV-B3.
- There is also a portable-core budget surface (`chio-kernel-core/src/budget_split.rs`, reached from `evaluate_with_full_floor` via `evaluate_portable_verdict` at `crates/kernel/chio-kernel/src/kernel/validation.rs:370`). Whether its sibling-split arithmetic is a third twin of `budget_precheck` or a different law entirely needs a session of its own before phase 1 scopes it in.
- Receipt coupling: the projection for `evidence_class_matches` is ambiguous. Candidates in the assembled body are `receipt_kind`, `boundary_class`, and `trust_level` (`receipt_persistence.rs:37-59`). The phase 5 PR must resolve this against the Lean `ReceiptCouplingFacts` model in `formal/lean4/Chio/Chio/Core/Protocol.lean` rather than picking silently.
- Guard absorption in `chio-kernel-core::evaluate` vs `chio-kernel::run_guards`: both are real twins. Plan says both in phase 3; if the core loop's error plumbing makes the step-level delegation ugly, is core-only plus a documented deferral acceptable?
- Should the Kani projection-binding harnesses live in `kani_public_harnesses.rs` (public lane, MAPPING.md-enforced) even when the projection code is in `chio-kernel` (a crate the public harness file cannot see)? Possible answer: a small `#[cfg(kani)]` harness module inside `chio-kernel` plus a new row scope in `formal/rust-verification/kani-harnesses.toml`; decide in phase 1.

## Manifest and registry updates

Per phase, in the same PR as the code change:

- `formal/proof-manifest.toml`: add the newly production-called symbols to `covered_rust_symbols` (`formal_core::budget_precheck`, `formal_core::dpop_freshness_valid`, `formal_core::nonce_admits`, `formal_core::revocation_snapshot_denies` are missing today); annotate the four already-listed formal_core symbols (lines 73-76) as absorbed once their phase lands. Extend `covered_rust_modules` if new kernel modules join the proof-facing set. Consider adding the absorbed call sites to `shell_entrypoints` where they are the shell-side boundary.
- `formal/MAPPING.md`: new rows for every added Kani harness (enforced by `scripts/check-mapping.sh`); update the "Rust path constrained" column of existing rows that currently point at pre-absorption paths (for example the Apalache `RevocationCutCompleteness` and `KernelTransitionCancelSafe` rows).
- `docs/reference/CLAIM_REGISTRY.md`: `FORM-IMPLEMENTATION-LINKED` (line 57) may strengthen from "subject to strict Rust verification gates" toward naming the absorbed decision points; any wording change goes through the claim-gate inputs check (`proof-manifest.toml` `claim_gate_inputs`).
- `formal/rust-verification/kani-public-harnesses.toml` (or `kani-harnesses.toml`, per the open question): register new harnesses.
- `formal/theorem-inventory.json`: no new Lean theorems expected from this doc alone, but if phase 5 tightens the `ReceiptCouplingFacts` projection, the touched theorem notes should say so.
- Visibility change note: `crates/kernel/chio-kernel-core/src/lib.rs:65-66` currently declares `formal_aeneas` and `formal_core` as `pub(crate)`; the curated re-exports land in phase 1 and grow per phase.
