# Milestone 03: Capability Algebra Property + Bounded-Model Suite

Status: proposed
Lens consensus: protocol, security, testing
Owner: formal-verification + kernel
Cross-refs: M01 (codegen drift), M04 (replay shares fuzzers), M05 (async refactor must keep suite green)

## Goal

Convert the "capability-based" load-bearing claim from a hand-tested assertion into a layered property and bounded-model artifact. Lift Chio's algebraic guarantees (attenuation, scope subsumption, revocation, delegation depth, deny-overrides) from a small differential proptest in `formal/diff-tests` and the existing 5-harness Kani slice to a full property suite across `chio-core-types`, `chio-kernel-core`, `chio-credentials`, `chio-policy`, and `chio-kernel`, plus an Apalache-checked TLA+ module for the concurrent-revocation regime that Lean's static `bounded_model` claimClass cannot reach.

## Why now

P3 (Bounded model trajectory) and the v3.18 audit landed scope subsumption proofs in `formal/lean4/Chio/Chio/Proofs/Monotonicity.lean` and a working differential in `formal/diff-tests/tests/scope_diff.rs`, but proptest is declared at workspace level and used by only two files (`crates/chio-core/tests/property_invariants.rs` and `crates/chio-kernel/tests/property_budget_store.rs`). Kani public coverage is fixed at the five symbols listed in `formal/rust-verification/kani-public-harnesses.toml`. Federation, delegation chain, and revocation are exactly the surfaces external auditors will probe first, and they currently rest on integration tests. Closing the algebra gap before any v4-class qualification work prevents repeated re-litigation.

## Verified inventory (today)

- 5 Kani public harnesses in `formal/rust-verification/kani-public-harnesses.toml` (`verify_capability`, `NormalizedScope::is_subset_of`, `resolve_matching_grants`, `evaluate`, `sign_receipt`).
- Lean modules under `formal/lean4/Chio/Chio/`: `Core/{Capability,Protocol,Receipt,Revocation,Scope}.lean`, `Proofs/{AeneasEquivalence,Evaluation,FormalClosure,Monotonicity,Protocol,Receipt,Revocation}.lean`, `Spec/Properties.lean`.
- 10 ASSUME entries in `formal/assumptions.toml` (`ASSUME-ED25519`, `ASSUME-SHA256`, `ASSUME-CANONICAL-JSON`, `ASSUME-OS-CLOCK`, `ASSUME-SQLITE-ATOMICITY`, `ASSUME-TLS`, `ASSUME-NETWORK-TRANSPORT`, `ASSUME-EXTERNAL-REGISTRIES`, `ASSUME-SUBPROCESS-ISOLATION`, `ASSUME-CHAIN-FINALITY`).
- Zero `*.tla` files in the repo today.
- Zero `use proptest` lines in `chio-credentials` or `chio-policy`.
- Capability algebra (`ChioScope::is_subset_of`, `ToolGrant::is_subset_of`, `validate_attenuation`, `NormalizedScope`) lives in `chio-core-types/src/capability.rs` and `chio-kernel-core/src/normalized.rs`. `chio-core` is a re-export facade.
- `chio-credentials` is the portable-VC and Agent Passport surface (no native delegation-chain primitive); delegation chains live on `CapabilityToken` in `chio-core-types`.
- `chio-policy` is HushSpec (allow/warn/deny) with `merge` (extends inheritance) and `evaluate`; it has no scope-intersection operator.

## In scope

- 18 named proptest invariants across four crates, retargeted to where each algebra actually lives (see Phase 1).
- TLA+ module `formal/tla/RevocationPropagation.tla` modelling concurrent revocation across N federated authorities, checked by Apalache `0.50.x` under `PROCS=4, CAPS=8` in CI.
- Kani harness expansion from 5 to 10 symbols.
- Tiered fuzz schedule: 256 cases per invariant on PR, 4096 nightly via `PROPTEST_CASES`, regression seeds persisted under `crates/<crate>/proptest-regressions/` with `PROPTEST_REGRESSIONS=true`.
- Mapping doc `formal/MAPPING.md` tying TLA+ actions to Lean theorems and Rust call sites; assumption-discharge update in `formal/assumptions.toml`.

## Out of scope

- New protocol features. The algebra under test is what already ships.
- Replacing Lean's `bounded_model` claimClass with `proven` for properties that need unbounded induction; that is later trajectory work.
- Symbolic execution beyond Kani (no Crux, no Verus expansion this milestone).
- Distributed liveness proofs beyond a single `RevocationEventuallySeen` weak-fairness check; we model safety primarily.
- Adversarial-bytes decoder fuzzing for capability-shaped inputs. That class of bug is owned by M02 (`capability_receipt`, `mcp_envelope_decode`, `oid4vp_presentation` libFuzzer targets); the proptest invariants here assume well-formed inputs and check the algebra. See M02's "M02 vs M03 oracle ownership" table for the partition. Cross-oracle promotion (proptest counterexample to libFuzzer seed and back) is the M02 `scripts/promote_fuzz_seed.sh --mode {libfuzzer,proptest}` workflow; this milestone consumes it but does not own it.

## Success criteria (measurable)

- 18 new proptest invariants land, distributed: 5 in `chio-core-types`, 5 in `chio-kernel-core`, 4 in `chio-credentials`, 4 in `chio-policy`. Each invariant has a name in the exit list below. (chio-kernel keeps its existing `property_budget_store.rs`; this milestone does not duplicate it.)
- `cargo test --workspace` runs 256 cases per invariant on PR; nightly job sets `PROPTEST_CASES=4096` and posts a duration metric.
- Kani public harness count grows from 5 to 10. `kani-public-harnesses.toml` `covered_symbols` lists all 10. `scripts/check-kani-public-core.sh` exits 0 in CI.
- `formal/tla/RevocationPropagation.tla` exists with safety invariants `NoAllowAfterRevoke`, `MonotoneLog`, `AttenuationPreserving` and one liveness property `RevocationEventuallySeen` (weak fairness on `Propagate`). Apalache run `apalache-mc check --inv=NoAllowAfterRevoke --length=12 RevocationPropagation.tla` is green under `PROCS=4, CAPS=8`.
- `formal/MAPPING.md` documents, per row, an algebra property -> Lean theorem ID -> TLA+ action -> Rust call site -> proptest/Kani harness.
- At least one entry in `formal/assumptions.toml` is narrowed: `ASSUME-SQLITE-ATOMICITY` reduces from "atomicity for revocation, budget, receipt, and registry state" to "atomicity per single-row write"; the cross-row case is discharged by a tested invariant in the budget store and a TLA+ check on the revocation log. Discharge mechanism is recorded as a `RETIRED-` block in `formal/assumptions.toml` and as a row in `formal/proof-manifest.toml`.

## Phase breakdown

### Phase 1 - Proptest expansion across the four algebra crates

Effort: L (8 days). First commit: `test(chio-core-types): add capability algebra proptest scaffold` touching `crates/chio-core-types/tests/property_capability_algebra.rs`, `crates/chio-core-types/Cargo.toml` (proptest dev-dep), `crates/chio-core-types/proptest-regressions/.gitkeep`.

Atomic tasks:

1. (S, 0.5d) Add `proptest` as `[dev-dependencies]` in the four crate Cargo.tomls and create `proptest-regressions/` directories. Commit: `test: enable proptest dev-dep in algebra crates`.
2. (M, 1.5d) Land `crates/chio-core-types/tests/property_capability_algebra.rs` with five `proptest!` blocks. Commit: `test(chio-core-types): name five capability algebra invariants`.
3. (M, 1.5d) Land `crates/chio-kernel-core/tests/property_evaluate.rs` with five `proptest!` blocks reusing generators from `formal/diff-tests/src/generators.rs`. Commit: `test(chio-kernel-core): name five evaluate invariants`.
4. (M, 1.5d) Land `crates/chio-credentials/tests/property_passport.rs` with four blocks. Commit: `test(chio-credentials): name four passport lifecycle invariants`.
5. (M, 1d) Land `crates/chio-policy/tests/property_evaluate.rs` with four blocks. Commit: `test(chio-policy): name four merge/evaluate invariants`.
6. (S, 1d) Wire `PROPTEST_CASES=256` into `.github/workflows/ci.yml` PR job and `PROPTEST_CASES=4096` into `.github/workflows/nightly.yml`. Commit: `ci: tier proptest case count by lane`.
7. (NEW) (S, 0.5d) Add `scripts/check-proptest-coverage.sh` that greps each named invariant function and fails if any is missing or renamed; wire into the `verify` job. Commit: `ci(NEW): gate proptest invariant inventory`.

Named invariants by full Rust path (each is the exact `#[test]` or `proptest!` function name in the file):

- `chio_core_types::tests::property_capability_algebra::scope_subset_reflexive`
- `chio_core_types::tests::property_capability_algebra::scope_subset_transitive_normalized`
- `chio_core_types::tests::property_capability_algebra::tool_grant_subset_implies_scope_subset`
- `chio_core_types::tests::property_capability_algebra::validate_attenuation_monotonic_under_chain_extension`
- `chio_core_types::tests::property_capability_algebra::delegation_depth_bounded_by_root`
- `chio_kernel_core::tests::property_evaluate::evaluate_deny_when_capability_revoked`
- `chio_kernel_core::tests::property_evaluate::evaluate_allow_implies_grant_subset_of_request`
- `chio_kernel_core::tests::property_evaluate::resolve_matching_grants_order_independent`
- `chio_kernel_core::tests::property_evaluate::intersection_distributes_over_grant_union`
- `chio_kernel_core::tests::property_evaluate::wildcard_subsumes_specific_under_intersection`
- `chio_credentials::tests::property_passport::passport_verify_idempotent_on_well_formed`
- `chio_credentials::tests::property_passport::revoked_lifecycle_entry_never_verifies`
- `chio_credentials::tests::property_passport::lifecycle_state_transitions_monotone`
- `chio_credentials::tests::property_passport::passport_signature_breaks_under_any_subject_mutation`
- `chio_policy::tests::property_evaluate::merge_associative_for_extends`
- `chio_policy::tests::property_evaluate::deny_overrides_warn_and_allow`
- `chio_policy::tests::property_evaluate::decision_deterministic_for_fixed_input`
- `chio_policy::tests::property_evaluate::empty_extends_chain_is_identity_under_merge`

Note: the existing `crates/chio-core/tests/property_invariants.rs` and `crates/chio-kernel/tests/property_budget_store.rs` remain in place; this milestone does not touch their case count beyond raising it via env var.

### Phase 2 - Kani harness expansion

Effort: M (5 days). First commit: `test(chio-kernel-core): add scope intersection associativity Kani harness` touching `crates/chio-kernel-core/src/kani_public_harnesses.rs`, `formal/rust-verification/kani-public-harnesses.toml`.

Pin Kani at the toolchain version already in `rust-toolchain.toml` for the harness crate; bump only if a harness exceeds the existing `unwind=8` budget after minimization.

Atomic tasks:

1. (M, 1d) Land `verify_scope_intersection_associative` and `verify_revocation_predicate_idempotent`. Commit: `test(chio-kernel-core): prove scope intersection associative + revocation idempotent`.
2. (M, 1d) Land `verify_delegation_chain_step`. Commit: `test(chio-kernel-core): prove single-step delegation attenuation`.
3. (S, 0.5d) Land `verify_receipt_roundtrip`. Commit: `test(chio-kernel-core): prove receipt sign/verify roundtrip`.
4. (M, 1d) Land `verify_budget_checked_add_no_overflow`. Commit: `test(chio-kernel-core): prove budget overflow never partial-commits`.
5. (S, 0.5d) Update `formal/rust-verification/kani-public-harnesses.toml` `covered_symbols` to ten and add a `nightly_only` `harness_groups` entry for any harness exceeding the 6-min PR budget. Commit: `formal: extend kani public coverage to ten harnesses`.
6. (S, 0.5d) Wall-clock each harness on the CI runner; fold over-budget harnesses into the nightly group. Commit: `ci(formal): split slow Kani harnesses to nightly group`.
7. (NEW) (S, 0.5d) Add a CI check that diff-runs Kani only on harness files modified in the PR (preserves the full ten-harness sweep on `main` and nightly). Commit: `ci(NEW): scope PR Kani run to changed harnesses`.

Named harnesses by full Rust path:

- `chio_kernel_core::kani_public_harnesses::verify_scope_intersection_associative`
- `chio_kernel_core::kani_public_harnesses::verify_revocation_predicate_idempotent`
- `chio_kernel_core::kani_public_harnesses::verify_delegation_chain_step`
- `chio_kernel_core::kani_public_harnesses::verify_receipt_roundtrip`
- `chio_kernel_core::kani_public_harnesses::verify_budget_checked_add_no_overflow`

Existing five (preserved):

- `chio_kernel_core::kani_public_harnesses::verify_capability`
- `chio_kernel_core::kani_public_harnesses::verify_normalized_scope_is_subset_of`
- `chio_kernel_core::kani_public_harnesses::verify_resolve_matching_grants`
- `chio_kernel_core::kani_public_harnesses::verify_evaluate`
- `chio_kernel_core::kani_public_harnesses::verify_sign_receipt`

### Phase 3 - TLA+ revocation propagation + assumption discharge

Effort: L (10 days). First commit: `formal: scaffold RevocationPropagation TLA+ module` touching `formal/tla/RevocationPropagation.tla`, `formal/tla/MCRevocationPropagation.cfg`, `tools/install-apalache.sh`.

Atomic tasks:

1. (S, 0.5d) Land `tools/install-apalache.sh` pinning Apalache `0.50.x` and writing the `.cfg`. Commit: `tools: pin apalache 0.50.x installer`.
2. (L, 3d) Land `formal/tla/RevocationPropagation.tla` skeleton (state vars, init, next, three safety invariants by name). Commit: `formal: scaffold RevocationPropagation safety invariants`.
3. (M, 1.5d) Add `RevocationEventuallySeen` liveness property gated on weak fairness of `Propagate`. Commit: `formal: add RevocationEventuallySeen liveness lane`.
4. (M, 1.5d) Wire the `formal-tla` PR job in `.github/workflows/ci.yml` and the `formal-tla-liveness` nightly job in `.github/workflows/nightly.yml`. Commit: `ci(formal): add Apalache PR + liveness lanes`.
5. (M, 1.5d) Author `formal/MAPPING.md` and `scripts/check-mapping.sh`. Commit: `formal: cross-reference TLA+ to Lean and Rust call sites`.
6. (M, 1d) Update `formal/assumptions.toml` (narrow `ASSUME-SQLITE-ATOMICITY`, add `RETIRED-SQLITE-CROSS-ROW`) and `formal/proof-manifest.toml`. Commit: `formal: discharge cross-row sqlite atomicity via budget invariant + MonotoneLog`.
7. (NEW) (S, 1d) Land `formal/OWNERS.md` placeholder template (`TBD-primary` / `TBD-backup` slots, responsibilities subsection). Commit: `formal(NEW): scaffold OWNERS template with TBD slots`.

Apalache module sketch (the actual skeleton committed at task 2; compiles in Apalache `0.50.x` without errors). The model separates **current revocation view** from **historical receipts** and tracks revocation **epochs** so that `NoAllowAfterRevoke` does not falsely flag legitimate allow-before-revoke histories, and so `RevocationEventuallySeen` is a real per-pair liveness assertion gated on `WF_vars(Propagate)`:

```tla
---- MODULE RevocationPropagation ----
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS PROCS, CAPS, DEPTH_MAX
ASSUME PROCS # {} /\ CAPS # {} /\ DEPTH_MAX \in Nat

States == {"active", "attenuated", "revoked"}

VARIABLES
    state,        \* [PROCS -> [CAPS -> States]]; per-process current view
    depth,        \* [PROCS -> [CAPS -> 0..DEPTH_MAX]]; per-process delegation depth
    rev_epoch,    \* [PROCS -> [CAPS -> Nat]]; 0 means not-yet-revoked from this proc's view
    receipt_log,  \* [PROCS -> Seq([cap: CAPS, verdict: {"allow","deny"}, t: Nat, seen_epoch: Nat])]
    pending,      \* set of [from: PROCS, to: PROCS, cap: CAPS, epoch: Nat] propagation messages
    clock         \* Nat; advanced by Revoke and Evaluate so receipts are timestamp-ordered

vars == << state, depth, rev_epoch, receipt_log, pending, clock >>

Init ==
    /\ state       = [a \in PROCS |-> [c \in CAPS |-> "active"]]
    /\ depth       = [a \in PROCS |-> [c \in CAPS |-> 0]]
    /\ rev_epoch   = [a \in PROCS |-> [c \in CAPS |-> 0]]
    /\ receipt_log = [a \in PROCS |-> << >>]
    /\ pending     = {}
    /\ clock       = 1

Attenuate(a, c) ==
    /\ state[a][c] # "revoked"
    /\ depth[a][c] < DEPTH_MAX
    /\ depth' = [depth EXCEPT ![a][c] = @ + 1]
    /\ state' = [state EXCEPT ![a][c] = "attenuated"]
    /\ UNCHANGED << rev_epoch, receipt_log, pending, clock >>

Revoke(a, c) ==
    /\ state[a][c] # "revoked"
    /\ LET e == clock IN
       /\ state' = [state EXCEPT ![a][c] = "revoked"]
       /\ rev_epoch' = [rev_epoch EXCEPT ![a][c] = e]
       /\ pending' = pending \cup
            { [from |-> a, to |-> b, cap |-> c, epoch |-> e] : b \in PROCS \ {a} }
       /\ clock' = clock + 1
    /\ UNCHANGED << depth, receipt_log >>

Propagate(m) ==
    /\ m \in pending
    /\ pending' = pending \ {m}
    /\ IF m.epoch > rev_epoch[m.to][m.cap]
       THEN /\ rev_epoch' = [rev_epoch EXCEPT ![m.to][m.cap] = m.epoch]
            /\ state'     = [state     EXCEPT ![m.to][m.cap] = "revoked"]
       ELSE /\ UNCHANGED << rev_epoch, state >>
    /\ UNCHANGED << depth, receipt_log, clock >>

Evaluate(a, c) ==
    /\ LET v == IF rev_epoch[a][c] = 0 THEN "allow" ELSE "deny" IN
       receipt_log' = [receipt_log EXCEPT ![a] =
         Append(@, [cap |-> c, verdict |-> v, t |-> clock, seen_epoch |-> rev_epoch[a][c]])]
    /\ clock' = clock + 1
    /\ UNCHANGED << state, depth, rev_epoch, pending >>

Next ==
    \/ \E a \in PROCS, c \in CAPS :
         Attenuate(a, c) \/ Revoke(a, c) \/ Evaluate(a, c)
    \/ \E m \in pending : Propagate(m)

Spec == Init /\ [][Next]_vars /\ WF_vars(\E m \in pending : Propagate(m))

\* Safety invariants

NoAllowAfterRevoke ==
    \A a \in PROCS, c \in CAPS, i \in 1..Len(receipt_log[a]) :
        LET r == receipt_log[a][i] IN
            r.cap = c /\ r.verdict = "allow" => r.seen_epoch = 0

MonotoneLog ==
    \A a \in PROCS, i, j \in 1..Len(receipt_log[a]) :
        i < j => receipt_log[a][i].t < receipt_log[a][j].t

AttenuationPreserving ==
    \A a \in PROCS, c \in CAPS :
        /\ depth[a][c] \in 0..DEPTH_MAX
        /\ (state[a][c] = "attenuated" => depth[a][c] > 0)

\* Liveness (nightly)

RevocationEventuallySeen ==
    \A a, b \in PROCS, c \in CAPS :
        rev_epoch[a][c] # 0 ~> rev_epoch[b][c] >= rev_epoch[a][c]

====
```

Code mapping (load-bearing; cited by `formal/MAPPING.md` at task 5):

- `state` and revocation transitions map to `CapabilityToken` lifecycle and `RevocationLog` consumers in `crates/chio-credentials/`.
- `depth` and the `DEPTH_MAX` bound map to delegation/attenuation in `crates/chio-core-types/src/capability.rs:36-56`. Scope subset enforcement maps to `ChioScope::is_subset_of` (`capability.rs:195-216`) and `NormalizedScope::is_subset_of` (`crates/chio-kernel-core/src/normalized.rs:253-294`).
- `rev_epoch` corresponds to the propagation generation observable per-process in `crates/chio-kernel/src/capability_lineage.rs:11-32`; the SQLite-backed materialization lives in `crates/chio-store-sqlite/`.
- `receipt_log` append-only structure maps to `crates/chio-kernel/src/receipt_store.rs:67-79`; `clock` is the kernel's monotonic receipt counter.
- The normative property "an evaluate that issues `allow` after the issuing authority's revoke must not be observable" is `spec/PROTOCOL.md:365-379` and `:385-389`. `NoAllowAfterRevoke` formalizes it against per-process `seen_epoch`, not global state, so causal allow-before-revoke histories pass.

Apalache invocation (PR job): `apalache-mc check --inv=NoAllowAfterRevoke --inv=MonotoneLog --inv=AttenuationPreserving --length=12 formal/tla/RevocationPropagation.tla`.

Apalache invocation (nightly liveness job in `.github/workflows/nightly.yml` named `formal-tla-liveness`): `apalache-mc check --inv=RevocationEventuallySeen --length=20 formal/tla/RevocationPropagation.tla` plus the three safety invariants at the larger `PROCS=6, CAPS=16` config gated behind `workflow_dispatch`.

Pin Apalache at `0.50.x` (or the latest stable at planning time; record exact version in `tools/install-apalache.sh`).

`formal/tla/RevocationPropagation.tla` (new) models:

- State: six variables per the module above (`state`, `depth`, `rev_epoch`, `receipt_log`, `pending`, `clock`). `state[a][c]` ranges over `{active, attenuated, revoked}`; `rev_epoch[a][c]` is the per-process revocation epoch (0 means not-yet-seen); `receipt_log[a]` is an append-only sequence of `[cap, verdict, t, seen_epoch]` records; `pending` is the unordered set of in-flight propagation messages.
- Actions: `Attenuate(a, c)`, `Revoke(a, c)` (advances `clock`, stamps `rev_epoch`, broadcasts to peers via `pending`), `Propagate(m)` (consumes a `pending` message and updates the receiver's `rev_epoch` if the message's epoch is newer), `Evaluate(a, c)` (issues a receipt with the current `seen_epoch`).
- Constants: `PROCS` (set of authority identifiers), `CAPS` (set of capability identifiers), `DEPTH_MAX`. CI configuration `PROCS=4, CAPS=8, DEPTH_MAX=4` in `formal/tla/MCRevocationPropagation.cfg`; nightly liveness lane runs `PROCS=6, CAPS=16`.

Safety invariants (named):

- `NoAllowAfterRevoke`: every `allow` receipt was issued with `seen_epoch = 0`. Causal allow-before-revoke histories are admitted; allows after the issuing process's local revoke-view are forbidden.
- `MonotoneLog`: per-authority `receipt_log` timestamps are strictly increasing; the append-only shape is enforced by construction (every `Evaluate` uses `Append`; no action rewrites or deletes).
- `AttenuationPreserving`: `depth[a][c]` stays in `0..DEPTH_MAX`; the `attenuated` state implies `depth[a][c] > 0`.

Liveness:

- `RevocationEventuallySeen`: under `WF_vars(\E m \in pending : Propagate(m))`, for every pair of authorities `(a, b)` and capability `c`, if `a` revoked `c` at some epoch then `b`'s `rev_epoch[b][c]` eventually reaches at least that epoch.

CI integration:

- New job `formal-tla` in `.github/workflows/ci.yml` invoking `apalache-mc check --inv=NoAllowAfterRevoke --inv=MonotoneLog --inv=AttenuationPreserving --length=12 formal/tla/RevocationPropagation.tla`.
- Runtime budget: 20 min wall-clock; if exceeded, the job moves to `nightly.yml` and PR runs only `--length=6`.
- Configuration knobs `PROCS` and `CAPS` are env vars consumed by `tools/install-apalache.sh` (which writes the `.cfg`); larger configs (`PROCS=6`, `CAPS=16`) are gated behind manual `workflow_dispatch`.
- Liveness check (`RevocationEventuallySeen`) runs nightly only.

Mapping and assumption discharge:

- Write `formal/MAPPING.md` cross-referencing TLA+ actions to Lean theorems in `formal/lean4/Chio/Chio/Proofs/Revocation.lean` and to Rust symbols in `chio-core-types::capability`, `chio-kernel-core::evaluate`, and the credential-revocation paths in `chio-credentials::passport`.
- Update `formal/assumptions.toml`: narrow `ASSUME-SQLITE-ATOMICITY` to per-row atomicity; add a `RETIRED-SQLITE-CROSS-ROW` block citing the budget-store invariant `overflow_never_partially_commits` (proptest) and the TLA+ `MonotoneLog` invariant as joint discharge. Annotate `P2`, `P4`, `P6`, `P7` in `formal/proof-manifest.toml` with the new ledger entry. No other ASSUME entries are retired this milestone (sign-off gate).

## CI runtime budget

- PR job total wall-clock target: 25 min on the single CI runner image (locked in Wave 1 decision 6). Breakdown: proptest at `PROPTEST_CASES=256` ~6 min, ten Kani harnesses ~12 min (one nightly-only outlier permitted), Apalache `--length=12` ~6 min, mapping + lint ~1 min.
- Nightly job total wall-clock target: 90 min. Breakdown: proptest at `PROPTEST_CASES=4096` ~25 min, full Kani sweep with `unwind=12` ~30 min, Apalache `--length=20` plus liveness ~30 min, slack 5 min.
- Apalache runner max-memory cap: 8 GiB (`--mem=8g` on the runner). If a PR run OOMs at `--length=12`, drop to `--length=8` for that PR and file an issue tagged `apalache-blowup`.
- Loom interaction: M05 holds the loom budget separately (10 min, `LOOM_MAX_PREEMPTIONS=3`). M03 does not consume loom time.

## Liveness lane

- Workflow file: `.github/workflows/nightly.yml`.
- Job name: `formal-tla-liveness`.
- Property checked: `RevocationEventuallySeen` (weak fairness on `Propagate`). Runs `apalache-mc check --inv=RevocationEventuallySeen --length=20 formal/tla/RevocationPropagation.tla`.
- Output: posts a duration metric and counterexample trace (if any) as a CI artifact retained for 30 days.
- Failure routes to `formal-verification` owner via the issue template `formal/issue-templates/liveness-counterexample.md` (Phase 3 task 3 lands the template alongside the workflow).

## Property failure triage runbook

When a proptest minimizes to a counterexample on PR or nightly:

1. **Persist the seed**. The shrunk input is auto-written to `crates/<crate>/proptest-regressions/<file>.txt` by the proptest framework. The PR author commits that file in the same PR; CI re-runs to confirm the regression seed reproduces.
2. **File a tracking issue** using `formal/issue-templates/property-counterexample.md`. The issue body must include: the named invariant (full Rust path), the shrunk input as JSON, the offending git SHA, the proptest seed line, the lens (`property` / `kani` / `apalache`).
3. **Gate the merge**. The PR is blocked from merging until either (a) the underlying defect is fixed and the regression seed passes, or (b) a `formal-verification` owner approves a documented invariant amendment with a rationale comment in the issue. Option (b) is rare and requires a second reviewer.
4. **Cross-check Lean**. If the counterexample reveals a gap between the proptest and the Lean theorem cited in `formal/MAPPING.md`, add a row to `formal/proof-manifest.toml` under a `discrepancy` block and reopen the relevant Lean module.
5. **Update the mapping**. If the invariant text changes, update `formal/MAPPING.md` in the same PR. `scripts/check-mapping.sh` will fail until the new symbol is reachable.
6. **Backport gate**. If the property is on a release branch, the fix follows the standard backport flow; the regression seed must land on every backport target.

For Kani counterexamples the same flow applies, with the seed replaced by the Kani concrete trace under `target/kani/<harness>/`. For Apalache counterexamples, the trace from `--counter-example=trace.tla` is committed under `formal/tla/counterexamples/` with a sha256-named filename.

## `formal/OWNERS.md` placeholder template

Phase 3 task 7 lands `formal/OWNERS.md` with the following content (the user fills the two `TBD-*` slots before M03 closes; not blocking Wave 1 start per Wave 1 decision 7):

```markdown
# formal/ Ownership

This directory is governed jointly with the `formal-verification` group named in
`formal/assumptions.toml`. The two roles below carry named accountability for
the formal artifacts.

## Roles

- Primary: `TBD-primary` (GitHub handle). First responder for proof breakage,
  ASSUME-discharge proposals, and external-audit liaison.
- Backup: `TBD-backup` (GitHub handle). Covers PTO and overflow; second
  reviewer on any ASSUME retirement.

## Responsibilities

- Theorem-inventory cadence: `formal/theorem-inventory.json` is regenerated on
  every change under `formal/lean4/` via the precommit hook
  `scripts/regen-theorem-inventory.sh`. Primary reviews drift weekly.
- ASSUME retirement gate-keeping: any retirement of an entry in
  `formal/assumptions.toml` requires sign-off from primary plus one of (backup,
  kernel owner, security reviewer). Discharge mechanism must cite a Lean
  theorem ID, a property-test name, or an Apalache invariant.
- Apalache lane health: primary owns the green/red status of the
  `formal-tla` PR job and the `formal-tla-liveness` nightly job. Counterexamples
  open a tracking issue within one business day.
- Kani harness coverage: `kani-public-harnesses.toml` `covered_symbols` must
  match `harness_groups`. Primary reviews any change to `covered_symbols`.
- Mapping doc rot: `formal/MAPPING.md` is checked by `scripts/check-mapping.sh`;
  primary is the on-call when the script fails on `main`.
- External audit liaison: primary fields auditor questions and routes them to
  the right Lean module, Rust call site, or TLA+ action via `MAPPING.md`.

## Escalation

- Property failure on PR: see `Property failure triage runbook` in
  `.planning/trajectory/03-capability-algebra-properties.md`.
- Apalache OOM: file `apalache-blowup` tag and CC primary.
- Lean build break: kernel owner pages primary; primary either fixes within 24h
  or rolls back the offending PR.
```

## Dependencies

- Lean theorem set in `formal/lean4/Chio/Chio/Proofs/` (already present; see verified inventory).
- Existing differential generators in `formal/diff-tests/src/generators.rs`.
- `proptest` workspace dependency (already declared, currently used only in `chio-core` and `chio-kernel`).
- Apalache binary in CI image; `tools/install-apalache.sh` (new) pins version and writes `.cfg`.
- Kani toolchain pin in `rust-toolchain.toml` for the harness crate (already pinned for the existing 5).

## Cross-milestone touchpoints

- **M01 (spec codegen)**: capability and scope types are codegen targets. If M01 changes the wire shape of `ChioScope`, `CapabilityToken`, or `NormalizedScope`, every property and Kani harness in this milestone must be re-run. Mapping doc must call out which row is affected.
- **M04 (deterministic replay)**: shares the proptest generator pool. Place reusable generators in `formal/diff-tests/src/generators.rs` (already there) so M04's replay corpus and M03's invariants draw from the same arbitraries.
- **M05 (async kernel)**: the `evaluate` and `verify_capability` paths get migrated to `async fn` with interior mutability. The property suite from this milestone is the regression net for M05; `cargo test --workspace` plus the Kani harnesses must stay green across that refactor. M03 covers the algebra (capability subset, scope intersection, evaluate verdicts, revocation propagation, receipt sign/verify, budget overflow); M05 owns its own loom coverage for session lifecycle, receipt-channel backpressure, and inflight registry under thread interleaving (those surfaces are out-of-scope for M03 because they are concurrency-mechanics, not algebra). The named invariants `chio_kernel_core::tests::property_evaluate::evaluate_deny_when_capability_revoked`, `evaluate_allow_implies_grant_subset_of_request`, and `resolve_matching_grants_order_independent` plus the Kani harnesses `verify_evaluate`, `verify_revocation_predicate_idempotent`, `verify_budget_checked_add_no_overflow` are the explicit safety net M05 tests against on every PR.

## Risks and mitigations

- Apalache scalability at `PROCS=4, CAPS=8`. Symbolic state space for receipt logs grows fast; the run may not terminate in 20 min. Mitigation: parameter sweep during Phase 3 spike; if `--length=12` does not terminate, ship `--length=8` on PR and `--length=12` on nightly; if even nightly times out, drop one safety invariant per run and rotate.
- TLA+ author availability. The team has limited TLA+ experience. Mitigation: Phase 3 budgets a one-week spike for the spec author; reuse `tlaplus/Examples` patterns for append-only logs; pair with a Lean reviewer for invariant naming.
- Kani harness divergence from real Rust code. Harnesses bound input size (e.g. 4 grants) and may stop matching real call sites if the production code changes. Mitigation: every harness names the production symbol it covers in `harness_groups`; CI fails if a covered symbol's signature changes without a matching harness update. M01 codegen drift is the most likely trigger.
- Proptest minification flakiness on receipt-shaped types. Receipts contain `BTreeMap<String, Value>` and signed bytes; shrinking can produce inconsistent intermediate states. Mitigation: reuse the `BudgetModel` reference pattern from `property_budget_store.rs`; never assert on shrunk shape, only on outcome class. Persist regressions per crate.
- Kani `unwind` blowup on intersection harness. Mitigation: bound input scope size to 4 grants in the harness, document the bound in `harness_groups`.
- Mapping doc rot. `formal/MAPPING.md` is plain prose and will drift as crates rename. Mitigation: add a `scripts/check-mapping.sh` that greps the cited Rust symbols and Lean theorem IDs; CI fails if any cited target is missing. Run the same check after every M01 codegen regeneration.
- Assumption demotion claims more than it can prove. Mitigation: every retired entry must reference both a Lean theorem (or Rust property) and a TLA+ invariant or it stays. The narrowed `ASSUME-SQLITE-ATOMICITY` requires sign-off from the formal-verification owner before merge.

## Code touchpoints

- `crates/chio-core-types/tests/property_capability_algebra.rs` (new)
- `crates/chio-kernel-core/tests/property_evaluate.rs` (new)
- `crates/chio-credentials/tests/property_passport.rs` (new)
- `crates/chio-policy/tests/property_evaluate.rs` (new)
- `crates/chio-kernel-core/src/kani_public_harnesses.rs` (extend)
- `formal/rust-verification/kani-public-harnesses.toml` (update)
- `formal/tla/RevocationPropagation.tla` (new)
- `formal/tla/MCRevocationPropagation.cfg` (new)
- `formal/MAPPING.md` (new)
- `formal/assumptions.toml` (edit)
- `formal/proof-manifest.toml` (edit)
- `tools/install-apalache.sh` (new)
- `scripts/check-mapping.sh` (new)
- `scripts/check-proptest-coverage.sh` (new, NEW sub-task)
- `formal/OWNERS.md` (new, NEW sub-task)
- `formal/issue-templates/property-counterexample.md` (new)
- `formal/issue-templates/liveness-counterexample.md` (new)
- `formal/tla/counterexamples/.gitkeep` (new, holds Apalache traces)
- `.github/workflows/ci.yml` and `.github/workflows/nightly.yml` (extend)

## Open questions

- Should Lean proofs in `formal/lean4/Chio/Chio/Proofs/` move to constructive style for the theorems referenced by `formal/MAPPING.md`, or is classical reasoning acceptable as long as the witness is recoverable from the differential? Default: classical with a recorded witness; revisit if any auditor flags it.
- (Locked Wave 1 decision 7) `formal/OWNERS.md` lands in Phase 3 task 7 with `TBD-primary` / `TBD-backup` slots. The two GitHub handles are the only Wave 1 decision deferred to the user; assignment is due before M03 closes and does NOT block Wave 1 start.
- `theorem-inventory.json` maintenance discipline: how often is it regenerated, and by whom? Proposal: regeneration is a precommit hook on changes under `formal/lean4/`; checked in CI.
- (Locked Wave 1 decision 6) Apalache `0.50.x` is primary. TLC is available as a manual debug-only target (no CI lane). Single CI runner image. Re-open only by editing this section and the trajectory README together.
- Should `chio-federation` get its own property crate now, or reuse `chio-core-types` and `chio-credentials` invariants over a federation harness? Defer to milestone 04.
