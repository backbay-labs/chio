# FV-B4: Loom harness registry and deterministic simulation testing

Status: Proposed (2026-07-09)
Theme: B - Aim the formal tools at the actual bug generator
Effort: M (Part 1, loom registry) / L (Part 2, DST)
Depends on: [FV-B1](FV-B1-drop-guard-model.md) and [FV-B3](FV-B3-budget-conservation-law.md) for the invariant statements the DST asserts; Part 1 has no dependencies
Feeds: [FV-E5](FV-E5-lane-ratchets.md), [FV-D1](FV-D1-distributed-revocation-model.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G3, G5, G1), [FV-E4](FV-E4-fuzz-plumbing-repair.md), [FV-C1](FV-C1-receipt-trace-validation.md)

## Summary

chio-kernel has ten loom interleaving models, including two that model the drop guard directly, and not one of them runs in CI: no workflow contains the string "loom" (verified by grepping `.github/workflows/` this session). Kani got the registry treatment (`.kani/harnesses.toml` drives a manifest sweep); loom gets nothing, so its models rot silently and their `--cfg loom` gate means `cargo test` never compiles them. Part 1 gives loom the same treatment: a `.loom/harnesses.toml` registry, a manifest-driven runner script, and a nightly lane. Part 2 is the larger bet: a deterministic simulation harness that drives the REAL kernel and store through seeded schedules with fault injection at persistence boundaries, asserting the TLA-derived invariants (ReceiptBeforeAllow, cancel-safety, the FV-B3 conservation law) at runtime. Part 2 is honestly L-sized; the phase plan cuts a minimal single-process slice first.

## Motivation and evidence

- The drop-guard fix family (`c2e8be7e3` through `38cc91471`, verified via `git show --stat`) shipped with a loom model of the drop race (`0981bc67b` gave it a failable non-atomic store), yet that model only runs when a developer remembers the incantation. A model that never runs is indistinguishable from no model (G5), and a lane with no PR or nightly hook is invisible to G1's gating story.
- Bounded model checking (FV-B1) explores an ABSTRACT machine; loom explores the real synchronization primitives but only in hand-carved micro-models; unit tests explore single schedules of the real code. The uncovered quadrant is many-schedule exploration of the real kernel: exactly where async cancellation bugs live, since a dropped future is a scheduler decision, not a code path a test naturally takes. DST covers that quadrant with seeded, replayable schedules.
- The Apalache lane explicitly defers concurrent commit-vs-cancel interleavings (`formal/apalache/KernelTransitionCancelSafe.tla` header, lines 8-14, read this session). Someone has to own them; loom owns the primitive-level races, DST owns the end-to-end ones.

## Current state

All claims verified this session unless marked [v].

- Loom tests: `crates/kernel/chio-kernel/tests/loom_concurrency.rs` (read in full), gated `#[cfg(any(loom, chio_kernel_loom))]` (line 1). Ten `loom::model` tests:
  - `loom_session_create_lookup_terminal_same_id` (line 65)
  - `loom_parent_signs_receipt_while_child_spawns` (line 119)
  - `loom_revocation_race_eval` (line 158)
  - `loom_receipt_channel_producer_drain` (line 216)
  - `loom_inflight_increment_decrement_storm` (line 298)
  - `loom_dashmap_session_insert_remove_concurrent` (line 379)
  - `loom_emergency_stop_arcswap` (line 418)
  - `loom_budget_atomic_decrement` (line 474)
  - `loom_post_admission_drop_guards_race_on_receipt_store_write_lock` (line 631): two armed post-dispatch guards racing on a deliberately non-atomic receipt store (`NonAtomicReceiptStore`, lines 564-601) serialized by the modeled `receipt_store_write_lock`; asserts no receipt lost, no double-record, zero releases.
  - `loom_disarmed_drop_guard_is_noop` (line 682).
- `loom` is a dev-dependency (`crates/kernel/chio-kernel/Cargo.toml:84`), with `cfg(loom)` and `cfg(chio_kernel_loom)` registered in `check-cfg` (line 195).
- No loom CI lane: `grep -rn loom .github/workflows/` returns nothing. Nightly jobs are `proptest-nightly`, `kani-public-nightly`, `formal-qualification`, `coverage` (`.github/workflows/nightly.yml`, job list verified).
- The Kani precedent to copy: `.kani/harnesses.toml` (schema `chio.kani.multi-crate.v1`, read this session) with per-entry `crate`, `harness`, `default_unwind`, `timeout_secs`, `lane`, `notes`, iterated by CI so adding a harness requires no workflow edit (header lines 24-28).
- Determinism seams for DST (assessed honestly):
  - `chio-kernel-core` has trait seams for time and entropy: `clock.rs` ("The kernel core never calls std::time::SystemTime::now()... inject... a fuzzed/mock clock for deterministic testing") and `rng.rs` ("The kernel core never calls OsRng directly"), both headers read this session [also v].
  - chio-kernel's effectful edges are traits: `BudgetStore` (`src/budget_store.rs:260`), `ReceiptStore` (`src/receipt_store.rs:187`), `PaymentAdapter` (`src/payment.rs:150`), `ToolServerConnection` (`src/runtime.rs:266`), `RuntimeAdmissionHook` (`src/kernel/mod.rs:87`). Every one can be wrapped by a deterministic fault-injecting implementation without kernel changes. This is the decisive enabler.
  - `crates/kernel/chio-runtime-harness` exists [v from crate map] but is NOT the right home: its `lib.rs` (read this session) is a runtime loopback harness for attest proof regeneration (scenario JSON in, `JsonRuntimeAdmissionStore`, proof-parity outputs). Two of its patterns are worth copying (explicit `now_unix_ms` input; scenario files as fixtures), but grafting kernel fault injection onto it would tangle two unrelated purposes.
  - Async runtime: chio-kernel depends on tokio (`Cargo.toml:69`) and evaluation is an async future with the dispatch await as the interesting suspension point (`kernel/evaluation/async_evaluation_core.rs:525` marks dispatch-started immediately before it). The kernel is a library, not a network of tokio tasks.

## Design

### Part 1: loom registry, runner, nightly lane

Registry `.loom/harnesses.toml`, schema `chio.loom.v1`:

```toml
schema = "chio.loom.v1"

[[harness]]
crate = "chio-kernel"
test = "loom_concurrency::loom_post_admission_drop_guards_race_on_receipt_store_write_lock"
max_preemptions = 3
lane = "nightly"
notes = "Two armed post-dispatch drop guards racing on the modeled receipt_store_write_lock; pins receipt-loss and double-record. Motivated by 0981bc67b / c2e8be7e3."
```

Fields: `crate` (cargo package), `test` (integration-test target module path plus test name; the runner splits on `::` to derive `--test loom_concurrency <name>`), `max_preemptions` (exported as `LOOM_MAX_PREEMPTIONS`; bounds schedule explosion per harness), `lane` (`"nightly"` now; `"pr"` reserved for a future fast tier under [FV-E3](FV-E3-pr-formal-smoke-tier.md)), `notes`. Seed entries: all ten tests listed above, `max_preemptions = 3` default (loom's own recommended practical bound), the two drop-guard entries annotated with their motivating commits.

Runner `scripts/run-loom-manifest.sh`: parse the registry (python3 `tomllib`, matching `scripts/check-apalache-formal-slice.py`'s python precedent), then per entry:

```bash
RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=<n> \
  cargo test -p <crate> --release --test <target> <test_name> -- --nocapture
```

Release profile is required (loom exhaustive exploration in debug is impractically slow). The script fails on first failing entry, prints the exact reproduction command including `LOOM_CHECKPOINT_FILE` guidance for local replay, and (matching the fail-closed house rule) fails if the registry names a test that does not exist or if a listed test compiles to zero executed tests (guards against the silent `cfg` mismatch failure mode: a typo in `--cfg loom` currently makes every loom test vanish successfully).

CI: new `loom-nightly` job in `.github/workflows/nightly.yml` (checkout, Rust toolchain, protobuf step copied from sibling jobs, then `scripts/run-loom-manifest.sh`). Nightly-only initially: exhaustive loom runs are minutes-per-test and the models change rarely; a PR path-filter on `tests/loom_concurrency.rs` and `.loom/**` can be added as a cheap targeted gate in the same PR if runtime measurements allow.

MAPPING: new "Loom interleaving harnesses" section in `formal/MAPPING.md`, one row per registry entry (property = test name, source = `crates/kernel/chio-kernel/tests/loom_concurrency.rs`, Rust path constrained = the production surface the model mirrors, e.g. the drop-guard row points at `kernel/kernel_drop_guard.rs:299-358` and the receipt-store write-lock serialization the model's own comment cites at lines 550-563). Extend `scripts/check-mapping.sh` with a loom whitelist so registry rows and MAPPING rows cannot drift (the script currently enforces only the RevocationPropagation TLA names and `kani_public_harnesses.rs`, verified by reading it).

### Part 2: deterministic simulation testing (DST)

Goal: run the REAL `ChioKernel` + a real store through seeded, replayable executions where the harness controls (1) the schedule (when the evaluation future is polled and when it is dropped), (2) the clock and rng, and (3) fault injection at the persistence boundary, then assert the TLA-derived invariants as runtime oracles after every episode:

- `ReceiptBeforeAllow`: no allow verdict is surfaced to the caller before its allow receipt is persisted (oracle: the instrumented `ReceiptStore` records a persist-sequence; the harness records the response-return instant in the same logical clock; assert order).
- Cancel-safety / drop disposition: after a forced drop, the FV-B1 disposition holds (exactly-one-or-zero terminal receipt per the phase, child receipts flushed, lease retained iff post-dispatch), checked against the receipt log.
- FV-B3 conservation: run the lane (c) audit (`kernel/ledger_audit.rs`) at episode end; the DST is lane (c)'s most aggressive driver.

Mechanism, minimal and bespoke: the interesting nondeterminism is future cancellation, not task scheduling, so phase 1 does not need turmoil or madsim. A seeded partial-poll executor is ~100 lines: build the evaluation future, poll it manually N steps where N is drawn from a seeded rng (`Ok(n)` completes, `Drop(n)` polls n times then drops the future mid-flight), with the wrapped `ToolServerConnection` yielding `Pending` a seeded number of times so there are real suspension points on both sides of `mark_dispatch_started`. Fault injection lives in wrapper implementations of the trait seams: `FaultingReceiptStore` (kill/fail before or after the nth persist, modeling crash-before/crash-after receipt persist), `FaultingBudgetStore` (fail the nth mutation, driving the `PreDispatchCleanupFault` path at `kernel/kernel_drop_guard.rs:139-229`), `FaultingRuntimeAdmissionHook` (fail `release_reserved`, driving the Finding C fault receipt). Crash-recovery episodes reopen the sqlite store and assert the invariants against the recovered state.

Home: `crates/kernel/chio-kernel/tests/dst/` (an integration-test module tree: `dst_drop_injection.rs` plus a `dst_support` module with the executor and the faulting wrappers), reusing the test-support constructors that `drop_guard_proptest.rs` already uses. Not `chio-runtime-harness` (wrong purpose, see Current state); a dedicated `chio-kernel-dst` crate is a later refactor if the support module outgrows the tests tree.

Episode shape (the replayability contract, reviewable now):

```rust
struct Episode {
    seed: u64,                       // drives poll counts, drop point, fault schedule
    plan: FaultPlan,                 // derived from seed; printed on failure
}
struct FaultPlan {
    polls_before_drop: Option<u32>,  // None = run to completion
    receipt_persist_fault: Option<PersistFault>, // KillBefore(n) | KillAfter(n) | FailNth(n)
    budget_mutation_fault: Option<u32>,          // fail the nth store mutation
    lease_release_fault: bool,                   // fail RuntimeAdmissionHook::release_reserved
}
// Oracle checks run after every episode (and after reopen, in crash episodes):
//   oracle_receipt_before_allow(&trace);
//   oracle_drop_disposition(&receipt_log, &plan);   // FV-B1 disposition table
//   oracle_conservation(&store);                    // FV-B3 lane (c) audit
```

Every failure message prints `(seed, plan)` so any CI failure is one command to replay; failing seeds get committed to a `dst-regressions.toml` corpus, mirroring the proptest-regressions discipline and feeding [FV-E2](FV-E2-counterexample-regression-pipeline.md).

Stretch (explicitly out of the minimal phase): message loss and reordering for federation via the iroh transport seam (the transport crate is seam-isolated by design), which upgrades the DST from single-process to distributed and feeds [FV-D1](FV-D1-distributed-revocation-model.md); adopting turmoil if and when that phase makes tokio task scheduling itself the nondeterminism under test. madsim is not recommended: it substitutes the runtime wholesale and would fork the dependency graph for little gain at this layer.

## Implementation plan

1. Phase 1 (M) - loom registry and lane. Add `.loom/harnesses.toml` (ten seed entries), `scripts/run-loom-manifest.sh`, the `loom-nightly` job in `.github/workflows/nightly.yml`, the MAPPING.md loom section, and the `check-mapping.sh` loom whitelist. Measure wall-clock per entry on the hosted runner and record it in the registry `notes` (input to [FV-E5](FV-E5-lane-ratchets.md) budgets).
2. Phase 2 (M) - DST core. Add `crates/kernel/chio-kernel/tests/dst/` with the seeded partial-poll executor, `FaultingReceiptStore`/`FaultingBudgetStore`/`FaultingRuntimeAdmissionHook` wrappers, and episode runner asserting the three invariant oracles over `InMemoryBudgetStore` plus the sqlite receipt store. Fixed seed set (e.g. 64 seeds) on PR; wide seeded sweep (10k episodes) in nightly.
3. Phase 3 (L) - crash-recovery episodes. Kill-and-reopen the sqlite store at seeded persist boundaries (crash before/after receipt persist); assert ReceiptBeforeAllow and conservation against the reopened store. This is where the RETIRED-SQLITE-CROSS-ROW discharge argument (`formal/proof-manifest.toml`, `discharged_assumptions`) gets its first executable witness.
4. Phase 4 (stretch) - federation loss/reorder via the iroh transport seam; evaluate turmoil then, not before. Tracked as a separate line item feeding FV-D1, not a blocker for B4 acceptance.

## CI and gating changes

- `.github/workflows/nightly.yml`: new `loom-nightly` job (Phase 1) and a `dst-nightly` step or job (Phase 2's wide sweep). Both manifest/seed driven so growth needs no workflow edits.
- PR tier: DST fixed-seed set runs as ordinary `cargo test` integration tests (no special flags), so it lands in the default PR gate automatically; loom stays nightly until measured, then a path-filtered PR job over `tests/loom_concurrency.rs` and `.loom/**` may be added.
- Failure routing: loom or DST failures file through `formal/issue-templates/property-counterexample.md` [v], lens `proptest` being the closest existing category; add a `loom | dst` lens value to the template in Phase 1 so classification (spec/implementation/harness bug) applies uniformly.

## Acceptance criteria

- [ ] `.loom/harnesses.toml` exists with all ten current loom tests registered; `scripts/run-loom-manifest.sh` runs them green locally and fails loudly on a missing or zero-test entry.
- [ ] `loom-nightly` job green on consecutive nights; per-entry wall-clock recorded in the registry.
- [ ] `formal/MAPPING.md` loom section landed; `scripts/check-mapping.sh` enforces registry/MAPPING agreement for loom names.
- [ ] DST phase 2: a seeded episode runner exercises the real kernel with drop injection on both sides of `mark_dispatch_started`, and the three oracles (ReceiptBeforeAllow, drop disposition, FV-B3 conservation) pass over the fixed seed set on PR and the wide sweep nightly.
- [ ] Any DST failure reproduces from its printed `(seed, plan)` in one command; at least one deliberately injected bug (revert of `38cc91471`'s flush, applied locally) is demonstrated caught by the sweep before acceptance.
- [ ] Crash-recovery episodes (Phase 3) assert ReceiptBeforeAllow across a reopen; documented run linked from the proof coverage map ([FV-C5](FV-C5-proof-coverage-map.md)).
- [ ] Honest scope note in all docs: DST phase 2-3 is single-process, single-store; federation is a stretch phase.

## Risks and mitigations

- Loom runtime blowup as models grow (exhaustive exploration is exponential in preemptions). Mitigation: per-entry `max_preemptions` in the registry; nightly lane; [FV-E5](FV-E5-lane-ratchets.md) owns budget ratchets.
- The bespoke executor drifts from real tokio behavior (a schedule tokio would never produce, or missing ones it would). Mitigation: the executor only chooses poll counts and drop points, which are legal for ANY executor per the Future contract; assertions are about kernel obligations on drop, which must hold under every conforming executor. Document this argument in `dst_support`.
- DST flakiness from hidden nondeterminism (hash seeds, time). Mitigation: clock/rng enter through the existing seams; `HashMap` iteration inside the kernel is not schedule-visible to the oracles; any residual nondeterminism is a bug in the harness by definition (episode replay must be bit-identical on oracle inputs) and acceptance requires demonstrating replay.
- Part 2 scope creep toward a distributed simulator. Mitigation: the phase gates above; federation explicitly deferred to FV-D1 with only the seam noted here.
- Registry rot (tests added without registry rows). Mitigation: the runner script cross-checks `#[cfg(any(loom, chio_kernel_loom))] #[test]` occurrences in `tests/loom_concurrency.rs` against registry entries and fails on unregistered tests, the same closed-loop trick `check-mapping.sh` uses for Kani harnesses.

## Open questions

- `chio_kernel_loom` vs `loom` cfg: the double gate (`Cargo.toml:195` registers both) suggests an intended crate-local alias; the runner should standardize on one flag and the registry should record which. Decide in Phase 1.
- Should the DST oracles consume the FV-B1 TLA invariants mechanically (generated runtime checkers per [FV-C1](FV-C1-receipt-trace-validation.md)) instead of hand-written Rust assertions? Hand-written for phase 2; convergence with C1's trace validator is the right end state and should be revisited when both exist.
- Seed corpus policy: commit failing seeds only (proptest-regressions style) or also a rotating green corpus for coverage tracking? Leaning failing-only; green corpora belong to the fuzz lane and inherit [FV-E4](FV-E4-fuzz-plumbing-repair.md)'s plumbing concerns.
- Whether `loom_budget_atomic_decrement` (line 474) and the FV-B3 lane (d) proptest should share a single model of the budget CAS loop to avoid a third divergent mini-model (G4); candidate for [FV-A3](FV-A3-creusot-dedup.md)-style dedup review.

## Manifest and registry updates

- New registry: `.loom/harnesses.toml` (schema `chio.loom.v1`) as specified; source of truth for the loom lane, same contract as `.kani/harnesses.toml` ("append a block, CI auto-iterates").
- New script: `scripts/run-loom-manifest.sh` (runner + registry/test cross-check).
- `formal/MAPPING.md`: new loom section with ten rows; drop-guard rows cite `kernel/kernel_drop_guard.rs:299-358` and motivating commits `0981bc67b`, `c2e8be7e3`; add DST oracle rows once Phase 2 lands (property = oracle name, source = `crates/kernel/chio-kernel/tests/dst/`).
- `scripts/check-mapping.sh`: loom whitelist enforcement as described.
- `formal/proof-manifest.toml`: append `./scripts/run-loom-manifest.sh` to `gate_commands` once the lane is stable (nightly-green for a week), and a `notes` line placing loom and DST in the evidence taxonomy (interleaving witnesses over real primitives; not proofs; complementary to the Apalache bounded models).
- `formal/theorem-inventory.json`, `formal/assumptions.toml`, `.kani/harnesses.toml`: no changes. DST seed regressions live in `crates/kernel/chio-kernel/tests/dst/dst-regressions.toml`, referenced from the counterexample issue template once the `loom | dst` lens value is added.
