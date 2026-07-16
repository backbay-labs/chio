# FV-B4: Loom registry and deterministic simulation testing

Status: Implemented (2026-07-11; local evidence complete, hosted advisory streak pending)
Theme: B - Aim the formal tools at the actual bug generator
Effort: Complete
Depends on: [FV-B1](FV-B1-drop-guard-model.md), [FV-B3](FV-B3-budget-conservation-law.md)
Feeds: [FV-E5](FV-E5-lane-ratchets.md), [FV-D1](FV-D1-distributed-revocation-model.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md), [FV-C1](FV-C1-receipt-trace-validation.md), [FV-C5](FV-C5-proof-coverage-map.md)

## Summary

FV-B4 now has two closed verification lanes:

1. Ten bounded Loom models are registered in `.loom/harnesses.toml`, executed
   one at a time by a fail-closed runner, mapped to production surfaces, and
   scheduled in the dispatchable nightly workflow.
2. Deterministic simulation testing drives real `ChioKernel` evaluation
   futures with seeded partial polling, real dispatch, faulting receipt,
   budget, and runtime-admission seams, and three runtime oracles. The PR corpus
   has 64 fixed seeds. The nightly lane executes exactly 10,000 episodes.
   Crash episodes use real SQLite receipt and budget stores, close every handle,
   reopen both databases, and audit recovered state.

The only incomplete acceptance item is the external seven-night hosted success
streak. No hosted run is claimed by this change.

Local completion evidence on 2026-07-15 ran all ten Loom models with three
preemptions in 229.86 seconds and all 10,000 deterministic schedules in 63.24
seconds.

## Decisions

- Loom remains a bounded abstract-model lane. Every registry entry carries
  `scope = "bounded_abstract_model"`; green Loom runs do not claim production
  primitive refinement.
- Runtime admission now has a default-ready
  `poll_ready_before_dispatch` method. It runs after reservation and drop-guard
  construction but before `mark_dispatch_started`. Normal hooks remain
  immediately ready. DST hooks return `Pending` once, giving the real future a
  legal cancellation point in the previously unsuspendable pre-dispatch window.
- A one-poll drop exercises pre-dispatch cleanup. A two-poll drop passes the
  readiness boundary, enters the real tool-server future, and exercises
  post-dispatch retention and cancellation. Completion plans poll until the
  real response returns.
- The seed grammar is closed to eight episode classes: clean pre-dispatch drop,
  admission-release fault, budget-reversal fault, two post-dispatch waits,
  clean allow, receipt-persist fault, and budget-admission fault.
- `ReceiptBeforeAllow` uses one logical trace shared by the receipt wrapper and
  executor. Volatile receipt IDs, wall-clock timestamps, and cryptographic
  entropy are deliberately excluded from the oracle projection. Security
  signing still uses real entropy.
- The FV-B3 oracle replays the real store mutation journal after every episode
  and compares partition totals, invocation snapshots, exposure snapshots,
  realized spend, and final usage. It is an executable runtime witness, not a
  proved refinement.
- Hand-written runtime oracles are retained for this phase. Mechanical
  generation from the FV-C1 trace vocabulary is a future architecture option,
  not an acceptance dependency.
- Corpus policy is resolved: keep a fixed green 64-seed PR corpus and a separate
  regression corpus for defect-specific seeds. Wide coverage uses a stable
  10,000-seed range, so any failure is directly replayable.
- The lane is single-process and single-store. Federation loss, duplication,
  and reordering remain in FV-D1 rather than being implied by these results.
- Both nightly jobs are advisory with a seven-run promotion threshold.
  `evidence_after_run_id = 0` records that no hosted streak exists yet.

## Loom Lane

`.loom/harnesses.toml` registers all ten tests in
`tests/loom_concurrency.rs`. The registry fixes package, integration target,
test name, preemption bound, lane, scope, and notes.

`scripts/run-loom-manifest.sh` rejects:

- unknown or missing fields;
- unsafe identifiers or duplicate entries;
- registry and source disagreement;
- zero compiled tests or compiled-list drift;
- ignored tests;
- anything other than exactly one passing test for an entry;
- pass-through libtest arguments.

The runner appends `--cfg chio_kernel_loom`, applies each bound, retains
per-test logs and timings under `target/loom/`, and prints checkpoint capture
and replay commands on failure. `scripts/tests/run-loom-manifest.test.sh`
covers the fail-closed runner cases.

## DST Lane

The machine-readable inputs are:

- `.dst/episodes.toml`: runner contract, exact counts, lanes, and ignored state;
- `.dst/harnesses.toml`: proof-coverage identities;
- `tests/dst/seeds.toml`: exactly 64 unique fixed PR seeds;
- `tests/dst/dst-regressions.toml`: defect regression seeds.

`scripts/run-dst.sh` cross-checks both registries, Cargo metadata, Rust source
declarations, compiled libtest discovery, and seed counts before it runs a
test. It fails on zero-match discovery or any result other than exactly one
passing test.

The real-kernel support module provides:

- a manual, safe `Future::poll` driver;
- a yielding real `ToolServerConnection`;
- a fail-nth `ReceiptStore`;
- a fail-nth delegating `BudgetStore`;
- a runtime-admission hook that can fail reservation release;
- a logical trace shared across persistence and response return;
- an FV-B3 journal replay oracle.

## Runtime Oracles

### ReceiptBeforeAllow

An allow response is valid only when the same logical trace contains an earlier
persisted allow receipt. Receipt append failure after real dispatch returns an
error and never surfaces `Verdict::Allow`.

### Drop disposition

- Clean pre-dispatch drop: one admission, one release, zero server starts, zero
  receipts.
- Faulted pre-dispatch cleanup: one release attempt, zero server starts, exactly
  one signed cancellation receipt with the cleanup-fault marker.
- Post-dispatch drop: one server start, zero reservation releases, exactly one
  cancellation receipt with retained-reservation metadata.
- Normal completion: one server start and one persisted allow receipt.
- Admission failures remain pre-dispatch and persist a deny response.

### Reservation conservation

Every episode replays the concrete budget journal and checks:

`reserved = outstanding + committed + released`

It also checks each journal after-snapshot and the final usage row. Crash
episodes rerun the same oracle against the reopened SQLite budget database.

## Crash Recovery

`dst_sqlite_crash_reopen_boundaries` runs two real-store episodes:

- crash before the first receipt append reaches SQLite;
- crash after SQLite synchronously commits the receipt but before the append
  result reaches the kernel.

The tool server runs in both cases and no allow response reaches the caller.
After all kernel and store handles are dropped, `SqliteReceiptStore::open_existing`
and `SqliteBudgetStore::open` recover the files. The pre-persist case contains
zero tool receipts. The post-persist case contains one signed allow receipt.
Both recovered budget journals conserve the dispatched five-unit
reconciliation.

## Mutation Witness

`dst_child_receipt_flush_regression_is_killed` first runs the unmodified real
nested-flow path and observes one durable completed child receipt. It then
injects a receipt-store mutation that acknowledges but suppresses the child
append, which models the flush omission fixed by `38cc91471`. The
`ChildReceiptsFlushed` oracle rejects the mutated run with the named invariant.
The mutation does not alter production code.

## Replay Contract

Every episode failure prints the seed, complete derived plan, and this command:

```bash
bash scripts/run-dst.sh --lane replay --seed <u64>
```

The replay lane requires `--seed`, sets `CHIO_DST_SEED`, runs exactly the
ignored replay test, and prints the plan before execution.

## CI and Posture

`.github/workflows/nightly.yml` supports both `schedule` and
`workflow_dispatch`.

- `loom-nightly (bounded abstract models)` executes the closed Loom registry
  and uploads `target/loom`.
- `dst-nightly (10k real-kernel episodes)` executes exactly 10,000 episodes
  and uploads `target/dst`.
- The 64 fixed seeds, crash/reopen test, and mutation witness are ordinary
  non-ignored integration tests, so the workspace PR test gate runs them.

`releases.toml` keeps both jobs advisory and requires seven consecutive
scheduled successes before a separate reviewed promotion.

## Local Evidence

Executed on 2026-07-11:

```text
cargo test -p chio-kernel --test dst_drop_injection
result: 3 passed; 0 failed; 2 ignored

bash scripts/run-dst.sh --lane pr
result: 3 registered PR tests passed individually

bash scripts/run-dst.sh --lane replay --seed 38
result: seed and full plan printed; exactly one replay test passed

bash scripts/run-dst.sh --lane nightly
result: exactly 10,000 episodes passed
test runtime: 34.75 seconds
runner wall time: 36.81 seconds

bash scripts/run-loom-manifest.sh --lane nightly
result: all 10 registered models passed at max_preemptions=3
cold release build: 28 minutes 54 seconds on a contended local host
warm per-model invocations: 0.82 to 5.56 seconds
```

The Loom runner, mapping gate, generated coverage, formatting, clippy, package
tests, workflow validation, and graph checks are part of the final acceptance
command set for this change.

## Acceptance

- [x] All ten Loom tests are registered, source-closed, mapped, and run by the
  fail-closed manifest runner.
- [x] Loom and DST nightly jobs are scheduled and manually dispatchable.
- [x] The fixed PR corpus contains exactly 64 unique seeds.
- [x] The real kernel is dropped on both sides of `mark_dispatch_started`.
- [x] Receipt, budget, and runtime-admission faults are exercised.
- [x] ReceiptBeforeAllow, exact drop disposition, and FV-B3 conservation run
  after every seeded episode.
- [x] The 10,000-episode wide sweep executed locally and passed.
- [x] Any seed replays in one command with its full plan printed.
- [x] Both SQLite crash boundaries close, reopen, and audit real stores.
- [x] The deliberate child-receipt flush omission is rejected.
- [x] MAPPING and generated proof coverage consume the registries.
- [x] Documentation states the single-process, single-store boundary.
- [ ] Seven consecutive hosted scheduled successes exist for each advisory
  nightly job.

## Promotion Rule

Do not change either lane to required posture until seven consecutive hosted
scheduled runs are reviewed, fresh, and recorded through the release-gate
evidence process. Local success and `workflow_dispatch` runs do not count
toward that streak.
