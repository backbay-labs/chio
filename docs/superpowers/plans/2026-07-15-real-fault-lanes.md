# Real Fault Lanes Implementation Plan (chaos, loadgen, loom)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the three highest-risk pieces of testing theater identified by `docs/architecture/reliability/PLAN-load-soak-chaos-program.md` with real harnesses: a sustained-load lane that boots the actual kernel stack (finding F49/F56), a chaos lane that actually injects the whitelisted fault classes (F53), and a loom lane that actually executes the three TCB interleaving models (F52).

**Architecture:** Two new workspace bench crates (`bench/chio-loadgen`, `bench/chio-chaos`) that boot real production types (`ChioKernel`, `SqliteReceiptStore`, stub tool server) and fail closed; `chio-chaos` reuses `chio-loadgen`'s `StackHarness`. The loom work makes the three existing `--cfg loom` test targets actually run (locally via a Makefile target, nightly via CI). CI lanes: cut `sustained-p99-nightly.yml` over to the real harness, add `chio-chaos-nightly.yml` and `loom-nightly.yml`.

**Tech Stack:** Rust (workspace toolchain), existing workspace deps ONLY (`thiserror`, `tempfile`, `rusqlite`, `serde`, `serde_json`, `tokio`, `loom`, `proptest`). GitHub Actions following the repo's existing workflow conventions.

## Explicit scope boundaries (do NOT widen)

In scope: F49 (real sustained lane, synthetic bench deleted), F53 core (real fault injection for 7 of the 8 scenario classes, in-tree assertions), F52 (loom models execute; kernel model ported toward real types).

Out of scope, documented as follow-ups (do not implement): chaos-report fixture regeneration/signing/freshness gates and the CI chaos-runner key (the evidence-pipeline half of F53); the `growth-probe`/`SizeProbe` feature and weekly 8h soak (F56 beyond RSS+queue accounting); `RelayOutage` scenario (needs federation relay infra); F50 (healthcare replay), F51 (TTFRH), F54 (wasm PR gate), F55 (bench-regression rework).

## Global Constraints

- No em dashes (U+2014) anywhere: code, comments, docs, commit messages. Use hyphens or parentheses.
- Clippy `unwrap_used = "deny"`, `expect_used = "deny"` workspace-wide. In tests, use the workspace's established helper pattern (see `.test_unwrap()` usage in `crates/platform/chio-store-sqlite/src/receipt_store/tests/bootstrap.rs`; find its definition and import it the same way).
- Fail-closed: every fallible harness path yields a typed error and denies; no silent success.
- **NO new external crates.io dependencies.** Supply-chain gates (cargo-deny duplicate baseline, cargo-vet exemptions) make new deps expensive. Known no-dep substitutes: percentiles = sort a `Vec<u64>` and index; RSS = `/proc/self/statm` on Linux, `ps -o rss= -p <pid>` via `std::process::Command` on macOS; SIGKILL = `std::process::Child::kill`; SIGTERM = `Command::new("kill").args(["-TERM", pid])`; deterministic RNG = local SplitMix64 (~12 lines).
- New crates: `publish = false`, `[lints] workspace = true`, added to root `Cargo.toml` `[workspace] members` next to `bench/ttfrh`.
- Tests must pass on macOS (dev) and Linux (CI). Anything Unix-signal-based: fine on both; anything `/proc`-based needs the macOS fallback.
- Default `cargo test` runs must stay fast: long-strength runs are env-scaled (e.g. `CHIO_CHAOS_ITERATIONS`, `CHIO_SUSTAINED_P99_SECONDS`), with small defaults for the PR tier and larger values set by the nightly workflows.
- Every scenario must implement the InjectionNoOp discipline: if the fault demonstrably did not take effect, the scenario FAILS with a typed `InjectionNoOp` error. A scenario that cannot prove it injected must not report success.
- Comments state contracts and invariants only. No dev-history, no planning references, no tutorial narration, no "we do X because the plan said so".
- Conventional commits (`test:`, `ci:`, `docs:` prefixes as appropriate). Commit message bodies end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Workflow YAML conventions: copy the pinned action SHAs, `permissions: contents: read`, and `concurrency` blocks from `.github/workflows/sustained-p99-nightly.yml`.
- Gate before declaring any task done: `cargo build --workspace && cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings` plus the focused tests for the task. Full `cargo test --workspace` runs once at the final milestone, not per task.
- If a change touches anything referenced by `scripts/tests/*.sh` meta-gates (grep first!), run the affected script locally.

---

## Milestone A: `bench/chio-loadgen` (F49/F56 core)

### Task A1: Loadgen crate skeleton + StackHarness boot

**Files:**
- Create: `bench/chio-loadgen/Cargo.toml`
- Create: `bench/chio-loadgen/src/lib.rs` (config + error types + re-exports)
- Create: `bench/chio-loadgen/src/stack.rs` (`StackHarness`)
- Create: `bench/chio-loadgen/src/rss.rs` (cross-platform RSS sampling)
- Create: `bench/chio-loadgen/tests/boot.rs`
- Modify: root `Cargo.toml` (add `"bench/chio-loadgen"` to members, next to line 172 `"bench/healthcare-pilot-capacity"`)

**Read first (in this order):**
1. `crates/kernel/chio-kernel/benches/fixtures/dispatch_request_fixture.rs` - `DispatchAllowFixture` builds a real `ChioKernel::new(make_config())` with an in-memory receipt log and exposes `dispatch_allow_once()`. This is the dispatch recipe; the harness swaps the in-memory log for `SqliteReceiptStore`.
2. `crates/kernel/chio-runtime-harness/src/kernel.rs` lines 18-90 - stub `ToolServerConnection` impl and the `CapabilityToken::sign` mint recipe (`ChioScope`/`ToolGrant`/`Operation::Invoke`).
3. `tests/e2e/tests/full_flow.rs` - full-stack wiring reference.
4. `crates/platform/chio-store-sqlite/src/lib.rs` (`SqliteStoreOptions`, `SqlitePoolConfig`, exports) and the `pub fn` surface of `src/receipt_store.rs` (`open`, `append_chio_receipt*`, `flush_receipt_writes`, `latest_committed_entry_seq`, `receipt_store_health`).

**Interfaces (produced; later tasks depend on these exact names):**

```rust
pub struct LoadgenConfig {
    pub arrival_rate_hz: u32,
    pub duration: std::time::Duration,
    pub tool_latency: std::time::Duration,
    pub store: StoreBacking,
    pub p99_budget: std::time::Duration,
    pub rss_growth_budget_bytes: u64,
}

#[derive(Debug, Clone)]
pub enum StoreBacking {
    Sqlite { path: std::path::PathBuf },
    Memory,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadgenError {
    #[error("receipt store failed to open: {0}")]
    StoreOpen(String),
    #[error("in-memory store is not permitted in a gating run")]
    MemoryStoreRejectedInGate,
    #[error("kernel boot failed: {0}")]
    KernelBoot(String),
    #[error("dispatch failed mid-run: {0}")]
    Dispatch(String),
    #[error("p99 {observed_ms}ms exceeded budget {budget_ms}ms")]
    P99Exceeded { observed_ms: u128, budget_ms: u128 },
    #[error("RSS grew {grew_bytes} bytes over budget {budget_bytes}")]
    RssGrowthExceeded { grew_bytes: u64, budget_bytes: u64 },
}

pub struct StackHarness { /* kernel, store handle, stub tool server, capability */ }

impl StackHarness {
    /// Gating entry point: rejects StoreBacking::Memory (fail-closed).
    pub fn boot(config: &LoadgenConfig) -> Result<Self, LoadgenError>;
    /// Local smoke entry point: permits Memory.
    pub fn boot_smoke(config: &LoadgenConfig) -> Result<Self, LoadgenError>;
    /// One allow-path dispatch through the real kernel; returns end-to-end latency.
    pub fn dispatch_allow_once(&self) -> Result<std::time::Duration, LoadgenError>;
    /// Direct access for chaos scenarios (Milestone B).
    pub fn store(&self) -> Option<&chio_store_sqlite::SqliteReceiptStore>;
    /// Force-flush pending receipt writes; returns latest committed entry seq.
    pub fn flush_durable(&self) -> Result<u64, LoadgenError>;
}

pub mod rss { pub fn current_rss_bytes() -> Option<u64>; }
```

The stub tool server is configurable-latency: it holds a `tool_latency: Duration` and sleeps for it inside `invoke` before returning JSON. Milestone B needs to override this per-scenario, so make the latency an `Arc<AtomicU64>` (millis) the harness exposes as `set_tool_latency_ms(u64)`.

**Steps:**

- [ ] **A1.1** Write `bench/chio-loadgen/tests/boot.rs` with three failing tests: `boot_rejects_memory_store_in_gate_mode` (expects `Err(LoadgenError::MemoryStoreRejectedInGate)`), `boot_reports_store_open_error_on_unwritable_path` (path under a regular file, e.g. `<tmpfile>/nested/receipts.sqlite`, expects `Err(LoadgenError::StoreOpen(_))`), `boot_smoke_dispatch_persists_one_receipt` (Sqlite in tempdir; `dispatch_allow_once()` then `flush_durable()` returns seq >= 1).
- [ ] **A1.2** Run `cargo test -p chio-loadgen` and confirm compile failure (crate absent), then scaffold `Cargo.toml` + empty lib until tests fail on assertions, not compilation of the test file itself.
- [ ] **A1.3** Implement `StackHarness` against the real APIs from the read-first list. No `unwrap`/`expect` anywhere.
- [ ] **A1.4** Run `cargo test -p chio-loadgen` until 3/3 pass; run `cargo clippy -p chio-loadgen -- -D warnings` and `cargo fmt --all -- --check`.
- [ ] **A1.5** Commit: `test(loadgen): boot real kernel and sqlite stack harness (F49)`

### Task A2: Sustained runner with measured percentiles and RSS

**Files:**
- Create: `bench/chio-loadgen/src/sustained.rs`
- Create: `bench/chio-loadgen/tests/sustained.rs`
- Modify: `bench/chio-loadgen/src/lib.rs` (export `run_sustained`, `LoadReport`)

**Interfaces (produced):**

```rust
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadReport {
    pub calls_attempted: u64,
    pub calls_ok: u64,
    pub ttfrh_ms: u128,           // wall-clock to first DURABLE receipt (flush confirmed)
    pub p50_ms: u128,
    pub p99_ms: u128,
    pub rss_start_bytes: Option<u64>,
    pub rss_end_bytes: Option<u64>,
    pub exporter_queue_high_water: Option<u64>,
    pub within_budget: bool,
}

pub fn run_sustained(harness: &StackHarness, config: &LoadgenConfig) -> Result<LoadReport, LoadgenError>;
/// Applies the fail-closed gate: Err(P99Exceeded/RssGrowthExceeded) when over budget.
pub fn enforce_budget(report: &LoadReport, config: &LoadgenConfig) -> Result<(), LoadgenError>;
```

**Implementation notes:**
- Pacer: absolute schedule (`start + n * interval`), not cumulative sleeps, so drift does not accumulate. Record per-call end-to-end latency in a `Vec<u64>` (nanos); percentiles by sort-and-index.
- RSS: sample at start and end (plus every 5s into a high-water) via `rss::current_rss_bytes()`; `None` on unsupported platforms is carried through, never fabricated.
- Exporter queue accounting: attempt to wire `chio-otel-receipt-exporter`'s public ingress queue snapshot. If wiring it requires a live collector endpoint or more than modest effort, set `exporter_queue_high_water: None` and record the decision in your report (this field is explicitly allowed to land as `None` in this PR).

**Steps:**

- [ ] **A2.1** Write failing tests in `tests/sustained.rs`: `pacer_holds_arrival_rate_within_tolerance` (2s at 200hz on Memory smoke boot: `calls_attempted` in 360..=440), `sustained_smoke_reports_measured_percentiles` (2s on Sqlite tempdir: `p99_ms > 0`, `calls_ok > 0`, `ttfrh_ms > 0`), `budget_violation_is_typed` (set `tool_latency = 20ms`, `p99_budget = 1ms`, expect `enforce_budget` = `Err(LoadgenError::P99Exceeded { .. })`).
- [ ] **A2.2** Run to confirm failures, implement, iterate to green.
- [ ] **A2.3** `cargo clippy -p chio-loadgen -- -D warnings && cargo fmt --all -- --check`.
- [ ] **A2.4** Commit: `test(loadgen): sustained runner with measured percentiles and rss accounting`

### Task A3: Gate binary + CI cutover + delete the synthetic bench

**Files:**
- Create: `bench/chio-loadgen/src/bin/sustained.rs`
- Modify: `.github/workflows/sustained-p99-nightly.yml` (replace the `cargo bench -p chio-kernel --features sustained-p99-nightly ...` step with the gate binary; keep the two companion smoke steps and env var)
- Delete: `crates/kernel/chio-kernel/benches/sustained_p99_30min.rs`
- Modify: `crates/kernel/chio-kernel/Cargo.toml` (remove `sustained-p99-nightly = []` feature at line 25 and the `[[bench]] name = "sustained_p99_30min"` block at lines 152-153)

**Binary contract:** reads `CHIO_SUSTAINED_P99_SECONDS` (default 30), `CHIO_LOADGEN_RATE_HZ` (default 200), `CHIO_LOADGEN_P99_BUDGET_MS` (default 50), `CHIO_LOADGEN_RSS_BUDGET_MB` (default 64). Boots `StackHarness::boot` with `StoreBacking::Sqlite` under a temp dir, runs `run_sustained`, prints the `LoadReport` as JSON to stdout, exits nonzero via `std::process::ExitCode` on `enforce_budget` error. No panics.

**Steps:**

- [ ] **A3.1** Implement the binary; local check: `CHIO_SUSTAINED_P99_SECONDS=5 cargo run -p chio-loadgen --release --bin sustained` prints JSON and exits 0; then `CHIO_LOADGEN_P99_BUDGET_MS=0 ...` exits nonzero.
- [ ] **A3.2** Cut over the workflow step to: `cargo run -p chio-loadgen --release --bin sustained` (env `CHIO_SUSTAINED_P99_SECONDS: "1800"` stays at workflow level).
- [ ] **A3.3** Delete the synthetic bench + feature. Then prove zero dangling references: `rg -n "sustained_p99_30min|sustained-p99-nightly|probe_kernel_store_exporter_stack" --glob '!docs/**' --glob '!.git'` must return only the workflow file's own name/env var and this plan. Also `rg -n "sustained" scripts/ ci-gates/` and update any meta-gate that greps for the old step (run the affected `scripts/tests/*.sh` locally if touched).
- [ ] **A3.4** `cargo build --workspace && cargo test -p chio-kernel --lib && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check` (workspace build proves the feature removal broke nothing).
- [ ] **A3.5** Commit: `test(loadgen): cut sustained-p99 lane over to real stack and delete synthetic bench (F49)`

---

## Milestone B: `bench/chio-chaos` (F53 core)

### Task B1: Chaos crate + SIGKILL-mid-append crash recovery

**Files:**
- Create: `bench/chio-chaos/Cargo.toml` (deps: `chio-loadgen` by path, `chio-store-sqlite`, `chio-kernel`, `chio-core-types`, `thiserror`, `tempfile`, `serde`, `serde_json`; `[lints] workspace = true`; `publish = false`)
- Create: `bench/chio-chaos/src/lib.rs` (scenario vocabulary + seeded RNG)
- Create: `bench/chio-chaos/src/bin/chaos_victim.rs`
- Create: `bench/chio-chaos/tests/kill_mid_append.rs`
- Modify: root `Cargo.toml` members (add `"bench/chio-chaos"`)

**Interfaces (produced):**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaosScenario {
    KillMinusNineMidAppend,
    SqliteEnospc,
    SigtermDrain,
    RetentionDuringLoad,
    HungToolServer,
    BlockingGuard,
    WedgedWriter,
}

impl ChaosScenario {
    /// Passport case id this scenario exercises (see the whitelist in
    /// crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs::is_supported_chaos_case).
    pub fn passport_case_id(&self) -> &'static str;
}

#[derive(Debug, thiserror::Error)]
pub enum ChaosError {
    #[error("stack boot failed: {0}")]
    Boot(String),
    #[error("fault injection did not take effect: {0}")]
    InjectionNoOp(&'static str),
    #[error("post-fault invariant violated: {0}")]
    InvariantViolated(String),
    #[error("victim process control failed: {0}")]
    Victim(String),
}

/// SplitMix64; seed printed in every test so failures reproduce.
pub struct ChaosRng(u64);
impl ChaosRng { pub fn new(seed: u64) -> Self; pub fn next_u64(&mut self) -> u64; pub fn range(&mut self, lo: u64, hi: u64) -> u64; }
```

`passport_case_id` mapping: KillMinusNineMidAppend and SqliteEnospc -> `receipt-log-unavailable`; SigtermDrain -> `tool-restart-lost-lease-cache`; RetentionDuringLoad -> `registry-split-brain`; HungToolServer -> `revocation-oracle-unavailable`; BlockingGuard -> `policy-reload-during-dispatch`; WedgedWriter -> `clock-skew-expiry-bypass`. (These ids are assertions of intent only in this PR; report regeneration is out of scope.)

**Victim protocol (`chaos_victim` binary):**
- Args: `<db_path> <ack_path> <max_receipts>`.
- Opens `SqliteReceiptStore::open(db_path)`, then loops: append one receipt, call `flush_receipt_writes()` (durability barrier), and only after a successful flush append a line `ack <seq>\n` to `ack_path` opened with `O_APPEND`, calling `sync_data()` after each line. Exits 0 after `max_receipts`.
- The ack file is the ground truth of "the store told a client this receipt is durable".

**Test `chaos_kill_mid_append_preserves_durable_acks` (in `tests/kill_mid_append.rs`), also aliased in a doc comment as the plan's named test `chaos_receipt_log_unavailable_preserves_merkle_head`:**
- One tempdir, ONE db reused across all rounds (torn state accumulates realistically), fresh victim per round.
- Per round r in 0..N (N = env `CHIO_CHAOS_ITERATIONS`, default 5): spawn the victim via `env!("CARGO_BIN_EXE_chaos_victim")`, sleep a seeded `ChaosRng.range(5, 400)` ms, `child.kill()` (SIGKILL), reap.
- InjectionNoOp discipline: if the victim already exited cleanly before the kill in EVERY round (check `try_wait` before kill), the test fails with `InjectionNoOp` (raise `max_receipts` so it cannot finish early).
- After each kill: reopen the store; assertions (each a typed `InvariantViolated` with context on failure):
  1. `SqliteReceiptStore::open` succeeds (recovery never bricks).
  2. `receipt_store_health()` reports a healthy verified head (read the health report struct's fields; anything poisoned/unverified fails).
  3. Every `ack <seq>` in the ack file satisfies `seq <= latest_committed_entry_seq()` AND the store can read that entry back (no acknowledged receipt lost).
  4. A fresh append + flush succeeds (store still serves writes).
- Print the seed on entry: `eprintln!("chaos seed: {seed}")`, seed from env `CHIO_CHAOS_SEED` or a fixed default (0xC10A0515).

**Checker-integrity test `ack_checker_detects_fabricated_loss`:** write an ack line for `latest_committed_entry_seq() + 10` into a copy of the ack file and assert the invariant checker reports a violation. This proves assertion 3 is not vacuous.

**Steps:**

- [ ] **B1.1** Write the two failing tests first (they fail to compile against the not-yet-existing lib; then fail on assertions once scaffolded).
- [ ] **B1.2** Implement lib + victim binary. The invariant checker must be a plain function `check_durable_acks(store: &SqliteReceiptStore, ack_path: &Path) -> Result<(), ChaosError>` so the checker-integrity test can call it directly.
- [ ] **B1.3** `cargo test -p chio-chaos` green on macOS; `cargo clippy -p chio-chaos -- -D warnings && cargo fmt --all -- --check`.
- [ ] **B1.4** Commit: `test(chaos): sigkill-mid-append crash recovery with durable-ack verification (F53)`

### Task B2: ENOSPC, wedged writer, retention under load

**Files:**
- Create: `bench/chio-chaos/tests/store_faults.rs`
- Modify (single product seam, keep minimal): `crates/platform/chio-store-sqlite/src/lib.rs` + `src/receipt_store.rs` so the store can be opened with a bounded page count (`PRAGMA max_page_count`) applied to every pool connection. Follow the existing options pattern (`SqliteStoreOptions`/`SqlitePoolConfig`); if `open()` has no options-taking sibling, add `open_with_options` and keep `open` delegating with defaults. The knob is a genuine ops bound (cap store growth), not test-only; document it as such.

**Tests (all in `store_faults.rs`):**
- `chaos_enospc_denies_typed_and_recovers`: open store with a small `max_page_count`; append until an append/flush returns an error. Assert: (a) the error is a typed `ReceiptStoreError` (stringify and assert it mentions full/disk, whatever SQLITE_FULL maps to; inspect the real variant first and assert on the variant, not the string, if exported), (b) subsequent appends keep failing closed (head poisoned per the store's contract in `src/receipt_store.rs` `commit_receipt_batch`), (c) reopening the same db with a larger `max_page_count` recovers: health OK, appends succeed, and no pre-fault DURABLE ack was lost (reuse `check_durable_acks`). InjectionNoOp: if no append ever failed, fail.
- `chaos_wedged_writer_yields_typed_busy_deny`: open a raw `rusqlite::Connection` on the same db path, `BEGIN IMMEDIATE`, hold it; assert store appends fail with a typed busy/timeout error within a bounded time (no silent success, no hang: wrap in a generous timeout); drop the wedge; assert appends recover.
- `chaos_retention_under_load_keeps_verified_head`: spawn a thread appending continuously; call `retention_repair(<archive_path>)` (and, if enabled in this store build, one background-checkpoint rotation) mid-load; join; assert health OK, `latest_committed_entry_seq` monotone vs before, fresh append works.

**Steps:**

- [ ] **B2.1** Failing tests first; run `cargo test -p chio-chaos --test store_faults` to see them fail.
- [ ] **B2.2** Implement the `max_page_count` option seam (smallest possible diff; every existing caller unaffected; new unit test in the store crate for the option: `bounded_page_count_yields_full_error` living where the store's own tests live).
- [ ] **B2.3** Green + `cargo clippy -p chio-store-sqlite -p chio-chaos -- -D warnings && cargo fmt --all -- --check && cargo test -p chio-store-sqlite`.
- [ ] **B2.4** Commit: `test(chaos): enospc, wedged-writer, and retention-under-load scenarios`

### Task B3: Kernel-path scenarios + nightly lane

**Files:**
- Create: `bench/chio-chaos/tests/kernel_faults.rs`
- Create: `bench/chio-chaos/tests/sigterm_drain.rs`
- Create: `.github/workflows/chio-chaos-nightly.yml`

**Tests:**
- `chaos_hung_tool_server_hits_deadline_and_denies`: boot `StackHarness` (from chio-loadgen) with `set_tool_latency_ms` far above the kernel's dispatch deadline (find the deadline knob in the kernel config; RFC-0001 landed hot-path deadlines; if there is genuinely no configurable deadline, STOP and report BLOCKED with what you found). Assert: dispatch returns a deny/timeout (typed, not a hang), and if the kernel emits a deny receipt for it, that receipt is persisted after flush. InjectionNoOp: dispatch succeeding normally fails the test.
- `chaos_blocking_guard_times_out_fail_closed`: register a guard that sleeps past the guard pipeline timeout (find the guard timeout knob; same BLOCKED rule). Assert typed fail-closed deny.
- `chaos_sigterm_drain_loses_no_durable_acks` (in `sigterm_drain.rs`): reuse the B1 victim; instead of SIGKILL send SIGTERM (`Command::new("kill")`); assert the victim exits within 30s with code 0, and `check_durable_acks` passes on reopen. (If the victim binary needs a SIGTERM handler to flush-and-exit cleanly, implement it in the victim with std-only means: a `signal-hook`-free approach is to let SIGTERM's default termination stand IF flush-per-append already guarantees the ack invariant; in that case the assertion is exit-by-signal + `check_durable_acks` passes; document which contract the victim provides.)
- Every test in this crate honors `CHIO_CHAOS_ITERATIONS` (default small).

**Workflow `.github/workflows/chio-chaos-nightly.yml`:** nightly cron + `workflow_dispatch`; ubuntu-latest; setup-rust stable; single step `cargo test -p chio-chaos --release -- --nocapture` with env `CHIO_CHAOS_ITERATIONS: "40"`; `timeout-minutes: 45`; pinned action SHAs, `permissions: contents: read`, concurrency group like the sustained lane.

**Steps:**

- [ ] **B3.1** Failing tests, then implement.
- [ ] **B3.2** Green locally with default iterations; spot-run once with `CHIO_CHAOS_ITERATIONS=15` to shake out flake; fix any nondeterminism found (seeds make rounds reproducible).
- [ ] **B3.3** `cargo clippy -p chio-chaos -- -D warnings && cargo fmt --all -- --check`.
- [ ] **B3.4** Commit: `test(chaos): deadline, guard-timeout, sigterm-drain scenarios and nightly lane`

---

## Milestone C: Loom lane (F52)

### Task C1: Make the three loom targets actually run

**Files:**
- Modify: whatever the three targets need to compile and pass (they have NEVER been executed):
  - `crates/kernel/chio-kernel/tests/loom_concurrency.rs` (742 lines, gated `#[cfg(any(loom, chio_kernel_loom))]`)
  - `crates/observability/chio-otel-receipt-exporter/tests/loom_ring_sender_vs_shutdown.rs` (178 lines, `#[cfg(loom)]`)
  - `crates/guards/chio-wasm-guards/tests/loom_instance_pre_reload_vs_checkout.rs` (119 lines, `#[cfg(loom)]`)
- Modify: root `Makefile` (add a `loom` target running all three commands below)

**Commands (one target per invocation, never package-wide):**
```bash
RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 cargo test --release -p chio-kernel --test loom_concurrency
RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 cargo test --release -p chio-otel-receipt-exporter --test loom_ring_sender_vs_shutdown
RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 cargo test --release -p chio-wasm-guards --test loom_instance_pre_reload_vs_checkout
```

**Rules:** fix compile drift and model bugs so all three pass; if a model reveals a REAL bug in shipped code, STOP and report BLOCKED with the interleaving trace (that is a product bug, not a test chore). Verify `--cfg loom` under `RUSTFLAGS` does not break the crates' normal dev-dependency builds (the `unexpected_cfgs` registration mentioned at root `Cargo.toml` line 233 should already cover it; if warnings appear, extend the check-cfg registration, do not silence with allow).

**Steps:**

- [ ] **C1.1** Run each command; record failures verbatim in your report.
- [ ] **C1.2** Fix until all three pass. Keep model semantics; do not weaken assertions to get green.
- [ ] **C1.3** Add the `loom` Makefile target; run `make loom` end to end once.
- [ ] **C1.4** Normal-cfg sanity: `cargo test -p chio-otel-receipt-exporter --test loom_ring_sender_vs_shutdown` (without RUSTFLAGS) still compiles-and-skips, and `cargo clippy -p chio-kernel -p chio-otel-receipt-exporter -p chio-wasm-guards -- -D warnings` is clean.
- [ ] **C1.5** Commit: `test(loom): make the three tcb interleaving models actually execute (F52)`

### Task C2: Port the kernel loom model toward real session-table types

**Files:**
- Modify: `crates/kernel/chio-kernel/tests/loom_concurrency.rs`
- Possibly modify: `crates/kernel/chio-kernel/src/` ONLY to add `#[cfg(any(loom, chio_kernel_loom))]` loom-instrumented sync aliases if the real session-table types are otherwise un-modelable. Product behavior under normal cfg must be byte-identical.

**Requirement:** the current file models a hand-built `ModelSession`; the lane must check shipped code. Port the highest-value invariant to the real types: **no interleaving admits a tool call after a session is marked terminal**. If a full port is infeasible without invasive kernel changes, port that invariant against the real state-machine type(s) and keep the remaining models as-is; state exactly what is real and what is modeled in a module-level doc comment (a reviewer reading only that comment must not overestimate coverage).

**Steps:**

- [ ] **C2.1** Read the kernel session table implementation (find it: `rg -n "session" crates/kernel/chio-kernel/src/ --files-with-matches | head`), identify the terminal-state admission check.
- [ ] **C2.2** Implement the ported model; run the C1 kernel loom command until green.
- [ ] **C2.3** `cargo clippy -p chio-kernel -- -D warnings && cargo fmt --all -- --check`; normal-cfg `cargo test -p chio-kernel --lib` still green.
- [ ] **C2.4** Commit: `test(loom): port kernel session-table model toward shipped types`

### Task C3: Loom nightly workflow

**Files:**
- Create: `.github/workflows/loom-nightly.yml`

**Content:** nightly cron + `workflow_dispatch`; matrix over the three C1 commands (one job leg per target, so a hang in one cannot mask the others); `timeout-minutes: 60` each; `RUSTFLAGS: "--cfg loom"`, `LOOM_MAX_PREEMPTIONS: "3"`; repo conventions (pinned SHAs, permissions, concurrency; copy from `sustained-p99-nightly.yml`).

**Steps:**

- [ ] **C3.1** Write the workflow; validate YAML (`python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/loom-nightly.yml'))"` or actionlint if available).
- [ ] **C3.2** Commit: `ci(loom): nightly interleaving lane for the three tcb models`

---

## Milestone D: Honest docs + final gate

### Task D1: Documentation delta + full workspace gate

**Files:**
- Modify: `docs/architecture/reliability/PLAN-load-soak-chaos-program.md` (status header only: add a line `- Implemented in part: 2026-07-15, see "Implementation delta" below` and a short delta section listing exactly what landed (F49 lane cutover, F53 harness scenarios without report regeneration, F52 lanes) and what remains (the out-of-scope list from this plan). No rewriting of the original analysis.)
- Modify: `docs/architecture/reliability/README.md` IF it indexes finding status (check first; keep the edit one-line-per-finding).
- Create: `bench/chio-loadgen/README.md` and `bench/chio-chaos/README.md` (short: what it boots, what it asserts, env knobs, how to run locally; follow the tone of `bench/ttfrh`'s README if present).

**Steps:**

- [ ] **D1.1** Docs edits above.
- [ ] **D1.2** Full gate: `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`. Also `make loom` (or the three loom commands) once more, and the B/C named tests with `CHIO_CHAOS_ITERATIONS=10`.
- [ ] **D1.3** `rg -n "\u2014" $(git diff --name-only main...HEAD)` returns nothing (no em dashes in anything we touched).
- [ ] **D1.4** Commit: `docs(reliability): record implemented fault-lane delta against the load-soak-chaos plan`

## Self-review checklist (run after writing, before dispatch)

1. Spec coverage: F49 -> A1-A3; F53 core -> B1-B3; F52 -> C1-C3; honesty boundary -> scope section + D1. Out-of-scope items are named, not silently dropped.
2. Placeholder scan: no TBD/TODO; every step names commands, files, and expected outcomes; interface blocks are complete Rust.
3. Type consistency: `StackHarness::boot/boot_smoke/dispatch_allow_once/flush_durable/set_tool_latency_ms/store` used identically in A1, A2, B3; `check_durable_acks` defined in B1, reused in B2/B3; `LoadgenError` variants referenced in A2/A3 match A1's definition.
