# PLAN-load-chaos: Load, soak, and chaos program: replace testing theater with real harnesses

- Status: Draft (proposed, wave-3 reliability program)
- Implemented in part: 2026-07-15, see "Implementation delta (2026-07-15)" below
- Date: 2026-07-04
- Extends: none
- Depends on: RFC-0004 (bounded-memory / ENOMEM analog), RFC-0006 (storage hot path)
- Closes findings: F49, F50, F51, F52, F53, F54, F55, F56 (see ./README.md and the readiness review)

## Summary

Chio ships an entire tier of green reliability signals that measure nothing about the
running system. The nightly "sustained p99" lane times a local `VecDeque<u64>` loop; the
required TTFRH gate computes percentiles of five hard-coded integers; the healthcare
capacity "harness" is linear arithmetic whose constants were chosen to land just inside
the SLO bounds and it runs in no workflow; the chaos and attack-simulation "coverage" is a
set of hand-committed, cryptographically signed JSON reports declaring `status: passed`
with no harness that ever injects the fault, and those signed reports are consumed as
resilience evidence by the transaction-passport verifier itself. This plan replaces the
theater with two real harness crates (`chio-loadgen`, `chio-chaos`), a `growth-probe`
cargo feature that lets soaks assert bounded maps rather than only RSS, real CI tiering for
loom and wasm-guards, baseline-persisted perf regression tracking beyond the kernel, and a
loadgen replay that regenerates the healthcare quota table from measured runs. Every gate
in this plan boots real production types (`ChioKernel`, `SqliteReceiptStore`, the OTel
exporter queue) and fails closed. This is the mechanism by which RFC-0001 through RFC-0013
acquire enforceable acceptance tests; each injection is mapped to the findings it exercises.

## Motivation

The readiness review reads Chio against "PostgreSQL and the OOM Killer": overload must fail
early, local, and graceful; the blast radius of a component dying mid-operation must be
known; internal accounting must be trustworthy or loudly broken; budgets must be
predictable; recovery must be durable. A test tier that is green while measuring a constant
is worse than an absent one, because it actively certifies the properties it does not check.

Blast radius, by finding:

- F49 / F56 (medium). A real sustained-load regression (exporter queue growth, session-table
  lock contention, store write-p99 collapse over 30 minutes) ships because the nightly
  `sustained p99` lane only times a `VecDeque` loop and the two companion benches in the
  same workflow run one un-measured iteration. Anyone reading `sustained-p99-nightly: green`
  as evidence of bounded kernel behavior is misled; the OOM-kill endgame from the article
  reaches production first observed as rising RSS on a months-running kernel.
- F50 (high, production path). The healthcare pilot is SLO-committed off `quota.md`, whose
  "5x = 125,000 receipts/day, p95 < 250 ms, tested headroom" traces to `base + (factor-1)*k`
  arithmetic, not to any replay against a Chio component. A real 2x-5x burst can blow the
  SLO or wedge with "tested headroom" on paper, and this sits next to a HITRUST package, so
  it is also an audit-integrity defect.
- F51 (medium). The product's flagship 60s time-to-first-receipt can regress arbitrarily
  while the required PR gate passes, because it evaluates constants that top out at 49.8s
  against a 66s budget and the container lane runs the identical synthetic binary.
- F52 (medium). Loom models exist for three TCB hot paths (kernel session table, exporter
  ring-vs-shutdown, wasm-guard pre-reload-vs-checkout) and no lane ever sets `--cfg loom`, so
  interleaving coverage is zero while a reviewer reasonably assumes model-checked concurrency.
- F53 (high, production path). The eight declared fault classes are never executed, yet
  signed `status: passed` chaos reports sit in the proof-room chain and are accepted by
  production passport validation on shape and signature alone. Two-sided: an actual crash can
  tear the WAL or lose a terminal receipt in the append-only audit log with unknown recovery
  (L5), and relying parties are told chaos experiments passed when no mechanism to run them
  exists (L3).
- F54 (medium, production path). The wasm sandbox trust boundary has one integration target
  PR-gated (`py_guard_integration`); escape, watchdog-rollback, reload-race, and blocklist
  enforcement are only checked post-merge by release qualification, so main can carry an
  undetected sandbox regression between merge and the next qualification.
- F55 (medium, production path). Perf regression tracking is nightly-only, kernel-only,
  HEAD-vs-HEAD^, 10% threshold, no persisted trend. A store/guard/adapter regression, or one
  in a non-tip commit of the day, is never compared against anything.

## Current behavior (verified 2026-07-04)

Signatures and constants below were re-read from live code; several line numbers in the
readiness review had drifted and are corrected here.

### The synthetic sustained lane (F49, F56)

`crates/kernel/chio-kernel/benches/sustained_p99_30min.rs` defines, despite its name and its
home in the kernel crate:

```rust
const QUEUE_CAPACITY: usize = 256;
const DROP_BURST: usize = QUEUE_CAPACITY + 32; // 288
const P99_WARN_MICROS: u128 = 50_000;

fn probe_kernel_store_exporter_stack(
    queue: &mut VecDeque<u64>,
    sequence: &mut u64,
    stats: &mut SustainedStats,
) { /* push/pop u64s, XOR/rotate drain; no kernel/store/exporter type constructed */ }
```

The file imports only `std::collections::VecDeque` and `std::time`. The loop sleeps 1ms per
iteration, so the 30-minute nightly (`CHIO_SUSTAINED_P99_SECONDS=1800`) is nearly all sleep.
The lane runs `cargo bench -p chio-kernel --features sustained-p99-nightly --bench
sustained_p99_30min -- --test --nocapture` (`.github/workflows/sustained-p99-nightly.yml`),
and its two "real component" companions run in Criterion smoke mode with no measurement:

```yaml
- run: cargo bench -p chio-store-sqlite --bench store_receipt_write_throughput -- --test
- run: cargo bench -p chio-wasm-guards --features wasmtime-runtime --bench guard_pool_checkout_p99 -- --test
```

The bench is gated by `required-features = ["sustained-p99-nightly"]`
(`crates/kernel/chio-kernel/Cargo.toml`), so it is excluded from every other lane and from
`bench-regression.yml`'s kernel enumeration (which skips required-features benches).

A real stack fixture already exists but is unused by this lane:
`crates/kernel/chio-kernel/benches/fixtures/dispatch_request_fixture.rs` exposes
`DispatchAllowFixture::new()` with `dispatch_allow_once(&self) -> bool`,
`receipt_append_once(&self) -> usize`, `budget_decrement_once(&self) -> bool`,
`revocation_lookup_once(&self) -> bool`, and `guard_pipeline_5_once(&self) -> bool`. It
builds a real `ChioKernel::new(make_config())` but uses an in-memory `ReceiptLog::new()`, not
the durable store.

### The synthetic TTFRH gate (F51)

`bench/ttfrh/src/lib.rs`:

```rust
pub struct RunnerPlan {
    pub template: TemplateRunner,
    pub command: &'static str,             // e.g. "npx create-chio-app ... && bun run build"
    pub advisory: bool,
    pub synthetic_samples_ms: &'static [u64],
}

pub fn run_plan(plan: &RunnerPlan, budget: Budget) -> RunnerReport {
    let mut samples = plan.synthetic_samples_ms.to_vec();
    samples.sort_unstable();
    // p50/p99 of the constants; plan.command is never executed
    ...
}
```

`plan.command` is an inert string; the only `std::process` import in the crate is
`use std::process::ExitCode` (`bench/ttfrh/src/main.rs`). The samples are constants
(`next_ai_sdk_receipts.rs`: `SAMPLES_MS = [42_100, 44_300, 45_900, 47_500, 49_800]`) whose
comment claims the container lane "overwrites these with live samples". The budget is
`DEFAULT_BUDGET_MS = 60_000` plus `DEFAULT_BUFFER_PCT = 10`, so `effective_ms() = 66_000`;
the largest shipped sample is 49.8s, so the gate can only fail if the constants are edited.
`.github/workflows/ttfrh.yml` runs the byte-identical binary in both the PR `in-process-bench`
job and the push-only `container-lane`
(`cargo run -p ttfrh-bench --release -- --all --p99-budget-ms 60000`). A release-assurance
meta-check certifies the hollow container:
`scripts/tests/ci-release-assurance.test.sh` -> `check_ttfrh_container_lane_is_not_echo_only`
greps for `docker run` and that exact cargo line.

### The arithmetic capacity harness (F50)

`bench/healthcare-pilot-capacity/src/runner.rs`:

```rust
fn sample_for_multiple(input: ReplayInput, multiple: ReplayMultiple) -> CapacitySample {
    let factor = multiple.factor();
    let p50_ms = input.base_latency_p50_ms + (factor - 1) * 6;
    let p95_ms = input.base_latency_p95_ms + (factor - 1) * 18;
    let p99_ms = input.base_latency_p99_ms + (factor - 1) * 55;
    let trust_ms = input.base_trust_convergence_ms + (factor - 1) * 12;
    let backpressure_ms = input.base_exporter_backpressure_ms + (factor - 1) * 30;
    CapacitySample {
        /* ... */
        within_bounded_profile: p95_ms <= 250 && p99_ms <= 1_000 && backpressure_ms <= 250,
    }
}
```

Baseline `healthcare_shadow_baseline()`: 25,000/day, p50 54, p95 176, p99 640, backpressure
20. At 5x this yields p95 = 248, p99 = 860, backpressure = 140, passing by construction with a
2ms p95 margin, and `default_shadow_profile_stays_within_bounds` asserts that tautology in the
per-PR workspace lane (`Cargo.toml` workspace member `bench/healthcare-pilot-capacity`). No
workflow references the crate. The claimed capture path is hollow:
`bench/healthcare-pilot-capacity/scripts/shadow-capture.sh` (74 lines) writes a static JSON
manifest describing an intended read-only tee (no `curl`, no metrics), and no code path
ingests a capture into `ReplayInput`. `docs/operator-runbook/quota.md` then states the formula
outputs as measured fact ("P2 replayed that baseline", "5x replay row stayed inside the P1 SLO
envelope", 125,000/day = "Maximum tested headroom") and calibrates P1 incident thresholds off
them.

### Signed but unexecuted chaos evidence (F53)

`ci-gates/runtime.toml` declares `runtime-attack-simulation` (10 docs) and `runtime-chaos`
(8 docs) pointing at `fixtures/proof-room/runtime-security/valid-side-effecting-call/`. The
xtask handlers `handle_attack_simulation` and `handle_chaos`
(`xtask/src/fixtures_runtime.rs`) do exactly two things: `run_runtime_validate_pairs`
(schema-validate the committed docs) and `run_runtime_cargo_tests`. Executed per PR by the
`chio-runtime.yml` matrix legs (`capability: [..., attack-simulation, chaos]`). A fixture such
as `chaos-run-receipt-log-unavailable.json` carries `status: "passed"`, `failure_injected:
"append-only receipt log cannot commit terminal status"`, real-looking digests, and an ed25519
`signature`, but no harness injects that fault. The transaction-passport verifier consumes it:
`crates/platform/chio-transaction-passport/src/runtime_security.rs` parses `chaos_reports` by
role and calls `validate_chaos_run_report`, which (in `.../runtime_security/artifacts.rs`)
checks schema id, non-empty fields, digest shape, the `is_supported_chaos_case` whitelist,
`status == "passed"`, trusted issuer, and signature. The eight whitelisted cases are
`revocation-oracle-unavailable`, `receipt-log-unavailable`, `policy-reload-during-dispatch`,
`duplicate-nonce-race`, `tool-restart-lost-lease-cache`, `registry-split-brain`,
`clock-skew-expiry-bypass`, `sandbox-profile-drift`. The build script embeds these bytes into
the `chio-cli` and `chio-proof-room` binaries, so never-executed "passed" evidence ships as
canonical proof-room content. The store's only crash-adjacent test,
`crates/platform/chio-store-sqlite/src/receipt_store/tests/bootstrap.rs`
(`sqlite_receipt_store_persists_across_reopen`), is a clean drop-and-reopen with no torn write.
`SqliteReceiptStore::open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError>` is the
constructor a real harness would use (`ReceiptStoreError` itself lives in `chio-kernel` and is
re-exported at that crate's root, not from `chio-store-sqlite`).

### Never-run loom, post-merge-only wasm-guards, shallow bench-regression (F52, F54, F55)

- `crates/kernel/chio-kernel/tests/loom_concurrency.rs` is gated
  `#![cfg_attr(not(any(loom, chio_kernel_loom)), allow(dead_code))]` on a hand-built
  `ModelSession`; `crates/observability/chio-otel-receipt-exporter/tests/loom_ring_sender_vs_shutdown.rs`
  is `#[cfg(loom)]` and does import the real `chio_otel_receipt_exporter::queue_core::BoundedDropOldestQueue`;
  `crates/guards/chio-wasm-guards/tests/loom_instance_pre_reload_vs_checkout.rs` is `#[cfg(loom)]`
  over a hand-built model. `loom = "0.7"` is a workspace dep. No file under `.github/`, `scripts/`,
  `xtask/`, or `Makefile` sets `--cfg loom`.
- `.github/workflows/ci.yml`: `cargo test --workspace --exclude chio-wasm-guards` (line 177),
  then `cargo test -p chio-wasm-guards --lib` (line 183); only `--test py_guard_integration`
  (line 194) is PR-gated. MSRV excludes the crate and runs `--lib` (lines 218, 220). Full
  integration runs only in `release-qualification.yml` (push-to-main and dispatch).
- `.github/workflows/bench-regression.yml` triggers on nightly cron and dispatch only; the
  baseline resolves to `HEAD^` on schedule; the bench list is parsed only from
  `crates/kernel/chio-kernel/Cargo.toml` (skipping required-features benches);
  `scripts/criterion-compare.sh --threshold-percent 10`; no artifact upload, so no trend
  history. `provider-conformance.yml` smoke-runs one adapter bench
  (`cargo bench -p chio-openai-adapter --features provider-adapter --bench verdict_latency -- --test`).
  The only allocation test, `crates/kernel/chio-kernel/benches/dispatch_allow_dhat.rs`, asserts
  512 blocks / 40_960 bytes for a single `dispatch_allow` call, not growth over time.

## Design

Two harness crates plus a probe feature, then real CI tiering. Harnesses live under `bench/`
alongside the existing `ttfrh` and `healthcare-pilot-capacity` workspace members, so they are
workspace members that build in CI but never enter product binaries.

### 1. `bench/chio-loadgen` (~1,400 LOC) - the real sustained-load harness

Boots the actual stack and drives `dispatch -> persist -> export` at a fixed arrival rate
against a configurable-latency tool stub, recording an end-to-end latency histogram, RSS, and
lock/queue accounting. This is the single object that replaces the F49 `VecDeque` lane, feeds
the F50 healthcare replay, drives the F51 TTFRH measurement, and provides the F56 soak.

```rust
/// Boot-time configuration for the load harness. All durations and rates are
/// explicit so a lane cannot silently widen its own budget.
#[derive(Debug, Clone)]
pub struct LoadgenConfig {
    /// Target sustained arrival rate (dispatch calls per second).
    pub arrival_rate_hz: u32,
    /// Wall-clock duration of the sustained phase.
    pub duration: std::time::Duration,
    /// Simulated per-call tool latency; models a slow downstream.
    pub tool_latency: std::time::Duration,
    /// Receipt-store backing. `Sqlite` is the real path; `Memory` is for local smoke only.
    pub store: StoreBacking,
    /// p99 end-to-end deadline (fail-closed gate).
    pub p99_budget: std::time::Duration,
    /// Maximum tolerated RSS growth from steady-state baseline to end of run.
    pub rss_growth_budget_bytes: u64,
}

#[derive(Debug, Clone)]
pub enum StoreBacking {
    Sqlite { path: std::path::PathBuf },
    Memory,
}

impl Default for LoadgenConfig {
    fn default() -> Self {
        Self {
            arrival_rate_hz: 200,
            duration: std::time::Duration::from_secs(30 * 60),
            tool_latency: std::time::Duration::from_millis(5),
            store: StoreBacking::Sqlite { path: std::path::PathBuf::from("target/loadgen/receipts.sqlite") },
            p99_budget: std::time::Duration::from_millis(50),
            rss_growth_budget_bytes: 64 * 1024 * 1024,
        }
    }
}

pub struct StackHarness {
    kernel: chio_kernel::ChioKernel,
    store: chio_store_sqlite::SqliteReceiptStore,
    // `queue_core::BoundedDropOldestQueue` is `pub` only under `#[cfg(loom)]`; the
    // public exporter surface that owns the bounded queue is the ingress. Queue
    // depth is read via `OtlpGrpcIngress::snapshot() -> OtlpExporterQueueSnapshot`.
    exporter: chio_otel_receipt_exporter::OtlpGrpcIngress,
    // owned tool stub, budget store, revocation store
}

impl StackHarness {
    /// Fail-closed boot: any component that will not initialize denies the run.
    pub fn boot(config: &LoadgenConfig) -> Result<Self, LoadgenError> {
        let store = match &config.store {
            StoreBacking::Sqlite { path } => chio_store_sqlite::SqliteReceiptStore::open(path)
                .map_err(LoadgenError::StoreOpen)?,
            // Local smoke runs use a separate `boot_smoke` entry point that permits
            // `Memory`; this gating entry point rejects it so a lane cannot quietly
            // lose the durable path.
            StoreBacking::Memory => return Err(LoadgenError::MemoryStoreRejectedInGate),
        };
        // build kernel + exporter queue + configurable-latency tool stub ...
        Ok(/* ... */)
    }

    /// Drive the sustained phase. Returns a report; never panics.
    pub fn run_sustained(&mut self, config: &LoadgenConfig) -> Result<LoadReport, LoadgenError> {
        // token-bucket pacer at arrival_rate_hz; per-call: dispatch -> append -> enqueue export
        // record histogram (hdr), sample RSS every 5s, record budget-lock wait via metrics
    }
}

#[derive(Debug, Clone)]
pub struct LoadReport {
    pub ttfrh: std::time::Duration,          // time to first receipt hitting the durable store
    pub p50: std::time::Duration,
    pub p99: std::time::Duration,
    pub rss_start_bytes: u64,
    pub rss_end_bytes: u64,
    pub receipt_store_lag_max: u64,          // exporter queue depth high-water
    pub budget_lock_wait_p99: std::time::Duration,
    pub bounded_map_sizes: Vec<(String, usize)>, // from growth-probe, if enabled
    pub within_budget: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadgenError {
    // `ReceiptStoreError` is defined in chio-kernel (receipt_store module) and
    // re-exported at the kernel crate root; chio-store-sqlite returns it but does
    // not re-export it.
    #[error("receipt store failed to open: {0}")]
    StoreOpen(chio_kernel::ReceiptStoreError),
    #[error("in-memory store is not permitted in a gating run")]
    MemoryStoreRejectedInGate,
    #[error("p99 {observed:?} exceeded budget {budget:?}")]
    P99Exceeded { observed: std::time::Duration, budget: std::time::Duration },
    #[error("RSS grew {grew} bytes over budget {budget}")]
    RssGrowthExceeded { grew: u64, budget: u64 },
    #[error("dispatch failed mid-run: {0}")]
    Dispatch(String),
}
```

The gate binary (`bench/chio-loadgen/src/bin/sustained.rs`) reads `CHIO_SUSTAINED_P99_SECONDS`
for duration, calls `boot` then `run_sustained`, and returns a non-zero `ExitCode` on
`P99Exceeded` or `RssGrowthExceeded`. No `unwrap`/`expect`; every fallible step is `?` or an
explicit `match` into a typed `LoadgenError`.

Two additional modes reuse the same `StackHarness`:

- `--mode ttfrh` (F51): shells `RunnerPlan.command` via `std::process::Command` (scaffold +
  install + build + first receipt round-trip) at least 5 times, timing wall-clock to first
  receipt, and writes samples to a JSON artifact. `bench/ttfrh` grows a `--samples-file <path>`
  input that, when present, overrides `synthetic_samples_ms`; the container lane fails closed
  if it ever falls back to synthetic. The PR in-process job is renamed `ttfrh-advisory-smoke`
  (not a timing gate); the required timing check becomes the reference-runner container lane
  consuming (and freshness-gating) the latest samples artifact.
- `--mode replay <capture.json>` (F50): populates `ReplayInput` from a captured or generated
  request stream and drives 1x/2x/5x measured runs, emitting `CapacityReport` from the actual
  histograms rather than `sample_for_multiple`. `run_capacity_profile` is retained only as a
  modeled projection and relabeled; `default_shadow_profile_stays_within_bounds` is inverted
  into a docs-lint that fails if `quota.md` still calls modeled rows "tested".

### 2. `growth-probe` cargo feature (~150 LOC across RFC-0004 crates) + soaks (F56)

RFC-0004 installs the `BoundedMap`/`Ring` abstraction with a live size metric. This plan adds
a test-only exact-count surface so a soak can assert the maps are bounded, not merely that RSS
looks flat. A shared trait in `chio-core-types`, gated behind `growth-probe`:

```rust
#[cfg(feature = "growth-probe")]
pub trait SizeProbe {
    /// Exact current element count of a long-lived collection.
    fn probe_len(&self) -> usize;
    /// Stable identifier used in soak assertions and reports.
    fn probe_label(&self) -> &'static str;
}
```

Each confirmed offender from RFC-0004 (kernel receipt mirrors, federation dual-receipt/DSSE
caches, velocity token-bucket maps, federation admission rate-limiter, per-tenant concurrency
table, per-session journal) implements `SizeProbe` under `#[cfg(feature = "growth-probe")]`,
forwarding to the RFC-0004 `BoundedMap::len()`. `chio-loadgen` enables the feature transitively
and exposes the collected `(label, len)` pairs in `LoadReport.bounded_map_sizes`.

Two soak tiers driven by the same harness:

- Nightly 30-minute soak (`soak-nightly.yml`): `run_sustained` for 30 minutes inside a
  `systemd-run --property=MemoryMax=...` cgroup, asserting p99 budget, RSS growth budget, and
  that every `probe_len()` stays at or below its RFC-0004 capacity policy.
- Weekly 8-hour soak (`soak-weekly.yml`): identical assertions over 8 hours; additionally
  asserts monotonic-flatness of each probe (no upward trend across the run window), which is
  the assertion RSS alone cannot make.

### 3. `bench/chio-chaos` (~1,800 LOC) - real fault injection and honest fixtures (F53)

A nightly harness that boots kernel + durable `SqliteReceiptStore` + revocation oracle + tool
server + federation relay stub, induces each fault for real, asserts the fixture's own
`expected_result`, and emits + signs a fresh `chaos-run` / `attack-simulation` report from the
actual run. The reliability-lens scenarios named by this program and the passport whitelist are
the same eight failure modes viewed two ways; the mapping is in the table below.

```rust
#[derive(Debug, Clone, Copy)]
pub enum ChaosScenario {
    KillMinusNineMidAppend,     // child SIGKILL between WAL write and commit
    SqliteEnospc,               // VFS shim returns SQLITE_FULL
    SigtermDrain,               // SIGTERM during sustained load
    RetentionDuringLoad,        // retention prune while appending
    HungToolServer,             // tool stub sleeps past the dispatch deadline
    BlockingGuard,              // guard stub blocks past the guard timeout
    WedgedWriter,               // hold the single writer connection
    RelayOutage,                // drop the federation relay
}

pub trait Injection {
    /// Induce the fault against a live stack; returns the observed outcome.
    fn inject(&self, stack: &mut StackHarness) -> Result<ChaosOutcome, ChaosError>;
    /// The proof-room case id this run regenerates, if any.
    fn passport_case_id(&self) -> Option<&'static str>;
}

#[derive(Debug, Clone)]
pub struct ChaosOutcome {
    pub failure_injected: String,
    pub expected_result_met: bool,   // e.g. signed incident receipt OR verifier marks totality failed
    pub deterministic_seed: [u8; 32],
    pub runtime_receipt_refs: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChaosError {
    #[error("stack boot failed: {0}")]
    Boot(#[from] LoadgenError),
    #[error("fault injection did not take effect: {0}")]
    InjectionNoOp(&'static str),
    #[error("post-fault invariant violated: {0}")]
    InvariantViolated(String),
    #[error("report signing failed: {0}")]
    Signing(String),
}
```

Report emission is fail-closed and canonical: the `RuntimeChaosRunReport` is serialized as
canonical JSON (RFC 8785) before signing, `runner_version_digest` is the SHA-256 of the runner
binary, `deterministic_seed_digest` is the SHA-256 of the run seed, and
`actual_verifier_report_digest` is computed from the real verifier output. The report is signed
only by a dedicated CI chaos-runner key (a distinct trust root), so a hand-committed report
signed by any other key fails the passport trusted-issuer check. The nightly writes fresh
fixtures under `fixtures/proof-room/runtime-security/valid-side-effecting-call/`; a PR-tier
freshness gate (below) then makes hand-committed reports unable to pass.

Digest-and-freshness gate. Add to `ci-gates/runtime.toml` a `regenerated_by` binding and a
`max_age_days` per chaos/attack facet, and extend the xtask handlers so `handle_chaos` /
`handle_attack_simulation` additionally: (a) require each fixture's issuer to be the chaos-runner
trust root, and (b) require `generated_at_unix_ms` within `max_age_days`. A committed report
older than the window, or signed by a developer key, fails the per-PR `chio-runtime.yml` matrix
leg. The schema gains one field (see below).

Injection-to-finding-and-RFC map:

| Scenario | Mechanism | Asserts (fail-closed) | Closes / exercises | Passport case regenerated |
|---|---|---|---|---|
| KillMinusNineMidAppend | child SIGKILL between WAL write and commit, then reopen | Merkle continuity; no torn/lost terminal receipt | F53; RFC-0005, RFC-0006 | `receipt-log-unavailable` |
| SqliteEnospc | VFS shim / loopback quota returns `SQLITE_FULL` | typed deny, bounded retry, RSS bounded | F53, F56; RFC-0004, RFC-0006 | `receipt-log-unavailable` (space variant) |
| SigtermDrain | SIGTERM during sustained load | exporter queue drained or bounded-drop accounted; no lost terminal receipt | RFC-0008, RFC-0009 | `tool-restart-lost-lease-cache` |
| RetentionDuringLoad | trigger retention while appending | no bricking; verified head stays consistent | RFC-0007 | `registry-split-brain` |
| HungToolServer | tool stub sleeps past deadline | dispatch deadline fires; deny receipt; budget unwound | RFC-0001, RFC-0002 | `revocation-oracle-unavailable` |
| BlockingGuard | guard stub blocks past timeout | guard timeout; fail-closed deny | RFC-0001 | `policy-reload-during-dispatch`, `sandbox-profile-drift` |
| WedgedWriter | hold the single writer connection | `busy_timeout` -> typed `SQLITE_BUSY` deny; no silent success | RFC-0006, F53 | `clock-skew-expiry-bypass` |
| RelayOutage | drop federation relay | federation fails closed; local ops continue; bounded retry | ADR-0014; RFC-0009 | `duplicate-nonce-race` |

Where a reliability scenario does not naturally produce a whitelisted case, the harness also
runs the dedicated passport-case producer directly (for example stalling the revocation oracle
for `revocation-oracle-unavailable`, hot-reloading policy mid-dispatch for
`policy-reload-during-dispatch`, mocked clock skew near expiry for
`clock-skew-expiry-bypass`, concurrent duplicate-nonce submission for `duplicate-nonce-race`),
so all eight whitelisted fixtures are regenerated from real runs.

### 4. Loom nightly (F52) and wasm-guards PR gate (F54)

- `loom-nightly.yml` (nightly cron): scope `--cfg loom` to ONLY the loom test target in each
  crate (never the whole package), so the crate's normal integration tests are not compiled
  under the loom cfg. `chio-otel-receipt-exporter` and `chio-wasm-guards` hide their normal
  exports behind `#[cfg(not(loom))]` (for example `chio-wasm-guards` exposes only
  `LOOM_MODEL_ONLY` under `loom`), so a package-wide `cargo test -p <crate>` under `--cfg loom`
  fails to compile the blocklist/reload tests. Run one target per invocation:
  `RUSTFLAGS="--cfg loom" cargo test --release -p chio-kernel --test loom_concurrency`,
  `RUSTFLAGS="--cfg loom" cargo test --release -p chio-otel-receipt-exporter --test loom_ring_sender_vs_shutdown`,
  and `RUSTFLAGS="--cfg loom" cargo test --release -p chio-wasm-guards --test loom_instance_pre_reload_vs_checkout`,
  each with `LOOM_MAX_PREEMPTIONS` bounded (start at 3). Separately, port `loom_concurrency.rs` from its hand-built
  `ModelSession` to the real session-table types (the exporter test already models the real
  `BoundedDropOldestQueue`), so the lane checks shipped code. Runtime budget 20-60 minutes;
  raise preemptions only as the models stabilize.
- Extend `ci.yml` with a PR job path-filtered on `crates/guards/chio-wasm-guards/**` and the
  kernel guard-pipeline glue, running `cargo test -p chio-wasm-guards --features wasmtime-runtime`
  (at minimum the `escape`, `watchdog_rollback`, `reload_race`, and `blocklist_enforcement`
  targets) on a wasm-capable runner. The existing `--exclude chio-wasm-guards` workspace step is
  unchanged; this is an additive gate so the sandbox boundary is checked before merge.

### 5. Baseline-persisted perf regression (F55)

Rework `bench-regression.yml`: persist Criterion baselines per main commit (artifact or
branch-keyed cache) and compare each nightly run against both `HEAD^` and a rolling pinned
baseline (7-day-old) to catch sub-threshold drift, keeping trend history as an uploaded
artifact. Extend the bench enumeration beyond `chio-kernel` to `chio-store-sqlite`
(`store_receipt_write_throughput`), `chio-wasm-guards` (`guard_pool_checkout_p99`), and the
adapter `verdict_latency` benches, running them in measured mode (drop `-- --test`) with the
10% threshold. The synthetic `sustained_p99_30min` bench is deleted; the nightly p99 signal
comes from `chio-loadgen`.

### Crate, LOC, and CI-tier summary

| Component | Location | Rough LOC | CI tier | Honest runtime |
|---|---|---|---|---|
| `chio-loadgen` | `bench/chio-loadgen` | ~1,400 | nightly (sustained p99) + reference-runner (TTFRH) | ~30 min sustained; ~10-20 min TTFRH x5 |
| `growth-probe` feature | `chio-core-types` + RFC-0004 crates | ~150 | enabled by soaks | n/a (compile-time) |
| 30-min soak | `soak-nightly.yml` | (harness) | nightly | ~35 min incl. build |
| 8-hour soak | `soak-weekly.yml` | (harness) | weekly | ~8.3 h |
| `chio-chaos` | `bench/chio-chaos` | ~1,800 | nightly (inject + regen) + PR (freshness gate) | ~20-40 min nightly; seconds PR |
| Loom lane | `loom-nightly.yml` | ~250 (model port) | nightly | ~20-60 min |
| Wasm-guards PR gate | `ci.yml` addition | ~40 (yaml) | PR (path-filtered) | ~10-15 min |
| Bench-regression rework | `bench-regression.yml` | ~120 (yaml + script) | nightly | ~45-60 min |
| Healthcare replay | `chio-loadgen --mode replay` | (harness) | nightly / on-demand | ~15 min |

## Wire, schema, and receipt impact

- `spec/schemas/.../chaos-run-report.schema.json` and `attack-simulation-report.schema.json`
  gain one required field, `generated_at_unix_ms` (integer), so the freshness gate has a
  provenance timestamp. Existing fields (`runner_version_digest`, `deterministic_seed_digest`,
  `actual_verifier_report_digest`, `runtime_receipt_refs`, `status`, `issuer`, `signature`)
  are unchanged in shape but become genuinely computed. All reports are signed over canonical
  JSON (RFC 8785); adding a field is a v1-compatible additive change guarded by schema id.
- `RuntimeChaosRunReport` / `RuntimeAttackSimulationReport` and their validators
  (`validate_chaos_run_report`, `validate_attack_simulation_report`) gain a
  `generated_at_unix_ms` field and a freshness check invoked from the ci-gate handler (not from
  production passport verification, which stays shape-plus-signature; freshness is a CI
  admission property, not a wire property).
- No change to `ChioReceipt`, receipt kinds, or the dispatch wire path. `chio-loadgen` and
  `chio-chaos` consume existing signed types; they add no new receipt kind.
- `ci-gates/runtime.toml` gains `max_age_days` and `regenerated_by` keys on the chaos and
  attack-simulation facets. `LoadgenConfig`, `LoadReport`, `ChaosScenario`, and `ChaosOutcome`
  are internal harness types, not wire types.

## Migration and compatibility

- Staged, additive, feature-flagged. `chio-loadgen` and `chio-chaos` land first as buildable
  workspace members with their gate binaries; the synthetic lanes keep running in parallel for
  one nightly cycle to compare signals.
- Cutover per lane: (1) `sustained-p99-nightly.yml` switches its step to the loadgen gate and
  the `sustained_p99_30min` bench + its `sustained-p99-nightly` feature are deleted; (2)
  `bench/ttfrh` grows `--samples-file`, the container lane becomes measured, and the PR job is
  renamed `ttfrh-advisory-smoke`; (3) `quota.md` rows are relabeled modeled projections until
  the loadgen replay artifact lands, then regenerated from it; (4) the chaos fixtures are
  regenerated by the runner and the freshness gate is enabled only after the first successful
  regeneration so the tree is never briefly red.
- The `growth-probe` feature is off by default and compiled only in soak lanes, so it adds no
  cost to product builds and cannot alter production behavior.
- Passport compatibility: production verification is unchanged; a relying party that accepted a
  prior fixture continues to, and the added `generated_at_unix_ms` is optional at the
  verifier and required only at the CI admission gate, so old bundles still validate while new
  fixtures carry provenance.

## Test and verification plan

- Unit. `chio-loadgen`: `StackHarness::boot` returns `LoadgenError::StoreOpen` on an
  unwritable path and `MemoryStoreRejectedInGate` for `StoreBacking::Memory`; the pacer holds
  arrival rate within tolerance. `chio-chaos`: each `Injection::inject` returns
  `InjectionNoOp` if the fault did not take effect (so a scenario that silently fails to inject
  cannot report `passed`).
- Property. TTFRH `--samples-file` parsing round-trips; canonical-JSON serialization of every
  chaos report is byte-stable across runs given a fixed seed (proves the digest gate is
  deterministic).
- Loom. The ported kernel session-table model, the exporter `BoundedDropOldestQueue`
  ring-vs-shutdown model, and the wasm-guard pre-reload-vs-checkout model run under `--cfg
  loom` nightly; the specific proof is that no interleaving admits a tool call after a session
  is marked terminal.
- Soak. `soak-nightly` (30 min) and `soak-weekly` (8 h) assert p99 budget, RSS growth budget,
  and per-collection `probe_len()` at or below RFC-0004 capacity; the named test is
  `loadgen_soak_bounded_maps` (weekly), which fails on any probe trending upward across the
  window. This is the direct acceptance test for RFC-0004.
- Chaos. The named test is `chaos_receipt_log_unavailable_preserves_merkle_head`
  (KillMinusNineMidAppend): kill the process between WAL write and commit, reopen, and assert
  Merkle continuity and a signed incident or verifier-failed totality. The full eight-scenario
  suite is the acceptance surface for RFC-0001, RFC-0002, RFC-0005, RFC-0006, RFC-0007,
  RFC-0008, and ADR-0014.
- Perf regression. `bench-regression` compares store/guard/adapter benches against a rolling
  baseline; the named guard is the `criterion-compare.sh` step failing when
  `store_receipt_write_throughput` regresses more than 10% vs the 7-day baseline.
- Freshness gate. `chio-runtime.yml` matrix legs fail when a chaos fixture is stale or signed
  by a non-runner key; the named test is `chaos_fixture_rejected_when_hand_committed`.

This plan is the load-chaos program that the readiness review's formal-methods and
reliability RFCs depend on for their acceptance evidence; each RFC references the specific
named test above.

## Acceptance criteria

- The nightly p99 lane boots `ChioKernel` + `SqliteReceiptStore` + the exporter queue and fails
  closed on `P99Exceeded` or `RssGrowthExceeded`; no `VecDeque`-only bench remains in tree, and
  `grep -R "probe_kernel_store_exporter_stack" crates/` returns nothing.
- The required TTFRH check evaluates measured wall-clock samples from `RunnerPlan.command` and
  fails closed if it falls back to synthetic; no lane can pass by editing constants.
- `quota.md`'s 2x/5x rows are regenerated from a measured `chio-loadgen --mode replay` artifact,
  or are explicitly labeled modeled projections with "Maximum tested headroom" removed until
  they are; `default_shadow_profile_stays_within_bounds` no longer asserts a tautology.
- All eight whitelisted chaos fixtures are produced by `chio-chaos` from real fault injection,
  signed by the CI runner key, and carry a fresh `generated_at_unix_ms`; a hand-committed or
  stale fixture fails the per-PR runtime gate.
- Loom runs nightly over the three models (with the kernel model ported to real types); the
  wasm-guards escape/watchdog/reload/blocklist targets run on every PR touching the crate.
- `bench-regression` compares store, guard, and adapter benches against a persisted rolling
  baseline and retains trend history.
- Every soak asserts bounded `probe_len()` for each RFC-0004 collection, not only RSS.
- No `unwrap`/`expect` in any harness code; every fallible path yields a typed
  `LoadgenError`/`ChaosError` and denies.

## Risks and alternatives

- Reference-runner dependency (TTFRH, container timing). Clean-machine timing is only
  meaningful on a dedicated 4-core runner, which shared PR runners cannot provide. Mitigation:
  the required timing check runs on the reference runner post-merge and is freshness-gated; the
  PR lane is explicitly advisory so it cannot be misread as a timing gate. Rejected: forcing a
  from-scratch container build on every PR (wasteful and still not clean-machine).
- Chaos flakiness. Real fault injection (SIGKILL races, `SQLITE_FULL` shims) is inherently
  noisier than schema validation. Mitigation: deterministic seeds, bounded retries with typed
  errors, and nightly (not PR) placement for the injection runs; only the fast
  freshness-and-signature gate runs per PR. Rejected: keeping the hand-committed fixtures
  (the F53 defect).
- Runtime cost. The 8-hour weekly soak and the loom sweep are expensive. Mitigation: weekly
  cadence, bounded `LOOM_MAX_PREEMPTIONS`, single-job concurrency with `cancel-in-progress:
  false`. Rejected: a synthetic proxy that is cheap and measures nothing (the status quo).
- Signing-key custody. The chaos-runner trust root must be CI-only; if a developer key could
  sign accepted fixtures the freshness gate is defeated. Mitigation: the runner key is a
  distinct trust root, held only in CI secrets, and the passport whitelist and CI gate both
  require it for chaos/attack roles.
- Throughput perturbation from probes. `growth-probe` is off by default and compiled only in
  soaks, so production and PR builds are unaffected; the exact-count path is not on the hot
  path.

## Rollout and sequencing

1. RFC-0004 lands the `BoundedMap`/`Ring` abstraction and live size metrics; this plan's
   `growth-probe` feature and the soak `probe_len()` assertions depend on it.
2. RFC-0006 lands the incremental verified head, background checkpoints, and single-writer
   discipline; `chio-chaos`'s KillMinusNineMidAppend, WedgedWriter, and SqliteEnospc scenarios
   assert its recovery and fail-closed properties.
3. Land `bench/chio-loadgen` (harness + sustained gate binary), cut over
   `sustained-p99-nightly.yml`, and delete the synthetic bench and its feature.
4. Land the TTFRH `--samples-file` path and rename the PR lane; land the healthcare replay
   mode and regenerate `quota.md`.
5. Land `bench/chio-chaos`, regenerate the eight fixtures, add the schema field, then enable
   the runtime freshness-and-key gate.
6. Land `loom-nightly.yml` and the wasm-guards PR gate; rework `bench-regression.yml`.

Steps 3 through 6 are independent of each other and can proceed in parallel once steps 1 and 2
are available; the chaos storage scenarios (step 5) are strongest after RFC-0006 (step 2) so
they assert the new recovery path rather than the legacy full-history rebuild.

## Implementation delta (2026-07-15)

This section records what has actually landed against the plan above. The
original analysis is unchanged; this is an append-only status note. It is
deliberately conservative: nothing here should be read as broader coverage than
the tests and lanes named.

### Landed

- F49 (sustained lane cutover). `bench/chio-loadgen` is a real harness:
  `StackHarness::boot` starts a live `ChioKernel` wired to a durable
  `SqliteReceiptStore` and a configurable-latency stub tool server, and
  `run_sustained` measures p50/p99 end-to-end latency and resident-set growth
  with a fail-closed budget gate (`P99Exceeded`, `RssGrowthExceeded`). The
  synthetic `sustained_p99_30min` bench and its `sustained-p99-nightly` cargo
  feature were deleted; `sustained-p99-nightly.yml` now runs the real gate binary
  (`cargo run -p chio-loadgen --release --bin sustained`). See
  `bench/chio-loadgen/README.md`.
- F53 (real in-tree fault injection, harness half). `bench/chio-chaos` injects
  seven of the eight named fault classes against the live stack and asserts a
  typed fail-closed deny plus recovery, each under the `InjectionNoOp`
  discipline: SIGKILL-mid-append crash recovery with durable-ack verification,
  SIGTERM-drain durable-ack preservation, ENOSPC (bounded `max_page_count`)
  typed disk-full deny, wedged-writer `SQLITE_BUSY` deny and reseed,
  retention-under-load head consistency, hung-tool-server dispatch-deadline deny,
  and blocking-guard guard-pipeline-timeout deny. New nightly lane
  `chio-chaos-nightly.yml`. The only product change was an optional
  `max_page_count` on the sqlite pool config (an ops growth bound). See
  `bench/chio-chaos/README.md`.
- F52 (loom execution). The three TCB loom models now actually execute under
  `--cfg loom` (`make loom`; the kernel is gated to compile under loom), and one
  model was ported to drive the real `chio_kernel::session::Session` (terminal-
  state admission invariant) rather than a hand-built stand-in. New nightly lane
  `loom-nightly.yml` matrixed over the targets (one job per target so a hang
  cannot mask the others). The store crate's `loom_receipt_writer` commit-actor
  accounting models run as a fourth matrixed target under their own
  `chio_store_sqlite_loom` cfg; the store's settlement-routing loom stand-in was
  replaced by a real concurrent SQLite race test
  (`chio-store-sqlite/tests/settle_attempts_races.rs`) because every SQL
  statement it modeled is already an atomic step, leaving loom nothing to
  falsify.

### Not done (remains as follow-up)

Named here so no reader overestimates coverage:

- Chaos report regeneration, signing, and freshness gates (the evidence-pipeline
  half of F53). The signed `chaos-run` / `attack-simulation` fixtures the
  transaction-passport verifier consumes are still hand-committed. This branch
  injects the faults for real in-tree but does not regenerate those signed
  fixtures from the runs, and the CI chaos-runner signing key and per-facet
  `max_age_days` / `regenerated_by` freshness gate are not wired.
- `growth-probe` / `SizeProbe` feature and the soaks (F56 beyond RSS and queue
  accounting), including the weekly 8-hour soak.
- `RelayOutage` chaos scenario (needs federation relay infrastructure); it is the
  eighth fault class and is not implemented.
- F50 (healthcare replay / `--mode replay` and `quota.md` regeneration), F51
  (TTFRH real wall-clock timing / `--samples-file`), F54 (wasm-guards PR gate),
  and F55 (baseline-persisted bench-regression rework).
- `exporter_queue_high_water` lands as `None`: the loadgen dispatch path does not
  traverse the OTLP ingress queue, so there is no live exporter queue to
  snapshot.
- The retention chaos scenario exercises reseed-under-load serialization, not the
  destructive prune/delete path (no orphan state is seeded).
- SIGKILL proves process-crash recovery, not power-loss durability (the OS page
  cache survives SIGKILL).
