# Milestone 05: Real Async Kernel Migration (For Real This Time)

## Lens

Single lens: performance. Throughput, tail latency, and the structural concurrency
that makes both possible. This milestone is not about adding features. It is
about making the kernel call graph actually concurrent so a single Chio process
can hold more than one tool call in flight without serialising on a kernel-level
mutex.

## Why this is on the trajectory

The kernel sits in front of every tool call. Every capability validation, every
guard run, every receipt sign passes through `ChioKernel::evaluate_tool_call`.
If that path is single-threaded behind a process-wide lock, no amount of work in
the rest of the workspace produces user-visible throughput. Adapters and edges
queue. SIEM exports stall. Federation cosigning serialises. The only thing that
moves the throughput needle is widening the kernel itself.

Today the kernel is wide on the type signature and narrow in practice. The hot
path is sync. The session map is sync. The receipt log is sync. The runtime is
"async" only at the outer leaf of the API.

## Prior-art reckoning

Milestone v2.80 ("Core Decomposition and Async Kernel", phases 303-306) is
recorded as Complete in `.planning/ROADMAP.md` and listed in
`.planning/PROJECT.md`. The ledger reads cleanly. The code agrees with part of
the ledger and disagrees with another. We separate the two carefully:

What v2.80 actually shipped (credit where due):

- Phase 303 (chio-core crate decomposition) and phase 304 (mega-file module
  decomposition) did extract module trees and bring the file-size gate green
  for the structural seams roadmap had named. The decomposition half is real.
- Phase 305-01 wrapped runtime state behind interior mutability primitives:
  `sessions: RwLock<HashMap<SessionId, Session>>`, `Mutex<Box<dyn BudgetStore>>`
  and friends, atomic counters for checkpoint sequencing. This was a necessary
  precursor; it is preserved.
- Phase 305-02 flipped the public entrypoint to `async fn(&self, ...)` and kept
  a `*_blocking` shim for sync callers. The signature is correct.
- Phase 305-03 added a multi-thread tokio test that asserts two concurrent
  callers of one shared kernel do not deadlock.

What v2.80 did not ship, despite the ledger's tone:

- The body of `pub async fn evaluate_tool_call` at
  `crates/chio-kernel/src/kernel/mod.rs:1915` is one line. It calls
  `self.evaluate_tool_call_sync_with_session_roots` at line 2209. The sync
  method is the real implementation. The async keyword on the public API is a
  type-system claim, not a runtime claim.
- The kernel still holds 10 sync primitives (counted below). Two concurrent
  callers do not deadlock because the test is short and uncontended; under
  load every receipt-log append and every session lookup serialises through
  the same `std::sync::Mutex` / `std::sync::RwLock`.

This milestone is the concurrency half that did not actually land. We do not
redo phases 303 or 304. We exploit them.

## Hard counts (measured 2026-04-25)

Reproduce with the commands in parentheses. Update the date and numbers if you
re-run; do not silently let them drift.

- `crates/chio-kernel/src/lib.rs`: 393 lines, 0 `async fn`, 0 `&mut self`,
  0 `.await`. Re-export shim only. (`grep -c 'async fn' .../lib.rs`)
- `crates/chio-kernel/src/kernel/mod.rs`: 5800 lines. Hosts the `ChioKernel`
  struct definition and the `evaluate_tool_call*` family.
- Workspace-wide async coverage in the kernel crate: 3 `async fn` against 1133
  fn signatures (0.26 percent). 3 `.await` sites total. (`grep -rE
  '^\s*(pub\s+)?(async\s+)?fn\s+' crates/chio-kernel/src/ | wc -l` and
  `grep -rE '^\s*(pub\s+)?async\s+fn\s+' crates/chio-kernel/src/ | wc -l`.)
- `crates/chio-kernel/src/session.rs`: 1186 lines, 27 `&mut self` methods.
  Every state transition demands exclusive access to the session.
  (`grep -c '&mut self' .../session.rs`)
- `ChioKernel` struct sync primitives (search `crates/chio-kernel/src/kernel/mod.rs`
  starting at line 875): `Mutex<Box<dyn BudgetStore>>`,
  `Mutex<Box<dyn RevocationStore>>`, `RwLock<HashMap<SessionId, Session>>`,
  `Mutex<ReceiptLog>`, `Mutex<ChildReceiptLog>`,
  `Option<Mutex<Box<dyn ReceiptStore>>>`, `Mutex<Option<String>>`
  (`emergency_stop_reason`), `RwLock<HashMap<String, FederationPeer>>`
  (`federation_peers`), `Mutex<HashMap<String, DualSignedReceipt>>`
  (`federation_dual_receipts`), `Mutex<Option<String>>`
  (`federation_local_kernel_id`). All `std::sync`, none `tokio::sync`. Holding
  any of them across an `.await` is a runtime hazard; in practice nothing
  awaits inside them because nothing awaits anywhere.
- Mega-file inventory (LOC): `operator_report.rs` 1759, `budget_store.rs` 1711,
  `receipt_support.rs` 1494, `checkpoint.rs` 1481, `approval.rs` 1404,
  `session.rs` 1186. The 304 file-size gate (3000 lines) is green; these are
  not "mega" by that gate, but they are still the largest concurrency
  hotspots and bench attribution targets.
- Bench coverage (`find crates -path '*/benches/*.rs'`): exactly two files,
  `chio-core/benches/core_primitives.rs` and
  `chio-wasm-guards/benches/wasm_guard_perf.rs`. There is no kernel bench.

## Workspace dependency state

Pinned in `[workspace.dependencies]` of root `Cargo.toml` today:

- `tokio = { version = "1", features = ["full"] }`
- `criterion = "0.5"`

Not pinned anywhere; this milestone adds them and pins versions on the day work
opens (do not paste these values without re-checking crates.io for the
then-current latest patch):

- `dashmap = "6"`
- `arc-swap = "1"`
- `tower = { version = "0.5", features = ["util", "limit", "load-shed", "timeout"] }`
- `tower-layer = "0.3"`, `tower-service = "0.3"` (already used inside `chio-tower`)
- `loom = "0.7"` (dev-dependency, gated on `cfg(loom)`)
- `parking_lot = "0.12"` for any non-async hot path that survives the migration

`chio-tower` already exists as a per-crate at `crates/chio-tower/`. It currently
hosts HTTP-edge middleware (`tower = "0.5"`, `tower-layer = "0.3"`,
`tower-service = "0.3"`, `http = "1"`, `http-body = "1"`). The kernel
`tower::Service` impl lands here, not in a new crate. Pin `tower` at the
workspace root so all crates resolve the same minor version.

## Scope

1. Convert `ChioKernel::evaluate_tool_call` to a true async body. The current
   one-liner at `kernel/mod.rs:1915` becomes a real flow that awaits guard
   evaluation, store reads, receipt signing, and tool dispatch. Drop
   `evaluate_tool_call_sync_with_session_roots` as a public-facing path; keep a
   `*_blocking` shim only for the synchronous CLI test harnesses identified in
   305-02. Convert `dispatch_tool_call_with_cost` similarly.

2. Replace the 27 `&mut self` methods on `Session` with `&self` against
   interior mutability. The session map moves from `RwLock<HashMap<_, Session>>`
   to `DashMap<SessionId, Arc<SessionState>>`, where `SessionState` holds its
   transition machine behind a `tokio::sync::RwLock` and the per-request
   inflight registry behind lock-free counters (`AtomicU64`). Subscriptions
   and terminal registries become append-only structures keyed off the session
   `Arc`.

3. Drop `std::sync::Mutex` from the `ChioKernel` struct. Wrap the kernel with
   tower middleware in `chio-tower` for request shedding, per-tenant
   concurrency limits, timeouts, and tracing. The kernel itself is
   `Arc<ChioKernel>` and shared.

4. `chio-tower::KernelService` `tower::Service` impl shape:

   ```rust
   pub struct KernelService { kernel: Arc<ChioKernel> }

   impl Service<KernelRequest> for KernelService {
       type Response = KernelResponse;
       type Error = KernelError;
       type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
       fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
       fn call(&mut self, req: KernelRequest) -> Self::Future { ... }
   }
   ```

   `KernelRequest` is the existing `ToolCallRequest` carrier; `KernelResponse`
   wraps `Verdict` plus signed-receipt handle. Middleware composes in a fixed
   outer-to-inner order: `TraceLayer` (tracing span per request) ->
   `TimeoutLayer` (per-request deadline) -> `ConcurrencyLimitLayer` (per-tenant
   semaphore keyed by `tenant_id` derived from capability) -> `LoadShedLayer`
   (return `Overloaded` rather than queue under saturation) -> `AuthLayer`
   (capability presence and signature precheck; full validation stays inside
   the kernel) -> `KernelService`. Auth is a precheck only; the kernel remains
   the trust boundary for capability semantics. M03 properties guard the
   kernel-side validation.

5. Replace `Mutex<Box<dyn BudgetStore>>` with stores that own their own
   interior sync (the in-memory implementation moves to `DashMap` plus atomic
   counters; external implementations document their concurrency contract in
   their crate-level rustdoc).

6. Receipt log writes go through an mpsc channel into a single signing task.
   Producers do not wait on the lock; they wait on backpressure only when the
   queue is bounded and full. The channel is bounded; the bound is a config
   knob with a fail-closed default.

7. `loom` test suite for the session state machine and the inflight registry,
   gated on `cfg(loom)`. Models lifecycle transitions, parent/child request
   lineage, and the new `&self` interior mutability under arbitrary thread
   interleavings (see Loom phase below for the explicit list).

8. `criterion` bench suite covering 12 hot paths in
   `crates/chio-kernel/benches/`:

   1. capability signature verify (Ed25519, warm key cache)
   2. scope match (`ToolGrant::matches` against a typical agent grant)
   3. time-bound check (`now_secs` against issued/expires)
   4. revocation lookup (in-memory store, hit and miss interleaved 50/50)
   5. budget decrement (atomic path, single tenant)
   6. single-guard eval (a representative native guard)
   7. full guard pipeline (5 guards, the default deployment shape)
   8. receipt sign (Ed25519 over canonical JSON of a typical receipt)
   9. receipt append (in-memory log, post-channel)
   10. session lookup (DashMap path)
   11. dispatch happy path (validate -> guards -> dispatch -> sign)
   12. dispatch deny path (capability missing, fail-closed)

9. Per-crate criterion job in CI. Baseline is the merge-base commit of the PR
   against `main` (not last release, which drifts). Comparison uses
   `criterion-compare-action` (or equivalent) and is computed against the
   median of 100 samples, with confidence intervals on the diff. PRs that
   regress any tracked metric by more than 10 percent (lower bound of the 95
   percent CI) fail the gate. Flamegraphs and Criterion HTML reports are
   uploaded as CI artifacts on every PR run; retention is 30 days for
   intermediate runs, 365 days for merge commits to `main`.

## Targets (kernel-level p99 on 4-core, warm cache, in-memory stores)

- Capability validation: < 200 microseconds.
- Dispatch happy path (validate -> guard pipeline -> dispatch -> sign): < 2 ms.
- Receipt sign and append: < 500 microseconds.
- Sustained throughput: 5,000 req/s on 4 cores. Current measured baseline is
  ~600 req/s extrapolated from the existing `chio-core` and `chio-wasm-guards`
  benches through the sync kernel path; the new bench suite establishes the
  real number on day one before any refactor lands.

Track p50, p95, p99, and p99.9 separately. p50 alone hides tail-latency
regressions; the gate runs on p99.

## Test strategy

- `loom` for state-machine correctness under concurrency. Required to be green
  before benches are believed.
- `criterion` for steady-state numbers. Each hot path gets its own bench file
  so regressions point at a specific function.
- Property tests from M03 act as the safety net during the refactor. Bench
  numbers do not matter if `cargo test --workspace` is red.
- M04 replay-equivalence goldens act as a second safety net: receipt bytes
  must not change as a side effect of moving locks around.
- M02 fuzzing should run concurrently as a third net; the lock-free dispatch
  path is a new fuzz surface and benefits from coverage during the rewrite.

## Loom phase detail

Loom catches data races and ordering bugs under arbitrary thread interleavings.
It does not catch logic bugs, deadlocks that arise from real-time scheduling,
or bugs caused by async cancellation in `tokio` (loom does not model the
tokio runtime; it models `std::thread` and `std::sync` against a permutation
search).

Interleavings checked:

- Concurrent session create + lookup + terminal-mark on the same `SessionId`.
- Parent request signs receipt while child request is created and signs its
  own receipt. Asserts lineage edges always point at a written parent.
- Two evaluators race the same capability whose revocation is being inserted
  on a third thread. Asserts no allow-after-revoke.
- Receipt-channel producer races receipt-channel drain on the signing task,
  with bounded-queue backpressure.
- Inflight registry increment/decrement under spawn/cancel storms.

Runtime budget per CI run: 10 minutes wall clock on the reference 4-core
runner, with `LOOM_MAX_PREEMPTIONS=3`. Increase only with a documented reason;
loom search space explodes super-exponentially in preemptions.

## Risks

- Refactor-merge-conflict storms with parallel feature work landing in
  `kernel/mod.rs`. Mitigation: declare a freeze on `kernel/mod.rs` and
  `session.rs` for the duration of the milestone, or land the milestone in a
  series of small PRs that each preserve compile and tests.
- Downstream SDK breakage if public types acquire async. The public API is
  already `async fn`; the risk is internals leaking through `pub use`. Audit
  every `pub use` from `chio-kernel` and freeze signatures on day one.
- Tokio version conflict with existing crates. Workspace pins `tokio = "1"`
  with `features = ["full"]`. Verify after dependency additions that
  `cargo tree -p chio-kernel -d` shows a single tokio 1.x.
- Tail-latency regression hidden in p50. Gate explicitly on p99 (and ideally
  p99.9 advisory) per metric, not p50 or mean.
- Fuel-bench drift on macOS vs Linux runners. Criterion numbers are not
  portable across kernels (different schedulers, different syscall costs).
  Pin the bench gate to one runner OS (Linux) for the comparison; macOS runs
  for local dev only.
- Channel-backpressure misconfiguration. A receipt-log channel that is too
  small stalls the kernel; too large lets memory grow unbounded under load.
  Default must fail-closed (bounded, with metrics on queue depth).

## Cross-doc references

- M02 (`02-fuzzing-post-pr13.md`): fuzz harness should run continuously during
  this refactor as a net for the new lock-free paths.
- M03 (`03-capability-algebra-properties.md`): properties must remain green
  during every PR of this milestone. They are the correctness backstop.
- M04 (`04-deterministic-replay.md`): receipt-byte goldens must not change as
  a side effect of moving locks. M04 landing first is preferred; if M04 is
  in-flight, M05 owns coordination of any receipt schema reorderings that
  fall out of the lock-free path.
- M06 (`06-wasm-guard-platform.md`): the WASM guard runtime is a downstream
  consumer. The fuel and timeout APIs may need adjustments once guards are
  awaited concurrently rather than in single-threaded sequence.

## Dependencies

- Blocked by M03. The session state machine refactor and the store concurrency
  rewrite need a dense correctness net.
- Benefits from M01 (codegen) only insofar as downstream SDK callers of
  `evaluate_tool_call` remain stable. If M01 is mid-flight when this starts,
  freeze the public async signatures on day one and move on.
- Parallelisable with M04 but only cautiously, per cross-doc note above.

## Out of scope

- New tool-server protocols.
- Cross-process kernel sharding. Single-process concurrency only.
- Replacing `chio-policy` or guard implementations. Guards are awaited as-is;
  if a guard is sync today it stays sync, wrapped in `spawn_blocking` only
  when a bench shows it pinning a worker.
- Re-cutting the mega-files. The decomposition half of v2.80 stays as it is;
  this milestone touches functions, not module boundaries.

## Exit criteria

- `cargo test --workspace` green, including the new `loom` suite under
  `--cfg loom`.
- Bench suite present, wired into CI, with the 12 tracked metrics meeting the
  targets above on the reference 4-core Linux runner.
- `&mut self` count on `Session` and the kernel struct documented before and
  after in the milestone's audit doc. Target: zero `&mut self` on `Session`,
  zero `std::sync::Mutex` fields on `ChioKernel`.
- Flamegraph artifact present on the merge commit and linked from the audit
  doc, showing no single function above 8 percent CPU on the dispatch-allow
  bench.
- v2.80's Complete status updated in `.planning/ROADMAP.md` with a forward
  pointer to this milestone for the concurrency closure.

## Round-2 addenda

### Phase task breakdown, sizing, and first commits

This milestone is the longest in the trajectory. Total estimate: 32-42
engineering days for one focused engineer plus reviewer cycles. Phases run
sequentially because Phase 2 inverts ownership against Phase 1's surface and
Phase 3 deletes the sync surface Phase 1 dual-tracks.

**Phase 0 (Baselines and Freeze): S, 2 days.**

- P0.T1: Land bench scaffold with placeholder bodies for all 12 paths so the
  comparison gate is wired before any code moves. Numbers are noise on day one;
  the diff is what matters.
- P0.T2: Pin `dashmap`, `arc-swap`, `loom`, `parking_lot`, and `tower` features
  in root `Cargo.toml`. `cargo tree -p chio-kernel -d` must show single tokio.
- P0.T3: Open the audit doc at `.planning/audits/M05-async-kernel.md`. Record
  starting counts (1133 fns, 3 awaits, 27 `&mut self`, 10 sync primitives).
- P0.T4: Apply the freeze (see "Freeze window enforcement" below).

First commit of the milestone (Phase 0 first, ordering matters):
`chore(kernel): add M05 baseline bench scaffold and pin tower 0.5 deps`. Files:
`crates/chio-kernel/benches/dispatch_allow.rs` (and 11 siblings) as empty
criterion harnesses; `Cargo.toml` workspace dep adds; `.planning/audits/M05-async-kernel.md`.

**Phase 1 (Async surface, dual-track): L, 10-14 days.** Load-bearing phase.

- P1.T1: Extract `trait ToolEvaluator` from the sync body. The trait surfaces
  the four steps (capability validate, guard pipeline, dispatch, receipt sign)
  as `async fn` methods with default impls that delegate to the existing sync
  helpers wrapped in `tokio::task::block_in_place`. No behaviour change.
- P1.T2: Rename `evaluate_tool_call_sync_with_session_roots` to
  `evaluate_tool_call_sync_inner` and mark it `#[doc(hidden)]`. Public surface
  now routes through `ToolEvaluator`.
- P1.T3: Implement async bodies on `ToolEvaluator` for the in-memory store
  case. The receipt-sign path moves behind an `mpsc::Sender<SignRequest>` plus
  oneshot reply channel. Producers `.await` on send, not on a mutex.
- P1.T4: Same migration for `dispatch_tool_call_with_cost`.
- P1.T5: Mark `evaluate_tool_call_blocking` `#[deprecated(since = "x.y", note
  = "use evaluate_tool_call().await; gated under feature legacy-sync from
  next release")]` and add the `legacy-sync` feature flag (default-on for one
  release cycle, default-off thereafter).
- P1.T6: Update all in-tree callers to the async path. Audit `pub use` from
  `chio-kernel`; freeze the public re-export set.
- P1.T7: Add the dual-track regression test: same fixture in/out via async
  and sync paths, asserting byte-identical receipts (M04 goldens).

**Phase 1 first commit (load-bearing for the milestone):**
`feat(kernel): introduce ToolEvaluator trait splitting evaluate_tool_call into async-capable steps`.
Files: `crates/chio-kernel/src/kernel/evaluator.rs` (new),
`crates/chio-kernel/src/kernel/mod.rs` (add the trait impl, no body changes
yet), `crates/chio-kernel/src/lib.rs` (re-export trait). This commit is
deliberately mechanical so the diff reads cleanly; behaviour change lands in
P1.T3 under `feat(kernel): move receipt signing onto an mpsc-backed signing
task`.

**Phase 2 (Interior mutability): L, 8-10 days.**

- P2.T1: Migrate `Session` from 27 `&mut self` to 27 `&self` against an inner
  `tokio::sync::RwLock<SessionInner>` and `AtomicU64` counters. Land in
  one PR per logical group of methods (state transitions, inflight, terminal
  marking, subscriptions): four PRs.
- P2.T2: Migrate `sessions: RwLock<HashMap<_, Session>>` to
  `DashMap<SessionId, Arc<Session>>`. Update all lookup sites.
- P2.T3: Replace `Mutex<Box<dyn BudgetStore>>` (and `RevocationStore`,
  `ReceiptStore`) with `Arc<dyn Store>` plus per-store interior sync.
- P2.T4: Drop the remaining `std::sync::Mutex` fields on `ChioKernel`. Target:
  zero. `emergency_stop_reason` and `federation_local_kernel_id` become
  `ArcSwap<Option<String>>`.
- P2.T5: Add Loom suite under `cfg(loom)` covering all interleavings listed
  below.

**Phase 2 first commit:**
`refactor(kernel): convert Session state transitions to &self with tokio::sync::RwLock`.

**Phase 3 (Tower middleware and observability): M, 6-8 days.**

- P3.T1: Add `KernelService` (skeleton below) to `chio-tower`. Compose
  middleware in the documented outer-to-inner order.
- P3.T2: Add per-tenant `ConcurrencyLimitLayer` keyed by capability-derived
  `tenant_id` with bounded semaphore.
- P3.T3: Wire `LoadShedLayer` returning `Overloaded` (HTTP 503 at the edge).
- P3.T4: Bench gate flips from advisory to required on PR.

**Phase 3 first commit:**
`feat(tower): add KernelService and middleware stack for kernel dispatch`.

**Phase 4 (Cleanup and SDK breakage): S, 4-6 days.**

- P4.T1: Remove `legacy-sync` from default features. Public sync API now
  requires opt-in.
- P4.T2: Update SDK consumers (`chio-cli`, `chio-mcp-edge`, `chio-a2a-edge`)
  to async paths. Document migration in `docs/migrations/M05-async-kernel.md`.
- P4.T3: Flamegraph artifact and audit doc final pass.

**Phase 4 first commit:** `chore(kernel): remove legacy-sync default feature`.

### Migration tactic for `evaluate_tool_call`

Today (`kernel/mod.rs:1915`):

```rust
pub async fn evaluate_tool_call(&self, request: &ToolCallRequest)
    -> Result<ToolCallResponse, KernelError>
{
    self.evaluate_tool_call_sync_with_session_roots(request, None, None)
}
```

The body delegates to the sync method at `:2209`. The migration sequence:

1. **Extract pure trait (P1.T1)**: define `trait ToolEvaluator { async fn
   validate_capability; async fn run_guards; async fn dispatch; async fn
   sign_receipt; }` in `crates/chio-kernel/src/kernel/evaluator.rs`. Default
   bodies wrap the existing sync helpers in `block_in_place`. Compile and
   tests pass with zero behaviour change.
2. **Rename sync entrypoint (P1.T2)**: `_sync_with_session_roots` becomes
   `_sync_inner` and is `#[doc(hidden)]`. The public async fn still calls it.
3. **Async-native steps (P1.T3-T4)**: replace each default trait body in turn
   with a real async impl. Receipt signing leaves the lock-step path first
   because it is the throughput pinch.
4. **Dual-track period (one release cycle)**: both `evaluate_tool_call`
   (`async`) and `evaluate_tool_call_blocking` (sync, deprecated) ship.
   `legacy-sync` feature default-on.
5. **Sunset (P4.T1)**: `legacy-sync` default-off; sync path requires
   `--features legacy-sync`. One release later, delete it entirely.

Commit sequence inside Phase 1: T1 (mechanical), T3 (behaviour change for
signing), T4 (dispatch), T5 (deprecation marker), T6 (caller migration), T7
(byte-identity test). Each commit independently passes
`cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

### Bench paths and per-bench SLOs

Twelve criterion files live at `crates/chio-kernel/benches/`. Every file is a
single criterion benchmark group. SLO is per-iteration p99 on the reference
4-core Linux runner.

| File path | Bench | SLO p99 |
|-----------|-------|---------|
| `crates/chio-kernel/benches/cap_verify_ed25519.rs` | Ed25519 cap signature verify, warm cache | < 60 us |
| `crates/chio-kernel/benches/scope_match.rs` | `ToolGrant::matches` typical agent grant | < 5 us |
| `crates/chio-kernel/benches/time_bound.rs` | `now_secs` against issued/expires | < 1 us |
| `crates/chio-kernel/benches/revocation_lookup.rs` | In-memory store, 50/50 hit/miss | < 3 us |
| `crates/chio-kernel/benches/budget_decrement.rs` | Atomic path, single tenant | < 2 us |
| `crates/chio-kernel/benches/single_guard.rs` | One representative native guard | < 80 us |
| `crates/chio-kernel/benches/guard_pipeline_5.rs` | Five-guard default deployment | < 400 us |
| `crates/chio-kernel/benches/receipt_sign.rs` | Ed25519 over canonical JSON | < 200 us |
| `crates/chio-kernel/benches/receipt_append.rs` | In-memory log, post-channel | < 50 us |
| `crates/chio-kernel/benches/session_lookup.rs` | DashMap path | < 2 us |
| `crates/chio-kernel/benches/dispatch_allow.rs` | Validate -> guards -> dispatch -> sign | < 2 ms |
| `crates/chio-kernel/benches/dispatch_deny.rs` | Capability missing, fail-closed | < 250 us |

### Freeze window enforcement

Phase 1 needs a merge freeze on `crates/chio-kernel/src/kernel/mod.rs` and
`crates/chio-kernel/src/session.rs`. Enforcement (all three):

1. **Branch protection rule** on `main`: `crates/chio-kernel/src/kernel/mod.rs`
   and `crates/chio-kernel/src/session.rs` require review from the
   `@bb-connor` team for the duration of Phase 1. Configured via
   GitHub branch protection > "Require code owner reviews".
2. **CODEOWNERS gate**: append to `.github/CODEOWNERS`:
   ```
   crates/chio-kernel/src/kernel/mod.rs @bb-connor
   crates/chio-kernel/src/session.rs   @bb-connor
   ```
   Removed in P4.T3 once Phase 4 closes.
3. **Communication template** posted in `#chio-dev` and pinned for the freeze
   window:

   > M05 freeze window: kernel/mod.rs and session.rs are review-gated by
   > @bb-connor through DATE. If you have feature work touching these
   > files, rebase onto the M05 branch or coordinate in-thread. Bug fixes
   > land via cherry-pick after a green M05 phase merge. ETA: PHASE_1_END.

Out-of-band fixes for production-blocking bugs route through a tagged
`hotfix/` branch with a single-reviewer override documented in the audit doc.

### Loom interleaving list and budget

Each interleaving is one `#[cfg(loom)] #[test]` in
`crates/chio-kernel/tests/loom_concurrency.rs`. Per-test wall budget: 90 s on
the reference 4-core runner. Suite total: 10 minutes wall. Preemption budget:
`LOOM_MAX_PREEMPTIONS=3` workspace default.

1. `loom_session_create_lookup_terminal_same_id`: thread A creates session S,
   thread B looks up S, thread C marks S terminal. No allow-after-terminal.
2. `loom_parent_signs_receipt_while_child_spawns`: parent receipt write
   races child create+sign. Child lineage edge always points at a written
   parent.
3. `loom_revocation_race_eval`: two evaluators race the same capability while
   a third inserts revocation. Asserts no allow-after-revoke (post-insert).
4. `loom_receipt_channel_producer_drain`: bounded mpsc producer races signer
   drain. Backpressure observed when full; no message loss; no double-sign.
5. `loom_inflight_increment_decrement_storm`: spawn/cancel storm against the
   `AtomicU64` inflight registry. Counter returns to zero; no underflow.
6. `loom_dashmap_session_insert_remove_concurrent`: insert/remove same
   `SessionId` across two threads with a third lookup. Lookup observes one
   of {present, absent}, never torn.
7. `loom_emergency_stop_arcswap`: writer flips `emergency_stop_reason`,
   reader observes either old or new, never partial.
8. `loom_budget_atomic_decrement`: two threads decrement same tenant budget
   below floor. Exactly one observes "depleted"; budget never goes negative.

Increasing preemptions beyond 3 requires a documented justification in the
test docstring; the suite's wall budget grows super-exponentially.

### Tower service shape (skeleton)

Lives at `crates/chio-tower/src/kernel_service.rs`. Tower 0.5 features pinned
at workspace root: `tower = { version = "0.5", features = ["util", "limit",
"load-shed", "timeout", "trace"] }`.

```rust
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower::limit::ConcurrencyLimitLayer;
use tower::load_shed::LoadShedLayer;
use tower::timeout::TimeoutLayer;
use tower::trace::TraceLayer;

#[derive(Clone)]
pub struct KernelService {
    kernel: Arc<chio_kernel::ChioKernel>,
}

pub struct KernelRequest {
    pub call: chio_core_types::ToolCallRequest,
    pub tenant_id: chio_core_types::TenantId,
}

pub struct KernelResponse {
    pub verdict: chio_core_types::Verdict,
    pub receipt: chio_core_types::SignedReceiptHandle,
}

#[derive(Debug, thiserror::Error)]
pub enum KernelServiceError {
    #[error("kernel: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
    #[error("overloaded")]
    Overloaded,
    #[error("timeout")]
    Timeout,
}

impl Service<KernelRequest> for KernelService {
    type Response = KernelResponse;
    type Error = KernelServiceError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: KernelRequest) -> Self::Future {
        let kernel = Arc::clone(&self.kernel);
        Box::pin(async move {
            let resp = kernel.evaluate_tool_call(&req.call).await?;
            Ok(KernelResponse {
                verdict: resp.verdict,
                receipt: resp.receipt_handle,
            })
        })
    }
}

pub fn build_layered(
    kernel: Arc<chio_kernel::ChioKernel>,
    per_tenant_limit: usize,
    request_timeout: Duration,
) -> impl Service<KernelRequest, Response = KernelResponse, Error = KernelServiceError> + Clone {
    ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(request_timeout))
        .layer(ConcurrencyLimitLayer::new(per_tenant_limit))
        .layer(LoadShedLayer::new())
        .layer(crate::auth::AuthLayer::new())
        .service(KernelService { kernel })
}
```

`AuthLayer` is a precheck for capability presence and signature shape only.
The kernel remains the trust boundary for capability semantics; M03
properties guard the inner validation.

### SDK breakage analysis and deprecation timeline

Public types that gain async-only signatures (audit by `pub use` from
`crates/chio-kernel/src/lib.rs`):

- `ChioKernel::evaluate_tool_call` (already async, body becomes real async).
- `ChioKernel::dispatch_tool_call_with_cost` (becomes async).
- `Session` accessors that today take `&mut self` (27 methods, see
  `session.rs`). Become `&self` async.
- `BudgetStore`, `RevocationStore`, `ReceiptStore` traits (gain `async fn`
  per method; trait migrates to `#[async_trait]`).

Deprecation timeline:

- **Release N (M05 ships)**: async paths primary. `legacy-sync` feature
  default-on. `*_blocking` shims marked `#[deprecated]`. Migration guide at
  `docs/migrations/M05-async-kernel.md`.
- **Release N+1**: `legacy-sync` default-off. Consumers opt in explicitly via
  `--features legacy-sync`. CHANGELOG calls out the flip.
- **Release N+2**: `legacy-sync` deleted. `*_blocking` shims gone. Sync
  callers must adopt async or pin to N+1.

Downstream impact survey (run on Phase 1 day one): `chio-cli`,
`chio-mcp-edge`, `chio-mcp-adapter`, `chio-a2a-edge`, `chio-acp-edge`,
`chio-acp-proxy`, `chio-control-plane`, all four SDK crates under
`sdks/`. Each gets a tracking checkbox in the audit doc.

### Rollback plan for Phase 2

If Phase 2's interior-mutability work ships and breaks production, the
revert path:

1. **Detection**: any of (a) bench gate p99 regresses by > 10 percent on
   `dispatch_allow` for two consecutive merges, (b) Loom suite times out on
   any of the eight interleavings, (c) production receipt-byte hash divergence
   reported by an M04 replay job.
2. **Immediate revert**: `git revert -m 1 <merge_commit>` for the offending
   PR. Phase 2 commits are structured as one-PR-per-method-group precisely
   so revert is granular: state transitions, inflight, terminal, subscriptions
   each revert independently.
3. **`legacy-sync` re-enable**: if revert is not enough (downstream consumers
   already adopted the new shape), flip `legacy-sync = ["default"]` in the
   patch release and post a CHANGELOG advisory.
4. **Post-mortem template**: `docs/postmortems/M05-phase2-revert-TEMPLATE.md`
   pre-staged. Captures: which interleaving was missed, what bench would have
   caught it, what test gets added before the next attempt.
5. **Worst case**: revert the entire Phase 2 merge train back to the Phase 1
   tag. Phase 1 dual-track means the sync surface is intact and production
   keeps running on the old path while Phase 2 is rebuilt.

### New sub-tasks (NEW)

- (NEW) **P0.T5**: `cargo-mutants` baseline run on `crates/chio-kernel/src/kernel/`
  before any code moves. Mutation kill rate is recorded in the audit doc; the
  refactor must not regress it. Mutants surviving on the new lock-free paths
  become test targets in Phase 2.
- (NEW) **P3.T5**: `tokio-console` integration smoke test. Add a gated
  `tokio = { features = ["tracing"] }` build and one CI job that runs the
  dispatch-allow bench under `tokio-console` and asserts no task is starved
  (no `idle > 1s` events). Catches accidental `block_in_place` regressions
  that would otherwise hide behind passing benches.
- (NEW) **P4.T4**: Receipt-signer task crash-recovery test. Kill the signing
  task via `JoinHandle::abort` mid-flight and assert that producers fail
  closed within the channel-bounded deadline rather than hanging forever.
  This is a runtime hazard the loom suite cannot model (loom does not run
  the tokio scheduler), so it lives as a tokio integration test at
  `crates/chio-kernel/tests/signer_crash.rs`.

### Coordination with M06 (host-call boundary)

M06 Phase 1 replaces the three `Linker::func_wrap` registrations
(`crates/chio-wasm-guards/src/host.rs:110/159/221`) with `bindgen!`-generated
host wiring. Those host calls live inside the kernel's guard-pipeline async
surface that M05 widens. Two coordination requirements:

- M06 Phase 1 host-call signatures MUST be modeled as `async fn` from day one
  in the WIT-derived host trait, even if the in-process body is synchronous
  initially. M05's guard pipeline awaits these boundaries; a sync-only host
  trait would force a second migration.
- M05 Phase 1 (P1.T3) MUST NOT change the input/output payload shape of the
  guard host calls. M06 Phase 1's `bindgen!` migration depends on the current
  payload contract (`level: u32`, `msg: string`, `key: string -> option<string>`,
  `() -> u64`) staying byte-for-byte stable. The fuel and timeout APIs may
  shift; the host call shape must not.

If both milestones run in parallel, M06 Phase 1 blocks on M05's P1.T3
behaviour-change commit landing first, so the bindgen! work targets the new
async-native host trait directly.
