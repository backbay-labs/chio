# RFC-0001: Hot-path deadlines and watchdogs

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0006 (monetary budget semantics), ADR-0013 (async receipt durability)
- Depends on: RFC-0002 (unconditional post-admission unwind)
- Closes findings: F01, F07, F14 (see ./README.md and the readiness review); implements deep-dive D1 (pre-dispatch readiness gate checks config presence, not writer liveness)

## Summary

Every await on the Chio mediation path is today unbounded: a guard doing blocking
I/O, a tool server that never answers, a wedged SQLite receipt-commit writer, or a
control-plane quorum sync that never returns can each suspend a request forever and,
in the guard and quorum cases, pin the worker thread that a request would need to
time itself out. This RFC adds three configurable wall-clock budgets to the runtime
`KernelConfig` (guard-pipeline budget with per-guard overrides, per-tool-server
dispatch budget, receipt-append budget), a `tokio::time::timeout` enforcement
strategy that runs the exact same fail-closed unwind path as request cancellation
(reverse monetary budget holds, apply RFC-0002's explicit reservation disposition,
emit a signed `Cancelled` receipt), a `spawn_blocking` treatment so a hung
synchronous guard can no longer pin
an async worker, and a wedged-writer watchdog that makes writer liveness (not just
config presence) a pre-dispatch gate. The posture stays fail-closed throughout:
budget expiry and writer unavailability deny, they never allow.

## Motivation

The Ubicloud "PostgreSQL and the OOM Killer" lens asks five things of an overload:
fail early, local, and graceful (not process death, not unbounded growth); know the
blast radius when a component dies mid-operation; keep internal accounting
trustworthy or loudly broken; keep budgets predictable; recover durably. The
mediation path fails all five under the following concrete triggers.

- **F01 (high): no timeout or watchdog on guard evaluation or tool dispatch.**
  Trigger: one guard doing blocking I/O (the stock `WebhookChannel` approval guard
  uses a synchronous `ureq` call with a 5s default at
  `crates/kernel/chio-kernel/src/approval_channels.rs:46,81`; custom guards are
  unbounded), or one tool server that never responds. Effect: `run_guards` is a
  synchronous sequential loop invoked inline inside the async evaluate future
  (`crates/kernel/chio-kernel/src/kernel/dispatch.rs:261`, called at
  `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs:345`),
  so a blocking guard pins a tokio worker thread that the host `TimeoutLayer`
  (`crates/protocol/chio-tower/src/kernel_service.rs:362`) cannot preempt, because
  the timeout future needs a free worker to be polled; N concurrent hung guards
  starve the pool. A hung dispatch parks its future forever
  (`dispatch_tool_call_with_cost_after_nonce_check`, dispatch.rs:448, awaits with no
  timeout wrapper at dispatch.rs:461-477) on any host without the tower stack (the
  mcp-edge stdio bridge at `crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs:164`
  has no timeout, and the sync bridge at
  `crates/kernel/chio-kernel/src/kernel/mod.rs:211` cannot be cancelled), retaining
  monetary budget holds (ADR-0006) and runtime-admission reservations indefinitely.
  Blast radius: whole-kernel degradation or stall for every agent and tenant the
  process mediates.

- **F07 (medium) plus D1: the receipt write lock is held across an unbounded append
  and an inline checkpoint.** `record_chio_receipt`
  (`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:164`) takes
  the kernel-wide `receipt_store_write_lock` (a `std::sync::Mutex<()>` at
  `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:147`) and, while holding it,
  calls a commit-actor append whose `result.recv()` has no timeout
  (`crates/platform/chio-store-sqlite/src/receipt_store.rs:192`) and, every
  `checkpoint_batch_size` receipts, `maybe_trigger_checkpoint_locked` with up to 8
  store-round-trip retry rounds still under the lock (receipt_persistence.rs:197-247).
  A wedged (alive but stuck) writer therefore stalls every subsequent tool call
  kernel-wide with no watchdog. D1 adds the deeper defect: the pre-dispatch readiness
  gate `ensure_receipt_persistence_ready`
  (`crates/kernel/chio-kernel/src/kernel/construction.rs:244`) checks
  `self.receipt_store.is_some() || self.config.allow_ephemeral_receipt_log` and
  nothing else, so a saturated queue or dead writer passes the gate, the tool
  dispatches and its side effect happens, and only the post-dispatch persistence
  fails, leaving an executed side effect with no receipt anywhere. Writer death is
  surfaced only as per-call errors; the health surface can stay green
  (`receipt_store_health` computes `healthy = status.healthy &&
  writer_counters().last_error.is_none()` at receipt_store.rs:626-631, and the
  `Disconnected` append path at receipt_store.rs:187-190 sets neither
  `last_error` nor `failed_total`), and its only consumer is a local CLI command
  (`crates/products/chio-cli/src/cli/trust/receipt/health.rs:60`) that opens its own
  store and cannot observe the serving kernel.

- **F14 (high): budget-write quorum waits are unbounded when a sync never returns.**
  `wait_for_budget_write_quorum_commit`
  (`crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs:672`) loops
  `check quorum -> spawn_blocking(sync_cluster_once).await -> check -> deadline check
  -> sleep 250ms`, but the deadline is evaluated only at deltas.rs:715, after the sync
  returns. If a blocking sync never returns (a dead peer holding a socket), the
  `.await` at deltas.rs:700 hangs forever with no `tokio::time::timeout` bounding it;
  the clamp(20 * sync_interval, 5s, 30s) budget at deltas.rs:663 is never consulted.
  This RFC closes the "no bounding deadline around the whole wait" half of F14; the
  quorum-observation redesign (decoupling waiting from syncing) is a control-plane
  follow-up tracked separately.

The common shape: an await with no ceiling, and in two cases a blocking body that
occupies the very thread that would enforce the ceiling.

## Current behavior (verified 2026-07-04)

Signatures below are quoted from current code.

Runtime `KernelConfig` (`kernel_struct.rs:10`) carries duration and batch knobs but
no mediation-path deadline. Relevant existing fields and defaults:

```rust
pub struct KernelConfig {
    // ...
    pub max_stream_duration_secs: u64,   // post-dispatch stream cap only
    pub max_stream_total_bytes: u64,
    pub allow_ephemeral_receipt_log: bool,
    pub checkpoint_batch_size: u64,      // DEFAULT_CHECKPOINT_BATCH_SIZE = 100
    pub retention_config: Option<crate::receipt_store::RetentionConfig>,
}
// kernel_struct.rs:119-123
pub const DEFAULT_MAX_STREAM_DURATION_SECS: u64 = 300;
pub const DEFAULT_CHECKPOINT_BATCH_SIZE: u64 = 100;
```

`max_stream_duration_secs` is applied only after dispatch returns
(`apply_stream_limits`, `finalization.rs:198`, reads the limit at finalization.rs:207),
so it reclassifies a completed-but-slow stream as `Incomplete`; it does not bound a
dispatch that never returns.

The guard pipeline is synchronous and inline:

```rust
// dispatch.rs:261
pub(crate) fn run_guards(
    &self,
    request: &ToolCallRequest,
    scope: &ChioScope,
    session_filesystem_roots: Option<&[String]>,
    matched_grant_index: Option<usize>,
) -> Result<Vec<chio_core::receipt::metadata::GuardEvidence>, GuardRunError>
```

Dispatch is awaited with no wrapper:

```rust
// dispatch.rs:448
pub(crate) async fn dispatch_tool_call_with_cost_after_nonce_check(
    &self,
    request: &ToolCallRequest,
    has_monetary_grant: bool,
) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError>
// awaits invoke_stream / invoke_with_cost / invoke at dispatch.rs:461-477
```

The unwind machinery this RFC reuses already exists. On the dispatch result, the
async core matches `KernelError::RequestCancelled { reason, .. }` and runs the unwind
inline (async_evaluation_core.rs:547-581):

```rust
// dispatch.rs:125
pub(crate) fn unwind_aborted_monetary_invocation(
    &self,
    request: &ToolCallRequest,
    cap: &CapabilityToken,
    charge_result: Option<&BudgetChargeResult>,
    payment_authorization: Option<&PaymentAuthorization>,
) -> Result<Option<BudgetReverseHoldDecision>, KernelError>

// dispatch.rs:393
pub(crate) fn release_runtime_admission_reservations(
    &self,
    metadata: Option<&serde_json::Value>,
) -> Result<(), KernelError>

// terminal_responses.rs:4  (signs a Decision::Cancelled receipt via
// record_chio_receipt_with_federation, returns Verdict::Deny + terminal Cancelled)
pub(crate) fn build_cancelled_response_with_metadata(
    &self,
    request: &ToolCallRequest,
    reason: &str,
    timestamp: u64,
    matched_grant_index: Option<usize>,
    extra_metadata: Option<serde_json::Value>,
) -> Result<ToolCallResponse, KernelError>
```

`PostAdmissionDropGuard` (`kernel_drop_guard.rs:19`) already converts a dropped
post-admission future into the same unwind plus `Cancelled` receipt; it is armed
before dispatch and disarmed after (async_evaluation_core.rs:513-529). One
correction against current code: the `RequestCancelled` arm reverses monetary
holds and signs the `Cancelled` receipt but never touches runtime-admission
reservations (`release_runtime_admission_reservations` is called only from the
`UrlElicitationsRequired` arm at async_evaluation_core.rs:539 and the
generic-error arm at :626). RFC-0002 does not consolidate the arms into a single
abort helper; it makes reservation disposition explicit and fail-closed instead:
release only on provably pre-side-effect paths
(`dispatch_error_precedes_tool_side_effect`, kernel_drop_guard.rs:109), and on
every ambiguous post-dispatch path retain the reservation and mark it in receipt
metadata via `mark_runtime_admission_reservations_retained_fail_closed`. This
RFC's dispatch-deadline expiry adopts that identical disposition.

The commit actor already has a bounded flush variant but not a bounded append:

```rust
// receipt_store.rs:210 (chio-store-sqlite)
fn flush_with_timeout(&self, timeout: Duration) -> Result<(), ReceiptStoreError>
// receipt_store.rs:161 (chio-store-sqlite): append() blocks on result.recv() at :192
```

`ReceiptWriterCounters` is already mirrored in the kernel crate
(`crates/kernel/chio-kernel/src/receipt_store.rs:41`) and the `ReceiptStore` trait is
at receipt_store.rs:187.

## Design

### 1. Config: `HotPathDeadlineConfig` on the runtime `KernelConfig`

Add one nested field to `KernelConfig` (`kernel_struct.rs`). Values are milliseconds;
`0` means "no deadline" (unbounded) for the opt-in guard and dispatch budgets so that
existing deployments are byte-for-byte unchanged until an operator sets one. The
receipt-append budget is not permitted to be `0`: an unbounded wedged-writer stall is
never a valid posture, so a `0` (or below-floor) value is rejected at load time,
consistent with the fail-closed "invalid config rejects at load" house rule.

```rust
use std::collections::BTreeMap; // BTreeMap keeps canonical-JSON key order deterministic

/// Wall-clock budgets for the mediation hot path. See RFC-0001.
#[derive(Debug, Clone)]
pub struct HotPathDeadlineConfig {
    /// Budget for the whole guard pipeline, enforced around `run_guards`.
    /// `0` disables. Default: `0` (opt-in, preserves current inline behavior).
    pub guard_pipeline_budget_ms: u64,
    /// Per-guard overrides keyed by `Guard::name()`. A named guard is enforced
    /// against its own budget instead of the pipeline budget; `0` disables the
    /// override for that guard. Presence of any entry forces per-guard offload.
    pub per_guard_budget_ms: BTreeMap<String, u64>,
    /// When true, offload the guard pipeline to `spawn_blocking` even with no
    /// budget set, so a blocking guard never pins an async worker. Default false.
    pub always_offload_guards: bool,
    /// Default per-dispatch budget, enforced around
    /// `dispatch_tool_call_with_cost_after_nonce_check`. `0` disables. Default 0.
    pub dispatch_budget_ms: u64,
    /// Per-tool-server dispatch overrides keyed by `ServerId` string.
    pub per_server_dispatch_budget_ms: BTreeMap<String, u64>,
    /// Watchdog bound on one receipt-append round trip through the commit actor.
    /// Must be >= `MIN_RECEIPT_APPEND_BUDGET_MS`. Default 5000 (5s).
    pub receipt_append_budget_ms: u64,
    /// Watchdog poll cadence and staleness threshold for the commit-writer
    /// liveness probe. Defaults: 1000 ms poll, 10000 ms stall threshold.
    pub receipt_writer_poll_ms: u64,
    pub receipt_writer_stall_ms: u64,
}

pub const DEFAULT_RECEIPT_APPEND_BUDGET_MS: u64 = 5_000;
pub const MIN_RECEIPT_APPEND_BUDGET_MS: u64 = 250;
pub const DEFAULT_RECEIPT_WRITER_POLL_MS: u64 = 1_000;
pub const DEFAULT_RECEIPT_WRITER_STALL_MS: u64 = 10_000;

impl Default for HotPathDeadlineConfig {
    fn default() -> Self {
        Self {
            guard_pipeline_budget_ms: 0,
            per_guard_budget_ms: BTreeMap::new(),
            always_offload_guards: false,
            dispatch_budget_ms: 0,
            per_server_dispatch_budget_ms: BTreeMap::new(),
            receipt_append_budget_ms: DEFAULT_RECEIPT_APPEND_BUDGET_MS,
            receipt_writer_poll_ms: DEFAULT_RECEIPT_WRITER_POLL_MS,
            receipt_writer_stall_ms: DEFAULT_RECEIPT_WRITER_STALL_MS,
        }
    }
}

impl HotPathDeadlineConfig {
    /// Fail-closed load-time validation. Called from `ChioKernel::try_new`
    /// (new in this RFC) and mirrored in chio-config's `validate_kernel`.
    pub fn validate(&self) -> Result<(), KernelBuildError> {
        if self.receipt_append_budget_ms < MIN_RECEIPT_APPEND_BUDGET_MS {
            return Err(KernelBuildError::InvalidDeadlineConfig(format!(
                "receipt_append_budget_ms must be >= {MIN_RECEIPT_APPEND_BUDGET_MS}"
            )));
        }
        if self.receipt_writer_poll_ms == 0 || self.receipt_writer_stall_ms == 0 {
            return Err(KernelBuildError::InvalidDeadlineConfig(
                "receipt writer poll and stall thresholds must be non-zero".to_string(),
            ));
        }
        Ok(())
    }

    fn ms_to_budget(ms: u64) -> Option<Duration> {
        match ms {
            0 => None,
            v => Some(Duration::from_millis(v)),
        }
    }

    pub fn guard_pipeline_budget(&self) -> Option<Duration> {
        Self::ms_to_budget(self.guard_pipeline_budget_ms)
    }

    pub fn guard_budget_for(&self, name: &str) -> Option<Duration> {
        match self.per_guard_budget_ms.get(name) {
            Some(ms) => Self::ms_to_budget(*ms),
            None => self.guard_pipeline_budget(),
        }
    }

    pub fn dispatch_budget_for(&self, server_id: &str) -> Option<Duration> {
        match self.per_server_dispatch_budget_ms.get(server_id) {
            Some(ms) => Self::ms_to_budget(*ms),
            None => Self::ms_to_budget(self.dispatch_budget_ms),
        }
    }

    /// Effective append bound. Clamped to the floor as defense in depth so a
    /// host that constructs `KernelConfig` without running validation still
    /// never gets an unbounded (or below-floor) append.
    pub fn receipt_append_budget(&self) -> Duration {
        Duration::from_millis(self.receipt_append_budget_ms.max(MIN_RECEIPT_APPEND_BUDGET_MS))
    }
}
```

(`ServerId` is `pub type ServerId = String` at
`crates/kernel/chio-kernel/src/kernel/mod.rs:39`, so `&request.server_id`
coerces to the `&str` key.)

Add `pub deadlines: HotPathDeadlineConfig` to `KernelConfig`. There is no
`KernelConfig` builder or `Default` today; hosts fill the struct exhaustively
(for example `crates/protocol/chio-mcp-edge/src/runtime/execution_nonce_tests.rs:42`
and `crates/kernel/chio-runtime-harness/src/kernel.rs:320`), so adding the field
is a mechanical, compiler-guided migration: each site sets
`deadlines: HotPathDeadlineConfig::default()`. The runtime `KernelConfig` is a
construction input, not a wire payload (it holds a `Keypair`), so this addition
changes no signed or transmitted bytes.

Where validation runs, precisely: `ChioKernel::new(config: KernelConfig) -> Self`
(construction.rs:133) is infallible today, and no `KernelBuildError` type exists
yet; both the error type and a fallible entrypoint are introduced by this RFC.
Enforcement is layered, fail-closed at each layer:

- File path: chio-config already runs post-deserialization validation
  (`validate`, `crates/platform/chio-config/src/validation.rs:12`, rejecting
  with `ConfigError::Validation`); the new `[deadlines]` keys are checked in its
  existing `validate_kernel` pass, so an invalid config file rejects at load,
  per the "invalid policies reject at load time" house rule.
- Programmatic path: a new `ChioKernel::try_new(config: KernelConfig) ->
  Result<Self, KernelBuildError>` runs `HotPathDeadlineConfig::validate()` before
  construction and is the documented entrypoint for hosts that set deadlines;
  `KernelBuildError` is a small new error enum in construction.rs with the
  `InvalidDeadlineConfig(String)` variant. `ChioKernel::new` keeps its infallible
  signature for existing callers.
- Defense in depth: because `new` cannot reject, the kernel reads the append
  bound only through `receipt_append_budget()`, which clamps to the floor, so
  even a host that bypasses `try_new` can never run an unbounded append.

### 2. Error taxonomy (typed, fail-closed)

Add to `KernelError` (`kernel/error.rs`):

```rust
/// A mediation-path stage exceeded its configured wall-clock budget. The
/// invocation is aborted fail-closed through the shared unwind path (RFC-0002):
/// budget holds and runtime-admission reservations are released and a signed
/// `Cancelled` receipt is emitted. Never yields Allow.
#[error("hot-path deadline exceeded at {stage}: budget {budget_ms}ms")]
HotPathDeadlineExceeded { stage: HotPathStage, budget_ms: u64 },

/// The receipt commit writer is wedged, saturated, or dead, as reported by the
/// receipt-writer watchdog. Enforced at the pre-dispatch readiness gate so no
/// tool side effect occurs while receipts cannot be durably persisted.
#[error("receipt commit writer unavailable: {0}")]
ReceiptWriterUnavailable(String),
```

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HotPathStage {
    GuardPipeline,
    Dispatch,
    ReceiptAppend,
}

impl std::fmt::Display for HotPathStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::GuardPipeline => "guard_pipeline",
            Self::Dispatch => "dispatch",
            Self::ReceiptAppend => "receipt_append",
        };
        f.write_str(s)
    }
}
```

Both variants get a `report()` arm (`error.rs:216`) with a `CHIO-KERNEL-HOT-PATH-DEADLINE`
/ `CHIO-KERNEL-RECEIPT-WRITER-UNAVAILABLE` code and a fail-closed suggested fix
(raise the budget or repair the writer; do not retry blindly). The append-level bound
reuses the existing `ReceiptStoreError::Timeout { operation, timeout_ms }` which
already `#[from]`-converts into `KernelError::ReceiptPersistence` (error.rs:156-157),
so no new conversion is needed there.

### 3. Guard pipeline: `spawn_blocking` plus per-guard/pipeline deadline

`run_guards` stays as the synchronous core. A new async wrapper decides how to run it.
Because `spawn_blocking` requires a `'static` closure, and `Guard: Send + Sync`
(mod.rs:337), `ToolCallRequest: Clone` (runtime.rs:41), and `ChioScope: Clone`
(scope.rs:10) all hold, we change `guards: Vec<Box<dyn Guard>>` to
`guards: Arc<Vec<Arc<dyn Guard>>>` on `ChioKernel` so a single guard can be moved into
a blocking task by cloning its `Arc`, and we build an owned invocation once:

```rust
struct OwnedGuardInvocation {
    request: ToolCallRequest,
    scope: ChioScope,
    session_filesystem_roots: Option<Vec<String>>,
    matched_grant_index: Option<usize>,
}
```

```rust
pub(crate) async fn run_guards_within_budget(
    &self,
    request: &ToolCallRequest,
    scope: &ChioScope,
    session_filesystem_roots: Option<&[String]>,
    matched_grant_index: Option<usize>,
) -> Result<Vec<chio_core::receipt::metadata::GuardEvidence>, GuardRunError> {
    let has_per_guard = !self.config.deadlines.per_guard_budget_ms.is_empty();
    let pipeline_budget = self.config.deadlines.guard_pipeline_budget();
    let want_offload =
        pipeline_budget.is_some() || has_per_guard || self.config.deadlines.always_offload_guards;

    // No budget, no offload requested, or no tokio runtime present: keep the
    // current inline behavior. `spawn_blocking` needs a runtime, so the
    // no-runtime sync-bridge test path (mod.rs:227) always falls through here.
    if !want_offload || tokio::runtime::Handle::try_current().is_err() {
        return self.run_guards(request, scope, session_filesystem_roots, matched_grant_index);
    }

    let owned = Arc::new(OwnedGuardInvocation {
        request: request.clone(),
        scope: scope.clone(),
        session_filesystem_roots: session_filesystem_roots.map(<[String]>::to_vec),
        matched_grant_index,
    });

    if has_per_guard {
        // Enforce each guard against its effective budget, so one wedged guard is
        // bounded to its own budget while the rest still run. One blocking handoff
        // per guard; used only when operators opt into per-guard budgets.
        return self.run_guards_per_guard_offloaded(&owned).await;
    }

    // Single pipeline offload: one blocking handoff, one timeout.
    let guards = Arc::clone(&self.guards);
    let owned_for_task = Arc::clone(&owned);
    let join = tokio::task::spawn_blocking(move || run_guards_owned(&guards, &owned_for_task));
    match pipeline_budget {
        Some(budget) => match tokio::time::timeout(budget, join).await {
            Ok(Ok(result)) => result,
            Ok(Err(join_err)) => Err(GuardRunError::new(
                KernelError::Internal(format!("guard task join failed: {join_err}")),
                Vec::new(),
            )),
            Err(_elapsed) => Err(GuardRunError::new(
                KernelError::HotPathDeadlineExceeded {
                    stage: HotPathStage::GuardPipeline,
                    budget_ms: budget.as_millis().min(u128::from(u64::MAX)) as u64,
                },
                Vec::new(),
            )),
        },
        None => match join.await {
            Ok(result) => result,
            Err(join_err) => Err(GuardRunError::new(
                KernelError::Internal(format!("guard task join failed: {join_err}")),
                Vec::new(),
            )),
        },
    }
}
```

`run_guards_owned(&[Arc<dyn Guard>], &OwnedGuardInvocation)` rebuilds a `GuardContext`
from the owned fields and runs the identical sequential fail-closed loop
(dispatch.rs:277-322). `run_guards_per_guard_offloaded` iterates the guards, and for
each one clones its `Arc`, spawns a single-guard `spawn_blocking`, and wraps it in
`tokio::time::timeout(self.config.deadlines.guard_budget_for(guard.name()), ..)`,
accumulating evidence and short-circuiting fail-closed on the first deny, error, join
failure, or elapse (elapse maps to `HotPathStage::GuardPipeline`).

The elapse semantics are honest about Rust: `tokio::time::timeout` drops the
`JoinHandle` on expiry, which detaches (does not kill) the blocking thread. A runaway
synchronous guard therefore runs to completion on the blocking pool, its result
discarded, while the async worker is freed and the request fails fast. This is the
article's "fail early, local, graceful": the damage is contained in the blocking pool
instead of starving the async worker pool.

The async core changes one call site (async_evaluation_core.rs:345) from `run_guards`
to `self.run_guards_within_budget(...).await`; the deny/reverse handling below it is
unchanged. `nested_flow_evaluation.rs` gets the same swap. `run_guards` itself is
retained (it is the inline path and the blocking-closure core).

### 4. Tool dispatch: `tokio::time::timeout` with per-server budget

Wrap the dispatch call in async_evaluation_core.rs and nested_flow_evaluation.rs:

```rust
async fn dispatch_within_budget(
    &self,
    request: &ToolCallRequest,
    has_monetary: bool,
) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
    let call = self.dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary);
    match self.config.deadlines.dispatch_budget_for(&request.server_id) {
        None => call.await,
        // `tokio::time::timeout` needs a timer driver. On the no-runtime
        // `futures::executor::block_on` fallback (mod.rs:232) there is none, so
        // wrapping the call in a timeout would panic rather than degrade. Probe
        // for a runtime exactly like `run_guards_within_budget` does (section 3)
        // and run the dispatch inline when absent, so the no-runtime path is a
        // defined, fail-closed inline dispatch (bounded only by the sync caller)
        // rather than a panic. This is the runtime probe section 5 promises.
        Some(_) if tokio::runtime::Handle::try_current().is_err() => call.await,
        Some(budget) => match tokio::time::timeout(budget, call).await {
            Ok(result) => result,
            Err(_elapsed) => Err(KernelError::HotPathDeadlineExceeded {
                stage: HotPathStage::Dispatch,
                budget_ms: budget.as_millis().min(u128::from(u64::MAX)) as u64,
            }),
        },
    }
}
```

The existing dispatch-result `match` (async_evaluation_core.rs:530) gains one arm,
mirroring the `RequestCancelled` arm (async_evaluation_core.rs:547-581) plus
RFC-0002's retained-reservation marker:

```rust
Err(KernelError::HotPathDeadlineExceeded { stage, budget_ms }) => {
    let reason = format!("hot-path deadline exceeded at {stage}: budget {budget_ms}ms");
    // Reverses the monetary hold and payment authorization (ADR-0006).
    let unwind = self.unwind_aborted_monetary_invocation(
        request,
        cap,
        budget_mutation.charge_result(),
        payment_authorization.as_ref(),
    )?;
    warn!(
        request_id = %request.request_id,
        reason = %redacted!(&reason),
        "tool call deadline expired"
    );
    // A timed-out dispatch may have applied its side effect, so the
    // runtime-admission reservation is NOT released; it is retained and
    // marked auditable, exactly as RFC-0002 specifies for the
    // RequestCancelled arm. Releasing here would be fail-open: a
    // single-use destructive lease could be replayed after the
    // destructive action already executed.
    return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
        self.build_cancelled_response_with_metadata(
            request,
            &reason,
            now,
            Some(matched_grant_index),
            self.mark_runtime_admission_reservations_retained_fail_closed(
                match (budget_mutation.charge_result(), unwind.as_ref()) {
                    (Some(charge), Some(reverse)) => self.merge_budget_receipt_metadata(
                        extra_metadata.clone(),
                        self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", reverse)),
                        ),
                    ),
                    _ => extra_metadata.clone(),
                },
            ),
        )
    });
}
```

`nested_flow_evaluation.rs` mirrors the arm, as it does for `RequestCancelled`
today. Two implementation notes keep the disposition honest.
`KernelError::HotPathDeadlineExceeded { stage: Dispatch, .. }` must NOT be added
to `dispatch_error_precedes_tool_side_effect` (kernel_drop_guard.rs:109): expiry
says nothing about whether the tool side effect happened. And RFC-0002 must land
first so `mark_runtime_admission_reservations_retained_fail_closed` exists; the
monetary reversal and `Cancelled` receipt are shared with the existing arm, so
the cancel and deadline paths cannot drift.

Guard-pipeline elapse is handled earlier: `run_guards_within_budget` returns
`HotPathDeadlineExceeded { stage: GuardPipeline, .. }` inside the `GuardRunError`, and
the existing guard-deny arm (async_evaluation_core.rs:352-387) already reverses the
pre-execution budget mutation and builds a deny response, so a guard-pipeline deadline
reverses holds through the code path that already handles guard denials. No side
effect has occurred at that point because guards run pre-dispatch.

### 5. Sync-bridge and mcp-edge stdio coverage

The dispatch timeout is inside the async future, so it covers the sync bridge without
new code on the supported path: `block_on_async_tool_dispatch` (mod.rs:211) drives the
same instrumented future under `block_in_place` on a multi-thread runtime
(mod.rs:216-218), and `block_on` runs the tokio timer to completion, so the dispatch
budget fires. Same for the mcp-edge `block_in_place` branch (tool_calls.rs:170).
The mcp-edge current-thread branch, which calls
`evaluate_tool_call_blocking_with_metadata` (tool_calls.rs:189), needs no timer:
that path funnels into the sync bridge, which refuses on a current-thread runtime
with the existing typed error
(`SyncBridgeIncompatibleWithCurrentThreadRuntime`, error.rs:203), so it cannot
hang; that refusal is unchanged by this RFC. The only path where a tokio timer
cannot fire is the no-runtime `futures::executor::block_on` fallback
(mod.rs:232), which is the compute-only in-process test path; there
`run_guards_within_budget` and `dispatch_within_budget` degrade to inline/unwrapped
(the runtime probe in each returns "no runtime"), which is documented as acceptable
because that path has no blocking I/O to hang on.

### 6. Receipt-append watchdog (F07, D1)

Two coordinated changes make writer liveness a first-class, pre-dispatch, loudly
surfaced concern.

**(a) Bound the append.** Add to `chio-store-sqlite`:

```rust
// ReceiptCommitActor
fn append_with_timeout(
    &self,
    receipt: ChioReceipt,
    raw_json: String,
    timeout: Duration,
) -> Result<u64, ReceiptStoreError> {
    // identical to append() through try_send, then:
    match result.recv_timeout(timeout) {
        Ok(inner) => inner,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Do NOT decrement `inflight` here. `try_send` succeeded, so the
            // command is still queued or running on the actor, which OWNS the
            // inflight accounting and decrements it exactly once when it drains
            // the batch (`commit_receipt_batch`). Decrementing on the timeout
            // side too would double-count a slow-but-live append; under
            // concurrent writes the saturating subtract could drive `inflight`
            // to zero while work is still queued, making writer health look
            // drained before the actor catches up. The timeout still fails THIS
            // caller loudly and trips health via `failed_total` / `last_error`;
            // a genuinely wedged (not merely slow) writer keeps `inflight`
            // elevated, which is the honest signal, and the RFC-0001 watchdog
            // surfaces it.
            self.health.failed_total.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut last) = self.health.last_error.lock() {
                *last = Some("sqlite receipt commit append timed out".to_string());
            }
            Err(receipt_actor_append_timeout_error(timeout))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            atomic_saturating_sub(&self.health.inflight, 1);
            self.health.failed_total.fetch_add(1, Ordering::SeqCst);
            Err(receipt_actor_unavailable_error())
        }
    }
}
```

`receipt_actor_append_timeout_error` returns
`ReceiptStoreError::Timeout { operation: "sqlite receipt commit append", timeout_ms }`
(the variant used by `flush_with_timeout` at receipt_store.rs:277). Crucially this arm
also writes `last_error` and bumps `failed_total`, closing the D1 gap where the
`Disconnected` path (receipt_store.rs:187-190) set neither, so a timed-out or dead
writer now turns `receipt_store_health().healthy` false at receipt_store.rs:626-631
without any other change.

The bounded append reaches the kernel through the trait boundary: the kernel-side
`ReceiptStore` trait (kernel `receipt_store.rs:187`) gains

```rust
fn append_chio_receipt_with_timeout(
    &self,
    receipt: &ChioReceipt,
    _budget: Duration,
) -> Result<Option<u64>, ReceiptStoreError> {
    // Default: ignore the budget, keep today's behavior for stores
    // without an async writer.
    self.append_chio_receipt_returning_seq(receipt)
}
```

mirroring `append_chio_receipt_returning_seq` (receipt_store.rs:202);
`SqliteReceiptStore` overrides it to route through
`ReceiptCommitActor::append_with_timeout`. `record_chio_receipt`
(call site at receipt_persistence.rs:175) calls the
bounded append with `self.config.deadlines.receipt_append_budget()`, so the
kernel-wide `receipt_store_write_lock` is now held for at most that budget per
receipt, never forever. On timeout the call fails closed as
`KernelError::ReceiptPersistence(ReceiptStoreError::Timeout{..})`; no false Allow is
emitted (the allow response is signed only after persistence succeeds).

**(b) Move the checkpoint out of the lock and add a liveness watchdog.** Restructure
`record_chio_receipt` so the critical section holds only the bounded append plus the
local-log append, and hand checkpointing to a background task:

```rust
pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
    let checkpoint_seq = {
        let _write = self.receipt_store_write_lock.lock().map_err(|_| {
            KernelError::Internal("receipt store write lock poisoned".to_string())
        })?;
        let seq = self
            .with_receipt_store(|store| {
                Ok(store.append_chio_receipt_with_timeout(
                    receipt,
                    self.config.deadlines.receipt_append_budget(),
                )?)
            })?
            .flatten();
        self.append_chio_receipt_to_local_log(receipt.clone());
        seq.filter(|seq| self.should_checkpoint_after_seq(*seq))
    }; // lock released here, before any checkpoint round trips
    if let Some(seq) = checkpoint_seq {
        self.checkpoint_trigger.notify(seq); // single background checkpoint task
    }
    let _settlement_status = self.run_settlement_observer(receipt);
    Ok(())
}
```

`checkpoint_trigger` is a `tokio::sync::watch::Sender<u64>` field on `ChioKernel`
(watch semantics deliberately coalesce a burst of due sequences into the latest
one); the background checkpoint task holds the receiver, is spawned at
`ChioKernel::new` alongside the signing task (kernel_struct.rs:252), is joined by
`shutdown`, and on each observed seq calls the existing
`maybe_trigger_checkpoint_locked` logic (renamed; it no longer runs under the
caller's lock). Because the checkpoint logic is synchronous store I/O, the task
runs each round inside `spawn_blocking` so it never pins an async worker.
`create_next_receipt_checkpoint` already handles `Conflict` races
(receipt_persistence.rs:229-239), so moving it off the request path is safe; a
checkpoint is a periodic Merkle commitment over already-durable receipts, so ADR-0008
trigger semantics and receipt durability are preserved. This removes the
per-100th-receipt tail-latency spike F07 describes and the 8-round retry loop from the
critical section.

The `ReceiptStore` trait (kernel `receipt_store.rs:187`) gains a default-provided
liveness probe so non-sqlite stores are unaffected:

```rust
/// Point-in-time writer liveness. Default `Unknown` keeps stores that have no
/// async writer (or no watchdog wired) behaving exactly as today.
fn writer_liveness(&self) -> ReceiptWriterLiveness {
    ReceiptWriterLiveness::Unknown
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptWriterLiveness {
    Healthy,
    Saturated,
    Wedged,
    Dead,
    Unknown,
}
```

`SqliteReceiptStore` overrides it from `writer_counters()`:
`Dead` on a `Disconnected` probe, `Saturated` when `saturated_total` advanced within
the last window, `Wedged` when `inflight > 0` and `accepted_total > committed_total +
failed_total` and `last_commit_unix_ms` has not advanced for
`receipt_writer_stall_ms`, else `Healthy`.

The watchdog is a dedicated tokio task the kernel spawns at `ChioKernel::new`, mirroring
the existing `signing_task` handle (kernel_struct.rs:252) and joined by `shutdown`. It
polls `writer_liveness()` every `receipt_writer_poll_ms`, stores the latest verdict in
an `ArcSwap<ReceiptWriterLiveness>` the pre-dispatch gate reads (the kernel already
depends on `arc_swap`, kernel_struct.rs:4), and logs transitions. The hosting edge
exports the verdict as Prometheus series `chio_receipt_writer_healthy` (0/1) and
`chio_receipt_writer_liveness` (labeled) through the existing `chio-edge-metrics`
text surface (`crates/protocol/chio-edge-metrics/src/lib.rs`, `render_prometheus`);
the kernel library itself takes no metrics dependency. This gives the serving kernel
a health surface with real consumers, fixing D1's "only consumer is a local CLI that
opens its own store" (health.rs:29-33,43,60).

The pre-dispatch gate now consults liveness (construction.rs:244):

```rust
pub(crate) fn ensure_receipt_persistence_ready(&self) -> Result<(), KernelError> {
    if self.receipt_store.is_none() && !self.config.allow_ephemeral_receipt_log {
        return Err(KernelError::Internal(
            "durable receipt persistence unavailable: no receipt store configured".to_string(),
        ));
    }
    match self.receipt_writer_liveness() {
        ReceiptWriterLiveness::Healthy | ReceiptWriterLiveness::Unknown => Ok(()),
        state => Err(KernelError::ReceiptWriterUnavailable(format!(
            "receipt commit writer is {state:?}; denying before dispatch"
        ))),
    }
}
```

`Unknown` preserves today's behavior when no watchdog is installed. When it is, a
`Wedged`, `Saturated`, or `Dead` writer denies the request before dispatch, through the
existing `build_receipt_persistence_failclosed_deny_response_with_metadata` path
(async_evaluation_core.rs:243, nested_flow_evaluation.rs:191), so the tool side effect
never happens while receipts cannot be persisted. That is the D1 fix: the gate now
checks writer liveness, not merely config presence.

### 7. F14 bound (control-plane)

Wrap the whole quorum wait in `tokio::time::timeout` so a never-returning
`spawn_blocking(sync_cluster_once)` (deltas.rs:700) can no longer hang past the budget:

```rust
let timeout = budget_write_quorum_commit_timeout(state.config.cluster_sync_interval);
match tokio::time::timeout(timeout, wait_for_budget_write_quorum_commit_inner(state, budget_seq))
    .await
{
    Ok(result) => result,
    Err(_elapsed) => Err(plain_http_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "budget write quorum wait exceeded its deadline",
    )),
}
```

`wait_for_budget_write_quorum_commit_inner` is the current loop body minus the internal
deadline check (deltas.rs:715), which the outer timeout now subsumes. This is the
minimal deadline-correctness fix; decoupling quorum observation from per-request
syncing (the condvar/watch redesign) is a separate control-plane RFC.

### Crates, LOC, CI-tier placement

Changes are edits to existing crates plus one new kernel module. No new crate.

| Area | Files | Rough LOC |
| --- | --- | --- |
| Config struct + validation | `chio-kernel/.../kernel_struct.rs`, `construction.rs` (`try_new`, `KernelBuildError`), `chio-config/src/schema.rs` + `validation.rs` | ~130 |
| Error taxonomy | `chio-kernel/.../kernel/error.rs` | ~50 |
| Guard offload + deadline | `chio-kernel/.../kernel/dispatch.rs` (+ `guards: Arc<Vec<Arc<dyn Guard>>>`) | ~170 |
| Dispatch timeout + abort arm | `.../evaluation/async_evaluation_core.rs`, `nested_flow_evaluation.rs` | ~70 |
| Bounded append + off-lock checkpoint | `.../responses/receipt_persistence.rs`, `chio-store-sqlite/src/receipt_store.rs` | ~140 |
| Writer watchdog module + gate | new `.../kernel/receipt_writer_watchdog.rs`, `construction.rs`, trait in `receipt_store.rs` | ~220 |
| F14 timeout | `chio-control-plane/.../cluster/deltas.rs` | ~30 |

CI tiers: unit and property tests on the PR gate; loom on the liveness cell and the
`inflight` counter interactions nightly; wedged/hung fault injection (soak and chaos)
weekly under the load-chaos program.

## Wire, schema, and receipt impact

- **Receipt kinds: none new.** A deadline expiry reuses the existing
  `Decision::Cancelled` receipt (terminal_responses.rs:30), verdict `Verdict::Deny`,
  terminal state `Cancelled`; the stage and budget are carried in the `reason` string,
  which is an existing field. Canonical JSON (RFC 8785) is unaffected.
- **Config file: additive `[deadlines]` section** in the kernel config
  (`chio-config/src/schema.rs`). All keys are optional with the defaults above; the
  per-guard and per-server maps serialize as objects with `BTreeMap`-sorted keys so
  the canonical form is deterministic.
- **Health surface: additive.** `ReceiptStoreHealthReport` (receipt_store.rs:102) gains
  a `writer_liveness` field (`#[serde(default)]`, defaults `Unknown`); the CLI JSON
  schema `CHIO_CLI_RECEIPT_HEALTH_SCHEMA` gains one optional property. Existing
  consumers are unchanged. New Prometheus gauges `chio_receipt_writer_healthy` and
  `chio_receipt_writer_liveness` are added.
- **Runtime `KernelConfig`: not a wire type.** Adding `deadlines` changes no signed or
  transmitted payload.

## Migration and compatibility

- Guard and dispatch budgets default to `0` (disabled) and `always_offload_guards`
  defaults to `false`, so with a default config the guard pipeline runs inline exactly
  as today and dispatch is unwrapped. Byte-for-byte behavior preservation for
  deployments that do not opt in.
- The receipt-append bound defaults to 5s (bounded), a deliberate behavior change: a
  wedged writer that previously stalled forever now fails closed after the budget.
  This is strictly safer and is the F07/D1 fix. `0` is rejected at load time so the
  unbounded footgun is not reachable; operators tune the value, they cannot disable
  the bound.
- The writer watchdog is wired by the hosting edge binary (the edges already
  export a Prometheus text surface via `chio-edge-metrics`), not the library
  default. With no watchdog, `writer_liveness()` returns `Unknown` and the
  pre-dispatch gate behaves as today. This lets the watchdog roll out
  independently.
- Changing `guards` to `Arc<Vec<Arc<dyn Guard>>>` is internal (the field is
  `pub(super)`, kernel_struct.rs:134). `add_guard(&mut self, guard: Box<dyn Guard>)`
  (construction.rs:1172) keeps its public signature; internally it becomes
  `Arc::make_mut(&mut self.guards).push(Arc::from(guard))` (a `Box<dyn Guard>`
  converts to `Arc<dyn Guard>` directly, and `Vec<Arc<dyn Guard>>` is `Clone`, so
  `make_mut` is available). No public signature changes for guard registration
  callers.
- Staged rollout: (1) config + typed errors + bounded append + off-lock checkpoint
  (safe, append bound default-on); (2) guard and dispatch budgets (default-off,
  opt-in); (3) watchdog task + metrics + liveness gate; (4) flip watchdog on and set
  production budgets. F14's timeout ships with stage 1.

## Test and verification plan

Unit and property (PR gate):
- `guard_pipeline_budget_denies_hung_guard_and_frees_worker`: register a guard that
  sleeps past the budget; assert the request returns `HotPathDeadlineExceeded` within
  budget + slack and that a second concurrent request on the same worker pool still
  completes (proves no worker starvation).
- `per_guard_budget_bounds_single_guard_not_pipeline`: a slow named guard elapses on
  its override while other guards still run.
- `dispatch_budget_expiry_runs_full_unwind_and_emits_cancelled_receipt`: a tool server
  that never returns; assert budget hold reversed, runtime-admission reservation
  retained and marked (`reservations_retained_fail_closed`, RFC-0002 disposition),
  and exactly one persisted `Decision::Cancelled` receipt.
- `receipt_append_timeout_releases_write_lock_within_budget`: inject a wedged commit
  actor; assert `record_chio_receipt` returns `ReceiptPersistence(Timeout)` within the
  budget and a second caller is not blocked beyond it; assert `receipt_store_health`
  turns unhealthy.
- `wedged_writer_watchdog_denies_before_side_effect`: drive the writer to `Wedged`;
  assert `ensure_receipt_persistence_ready` denies pre-dispatch and the tool server's
  invoke counter stays zero.
- `sync_bridge_dispatch_respects_deadline_under_block_in_place`: multi-thread runtime,
  hung tool server through `block_on_async_tool_dispatch`; assert deadline fires.
- `hot_path_deadline_config_rejects_zero_append_budget`: load-time validation is
  fail-closed.
- F14: `budget_write_quorum_wait_bounds_never_returning_sync`.

loom (nightly): `receipt_writer_liveness_no_lost_wakeup` over the watchdog `ArcSwap`
publish plus the `inflight`/`committed_total` counter updates, ensuring the gate never
reads a torn or stale-forever verdict.

Soak and chaos (weekly, load-chaos program): `soak_hung_tool_server_no_worker_pool_starvation`
(N hung dispatches, assert the pool never wedges and steady-state throughput on other
tenants holds), `chaos_wedged_receipt_writer_fails_closed_no_orphan_side_effects`, and
`chaos_hung_approval_guard_contained_in_blocking_pool`. The named acceptance test that
this RFC's guard fix stands or falls on is
`guard_pipeline_budget_denies_hung_guard_and_frees_worker`; for the writer fix it is
`wedged_writer_watchdog_denies_before_side_effect`. Where the unwind receipt content is
asserted, the test ties into RFC-0002's post-admission unwind acceptance suite so
the cancel and deadline paths are proven identical. A formal-methods follow-up may model
the liveness state machine (Healthy/Saturated/Wedged/Dead) as a small TLA+ spec; this is
noted, not required for this RFC.

## Acceptance criteria

- No await on the mediation path (guard pipeline, tool dispatch, receipt append,
  quorum wait) can exceed its configured budget by more than a bounded timer slack.
- Under N concurrent hung guards or hung dispatches, the tokio worker pool does not
  starve: unrelated requests on other workers continue to complete.
- A guard-pipeline or dispatch deadline reverses all monetary budget holds and
  applies RFC-0002's reservation disposition (guard-pipeline expiry is
  pre-admission, so nothing is reserved yet; dispatch expiry retains and marks
  the reservation), and a dispatch deadline persists exactly one signed
  `Cancelled` receipt through the same code path as `RequestCancelled`.
- A wedged, saturated, or dead receipt writer is detected within
  `receipt_writer_stall_ms` and denied at the pre-dispatch gate, so no tool side effect
  occurs; `receipt_store_health().healthy` is false and the Prometheus gauge reads 0.
- The receipt write lock is never held longer than `receipt_append_budget_ms` per
  receipt, and checkpoint construction no longer runs under it.
- With a default config, guard and dispatch behavior is unchanged from pre-RFC.
- Invalid deadline config (append budget `0` or below floor, zero poll/stall) is
  rejected at kernel build time.

## Risks and alternatives

- **Blocking-pool pressure.** Offloading guards to `spawn_blocking` consumes blocking
  threads; many concurrent offloaded guards could saturate the default 512-thread
  pool. Mitigation: offload only when a budget or `always_offload_guards` applies, keep
  cheap in-process guards inline, and document pool sizing. A dedicated bounded guard
  executor is a possible future refinement.
- **Detached runaway guard.** `tokio::time::timeout` cannot kill a running synchronous
  thread (no safe cancellation of blocking code in Rust), so a wedged guard keeps
  occupying one blocking thread until it finishes. Accepted: the async worker is freed
  and the request fails fast; the blocking pool bounds the blast radius. Rejected
  alternative: requiring every `Guard` to be async, which breaks the existing sync
  `Guard` trait (mod.rs:337) and all current guards.
- **Mid-flight side effect on dispatch timeout.** Cancelling the dispatch future may
  leave a tool-server side effect partially applied, the same blast radius the existing
  `RequestCancelled` path already accepts (ADR-0006 is no-refund; the `Cancelled`
  receipt records the ambiguity). This is inherent to bounding an in-flight external
  call and is documented, not eliminated.
- **Watchdog vs `panic=abort`.** Release builds abort the process on a writer-thread
  panic (`Cargo.toml:236-240`), which covers only panics, not the wedge/saturation/dead
  states, and is a process-wide fail-stop rather than a local graceful deny. The
  watchdog covers exactly the states `panic=abort` misses and prefers local denial over
  whole-process death, which is the article's thesis. Rejected alternative: relying on
  `panic=abort` alone.
- **Latency and throughput.** The timer wheel cost is negligible; the bounded
  `recv_timeout` has no steady-state cost; the only measurable overhead is one context
  switch per offloaded guard, incurred only when budgets are enabled. Moving
  checkpointing off-lock removes a tail-latency spike, a net win.

## Rollout and sequencing

- **RFC-0002 (unconditional post-admission unwind) must land first for the
  dispatch-deadline arm.** The arm mirrors the existing `RequestCancelled` arm
  (async_evaluation_core.rs:547-581) and reuses RFC-0002's
  `mark_runtime_admission_reservations_retained_fail_closed` marker and its
  explicit reservation-disposition table, so the retained-reservation semantics
  are shared, not duplicated.
- **Independent of RFC-0002:** the bounded append, off-lock checkpoint, the writer
  watchdog and liveness gate, and the F14 timeout have no dependency on the unwind
  consolidation and can land in stage 1.
- Guard and dispatch budgets (stages 2-3) land after RFC-0002 so their expiry paths use
  the shared unwind and reservation disposition from day one.
- This RFC is the first of the wave-3 reliability program; the load-chaos program plan
  supplies the soak and chaos harness the acceptance tests above run in, and its
  hung-guard / hung-tool-server / wedged-writer fault injectors are prerequisites for
  the weekly-tier tests (not for the PR-gate tests, which use in-test fault doubles).
