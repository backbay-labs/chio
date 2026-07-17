//! `ChioKernel` guard evaluation, runtime admission, and tool dispatch.
//!
//! Holds parent-request continuation, guard execution, runtime admission
//! hook invocation, the tool-dispatch entrypoints, and child-receipt
//! recording.

use super::*;
use crate::budget_store::BudgetReverseHoldDecision;

pub(crate) struct GuardRunError {
    pub(crate) error: KernelError,
    pub(crate) evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
}

pub(crate) fn dispatch_admission_error_reason(error: &KernelError) -> String {
    match error {
        KernelError::GuardDenied(reason) if reason == EMERGENCY_STOP_DENY_REASON => reason.clone(),
        _ => error.to_string(),
    }
}

impl GuardRunError {
    fn new(error: KernelError, evidence: Vec<chio_core::receipt::metadata::GuardEvidence>) -> Self {
        Self { error, evidence }
    }
}

struct ChildReceiptRecordError {
    error: KernelError,
    disposition: ChildReceiptAppendDisposition,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ChildReceiptAppendDisposition {
    NotAttempted,
    OutcomeUnknown,
}

const DEADLINE_PENDING: u8 = 0;
const DEADLINE_ELAPSED: u8 = 1;
const DEADLINE_CANCELLED: u8 = 2;

struct RuntimeAdmissionDeadlineState {
    outcome: std::sync::atomic::AtomicU8,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

impl RuntimeAdmissionDeadlineState {
    fn new() -> Self {
        Self {
            outcome: std::sync::atomic::AtomicU8::new(DEADLINE_PENDING),
            waker: std::sync::Mutex::new(None),
        }
    }

    fn poll(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), KernelError>> {
        let outcome = self.outcome.load(std::sync::atomic::Ordering::SeqCst);
        if outcome == DEADLINE_ELAPSED {
            self.clear_waker();
            return std::task::Poll::Ready(Ok(()));
        }
        if outcome == DEADLINE_CANCELLED {
            self.clear_waker();
            return std::task::Poll::Ready(Err(KernelError::Internal(
                "cancelled runtime admission readiness deadline was polled".to_string(),
            )));
        }

        let mut waker = match self.waker.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let outcome = self.outcome.load(std::sync::atomic::Ordering::SeqCst);
        if outcome == DEADLINE_ELAPSED {
            waker.take();
            return std::task::Poll::Ready(Ok(()));
        }
        if outcome == DEADLINE_CANCELLED {
            waker.take();
            return std::task::Poll::Ready(Err(KernelError::Internal(
                "cancelled runtime admission readiness deadline was polled".to_string(),
            )));
        }
        if waker
            .as_ref()
            .is_none_or(|registered| !registered.will_wake(cx.waker()))
        {
            *waker = Some(cx.waker().clone());
        }
        std::task::Poll::Pending
    }

    fn expire(&self) {
        if self
            .outcome
            .compare_exchange(
                DEADLINE_PENDING,
                DEADLINE_ELAPSED,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            return;
        }
        let waker = match self.waker.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(waker) = waker {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()));
        }
    }

    fn cancel(&self) {
        let _ = self.outcome.compare_exchange(
            DEADLINE_PENDING,
            DEADLINE_CANCELLED,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        );
        self.clear_waker();
    }

    fn clear_waker(&self) {
        match self.waker.lock() {
            Ok(mut guard) => {
                guard.take();
            }
            Err(poisoned) => {
                poisoned.into_inner().take();
            }
        }
    }
}

type RuntimeAdmissionDeadlineKey = (Instant, u64);

// One process-wide worker orders monotonic deadlines. Registrations remove
// their exact map entry on drop so cancelled waits do not accumulate state.
struct RuntimeAdmissionDeadlineSchedule {
    next_id: u64,
    entries: std::collections::BTreeMap<
        RuntimeAdmissionDeadlineKey,
        std::sync::Arc<RuntimeAdmissionDeadlineState>,
    >,
}

struct RuntimeAdmissionDeadlineSchedulerShared {
    schedule: std::sync::Mutex<RuntimeAdmissionDeadlineSchedule>,
    changed: std::sync::Condvar,
}

struct RuntimeAdmissionDeadlineScheduler {
    shared: std::sync::Arc<RuntimeAdmissionDeadlineSchedulerShared>,
}

impl RuntimeAdmissionDeadlineScheduler {
    fn start() -> Result<std::sync::Arc<Self>, String> {
        let shared = std::sync::Arc::new(RuntimeAdmissionDeadlineSchedulerShared {
            schedule: std::sync::Mutex::new(RuntimeAdmissionDeadlineSchedule {
                next_id: 0,
                entries: std::collections::BTreeMap::new(),
            }),
            changed: std::sync::Condvar::new(),
        });
        let worker_shared = std::sync::Arc::clone(&shared);
        std::thread::Builder::new()
            .name("chio-runtime-admission-deadlines".to_string())
            .spawn(move || Self::run(worker_shared))
            .map_err(|error| {
                format!("failed to start runtime admission readiness deadline scheduler: {error}")
            })?;
        #[cfg(test)]
        RUNTIME_ADMISSION_DEADLINE_WORKER_STARTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(std::sync::Arc::new(Self { shared }))
    }

    fn run(shared: std::sync::Arc<RuntimeAdmissionDeadlineSchedulerShared>) {
        let mut schedule = match shared.schedule.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        loop {
            let next_deadline = schedule
                .entries
                .first_key_value()
                .map(|((deadline, _id), _state)| *deadline);
            let Some(next_deadline) = next_deadline else {
                schedule = match shared.changed.wait(schedule) {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                continue;
            };

            let now = Instant::now();
            if next_deadline <= now {
                let expired = schedule.entries.pop_first().map(|(_key, state)| state);
                drop(schedule);
                if let Some(expired) = expired {
                    expired.expire();
                }
                schedule = match shared.schedule.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                continue;
            }

            schedule = match shared
                .changed
                .wait_timeout(schedule, next_deadline.saturating_duration_since(now))
            {
                Ok((guard, _result)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    fn register(
        self: &std::sync::Arc<Self>,
        deadline: Instant,
        state: std::sync::Arc<RuntimeAdmissionDeadlineState>,
    ) -> Result<RuntimeAdmissionDeadlineRegistration, KernelError> {
        let mut schedule = match self.shared.schedule.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let id = schedule.next_id;
        schedule.next_id = schedule.next_id.checked_add(1).ok_or_else(|| {
            KernelError::Internal(
                "runtime admission readiness deadline identifier space exhausted".to_string(),
            )
        })?;
        let key = (deadline, id);
        schedule.entries.insert(key, state);
        drop(schedule);
        self.shared.changed.notify_one();
        Ok(RuntimeAdmissionDeadlineRegistration {
            scheduler: std::sync::Arc::clone(self),
            key,
        })
    }

    fn cancel(&self, key: RuntimeAdmissionDeadlineKey) {
        let removed = match self.shared.schedule.lock() {
            Ok(mut schedule) => schedule.entries.remove(&key).is_some(),
            Err(poisoned) => poisoned.into_inner().entries.remove(&key).is_some(),
        };
        if removed {
            self.shared.changed.notify_one();
        }
    }
}

struct RuntimeAdmissionDeadlineRegistration {
    scheduler: std::sync::Arc<RuntimeAdmissionDeadlineScheduler>,
    key: RuntimeAdmissionDeadlineKey,
}

impl Drop for RuntimeAdmissionDeadlineRegistration {
    fn drop(&mut self) {
        self.scheduler.cancel(self.key);
    }
}

static RUNTIME_ADMISSION_DEADLINE_SCHEDULER: std::sync::OnceLock<
    Result<std::sync::Arc<RuntimeAdmissionDeadlineScheduler>, String>,
> = std::sync::OnceLock::new();
static NEXT_RUNTIME_ADMISSION_READINESS_TOKEN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

#[cfg(test)]
static RUNTIME_ADMISSION_DEADLINE_WORKER_STARTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn runtime_admission_deadline_scheduler(
) -> Result<std::sync::Arc<RuntimeAdmissionDeadlineScheduler>, KernelError> {
    match RUNTIME_ADMISSION_DEADLINE_SCHEDULER.get_or_init(RuntimeAdmissionDeadlineScheduler::start)
    {
        Ok(scheduler) => Ok(std::sync::Arc::clone(scheduler)),
        Err(error) => Err(KernelError::Internal(error.clone())),
    }
}

fn allocate_runtime_admission_readiness_token(
) -> Result<RuntimeAdmissionReadinessToken, KernelError> {
    NEXT_RUNTIME_ADMISSION_READINESS_TOKEN
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |current| current.checked_add(1),
        )
        .map(RuntimeAdmissionReadinessToken)
        .map_err(|_| {
            KernelError::Internal("runtime admission readiness token space exhausted".to_string())
        })
}

struct RuntimeAdmissionDeadline {
    deadline: Instant,
    state: std::sync::Arc<RuntimeAdmissionDeadlineState>,
    registration: Option<RuntimeAdmissionDeadlineRegistration>,
}

impl RuntimeAdmissionDeadline {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            state: std::sync::Arc::new(RuntimeAdmissionDeadlineState::new()),
            registration: None,
        }
    }
}

impl std::future::Future for RuntimeAdmissionDeadline {
    type Output = Result<(), KernelError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if this.registration.is_none() {
            let scheduler = match runtime_admission_deadline_scheduler() {
                Ok(scheduler) => scheduler,
                Err(error) => return std::task::Poll::Ready(Err(error)),
            };
            let registration =
                match scheduler.register(this.deadline, std::sync::Arc::clone(&this.state)) {
                    Ok(registration) => registration,
                    Err(error) => return std::task::Poll::Ready(Err(error)),
                };
            this.registration = Some(registration);
        }
        this.state.poll(cx)
    }
}

impl Drop for RuntimeAdmissionDeadline {
    fn drop(&mut self) {
        self.state.cancel();
        self.registration.take();
    }
}

struct RuntimeAdmissionReadinessRegistration<'a> {
    hook: &'a dyn RuntimeAdmissionHook,
    request: &'a ToolCallRequest,
    token: RuntimeAdmissionReadinessToken,
}

impl Drop for RuntimeAdmissionReadinessRegistration<'_> {
    fn drop(&mut self) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.hook
                .unregister_ready_before_dispatch(self.request, self.token);
        }));
        if result.is_err() {
            warn!(
                request_id = %self.request.request_id,
                "runtime admission readiness unregister callback panicked"
            );
        }
    }
}

pub(crate) struct RuntimeReadinessRevalidation<'a> {
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) dpop_required: bool,
    pub(crate) matched_grant: &'a ToolGrant,
    pub(crate) matched_grant_index: usize,
    pub(crate) charge_result: Option<&'a BudgetChargeResult>,
    pub(crate) parent_context: Option<&'a OperationContext>,
    pub(crate) session_id: Option<&'a SessionId>,
    pub(crate) session_filesystem_roots: Option<&'a [String]>,
    pub(crate) receipt_admission: &'a ReceiptFederationAdmission,
    pub(crate) runtime_admission_metadata: Option<&'a serde_json::Value>,
    pub(crate) readiness_waited: bool,
    pub(crate) force_mutable_state_revalidation: bool,
    pub(crate) now_unix_secs: u64,
    pub(crate) now_unix_ms: u64,
}

/// Owned copy of a guard invocation, so the sequential guard core can run inside
/// `spawn_blocking` (which requires a `'static` closure) without borrowing from
/// the async evaluate future.
struct OwnedGuardInvocation {
    request: ToolCallRequest,
    scope: ChioScope,
    session_filesystem_roots: Option<Vec<String>>,
    matched_grant_index: Option<usize>,
}

/// Synchronous fail-closed guard loop. Shared by the inline path and the
/// offloaded (`spawn_blocking`) path so the two can never diverge. Any deny,
/// unsupported approval verdict, or guard error short-circuits fail-closed.
fn evaluate_guards_sequential(
    guards: &[Arc<dyn Guard>],
    ctx: &GuardContext,
) -> Result<Vec<chio_core::receipt::metadata::GuardEvidence>, GuardRunError> {
    let mut evidence = Vec::new();
    for guard in guards {
        match guard.evaluate(ctx) {
            Ok(decision) => {
                evidence.extend(decision.evidence);
                match decision.verdict {
                    Verdict::Allow => {
                        debug!(guard = guard.name(), "guard passed");
                    }
                    Verdict::Deny => {
                        return Err(GuardRunError::new(
                            KernelError::GuardDenied(format!(
                                "guard \"{}\" denied the request",
                                guard.name()
                            )),
                            evidence,
                        ));
                    }
                    Verdict::PendingApproval => {
                        // The `Guard` trait does not carry the HITL approval flow; that runs via
                        // `ApprovalGuard::evaluate`. A `Guard` returning `PendingApproval` is an
                        // unsupported state, so fail closed.
                        return Err(GuardRunError::new(
                            KernelError::GuardDenied(format!(
                                "guard \"{}\" returned an unsupported approval verdict",
                                guard.name()
                            )),
                            evidence,
                        ));
                    }
                }
            }
            Err(e) => {
                // Fail closed: guard errors are treated as denials.
                return Err(GuardRunError::new(
                    KernelError::GuardDenied(format!(
                        "guard \"{}\" error (fail-closed): {e}",
                        guard.name()
                    )),
                    evidence,
                ));
            }
        }
    }
    Ok(evidence)
}

/// Run the guard loop over an owned invocation, rebuilding the borrowed
/// `GuardContext` from the owned fields. Used by the blocking offload.
fn run_guards_owned(
    guards: &[Arc<dyn Guard>],
    owned: &OwnedGuardInvocation,
) -> Result<Vec<chio_core::receipt::metadata::GuardEvidence>, GuardRunError> {
    let ctx = GuardContext {
        request: &owned.request,
        scope: &owned.scope,
        agent_id: &owned.request.agent_id,
        server_id: &owned.request.server_id,
        session_filesystem_roots: owned.session_filesystem_roots.as_deref(),
        matched_grant_index: owned.matched_grant_index,
    };
    evaluate_guards_sequential(guards, &ctx)
}

fn budget_ms_saturating(budget: std::time::Duration) -> u64 {
    budget.as_millis().min(u128::from(u64::MAX)) as u64
}

/// The fail-closed error returned when a tool-server call outruns its dispatch
/// budget. Shared by every dispatch path (top-level and nested-flow) so the
/// timeout verdict is byte-identical wherever the deadline fires.
fn dispatch_deadline_exceeded(budget: std::time::Duration) -> KernelError {
    KernelError::HotPathDeadlineExceeded {
        stage: HotPathStage::Dispatch,
        budget_ms: budget_ms_saturating(budget),
    }
}

/// Aborts an offloaded `spawn_blocking` task when the awaiting future is
/// dropped, whether because its deadline fired or because the caller was
/// cancelled. Dropping a bare `JoinHandle` only *detaches* the task: one still
/// queued on a saturated blocking pool would then start and run the tool call
/// (or guard) after the kernel has already emitted a timed-out response and
/// unwound its charges. Aborting cancels a not-yet-started task so it cannot
/// execute side effects past the deadline; a task already running its blocking
/// body cannot be interrupted, but its own inner deadline still frees it, and a
/// task that already finished is aborted as a harmless no-op.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

thread_local! {
    /// Cached probe of whether the currently entered Tokio runtime has a timer
    /// driver, keyed by that runtime's id. Timer availability is a property of the
    /// entered runtime, not the OS thread, so caching a bare verdict per thread
    /// would let a timerless verdict leak into a later timer-enabled runtime on
    /// the same thread (skipping deadlines) or a timer-enabled verdict leak into a
    /// later timerless one (panicking on timer construction). The key is the
    /// runtime id (`None` for "no runtime entered"); the verdict is re-probed
    /// whenever the entered runtime changes. Within a single runtime the cache
    /// keeps the panic-hook swap off the steady-state hot path.
    static DISPATCH_TIMER_AVAILABLE: std::cell::Cell<Option<(Option<tokio::runtime::Id>, bool)>> =
        const { std::cell::Cell::new(None) };
}

/// Serializes the panic-hook swap in [`dispatch_timer_available`] so concurrent
/// first-probes on different worker threads cannot interleave their
/// take/set-hook pairs and leave the silencing hook installed process-wide.
static TIMER_PROBE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether `tokio::time::timeout` can run in the current context without
/// panicking, i.e. a Tokio runtime is entered and its time driver is enabled.
///
/// `Handle::try_current()` only proves a runtime is entered, not that timers are
/// enabled; a host runtime built without `enable_time` panics when a timer is
/// constructed. Tokio exposes no query for the driver, so this probes by
/// constructing one zero-duration timer under a caught unwind. The panic is
/// synchronous at construction, and the panic hook is silenced for the probe so
/// a timerless host does not emit a spurious backtrace. The swap is serialized
/// so the real hook is always restored, and the result is cached per runtime per
/// thread; callers fall back to running the guarded work inline when it is false.
pub(crate) fn dispatch_timer_available() -> bool {
    let current_runtime = tokio::runtime::Handle::try_current()
        .ok()
        .map(|handle| handle.id());
    DISPATCH_TIMER_AVAILABLE.with(|cached| {
        if let Some((probed_runtime, available)) = cached.get() {
            if probed_runtime == current_runtime {
                return available;
            }
        }
        let available = {
            let _serialized = TIMER_PROBE_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let result = std::panic::catch_unwind(|| {
                drop(tokio::time::timeout(
                    std::time::Duration::ZERO,
                    std::future::ready(()),
                ));
            })
            .is_ok();
            std::panic::set_hook(previous_hook);
            result
        };
        cached.set(Some((current_runtime, available)));
        available
    })
}

/// Whether a Tokio runtime is entered in the current context. `spawn_blocking`,
/// used to offload a blocking guard, requires one; a synchronous host driving
/// dispatch through `futures::executor::block_on` has none, so the offload must
/// degrade to running the guards inline rather than panicking.
pub(crate) fn dispatch_runtime_available() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

/// Bound a nested-flow tool-server call by its dispatch `budget`.
///
/// The top-level dispatch path moves a budgeted call onto `spawn_blocking` so a
/// connection that blocks synchronously before its first `.await` cannot pin an
/// async worker. A nested-flow call cannot use that mechanism: its future
/// borrows the nested-flow bridge (the caller's `&mut` client, the session map,
/// and the child-receipt buffer), so it is neither `Send` nor `'static`; it can
/// be moved to no other thread, nor detached after a deadline without leaving
/// those borrows dangling.
///
/// On a multi-thread runtime the call is therefore driven under
/// [`tokio::task::block_in_place`], which requires neither bound: Tokio promotes
/// a replacement worker while this thread blocks, so a nested connection that
/// blocks synchronously before its first `.await` no longer starves the async
/// worker pool, and the inner timeout still fails a *cooperating* call closed at
/// the budget. A call wedged in a synchronous poll cannot be interrupted (the
/// timer cannot be polled on the blocked thread); with a borrowed bridge that
/// cannot be handed to a detachable task this is inherent, and it stays confined
/// to the one blocked thread rather than the whole pool.
///
/// On a current-thread runtime there is no spare worker to promote, and with no
/// timer driver the timeout wrapper would panic, so the call runs inline: under
/// the timeout when a timer is present, and directly otherwise.
pub(crate) async fn dispatch_nested_call_within_budget<F>(
    call: F,
    budget: std::time::Duration,
) -> Result<ToolServerOutput, KernelError>
where
    F: std::future::Future<Output = Result<ToolServerOutput, KernelError>>,
{
    async fn bounded<F>(
        call: F,
        budget: std::time::Duration,
        timer_available: bool,
    ) -> Result<ToolServerOutput, KernelError>
    where
        F: std::future::Future<Output = Result<ToolServerOutput, KernelError>>,
    {
        if timer_available {
            match tokio::time::timeout(budget, call).await {
                Ok(result) => result,
                Err(_elapsed) => Err(dispatch_deadline_exceeded(budget)),
            }
        } else {
            call.await
        }
    }

    let timer_available = dispatch_timer_available();
    let multi_thread = matches!(
        tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()),
        Ok(tokio::runtime::RuntimeFlavor::MultiThread)
    );
    if multi_thread {
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| handle.block_on(bounded(call, budget, timer_available)))
    } else {
        bounded(call, budget, timer_available).await
    }
}

impl ChioKernel {
    pub(crate) async fn wait_for_runtime_admission_dispatch_readiness(
        &self,
        request: &ToolCallRequest,
    ) -> Result<bool, KernelError> {
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            return Ok(false);
        };
        let timeout = self.runtime_admission_readiness_timeout;
        let deadline_at = Instant::now().checked_add(timeout).ok_or_else(|| {
            KernelError::InvalidConstraint(
                "runtime admission readiness timeout exceeds the monotonic clock range".to_string(),
            )
        })?;
        let token = allocate_runtime_admission_readiness_token()?;
        let _readiness_registration = RuntimeAdmissionReadinessRegistration {
            hook: hook.as_ref(),
            request,
            token,
        };
        let mut waited = false;
        let readiness = std::future::poll_fn(|cx| {
            let poll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                hook.poll_ready_before_dispatch_with_token(request, token, cx)
            }));
            match poll {
                Ok(std::task::Poll::Ready(())) => std::task::Poll::Ready(Ok(waited)),
                Ok(std::task::Poll::Pending) => {
                    waited = true;
                    std::task::Poll::Pending
                }
                Err(_) => std::task::Poll::Ready(Err(KernelError::Internal(
                    "runtime admission readiness callback panicked (fail-closed)".to_string(),
                ))),
            }
        });
        let deadline = RuntimeAdmissionDeadline::new(deadline_at);
        futures::pin_mut!(readiness, deadline);
        match futures::future::select(readiness, deadline).await {
            futures::future::Either::Left((readiness_result, _deadline)) => {
                if Instant::now() >= deadline_at {
                    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
                    return Err(KernelError::RuntimeAdmissionReadinessTimeout { timeout_ms });
                }
                readiness_result
            }
            futures::future::Either::Right((deadline_result, _readiness)) => {
                deadline_result?;
                let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
                Err(KernelError::RuntimeAdmissionReadinessTimeout { timeout_ms })
            }
        }
    }

    pub(crate) fn revalidate_tool_call_after_runtime_readiness(
        &self,
        request: &ToolCallRequest,
        dpop_required: bool,
        now: u64,
    ) -> Result<(), String> {
        if self.is_emergency_stopped() {
            return Err(EMERGENCY_STOP_DENY_REASON.to_string());
        }

        // The full verifier covers issuer trust, signature, the current time
        // window, chain binding, and the negotiated remote profile. Use one
        // fresh clock rather than repeating the standalone time check.
        self.verify_capability_full_pre_admit(
            &request.capability,
            request.federated_origin_kernel_id.as_deref(),
            now,
        )
        .map_err(|reason| format!("capability revalidation failed: {reason}"))?;

        // This deliberately avoids check_tool_call_revocation_admission: the
        // initial admission already emitted its trace event, and this mutable
        // state recheck must not report a second admission transition.
        self.check_revocation(&request.capability)
            .map_err(|error| error.to_string())?;
        self.validate_delegation_admission(&request.capability)
            .map_err(|error| error.to_string())?;

        if dpop_required {
            let proof = request.dpop_proof.as_ref().ok_or_else(|| {
                "grant requires DPoP proof but none was provided during dispatch revalidation"
                    .to_string()
            })?;
            self.verify_dpop_for_permission_preview(
                proof,
                &request.capability,
                &request.server_id,
                &request.tool_name,
                &request.arguments,
            )
            .map_err(|error| error.to_string())?;
        }

        Ok(())
    }

    fn revalidate_receipt_boundary_after_runtime_readiness(
        &self,
        request: &ToolCallRequest,
        admitted: &ReceiptFederationAdmission,
        now: u64,
    ) -> Result<(), KernelError> {
        let current = self.kernel_receipt_admission_for_remote(
            request.federated_origin_kernel_id.as_deref(),
            now,
        )?;
        if current != *admitted {
            return Err(KernelError::Internal(
                "receipt federation admission changed while runtime readiness was pending"
                    .to_string(),
            ));
        }
        self.validate_web3_evidence_prerequisites()?;
        self.ensure_registered_tool_target(request)?;
        self.ensure_federated_receipt_persistence_ready(
            request.federated_origin_kernel_id.as_deref(),
        )?;
        self.ensure_receipt_persistence_ready()?;
        self.record_observed_capability_snapshot(&request.capability)
    }

    fn revalidate_guards_after_runtime_readiness(
        &self,
        revalidation: &RuntimeReadinessRevalidation<'_>,
        revalidate_all: bool,
    ) -> Result<(), KernelError> {
        let current_session_roots = revalidation
            .session_id
            .map(|session_id| self.session_enforceable_filesystem_root_paths_owned(session_id))
            .transpose()?;
        if let Some(current_roots) = current_session_roots.as_deref() {
            if Some(current_roots) != revalidation.session_filesystem_roots {
                return Err(KernelError::GuardDenied(
                    "session filesystem roots changed while runtime readiness was pending"
                        .to_string(),
                ));
            }
        }
        let session_filesystem_roots = current_session_roots
            .as_deref()
            .or(revalidation.session_filesystem_roots);
        let context = GuardContext {
            request: revalidation.request,
            scope: &revalidation.request.capability.scope,
            agent_id: &revalidation.request.agent_id,
            server_id: &revalidation.request.server_id,
            session_filesystem_roots,
            matched_grant_index: Some(revalidation.matched_grant_index),
        };
        for guard in self.guards.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if revalidate_all {
                    guard.revalidate_before_dispatch(&context)
                } else {
                    guard.revalidate_required_before_dispatch(&context)
                }
            }));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(KernelError::GuardDenied(format!(
                        "guard dispatch revalidation failed: {error}"
                    )));
                }
                Err(_) => {
                    return Err(KernelError::GuardDenied(
                        "guard dispatch revalidation panicked (fail-closed)".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn revalidate_runtime_hook_after_readiness(
        &self,
        revalidation: &RuntimeReadinessRevalidation<'_>,
        revalidate_all: bool,
    ) -> Result<(), KernelError> {
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            return Ok(());
        };
        if !revalidate_all && !hook.requires_dispatch_revalidation() {
            return Ok(());
        }
        let context = RuntimeAdmissionRevalidationContext {
            request: revalidation.request,
            admission_metadata: revalidation.runtime_admission_metadata,
            now_unix_secs: revalidation.now_unix_secs,
            now_unix_ms: revalidation.now_unix_ms,
            matched_grant_index: Some(revalidation.matched_grant_index),
            local_kernel_id: self.federation_local_kernel_id(),
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook.revalidate_before_dispatch(&context)
        })) {
            Ok(result) => result,
            Err(_) => Err(KernelError::Internal(
                "runtime admission dispatch revalidation panicked (fail-closed)".to_string(),
            )),
        }
    }

    fn ensure_session_request_not_cancelled(
        &self,
        session_id: Option<&SessionId>,
        request_id: &str,
    ) -> Result<(), KernelError> {
        let Some(session_id) = session_id else {
            return Ok(());
        };
        let request_id = RequestId::new(request_id.to_string());
        self.with_session(session_id, |session| {
            let Some(inflight) = session.inflight().get(&request_id) else {
                return Err(KernelError::RequestCancelled {
                    request_id,
                    reason: "session request completed while runtime readiness was pending"
                        .to_string(),
                });
            };
            if inflight.cancellation_requested {
                return Err(KernelError::RequestCancelled {
                    request_id: request_id.clone(),
                    reason: inflight.cancellation_reason.unwrap_or_else(|| {
                        "session request cancelled while runtime readiness was pending".to_string()
                    }),
                });
            }
            if inflight.session_anchor_id != session.session_anchor().id() {
                return Err(KernelError::RequestCancelled {
                    request_id,
                    reason: "session authorization changed while runtime readiness was pending"
                        .to_string(),
                });
            }
            Ok(())
        })
    }

    pub(crate) fn mark_session_request_dispatch_started(
        &self,
        session_id: Option<&SessionId>,
        request_id: &str,
    ) -> Result<(), KernelError> {
        let Some(session_id) = session_id else {
            return Ok(());
        };
        let request_id = RequestId::new(request_id.to_string());
        self.with_session(session_id, |session| {
            session
                .try_mark_request_dispatch_started(&request_id)
                .map_err(|failure| KernelError::RequestCancelled {
                    request_id: request_id.clone(),
                    reason: match failure {
                        crate::session::DispatchStartFailure::RequestNotInflight => {
                            "session request completed before dispatch".to_string()
                        }
                        crate::session::DispatchStartFailure::CancellationRequested { reason } => {
                            reason.unwrap_or_else(|| {
                                "session request cancelled before dispatch".to_string()
                            })
                        }
                        crate::session::DispatchStartFailure::SessionAnchorChanged => {
                            "session authorization changed before dispatch".to_string()
                        }
                    },
                })
        })
    }

    pub(crate) fn revalidate_runtime_readiness_boundary(
        &self,
        revalidation: RuntimeReadinessRevalidation<'_>,
    ) -> Result<(), KernelError> {
        let session_request_id = revalidation
            .parent_context
            .map_or(revalidation.request.request_id.as_str(), |context| {
                context.request_id.as_str()
            });
        self.ensure_session_request_not_cancelled(revalidation.session_id, session_request_id)?;
        self.revalidate_tool_call_after_runtime_readiness(
            revalidation.request,
            revalidation.dpop_required,
            revalidation.now_unix_secs,
        )
        .map_err(KernelError::GuardDenied)?;
        let _ = self.validate_execution_nonce_non_consuming(
            revalidation.request,
            &revalidation.request.capability,
            revalidation.now_unix_secs,
        )?;
        self.revalidate_receipt_boundary_after_runtime_readiness(
            revalidation.request,
            revalidation.receipt_admission,
            revalidation.now_unix_secs,
        )?;
        self.revalidate_governed_transaction_after_runtime_readiness(
            revalidation.request,
            &revalidation.request.capability,
            revalidation.matched_grant,
            revalidation.charge_result,
            revalidation.parent_context,
            revalidation.now_unix_secs,
        )?;
        let revalidate_all =
            revalidation.readiness_waited || revalidation.force_mutable_state_revalidation;
        self.revalidate_guards_after_runtime_readiness(&revalidation, revalidate_all)?;
        self.revalidate_runtime_hook_after_readiness(&revalidation, revalidate_all)?;
        Ok(())
    }

    pub(crate) fn validate_parent_request_continuation(
        &self,
        request: &ToolCallRequest,
        parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        let child_request_id = RequestId::new(request.request_id.clone());
        self.with_session(&parent_context.session_id, |session| {
            session.validate_context(parent_context)?;
            session
                .validate_parent_request_lineage(&child_request_id, &parent_context.request_id)?;
            Ok(())
        })
    }

    pub(crate) fn has_local_receipt_id(&self, receipt_id: &str) -> Result<bool, KernelError> {
        // Store-authoritative: a durable store is a point lookup by id, not an
        // O(n) mirror scan. On a store MISS fall back to the local mirror below: a
        // store may implement append without point loads (for example an
        // append-only or remote store), so a receipt appended and mirrored locally
        // must still resolve. A store READ ERROR fails closed and PROPAGATES; only
        // a genuine miss (`Ok(None)`) falls through to the mirror, so a store
        // verification failure is never masked by a mirror hit.
        //
        // Boundary: if that append-only/remote store does not implement point
        // loads, the bounded mirror is the ONLY lookup source.
        // Once the mirror evicts a receipt past `receipt_mirror_capacity`, this
        // returns `Ok(false)` and the dependent call-chain claim is denied
        // (fail-closed, never a false allow). Such deployments must implement
        // `ReceiptStore::load_chio_receipt` so older parent receipts stay
        // point-loadable after eviction.
        if self.receipt_store.is_some() {
            if self
                .with_receipt_store(|store| Ok(store.load_chio_receipt(receipt_id)?))?
                .flatten()
                .is_some()
            {
                return Ok(true);
            }
            if self
                .with_receipt_store(|store| Ok(store.load_child_receipt(receipt_id)?))?
                .flatten()
                .is_some()
            {
                return Ok(true);
            }
            // Store miss: fall through to the local mirror scan.
        }
        // Local mirror scan (no store, or store missed).
        let chio_receipt_match = match self.receipt_log.lock() {
            Ok(log) => log.iter().any(|receipt| receipt.id == receipt_id),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .any(|receipt| receipt.id == receipt_id),
        };
        if chio_receipt_match {
            return Ok(true);
        }

        Ok(match self.child_receipt_log.lock() {
            Ok(log) => log.iter().any(|receipt| receipt.id == receipt_id),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .any(|receipt| receipt.id == receipt_id),
        })
    }

    pub(crate) fn local_receipt_artifact(
        &self,
        receipt_id: &str,
    ) -> Result<Option<LocalReceiptArtifact>, KernelError> {
        // Consult the durable store first; on a MISS fall back to the local
        // mirror (append-only / remote stores may not implement point loads, so
        // a receipt appended and mirrored locally must still resolve). A store
        // READ ERROR fails closed and PROPAGATES; only a genuine miss
        // (`Ok(None)`) falls through to the mirror, so a store verification
        // failure can never be accepted from the bounded mirror.
        if self.receipt_store.is_some() {
            if let Some(receipt) = self
                .with_receipt_store(|store| Ok(store.load_chio_receipt(receipt_id)?))?
                .flatten()
            {
                return Ok(Some(LocalReceiptArtifact::Tool(Box::new(receipt))));
            }
            if let Some(child) = self
                .with_receipt_store(|store| Ok(store.load_child_receipt(receipt_id)?))?
                .flatten()
            {
                return Ok(Some(LocalReceiptArtifact::Child(Box::new(child))));
            }
            // Store miss: fall through to the local mirror scan.
        }
        let tool_match = match self.receipt_log.lock() {
            Ok(log) => log
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Tool(Box::new(receipt))),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Tool(Box::new(receipt))),
        };
        if tool_match.is_some() {
            return Ok(tool_match);
        }

        Ok(match self.child_receipt_log.lock() {
            Ok(log) => log
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Child(Box::new(receipt))),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Child(Box::new(receipt))),
        })
    }

    pub(crate) fn is_trusted_governed_continuation_signer(
        &self,
        signer: &chio_core::PublicKey,
    ) -> bool {
        if *signer == self.config.keypair.public_key() {
            return true;
        }
        if self
            .config
            .ca_public_keys
            .iter()
            .any(|candidate| candidate == signer)
        {
            return true;
        }
        self.capability_authority
            .trusted_public_keys()
            .into_iter()
            .any(|candidate| candidate == *signer)
    }

    /// Preserve every authorization and budget exposure after dispatch begins.
    /// The tool-server outcome is not trustworthy enough to prove that no side
    /// effect occurred, so releasing any hold here would reopen replay and
    /// spending capacity. The signed terminal receipt carries the retained ids
    /// for explicit operator reconciliation.
    pub(crate) fn retain_post_dispatch_state(
        &self,
        receipt_metadata: Option<serde_json::Value>,
        runtime_admission_metadata: Option<serde_json::Value>,
        charge_result: Option<&BudgetChargeResult>,
        budget_reconcile_decision: Option<&crate::budget_store::BudgetReconcileHoldDecision>,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Option<serde_json::Value> {
        let mut metadata = self.merge_retained_runtime_admission_metadata(
            receipt_metadata,
            runtime_admission_metadata,
        );
        if let Some(charge) = charge_result {
            metadata = self.merge_budget_receipt_metadata(
                metadata,
                self.budget_execution_receipt_metadata(
                    charge,
                    budget_reconcile_decision.map(|decision| ("reconciled", decision)),
                ),
            );
        }

        let mut retained = serde_json::Map::new();
        retained.insert(
            "post_dispatch_outcome_unknown".to_string(),
            serde_json::Value::Bool(true),
        );
        if let Some(charge) = charge_result.filter(|_| budget_reconcile_decision.is_none()) {
            retained.insert(
                "retained_budget_hold_id".to_string(),
                serde_json::json!(&charge.budget_hold_id),
            );
            retained.insert(
                "retained_budget_exposure_units".to_string(),
                serde_json::json!(charge.cost_charged),
            );
        }
        if let Some(authorization) = payment_authorization {
            retained.insert(
                "retained_payment_authorization_id".to_string(),
                serde_json::json!(&authorization.authorization_id),
            );
            retained.insert(
                "retained_payment_authorization_settled".to_string(),
                serde_json::json!(authorization.settled),
            );
        }
        merge_metadata_objects(
            metadata,
            Some(serde_json::json!({ "chio_runtime": retained })),
        )
    }

    pub(crate) fn unwind_aborted_payment(
        &self,
        request: &ToolCallRequest,
        charge: &BudgetChargeResult,
        authorization: &PaymentAuthorization,
        credential_disposition: PaymentCredentialDisposition,
    ) -> Result<PreDispatchPaymentUnwindEvidence, KernelError> {
        crate::payment::validate_payment_rail_identifier(
            "authorization identifier",
            &authorization.authorization_id,
        )
        .map_err(KernelError::Internal)?;
        let settled_transaction_id = if authorization.settled {
            let transaction_id = authorization
                .settlement_transaction_id
                .as_deref()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "settled authorization is missing its refund transaction identifier"
                            .to_string(),
                    )
                })?;
            crate::payment::validate_payment_rail_identifier(
                "settlement transaction identifier",
                transaction_id,
            )
            .map_err(KernelError::Internal)?;
            Some(transaction_id)
        } else {
            None
        };
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "payment authorization present without configured adapter".to_string(),
            )
        })?;
        let unwind_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if authorization.settled {
                let transaction_id = settled_transaction_id.ok_or_else(|| {
                    PaymentError::RailError(
                        "settled authorization is missing its refund transaction identifier"
                            .to_string(),
                    )
                })?;
                adapter.refund(
                    transaction_id,
                    charge.cost_charged,
                    &charge.currency,
                    &request.request_id,
                )
            } else {
                adapter.release(&authorization.authorization_id, &request.request_id)
            }
        }))
        .map_err(|_| {
            KernelError::Internal(
                "payment adapter panicked while unwinding aborted tool invocation".to_string(),
            )
        })?;
        let result = unwind_result.map_err(|error| {
            KernelError::Internal(format!(
                "failed to unwind payment after aborted tool invocation: {error}"
            ))
        })?;
        let (expected_status, settlement_status) = if authorization.settled {
            (
                RailSettlementStatus::Refunded,
                PreDispatchPaymentUnwindStatus::Refunded,
            )
        } else {
            (
                RailSettlementStatus::Released,
                PreDispatchPaymentUnwindStatus::Released,
            )
        };
        if result.settlement_status != expected_status {
            return Err(KernelError::Internal(format!(
                "payment unwind returned unexpected status {:?}; expected {expected_status:?}",
                result.settlement_status
            )));
        }
        crate::payment::validate_payment_rail_identifier(
            "unwind transaction identifier",
            &result.transaction_id,
        )
        .map_err(KernelError::Internal)?;
        Ok(PreDispatchPaymentUnwindEvidence {
            authorization_id: authorization.authorization_id.clone(),
            transaction_id: result.transaction_id,
            settlement_status,
            credential_disposition,
        })
    }

    pub(crate) fn unwind_aborted_monetary_invocation(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        charge_result: Option<&BudgetChargeResult>,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Result<Option<BudgetReverseHoldDecision>, KernelError> {
        let Some(charge) = charge_result else {
            return Ok(None);
        };

        if let Some(authorization) = payment_authorization {
            self.unwind_aborted_payment(
                request,
                charge,
                authorization,
                PaymentCredentialDisposition::NonePresent,
            )?;
        }

        Ok(Some(self.reverse_budget_charge(&cap.id, charge)?))
    }

    pub(crate) fn record_observed_capability_snapshot(
        &self,
        capability: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let parent_capability_id = capability
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        // Bound the snapshot write by the receipt append budget. The
        // pre-dispatch liveness gate denies an already-wedged writer, but a
        // writer that passes the check and then stalls on this write must fail
        // closed within budget rather than hang the request before dispatch.
        let budget = self.config.deadlines.receipt_append_budget();
        let _ = self.with_receipt_store(|store| {
            Ok(store.record_capability_snapshot_with_timeout(
                capability,
                parent_capability_id,
                budget,
            )?)
        })?;
        Ok(())
    }

    /// Verify a DPoP proof carried on the request against the capability.
    ///
    /// Fails closed: if no proof is present, or if the nonce store / config is
    /// absent (misconfigured kernel), or if verification fails, the call is denied.
    #[cfg(test)]
    pub(crate) fn verify_dpop_for_request(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let proof = request.dpop_proof.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed(
                "grant requires DPoP proof but none was provided".to_string(),
            )
        })?;

        let nonce_store = self.dpop_nonce_store.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed(
                "kernel DPoP nonce store not configured".to_string(),
            )
        })?;

        let config = self.dpop_config.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed("kernel DPoP config not configured".to_string())
        })?;

        let args_bytes = canonical_json_bytes(&request.arguments).map_err(|e| {
            KernelError::DpopVerificationFailed(format!(
                "failed to serialize arguments for action hash: {e}"
            ))
        })?;
        let action_hash = sha256_hex(&args_bytes);

        dpop::verify_dpop_proof(
            proof,
            cap,
            &request.server_id,
            &request.tool_name,
            &action_hash,
            nonce_store,
            config,
        )
    }

    /// Verify a DPoP proof for non-mutating permission preview.
    ///
    /// This mirrors invocation DPoP policy and checks that the nonce store and
    /// config are installed, but deliberately avoids inserting the nonce so a
    /// later authoritative invocation can still spend it.
    pub fn verify_dpop_for_permission_preview(
        &self,
        proof: &dpop::DpopProof,
        cap: &CapabilityToken,
        expected_tool_server: &str,
        expected_tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(), KernelError> {
        if self.dpop_nonce_store.is_none() {
            return Err(KernelError::DpopVerificationFailed(
                "kernel DPoP nonce store not configured".to_string(),
            ));
        }

        let config = self.dpop_config.as_ref().ok_or_else(|| {
            KernelError::DpopVerificationFailed("kernel DPoP config not configured".to_string())
        })?;

        let args_bytes = canonical_json_bytes(arguments).map_err(|e| {
            KernelError::DpopVerificationFailed(format!(
                "failed to serialize arguments for action hash: {e}"
            ))
        })?;
        let action_hash = sha256_hex(&args_bytes);

        dpop::verify_dpop_proof_stateless(
            proof,
            cap,
            expected_tool_server,
            expected_tool_name,
            &action_hash,
            config,
        )
    }

    /// Run all registered guards. Fail-closed: any error from a guard is
    /// treated as a deny.
    pub(crate) fn run_guards(
        &self,
        request: &ToolCallRequest,
        scope: &ChioScope,
        session_filesystem_roots: Option<&[String]>,
        matched_grant_index: Option<usize>,
    ) -> Result<Vec<chio_core::receipt::metadata::GuardEvidence>, GuardRunError> {
        let ctx = GuardContext {
            request,
            scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots,
            matched_grant_index,
        };
        evaluate_guards_sequential(self.guards.as_slice(), &ctx)
    }

    /// Async wrapper deciding how to run the synchronous guard pipeline. When a
    /// pipeline budget, a per-guard override, or `always_offload_guards` applies,
    /// the sync core runs under `spawn_blocking` (wrapped in `tokio::time::timeout`
    /// only when the runtime has a timer driver), so a blocking guard can no longer
    /// pin an async worker and a hung guard fails closed as
    /// `HotPathDeadlineExceeded`. A budget with no timer driver degrades to inline
    /// because the timeout wrapper would panic; `always_offload_guards` still
    /// offloads in that case and simply skips the unenforceable timeout. With no
    /// Tokio runtime at all `spawn_blocking` is unavailable, so the guards run
    /// inline.
    ///
    /// `tokio::time::timeout` drops the `JoinHandle` on expiry, which detaches
    /// (does not kill) the blocking thread: a runaway guard runs to completion
    /// on the blocking pool with its result discarded, while the async worker is
    /// freed and the request fails fast. The blast radius is contained in the
    /// blocking pool instead of starving the async worker pool.
    pub(crate) async fn run_guards_within_budget(
        &self,
        request: &ToolCallRequest,
        scope: &ChioScope,
        session_filesystem_roots: Option<&[String]>,
        matched_grant_index: Option<usize>,
    ) -> Result<Vec<chio_core::receipt::metadata::GuardEvidence>, GuardRunError> {
        let has_per_guard = !self.config.deadlines.per_guard_budget_ms.is_empty();
        let pipeline_budget = self.config.deadlines.guard_pipeline_budget();
        let needs_timer = pipeline_budget.is_some() || has_per_guard;
        let always_offload = self.config.deadlines.always_offload_guards;
        let want_offload = needs_timer || always_offload;

        // Offloading needs an entered Tokio runtime, since `spawn_blocking` panics
        // without one; a synchronous host bridging dispatch through
        // `futures::executor::block_on` has no runtime, so the offload degrades to
        // inline there.
        if !want_offload || !dispatch_runtime_available() {
            return self.run_guards(
                request,
                scope,
                session_filesystem_roots,
                matched_grant_index,
            );
        }

        // A budget is only enforceable with a Tokio time driver: the timeout
        // wrapper panics without one. A budget-only configuration therefore
        // degrades to inline when no timer is present. `always_offload_guards` is
        // different: it asks to keep a blocking guard off the async worker
        // regardless of budgets, so it still offloads onto `spawn_blocking` here
        // and only skips the (unenforceable) timeout.
        let timer_available = dispatch_timer_available();
        if needs_timer && !timer_available && !always_offload {
            return self.run_guards(
                request,
                scope,
                session_filesystem_roots,
                matched_grant_index,
            );
        }

        let owned = Arc::new(OwnedGuardInvocation {
            request: request.clone(),
            scope: scope.clone(),
            session_filesystem_roots: session_filesystem_roots.map(<[String]>::to_vec),
            matched_grant_index,
        });

        // Per-guard budgets require a per-guard timeout, so this path only runs
        // with a timer driver. Without one (reached only because
        // `always_offload_guards` forced the offload past the missing timer),
        // fall through to a single whole-pipeline `spawn_blocking` with no
        // enforceable timeout.
        if has_per_guard && timer_available {
            // Per-guard budgets bound each guard individually, but the whole
            // loop must still honor the pipeline budget: without an outer
            // deadline a chain of guards, each within its own budget, can run
            // far past the configured pipeline wall-clock limit. Keep the
            // pipeline deadline around the loop so total guard time stays bounded.
            let per_guard = self.run_guards_per_guard_offloaded(&owned);
            return match pipeline_budget {
                Some(budget) => match tokio::time::timeout(budget, per_guard).await {
                    Ok(result) => result,
                    Err(_elapsed) => Err(GuardRunError::new(
                        KernelError::HotPathDeadlineExceeded {
                            stage: HotPathStage::GuardPipeline,
                            budget_ms: budget_ms_saturating(budget),
                        },
                        Vec::new(),
                    )),
                },
                None => per_guard.await,
            };
        }

        let guards = Arc::clone(&self.guards);
        let owned_for_task = Arc::clone(&owned);
        let join = tokio::task::spawn_blocking(move || run_guards_owned(&guards, &owned_for_task));
        // Abort the offloaded guard loop if the pipeline deadline fires or this
        // future is cancelled, so a task still queued on a saturated blocking
        // pool cannot run the (side-effecting) guards after the request has
        // already failed closed.
        let _abort_on_drop = AbortOnDrop(join.abort_handle());
        match pipeline_budget.filter(|_| timer_available) {
            Some(budget) => match tokio::time::timeout(budget, join).await {
                Ok(Ok(result)) => result,
                Ok(Err(join_err)) => Err(GuardRunError::new(
                    KernelError::Internal(format!("guard task join failed: {join_err}")),
                    Vec::new(),
                )),
                Err(_elapsed) => Err(GuardRunError::new(
                    KernelError::HotPathDeadlineExceeded {
                        stage: HotPathStage::GuardPipeline,
                        budget_ms: budget_ms_saturating(budget),
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

    /// Enforce each guard against its own effective budget, so one wedged guard
    /// is bounded to its own budget while the rest still run. One blocking
    /// handoff per guard; used only when per-guard budgets are configured.
    async fn run_guards_per_guard_offloaded(
        &self,
        owned: &Arc<OwnedGuardInvocation>,
    ) -> Result<Vec<chio_core::receipt::metadata::GuardEvidence>, GuardRunError> {
        let mut evidence = Vec::new();
        for guard in self.guards.iter() {
            let budget = self.config.deadlines.guard_budget_for(guard.name());
            let guard = Arc::clone(guard);
            let owned = Arc::clone(owned);
            let run_one = tokio::task::spawn_blocking(move || {
                run_guards_owned(std::slice::from_ref(&guard), &owned)
            });
            // Abort this guard's offloaded task if its own budget fires or the
            // enclosing pipeline deadline drops this future, so a task still
            // queued on a saturated blocking pool cannot run the guard after the
            // request has already failed closed.
            let _abort_on_drop = AbortOnDrop(run_one.abort_handle());
            let outcome = match budget {
                Some(budget) => match tokio::time::timeout(budget, run_one).await {
                    Ok(joined) => joined,
                    Err(_elapsed) => {
                        return Err(GuardRunError::new(
                            KernelError::HotPathDeadlineExceeded {
                                stage: HotPathStage::GuardPipeline,
                                budget_ms: budget_ms_saturating(budget),
                            },
                            std::mem::take(&mut evidence),
                        ));
                    }
                },
                None => run_one.await,
            };
            match outcome {
                Ok(Ok(mut guard_evidence)) => evidence.append(&mut guard_evidence),
                Ok(Err(mut guard_error)) => {
                    // Preserve the evidence accumulated from earlier guards ahead
                    // of the failing guard's own evidence.
                    guard_error.evidence.splice(0..0, evidence);
                    return Err(guard_error);
                }
                Err(join_err) => {
                    return Err(GuardRunError::new(
                        KernelError::Internal(format!("guard task join failed: {join_err}")),
                        std::mem::take(&mut evidence),
                    ));
                }
            }
        }
        Ok(evidence)
    }

    pub(crate) fn run_runtime_admission_hook(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<&serde_json::Value>,
        now: u64,
        now_unix_ms: u64,
        matched_grant_index: Option<usize>,
    ) -> RuntimeAdmissionDecision {
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            let has_runtime_context = request
                .governed_intent
                .as_ref()
                .and_then(|intent| intent.context.as_ref())
                .is_some_and(|context| {
                    context.get("chioAdmission").is_some()
                        || context.get("chioTreaty").is_some()
                        || context.get("chioSwarm").is_some()
                });
            if has_runtime_context {
                return RuntimeAdmissionDecision::deny(
                    "chio runtime admission hook is required for governed runtime requests",
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "accepted": false,
                            "failure_code": "runtime_admission_hook_missing"
                        }
                    })),
                );
            }
            if request.federated_origin_kernel_id.is_some() {
                return RuntimeAdmissionDecision::deny(
                    "chio treaty-bound runtime admission context missing",
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "accepted": false,
                            "failure_code": "missing_chio_treaty_context"
                        }
                    })),
                );
            }
            return RuntimeAdmissionDecision::allow(None);
        };
        let context = RuntimeAdmissionContext {
            request,
            extra_metadata,
            now_unix_secs: now,
            now_unix_ms,
            matched_grant_index,
            local_kernel_id: self.federation_local_kernel_id(),
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook.evaluate(&context))) {
            Err(_) => RuntimeAdmissionDecision::deny(
                "runtime admission hook panicked (fail-closed)",
                Some(serde_json::json!({
                    "runtime_admission": {
                        "accepted": false,
                        "failure_code": "runtime_admission_hook_panic"
                    }
                })),
            ),
            Ok(Ok(decision)) => decision,
            Ok(Err(error)) => RuntimeAdmissionDecision::deny(
                format!("runtime admission hook error (fail-closed): {error}"),
                Some(serde_json::json!({
                    "runtime_admission": {
                        "accepted": false,
                        "failure_code": "runtime_admission_hook_error"
                    }
                })),
            ),
        }
    }

    pub(crate) fn release_runtime_admission_reservations(
        &self,
        metadata: Option<&serde_json::Value>,
    ) -> Result<(), KernelError> {
        let Some(metadata) = metadata else {
            return Ok(());
        };
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            return Ok(());
        };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook.release_reserved(metadata)
        }))
        .map_err(|_| {
            KernelError::Internal(
                "runtime admission hook panicked while releasing reservations".to_string(),
            )
        })?
    }

    /// Record, in receipt metadata, that runtime-admission reservations
    /// consumed at admission were deliberately NOT released because a tool
    /// side effect may have executed. The reserved ids are copied so an
    /// operator can locate and re-issue the burned lease/continuation from
    /// the signed receipt alone. Fail-closed: metadata without a
    /// `chio_runtime` block, or a `chio_runtime` block that carries no real
    /// reservation (no present, non-empty `reserved_*` id), is returned
    /// unchanged. Marking such metadata retained would claim a reservation was
    /// burned when there was nothing to recover, which misleads operators.
    pub(crate) fn mark_runtime_admission_reservations_retained_fail_closed(
        &self,
        metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let mut retained = serde_json::Map::new();
        {
            let Some(runtime) = metadata
                .as_ref()
                .and_then(|value| value.get("chio_runtime"))
                .and_then(serde_json::Value::as_object)
            else {
                return metadata;
            };
            // Copy across only the ids that name a REAL reservation: a present,
            // non-empty reserved lease/continuation id. A `chio_runtime` route
            // block that merely carries the key with no (or an empty) value had
            // nothing to burn.
            for (source, target) in [
                (
                    "reserved_destructive_lease_id",
                    "retained_destructive_lease_id",
                ),
                (
                    "reserved_treaty_continuation_id",
                    "retained_treaty_continuation_id",
                ),
                (
                    "reserved_swarm_continuation_id",
                    "retained_swarm_continuation_id",
                ),
            ] {
                if let Some(id) = runtime
                    .get(source)
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| !id.is_empty())
                {
                    retained.insert(target.to_string(), serde_json::json!(id));
                }
            }
            // Only mark retained when at least one real reservation was actually
            // retained. An observe-only admission or a metadata-only
            // `chio_runtime` route block has no `reserved_*` id to recover, so
            // it must not carry the fail-closed marker.
            if retained.is_empty() {
                return metadata;
            }
            retained.insert(
                "reservations_retained_fail_closed".to_string(),
                serde_json::Value::Bool(true),
            );
        }
        let marked = merge_metadata_objects(
            metadata,
            Some(serde_json::json!({ "chio_runtime": retained })),
        );
        #[cfg(debug_assertions)]
        self.debug_assert_runtime_reservations_retained(marked.as_ref());
        marked
    }

    pub(crate) fn merge_retained_runtime_admission_metadata(
        &self,
        receipt_metadata: Option<serde_json::Value>,
        runtime_admission_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let projected =
            project_runtime_admission_receipt_metadata(runtime_admission_metadata.as_ref())
                .unwrap_or(None);
        let retained = self.mark_runtime_admission_reservations_retained_fail_closed(projected);
        merge_metadata_objects(receipt_metadata, retained)
    }

    /// Forward the validated request and optionally report actual invocation
    /// cost, enforcing the configured dispatch budget. This is the phase-level
    /// dispatch entry point (`ToolEvaluator::dispatch`), so a custom evaluator or
    /// phase-level caller cannot bypass the deadline and hang indefinitely on a
    /// wedged tool server; it matches the budget the full evaluate path enforces.
    pub(crate) async fn dispatch_tool_call_with_cost(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        self.require_presented_execution_nonce(request, &request.capability)?;
        self.dispatch_within_budget(request, has_monetary_grant)
            .await
    }

    /// Bound the tool-server call by the per-server (or default) dispatch
    /// budget. On expiry the call fails closed with `HotPathDeadlineExceeded`,
    /// which the evaluate core unwinds like a cancellation.
    ///
    /// Wrapping the call future in `timeout` only bounds it if the connection
    /// yields to Tokio; a connection that does synchronous blocking work before
    /// its first `.await` would pin the polling worker and the timer would never
    /// fire. So on a multi-thread runtime a budgeted call is driven on a
    /// `spawn_blocking` thread (like the guard pipeline) and only its join handle
    /// is awaited under the deadline, keeping a blocking connection off the async
    /// worker pool. With no budget the call runs inline. On a current-thread
    /// runtime the call also runs inline under the timeout: there is no spare
    /// worker to isolate a blocking poll onto, and driving the call on a second
    /// thread would contend for the sole scheduler (so a blocking connection can
    /// still pin the only worker there, an inherent single-threaded-runtime
    /// limit). With no runtime at all it runs inline without a timeout (there is
    /// no async transport to hang on, and the timeout wrapper would panic without
    /// a timer driver).
    pub(crate) async fn dispatch_within_budget(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        let Some(budget) = self
            .config
            .deadlines
            .dispatch_budget_for(&request.server_id)
        else {
            return self
                .dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary_grant)
                .await;
        };

        let timer_available = dispatch_timer_available();
        let multi_thread = matches!(
            tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()),
            Ok(tokio::runtime::RuntimeFlavor::MultiThread)
        );
        if !multi_thread {
            let call =
                self.dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary_grant);
            if timer_available {
                return match tokio::time::timeout(budget, call).await {
                    Ok(result) => result,
                    Err(_elapsed) => Err(dispatch_deadline_exceeded(budget)),
                };
            }
            return call.await;
        }

        let server = match self.tool_servers.get(&request.server_id) {
            Some(server) => Arc::clone(server),
            None => {
                return Err(KernelError::ToolNotRegistered(format!(
                    "server \"{}\" / tool \"{}\"",
                    request.server_id, request.tool_name
                )));
            }
        };
        let tool_name = request.tool_name.clone();
        let arguments = request.arguments.clone();
        let handle = tokio::runtime::Handle::current();
        // Drive the connection call to completion on the blocking pool via
        // `Handle::block_on`. `spawn_blocking` threads carry the runtime handle
        // without being marked as "inside" it, so `block_on` does not panic there,
        // and a blocking first poll stays on the blocking pool rather than the
        // async worker.
        //
        // The inner timeout matters for a *cooperating* connection that never
        // completes (it yields but never resolves): `block_on` cannot be
        // cancelled by dropping the join handle, so without it that blocking
        // thread would be pinned forever. The inner timeout lets `block_on` return
        // at the budget, freeing the blocking thread. It cannot fire for a
        // connection still stuck in a synchronous blocking poll (the timer cannot
        // be polled either); that thread frees when the blocking work finally
        // returns, bounded by Tokio's blocking-pool ceiling rather than growing
        // without limit. Either way the outer timeout frees the async worker at
        // the budget, so the per-eval wall clock holds.
        let join = tokio::task::spawn_blocking(move || {
            let call =
                Self::invoke_resolved_server(server, tool_name, arguments, has_monetary_grant);
            if timer_available {
                handle.block_on(async move {
                    match tokio::time::timeout(budget, call).await {
                        Ok(result) => result,
                        Err(_elapsed) => Err(dispatch_deadline_exceeded(budget)),
                    }
                })
            } else {
                handle.block_on(call)
            }
        });
        // Cancel the offloaded call if the outer deadline fires before the
        // blocking pool even starts it. Dropping the join handle alone detaches
        // the task, so a call still queued on a saturated pool could later run
        // the tool after this eval has already returned a timed-out response and
        // unwound its charges.
        let _abort_on_drop = AbortOnDrop(join.abort_handle());

        if timer_available {
            match tokio::time::timeout(budget, join).await {
                Ok(Ok(result)) => result,
                Ok(Err(join_error)) => Err(KernelError::Internal(format!(
                    "dispatch task join failed: {join_error}"
                ))),
                Err(_elapsed) => Err(dispatch_deadline_exceeded(budget)),
            }
        } else {
            match join.await {
                Ok(result) => result,
                Err(join_error) => Err(KernelError::Internal(format!(
                    "dispatch task join failed: {join_error}"
                ))),
            }
        }
    }

    pub(crate) async fn dispatch_tool_call_with_cost_after_nonce_check(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        let server = self.tool_servers.get(&request.server_id).ok_or_else(|| {
            KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
        })?;
        Self::invoke_resolved_server(
            Arc::clone(server),
            request.tool_name.clone(),
            request.arguments.clone(),
            has_monetary_grant,
        )
        .await
    }

    /// Drive one already-resolved tool-server invocation to completion. Taken
    /// over owned inputs and free of any `&self` borrow so the dispatch deadline
    /// path can move it onto a `spawn_blocking` thread (`'static`), isolating a
    /// connection that blocks synchronously before its first `.await` from the
    /// async worker.
    async fn invoke_resolved_server(
        server: Arc<dyn ToolServerConnection>,
        tool_name: String,
        arguments: serde_json::Value,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        // Try streaming first regardless of monetary mode.
        //
        // Why the kernel cannot bound stream memory "as chunks arrive" at THIS
        // seam, and where the actual bounds live.
        //
        // `ToolServerConnection::invoke_stream` returns a FULLY MATERIALIZED
        // `ToolServerStreamResult` (which owns a `ToolCallStream { chunks: Vec<..>
        // }`). The connector is in-process trusted code that drains its transport
        // and builds the entire Vec BEFORE returning; the kernel receives control
        // only after materialization. There is no incremental per-chunk arrival at
        // this seam, so `push_chunk_bounded` cannot be driven here to bound the
        // stream as it accumulates. True accumulation-time bounding would require
        // changing the trait contract to a kernel-driven pull model (invoke_stream
        // yielding a chunk source the kernel pulls), a public runtime-API change
        // affecting every implementor; and even then a malicious in-process
        // connector could allocate before yielding. So the transient peak
        // allocation of a non-cooperating out-of-tree connector is a genuine
        // connector-trust-boundary limit, bounded only by the process RSS ceiling
        // (cgroup/ulimit).
        //
        // Layered bounds that DO apply:
        //   - Accumulation is bounded by the ACCUMULATOR. In-tree connectors cap
        //     it (A2A: `parse_sse_stream_with_limit`, MAX_SSE_TOTAL_BYTES = 1 MiB).
        //     `enforce_stream_byte_limit` / `push_chunk_bounded` (crate::runtime)
        //     are pub fail-closed Overloaded { StreamBytes / StreamChunks }
        //     primitives (bounding total bytes AND retained chunk count) so
        //     out-of-tree connector authors can bound their own invoke_stream.
        //   - Retained memory is bounded at finalize by `apply_stream_limits` /
        //     `truncate_stream_to_limits`: the stream is truncated to
        //     `max_stream_total_bytes` / `max_stream_chunks` and the receipt is
        //     marked incomplete,
        //     PRESERVING the charge-for-work-done and financial metadata on
        //     governed monetary streams (pinned by
        //     `governed_monetary_incomplete_receipt_keeps_financial_and_governed_metadata`
        //     and `streamed_tool_byte_limit_truncates_output_and_marks_receipt_incomplete`).
        //     A hard-deny (Err) here was deliberately reverted because it unwinds
        //     the monetary charge for an already-executed stream, so this seam
        //     does not hard-deny.
        if let Some(stream) = server
            .invoke_stream(&tool_name, arguments.clone(), None)
            .await?
        {
            return Ok((ToolServerOutput::Stream(stream), None));
        }

        if has_monetary_grant {
            let (value, cost) = server.invoke_with_cost(&tool_name, arguments, None).await?;
            Ok((ToolServerOutput::Value(value), cost))
        } else {
            let value = server.invoke(&tool_name, arguments, None).await?;
            Ok((ToolServerOutput::Value(value), None))
        }
    }

    /// Persist already-signed child receipts using commit-bounded durable
    /// appends under the kernel-wide receipt write lock, then the in-process log.
    /// Child receipts hold that lock, so an unbounded wait would let a wedged
    /// writer pin every subsequent receipt write; the bounded append fails
    /// closed on timeout. The in-process log is appended only after the durable
    /// append succeeds, so a failed append never records a child receipt that is
    /// absent from the durable log.
    pub(crate) fn record_child_receipts(
        &self,
        receipts: &mut Vec<ChildRequestReceipt>,
        unknown_outcomes: &mut Vec<ChildRequestReceipt>,
    ) -> Result<(), KernelError> {
        let mut recorded = 0;
        while recorded < receipts.len() {
            if let Err(failure) = self.record_child_receipt(&receipts[recorded]) {
                receipts.drain(..recorded);
                match failure.disposition {
                    ChildReceiptAppendDisposition::NotAttempted => {}
                    ChildReceiptAppendDisposition::OutcomeUnknown => {
                        if !receipts.is_empty() {
                            unknown_outcomes.push(receipts.remove(0));
                        }
                    }
                }
                return Err(failure.error);
            }
            recorded += 1;
        }
        receipts.clear();
        Ok(())
    }

    fn record_child_receipt(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ChildReceiptRecordError> {
        let receipt_store_write =
            self.receipt_store_write_lock
                .lock()
                .map_err(|_| ChildReceiptRecordError {
                    error: KernelError::Internal("receipt store write lock poisoned".to_string()),
                    disposition: ChildReceiptAppendDisposition::NotAttempted,
                })?;
        let append_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.with_receipt_store(|store| {
                Ok(store.append_child_receipt_with_timeout(
                    receipt,
                    self.config.deadlines.receipt_append_budget(),
                )?)
            })
        }));
        match append_result {
            Ok(Ok(_stored_seq)) => {}
            Ok(Err(error)) => {
                return Err(ChildReceiptRecordError {
                    error,
                    disposition: ChildReceiptAppendDisposition::OutcomeUnknown,
                });
            }
            Err(_) => {
                return Err(ChildReceiptRecordError {
                    error: KernelError::Internal(
                        "child receipt append panicked after persistence began".to_string(),
                    ),
                    disposition: ChildReceiptAppendDisposition::OutcomeUnknown,
                });
            }
        }
        self.append_child_receipt_to_local_log(receipt.clone());
        drop(receipt_store_write);
        Ok(())
    }

    pub(crate) fn append_chio_receipt_to_local_log(&self, receipt: ChioReceipt) {
        match self.receipt_log.lock() {
            Ok(mut log) => log.append(receipt),
            Err(poisoned) => poisoned.into_inner().append(receipt),
        }
    }

    fn append_child_receipt_to_local_log(&self, receipt: ChildRequestReceipt) {
        match self.child_receipt_log.lock() {
            Ok(mut log) => log.append(receipt),
            Err(poisoned) => poisoned.into_inner().append(receipt),
        }
    }
}

#[cfg(test)]
mod runtime_admission_deadline_tests {
    use super::*;

    struct SchedulerLockCheckingWaker {
        shared: std::sync::Arc<RuntimeAdmissionDeadlineSchedulerShared>,
        called: std::sync::atomic::AtomicBool,
        lock_available: std::sync::atomic::AtomicBool,
    }

    impl SchedulerLockCheckingWaker {
        fn record_wake(&self) {
            self.lock_available.store(
                self.shared.schedule.try_lock().is_ok(),
                std::sync::atomic::Ordering::SeqCst,
            );
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl std::task::Wake for SchedulerLockCheckingWaker {
        fn wake(self: std::sync::Arc<Self>) {
            self.record_wake();
        }

        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.record_wake();
        }
    }

    #[test]
    fn shared_readiness_scheduler_expires_concurrent_waits_on_one_worker() {
        let deadlines = (0..32)
            .map(|_| RuntimeAdmissionDeadline::new(Instant::now() + Duration::from_millis(10)))
            .collect::<Vec<_>>();
        let results = futures::executor::block_on(futures::future::join_all(deadlines));
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            RUNTIME_ADMISSION_DEADLINE_WORKER_STARTS.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "all concurrent readiness deadlines must share one worker"
        );
    }

    #[test]
    fn shared_readiness_scheduler_drops_cancelled_waits_without_retention() {
        let mut deadlines = (0..32)
            .map(|_| {
                Box::pin(RuntimeAdmissionDeadline::new(
                    Instant::now() + Duration::from_secs(30),
                ))
            })
            .collect::<Vec<_>>();
        let waker = futures::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        for deadline in &mut deadlines {
            assert!(matches!(
                std::future::Future::poll(deadline.as_mut(), &mut context),
                std::task::Poll::Pending
            ));
        }
        let states = deadlines
            .iter()
            .map(|deadline| std::sync::Arc::downgrade(&deadline.state))
            .collect::<Vec<_>>();

        drop(deadlines);

        assert!(states.iter().all(|state| state.upgrade().is_none()));
        assert_eq!(
            RUNTIME_ADMISSION_DEADLINE_WORKER_STARTS.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "cancellation must not start additional deadline workers"
        );
    }

    #[test]
    fn normal_readiness_completion_cancels_long_deadline_without_retention() {
        let deadline = RuntimeAdmissionDeadline::new(Instant::now() + Duration::from_secs(30));
        let state = std::sync::Arc::downgrade(&deadline.state);
        let mut first_poll = true;
        let readiness = std::future::poll_fn(move |cx| {
            if first_poll {
                first_poll = false;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        });

        let result = futures::executor::block_on(futures::future::select(readiness, deadline));
        let readiness_won = match result {
            futures::future::Either::Left(((), deadline)) => {
                drop(deadline);
                true
            }
            futures::future::Either::Right((_deadline_result, _readiness)) => false,
        };

        assert!(
            readiness_won,
            "readiness must resolve before the long deadline"
        );
        assert!(state.upgrade().is_none());
    }

    #[test]
    fn readiness_scheduler_identifier_overflow_inserts_no_deadline() {
        let scheduler = std::sync::Arc::new(RuntimeAdmissionDeadlineScheduler {
            shared: std::sync::Arc::new(RuntimeAdmissionDeadlineSchedulerShared {
                schedule: std::sync::Mutex::new(RuntimeAdmissionDeadlineSchedule {
                    next_id: u64::MAX,
                    entries: std::collections::BTreeMap::new(),
                }),
                changed: std::sync::Condvar::new(),
            }),
        });
        let registration = scheduler.register(
            Instant::now(),
            std::sync::Arc::new(RuntimeAdmissionDeadlineState::new()),
        );

        assert!(matches!(registration, Err(KernelError::Internal(_))));
        let entry_count = match scheduler.shared.schedule.lock() {
            Ok(schedule) => schedule.entries.len(),
            Err(poisoned) => poisoned.into_inner().entries.len(),
        };
        assert_eq!(entry_count, 0);
    }

    #[test]
    fn readiness_scheduler_releases_schedule_lock_before_waking() -> Result<(), KernelError> {
        let scheduler = runtime_admission_deadline_scheduler()?;
        let checker = std::sync::Arc::new(SchedulerLockCheckingWaker {
            shared: std::sync::Arc::clone(&scheduler.shared),
            called: std::sync::atomic::AtomicBool::new(false),
            lock_available: std::sync::atomic::AtomicBool::new(false),
        });
        let waker = std::task::Waker::from(std::sync::Arc::clone(&checker));
        let mut context = std::task::Context::from_waker(&waker);
        let mut deadline = Box::pin(RuntimeAdmissionDeadline::new(
            Instant::now() + Duration::from_millis(10),
        ));
        assert!(matches!(
            std::future::Future::poll(deadline.as_mut(), &mut context),
            std::task::Poll::Pending
        ));

        let wait_until = Instant::now() + Duration::from_secs(1);
        while !checker.called.load(std::sync::atomic::Ordering::SeqCst)
            && Instant::now() < wait_until
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(deadline);

        assert!(checker.called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            checker
                .lock_available
                .load(std::sync::atomic::Ordering::SeqCst),
            "deadline worker must release the scheduler lock before waking"
        );
        Ok(())
    }
}

#[cfg(test)]
mod timer_probe_tests {
    use super::dispatch_timer_available;

    // The probe verdict is keyed by runtime id, so each runtime is probed under
    // its own key. `re_probes_when_the_entered_runtime_changes_on_one_thread`
    // exercises two runtimes on one thread directly; the two single-runtime tests
    // below pin the per-runtime verdicts in isolation.

    #[test]
    fn re_probes_when_the_entered_runtime_changes_on_one_thread(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A timerless runtime, then a timer-enabled one, both entered from this
        // same OS thread. A per-thread-only cache would reuse the timerless
        // verdict and wrongly report no timer in the second runtime; keying on the
        // runtime id re-probes when the entered runtime changes.
        let timerless = tokio::runtime::Builder::new_current_thread().build()?;
        timerless.block_on(async {
            assert!(!dispatch_timer_available());
        });
        let timed = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        timed.block_on(async {
            assert!(dispatch_timer_available());
            let elapsed = tokio::time::timeout(
                std::time::Duration::from_millis(1),
                std::future::pending::<()>(),
            )
            .await;
            assert!(elapsed.is_err(), "the timer must actually fire here");
        });
        Ok(())
    }

    #[test]
    fn reports_false_in_a_runtime_without_a_time_driver() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(async {
            assert!(!dispatch_timer_available());
            // Mirror the hot-path guard: only wrap work in a timer when the probe
            // allows it, so a timerless runtime degrades to inline instead of
            // panicking on timer construction.
            let ran_inline = if dispatch_timer_available() {
                tokio::time::timeout(std::time::Duration::from_millis(1), std::future::ready(()))
                    .await
                    .is_ok()
            } else {
                std::future::ready(()).await;
                true
            };
            assert!(ran_inline);
        });
        Ok(())
    }

    #[test]
    fn reports_true_in_a_runtime_with_a_time_driver() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        runtime.block_on(async {
            assert!(dispatch_timer_available());
            let elapsed = tokio::time::timeout(
                std::time::Duration::from_millis(1),
                std::future::pending::<()>(),
            )
            .await;
            assert!(elapsed.is_err(), "the timer must actually fire here");
        });
        Ok(())
    }
}
