//! `ChioKernel` guard evaluation, runtime admission, and tool dispatch.
//!
//! Holds parent-request continuation, guard execution, runtime admission
//! hook invocation, the tool-dispatch entrypoints, and child-receipt
//! recording.

use chio_kernel_core::{guard_projection_allows_continuation, guard_step_admits, GuardStep};

use super::*;

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
    Committed,
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
        for guard in &self.guards {
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
                    reason: "session request cancelled while runtime readiness was pending"
                        .to_string(),
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
                            "session request completed before dispatch"
                        }
                        crate::session::DispatchStartFailure::CancellationRequested => {
                            "session request cancelled before dispatch"
                        }
                        crate::session::DispatchStartFailure::SessionAnchorChanged => {
                            "session authorization changed before dispatch"
                        }
                    }
                    .to_string(),
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

    pub(crate) fn has_local_receipt_id(&self, receipt_id: &str) -> bool {
        let chio_receipt_match = match self.receipt_log.lock() {
            Ok(log) => log
                .receipts()
                .iter()
                .any(|receipt| receipt.id == receipt_id),
            Err(poisoned) => poisoned
                .into_inner()
                .receipts()
                .iter()
                .any(|receipt| receipt.id == receipt_id),
        };
        if chio_receipt_match {
            return true;
        }

        match self.child_receipt_log.lock() {
            Ok(log) => log
                .receipts()
                .iter()
                .any(|receipt| receipt.id == receipt_id),
            Err(poisoned) => poisoned
                .into_inner()
                .receipts()
                .iter()
                .any(|receipt| receipt.id == receipt_id),
        }
    }

    pub(crate) fn local_receipt_artifact(&self, receipt_id: &str) -> Option<LocalReceiptArtifact> {
        let tool_match = match self.receipt_log.lock() {
            Ok(log) => log
                .receipts()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Tool(Box::new(receipt))),
            Err(poisoned) => poisoned
                .into_inner()
                .receipts()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Tool(Box::new(receipt))),
        };
        if tool_match.is_some() {
            return tool_match;
        }

        match self.child_receipt_log.lock() {
            Ok(log) => log
                .receipts()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Child(Box::new(receipt))),
            Err(poisoned) => poisoned
                .into_inner()
                .receipts()
                .iter()
                .find(|receipt| receipt.id == receipt_id)
                .cloned()
                .map(|receipt| LocalReceiptArtifact::Child(Box::new(receipt))),
        }
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

    pub(crate) fn record_observed_capability_snapshot(
        &self,
        capability: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let parent_capability_id = capability
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        let _ = self.with_receipt_store(|store| {
            Ok(store.record_capability_snapshot(capability, parent_capability_id)?)
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

        let mut evidence = Vec::new();
        for guard in &self.guards {
            let guard_name = guard.name();
            let evaluation =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| guard.evaluate(&ctx)))
                    .unwrap_or_else(|_| {
                        Err(KernelError::GuardDenied(
                            "guard evaluation panicked (fail-closed)".to_string(),
                        ))
                    });
            let step = match &evaluation {
                Ok(decision) => GuardStep::from(decision.verdict),
                Err(_) => GuardStep::Error,
            };
            let projected_allows = guard_step_admits(step);
            let continuation_evidence = match &evaluation {
                Ok(decision)
                    if guard_projection_allows_continuation(projected_allows, step)
                        && decision.verdict == Verdict::Allow =>
                {
                    Some(&decision.evidence)
                }
                _ => None,
            };
            if let Some(continuation_evidence) = continuation_evidence {
                evidence.extend_from_slice(continuation_evidence);
                debug!("guard passed");
                continue;
            }

            match evaluation {
                Ok(decision) => {
                    evidence.extend(decision.evidence);
                    match decision.verdict {
                        Verdict::Deny => {
                            return Err(GuardRunError::new(
                                KernelError::GuardDenied(format!(
                                    "guard \"{guard_name}\" denied the request"
                                )),
                                evidence,
                            ));
                        }
                        Verdict::PendingApproval => {
                            // The `Guard` trait does not carry the HITL approval flow; that runs via
                            // `ApprovalGuard::evaluate`. A `Guard` returning `PendingApproval` is an
                            // unsupported state, so fail closed.
                            return Err(GuardRunError::new(
                                KernelError::GuardDenied(
                                    format!(
                                        "guard \"{guard_name}\" returned an unsupported approval verdict"
                                    ),
                                ),
                                evidence,
                            ));
                        }
                        Verdict::Allow => {
                            return Err(GuardRunError::new(
                                KernelError::GuardDenied(format!(
                                    "guard \"{guard_name}\" failed the admission projection"
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
                            "guard \"{guard_name}\" error (fail-closed): {e}"
                        )),
                        evidence,
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

    /// Forward the validated request and optionally report actual invocation cost.
    pub(crate) async fn dispatch_tool_call_with_cost(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        self.require_presented_execution_nonce(request, &request.capability)?;
        self.dispatch_tool_call_with_cost_after_nonce_check(request, has_monetary_grant)
            .await
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

        // Try streaming first regardless of monetary mode.
        if let Some(stream) = server
            .invoke_stream(&request.tool_name, request.arguments.clone(), None)
            .await?
        {
            return Ok((ToolServerOutput::Stream(stream), None));
        }

        if has_monetary_grant {
            let (value, cost) = server
                .invoke_with_cost(&request.tool_name, request.arguments.clone(), None)
                .await?;
            Ok((ToolServerOutput::Value(value), cost))
        } else {
            let value = server
                .invoke(&request.tool_name, request.arguments.clone(), None)
                .await?;
            Ok((ToolServerOutput::Value(value), None))
        }
    }

    /// Build a denial response, including FinancialReceiptMetadata when the
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
                    ChildReceiptAppendDisposition::Committed => {
                        if !receipts.is_empty() {
                            receipts.remove(0);
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
            self.with_receipt_store(|store| Ok(store.append_child_receipt_returning_seq(receipt)?))
        }));
        let stored_seq = match append_result {
            Ok(Ok(stored_seq)) => stored_seq,
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
        };
        self.append_child_receipt_to_local_log(receipt.clone());
        if let Some(seq) = stored_seq.flatten() {
            if self.should_checkpoint_after_seq(seq) {
                let checkpoint_result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.maybe_trigger_checkpoint_locked(seq)
                    }));
                match checkpoint_result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(ChildReceiptRecordError {
                            error,
                            disposition: ChildReceiptAppendDisposition::Committed,
                        });
                    }
                    Err(_) => {
                        return Err(ChildReceiptRecordError {
                            error: KernelError::Internal(
                                "receipt checkpoint creation panicked after child append"
                                    .to_string(),
                            ),
                            disposition: ChildReceiptAppendDisposition::Committed,
                        });
                    }
                }
            }
        }
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
