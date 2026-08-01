//! `ChioKernel` guard evaluation, runtime admission, and tool dispatch.
//!
//! Holds parent-request continuation, guard execution, runtime admission
//! hook invocation, the tool-dispatch entrypoints, and child-receipt
//! recording.

use crate::budget_store::BudgetReverseHoldDecision;
use chio_log_redact::redacted;

use super::*;

pub(crate) struct GuardRunError {
    pub(crate) error: KernelError,
    pub(crate) evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
}

impl GuardRunError {
    fn new(error: KernelError, evidence: Vec<chio_core::receipt::metadata::GuardEvidence>) -> Self {
        Self { error, evidence }
    }
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
pub(crate) async fn dispatch_nested_call_within_budget<F, T>(
    call: F,
    budget: std::time::Duration,
) -> Result<T, KernelError>
where
    F: std::future::Future<Output = Result<T, KernelError>>,
{
    async fn bounded<F, T>(
        call: F,
        budget: std::time::Duration,
        timer_available: bool,
    ) -> Result<T, KernelError>
    where
        F: std::future::Future<Output = Result<T, KernelError>>,
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
        if self.load_durable_admission_receipt(receipt_id)?.is_some() {
            return Ok(true);
        }
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
        if let Some(receipt) = self.load_durable_admission_receipt(receipt_id)? {
            return Ok(Some(LocalReceiptArtifact::Tool(Box::new(receipt))));
        }
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

    pub(crate) fn unwind_pre_dispatch_monetary_invocation(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        charge_result: Option<&BudgetChargeResult>,
        payment_authorization: Option<&PaymentAuthorization>,
    ) -> Result<Option<BudgetReverseHoldDecision>, KernelError> {
        if let Some(authorization) = payment_authorization {
            let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "payment authorization present without configured adapter".to_string(),
                )
            })?;
            let refund_amount = ChioKernel::mustprepay_quoted_amount(request).or_else(|| {
                charge_result.map(|charge| (charge.cost_charged, charge.currency.clone()))
            });
            let (unwind_result, expected_status) = if authorization.state.is_final() {
                let (amount_units, currency) = refund_amount.ok_or_else(|| {
                    KernelError::Internal(
                        "final payment authorization omitted a refundable amount".to_string(),
                    )
                })?;
                (
                    adapter.refund(
                        &authorization.authorization_id,
                        amount_units,
                        &currency,
                        &request.request_id,
                    ),
                    RailSettlementStatus::Refunded,
                )
            } else {
                (
                    adapter.release(&authorization.authorization_id, &request.request_id),
                    RailSettlementStatus::Released,
                )
            };
            match unwind_result {
                Ok(result) if result.settlement_status == expected_status => {}
                Ok(_) => {
                    return Err(KernelError::Internal(
                        "payment unwind returned an unconfirmed status".to_string(),
                    ));
                }
                Err(_) => {
                    return Err(KernelError::Internal(
                        "payment unwind acknowledgement was not confirmed".to_string(),
                    ));
                }
            }
        }

        let Some(charge) = charge_result else {
            return Ok(None);
        };

        if charge.invocation_capture.is_some() {
            Ok(Some(self.cancel_captured_monetary_before_dispatch(
                &cap.id, charge,
            )?))
        } else {
            Ok(Some(self.reverse_budget_charge(&cap.id, charge)?))
        }
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
        match hook.evaluate(&context) {
            Ok(decision) => decision,
            Err(error) => RuntimeAdmissionDecision::deny(
                format!(
                    "runtime admission hook \"{}\" error (fail-closed): {error}",
                    hook.name()
                ),
                Some(serde_json::json!({
                    "runtime_admission": {
                        "hook": hook.name(),
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
        hook.release_reserved(metadata)
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
        merge_metadata_objects(
            metadata,
            Some(serde_json::json!({ "chio_runtime": retained })),
        )
    }

    pub(crate) fn release_runtime_admission_reservations_for_pre_dispatch_denial(
        &self,
        metadata: Option<serde_json::Value>,
    ) -> (Option<serde_json::Value>, bool) {
        let Some(metadata_value) = metadata else {
            return (None, true);
        };
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            return (Some(metadata_value), true);
        };

        match hook.release_reserved(&metadata_value) {
            Ok(()) => (Some(metadata_value), true),
            Err(error) => {
                warn!(
                    hook = hook.name(),
                    reason = %redacted!(&error),
                    "runtime admission reservation release failed on pre-dispatch denial"
                );
                (
                    merge_metadata_objects(
                        Some(metadata_value),
                        Some(serde_json::json!({
                            "chio_runtime": {
                                "reservation_release_failed": true,
                                "reservation_retained": true
                            }
                        })),
                    ),
                    false,
                )
            }
        }
    }

    /// Forward the validated request and optionally report actual invocation
    /// cost, enforcing the configured dispatch budget. This is the phase-level
    /// dispatch entry point (`ToolEvaluator::dispatch`), so a custom evaluator or
    /// phase-level caller cannot bypass the deadline and hang indefinitely on a
    /// wedged tool server; it matches the budget the full evaluate path enforces.
    #[cfg(test)]
    pub(crate) async fn dispatch_tool_call_with_cost(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        self.validate_required_execution_nonce(request, &request.capability)?;
        let request_has_monetary_grant = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )?
        .iter()
        .any(|matching| {
            matching.grant.max_cost_per_invocation.is_some()
                || matching.grant.max_total_cost.is_some()
        });
        if has_monetary_grant || request_has_monetary_grant {
            return Err(KernelError::DirectDispatchUnavailable);
        }
        self.reserve_presented_execution_nonce(request)?;
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
    #[cfg(test)]
    pub(crate) async fn dispatch_within_budget(
        &self,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        let server = self
            .tool_servers
            .get(&request.server_id)
            .cloned()
            .ok_or_else(|| {
                KernelError::ToolNotRegistered(format!(
                    "server \"{}\" / tool \"{}\"",
                    request.server_id, request.tool_name
                ))
            })?;
        self.dispatch_resolved_server_within_budget(server, request, has_monetary_grant)
            .await
    }

    pub(crate) async fn dispatch_resolved_server_within_budget(
        &self,
        server: Arc<dyn ToolServerConnection>,
        request: &ToolCallRequest,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        let Some(budget) = self
            .config
            .deadlines
            .dispatch_budget_for(&request.server_id)
        else {
            return Self::invoke_resolved_server(
                server,
                request.tool_name.clone(),
                request.arguments.clone(),
                has_monetary_grant,
            )
            .await;
        };

        let timer_available = dispatch_timer_available();
        let multi_thread = matches!(
            tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()),
            Ok(tokio::runtime::RuntimeFlavor::MultiThread)
        );
        if !multi_thread {
            let call = Self::invoke_resolved_server(
                server,
                request.tool_name.clone(),
                request.arguments.clone(),
                has_monetary_grant,
            );
            if timer_available {
                return match tokio::time::timeout(budget, call).await {
                    Ok(result) => result,
                    Err(_elapsed) => Err(dispatch_deadline_exceeded(budget)),
                };
            }
            return call.await;
        }

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

    /// Persist a single already-signed child receipt: a commit-bounded durable
    /// append under the kernel-wide receipt write lock, then the in-process log.
    /// Child receipts hold that lock, so an unbounded wait would let a wedged
    /// writer pin every subsequent receipt write; the bounded append fails
    /// closed on timeout. The in-process log is appended only after the durable
    /// append succeeds, so a failed append never records a child receipt that is
    /// absent from the durable log.
    pub(crate) fn record_child_receipt(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), KernelError> {
        let receipt_store_write = self
            .receipt_store_write_lock
            .lock()
            .map_err(|_| KernelError::Internal("receipt store write lock poisoned".to_string()))?;
        self.with_receipt_store(|store| {
            Ok(store.append_child_receipt_with_timeout(
                receipt,
                self.config.deadlines.receipt_append_budget(),
            )?)
        })?;
        drop(receipt_store_write);
        self.append_child_receipt_to_local_log(receipt.clone());
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
