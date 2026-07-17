//! `ChioKernel` capability and budget validation.
//!
//! Holds capability issuance/revocation, tool-server event drains, portable
//! verdict helpers, and budget charge/reconcile helpers. Governed-admission
//! validation lives in `governed_validation.rs`.

use chio_log_redact::redacted;

use self::responses::{AllowResponseNonce, FinalizeToolOutputCostContext};
use super::*;
use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetEventAuthority,
    BudgetHoldMutationDecision, BudgetReconcileHoldDecision, BudgetReconcileHoldRequest,
    BudgetReverseHoldDecision, BudgetReverseHoldRequest,
};

/// A settled MustPrepay prepayment captured before a reserve-for-caller execution
/// nonce is minted, paired with the rail reference that funded it.
///
/// The `authorization` is retained so a reservation tear-down can refund the
/// capture (the payer must not stay charged for a reservation that was denied).
/// The `payment_reference` is the rail transaction id of the capture (or the
/// authorization id when the rail settled at authorize time); it is carried onto
/// the reserved budget hold so the downstream `/v1/reconcile` receipt can name
/// the transaction that paid for the spend.
pub(crate) struct ReservedPrepayment {
    pub(crate) authorization: PaymentAuthorization,
    pub(crate) payment_reference: Option<String>,
}

impl ChioKernel {
    /// Issue a new capability for an agent.
    ///
    /// The kernel delegates issuance to the configured capability authority.
    pub fn issue_capability(
        &self,
        subject: &chio_core::PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let capability = self
            .capability_authority
            .issue_capability(subject, scope, ttl_seconds)?;

        info!(
            capability_id = %capability.id,
            subject = %subject.to_hex(),
            ttl = ttl_seconds,
            issuer = %capability.issuer.to_hex(),
            "issuing capability"
        );

        self.record_observed_capability_snapshot(&capability)?;

        Ok(capability)
    }

    /// Revoke a capability and all descendants in its delegation subtree.
    ///
    /// When a root capability is revoked, every capability whose
    /// `delegation_chain` contains the revoked ID will also be rejected
    /// on presentation (the kernel checks all chain entries against the
    /// revocation store).
    pub fn revoke_capability(&self, capability_id: &CapabilityId) -> Result<(), KernelError> {
        info!(capability_id = %capability_id, "revoking capability");
        let _ = self.with_revocation_store(|store| Ok(store.revoke(capability_id)?))?;
        Ok(())
    }

    /// Whether a capability id is present in the installed revocation store.
    ///
    /// Callers that authorize a token minted outside the kernel (an HTTP
    /// authority projecting a presented capability, for example) use this to
    /// check the caller's token against revocations, since the kernel's own
    /// revocation check runs against the internal capability it evaluates.
    pub fn is_capability_revoked(&self, capability_id: &str) -> Result<bool, KernelError> {
        self.with_revocation_store(|store| Ok(store.is_revoked(capability_id)?))
    }

    /// Read-only access to the receipt log.
    pub fn receipt_log(&self) -> ReceiptLog {
        match self.receipt_log.lock() {
            Ok(log) => log.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn child_receipt_log(&self) -> ChildReceiptLog {
        match self.child_receipt_log.lock() {
            Ok(log) => log.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    #[must_use]
    pub fn post_invocation_hook_count(&self) -> usize {
        self.post_invocation_pipeline.len()
    }

    pub async fn drain_tool_server_events_async(
        &self,
    ) -> Result<Vec<ToolServerEvent>, KernelError> {
        let mut events = Vec::new();
        let mut first_error = None;
        for (server_id, server) in &self.tool_servers {
            match server.drain_events().await {
                Ok(mut server_events) => events.append(&mut server_events),
                Err(error) => {
                    warn!(
                        server_id = %server_id,
                        reason = %redacted!(&error),
                        "failed to drain tool server events"
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if events.is_empty() {
            if let Some(error) = first_error {
                return Err(error);
            }
        }
        Ok(events)
    }

    pub fn try_drain_tool_server_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        block_on_async_tool_dispatch(self.drain_tool_server_events_async())
    }

    pub fn drain_tool_server_events(&self) -> Vec<ToolServerEvent> {
        match self.try_drain_tool_server_events() {
            Ok(events) => events,
            Err(error) => {
                warn!(
                    reason = %redacted!(&error),
                    "failed to drain tool server events"
                );
                Vec::new()
            }
        }
    }

    pub fn register_session_pending_url_elicitation(
        &self,
        session_id: &SessionId,
        elicitation_id: impl Into<String>,
        related_task_id: Option<String>,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.register_pending_url_elicitation(elicitation_id, related_task_id);
            Ok(())
        })
    }

    pub fn register_session_required_url_elicitations(
        &self,
        session_id: &SessionId,
        elicitations: &[CreateElicitationOperation],
        related_task_id: Option<&str>,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.register_required_url_elicitations(elicitations, related_task_id);
            Ok(())
        })
    }

    pub fn queue_session_elicitation_completion(
        &self,
        session_id: &SessionId,
        elicitation_id: &str,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_elicitation_completion(elicitation_id);
            Ok(())
        })
    }

    pub fn queue_session_late_event(
        &self,
        session_id: &SessionId,
        event: LateSessionEvent,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_late_event(event);
            Ok(())
        })
    }

    pub fn queue_session_tool_server_event(
        &self,
        session_id: &SessionId,
        event: ToolServerEvent,
    ) -> Result<(), KernelError> {
        self.with_session_mut(session_id, |session| {
            session.queue_tool_server_event(event);
            Ok(())
        })
    }

    pub fn queue_session_tool_server_events(
        &self,
        session_id: &SessionId,
    ) -> Result<(), KernelError> {
        let events = self.try_drain_tool_server_events()?;
        self.with_session_mut(session_id, |session| {
            for event in events {
                session.queue_tool_server_event(event);
            }
            Ok(())
        })
    }

    pub async fn queue_session_tool_server_events_async(
        &self,
        session_id: &SessionId,
    ) -> Result<(), KernelError> {
        let events = self.drain_tool_server_events_async().await?;
        self.with_session_mut(session_id, |session| {
            for event in events {
                session.queue_tool_server_event(event);
            }
            Ok(())
        })
    }

    pub fn drain_session_late_events(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<LateSessionEvent>, KernelError> {
        self.with_session_mut(session_id, |session| Ok(session.take_late_events()))
    }

    pub fn ca_count(&self) -> usize {
        self.config.ca_public_keys.len()
    }

    pub fn public_key(&self) -> chio_core::PublicKey {
        self.config.keypair.public_key()
    }

    /// Set the configured capability-token crypto floor.
    ///
    /// Boot paths that load `policy.crypto_floor` must call this before
    /// accepting traffic when they do not use [`Self::with_hybrid_signing_backend`].
    pub fn set_capability_crypto_floor(&mut self, floor: KernelCryptoFloor) {
        self.capability_crypto_floor = floor;
    }

    pub fn capability_issuer_is_trusted(&self, issuer: &chio_core::PublicKey) -> bool {
        self.trusted_issuer_keys().contains(issuer)
    }

    /// Verify the capability's signature against the trusted CA keys or the
    /// kernel's own key (for locally-issued capabilities).
    /// Resolve the trusted-issuer set for capability verification.
    ///
    /// This combines the configured CA public keys, the capability
    /// authority's trusted keys, and the kernel's own public key. The
    /// method is also used by the chio-kernel-core delegation path
    /// so the portable TCB verifier sees the same trust set as the
    /// inline check.
    pub(crate) fn trusted_issuer_keys(&self) -> Vec<chio_core::PublicKey> {
        let mut trusted = self.config.ca_public_keys.clone();
        for authority_pk in self.capability_authority.trusted_public_keys() {
            if !trusted.contains(&authority_pk) {
                trusted.push(authority_pk);
            }
        }
        let kernel_pk = self.config.keypair.public_key();
        if !trusted.contains(&kernel_pk) {
            trusted.push(kernel_pk);
        }
        trusted
    }

    /// Spec: PROTOCOL.md requires production kernels to route every
    /// capability admission through `verify_capability_full`; this wrapper
    /// is the kernel-side enforcement of that MUST.
    pub(crate) fn verify_capability_full_pre_admit(
        &self,
        cap: &CapabilityToken,
        remote_kernel_id: Option<&str>,
        now: u64,
    ) -> Result<(), String> {
        let trusted = self.trusted_issuer_keys();
        let clock = chio_kernel_core::FixedClock::new(now);
        let peer_profile = self.capability_negotiation_for_remote(remote_kernel_id, now)?;
        let trust_resolver = self.capability_trust_root_resolver_snapshot();
        let mut budgets = chio_kernel_core::NoopBudgetRegistry;

        chio_kernel_core::verify_capability_full(
            cap,
            &trusted,
            &clock,
            capability_crypto_floor(self.capability_crypto_floor),
            &peer_profile,
            &trust_resolver,
            &mut budgets,
        )
        .map(|_| ())
        .map_err(|error| chio_kernel_core::KernelCoreError::InvalidCapability(error).deny_reason())
    }

    /// The hosted `evaluate_tool_call_*` paths route the full chain
    /// through [`Self::verify_capability_full_pre_admit`], which runs
    /// the production verifier with `NoopBudgetRegistry` so a token
    /// that subsequently fails any other check does not consume the
    /// parent's share. This method then performs the deferred admit
    /// against the kernel's long-lived `budget_registry`. The lock is
    /// held only for the duration of the admit call, matching the
    /// portable hot path.
    ///
    /// Errors are returned as plain strings so the caller can route
    /// them through the existing deny-response paths without taking
    /// a `KernelError` dependency on the verifier shape.
    ///
    /// The split between pre-admit verification and budget admission
    /// enforces the ordering rule "signature first, admit last", so a
    /// denied request never starves later valid siblings.
    /// Admit `cap`'s sibling-sum budget share under its parent, acquiring one
    /// per-evaluation holder lease on the child admission edge.
    ///
    /// Returns `Ok(true)` when THIS evaluation acquired a lease: the capability
    /// has a parent and the admit succeeded, whether it INSERTED a fresh edge
    /// or took an additional holder on an edge an overlapping evaluation
    /// already inserted (an idempotent re-admit). Returns `Ok(false)` only when
    /// the capability has no parent to admit against (no lease exists to
    /// release). A failed admit (oversubscribe / cap-exceed / different share)
    /// acquires NO lease and returns `Err`.
    ///
    /// The lease increment happens inside `try_admit_child` under the registry
    /// lock, so it is atomic with the insert/holder decision (no TOCTOU). The
    /// boolean tells a pre-dispatch cleanup path whether THIS evaluation holds a
    /// lease it must release: exactly the evaluations that acquired a lease
    /// release one (via `release_admitted_capability_budget`), and the edge is
    /// freed only when the last holder releases. Reference counting - rather
    /// than a "newly inserted" owner flag - is required because overlapping
    /// evaluations of the same delegated capability concurrently depend on the
    /// single registry edge; freeing it on the inserting evaluation's cleanup
    /// would return a re-admitting sibling's live share and let an
    /// oversubscribing sibling bypass the parent cap.
    pub(crate) fn admit_capability_budget(&self, cap: &CapabilityToken) -> Result<bool, String> {
        if let Some(parent_link) = cap.delegation_chain.last() {
            use chio_kernel_core::BudgetRegistry;
            // A delegated reserve-for-caller hold left open by a prior process
            // still consumes its parent's sibling-sum share, but that admission
            // was lost when this kernel rebuilt its in-memory registry. Deny this
            // delegated admission fail-closed until every such hold has closed, so
            // a sibling is never admitted against the parent as if the still-open
            // reservation consumed nothing.
            self.enforce_restart_reserved_hold_gate()?;
            let proposed_share = cap
                .budget_share_bps
                .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS);
            let mut budgets = match self.budget_registry.lock() {
                Ok(guard) => guard,
                Err(_poisoned) => {
                    // Fail closed on a poisoned monetary lock: a half-mutated
                    // budget registry must never admit a child on a lucky recovery.
                    self.record_tcb_lock_poison("budget_registry");
                    return Err("budget registry lock poisoned; failing closed".to_string());
                }
            };
            budgets
                .try_admit_child(
                    parent_link.capability_id.as_str(),
                    cap.id.clone(),
                    proposed_share,
                )
                .map_err(|err| err.to_string())?;
            // The admit succeeded against a parent link, so this evaluation now
            // holds a lease it is responsible for releasing on cleanup.
            return Ok(true);
        }

        Ok(false)
    }

    pub(crate) fn release_admitted_capability_budget(
        &self,
        cap: &CapabilityToken,
    ) -> Result<(), String> {
        if let Some(parent_link) = cap.delegation_chain.last() {
            use chio_kernel_core::BudgetRegistry;
            let proposed_share = cap
                .budget_share_bps
                .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS);
            let mut budgets = match self.budget_registry.lock() {
                Ok(guard) => guard,
                Err(_poisoned) => {
                    self.record_tcb_lock_poison("budget_registry");
                    return Err("budget registry lock poisoned; failing closed".to_string());
                }
            };
            budgets
                .release_child(
                    parent_link.capability_id.as_str(),
                    cap.id.as_str(),
                    proposed_share,
                )
                .map_err(|err| err.to_string())?;
        }

        Ok(())
    }

    fn lock_reserved_sibling_shares(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, ReservedSiblingShare>> {
        match self.reserved_sibling_shares.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Budget hold ids that currently hold a reserve-for-caller sibling share
    /// open. The TTL reaper uses this to release the parent's headroom for the
    /// exact holds it settles.
    pub(crate) fn tracked_reserved_sibling_hold_ids(&self) -> Vec<String> {
        self.lock_reserved_sibling_shares()
            .keys()
            .cloned()
            .collect()
    }

    /// Record that a reserve-for-caller hold keeps `cap`'s sibling-sum share
    /// admitted until the hold closes, keyed by the hold id. Roots hold no
    /// sibling share (empty delegation chain) and record nothing.
    pub(crate) fn record_reserved_sibling_share(&self, hold_id: &str, cap: &CapabilityToken) {
        let Some(parent_link) = cap.delegation_chain.last() else {
            return;
        };
        let share_bps = cap
            .budget_share_bps
            .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS);
        self.lock_reserved_sibling_shares().insert(
            hold_id.to_string(),
            ReservedSiblingShare {
                parent_token_id: parent_link.capability_id.clone(),
                child_token_id: cap.id.clone(),
                share_bps,
            },
        );
    }

    /// Release the sibling-sum share a reserve-for-caller hold kept admitted,
    /// once the hold has closed (reconciled by nonce or reaped). Idempotent: an
    /// unknown hold id is a no-op. A registry release error is logged rather
    /// than propagated so hold settlement is never blocked by admission
    /// bookkeeping (release cannot mismatch because the exact admitted share was
    /// recorded).
    pub(crate) fn release_reserved_sibling_share_for_hold(&self, hold_id: &str) {
        let Some(entry) = self.lock_reserved_sibling_shares().remove(hold_id) else {
            return;
        };
        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(error) = budgets.release_child(
            &entry.parent_token_id,
            &entry.child_token_id,
            entry.share_bps,
        ) {
            warn!(
                hold_id = %hold_id,
                reason = %redacted!(&error),
                "failed to release reserved sibling share for a closed hold"
            );
        }
    }

    fn lock_restart_reserved_hold_gate(
        &self,
    ) -> std::sync::MutexGuard<'_, crate::kernel::RestartReservedHoldGate> {
        match self.restart_reserved_hold_gate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Rebuild the delegated reserve-for-caller accounting from the durable
    /// budget store after a restart, arming the fail-closed gate consulted on
    /// every delegated admission.
    ///
    /// A delegated reservation keeps its child's sibling-sum share admitted
    /// against the parent while its durable hold stays open, but that admission
    /// lives only in this process's in-memory registry. A mediation kernel built
    /// fresh over a populated budget store therefore starts with an empty
    /// sibling-sum map even though open delegated reservations from the prior
    /// process are still consuming their parents' budget. The durable hold record
    /// carries neither the immediate parent capability id nor the child and
    /// parent shares, so the in-memory reservation cannot be reconstructed. Rather
    /// than admit a sibling against an unaccounted reservation, the kernel gates
    /// delegated admission fail-closed until every such open hold has closed.
    ///
    /// Fail-closed: a store read error aborts here so kernel startup can refuse to
    /// serve mediation over a store it could not inspect. When the store reports
    /// no open holds the gate stays clear; when it can enumerate its reserved
    /// holds the gate tracks exactly those still open; when it cannot enumerate
    /// them yet reports open holds the gate denies until the open-hold count
    /// drains to zero.
    pub fn arm_restart_reserved_hold_gate(&self) -> Result<(), KernelError> {
        let gate = match self
            .with_budget_store(|store| Ok(store.list_open_delegated_reserved_hold_ids()?))?
        {
            Some(hold_ids) => {
                let pending: std::collections::HashSet<String> = hold_ids.into_iter().collect();
                if pending.is_empty() {
                    crate::kernel::RestartReservedHoldGate::Clear
                } else {
                    crate::kernel::RestartReservedHoldGate::PendingHolds(pending)
                }
            }
            None => {
                let open = self.with_budget_store(|store| Ok(store.count_open_holds()?))?;
                if open == 0 {
                    crate::kernel::RestartReservedHoldGate::Clear
                } else {
                    crate::kernel::RestartReservedHoldGate::PendingOpaqueCount
                }
            }
        };
        *self.lock_restart_reserved_hold_gate() = gate;
        Ok(())
    }

    /// Deny a delegated admission fail-closed while a delegated reserve-for-caller
    /// hold from a prior process is still open and unaccounted (see
    /// [`Self::arm_restart_reserved_hold_gate`]). Returns `Ok(())` once the gate is
    /// clear so the admission proceeds. Idempotently drains holds that have since
    /// closed, clearing the gate exactly when the last one settles so mediation
    /// resumes without a restart. Fail-closed on a store read error and on any
    /// hold that stays open.
    fn enforce_restart_reserved_hold_gate(&self) -> Result<(), String> {
        let mut gate = self.lock_restart_reserved_hold_gate();
        match &*gate {
            crate::kernel::RestartReservedHoldGate::Clear => Ok(()),
            crate::kernel::RestartReservedHoldGate::PendingHolds(pending) => {
                let mut still_open = std::collections::HashSet::new();
                for hold_id in pending {
                    let open = self
                        .with_budget_store(|store| {
                            Ok(match store.get_budget_hold(hold_id)? {
                                Some(hold) => hold.disposition.is_open(),
                                None => false,
                            })
                        })
                        .map_err(|error| error.to_string())?;
                    if open {
                        still_open.insert(hold_id.clone());
                    }
                }
                if still_open.is_empty() {
                    *gate = crate::kernel::RestartReservedHoldGate::Clear;
                    Ok(())
                } else {
                    let count = still_open.len();
                    *gate = crate::kernel::RestartReservedHoldGate::PendingHolds(still_open);
                    Err(format!(
                        "delegated reserve-for-caller hold(s) from a prior process remain open \
                         ({count}); a sibling cannot be admitted until they are reconciled or \
                         reaped, because their sibling-sum share cannot be rebuilt from the \
                         durable record"
                    ))
                }
            }
            crate::kernel::RestartReservedHoldGate::PendingOpaqueCount => {
                let open = self
                    .with_budget_store(|store| Ok(store.count_open_holds()?))
                    .map_err(|error| error.to_string())?;
                if open == 0 {
                    *gate = crate::kernel::RestartReservedHoldGate::Clear;
                    Ok(())
                } else {
                    Err(format!(
                        "open budget hold(s) from a prior process remain ({open}) and the store \
                         cannot enumerate reserved holds; a delegated sibling cannot be admitted \
                         until they are reconciled or reaped"
                    ))
                }
            }
        }
    }

    /// Run the portable pure-compute verdict path provided by
    /// `chio-kernel-core`.
    ///
    /// This exposes the same synchronous checks the core kernel performs
    /// (capability signature, issuer trust, time bounds, subject binding,
    /// scope match, sync guard pipeline) in isolation from the
    /// `chio-kernel`-only concerns (budget mutation, revocation lookup,
    /// governed-transaction evaluation, tool dispatch, receipt
    /// persistence).
    ///
    /// Adapters that run the kernel on constrained platforms (wasm32,
    /// edge workers, mobile via FFI) should prefer this entry point --
    /// it does not require a tokio runtime, a sqlite database, or any
    /// IO adapter. The full `evaluate_tool_call_*` API remains the
    /// authoritative path for the desktop sidecar.
    ///
    /// Verified-core boundary note:
    /// `formal/proof-manifest.toml` treats this shell method as the one
    /// `chio-kernel` entrypoint inside the current bounded verified core,
    /// because it delegates directly to `chio_kernel_core::evaluate` after
    /// supplying trusted issuers and portable guard/context wiring.
    pub fn evaluate_portable_verdict<'a>(
        &self,
        capability: &'a CapabilityToken,
        request: &chio_kernel_core::PortableToolCallRequest,
        guards: &'a [&'a dyn chio_kernel_core::Guard],
        clock: &'a dyn chio_kernel_core::Clock,
        session_filesystem_roots: Option<&'a [String]>,
    ) -> chio_kernel_core::EvaluationVerdict {
        let trusted = self.trusted_issuer_keys();
        let peer_profile = match self.capability_negotiation_for_remote(None, clock.now_unix_secs())
        {
            Ok(profile) => profile,
            // Fail closed: a negotiation error denies rather than falling back
            // to the permissive default profile.
            Err(reason) => {
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some(format!(
                        "capability negotiation failed; denying fail-closed: {reason}"
                    )),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        let trust_resolver = self.capability_trust_root_resolver_snapshot();
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => {
                // The monetary lock is poisoned: a panic left the registry in an
                // unknown state. Deny fail-closed and trip the degraded flag so
                // later evaluations are denied at the pre-dispatch gate too.
                self.record_tcb_lock_poison("budget_registry");
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some("budget registry lock poisoned; denying fail-closed".to_string()),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        chio_kernel_core::evaluate_with_full_floor(
            chio_kernel_core::EvaluateInput {
                request,
                capability,
                trusted_issuers: &trusted,
                clock,
                guards,
                session_filesystem_roots,
            },
            capability_crypto_floor(self.capability_crypto_floor),
            &peer_profile,
            &trust_resolver,
            &mut *budgets,
        )
    }

    pub fn register_budget_parent(
        &self,
        parent_token_id: String,
        parent_share_bps: u16,
    ) -> Result<(), chio_kernel_core::BudgetSplitError> {
        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Recovering the guard keeps setup working, but tripping the flag
                // means the next evaluation is denied at the pre-dispatch gate.
                self.record_tcb_lock_poison("budget_registry");
                poisoned.into_inner()
            }
        };
        budgets.register_parent(parent_token_id, parent_share_bps)
    }

    pub fn evict_budget_parent(&self, parent_token_id: &str) {
        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                self.record_tcb_lock_poison("budget_registry");
                poisoned.into_inner()
            }
        };
        budgets.evict_parent(parent_token_id);
    }

    /// Check the revocation store for the capability and its entire
    /// delegation chain. If any ancestor is revoked, the capability is
    /// rejected.
    pub(crate) fn check_revocation(&self, cap: &CapabilityToken) -> Result<(), KernelError> {
        if self.with_revocation_store(|store| Ok(store.is_revoked(&cap.id)?))? {
            return Err(KernelError::CapabilityRevoked(cap.id.clone()));
        }
        for link in &cap.delegation_chain {
            if self.with_revocation_store(|store| Ok(store.is_revoked(&link.capability_id)?))? {
                return Err(KernelError::DelegationChainRevoked(
                    link.capability_id.clone(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_delegation_admission(
        &self,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        // When the `delegation` feature is on, consult the installed
        // `RevocationView` snapshot before re-running the validation chain
        // validation. Fail-closed: a revoked ancestor or leaf denies
        // dispatch even if the chain is otherwise valid. This is a
        // no-op (`Ok(())`) when no view is installed.
        #[cfg(feature = "delegation")]
        delegation::consult_revocation_view(cap, self.revocation_view.as_ref())?;

        if cap.delegation_chain.is_empty() {
            return Ok(());
        }

        chio_core::capability::attenuation::validate_delegation_chain(
            &cap.delegation_chain,
            Some(self.config.max_delegation_depth),
        )
        .map_err(|error| KernelError::DelegationInvalid(error.to_string()))?;

        let Some(last_link) = cap.delegation_chain.last() else {
            return Err(KernelError::DelegationInvalid(
                "delegation chain disappeared after validation".to_string(),
            ));
        };
        if last_link.delegatee != cap.subject {
            return Err(KernelError::DelegationInvalid(format!(
                "leaf capability subject {} does not match final delegation delegatee {}",
                cap.subject.to_hex(),
                last_link.delegatee.to_hex()
            )));
        }

        let mut ancestor_snapshots = Vec::with_capacity(cap.delegation_chain.len());
        for (index, link) in cap.delegation_chain.iter().enumerate() {
            let snapshot = self
                .with_receipt_store(
                    |store| Ok(store.get_capability_snapshot(&link.capability_id)?),
                )?
                .flatten()
                .ok_or_else(|| {
                    KernelError::DelegationInvalid(format!(
                        "missing capability snapshot for delegation ancestor {} at link index {}",
                        link.capability_id, index
                    ))
                })?;
            let expected_depth = index as u64;
            if snapshot.delegation_depth != expected_depth {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation ancestor {} at link index {} has stored depth {}, expected {}",
                    snapshot.capability_id, index, snapshot.delegation_depth, expected_depth
                )));
            }

            let expected_parent_capability_id = index
                .checked_sub(1)
                .map(|parent_index| cap.delegation_chain[parent_index].capability_id.as_str());
            if snapshot.parent_capability_id.as_deref() != expected_parent_capability_id {
                let observed_parent = snapshot.parent_capability_id.as_deref().unwrap_or("<root>");
                let expected_parent = expected_parent_capability_id.unwrap_or("<root>");
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation ancestor {} at link index {} is lineage-linked to {}, expected {}",
                    snapshot.capability_id, index, observed_parent, expected_parent
                )));
            }

            ancestor_snapshots.push(snapshot);
        }

        for (index, link) in cap.delegation_chain.iter().enumerate() {
            let parent_snapshot = &ancestor_snapshots[index];
            let parent_scope = scope_from_capability_snapshot(parent_snapshot)?;

            if parent_snapshot.subject_key != link.delegator.to_hex() {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} delegator {} does not match parent capability subject {}",
                    index,
                    link.delegator.to_hex(),
                    parent_snapshot.subject_key
                )));
            }
            if link.timestamp < parent_snapshot.issued_at
                || link.timestamp >= parent_snapshot.expires_at
            {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} timestamp {} is outside parent capability {} validity window [{} , {})",
                    index,
                    link.timestamp,
                    parent_snapshot.capability_id,
                    parent_snapshot.issued_at,
                    parent_snapshot.expires_at
                )));
            }

            let (
                child_capability_id,
                child_subject_key,
                child_scope,
                child_issued_at,
                child_expires_at,
                child_parent_capability_id,
            ) = if let Some(next_snapshot) = ancestor_snapshots.get(index + 1) {
                (
                    next_snapshot.capability_id.clone(),
                    next_snapshot.subject_key.clone(),
                    scope_from_capability_snapshot(next_snapshot)?,
                    next_snapshot.issued_at,
                    next_snapshot.expires_at,
                    next_snapshot.parent_capability_id.clone(),
                )
            } else {
                (
                    cap.id.clone(),
                    cap.subject.to_hex(),
                    cap.scope.clone(),
                    cap.issued_at,
                    cap.expires_at,
                    Some(link.capability_id.clone()),
                )
            };

            if child_subject_key != link.delegatee.to_hex() {
                return Err(KernelError::DelegationInvalid(format!(
                    "delegation link {} delegatee {} does not match child capability subject {}",
                    index,
                    link.delegatee.to_hex(),
                    child_subject_key
                )));
            }
            if child_parent_capability_id.as_deref() != Some(link.capability_id.as_str()) {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} is not lineage-linked to parent capability {}",
                    child_capability_id, link.capability_id
                )));
            }
            if child_issued_at < link.timestamp {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} was issued before delegation link {} timestamp",
                    child_capability_id, index
                )));
            }
            if child_issued_at < parent_snapshot.issued_at {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} predates parent capability {} issuance",
                    child_capability_id, parent_snapshot.capability_id
                )));
            }
            if child_expires_at > parent_snapshot.expires_at {
                return Err(KernelError::DelegationInvalid(format!(
                    "child capability {} expires after parent capability {}",
                    child_capability_id, parent_snapshot.capability_id
                )));
            }

            validate_delegation_scope_step(
                &parent_snapshot.capability_id,
                &child_capability_id,
                &parent_scope,
                &child_scope,
                child_expires_at,
                link,
            )?;
        }

        Ok(())
    }

    fn local_budget_event_authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: format!("kernel:{}", self.config.keypair.public_key().to_hex()),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        }
    }

    pub(crate) fn budget_backend_receipt_metadata(&self) -> Result<serde_json::Value, KernelError> {
        let (guarantee_level, authority_profile, metering_profile) =
            self.with_budget_store(|store| {
                Ok((
                    store.budget_guarantee_level().as_str().to_string(),
                    store.budget_authority_profile().as_str().to_string(),
                    store.budget_metering_profile().as_str().to_string(),
                ))
            })?;
        Ok(serde_json::json!({
            "budget_authority": {
                "guarantee_level": guarantee_level,
                "authority_profile": authority_profile,
                "metering_profile": metering_profile,
            }
        }))
    }

    pub(crate) fn budget_execution_receipt_metadata(
        &self,
        charge: &BudgetChargeResult,
        terminal_event: Option<(&str, &BudgetHoldMutationDecision)>,
        execution_nonce_id: Option<&str>,
    ) -> serde_json::Value {
        let mut budget_authority = serde_json::Map::new();
        budget_authority.insert(
            "guarantee_level".to_string(),
            serde_json::json!(charge.authorize_metadata.guarantee_level.as_str()),
        );
        budget_authority.insert(
            "authority_profile".to_string(),
            serde_json::json!(charge.authorize_metadata.budget_profile.as_str()),
        );
        budget_authority.insert(
            "metering_profile".to_string(),
            serde_json::json!(charge.authorize_metadata.metering_profile.as_str()),
        );
        budget_authority.insert(
            "hold_id".to_string(),
            serde_json::json!(&charge.budget_hold_id),
        );
        if let Some(budget_term) = charge.authorize_metadata.budget_term() {
            budget_authority.insert("budget_term".to_string(), serde_json::json!(budget_term));
        }
        if let Some(authority) = charge.authorize_metadata.authority.as_ref() {
            budget_authority.insert(
                "authority".to_string(),
                serde_json::json!({
                    "authority_id": &authority.authority_id,
                    "lease_id": &authority.lease_id,
                    "lease_epoch": authority.lease_epoch,
                }),
            );
        }

        let mut authorize = serde_json::Map::new();
        if let Some(event_id) = charge.authorize_metadata.event_id.as_ref() {
            authorize.insert("event_id".to_string(), serde_json::json!(event_id));
        }
        if let Some(commit_index) = charge.authorize_metadata.budget_commit_index {
            authorize.insert(
                "budget_commit_index".to_string(),
                serde_json::json!(commit_index),
            );
        }
        authorize.insert(
            "exposure_units".to_string(),
            serde_json::json!(charge.cost_charged),
        );
        authorize.insert(
            "committed_cost_units_after".to_string(),
            serde_json::json!(charge.new_committed_cost_units),
        );
        budget_authority.insert(
            "authorize".to_string(),
            serde_json::Value::Object(authorize),
        );

        if let Some((disposition, terminal_event)) = terminal_event {
            let mut terminal = serde_json::Map::new();
            terminal.insert("disposition".to_string(), serde_json::json!(disposition));
            if let Some(event_id) = terminal_event.metadata.event_id.as_ref() {
                terminal.insert("event_id".to_string(), serde_json::json!(event_id));
            }
            if let Some(commit_index) = terminal_event.metadata.budget_commit_index {
                terminal.insert(
                    "budget_commit_index".to_string(),
                    serde_json::json!(commit_index),
                );
            }
            terminal.insert(
                "exposure_units".to_string(),
                serde_json::json!(terminal_event.exposure_units),
            );
            terminal.insert(
                "realized_spend_units".to_string(),
                serde_json::json!(terminal_event.realized_spend_units),
            );
            terminal.insert(
                "committed_cost_units_after".to_string(),
                serde_json::json!(terminal_event.committed_cost_units_after),
            );
            budget_authority.insert("terminal".to_string(), serde_json::Value::Object(terminal));
        }

        if let Some(nonce_id) = execution_nonce_id {
            budget_authority.insert(
                "execution_nonce_id".to_string(),
                serde_json::json!(nonce_id),
            );
            budget_authority.insert(
                "mediated_spend".to_string(),
                serde_json::json!({
                    "profile": chio_core_types::receipt::authoritative_spend::MEDIATED_SPEND_PROFILE
                }),
            );
        }

        serde_json::json!({ "budget_authority": budget_authority })
    }

    pub(crate) fn merge_budget_receipt_metadata(
        &self,
        extra_metadata: Option<serde_json::Value>,
        budget_metadata: serde_json::Value,
    ) -> Option<serde_json::Value> {
        merge_metadata_objects(extra_metadata, Some(budget_metadata))
    }

    /// Check and decrement the invocation budget for a capability.
    ///
    /// Returns the matched grant index and the exact pre-execution budget mutation.
    pub(crate) fn check_and_increment_budget(
        &self,
        request_id: &str,
        cap: &CapabilityToken,
        matching_grants: &[MatchingGrant<'_>],
    ) -> Result<(usize, PreExecutionBudgetMutation), KernelError> {
        let mut saw_exhausted_budget = false;

        for matching in matching_grants {
            let grant = matching.grant;
            let has_monetary =
                grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();

            if has_monetary {
                // Use worst-case max_cost_per_invocation as the pre-execution debit.
                let cost_units = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.units)
                    .unwrap_or(0);
                let currency = grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|m| m.currency.clone())
                    .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                    .unwrap_or_else(|| "USD".to_string());
                let max_total = grant.max_total_cost.as_ref().map(|m| m.units);
                let max_per = grant.max_cost_per_invocation.as_ref().map(|m| m.units);
                let budget_total = max_total.unwrap_or(u64::MAX);
                let budget_hold_id =
                    format!("budget-hold:{}:{}:{}", request_id, cap.id, matching.index);
                let authorize_event_id = format!("{budget_hold_id}:authorize");
                let authority = self.local_budget_event_authority();

                // The recoverable money record commits in the SAME
                // transaction as the hold write, before the rail is touched:
                // a crash in any later window resolves through the journal
                // instead of leaving moved funds with no trace.
                let payment_journal = self.payment_journal_active().then(|| {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|elapsed| elapsed.as_millis().min(u64::MAX as u128) as u64)
                        .unwrap_or(0);
                    let rail = self
                        .payment_adapter
                        .as_ref()
                        .map(|adapter| adapter.rail_id().to_string())
                        .unwrap_or_default();
                    // Resolved exactly as the terminal receipt and the
                    // dispatch intent resolve it (request-scoped entry
                    // first, thread-local scope otherwise), so a recovered
                    // charge's reconciliation receipt is never dropped from
                    // the owning tenant's receipt view.
                    let tenant_id = self
                        .receipt_tenant_id_for_request(Some(request_id))
                        .unwrap_or_else(current_scoped_receipt_tenant_id);
                    crate::payment::PaymentJournalRecord {
                        request_id: request_id.to_string(),
                        capability_id: cap.id.clone(),
                        grant_index: matching.index as u32,
                        hold_id: Some(budget_hold_id.clone()),
                        rail,
                        authorization_id: None,
                        transaction_id: None,
                        amount_units: cost_units,
                        settle_action: None,
                        settle_amount_units: None,
                        currency: currency.clone(),
                        state: crate::payment::PaymentJournalState::HoldPlaced,
                        created_at_unix_ms: now_ms,
                        tenant_id,
                    }
                });

                let decision = self.with_budget_store(|store| {
                    Ok(store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
                        capability_id: cap.id.clone(),
                        grant_index: matching.index,
                        max_invocations: grant.max_invocations,
                        requested_exposure_units: cost_units,
                        max_cost_per_invocation: max_per,
                        max_total_cost_units: max_total,
                        hold_id: Some(budget_hold_id.clone()),
                        event_id: Some(authorize_event_id),
                        authority: Some(authority.clone()),
                        payment_journal: payment_journal.clone(),
                    })?)
                })?;
                match decision {
                    BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                        let charge = BudgetChargeResult {
                            grant_index: matching.index,
                            cost_charged: cost_units,
                            currency,
                            budget_total,
                            new_committed_cost_units: authorized.committed_cost_units_after,
                            budget_hold_id: authorized
                                .hold_id
                                .unwrap_or_else(|| budget_hold_id.clone()),
                            authorize_metadata: authorized.metadata,
                        };
                        return Ok((matching.index, PreExecutionBudgetMutation::Charge(charge)));
                    }
                    BudgetAuthorizeHoldDecision::Denied(_) => {
                        saw_exhausted_budget = true;
                    }
                }
            } else {
                if grant.max_invocations.is_none() {
                    return Ok((matching.index, PreExecutionBudgetMutation::None));
                }

                if self.with_budget_store(|store| {
                    Ok(store.try_increment(&cap.id, matching.index, grant.max_invocations)?)
                })? {
                    return Ok((
                        matching.index,
                        PreExecutionBudgetMutation::Invocation {
                            grant_index: matching.index,
                        },
                    ));
                }
                saw_exhausted_budget = true;
            }
        }

        if saw_exhausted_budget {
            Err(KernelError::BudgetExhausted(cap.id.clone()))
        } else {
            // No matching grant had any limit -- allow with the first grant's index.
            let first_index = matching_grants.first().map(|m| m.index).unwrap_or(0);
            Ok((first_index, PreExecutionBudgetMutation::None))
        }
    }

    pub(crate) fn reverse_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetReverseHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            Ok(store.reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                reversed_exposure_units: charge.cost_charged,
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.reverse_event_id()),
                authority,
            })?)
        })
    }

    pub(crate) fn reverse_pre_execution_budget_mutation(
        &self,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
    ) -> Result<Option<BudgetReverseHoldDecision>, KernelError> {
        match budget_mutation {
            PreExecutionBudgetMutation::Charge(charge) => {
                self.reverse_budget_charge(&cap.id, charge).map(Some)
            }
            PreExecutionBudgetMutation::Invocation { grant_index } => {
                self.with_budget_store(|store| {
                    Ok(store.reverse_charge_cost(&cap.id, *grant_index, 0)?)
                })?;
                Ok(None)
            }
            PreExecutionBudgetMutation::None => Ok(None),
        }
    }

    /// Whether the registered tool server for `server_id` measures the realized
    /// cost of an invocation it dispatches.
    ///
    /// An absent server defaults to `true` (measured), preserving
    /// reconcile-and-settle behavior for every real server. The server is
    /// always present here because dispatch resolved it before finalization, so
    /// the default is unreachable in practice.
    pub(crate) fn tool_server_measures_realized_cost(&self, server_id: &str) -> bool {
        self.tool_servers
            .get(server_id)
            .is_none_or(|server| server.measures_realized_cost())
    }

    /// Finalize a tool output whose realized cost was not measured on this path.
    ///
    /// A tool server that reports `measures_realized_cost() == false` did not
    /// execute the target tool, so no realized cost exists here. The kernel must
    /// not sign a settled, reconciled authoritative spend for it: instead it
    /// reverses the pre-execution hold (nothing was spent on this path) and
    /// emits a provisional allow receipt whose budget authority carries a
    /// `reversed` terminal and whose settlement stays `pending`. Such a receipt
    /// is rejected by `is_authoritative_spend_receipt` (the hold is not
    /// reconciled). Real reconciliation happens at the execution site.
    fn finalize_unmeasured_cost_provisional_allow(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        charge: BudgetChargeResult,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let reverse = self.reverse_budget_charge(&cap.id, &charge)?;
        let running_committed_cost_units = reverse.committed_cost_units_after;
        let budget_remaining = charge
            .budget_total
            .saturating_sub(running_committed_cost_units);
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: 0,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));

        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(value) => ToolCallOutput::Value(value.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                ToolCallOutput::Stream(stream.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        // The nonce id is intentionally omitted from the budget authority so the
        // receipt makes no `mediated_spend` profile claim: this is a provisional
        // confirmation, not an authoritative spend.
        let budget_metadata =
            self.budget_execution_receipt_metadata(&charge, Some(("reversed", &reverse)), None);
        let merged = merge_metadata_objects(
            financial_json,
            self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
        );

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    merged,
                    // This provisional allow already reversed the budget hold and
                    // did not execute the tool at the kernel, so there is no
                    // reserved hold to reconcile and nothing to authorize
                    // downstream. Emit no execution nonce: a spendable nonce here
                    // would carry no reserved hold, letting a gate deployment
                    // execute against a refunded hold and spend outside the cap.
                    AllowResponseNonce::Suppressed,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    // The tool ran (a side effect may have committed) but the
                    // stream ended incomplete, so any runtime-admission lease
                    // consumed at admission is retained, not released. Mark it
                    // so the burned lease is recoverable from the receipt.
                    self.mark_runtime_admission_reservations_retained_fail_closed(merged),
                ),
        }
    }

    fn reconcile_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
        realized_cost_units: u64,
    ) -> Result<BudgetReconcileHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            Ok(store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                exposed_cost_units: charge.cost_charged,
                realized_spend_units: realized_cost_units.min(charge.cost_charged),
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.reconcile_event_id()),
                authority,
            })?)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_budgeted_tool_output_with_cost_and_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        cost_context: FinalizeToolOutputCostContext<'_>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let FinalizeToolOutputCostContext {
            charge_result,
            reported_cost,
            payment_authorization,
            cap,
        } = cost_context;
        let Some(charge) = charge_result else {
            // When a payment was authorized but the grant carries no monetary ceiling,
            // the realized spend is the prepaid quote. Settle the authorization so the
            // invocation is recorded as a completed prepayment; fail closed if it
            // cannot be settled rather than admit the tool against a perpetual hold.
            let Some(auth) = payment_authorization.as_ref() else {
                return self.finalize_tool_output_with_metadata(
                    request,
                    output,
                    elapsed,
                    timestamp,
                    matched_grant_index,
                    extra_metadata,
                );
            };
            let Some(settlement) =
                self.settle_prepaid_authorization_without_charge(request, auth)?
            else {
                return self.build_deny_response_with_metadata(
                    request,
                    "MustPrepay authorization could not be settled after execution",
                    timestamp,
                    Some(matched_grant_index),
                    extra_metadata,
                );
            };
            let (payment_reference, settlement_status) = settlement.into_receipt_parts();
            // A grant with no monetary ceiling carries no budget charge, so the
            // realized spend is the prepaid quote. Populate the full financial
            // envelope from the quote (amount, currency, settlement, lineage) so
            // the receipt deserializes as `FinancialReceiptMetadata` and reflects
            // the completed prepaid spend, not a partial fragment that receipt
            // queries and dashboards cannot read.
            let (quoted_units, quoted_currency) =
                Self::mustprepay_quoted_amount(request).unwrap_or_else(|| (0, "USD".to_string()));
            let financial_meta = FinancialReceiptMetadata {
                grant_index: matched_grant_index as u32,
                cost_charged: quoted_units,
                currency: quoted_currency,
                budget_remaining: 0,
                budget_total: quoted_units,
                delegation_depth: cap.delegation_chain.len() as u32,
                root_budget_holder: cap.issuer.to_hex(),
                payment_reference,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: None,
            };
            let payment_meta = serde_json::json!({ "financial": financial_meta });
            // The kernel-built `financial` block is authoritative and must win over
            // any `financial` keys carried in caller/route `extra_metadata`, so the
            // settled-prepayment status that `require_earned_mediated_trust_level`
            // reads at the sign site reflects the real settlement and can never be
            // forged by a caller-supplied override. Pass it as the winning (second)
            // argument, matching the reconciled-hold path (see
            // `merge_budget_receipt_metadata`).
            let metadata = merge_metadata_objects(extra_metadata, Some(payment_meta));
            return self.finalize_tool_output_with_metadata(
                request,
                output,
                elapsed,
                timestamp,
                matched_grant_index,
                metadata,
            );
        };

        // A tool server that does not measure realized cost (a pre-execution
        // authorization gate that dispatches a pass-through while the real tool
        // runs elsewhere) never yields a settled, reconciled authoritative
        // spend: nothing executed here, so there is no realized cost to
        // reconcile. Reverse the pre-execution hold and emit a provisional
        // receipt. Guarded on the absence of a payment authorization because
        // such gates carry no prepayment; a prepaid invocation always runs
        // through the measured settlement path below.
        if payment_authorization.is_none()
            && !self.tool_server_measures_realized_cost(&request.server_id)
        {
            return self.finalize_unmeasured_cost_provisional_allow(
                request,
                output,
                elapsed,
                timestamp,
                charge,
                extra_metadata,
            );
        }

        let reported_cost_ref = reported_cost.as_ref();
        let mut oracle_evidence = None;
        let mut cross_currency_note = None;
        let (actual_cost, cross_currency_failed) = if let Some(cost) =
            reported_cost_ref.filter(|cost| cost.currency != charge.currency)
        {
            match self.resolve_cross_currency_cost(cost, &charge.currency, timestamp) {
                Ok((converted_units, evidence)) => {
                    oracle_evidence = Some(evidence);
                    cross_currency_note = Some(serde_json::json!({
                        "oracle_conversion": {
                            "status": "applied",
                            "reported_currency": cost.currency,
                            "grant_currency": charge.currency,
                            "reported_units": cost.units,
                            "converted_units": converted_units
                        }
                    }));
                    (converted_units, false)
                }
                Err(error) => {
                    warn!(
                        request_id = %request.request_id,
                        reported_currency = %cost.currency,
                        charged_currency = %charge.currency,
                        reason = %redacted!(&error),
                        "cross-currency reconciliation failed; closing hold at authorized exposure"
                    );
                    cross_currency_note = Some(serde_json::json!({
                        "oracle_conversion": {
                            "status": "failed",
                            "reported_currency": cost.currency,
                            "grant_currency": charge.currency,
                            "reported_units": cost.units,
                            "provisional_units": charge.cost_charged,
                            "reason": error.to_string()
                        }
                    }));
                    (charge.cost_charged, true)
                }
            }
        } else {
            (
                reported_cost_ref
                    .map(|cost| cost.units)
                    .unwrap_or(charge.cost_charged),
                false,
            )
        };

        let payment_already_settled = payment_authorization
            .as_ref()
            .is_some_and(|authorization| authorization.settled);
        let cost_overrun =
            !cross_currency_failed && actual_cost > charge.cost_charged && charge.cost_charged > 0;

        if cost_overrun {
            warn!(
                request_id = %request.request_id,
                reported = actual_cost,
                charged = charge.cost_charged,
                "tool server reported cost exceeds max_cost_per_invocation; settlement_status=failed"
            );
        }

        let realized_budget_units =
            if cross_currency_failed || payment_already_settled || cost_overrun {
                charge.cost_charged
            } else {
                actual_cost.min(charge.cost_charged)
            };
        let reconcile = self.reconcile_budget_charge(&cap.id, &charge, realized_budget_units)?;
        let running_committed_cost_units = reconcile.committed_cost_units_after;

        let payment_result = if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled || cross_currency_failed || cost_overrun {
                None
            } else {
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::Internal(
                        "payment authorization present without configured adapter".to_string(),
                    )
                })?;
                // Commit the terminal settle action BEFORE any money can
                // move, so a crash inside the rail call replays the exact
                // recorded operation instead of guessing.
                let settle = if actual_cost == 0 {
                    crate::payment::PaymentSettleIntent {
                        action: crate::payment::PaymentSettleAction::Release,
                        amount_units: None,
                    }
                } else {
                    crate::payment::PaymentSettleIntent {
                        action: crate::payment::PaymentSettleAction::Capture,
                        amount_units: Some(actual_cost),
                    }
                };
                self.advance_payment_journal_if_active(
                    &request.request_id,
                    crate::payment::PaymentJournalState::Authorized,
                    crate::payment::PaymentJournalState::Settling,
                    None,
                    None,
                    Some(settle),
                )?;
                let result = if actual_cost == 0 {
                    adapter.release(&authorization.authorization_id, &request.request_id)
                } else {
                    adapter.capture(
                        &authorization.authorization_id,
                        actual_cost,
                        &charge.currency,
                        &request.request_id,
                    )
                };
                if let Ok(payment) = result.as_ref() {
                    self.advance_payment_journal_if_active(
                        &request.request_id,
                        crate::payment::PaymentJournalState::Settling,
                        crate::payment::PaymentJournalState::Settled,
                        None,
                        Some(&payment.transaction_id),
                        None,
                    )?;
                }
                Some(result)
            }
        } else {
            None
        };

        let settlement = if cross_currency_failed || cost_overrun {
            ReceiptSettlement {
                payment_reference: payment_authorization
                    .as_ref()
                    .map(|authorization| authorization.authorization_id.clone()),
                settlement_status: SettlementStatus::Failed,
            }
        } else if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled {
                ReceiptSettlement::from_authorization(authorization)
            } else if let Some(payment_result) = payment_result.as_ref() {
                match payment_result {
                    Ok(result) => ReceiptSettlement::from_payment_result(result),
                    Err(error) => {
                        warn!(
                            request_id = %request.request_id,
                            reason = %redacted!(&error),
                            "post-execution payment settlement failed"
                        );
                        ReceiptSettlement {
                            payment_reference: Some(authorization.authorization_id.clone()),
                            settlement_status: SettlementStatus::Failed,
                        }
                    }
                }
            } else {
                warn!(
                    request_id = %request.request_id,
                    authorization_id = %authorization.authorization_id,
                    "unsettled authorization completed without a payment result"
                );
                ReceiptSettlement {
                    payment_reference: Some(authorization.authorization_id.clone()),
                    settlement_status: SettlementStatus::Failed,
                }
            }
        } else {
            ReceiptSettlement::settled()
        };
        let recorded_cost = if payment_already_settled && !cross_currency_failed && !cost_overrun {
            charge.cost_charged
        } else {
            actual_cost
        };

        let budget_remaining = charge
            .budget_total
            .saturating_sub(running_committed_cost_units);
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) = settlement.into_receipt_parts();
        let payment_breakdown = payment_authorization.as_ref().map(|authorization| {
            serde_json::json!({
                "payment": {
                    "authorization_id": authorization.authorization_id,
                    "adapter_metadata": authorization.metadata,
                    "preauthorized_units": charge.cost_charged,
                    "recorded_units": recorded_cost
                }
            })
        });

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: recorded_cost,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: merge_metadata_objects(
                merge_metadata_objects(
                    reported_cost_ref.and_then(|cost| cost.breakdown.clone()),
                    payment_breakdown,
                ),
                cross_currency_note,
            ),
            oracle_evidence,
            attempted_cost: None,
        };

        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(value) => ToolCallOutput::Value(value.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                ToolCallOutput::Stream(stream.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        // For cost-bearing allows without a presented nonce, mint the execution
        // nonce before signing the receipt so the nonce id can be recorded in
        // the budget-authority metadata. The same nonce is placed on the
        // response so receipt metadata and response carry the same id.
        let preminted_execution_nonce = if request.execution_nonce.is_none() {
            if let Some(nonce_config) = self.execution_nonce_config.as_ref() {
                let action =
                    ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
                        KernelError::ReceiptSigningFailed(format!(
                            "failed to hash parameters for nonce binding: {e}"
                        ))
                    })?;
                let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
                let binding = self.nonce_binding_for(request, cap, &action.parameter_hash);
                let signed = crate::execution_nonce::mint_execution_nonce(
                    &self.config.keypair,
                    binding,
                    nonce_config,
                    now,
                )?;
                Some(Box::new(signed))
            } else {
                None
            }
        } else {
            None
        };

        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => {
                // Record the nonce that authorizes this spend: the freshly
                // preminted nonce when one was minted, otherwise the nonce the
                // request presented on a strict retry. Without the fallback a
                // successful strict retry records no nonce and the receipt fails
                // `is_authoritative_spend_receipt` with `NonceLinkMissing`.
                let budget_metadata = self.budget_execution_receipt_metadata(
                    &charge,
                    Some(("reconciled", &reconcile)),
                    preminted_execution_nonce
                        .as_deref()
                        .map(|n| n.nonce_id())
                        .or_else(|| request.execution_nonce.as_ref().map(|n| n.nonce_id())),
                );
                let merged = merge_metadata_objects(
                    financial_json,
                    self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
                );
                self.build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    merged,
                    // Reuse the nonce minted before signing when one was minted;
                    // otherwise mint after signing. On a strict retry the request
                    // already carries a nonce, so the mint path early-returns None
                    // and no fresh nonce is issued, preserving current behavior.
                    match preminted_execution_nonce {
                        Some(nonce) => AllowResponseNonce::Preminted(nonce),
                        None => AllowResponseNonce::MintForAllow,
                    },
                )
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => {
                let budget_metadata = self.budget_execution_receipt_metadata(
                    &charge,
                    Some(("reconciled", &reconcile)),
                    None,
                );
                let merged = merge_metadata_objects(
                    financial_json,
                    self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
                );
                self.build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    // The tool ran (a side effect may have committed) but the
                    // stream ended incomplete, so any runtime-admission lease
                    // consumed at admission is retained, not released. Mark it
                    // so the burned lease is recoverable from the receipt,
                    // matching the RequestIncomplete error arm.
                    self.mark_runtime_admission_reservations_retained_fail_closed(merged),
                )
            }
        }
    }

    fn block_on_price_oracle<T>(
        &self,
        future: impl Future<Output = Result<T, PriceOracleError>>,
    ) -> Result<T, KernelError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                    handle
                        .block_on(future)
                        .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))
                }),
                tokio::runtime::RuntimeFlavor::CurrentThread => {
                    Err(KernelError::CrossCurrencyOracle(
                        "current-thread tokio runtime cannot synchronously resolve price oracles"
                            .to_string(),
                    ))
                }
                flavor => Err(KernelError::CrossCurrencyOracle(format!(
                    "unsupported tokio runtime flavor for synchronous oracle resolution: {flavor:?}"
                ))),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    KernelError::CrossCurrencyOracle(format!(
                        "failed to build synchronous oracle runtime: {error}"
                    ))
                })?
                .block_on(future)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string())),
        }
    }

    pub(crate) fn resolve_cross_currency_cost(
        &self,
        reported_cost: &ToolInvocationCost,
        grant_currency: &str,
        timestamp: u64,
    ) -> Result<(u64, chio_core::web3::anchors::OracleConversionEvidence), KernelError> {
        let oracle =
            self.price_oracle
                .as_ref()
                .ok_or_else(|| KernelError::NoCrossCurrencyOracle {
                    base: reported_cost.currency.clone(),
                    quote: grant_currency.to_string(),
                })?;
        let rate =
            self.block_on_price_oracle(oracle.get_rate(&reported_cost.currency, grant_currency))?;
        let converted_units =
            convert_supported_units(reported_cost.units, &rate, rate.conversion_margin_bps)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        let evidence = rate
            .to_conversion_evidence(
                reported_cost.units,
                reported_cost.currency.clone(),
                grant_currency.to_string(),
                converted_units,
                timestamp,
            )
            .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        Ok((converted_units, evidence))
    }

    pub(crate) fn ensure_registered_tool_target(
        &self,
        request: &ToolCallRequest,
    ) -> Result<(), KernelError> {
        self.tool_servers.get(&request.server_id).ok_or_else(|| {
            KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
        })?;
        Ok(())
    }

    pub(crate) fn authorize_payment_if_needed(
        &self,
        request: &ToolCallRequest,
        charge_result: Option<&BudgetChargeResult>,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        // Derive the authorization amount. A MustPrepay intent prepays its quoted
        // cost, so the quote funds the prepayment whenever it is present, even when
        // a provisional monetary budget hold accompanies it: that hold covers
        // metered budget accounting, not the price the payer must prepay. Only a
        // non-MustPrepay metered charge authorizes the charged amount, and a request
        // with neither needs no payment.
        let (amount_units, currency) = if let Some(amount) = Self::mustprepay_quoted_amount(request)
        {
            amount
        } else if let Some(charge) = charge_result {
            (charge.cost_charged, charge.currency.clone())
        } else {
            return Ok(None);
        };

        let Some(adapter) = self.payment_adapter.as_ref() else {
            // The governed gate denies MustPrepay without an adapter earlier, but
            // the payment boundary is fail-closed as defense-in-depth: a MustPrepay
            // intent (which may also carry a provisional charge) must never reach
            // here without an adapter and be admitted unpaid.
            if Self::is_governed_mustprepay_request(request) {
                return Err(PaymentError::RailError(
                    "MustPrepay intent reached payment authorization without a configured adapter"
                        .to_string(),
                ));
            }
            return Ok(None);
        };

        let governed = request
            .governed_intent
            .as_ref()
            .map(|intent| {
                intent
                    .binding_hash()
                    .map(|intent_hash| GovernedPaymentContext {
                        intent_id: intent.id.clone(),
                        intent_hash,
                        purpose: intent.purpose.clone(),
                        server_id: intent.server_id.clone(),
                        tool_name: intent.tool_name.clone(),
                        approval_token_id: request
                            .approval_token
                            .as_ref()
                            .map(|token| token.id.clone()),
                    })
                    .map_err(|error| {
                        PaymentError::RailError(format!(
                            "failed to hash governed intent for payment authorization: {error}"
                        ))
                    })
            })
            .transpose()?;
        let commerce = request.governed_intent.as_ref().and_then(|intent| {
            intent
                .commerce
                .as_ref()
                .map(|commerce| CommercePaymentContext {
                    seller: commerce.seller.clone(),
                    shared_payment_token_id: commerce.shared_payment_token_id.clone(),
                    max_amount: intent.max_amount.clone(),
                })
        });

        let authorization = adapter.authorize(&PaymentAuthorizeRequest {
            amount_units,
            currency,
            payer: request.agent_id.clone(),
            payee: request.server_id.clone(),
            reference: request.request_id.clone(),
            governed,
            commerce,
        })?;
        // Advance the journal HoldPlaced -> Authorized only when a monetary charge
        // actually wrote a HoldPlaced row. A no-ceiling MustPrepay grant is not
        // monetary (no per-invocation or total ceiling), so admission takes the
        // non-monetary branch and writes NO HoldPlaced row; its prepayment is
        // journal-free by design and settles through the no-ceiling settle path.
        // Advancing unconditionally would fail closed against the missing
        // predecessor row and deny a just-captured prepayment, releasing (not
        // refunding) an already-settled capture, i.e. money loss. A present
        // `charge_result` is exactly the has-monetary case whose HoldPlaced row
        // exists whenever the journal is active; when the journal is off the advance
        // is a no-op regardless.
        if charge_result.is_some() {
            // Persist the rail authorization id BEFORE returning, so a crash
            // after authorize leaves a recoverable Authorized row. If the
            // advance cannot commit, undo the rail hold we just placed and fail
            // closed; the HoldPlaced row still records the attempt for boot
            // reconciliation.
            if let Err(error) = self.advance_payment_journal_if_active(
                &request.request_id,
                crate::payment::PaymentJournalState::HoldPlaced,
                crate::payment::PaymentJournalState::Authorized,
                Some(&authorization.authorization_id),
                None,
                None,
            ) {
                if let Err(release_error) =
                    adapter.release(&authorization.authorization_id, &request.request_id)
                {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&release_error),
                        "rail release after failed journal advance also failed"
                    );
                }
                return Err(PaymentError::Unavailable(format!(
                    "payment journal advance to authorized failed: {error}"
                )));
            }
        }
        Ok(Some(authorization))
    }

    /// Prepaid quote amount for a MustPrepay intent, if one applies.
    ///
    /// This is the authorization amount when the grant carries no monetary
    /// ceiling, so the same figure settles the hold after execution and is the
    /// amount refunded when a settled-at-authorize invocation is aborted.
    pub(crate) fn mustprepay_quoted_amount(request: &ToolCallRequest) -> Option<(u64, String)> {
        request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.metered_billing.as_ref())
            .filter(|metered| {
                metered.settlement_mode
                    == chio_core::capability::governance::MeteredSettlementMode::MustPrepay
            })
            .map(|metered| {
                (
                    metered.quote.quoted_cost.units,
                    metered.quote.quoted_cost.currency.clone(),
                )
            })
    }

    /// Whether `request` carries a governed MustPrepay intent, i.e. one whose
    /// metered billing mandates prepayment before the tool executes.
    pub(crate) fn is_governed_mustprepay_request(request: &ToolCallRequest) -> bool {
        Self::mustprepay_quoted_amount(request).is_some()
    }

    /// Satisfy the governed MustPrepay prepayment gate before a reserve-for-caller
    /// authorization nonce is minted.
    ///
    /// The reserve-for-caller path never dispatches the tool on this kernel: the
    /// caller presents the minted nonce to a downstream tool server, which
    /// reconciles the reserved budget hold without re-entering payment
    /// authorization. A MustPrepay intent therefore has no later settlement point,
    /// so the prepayment must be authorized AND settled here, before the nonce
    /// exists. Otherwise a reserved nonce would let the caller execute a MustPrepay
    /// spend downstream with no payment ever occurring.
    ///
    /// The prepayment is settled at the intent's quoted cost (the amount that will
    /// actually be prepaid), independently of the reserved budget hold that stays
    /// open for `max_total_cost` accounting and is reconciled downstream.
    ///
    /// Returns `Ok(None)` when the request is not a governed MustPrepay intent
    /// (nothing to prepay). Returns `Ok(Some(authorization))` carrying the settled
    /// prepayment so the caller can refund it if minting or persisting the
    /// reservation then fails, which would otherwise leave the payer captured for a
    /// reservation that was never handed out. Returns `Err` so the caller denies
    /// fail-closed when the prepayment cannot be authorized or settled; any
    /// unsettled hold is released so the payer's funds are not left frozen.
    pub(crate) fn ensure_reserved_mustprepay_prepaid(
        &self,
        request: &ToolCallRequest,
    ) -> Result<Option<ReservedPrepayment>, KernelError> {
        if !Self::is_governed_mustprepay_request(request) {
            return Ok(None);
        }
        let authorization = self
            .authorize_payment_if_needed(request, None)
            .map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "MustPrepay prepayment authorization failed before reserving an execution nonce: {error}"
                ))
            })?;
        let Some(authorization) = authorization else {
            return Err(KernelError::GovernedTransactionDenied(
                "MustPrepay intent reached the reserve-for-caller path without an authorized prepayment".to_string(),
            ));
        };
        match self.settle_prepaid_authorization_without_charge(request, &authorization)? {
            // The prepayment is now captured. Report it as settled so a later
            // reservation tear-down refunds it rather than releasing an already
            // captured hold, and carry the rail reference so the downstream
            // reconcile receipt can name the transaction that funded the spend.
            Some(settlement) => Ok(Some(ReservedPrepayment {
                authorization: PaymentAuthorization {
                    settled: true,
                    ..authorization
                },
                payment_reference: settlement.payment_reference,
            })),
            None => Err(KernelError::GovernedTransactionDenied(
                "MustPrepay prepayment could not be settled before reserving an execution nonce"
                    .to_string(),
            )),
        }
    }

    /// Settle a prepaid authorization for a MustPrepay call whose grant carries
    /// no monetary ceiling (no budget charge to reconcile).
    ///
    /// An adapter that already settled the hold is folded through unchanged. An
    /// unsettled hold is captured at the prepaid quote amount. Returns `None`
    /// when the hold cannot be settled so the caller fails closed.
    fn settle_prepaid_authorization_without_charge(
        &self,
        request: &ToolCallRequest,
        authorization: &PaymentAuthorization,
    ) -> Result<Option<ReceiptSettlement>, KernelError> {
        if authorization.settled {
            return Ok(Some(ReceiptSettlement::from_authorization(authorization)));
        }
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "payment authorization present without configured adapter".to_string(),
            )
        })?;
        let Some((amount_units, currency)) = Self::mustprepay_quoted_amount(request) else {
            warn!(
                request_id = %request.request_id,
                authorization_id = %authorization.authorization_id,
                "prepaid authorization lacks a resolvable quote amount; denying fail-closed"
            );
            Self::release_unsettled_prepaid_hold(&**adapter, request, authorization);
            return Ok(None);
        };
        match adapter.capture(
            &authorization.authorization_id,
            amount_units,
            &currency,
            &request.request_id,
        ) {
            Ok(result) => {
                let settlement = ReceiptSettlement::from_payment_result(&result);
                if settlement.settlement_status == SettlementStatus::Settled {
                    Ok(Some(settlement))
                } else {
                    warn!(
                        request_id = %request.request_id,
                        authorization_id = %authorization.authorization_id,
                        "prepaid authorization capture did not settle; denying fail-closed"
                    );
                    Self::release_unsettled_prepaid_hold(&**adapter, request, authorization);
                    Ok(None)
                }
            }
            Err(error) => {
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "prepaid authorization capture failed; denying fail-closed"
                );
                Self::release_unsettled_prepaid_hold(&**adapter, request, authorization);
                Ok(None)
            }
        }
    }

    /// Best-effort void of an unsettled prepaid hold when a MustPrepay call fails
    /// closed after execution, so the payer's funds are not left frozen at the
    /// facilitator until the authorization expires. Logs on failure and never
    /// propagates: the call is denied regardless of whether the release lands.
    fn release_unsettled_prepaid_hold(
        adapter: &dyn PaymentAdapter,
        request: &ToolCallRequest,
        authorization: &PaymentAuthorization,
    ) {
        if let Err(error) = adapter.release(&authorization.authorization_id, &request.request_id) {
            warn!(
                request_id = %request.request_id,
                authorization_id = %authorization.authorization_id,
                reason = %redacted!(&error),
                "failed to release unsettled prepaid authorization on fail-closed deny"
            );
        }
    }

    /// Refund a captured MustPrepay prepayment when a reserve-for-caller
    /// reservation tears down after the prepayment settled but before the caller
    /// receives a usable nonce (the reservation stamp reversed the budget hold, or
    /// the reserved receipt failed to persist). The prepayment was captured at the
    /// quoted cost before the nonce could be minted, so without this the payer
    /// would stay charged for a reservation that was denied. Refunds the prepaid
    /// quote through the same unwind path a mid-execution abort uses, with no
    /// budget charge to reverse. Logs on failure and never propagates: the
    /// reservation is denied regardless, and the original tear-down error is the
    /// one surfaced to the caller.
    pub(crate) fn refund_reserved_mustprepay_prepayment(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        prepayment: &PaymentAuthorization,
    ) {
        if let Err(error) =
            self.unwind_aborted_monetary_invocation(request, cap, None, Some(prepayment))
        {
            warn!(
                request_id = %request.request_id,
                authorization_id = %prepayment.authorization_id,
                reason = %redacted!(&error),
                "failed to refund captured MustPrepay prepayment after reserve tear-down"
            );
        }
    }
}
