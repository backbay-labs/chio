//! `ChioKernel` capability and budget validation.
//!
//! Holds capability issuance/revocation, tool-server event drains, portable
//! verdict helpers, and budget charge/reconcile helpers. Governed-admission
//! validation lives in `governed_validation.rs`.

use chio_log_redact::redacted;

use self::responses::{AllowResponseNonce, FinalizeToolOutputCostContext};
use super::*;
use crate::admission_operation::{
    AdmissionAttachment, AdmissionDigest, AdmissionIdentifier, AdmissionOperationState,
};
use crate::budget_store::{
    ApprovalRequiredBudgetHold, BudgetAuthorizeCumulativeApprovalRequest,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureInvocationRequest,
    BudgetCapturedBeforeDispatchCancellationDecision, BudgetCumulativeApprovalAccountKey,
    BudgetCumulativeApprovalAuthorizationDecision, BudgetCumulativeApprovalRequest,
    BudgetEventAuthority, BudgetHoldMutationDecision, BudgetInvocationCaptureDecision,
    BudgetInvocationQuota, BudgetQuotaKey, BudgetQuotaProfile, BudgetReconcileHoldDecision,
    BudgetReconcileHoldRequest, BudgetReverseHoldDecision, BudgetReverseHoldRequest,
};

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
        crate::ensure_capability_issuance_supported(&scope)?;
        let capability =
            self.capability_authority
                .issue_capability(subject, scope.clone(), ttl_seconds)?;
        crate::validate_issued_capability_response(
            &capability,
            subject,
            &scope,
            ttl_seconds,
            &self.capability_authority.authority_public_key(),
        )?;

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
        let direct_root = self.negotiated_capability_root(cap, &peer_profile)?;

        chio_kernel_core::verify_capability_full_with_root(
            cap,
            &trusted,
            &clock,
            capability_crypto_floor(self.capability_crypto_floor),
            chio_kernel_core::CapabilityFeatureContext {
                peer: &peer_profile,
                direct_root: direct_root.as_ref(),
            },
            &trust_resolver,
            &mut budgets,
        )
        .map_err(|error| {
            chio_kernel_core::KernelCoreError::InvalidCapability(error).deny_reason()
        })?;
        Ok(())
    }

    /// Resolve the signed root token that the negotiated family-budget verifiers
    /// require for a delegated capability.
    ///
    /// Migration prerequisite: once a peer negotiates either family budget feature,
    /// every delegated capability from that peer needs a receipt-store snapshot
    /// carrying `signed_capability` for its root. Snapshots written before signed
    /// token retention carry no signed token, so enabling a feature against a store
    /// that still holds them denies those capabilities with "has no signed token
    /// evidence", which is distinct from the missing-row and tamper reasons.
    /// Backfill signed root snapshots before turning either feature on.
    pub(crate) fn negotiated_capability_root(
        &self,
        cap: &CapabilityToken,
        peer: &chio_core::capability::features::CapabilityNegotiation,
    ) -> Result<Option<CapabilityToken>, String> {
        let features = &peer.features;
        let lineage_required = features
            .get(chio_core::capability::features::AGGREGATE_INVOCATION_BUDGET)
            .copied()
            .unwrap_or(false)
            || features
                .get(chio_core::capability::features::CUMULATIVE_APPROVAL_BUDGET)
                .copied()
                .unwrap_or(false);
        if !lineage_required || cap.delegation_chain.is_empty() {
            return Ok(None);
        }

        let root_id = cap
            .delegation_chain
            .first()
            .map(|link| link.capability_id.as_str())
            .ok_or_else(|| "delegated capability has no root delegation link".to_string())?;
        let snapshot = self
            .with_receipt_store(|store| Ok(store.get_capability_snapshot(root_id)?))
            .map_err(|error| format!("failed to resolve signed capability root: {error}"))?
            .flatten()
            .ok_or_else(|| format!("missing signed capability root snapshot for {root_id}"))?;
        let signed_root = snapshot.signed_capability.ok_or_else(|| {
            format!("capability root snapshot {root_id} has no signed token evidence")
        })?;
        if signed_root.id != root_id {
            return Err(format!(
                "signed capability root {} does not match requested root {root_id}",
                signed_root.id
            ));
        }
        Ok(Some(signed_root))
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
            self.enforce_restart_reserved_hold_gate()?;
            use chio_kernel_core::BudgetRegistry;
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

    pub(crate) fn tracked_reserved_sibling_hold_ids(&self) -> Vec<String> {
        self.lock_reserved_sibling_shares()
            .keys()
            .cloned()
            .collect()
    }

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
    ) -> std::sync::MutexGuard<'_, RestartReservedHoldGate> {
        match self.restart_reserved_hold_gate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn arm_restart_reserved_hold_gate(&self) -> Result<(), KernelError> {
        let gate = match self
            .with_budget_store(|store| Ok(store.list_open_delegated_reserved_hold_ids()?))?
        {
            Some(hold_ids) => {
                let pending: std::collections::HashSet<String> = hold_ids.into_iter().collect();
                if pending.is_empty() {
                    RestartReservedHoldGate::Clear
                } else {
                    RestartReservedHoldGate::PendingHolds(pending)
                }
            }
            None => {
                let open = self.with_budget_store(|store| Ok(store.count_open_holds()?))?;
                if open == 0 {
                    RestartReservedHoldGate::Clear
                } else {
                    RestartReservedHoldGate::PendingOpaqueCount
                }
            }
        };
        *self.lock_restart_reserved_hold_gate() = gate;
        Ok(())
    }

    fn enforce_restart_reserved_hold_gate(&self) -> Result<(), String> {
        let mut gate = self.lock_restart_reserved_hold_gate();
        match &*gate {
            RestartReservedHoldGate::Clear => Ok(()),
            RestartReservedHoldGate::PendingHolds(pending) => {
                let mut still_open = std::collections::HashSet::new();
                for hold_id in pending {
                    let open = self
                        .with_budget_store(|store| {
                            Ok(store
                                .get_budget_hold(hold_id)?
                                .is_some_and(|hold| hold.disposition.is_open()))
                        })
                        .map_err(|error| error.to_string())?;
                    if open {
                        still_open.insert(hold_id.clone());
                    }
                }
                if still_open.is_empty() {
                    *gate = RestartReservedHoldGate::Clear;
                    Ok(())
                } else {
                    let count = still_open.len();
                    *gate = RestartReservedHoldGate::PendingHolds(still_open);
                    Err(format!(
                        "delegated reserved holds from a prior process remain open ({count})"
                    ))
                }
            }
            RestartReservedHoldGate::PendingOpaqueCount => {
                let open = self
                    .with_budget_store(|store| Ok(store.count_open_holds()?))
                    .map_err(|error| error.to_string())?;
                if open == 0 {
                    *gate = RestartReservedHoldGate::Clear;
                    Ok(())
                } else {
                    Err(format!(
                        "open budget holds from a prior process remain ({open}) and cannot be enumerated"
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
        let direct_root = match self.negotiated_capability_root(capability, &peer_profile) {
            Ok(root) => root,
            Err(reason) => {
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some(reason),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
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
        chio_kernel_core::evaluate_with_full_floor_and_root(
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
            direct_root.as_ref(),
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

        if let Some(capture) = charge.invocation_capture.as_ref() {
            let mut invocation_capture = serde_json::Map::new();
            if let Some(event_id) = capture.metadata.event_id.as_ref() {
                invocation_capture.insert("event_id".to_string(), serde_json::json!(event_id));
            }
            if let Some(commit_index) = capture.metadata.budget_commit_index {
                invocation_capture.insert(
                    "budget_commit_index".to_string(),
                    serde_json::json!(commit_index),
                );
            }
            invocation_capture.insert(
                "invocation_count_after".to_string(),
                serde_json::json!(capture.invocation_count_after),
            );
            budget_authority.insert(
                "invocation_capture".to_string(),
                serde_json::Value::Object(invocation_capture),
            );
        }

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

    pub(crate) fn retained_admission_receipt_metadata(
        &self,
        budget_mutation: &PreExecutionBudgetMutation,
        runtime_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let retained =
            self.mark_runtime_admission_reservations_retained_fail_closed(runtime_metadata);
        match budget_mutation.charge_result() {
            Some(charge) => self.merge_budget_receipt_metadata(
                retained,
                self.budget_execution_receipt_metadata(charge, None, None),
            ),
            None => retained,
        }
    }

    pub(crate) fn ambiguous_invocation_capture_receipt_metadata(
        &self,
        budget_mutation: &PreExecutionBudgetMutation,
        runtime_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let retained =
            self.mark_runtime_admission_reservations_retained_fail_closed(runtime_metadata);
        let Some(charge) = budget_mutation.charge_result() else {
            return retained;
        };
        let mut budget_metadata = self.budget_execution_receipt_metadata(charge, None, None);
        if let Some(budget_authority) = budget_metadata
            .get_mut("budget_authority")
            .and_then(serde_json::Value::as_object_mut)
        {
            budget_authority.insert(
                "invocation_capture".to_string(),
                serde_json::json!({
                    "event_id": charge.capture_invocation_event_id(),
                    "invocation_capture_ambiguous": true,
                    "admission_retained": true,
                }),
            );
        }
        self.merge_budget_receipt_metadata(retained, budget_metadata)
    }

    pub(crate) fn ambiguous_cancellation_receipt_metadata(
        &self,
        charge: &BudgetChargeResult,
        runtime_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let mut budget_metadata = self.budget_execution_receipt_metadata(charge, None, None);
        if let Some(budget_authority) = budget_metadata
            .get_mut("budget_authority")
            .and_then(serde_json::Value::as_object_mut)
        {
            if let Some(capture) = budget_authority
                .get_mut("invocation_capture")
                .and_then(serde_json::Value::as_object_mut)
            {
                capture.insert(
                    "admission_retained".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            budget_authority.insert(
                "cancel_captured_before_dispatch".to_string(),
                serde_json::json!({
                    "event_id": charge.cancel_captured_before_dispatch_event_id(),
                    "cancellation_ambiguous": true,
                    "pre_dispatch_admission_release_attempted": true,
                }),
            );
        }
        self.merge_budget_receipt_metadata(runtime_metadata, budget_metadata)
    }

    pub(crate) fn captured_admission_retained_receipt_metadata(
        &self,
        charge: &BudgetChargeResult,
        runtime_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let mut budget_metadata = self.budget_execution_receipt_metadata(charge, None, None);
        if let Some(capture) = budget_metadata
            .get_mut("budget_authority")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|authority| authority.get_mut("invocation_capture"))
            .and_then(serde_json::Value::as_object_mut)
        {
            capture.insert(
                "admission_retained".to_string(),
                serde_json::Value::Bool(true),
            );
        }
        self.merge_budget_receipt_metadata(runtime_metadata, budget_metadata)
    }

    pub(crate) fn ambiguous_dispatch_receipt_metadata(
        &self,
        budget_mutation: &PreExecutionBudgetMutation,
        payment_authorization: Option<&PaymentAuthorization>,
        runtime_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let retained = self.retained_admission_receipt_metadata(budget_mutation, runtime_metadata);
        match payment_authorization {
            Some(authorization) => merge_metadata_objects(
                retained,
                Some(serde_json::json!({
                    "financial": {
                        "payment_reference": authorization.authorization_id,
                        "payment_authorization_retained": true
                    }
                })),
            ),
            None => retained,
        }
    }

    /// Record that an ambiguous post-dispatch outcome retained a budget or
    /// payment hold. On a durable kernel the recovery sweep reconciles the hold
    /// later; on a non-durable kernel there is no sweep, so the hold is retained
    /// until an operator acts. The `reconciliation` label separates the two.
    /// Only a genuine retention is counted; a pure deny that released everything
    /// is not.
    pub(crate) fn note_retained_ambiguous_hold(&self, retained: bool) {
        if !retained {
            return;
        }
        let reconciliation = if self.durable_admission_runtime.is_some() {
            "durable"
        } else {
            "none"
        };
        chio_metrics_spec::runtime::families::AMBIGUOUS_DISPATCH_RETAINED_HOLD
            .incr(&[reconciliation]);
    }

    fn cumulative_approval_request_for_grant(
        &self,
        request: &ToolCallRequest,
        matching: &MatchingGrant<'_>,
        admission: Option<&DurableToolAdmission>,
        now: u64,
    ) -> Result<Option<BudgetCumulativeApprovalRequest>, KernelError> {
        let cumulative_constraint_count = matching
            .grant
            .constraints
            .iter()
            .filter(|constraint| {
                matches!(
                    constraint,
                    Constraint::RequireCumulativeApprovalAbove { .. }
                )
            })
            .count();
        if cumulative_constraint_count == 0 {
            return Ok(None);
        }
        if cumulative_constraint_count != 1 {
            return Err(KernelError::GovernedTransactionDenied(
                "a matching grant must contain exactly one cumulative approval constraint"
                    .to_owned(),
            ));
        }
        let admission = admission.ok_or_else(|| {
            KernelError::DurableAdmission(
                "cumulative approval requires a durable admission operation".to_owned(),
            )
        })?;
        let peer = self
            .capability_negotiation_for_remote(request.federated_origin_kernel_id.as_deref(), now)
            .map_err(KernelError::GovernedTransactionDenied)?;
        if !peer.supports(chio_core::capability::features::CUMULATIVE_APPROVAL_BUDGET) {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval budgets were not negotiated".to_owned(),
            ));
        }
        let direct_root = self
            .negotiated_capability_root(&request.capability, &peer)
            .map_err(KernelError::GovernedTransactionDenied)?;
        let verified =
            chio_core::capability::cumulative_approval::verify_cumulative_approval_constraints(
                &request.capability,
                &self.trusted_issuer_keys(),
                direct_root.as_ref(),
            )
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let mut matching_constraints = verified
            .into_iter()
            .filter(|constraint| constraint.grant_index == matching.index);
        let constraint = matching_constraints.next().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval verification omitted the matching grant".to_owned(),
            )
        })?;
        if matching_constraints.next().is_some() {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval verification produced an ambiguous grant".to_owned(),
            ));
        }
        let intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval requires a governed transaction intent".to_owned(),
            )
        })?;
        if intent.server_id != request.server_id || intent.tool_name != request.tool_name {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval intent target does not match the request".to_owned(),
            ));
        }
        let requested_authorized = intent.max_amount.clone().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval intent requires a maximum amount".to_owned(),
            )
        })?;
        if requested_authorized.currency != constraint.threshold.currency {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval intent currency does not match the capability".to_owned(),
            ));
        }
        Ok(Some(BudgetCumulativeApprovalRequest {
            operation_id: admission.operation_id().to_owned(),
            account_key: BudgetCumulativeApprovalAccountKey {
                authority_id: constraint.authority_id.to_hex(),
                owner_id: constraint.owner_id,
                approval_budget_id: constraint.approval_budget_id,
                approval_budget_epoch: constraint.approval_budget_epoch,
                root_grant_hash: constraint.root_grant_hash,
                delegation_root_id: constraint.delegation_root_id,
                root_binding_digest: constraint.root_binding_digest,
                currency: constraint.threshold.currency.clone(),
            },
            authority_threshold: constraint.authority_threshold,
            effective_threshold: constraint.threshold,
            requested_authorized,
        }))
    }

    fn ensure_cumulative_approval_proposal(
        &self,
        request: &ToolCallRequest,
        required: &ApprovalRequiredBudgetHold,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<chio_core::capability::governance::ThresholdApprovalProposal, KernelError> {
        if admission.operation.state() == AdmissionOperationState::ApprovalRequired {
            if admission
                .operation
                .budget_hold_id()
                .is_none_or(|hold_id| hold_id.as_str() != required.hold_id)
            {
                return Err(KernelError::DurableAdmission(
                    "retained approval proposal changed its budget hold".to_owned(),
                ));
            }
            return admission
                .operation
                .threshold_proposal()
                .cloned()
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "approval-required operation omitted its stored proposal".to_owned(),
                    )
                });
        }
        let now = trusted_now_unix_ms / 1_000;
        let requirement = self.threshold_approval_requirement(request, now)?;
        let intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval requires a governed transaction intent".to_owned(),
            )
        })?;
        let intent_hash = intent
            .binding_hash()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let capability_digest = sha256_hex(
            &canonical_json_bytes(&request.capability)
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?,
        );
        let proposal_created_at = required.metadata.recorded_at_unix_seconds.ok_or_else(|| {
            KernelError::DurableAdmission(
                "cumulative approval authorization omitted its durable timestamp".to_owned(),
            )
        })?;
        let proposal_deadline =
            chio_core::capability::governance::ThresholdApprovalProposalBody::proposal_deadline(
                proposal_created_at,
                requirement.timeout_seconds,
                request.capability.expires_at,
                intent.governed_operation_expires_at(),
            )
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let proposal = chio_core::capability::governance::ThresholdApprovalProposal::sign(
            chio_core::capability::governance::ThresholdApprovalProposalBody {
                schema: chio_core::capability::governance::THRESHOLD_APPROVAL_PROPOSAL_SCHEMA
                    .to_owned(),
                proposal_id: admission.operation_id().to_owned(),
                request_id: request.request_id.clone(),
                governed_intent_hash: intent_hash,
                subject: request.capability.subject.clone(),
                authorizing_capability_digest: capability_digest,
                policy_hash: requirement.policy_hash,
                threshold: requirement.threshold,
                eligible_set_digest: requirement.eligible_set_digest,
                proposal_created_at,
                proposal_deadline,
                policy_authority: self.config.keypair.public_key(),
            },
            &self.config.keypair,
        )
        .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let proposal_hash = AdmissionDigest::try_new(
            "threshold_proposal_hash",
            proposal
                .artifact_digest()
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?,
        )?;
        admission.operation = self.apply_admission_command(
            admission.operation.clone(),
            vec![
                AdmissionAttachment::ThresholdProposalHash(proposal_hash),
                AdmissionAttachment::BudgetHoldId(AdmissionIdentifier::try_new(
                    "budget_hold_id",
                    required.hold_id.clone(),
                )?),
                AdmissionAttachment::ThresholdProposal(Box::new(proposal.clone())),
            ],
            AdmissionOperationState::ApprovalRequired,
            trusted_now_unix_ms,
        )?;
        Ok(proposal)
    }

    fn authorize_cumulative_approval(
        &self,
        request: &ToolCallRequest,
        grant_index: usize,
        required: &ApprovalRequiredBudgetHold,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::budget_store::BudgetHoldMutationDecision, KernelError> {
        let proposal = self.ensure_cumulative_approval_proposal(
            request,
            required,
            admission,
            trusted_now_unix_ms,
        )?;
        if request.threshold_approval_proposal.as_ref() != Some(&proposal) {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold approval request does not carry the stored proposal".to_owned(),
            ));
        }
        let intent_hash = request
            .governed_intent
            .as_ref()
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "cumulative approval requires a governed transaction intent".to_owned(),
                )
            })?
            .binding_hash()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let verified = self.validate_threshold_approval_set(
            request,
            &request.capability,
            &intent_hash,
            trusted_now_unix_ms / 1_000,
        )?;
        let approval_set_digest = verified
            .body
            .approval_set_hash()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let decision = self.with_budget_store(|store| {
            Ok(
                store.authorize_cumulative_approval(BudgetAuthorizeCumulativeApprovalRequest {
                    capability_id: request.capability.id.clone(),
                    grant_index,
                    operation_id: admission.operation_id().to_owned(),
                    hold_id: required.hold_id.clone(),
                    admission_binding: required.admission_binding.clone(),
                    approval_set_digest,
                    event_id: format!("{}:authorize-cumulative", required.hold_id),
                    authority: required.metadata.authority.clone(),
                })?,
            )
        })?;
        let mutation = match decision {
            BudgetCumulativeApprovalAuthorizationDecision::Authorized(mutation)
            | BudgetCumulativeApprovalAuthorizationDecision::AlreadyAuthorized(mutation) => {
                mutation
            }
        };
        admission.operation = self.apply_admission_command(
            admission.operation.clone(),
            Vec::new(),
            AdmissionOperationState::BudgetAuthorized,
            trusted_now_unix_ms,
        )?;
        Ok(mutation)
    }

    /// Check and decrement the invocation budget for a capability.
    ///
    /// Returns the matched grant index and the exact pre-execution budget mutation.
    pub(crate) fn check_and_increment_budget(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        matching_grants: &[MatchingGrant<'_>],
        nonce_preflight: bool,
        mut durable_admission: Option<&mut DurableToolAdmission>,
        trusted_now_unix_ms: u64,
    ) -> Result<BudgetAdmissionOutcome, KernelError> {
        let mut saw_exhausted_budget = false;
        let mut eligible_grant_seen = false;

        for matching in matching_grants {
            if durable_admission
                .as_deref()
                .is_some_and(|admission| !admission.permits_matching_grant(matching))
            {
                continue;
            }
            eligible_grant_seen = true;
            let grant = matching.grant;
            let has_monetary =
                grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();

            if has_monetary
                || (nonce_preflight && grant.max_invocations.is_some())
                || durable_admission.is_some()
            {
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
                let (budget_hold_id, authorize_event_id, admission_binding, authority) =
                    if let Some(admission) = durable_admission.as_deref() {
                        let (binding, authority) = self.durable_budget_binding(admission, cap)?;
                        (
                            admission.budget_hold_id(matching.index),
                            admission.budget_authorize_event_id(matching.index),
                            Some(binding),
                            authority,
                        )
                    } else {
                        let budget_hold_id = if nonce_preflight {
                            format!(
                                "nonce-preflight-budget-hold:{}:{}:{}",
                                request.request_id, cap.id, matching.index
                            )
                        } else {
                            format!(
                                "budget-hold:{}:{}:{}",
                                request.request_id, cap.id, matching.index
                            )
                        };
                        (
                            budget_hold_id.clone(),
                            format!("{budget_hold_id}:authorize"),
                            None,
                            self.local_budget_event_authority(),
                        )
                    };

                let mut invocation_quotas = Vec::with_capacity(3);
                if let Some(admission) = durable_admission.as_deref() {
                    if admission.aggregate_quota().is_some()
                        || admission.supplemental_quota().is_some()
                    {
                        if let Some(max_invocations) = grant.max_invocations {
                            invocation_quotas.push(BudgetInvocationQuota {
                                key: BudgetQuotaKey::grant(
                                    cap.id.clone(),
                                    u32::try_from(matching.index).map_err(|_| {
                                        KernelError::DurableAdmission(
                                            "matching grant index exceeds u32".to_string(),
                                        )
                                    })?,
                                ),
                                max_invocations,
                            });
                        }
                    }
                    if let Some(aggregate) = admission.aggregate_quota() {
                        invocation_quotas.push(aggregate.clone());
                    }
                    if let Some(supplemental) = admission.supplemental_quota() {
                        invocation_quotas.push(BudgetInvocationQuota {
                            key: BudgetQuotaKey {
                                profile: BudgetQuotaProfile::SupplementalBrokerCapabilityExecution,
                                owner_id: supplemental.owner_id().to_string(),
                                grant_index: None,
                            },
                            max_invocations: supplemental.max_invocations(),
                        });
                    }
                }
                invocation_quotas.sort_by(|left, right| left.key.cmp(&right.key));
                let cumulative_approval = self.cumulative_approval_request_for_grant(
                    request,
                    matching,
                    durable_admission.as_deref(),
                    trusted_now_unix_ms / 1_000,
                )?;
                let authorization_request = BudgetAuthorizeHoldRequest {
                    capability_id: cap.id.clone(),
                    grant_index: matching.index,
                    max_invocations: grant.max_invocations,
                    invocation_quotas,
                    cumulative_approval,
                    admission_binding,
                    requested_exposure_units: cost_units,
                    max_cost_per_invocation: max_per,
                    max_total_cost_units: max_total,
                    hold_id: Some(budget_hold_id.clone()),
                    event_id: Some(authorize_event_id),
                    authority: Some(authority.clone()),
                };
                let decision = if let Some(admission) = durable_admission.as_deref_mut() {
                    let payment_journal = if admission.requires_payment() {
                        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "durable monetary authorization lost its payment adapter"
                                    .to_owned(),
                            )
                        })?;
                        let rail_mode = adapter.rail_mode().ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "durable monetary authorization lost its payment rail mode"
                                    .to_owned(),
                            )
                        })?;
                        let journal = crate::payment::PaymentJournalRecord {
                            operation_id: admission.operation_id().to_owned(),
                            journal_version: 1,
                            request_namespace_digest: admission
                                .operation()
                                .binding()
                                .request_namespace_digest()
                                .as_str()
                                .to_owned(),
                            request_id: admission
                                .operation()
                                .binding()
                                .request_id()
                                .as_str()
                                .to_owned(),
                            capability_id: cap.id.clone(),
                            grant_index: u32::try_from(matching.index).map_err(|_| {
                                KernelError::DurableAdmission(
                                    "payment grant index exceeds the durable journal range"
                                        .to_owned(),
                                )
                            })?,
                            hold_id: Some(budget_hold_id.clone()),
                            rail: adapter.rail_id().to_owned(),
                            rail_mode,
                            authorization_id: None,
                            transaction_id: None,
                            amount_units: cost_units,
                            settle_action: None,
                            settle_amount_units: None,
                            release_authority: None,
                            currency: currency.clone(),
                            state: crate::payment::PaymentJournalState::HoldPlaced,
                            created_at_unix_ms: trusted_now_unix_ms.max(1),
                        };
                        journal
                            .validate()
                            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                        Some(journal)
                    } else {
                        None
                    };
                    self.authorize_durable_budget_hold(
                        admission,
                        authorization_request,
                        payment_journal,
                        trusted_now_unix_ms,
                    )?
                } else {
                    self.with_budget_store(|store| {
                        Ok(store.authorize_budget_hold(authorization_request)?)
                    })?
                };
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
                            invocation_capture: None,
                        };
                        let mutation = if has_monetary {
                            PreExecutionBudgetMutation::Charge(charge)
                        } else {
                            PreExecutionBudgetMutation::InvocationHold(charge)
                        };
                        return Ok(BudgetAdmissionOutcome::Authorized {
                            grant_index: matching.index,
                            mutation: Box::new(mutation),
                        });
                    }
                    BudgetAuthorizeHoldDecision::Denied(_) => {
                        saw_exhausted_budget = true;
                    }
                    BudgetAuthorizeHoldDecision::ApprovalRequired(required) => {
                        let admission = durable_admission.as_deref_mut().ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "cumulative approval lost its durable operation".to_owned(),
                            )
                        })?;
                        let proposal = self.ensure_cumulative_approval_proposal(
                            request,
                            &required,
                            admission,
                            trusted_now_unix_ms,
                        )?;
                        if request.approval_tokens.is_empty() {
                            return Ok(BudgetAdmissionOutcome::PendingApproval {
                                grant_index: matching.index,
                                proposal: Box::new(proposal),
                            });
                        }
                        let authorized = self.authorize_cumulative_approval(
                            request,
                            matching.index,
                            &required,
                            admission,
                            trusted_now_unix_ms,
                        )?;
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
                            invocation_capture: None,
                        };
                        let mutation = if has_monetary {
                            PreExecutionBudgetMutation::Charge(charge)
                        } else {
                            PreExecutionBudgetMutation::InvocationHold(charge)
                        };
                        return Ok(BudgetAdmissionOutcome::Authorized {
                            grant_index: matching.index,
                            mutation: Box::new(mutation),
                        });
                    }
                    BudgetAuthorizeHoldDecision::AlreadyCaptured(captured) => {
                        if !durable_admission
                            .as_deref()
                            .is_some_and(DurableToolAdmission::can_resume_captured_hold)
                        {
                            return Err(KernelError::CapturedBudgetReplay(cap.id.clone()));
                        }
                        let charge = BudgetChargeResult {
                            grant_index: matching.index,
                            cost_charged: cost_units,
                            currency,
                            budget_total,
                            new_committed_cost_units: captured.committed_cost_units_after,
                            budget_hold_id: captured
                                .hold_id
                                .clone()
                                .unwrap_or_else(|| budget_hold_id.clone()),
                            authorize_metadata: captured.metadata.clone(),
                            invocation_capture: Some(Box::new(captured)),
                        };
                        let mutation = if has_monetary {
                            PreExecutionBudgetMutation::Charge(charge)
                        } else {
                            PreExecutionBudgetMutation::InvocationHold(charge)
                        };
                        return Ok(BudgetAdmissionOutcome::Authorized {
                            grant_index: matching.index,
                            mutation: Box::new(mutation),
                        });
                    }
                }
            } else {
                if grant.max_invocations.is_none() {
                    return Ok(BudgetAdmissionOutcome::Authorized {
                        grant_index: matching.index,
                        mutation: Box::new(PreExecutionBudgetMutation::None),
                    });
                }

                if self.with_budget_store(|store| {
                    Ok(store.try_increment(&cap.id, matching.index, grant.max_invocations)?)
                })? {
                    return Ok(BudgetAdmissionOutcome::Authorized {
                        grant_index: matching.index,
                        mutation: Box::new(PreExecutionBudgetMutation::Invocation {
                            grant_index: matching.index,
                        }),
                    });
                }
                saw_exhausted_budget = true;
            }
        }

        if durable_admission.is_some() && !eligible_grant_seen {
            Err(KernelError::DurableAdmission(
                "retained budget hold does not identify a matching grant".to_string(),
            ))
        } else if saw_exhausted_budget {
            Err(KernelError::BudgetExhausted(cap.id.clone()))
        } else {
            // No matching grant had any limit -- allow with the first grant's index.
            let first_index = matching_grants.first().map(|m| m.index).unwrap_or(0);
            Ok(BudgetAdmissionOutcome::Authorized {
                grant_index: first_index,
                mutation: Box::new(PreExecutionBudgetMutation::None),
            })
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
                expected_cumulative_approval_state: None,
                authority,
            })?)
        })
    }

    pub(crate) fn capture_invocation(
        &self,
        cap: &CapabilityToken,
        budget_mutation: &mut PreExecutionBudgetMutation,
    ) -> Result<BudgetInvocationCaptureDecision, KernelError> {
        let charge = budget_mutation.durable_hold_result_mut().ok_or_else(|| {
            KernelError::Internal(
                "invocation capture requires an authorized budget hold".to_string(),
            )
        })?;
        let authority = charge.authorize_metadata.authority.clone();
        let decision = self.with_budget_store(|store| {
            Ok(
                store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
                    capability_id: cap.id.clone(),
                    grant_index: charge.grant_index,
                    hold_id: charge.budget_hold_id.clone(),
                    event_id: charge.capture_invocation_event_id(),
                    trusted_time: None,
                    authority,
                })?,
            )
        })?;
        let capture = match &decision {
            BudgetInvocationCaptureDecision::Captured(capture)
            | BudgetInvocationCaptureDecision::AlreadyCaptured(capture) => capture,
        };
        charge.invocation_capture = Some(Box::new(capture.clone()));
        Ok(decision)
    }

    pub(crate) fn cancel_captured_monetary_before_dispatch(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
    ) -> Result<BudgetHoldMutationDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        let decision = self.with_budget_store(|store| {
            Ok(store.cancel_captured_before_dispatch(
                BudgetCancelCapturedBeforeDispatchRequest {
                    capability_id: capability_id.to_string(),
                    grant_index: charge.grant_index,
                    hold_id: charge.budget_hold_id.clone(),
                    event_id: charge.cancel_captured_before_dispatch_event_id(),
                    authority,
                },
            )?)
        })?;
        Ok(match decision {
            BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(mutation)
            | BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(mutation) => {
                mutation
            }
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
            PreExecutionBudgetMutation::InvocationHold(hold) => {
                self.reverse_budget_charge(&cap.id, hold).map(Some)
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

    pub(crate) fn tool_server_measures_realized_cost(&self, server_id: &str) -> bool {
        self.tool_servers
            .get(server_id)
            .is_none_or(|server| server.measures_realized_cost())
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_unmeasured_cost_provisional_allow(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        charge: BudgetChargeResult,
        extra_metadata: Option<serde_json::Value>,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let reverse = if charge.invocation_capture.is_some() {
            self.cancel_captured_monetary_before_dispatch(&cap.id, &charge)?
        } else {
            self.reverse_budget_charge(&cap.id, &charge)?
        };
        let financial = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: 0,
            currency: charge.currency.clone(),
            budget_remaining: charge
                .budget_total
                .saturating_sub(reverse.committed_cost_units_after),
            budget_total: charge.budget_total,
            delegation_depth: cap.delegation_chain.len() as u32,
            root_budget_holder: cap.issuer.to_hex(),
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(value) => ToolCallOutput::Value(value.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream))
            | ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };
        let budget_metadata =
            self.budget_execution_receipt_metadata(&charge, Some(("reversed", &reverse)), None);
        let metadata = merge_metadata_objects(
            Some(serde_json::json!({ "financial": financial })),
            self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
        );

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata_and_payee_binding(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    metadata,
                    verified_payee_binding,
                    AllowResponseNonce::Suppressed,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output_metadata_and_payee_binding(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    self.mark_runtime_admission_reservations_retained_fail_closed(metadata),
                    verified_payee_binding,
                ),
        }
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
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<ToolCallResponse, KernelError> {
        let FinalizeToolOutputCostContext {
            charge_result,
            reported_cost,
            payment_authorization,
            cap,
        } = cost_context;
        let Some(charge) = charge_result else {
            if let Some(authorization) = payment_authorization.as_ref() {
                let (quoted_units, quoted_currency) = Self::mustprepay_quoted_amount(request)
                    .ok_or_else(|| {
                        KernelError::GovernedTransactionDenied(
                            "payment authorization omitted its MustPrepay quote".to_string(),
                        )
                    })?;
                let settlement = if authorization.state.is_final() {
                    ReceiptSettlement::from_authorization(authorization)
                } else {
                    let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                        KernelError::Internal(
                            "payment authorization present without configured adapter".to_string(),
                        )
                    })?;
                    let result = match adapter.capture(
                        &authorization.authorization_id,
                        quoted_units,
                        &quoted_currency,
                        &request.request_id,
                    ) {
                        Ok(result) => result,
                        Err(error) => {
                            let _ = adapter
                                .release(&authorization.authorization_id, &request.request_id);
                            return self.build_deny_response_with_metadata(
                                request,
                                &format!(
                                    "MustPrepay authorization could not be settled after execution: {error}"
                                ),
                                timestamp,
                                Some(matched_grant_index),
                                extra_metadata,
                            );
                        }
                    };
                    if result.settlement_status != crate::payment::RailSettlementStatus::Settled {
                        let _ =
                            adapter.release(&authorization.authorization_id, &request.request_id);
                    }
                    ReceiptSettlement::from_payment_result(&result)
                };
                if settlement.settlement_status != SettlementStatus::Settled {
                    return self.build_deny_response_with_metadata(
                        request,
                        "MustPrepay authorization could not be settled after execution",
                        timestamp,
                        Some(matched_grant_index),
                        extra_metadata,
                    );
                }
                let (payment_reference, settlement_status) = settlement.into_receipt_parts();
                let financial = FinancialReceiptMetadata {
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
                let metadata = merge_metadata_objects(
                    extra_metadata,
                    Some(serde_json::json!({ "financial": financial })),
                );
                return self.finalize_tool_output_with_metadata_and_payee_binding(
                    request,
                    output,
                    elapsed,
                    timestamp,
                    matched_grant_index,
                    metadata,
                    verified_payee_binding,
                );
            }
            return self.finalize_tool_output_with_metadata_and_payee_binding(
                request,
                output,
                elapsed,
                timestamp,
                matched_grant_index,
                extra_metadata,
                verified_payee_binding,
            );
        };

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
                verified_payee_binding,
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
            .is_some_and(|authorization| authorization.state.is_final());
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
            if authorization.state.is_final() || cross_currency_failed || cost_overrun {
                None
            } else {
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::Internal(
                        "payment authorization present without configured adapter".to_string(),
                    )
                })?;
                Some(if actual_cost == 0 {
                    adapter.release(&authorization.authorization_id, &request.request_id)
                } else {
                    adapter.capture(
                        &authorization.authorization_id,
                        actual_cost,
                        &charge.currency,
                        &request.request_id,
                    )
                })
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
            if authorization.state.is_final() {
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

        let preminted_execution_nonce = if request.execution_nonce.is_none() {
            if let Some(nonce_config) = self.execution_nonce_config.as_ref() {
                let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(
                    |error| {
                        KernelError::ReceiptSigningFailed(format!(
                            "failed to hash parameters for nonce binding: {error}"
                        ))
                    },
                )?;
                let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
                let binding = crate::execution_nonce::NonceBinding {
                    subject_id: cap.subject.to_hex(),
                    request_id: request.request_id.clone(),
                    capability_id: cap.id.clone(),
                    tool_server: request.server_id.clone(),
                    tool_name: request.tool_name.clone(),
                    parameter_hash: action.parameter_hash,
                };
                Some(Box::new(crate::execution_nonce::mint_execution_nonce(
                    &self.config.keypair,
                    binding,
                    nonce_config,
                    now,
                )?))
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
                let budget_metadata = self.budget_execution_receipt_metadata(
                    &charge,
                    Some(("reconciled", &reconcile)),
                    preminted_execution_nonce
                        .as_deref()
                        .map(|nonce| nonce.nonce_id())
                        .or_else(|| {
                            request
                                .execution_nonce
                                .as_ref()
                                .map(|nonce| nonce.nonce_id())
                        }),
                );
                let merged_extra_metadata = merge_metadata_objects(
                    financial_json,
                    self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
                );
                self.build_allow_response_with_metadata_and_payee_binding(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    merged_extra_metadata,
                    verified_payee_binding,
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
                let merged_extra_metadata = merge_metadata_objects(
                    financial_json,
                    self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
                );
                self.build_incomplete_response_with_output_metadata_and_payee_binding(
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
                    self.mark_runtime_admission_reservations_retained_fail_closed(
                        merged_extra_metadata,
                    ),
                    verified_payee_binding,
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
        durable_admission: Option<&DurableToolAdmission>,
        trusted_now_unix_ms: u64,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        let (amount_units, currency) = if let Some(amount) = Self::mustprepay_quoted_amount(request)
        {
            amount
        } else if let Some(charge) = charge_result {
            (charge.cost_charged, charge.currency.clone())
        } else {
            return Ok(None);
        };
        let Some(adapter) = self.payment_adapter.as_ref() else {
            if Self::is_governed_mustprepay_request(request) {
                return Err(PaymentError::RailError(
                    "MustPrepay intent reached payment authorization without a configured adapter"
                        .to_string(),
                ));
            }
            return Ok(None);
        };
        let durable_journal = durable_admission
            .filter(|_| charge_result.is_some())
            .map(|admission| {
                self.load_durable_payment_journal(admission)
                    .map_err(|error| PaymentError::RailError(error.to_string()))
            })
            .transpose()?;
        if let Some(journal) = durable_journal.as_ref() {
            let rail_mode = adapter.rail_mode().ok_or_else(|| {
                PaymentError::RailError("durable payment adapter omitted its rail mode".to_owned())
            })?;
            if adapter.rail_id() != journal.rail || rail_mode != journal.rail_mode {
                return Err(PaymentError::RailError(
                    "durable payment adapter does not match the persisted rail profile".to_owned(),
                ));
            }
            match (journal.state, journal.rail_mode) {
                (
                    crate::payment::PaymentJournalState::Authorized,
                    crate::payment::PaymentRailMode::ReversibleHold,
                ) => {
                    return Ok(Some(PaymentAuthorization {
                        authorization_id: journal.authorization_id.clone().ok_or_else(|| {
                            PaymentError::RailError(
                                "authorized payment journal omitted authorization_id".to_owned(),
                            )
                        })?,
                        state: crate::payment::PaymentAuthorizationState::Held,
                        metadata: serde_json::json!({ "durable_replay": true }),
                    }));
                }
                (
                    crate::payment::PaymentJournalState::Settled,
                    crate::payment::PaymentRailMode::PrepaidFinal,
                ) => {
                    return Ok(Some(PaymentAuthorization {
                        authorization_id: journal.authorization_id.clone().ok_or_else(|| {
                            PaymentError::RailError(
                                "settled prepayment journal omitted authorization_id".to_owned(),
                            )
                        })?,
                        state: crate::payment::PaymentAuthorizationState::PrepaidFinal,
                        metadata: serde_json::json!({ "durable_replay": true }),
                    }));
                }
                (crate::payment::PaymentJournalState::HoldPlaced, _) => {}
                _ => {
                    return Err(PaymentError::RailError(format!(
                        "payment journal cannot authorize from state {:?}",
                        journal.state
                    )));
                }
            }
        }

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
                            .map(|token| token.id.clone())
                            .or_else(|| {
                                request
                                    .threshold_approval_proposal
                                    .as_ref()
                                    .map(|proposal| proposal.body.proposal_id.clone())
                            }),
                    })
                    .map_err(|error| {
                        PaymentError::RailError(format!(
                            "failed to hash governed intent for payment authorization: {error}"
                        ))
                    })
            })
            .transpose()?;
        let commerce = if amount_units == 0 {
            None
        } else if let Some(commerce) = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.commerce.as_ref())
        {
            let binding = verified_payee_binding.ok_or_else(|| {
                PaymentError::RailError(
                    "governed commerce payment omitted verified payee binding".to_owned(),
                )
            })?;
            let approval_artifact_digest = request
                .approval_artifact_digest()
                .map_err(|error| PaymentError::RailError(error.to_string()))?
                .ok_or_else(|| {
                    PaymentError::RailError(
                        "governed commerce payment omitted verified approval".to_owned(),
                    )
                })?;
            let intent_hash = governed
                .as_ref()
                .map(|context| context.intent_hash.as_str());
            if binding.beneficiary_id() != commerce.seller
                || commerce.settlement_destination_ref.as_deref()
                    != Some(binding.settlement_destination_ref())
                || intent_hash != Some(binding.economic_intent_digest())
                || binding.pre_action_authority_digest() != approval_artifact_digest.as_str()
            {
                return Err(PaymentError::RailError(
                    "governed commerce payment does not match verified payee binding".to_owned(),
                ));
            }
            Some(CommercePaymentContext {
                seller: binding.beneficiary_id().to_owned(),
                settlement_destination_ref: binding.settlement_destination_ref().to_owned(),
                payee_binding_digest: binding.payee_binding_digest().to_owned(),
                pre_action_authority_digest: binding.pre_action_authority_digest().to_owned(),
                shared_payment_token_id: commerce.shared_payment_token_id.clone(),
                max_amount: request
                    .governed_intent
                    .as_ref()
                    .and_then(|intent| intent.max_amount.clone()),
            })
        } else {
            if verified_payee_binding.is_some() {
                return Err(PaymentError::RailError(
                    "verified payee binding has no governed commerce context".to_owned(),
                ));
            }
            None
        };
        let payee = verified_payee_binding.map_or_else(
            || request.server_id.clone(),
            |binding| binding.beneficiary_id().to_owned(),
        );

        let authorization = adapter.authorize(&PaymentAuthorizeRequest {
            amount_units,
            currency,
            payer: request.agent_id.clone(),
            payee,
            reference: durable_journal.as_ref().map_or_else(
                || request.request_id.clone(),
                |journal| journal.operation_id.clone(),
            ),
            governed,
            commerce,
        })?;
        if let (Some(admission), Some(journal)) = (durable_admission, durable_journal.as_ref()) {
            if !journal.rail_mode.accepts(authorization.state) {
                return Err(PaymentError::RailError(
                    "payment authorization state does not match the persisted rail mode".to_owned(),
                ));
            }
            let transition = match authorization.state {
                crate::payment::PaymentAuthorizationState::Held => {
                    crate::payment::PaymentJournalTransition::AuthorizationHeld {
                        authorization_id: authorization.authorization_id.clone(),
                    }
                }
                crate::payment::PaymentAuthorizationState::PrepaidFinal => {
                    crate::payment::PaymentJournalTransition::PrepaymentSettled {
                        authorization_id: authorization.authorization_id.clone(),
                    }
                }
            };
            let advanced = self
                .advance_durable_payment_journal(
                    admission,
                    journal,
                    &transition,
                    trusted_now_unix_ms,
                )
                .map_err(|error| PaymentError::RailError(error.to_string()))?;
            if advanced.authorization_id.as_deref() != Some(&authorization.authorization_id) {
                return Err(PaymentError::RailError(
                    "durable payment journal changed authorization identity".to_owned(),
                ));
            }
        }
        Ok(Some(authorization))
    }

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

    pub(crate) fn is_governed_mustprepay_request(request: &ToolCallRequest) -> bool {
        Self::mustprepay_quoted_amount(request).is_some()
    }

    pub(crate) fn ensure_reserved_mustprepay_prepaid(
        &self,
        request: &ToolCallRequest,
        charge_result: Option<&BudgetChargeResult>,
        durable_admission: Option<&DurableToolAdmission>,
        trusted_now_unix_ms: u64,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<Option<ReservedPrepayment>, KernelError> {
        if !Self::is_governed_mustprepay_request(request) {
            return Ok(None);
        }
        let authorization = self
            .authorize_payment_if_needed(
                request,
                charge_result,
                durable_admission,
                trusted_now_unix_ms,
                verified_payee_binding,
            )
            .map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "MustPrepay prepayment authorization failed before reserving an execution nonce: {error}"
                ))
            })?
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "MustPrepay reservation omitted its payment authorization".to_string(),
                )
            })?;

        if authorization.state.is_final() {
            return Ok(Some(ReservedPrepayment {
                payment_reference: Some(authorization.authorization_id.clone()),
                authorization,
            }));
        }

        let (amount_units, currency) =
            Self::mustprepay_quoted_amount(request).ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "MustPrepay reservation omitted its quoted amount".to_string(),
                )
            })?;
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "MustPrepay reservation omitted its payment adapter".to_string(),
            )
        })?;
        let result = match adapter.capture(
            &authorization.authorization_id,
            amount_units,
            &currency,
            &request.request_id,
        ) {
            Ok(result) => result,
            Err(error) => {
                let _ = adapter.release(&authorization.authorization_id, &request.request_id);
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "MustPrepay prepayment capture failed before reserving an execution nonce: {error}"
                )));
            }
        };
        if result.settlement_status != crate::payment::RailSettlementStatus::Settled {
            let _ = adapter.release(&authorization.authorization_id, &request.request_id);
            return Err(KernelError::GovernedTransactionDenied(
                "MustPrepay prepayment capture was not confirmed settled".to_string(),
            ));
        }
        Ok(Some(ReservedPrepayment {
            authorization: PaymentAuthorization {
                state: crate::payment::PaymentAuthorizationState::PrepaidFinal,
                ..authorization
            },
            payment_reference: Some(result.transaction_id),
        }))
    }

    pub(crate) fn refund_reserved_mustprepay_prepayment(
        &self,
        request: &ToolCallRequest,
        prepayment: &PaymentAuthorization,
    ) {
        let Some((amount_units, currency)) = Self::mustprepay_quoted_amount(request) else {
            return;
        };
        let Some(adapter) = self.payment_adapter.as_ref() else {
            return;
        };
        if let Err(error) = adapter.refund(
            &prepayment.authorization_id,
            amount_units,
            &currency,
            &request.request_id,
        ) {
            warn!(
                request_id = %request.request_id,
                authorization_id = %prepayment.authorization_id,
                reason = %redacted!(&error),
                "failed to refund captured MustPrepay prepayment after reservation failure"
            );
        }
    }
}
