//! `ChioKernel` capability and budget validation.
//!
//! Holds capability issuance/revocation, tool-server event drains, portable
//! verdict helpers, and budget charge/reconcile helpers. Governed-admission
//! validation lives in `governed_validation.rs`.

use chio_log_redact::redacted;

use self::responses::FinalizeToolOutputCostContext;
use super::*;
use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetEventAuthority,
    BudgetHoldMutationDecision, BudgetReconcileHoldDecision, BudgetReconcileHoldRequest,
    BudgetReverseHoldDecision, BudgetReverseHoldRequest,
};

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
            let proposed_share = cap
                .budget_share_bps
                .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS);
            let mut budgets = match self.budget_registry.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
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
                Err(poisoned) => poisoned.into_inner(),
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
            Err(poisoned) => poisoned.into_inner(),
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
            Err(poisoned) => poisoned.into_inner(),
        };
        budgets.register_parent(parent_token_id, parent_share_bps)
    }

    pub fn evict_budget_parent(&self, parent_token_id: &str) {
        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
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
            return self.finalize_tool_output_with_metadata(
                request,
                output,
                elapsed,
                timestamp,
                matched_grant_index,
                extra_metadata,
            );
        };

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

        let budget_metadata =
            self.budget_execution_receipt_metadata(&charge, Some(("reconciled", &reconcile)));
        let merged_extra_metadata =
            self.merge_budget_receipt_metadata(extra_metadata, budget_metadata);
        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));
        let merged_extra_metadata = merge_metadata_objects(financial_json, merged_extra_metadata);

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    merged_extra_metadata.clone(),
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
                    // so the burned lease is recoverable from the receipt,
                    // matching the RequestIncomplete error arm.
                    self.mark_runtime_admission_reservations_retained_fail_closed(
                        merged_extra_metadata,
                    ),
                ),
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
        let Some(charge) = charge_result else {
            return Ok(None);
        };
        let Some(adapter) = self.payment_adapter.as_ref() else {
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

        adapter
            .authorize(&PaymentAuthorizeRequest {
                amount_units: charge.cost_charged,
                currency: charge.currency.clone(),
                payer: request.agent_id.clone(),
                payee: request.server_id.clone(),
                reference: request.request_id.clone(),
                governed,
                commerce,
            })
            .map(Some)
    }
}
