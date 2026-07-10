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
            let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "payment authorization present without configured adapter".to_string(),
                )
            })?;
            let unwind_result = if authorization.settled {
                adapter.refund(
                    &authorization.authorization_id,
                    charge.cost_charged,
                    &charge.currency,
                    &request.request_id,
                )
            } else {
                adapter.release(&authorization.authorization_id, &request.request_id)
            };
            if let Err(error) = unwind_result {
                return Err(KernelError::Internal(format!(
                    "failed to unwind payment after aborted tool invocation: {error}"
                )));
            }
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
        let _ = self.with_receipt_store(|store| {
            Ok(store.record_capability_snapshot(capability, parent_capability_id)?)
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

        let mut evidence = Vec::new();
        for guard in &self.guards {
            match guard.evaluate(&ctx) {
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
    ) -> Option<serde_json::Value> {
        let metadata_value = metadata?;
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            return Some(metadata_value);
        };

        match hook.release_reserved(&metadata_value) {
            Ok(()) => Some(metadata_value),
            Err(error) => {
                let reason = error.to_string();
                warn!(
                    hook = hook.name(),
                    reason = %redacted!(&reason),
                    "runtime admission reservation release failed on pre-dispatch denial"
                );
                merge_metadata_objects(
                    Some(metadata_value),
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "reservation_release_failed": true,
                            "reservation_release_failure_reason": reason
                        }
                    })),
                )
            }
        }
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
        receipts: Vec<ChildRequestReceipt>,
    ) -> Result<(), KernelError> {
        for receipt in receipts {
            let receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
                KernelError::Internal("receipt store write lock poisoned".to_string())
            })?;
            self.with_receipt_store(|store| {
                Ok(store.append_child_receipt_returning_seq(&receipt)?)
            })?;
            drop(receipt_store_write);
            self.append_child_receipt_to_local_log(receipt);
        }
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
