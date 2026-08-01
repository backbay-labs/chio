// Kernel-backed ReceiptSigner implementation.
//
// Signs ACP audit entries into Chio receipts using an Ed25519 keypair,
// then stores them in the kernel's ReceiptStore and triggers Merkle
// checkpoints at the configured batch size.

use std::sync::Mutex;

use chio_core::crypto::Keypair;
use chio_core::receipt::{body::ChioReceiptBody, decision::Decision, decision::ToolCallAction};
use chio_kernel::receipt_store::{AuthorizationReceiptConsumption, ReceiptStore};

/// Health snapshot for the kernel signer's checkpoint subsystem.
///
/// `sign_acp_receipt` never blocks a successful receipt append on a
/// checkpoint error; instead, the most recent checkpoint failure is
/// recorded here so callers can surface it via health endpoints or
/// metrics. Consumers should treat `last_checkpoint_error` as a
/// transient indicator: subsequent appends and checkpoint attempts
/// will keep updating it.
#[derive(Debug, Clone, Default)]
pub struct KernelSignerCheckpointHealth {
    /// Number of consecutive failed checkpoint attempts since the last
    /// successful one. Reset to 0 on any successful checkpoint cycle.
    pub consecutive_failures: u64,
    /// The error message from the most recent failed checkpoint
    /// attempt, if any. `None` when the last attempt succeeded (or no
    /// attempt has run yet).
    pub last_checkpoint_error: Option<String>,
}

/// Kernel-backed receipt signer.
///
/// Holds the Ed25519 keypair and a mutable reference to the receipt
/// store. Each signed receipt is appended to the store and, when the
/// batch threshold is reached, a Merkle checkpoint is produced.
///
/// Checkpoint errors are decoupled from receipt signing: once an
/// append has committed the receipt, a subsequent checkpoint failure
/// is recorded into `checkpoint_health` and logged at WARN, but the
/// caller still observes the signed receipt and the ACP message flow
/// is not blocked.
pub struct KernelReceiptSigner {
    keypair: Keypair,
    // Kept for receipt-provenance parity once signer metadata is surfaced.
    #[allow(dead_code)]
    server_id: String,
    store: Mutex<Box<dyn ReceiptStore>>,
    checkpoint_batch_size: u64,
    checkpoint_health: Mutex<KernelSignerCheckpointHealth>,
}

struct VerifiedAuthorizationContext {
    authorization_receipt_id: String,
    request_id: String,
    session_id: String,
    tool_call_id: String,
    /// Tenant id copied from the live authorization receipt. ACP authorization
    /// receipts may legitimately carry `tenant_id: None` for non-enterprise
    /// (single-tenant or local) deployments, which is propagated as-is into the
    /// downstream consumer receipt and consumption record.
    tenant_id: Option<String>,
    parameter_hash: String,
    operation_payload: serde_json::Value,
}

impl KernelReceiptSigner {
    /// Create a new kernel-backed signer.
    pub fn new(
        keypair: Keypair,
        server_id: impl Into<String>,
        store: Box<dyn ReceiptStore>,
        checkpoint_batch_size: u64,
    ) -> Self {
        Self {
            keypair,
            server_id: server_id.into(),
            store: Mutex::new(store),
            checkpoint_batch_size,
            checkpoint_health: Mutex::new(KernelSignerCheckpointHealth::default()),
        }
    }

    /// Return the current checkpoint-subsystem health snapshot.
    ///
    /// Useful for health endpoints and metrics. Cloned out of the
    /// internal lock so callers do not hold the signer's mutex.
    pub fn checkpoint_health(&self) -> KernelSignerCheckpointHealth {
        match self.checkpoint_health.lock() {
            Ok(guard) => guard.clone(),
            // If the health mutex is poisoned (because a previous panic
            // tore down a holder), report a synthesized health value
            // that names the lock failure instead of panicking. This
            // keeps health endpoints alive even in the unlikely
            // poisoned-mutex case.
            Err(err) => KernelSignerCheckpointHealth {
                consecutive_failures: 0,
                last_checkpoint_error: Some(format!("checkpoint health lock poisoned: {err}")),
            },
        }
    }

    fn verify_live_authorization_receipt(
        &self,
        request: &AcpReceiptRequest,
    ) -> Result<VerifiedAuthorizationContext, ReceiptSignError> {
        let entry = &request.audit_entry;
        let capability_id = entry.capability_id.as_deref().ok_or_else(|| {
            ReceiptSignError::SigningFailed(
                "cryptographically enforced ACP audit entries must carry the live capability id"
                    .to_string(),
            )
        })?;
        if capability_id.is_empty() {
            return Err(ReceiptSignError::SigningFailed(
                "cryptographically enforced ACP audit entries must carry the live capability id"
                    .to_string(),
            ));
        }
        let authorization_receipt_id =
            entry.authorization_receipt_id.as_deref().ok_or_else(|| {
                ReceiptSignError::SigningFailed(
                    "cryptographically enforced ACP audit entries must reference an authorization receipt"
                        .to_string(),
                )
            })?;
        if authorization_receipt_id.is_empty() {
            return Err(ReceiptSignError::SigningFailed(
                "cryptographically enforced ACP audit entries must reference an authorization receipt"
                    .to_string(),
            ));
        }
        let authorization_request_id =
            entry.authorization_request_id.as_deref().ok_or_else(|| {
                ReceiptSignError::SigningFailed(
                    "cryptographically enforced ACP audit entries must reference the authorization request id"
                        .to_string(),
                )
            })?;
        if authorization_request_id.is_empty() {
            return Err(ReceiptSignError::SigningFailed(
                "cryptographically enforced ACP audit entries must reference the authorization request id"
                    .to_string(),
            ));
        }
        if entry.session_id.is_empty() || entry.tool_call_id.is_empty() {
            return Err(ReceiptSignError::SigningFailed(
                "cryptographically enforced ACP audit entries must bind session and tool call ids"
                    .to_string(),
            ));
        }
        let authorization_tool_call_id =
            entry.authorization_tool_call_id.as_deref().ok_or_else(|| {
                ReceiptSignError::SigningFailed(
                    "cryptographically enforced ACP audit entries must reference the authorization tool call id"
                        .to_string(),
                )
            })?;
        if authorization_tool_call_id != entry.tool_call_id.as_str() {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt tool call id mismatch".to_string(),
            ));
        }
        let authorization_correlation_id =
            entry.authorization_correlation_id.as_deref().ok_or_else(|| {
                ReceiptSignError::SigningFailed(
                    "cryptographically enforced ACP audit entries must reference the authorization correlation id"
                        .to_string(),
                )
            })?;
        if authorization_correlation_id.is_empty() {
            return Err(ReceiptSignError::SigningFailed(
                "cryptographically enforced ACP audit entries must reference the authorization correlation id"
                    .to_string(),
            ));
        }
        let authorization_operation = entry.authorization_operation.as_deref().ok_or_else(|| {
            ReceiptSignError::SigningFailed(
                "cryptographically enforced ACP audit entries must reference the authorization operation"
                    .to_string(),
            )
        })?;
        let authorization_resource = entry.authorization_resource.as_deref().ok_or_else(|| {
            ReceiptSignError::SigningFailed(
                "cryptographically enforced ACP audit entries must reference the authorization resource"
                    .to_string(),
            )
        })?;
        let authorization_parameter_hash =
            entry.authorization_parameter_hash.as_deref().ok_or_else(|| {
                ReceiptSignError::SigningFailed(
                    "cryptographically enforced ACP audit entries must reference the authorization parameter hash"
                        .to_string(),
                )
            })?;

        let authorization_receipt = {
            let store = self.store.lock().map_err(|e| {
                ReceiptSignError::SigningFailed(format!("store lock poisoned: {e}"))
            })?;
            store
                .load_chio_receipt(authorization_receipt_id)
                .map_err(|e| {
                    ReceiptSignError::SigningFailed(format!(
                        "failed to load ACP authorization receipt: {e}"
                    ))
                })?
                .ok_or_else(|| {
                    ReceiptSignError::SigningFailed(format!(
                        "authorization receipt {authorization_receipt_id} was not found"
                    ))
                })?
        };

        if authorization_receipt.id != authorization_receipt_id {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt id mismatch".to_string(),
            ));
        }
        if !authorization_receipt.verify_signature().map_err(|error| {
            ReceiptSignError::SigningFailed(format!(
                "authorization receipt signature verification failed: {error}"
            ))
        })? {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt signature verification failed".to_string(),
            ));
        }
        if authorization_receipt.kernel_key != self.keypair.public_key() {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt signer mismatch".to_string(),
            ));
        }
        if !authorization_receipt
            .action
            .verify_hash()
            .map_err(|error| {
                ReceiptSignError::SigningFailed(format!(
                    "authorization receipt parameter hash verification failed: {error}"
                ))
            })?
        {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt parameter hash mismatch".to_string(),
            ));
        }
        let action_parameters = &authorization_receipt.action.parameters;
        let action_authorization_parameter_hash = action_parameters
            .get("authorization_parameter_hash")
            .and_then(serde_json::Value::as_str);
        if action_authorization_parameter_hash != Some(authorization_parameter_hash) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt action parameter hash mismatch".to_string(),
            ));
        }
        let operation_payload = action_parameters.get("operation_payload").ok_or_else(|| {
            ReceiptSignError::SigningFailed(
                "authorization receipt must cover the full ACP operation payload".to_string(),
            )
        })?;
        let operation_payload_bytes = chio_core::canonical::canonical_json_bytes(operation_payload)
            .map_err(|error| {
                ReceiptSignError::SigningFailed(format!(
                    "authorization receipt operation payload canonicalization failed: {error}"
                ))
            })?;
        let operation_payload_hash = chio_core::sha256_hex(&operation_payload_bytes);
        if operation_payload_hash != authorization_parameter_hash {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt operation payload hash mismatch".to_string(),
            ));
        }
        if authorization_receipt.capability_id != capability_id {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt capability mismatch".to_string(),
            ));
        }
        if authorization_receipt.tool_server != request.tool_server
            || authorization_receipt.tool_name != request.tool_name
        {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt tool target mismatch".to_string(),
            ));
        }
        if !authorization_receipt.is_allowed() {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt must be a mediated allow".to_string(),
            ));
        }
        let stored_request_id = authorization_receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("receipt_context"))
            .and_then(|context| context.get("request_id"))
            .and_then(serde_json::Value::as_str);
        if stored_request_id != Some(authorization_request_id) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt request id mismatch".to_string(),
            ));
        }
        let stored_session_id = action_parameters
            .get("session_id")
            .and_then(serde_json::Value::as_str);
        if stored_session_id != Some(entry.session_id.as_str()) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt session id mismatch".to_string(),
            ));
        }
        let stored_tool_call_id = action_parameters.get("tool_call_id").ok_or_else(|| {
            ReceiptSignError::SigningFailed(
                "authorization receipt must carry a tool call id field".to_string(),
            )
        })?;
        let stored_tool_call_id = stored_tool_call_id.as_str().ok_or_else(|| {
            ReceiptSignError::SigningFailed(
                "authorization receipt tool call id must be a string".to_string(),
            )
        })?;
        // Deferred-bind semantics: ACP fs/read_text_file, fs/write_text_file,
        // and terminal/create requests do not carry a `toolCallId` at the
        // capability gate, so `KernelCapabilityChecker` signs the action with
        // `tool_call_id = ""`. The real `toolCallId` is later
        // assigned by the agent and arrives on the `session/update`
        // notification, at which point `bind_pending_capability_context`
        // resolves it through the per-session-operation FIFO. When the stored
        // value is explicitly empty we treat it as a deferred bind and
        // accept any non-empty resolved `authorization_tool_call_id`; the
        // link integrity is enforced by the FIFO match and by the strict
        // equality check between `entry.authorization_tool_call_id` and
        // `entry.tool_call_id` above.
        if !stored_tool_call_id.is_empty() && stored_tool_call_id != authorization_tool_call_id {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt tool call id mismatch".to_string(),
            ));
        }
        let stored_correlation_id = action_parameters
            .get("authorization_correlation_id")
            .and_then(serde_json::Value::as_str);
        if stored_correlation_id != Some(authorization_correlation_id) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt correlation id mismatch".to_string(),
            ));
        }
        let stored_operation = action_parameters
            .get("operation")
            .and_then(serde_json::Value::as_str);
        if stored_operation != Some(authorization_operation) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt operation mismatch".to_string(),
            ));
        }
        let stored_resource = action_parameters
            .get("resource")
            .and_then(serde_json::Value::as_str);
        if stored_resource != Some(authorization_resource) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt resource mismatch".to_string(),
            ));
        }
        // Tenant id is optional: the kernel legitimately signs receipts with
        // `tenant_id: None` for single-tenant / non-enterprise deployments.
        // Reject only malformed `Some("")` shapes; pass through `None` and
        // valid `Some(<non-empty>)` values unchanged.
        let tenant_id = match authorization_receipt.tenant_id.clone() {
            Some(tenant_id) if tenant_id.trim().is_empty() => {
                return Err(ReceiptSignError::SigningFailed(
                    "authorization receipt tenant id must not be empty when present".to_string(),
                ));
            }
            other => other,
        };
        Ok(VerifiedAuthorizationContext {
            authorization_receipt_id: authorization_receipt_id.to_string(),
            request_id: authorization_request_id.to_string(),
            session_id: entry.session_id.clone(),
            tool_call_id: entry.tool_call_id.clone(),
            tenant_id,
            parameter_hash: authorization_parameter_hash.to_string(),
            operation_payload: operation_payload.clone(),
        })
    }

    fn checkpoint_after_append(&self, store: &dyn ReceiptStore) -> Result<(), ReceiptSignError> {
        if self.checkpoint_batch_size == 0 {
            return Ok(());
        }

        let latest_committed = store.latest_committed_entry_seq().map_err(|e| {
            ReceiptSignError::SigningFailed(format!("receipt checkpoint status failed: {e}"))
        })?;
        let latest_checkpointed = store.latest_checkpointed_entry_seq().map_err(|e| {
            ReceiptSignError::SigningFailed(format!("receipt checkpoint status failed: {e}"))
        })?;
        if latest_committed.saturating_sub(latest_checkpointed) < self.checkpoint_batch_size {
            return Ok(());
        }

        let report = store
            .create_next_receipt_checkpoint(self.checkpoint_batch_size, &self.keypair)
            .map_err(|e| {
                ReceiptSignError::SigningFailed(format!("receipt checkpoint creation failed: {e}"))
            })?;

        if report.created {
            tracing::debug!(
                checkpoint_seq = report.checkpoint_seq,
                batch_start_seq = report.batch_start_seq,
                batch_end_seq = report.batch_end_seq,
                latest_committed_entry_seq = report.latest_committed_entry_seq,
                latest_checkpointed_entry_seq = report.latest_checkpointed_entry_seq,
                "ACP receipt checkpoint created"
            );
        } else if report
            .latest_committed_entry_seq
            .saturating_sub(report.latest_checkpointed_entry_seq)
            >= self.checkpoint_batch_size
        {
            return Err(ReceiptSignError::SigningFailed(
                "receipt checkpoint creation did not cover an eligible receipt range".to_string(),
            ));
        }

        Ok(())
    }

    /// Note a checkpoint failure into the health snapshot and emit a
    /// tracing warning. Does not return an error: callers must not
    /// block successful receipt flows on checkpoint errors.
    fn record_checkpoint_failure(&self, receipt_id: &str, err: &ReceiptSignError) {
        let err_string = err.to_string();
        tracing::warn!(
            receipt_id = %receipt_id,
            checkpoint_error = %err_string,
            "ACP receipt checkpoint failed after successful append; receipt is durable, checkpoint subsystem will retry on next eligible batch"
        );
        if let Ok(mut health) = self.checkpoint_health.lock() {
            health.consecutive_failures = health.consecutive_failures.saturating_add(1);
            health.last_checkpoint_error = Some(err_string);
        }
    }

    /// Note a successful checkpoint attempt (including no-op batches
    /// below the batch threshold). Resets failure state.
    fn record_checkpoint_success(&self) {
        if let Ok(mut health) = self.checkpoint_health.lock() {
            health.consecutive_failures = 0;
            health.last_checkpoint_error = None;
        }
    }
}

impl ReceiptSigner for KernelReceiptSigner {
    fn sign_acp_receipt(
        &self,
        request: &AcpReceiptRequest,
    ) -> Result<ChioReceipt, ReceiptSignError> {
        let entry = &request.audit_entry;

        let timestamp = entry.timestamp.parse::<u64>().unwrap_or_else(|_| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        let enforcement_mode = entry
            .enforcement_mode
            .unwrap_or(AcpEnforcementMode::AuditOnly);
        let authorization_context =
            if enforcement_mode == AcpEnforcementMode::CryptographicallyEnforced {
                Some(self.verify_live_authorization_receipt(request)?)
            } else {
                None
            };
        let (decision, trust_level, semantics) = match enforcement_mode {
            AcpEnforcementMode::AuditOnly => (
                None,
                chio_core::receipt::kinds::TrustLevel::Verified,
                chio_core::receipt::metadata::ReceiptSemanticFields::trace_detect_only(),
            ),
            AcpEnforcementMode::CryptographicallyEnforced => (
                Some(Decision::Allow),
                chio_core::receipt::kinds::TrustLevel::Mediated,
                chio_core::receipt::metadata::ReceiptSemanticFields::mediated_prevent(),
            ),
        };
        let mut action_parameters = serde_json::json!({
            "tool_call_id": entry.tool_call_id,
            "title": entry.title,
            "kind": entry.kind,
            "status": entry.status,
            "authorization_parameter_hash": entry.authorization_parameter_hash,
        });
        if let Some(context) = &authorization_context {
            action_parameters["operation_payload"] = context.operation_payload.clone();
        }
        let action = ToolCallAction::from_parameters(action_parameters)
            .map_err(|e| ReceiptSignError::SigningFailed(format!("hash ACP parameters: {e}")))?;

        let body = ChioReceiptBody {
            // `ChioReceipt::sign` replaces this with the canonical
            // content-addressed receipt id (`chio_receipt_id`), so the literal
            // value here is only a pre-signing id for debug logging. The actual
            // per-event uniqueness flows through `action.parameters` (status,
            // title, kind, content_hash) and through `content_hash`, both of
            // which the canonical id input pulls in. Encode the discriminator
            // into the pre-signing id so tracing logs and any code path that
            // inspects the pre-signing body can tell `running` and
            // terminal `tool_call_update` events apart, and so a future change
            // that bypasses content-addressing does not silently collide on
            // `acp-{tool_call_id}`.
            id: format!(
                "acp-{}-{}-{}",
                entry.tool_call_id, entry.status, entry.content_hash
            ),
            timestamp,
            capability_id: entry
                .capability_id
                .clone()
                .unwrap_or_else(|| format!("acp-session:{}", entry.session_id)),
            tool_server: request.tool_server.clone(),
            tool_name: request.tool_name.clone(),
            action,
            decision,
            receipt_kind: semantics.receipt_kind,
            boundary_class: semantics.boundary_class,
            observation_outcome: semantics.observation_outcome,
            tool_origin: semantics.tool_origin,
            redaction_mode: semantics.redaction_mode,
            actor_chain: semantics.actor_chain.clone(),
            content_hash: entry.content_hash.clone(),
            policy_hash: String::new(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "acp": {
                    "sessionId": entry.session_id,
                    "toolCallId": entry.tool_call_id,
                    "capabilityId": entry.capability_id,
                    "authorizationReceiptId": entry.authorization_receipt_id,
                    "authorizationRequestId": entry.authorization_request_id,
                    "authorizationToolCallId": entry.authorization_tool_call_id,
                    "authorizationCorrelationId": entry.authorization_correlation_id,
                    "authorizationOperation": entry.authorization_operation,
                    "authorizationResource": entry.authorization_resource,
                    "authorizationParameterHash": entry.authorization_parameter_hash,
                    "enforcementMode": enforcement_mode,
                },
                // Mirror the live authorization request id at the canonical
                // `receipt_context.request_id` path so downstream verifiers can
                // reconstruct the request-receipt linkage uniformly across the
                // authorization receipt (written by the kernel) and the
                // consumer receipt (written here). When the entry was promoted
                // through a cryptographically enforced check, this matches the
                // `metadata.receipt_context.request_id` already on the
                // referenced authorization receipt.
                "receipt_context": {
                    "request_id": entry.authorization_request_id,
                    "session_id": entry.session_id,
                    "tool_call_id": entry.tool_call_id,
                    "authorization_receipt_id": entry.authorization_receipt_id,
                    "authorization_correlation_id": entry.authorization_correlation_id,
                    "authorization_operation": entry.authorization_operation,
                    "authorization_resource": entry.authorization_resource,
                    "authorization_parameter_hash": entry.authorization_parameter_hash,
                }
            })),
            trust_level,
            tenant_id: authorization_context
                .as_ref()
                .and_then(|context| context.tenant_id.clone()),
            kernel_key: self.keypair.public_key(),
            bbs_projection_version: None,
        };

        let receipt = ChioReceipt::sign(body, &self.keypair)
            .map_err(|e| ReceiptSignError::SigningFailed(format!("Ed25519 signing failed: {e}")))?;

        // Append to the receipt store. The append itself is part of
        // the signing boundary and fails closed: if the receipt cannot
        // be persisted, the caller must not believe a signed receipt
        // exists.
        //
        // Checkpoint creation, by contrast, is decoupled. Once the
        // receipt has been committed to the store, blocking the ACP
        // message flow on a Merkle-checkpoint error would be
        // disproportionate (the evidence is already durable). Record
        // the failure into `checkpoint_health` and emit a tracing
        // warning instead, then fall through to return the signed
        // receipt to the caller.
        {
            let store = self.store.lock().map_err(|e| {
                ReceiptSignError::SigningFailed(format!("store lock poisoned: {e}"))
            })?;
            if let Some(context) = &authorization_context {
                let consumption = AuthorizationReceiptConsumption {
                    authorization_receipt_id: context.authorization_receipt_id.clone(),
                    consumer_receipt_id: receipt.id.clone(),
                    request_id: context.request_id.clone(),
                    session_id: context.session_id.clone(),
                    tool_call_id: context.tool_call_id.clone(),
                    tenant_id: context.tenant_id.clone(),
                    parameter_hash: context.parameter_hash.clone(),
                    consumed_at_unix_ms: timestamp.saturating_mul(1000),
                };
                store
                    .append_chio_receipt_consuming_authorization(&receipt, &consumption)
                    .map_err(|e| {
                        ReceiptSignError::SigningFailed(format!("receipt store append failed: {e}"))
                    })?;
            } else {
                store.append_chio_receipt(&receipt).map_err(|e| {
                    ReceiptSignError::SigningFailed(format!("receipt store append failed: {e}"))
                })?;
            }
            if let Err(err) = self.checkpoint_after_append(store.as_ref()) {
                self.record_checkpoint_failure(&receipt.id, &err);
            } else {
                self.record_checkpoint_success();
            }
        }

        tracing::info!(
            receipt_id = %receipt.id,
            tool_call_id = %entry.tool_call_id,
            "signed ACP receipt"
        );

        Ok(receipt)
    }
}
