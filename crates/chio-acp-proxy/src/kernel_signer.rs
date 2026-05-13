// Kernel-backed ReceiptSigner implementation.
//
// Signs ACP audit entries into Chio receipts using an Ed25519 keypair,
// then stores them in the kernel's ReceiptStore and triggers Merkle
// checkpoints at the configured batch size.

use std::collections::BTreeSet;
use std::sync::Mutex;

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceiptBody, Decision, ToolCallAction};
use chio_kernel::checkpoint::{build_checkpoint, KernelCheckpoint};
use chio_kernel::receipt_store::ReceiptStore;

/// Kernel-backed receipt signer.
///
/// Holds the Ed25519 keypair and a mutable reference to the receipt
/// store. Each signed receipt is appended to the store and, when the
/// batch threshold is reached, a Merkle checkpoint is produced.
pub struct KernelReceiptSigner {
    keypair: Keypair,
    // Kept for receipt-provenance parity once signer metadata is surfaced.
    #[allow(dead_code)]
    server_id: String,
    store: Mutex<Box<dyn ReceiptStore>>,
    checkpoint_batch_size: u64,
    /// Tracks the sequence numbers for checkpoint batching.
    checkpoint_seq: Mutex<u64>,
    batch_start_seq: Mutex<u64>,
    current_seq: Mutex<u64>,
    consumed_authorization_receipts: Mutex<BTreeSet<String>>,
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
            checkpoint_seq: Mutex::new(0),
            batch_start_seq: Mutex::new(0),
            current_seq: Mutex::new(0),
            consumed_authorization_receipts: Mutex::new(BTreeSet::new()),
        }
    }

    fn verify_live_authorization_receipt(
        &self,
        request: &AcpReceiptRequest,
    ) -> Result<(), ReceiptSignError> {
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
        let receipt_context = authorization_receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("receipt_context"));
        let stored_session_id = receipt_context
            .and_then(|context| context.get("session_id"))
            .and_then(serde_json::Value::as_str);
        if stored_session_id != Some(entry.session_id.as_str()) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt session id mismatch".to_string(),
            ));
        }
        let stored_tool_call_id = receipt_context
            .and_then(|context| context.get("tool_call_id"))
            .and_then(serde_json::Value::as_str);
        if stored_tool_call_id != Some(entry.tool_call_id.as_str()) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt tool call id mismatch".to_string(),
            ));
        }
        let mut consumed = self.consumed_authorization_receipts.lock().map_err(|e| {
            ReceiptSignError::SigningFailed(format!("authorization consumption lock poisoned: {e}"))
        })?;
        if !consumed.insert(authorization_receipt_id.to_string()) {
            return Err(ReceiptSignError::SigningFailed(
                "authorization receipt already consumed".to_string(),
            ));
        }
        Ok(())
    }

    /// Attempt a Merkle checkpoint if the batch threshold has been reached.
    fn maybe_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptSignError> {
        let current = *self
            .current_seq
            .lock()
            .map_err(|e| ReceiptSignError::SigningFailed(format!("lock poisoned: {e}")))?;
        let batch_start = *self
            .batch_start_seq
            .lock()
            .map_err(|e| ReceiptSignError::SigningFailed(format!("lock poisoned: {e}")))?;

        let batch_count = current.saturating_sub(batch_start);
        if batch_count < self.checkpoint_batch_size {
            return Ok(None);
        }

        let store = self
            .store
            .lock()
            .map_err(|e| ReceiptSignError::SigningFailed(format!("store lock poisoned: {e}")))?;

        if !store.supports_kernel_signed_checkpoints() {
            // Store does not support checkpoints -- reset batch tracking.
            let mut bs = self
                .batch_start_seq
                .lock()
                .map_err(|e| ReceiptSignError::SigningFailed(format!("lock poisoned: {e}")))?;
            *bs = current;
            return Ok(None);
        }

        // Gather canonical bytes for the batch.
        let batch_bytes = store
            .receipts_canonical_bytes_range(batch_start, current)
            .map_err(|e| {
                ReceiptSignError::SigningFailed(format!(
                    "failed to read receipt bytes for checkpoint: {e}"
                ))
            })?;

        if batch_bytes.is_empty() {
            return Ok(None);
        }

        let leaves: Vec<Vec<u8>> = batch_bytes.into_iter().map(|(_, b)| b).collect();

        let mut cs = self
            .checkpoint_seq
            .lock()
            .map_err(|e| ReceiptSignError::SigningFailed(format!("lock poisoned: {e}")))?;

        let checkpoint = build_checkpoint(
            *cs,
            batch_start,
            current.saturating_sub(1),
            &leaves,
            &self.keypair,
        )
        .map_err(|e| ReceiptSignError::SigningFailed(format!("checkpoint build failed: {e}")))?;

        store.store_checkpoint(&checkpoint).map_err(|e| {
            ReceiptSignError::SigningFailed(format!("checkpoint store failed: {e}"))
        })?;

        *cs += 1;
        drop(cs);

        // Advance the batch start.
        let mut bs = self
            .batch_start_seq
            .lock()
            .map_err(|e| ReceiptSignError::SigningFailed(format!("lock poisoned: {e}")))?;
        *bs = current;

        tracing::info!(
            checkpoint_seq = checkpoint.body.checkpoint_seq,
            tree_size = checkpoint.body.tree_size,
            "ACP receipt Merkle checkpoint"
        );

        Ok(Some(checkpoint))
    }
}

impl ReceiptSigner for KernelReceiptSigner {
    fn sign_acp_receipt(
        &self,
        request: &AcpReceiptRequest,
    ) -> Result<ChioReceipt, ReceiptSignError> {
        let entry = &request.audit_entry;

        let action_parameters = serde_json::json!({
            "tool_call_id": entry.tool_call_id,
            "title": entry.title,
            "kind": entry.kind,
            "status": entry.status,
        });
        let action = ToolCallAction::from_parameters(action_parameters)
            .map_err(|e| ReceiptSignError::SigningFailed(format!("hash ACP parameters: {e}")))?;

        let timestamp = entry.timestamp.parse::<u64>().unwrap_or_else(|_| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        let enforcement_mode = entry.enforcement_mode.unwrap_or(AcpEnforcementMode::AuditOnly);
        if enforcement_mode == AcpEnforcementMode::CryptographicallyEnforced {
            self.verify_live_authorization_receipt(request)?;
        }
        let (decision, trust_level, semantics) = match enforcement_mode {
            AcpEnforcementMode::AuditOnly => (
                Decision::Incomplete {
                    reason: "ACP audit-only observation is trace-only".to_string(),
                },
                chio_core::TrustLevel::Verified,
                chio_core::ReceiptSemanticFields::trace_detect_only(),
            ),
            AcpEnforcementMode::CryptographicallyEnforced => (
                Decision::Allow,
                chio_core::TrustLevel::Mediated,
                chio_core::ReceiptSemanticFields::mediated_prevent(),
            ),
        };

        let body = ChioReceiptBody {
            id: format!("acp-{}", entry.tool_call_id),
            timestamp,
            capability_id: entry
                .capability_id
                .clone()
                .unwrap_or_else(|| format!("acp-session:{}", entry.session_id)),
            tool_server: request.tool_server.clone(),
            tool_name: request.tool_name.clone(),
            action,
            decision,
            content_hash: entry.content_hash.clone(),
            policy_hash: String::new(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "receipt_semantics": semantics,
                "acp": {
                    "sessionId": entry.session_id,
                    "toolCallId": entry.tool_call_id,
                    "capabilityId": entry.capability_id,
                    "authorizationReceiptId": entry.authorization_receipt_id,
                    "authorizationRequestId": entry.authorization_request_id,
                    "enforcementMode": enforcement_mode,
                }
            })),
            trust_level,
            tenant_id: None,
            kernel_key: self.keypair.public_key(),
        };

        // Sign the receipt.
        let receipt = ChioReceipt::sign(body, &self.keypair)
            .map_err(|e| ReceiptSignError::SigningFailed(format!("Ed25519 signing failed: {e}")))?;

        // Append to the receipt store and track seq.
        {
            let store = self.store.lock().map_err(|e| {
                ReceiptSignError::SigningFailed(format!("store lock poisoned: {e}"))
            })?;
            store.append_chio_receipt(&receipt).map_err(|e| {
                ReceiptSignError::SigningFailed(format!("receipt store append failed: {e}"))
            })?;
        }

        // Increment sequence counter.
        {
            let mut seq = self
                .current_seq
                .lock()
                .map_err(|e| ReceiptSignError::SigningFailed(format!("lock poisoned: {e}")))?;
            *seq += 1;
        }

        // Attempt a checkpoint if the batch threshold was reached.
        // Checkpoint failures are logged but not propagated -- the receipt
        // itself was already signed and stored successfully, and blocking
        // receipt issuance on a checkpoint error would be disproportionate.
        match self.maybe_checkpoint() {
            Ok(Some(cp)) => {
                tracing::debug!(
                    checkpoint_seq = cp.body.checkpoint_seq,
                    "Merkle checkpoint created"
                );
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Merkle checkpoint failed (receipt was still signed and stored)"
                );
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
