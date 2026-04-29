// Kernel-backed ReceiptSigner implementation.
//
// Signs ACP audit entries into Chio receipts using an Ed25519 keypair,
// then stores them in the kernel's ReceiptStore and triggers Merkle
// checkpoints at the configured batch size.

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
        }
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
            decision: Decision::Allow,
            content_hash: entry.content_hash.clone(),
            policy_hash: String::new(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "acp": {
                    "sessionId": entry.session_id,
                    "enforcementMode": entry.enforcement_mode,
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
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
