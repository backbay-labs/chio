use chio_core::canonical::CanonicalBytes;
use chio_core::capability::token::CapabilityToken;
use chio_core::credit::CreditBondRow;
use chio_core::crypto::Keypair;
use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};

use crate::capability_lineage::CapabilitySnapshot;
use crate::checkpoint::KernelCheckpoint;

/// Configuration for receipt retention and archival.
///
/// When set on `KernelConfig`, the kernel can archive aged-out or oversized
/// receipt databases to a separate read-only SQLite file while keeping archived
/// receipts verifiable against their Merkle checkpoint roots.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// Number of days to retain receipts in the live database. Default: 90.
    pub retention_days: u64,
    /// Maximum size in bytes before the live database is rotated. Default: 10 GB.
    pub max_size_bytes: u64,
    /// Path for the archive SQLite file. Must be writable on first rotation.
    pub archive_path: String,
    /// Optional tenant scope for retention. When set, rotation only archives
    /// receipts for this tenant and leaves other tenant evidence untouched.
    pub tenant_id: Option<String>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            retention_days: 90,
            max_size_bytes: 10_737_418_240,
            archive_path: "receipts-archive.sqlite3".to_string(),
            tenant_id: None,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptWriterCounters {
    pub accepted_total: u64,
    pub committed_total: u64,
    pub failed_total: u64,
    pub saturated_total: u64,
    pub inflight: u64,
    #[serde(default)]
    pub last_commit_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptWalCheckpointReport {
    pub busy: u64,
    pub log_frames: u64,
    pub checkpointed_frames: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptFlushReport {
    pub writer: ReceiptWriterCounters,
    pub latest_committed_entry_seq: u64,
    #[serde(default)]
    pub latest_checkpoint_seq: Option<u64>,
    pub latest_checkpointed_entry_seq: u64,
    #[serde(default)]
    pub uncheckpointed_start_seq: Option<u64>,
    #[serde(default)]
    pub uncheckpointed_end_seq: Option<u64>,
    #[serde(default)]
    pub wal_checkpoint: Option<ReceiptWalCheckpointReport>,
    #[serde(default)]
    pub db_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptCheckpointRange {
    pub start_seq: u64,
    pub end_seq: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptCheckpointStatusReport {
    pub healthy: bool,
    pub latest_committed_entry_seq: u64,
    #[serde(default)]
    pub latest_checkpoint_seq: Option<u64>,
    pub latest_checkpointed_entry_seq: u64,
    #[serde(default)]
    pub next_range: Option<ReceiptCheckpointRange>,
    #[serde(default)]
    pub checkpoint_error: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptStoreHealthReport {
    pub healthy: bool,
    pub writer: ReceiptWriterCounters,
    pub latest_committed_entry_seq: u64,
    #[serde(default)]
    pub latest_checkpoint_seq: Option<u64>,
    pub latest_checkpointed_entry_seq: u64,
    #[serde(default)]
    pub uncheckpointed_start_seq: Option<u64>,
    #[serde(default)]
    pub uncheckpointed_end_seq: Option<u64>,
    #[serde(default)]
    pub checkpoint_error: Option<String>,
    #[serde(default)]
    pub db_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptCheckpointCreateReport {
    pub created: bool,
    #[serde(default)]
    pub checkpoint_seq: Option<u64>,
    #[serde(default)]
    pub batch_start_seq: Option<u64>,
    #[serde(default)]
    pub batch_end_seq: Option<u64>,
    pub latest_committed_entry_seq: u64,
    pub latest_checkpointed_entry_seq: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationReceiptConsumption {
    pub authorization_receipt_id: String,
    pub consumer_receipt_id: String,
    pub request_id: String,
    pub session_id: String,
    pub tool_call_id: String,
    /// Tenant id copied from the live authorization receipt. ACP authorization
    /// receipts may legitimately carry `tenant_id: None` for non-enterprise
    /// (single-tenant or local) deployments; the consumption record mirrors
    /// the receipt's tenant scope (including `None`) for binding integrity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub parameter_hash: String,
    pub consumed_at_unix_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("sqlite pool error: {0}")]
    Pool(String),

    #[error("{operation} timed out after {timeout_ms}ms")]
    Timeout { operation: String, timeout_ms: u64 },

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("failed to prepare receipt store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto decode error: {0}")]
    CryptoDecode(String),

    #[error("canonical json error: {0}")]
    Canonical(String),

    #[error("invalid outcome filter: {0}")]
    InvalidOutcome(String),

    #[error("receipt read boundary error: {0}")]
    ReadBoundary(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("not found: {0}")]
    NotFound(String),
}

pub trait ReceiptStore: Send + Sync {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError>;
    /// Load a chio receipt by id. The provided default returns `None`; a store
    /// backing a store-authoritative deployment MUST override this (and
    /// `load_child_receipt`) with a real point lookup.
    ///
    /// The kernel consults this BEFORE the bounded in-memory receipt mirror and
    /// falls back to the mirror only on a genuine `Ok(None)` miss. An append-only
    /// or remote store that does NOT override this therefore relies entirely on
    /// the mirror for point lookups: once the mirror evicts a receipt (past
    /// `receipt_mirror_capacity`), governed call-chain validation of an older
    /// `parent_receipt_id` misses both the store and the mirror and fails closed
    /// (a deny of the dependent claim, never a false allow). A store-authoritative
    /// remote deployment that must resolve older parent receipts MUST implement
    /// this point load so bounded-mirror eviction does not cause false denials.
    fn load_chio_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(None)
    }
    /// Load a child-request receipt by id. Provided default returns `None`; a
    /// store used for a store-authoritative deployment must override both this
    /// and `load_chio_receipt`. A miss is a fail-closed deny
    /// of the dependent call-chain claim, never a false allow. The same
    /// bounded-mirror eviction caveat documented on `load_chio_receipt` applies.
    fn load_child_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        Ok(None)
    }
    fn append_chio_receipt_canonical(
        &self,
        receipt: &ChioReceipt,
        _canonical: &CanonicalBytes,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt(receipt)
    }
    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_chio_receipt(receipt)?;
        Ok(None)
    }
    fn append_chio_receipt_consuming_authorization(
        &self,
        _receipt: &ChioReceipt,
        _consumption: &AuthorizationReceiptConsumption,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "durable authorization receipt consumption is not supported by this receipt store"
                .to_string(),
        ))
    }
    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError>;
    fn append_child_receipt_returning_seq(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_child_receipt(receipt)?;
        Ok(None)
    }

    fn receipts_canonical_bytes_range(
        &self,
        _start_seq: u64,
        _end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt canonical byte ranges are not supported by this receipt store".to_string(),
        ))
    }

    fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt writer flush is not supported by this receipt store".to_string(),
        ))
    }

    fn flush_receipt_writes_with_timeout(
        &self,
        _timeout: std::time::Duration,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.flush_receipt_writes()
    }

    fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt store health is not supported by this receipt store".to_string(),
        ))
    }

    fn latest_committed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt committed sequence reporting is not supported by this receipt store"
                .to_string(),
        ))
    }

    fn latest_checkpointed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint sequence reporting is not supported by this receipt store"
                .to_string(),
        ))
    }

    fn next_checkpoint_range(
        &self,
        _max_batch: u64,
    ) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint ranges are not supported by this receipt store".to_string(),
        ))
    }

    fn receipt_checkpoint_status(
        &self,
        _max_batch: Option<u64>,
    ) -> Result<ReceiptCheckpointStatusReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint status is not supported by this receipt store".to_string(),
        ))
    }

    fn store_checkpoint(&self, _checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint storage is not supported by this receipt store".to_string(),
        ))
    }

    fn create_next_receipt_checkpoint(
        &self,
        _max_batch: u64,
        _keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "receipt checkpoint creation is not supported by this receipt store".to_string(),
        ))
    }

    fn load_checkpoint_by_seq(
        &self,
        _checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        Ok(None)
    }

    fn load_latest_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let mut checkpoint_seq = 1;
        let mut latest = None;
        loop {
            let Some(checkpoint) = self.load_checkpoint_by_seq(checkpoint_seq)? else {
                return Ok(latest);
            };
            if checkpoint.body.checkpoint_seq != checkpoint_seq {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint loader returned checkpoint {} for requested sequence {}",
                    checkpoint.body.checkpoint_seq, checkpoint_seq
                )));
            }
            checkpoint_seq = checkpoint
                .body
                .checkpoint_seq
                .checked_add(1)
                .ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "checkpoint_seq overflow while loading latest".to_string(),
                    )
                })?;
            latest = Some(checkpoint);
        }
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        false
    }

    /// Install a background checkpoint signer on stores that build their own
    /// checkpoints on the writer thread. Returns `Ok(false)` when
    /// the store does not support background checkpointing (default).
    fn enable_background_checkpoints(
        &self,
        _keypair: Keypair,
        _max_batch: u64,
    ) -> Result<bool, ReceiptStoreError> {
        Ok(false)
    }

    fn record_capability_snapshot(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn get_capability_snapshot(
        &self,
        _capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
        Ok(None)
    }

    fn get_capability_delegation_chain(
        &self,
        _capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, ReceiptStoreError> {
        Ok(Vec::new())
    }

    fn resolve_credit_bond(
        &self,
        _bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        Ok(None)
    }

    /// Persist a serialized `SessionAnchor` (JSON form).
    fn record_session_anchor(
        &self,
        _session_id: &str,
        _anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        _supersedes_anchor_id: Option<&str>,
        _anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    /// Persist a serialized `RequestLineageRecord` (JSON form).
    #[allow(clippy::too_many_arguments)]
    fn record_request_lineage(
        &self,
        _session_id: &str,
        _request_id: &str,
        _parent_request_id: Option<&str>,
        _session_anchor_id: Option<&str>,
        _recorded_at: u64,
        _request_fingerprint: Option<&str>,
        _lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    /// Persist a serialized `ReceiptLineageStatement` (JSON form).
    #[allow(clippy::too_many_arguments)]
    fn record_receipt_lineage_statement(
        &self,
        _child_receipt_id: &str,
        _request_id: Option<&str>,
        _session_id: Option<&str>,
        _session_anchor_id: Option<&str>,
        _parent_request_id: Option<&str>,
        _parent_receipt_id: Option<&str>,
        _chain_id: Option<&str>,
        _recorded_at: u64,
        _statement_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn get_receipt_lineage_verification(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ReceiptLineageVerification>, ReceiptStoreError> {
        Ok(None)
    }

    fn list_receipt_lineage_statement_links(
        &self,
        _receipt_id: &str,
    ) -> Result<Vec<ReceiptLineageStatementLink>, ReceiptStoreError> {
        Ok(Vec::new())
    }

    fn as_any_mut(&self) -> Option<&dyn std::any::Any> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AppendOnlyStore;

    impl ReceiptStore for AppendOnlyStore {
        fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            Ok(())
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }
    }

    #[test]
    fn unsupported_durability_surfaces_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let store = AppendOnlyStore;
        let checkpoint = crate::checkpoint::build_checkpoint(
            1,
            1,
            1,
            &[b"receipt".to_vec()],
            &Keypair::generate(),
        )?;

        assert!(matches!(
            store.receipts_canonical_bytes_range(1, 1),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt canonical byte ranges are not supported")
        ));
        assert!(matches!(
            store.flush_receipt_writes(),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt writer flush is not supported")
        ));
        assert!(matches!(
            store.flush_receipt_writes_with_timeout(std::time::Duration::from_millis(1)),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt writer flush is not supported")
        ));
        assert!(matches!(
            store.receipt_store_health(),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt store health is not supported")
        ));
        assert!(matches!(
            store.latest_committed_entry_seq(),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt committed sequence reporting is not supported")
        ));
        assert!(matches!(
            store.latest_checkpointed_entry_seq(),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt checkpoint sequence reporting is not supported")
        ));
        assert!(matches!(
            store.next_checkpoint_range(1),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt checkpoint ranges are not supported")
        ));
        assert!(matches!(
            store.receipt_checkpoint_status(Some(1)),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt checkpoint status is not supported")
        ));
        assert!(matches!(
            store.store_checkpoint(&checkpoint),
            Err(ReceiptStoreError::Conflict(message))
                if message.contains("receipt checkpoint storage is not supported")
        ));
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct StoredToolReceipt {
    pub seq: u64,
    pub receipt: ChioReceipt,
}

#[derive(Debug, Clone)]
pub struct StoredChildReceipt {
    pub seq: u64,
    pub receipt: ChildRequestReceipt,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLineageVerification {
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    pub session_anchor_verified: bool,
    pub parent_request_verified: bool,
    pub parent_receipt_verified: bool,
    pub replay_protected: bool,
}

impl ReceiptLineageVerification {
    #[must_use]
    pub fn delegated_call_chain_bound(&self) -> bool {
        self.parent_receipt_verified
            || (self.session_anchor_verified && self.parent_request_verified)
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLineageStatementLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_id: Option<String>,
    pub child_receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    pub recorded_at: u64,
}

#[derive(Debug, Clone)]
pub struct FederatedEvidenceShareImport {
    pub share_id: String,
    pub manifest_hash: String,
    pub exported_at: u64,
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: String,
    pub require_proofs: bool,
    pub query_json: String,
    pub tool_receipts: Vec<StoredToolReceipt>,
    pub capability_lineage: Vec<CapabilitySnapshot>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FederatedEvidenceShareSummary {
    pub share_id: String,
    pub manifest_hash: String,
    pub imported_at: u64,
    pub exported_at: u64,
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: String,
    pub require_proofs: bool,
    pub tool_receipts: u64,
    pub capability_lineage: u64,
}
