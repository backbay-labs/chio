//! Capability lineage index for Chio kernel.
//!
//! This module provides persistence and query functions for capability snapshots.
//! Snapshots are recorded at issuance time and co-located with the receipt database
//! for efficient JOINs. The delegation chain can be walked via WITH RECURSIVE CTE.

use serde::{Deserialize, Serialize};

use crate::receipt_store::ReceiptStoreError;

/// A point-in-time snapshot of a capability token persisted at issuance.
///
/// Stored in the `capability_lineage` table alongside `chio_tool_receipts`
/// for efficient JOINs during audit queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// The unique token ID (matches CapabilityToken.id).
    pub capability_id: String,
    /// Hex-encoded subject public key (agent bound to this capability).
    pub subject_key: String,
    /// Hex-encoded issuer public key (Capability Authority or delegating agent).
    pub issuer_key: String,
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    /// JSON-serialized ChioScope (grants, resource_grants, prompt_grants).
    pub grants_json: String,
    /// Depth in the delegation chain. Root capabilities have depth 0.
    pub delegation_depth: u64,
    /// Parent capability_id if this was delegated from another token.
    pub parent_capability_id: Option<String>,
}

/// A capability snapshot with the source database sequence used for cluster sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCapabilitySnapshot {
    pub seq: u64,
    pub snapshot: CapabilitySnapshot,
}

/// Errors from capability lineage operations.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityLineageError {
    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
