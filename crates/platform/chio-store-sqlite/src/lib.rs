//! SQLite-backed persistence, query, and report layer for the Chio protocol.
//!
//! This crate is the concrete persistent backend for the kernel's receipt log
//! and its supporting state. It implements the receipt store and query path,
//! budget and approval stores, capability-lineage and revocation stores, an
//! execution-nonce store, an encrypted-blob store, IOU and dead-letter stores,
//! and evidence-export queries. The store traits it implements are defined by
//! `chio-kernel` and `chio-core`. Reader-heavy receipt queries use a
//! connection pool (eight readers by default); writes are serialized through a
//! group-commit actor onto a single writer connection.
//!
//! # Modules
//!
//! - [`receipt_store`] / [`receipt_query`] -- receipt persistence and the
//!   query path.
//! - [`budget_store`] -- durable budget state.
//! - [`approval_store`] / [`batch_approval_store`] -- human-approval state.
//! - [`capability_lineage`] / [`revocation_store`] -- capability provenance and
//!   revocation.
//! - [`execution_nonce_store`] / [`dead_letters`] / [`iou_store`] -- nonce
//!   replay guard, settlement dead letters, and IOU envelopes.
//! - [`encrypted_blob`] / [`memory_provenance_store`] / [`evidence_export`] --
//!   encrypted payloads, memory provenance, and evidence export.

#![forbid(unsafe_code)]

pub mod approval_store;
pub mod authority;
pub mod batch_approval_store;
pub mod budget_store;
pub mod capability_lineage;
pub mod dead_letters;
pub mod encrypted_blob;
pub mod evidence_export;
pub mod execution_nonce_store;
pub mod iou_store;
#[cfg(feature = "lineage")]
pub mod lineage_cte;
pub mod memory_provenance_store;
pub mod receipt_query;
pub mod receipt_store;
pub mod revocation_store;

pub use chio_core::crypto::SharedCanonicalBytes;
pub use chio_core::{CanonicalBytes, CanonicalJsonWitness};
pub use chio_kernel::{EvidenceChildReceiptScope, EvidenceExportQuery};

/// Default SQLite reader pool size.
///
/// Reader-heavy receipt queries keep the existing eight-connection default.
pub const DEFAULT_READER_POOL_MAX_SIZE: u32 = 8;

/// Default SQLite writer pool size.
///
/// Receipt writes are serialized through the group-commit actor, so the
/// writer pool defaults to a single connection.
pub const DEFAULT_WRITER_POOL_MAX_SIZE: u32 = 1;

/// SQLite pool sizing for receipt-store read and write paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlitePoolConfig {
    pub reader_pool_max_size: u32,
    pub writer_pool_max_size: u32,
}

impl Default for SqlitePoolConfig {
    fn default() -> Self {
        Self {
            reader_pool_max_size: DEFAULT_READER_POOL_MAX_SIZE,
            writer_pool_max_size: DEFAULT_WRITER_POOL_MAX_SIZE,
        }
    }
}

/// Receipt-store construction options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteStoreOptions {
    pub pool: SqlitePoolConfig,
    /// When true (default), the append path uses the actor-owned verified
    /// head (O(1) predecessor check + O(b) delta cross-check). When false,
    /// the store keeps today's full per-append verification so operators can
    /// A/B a suspect database. Read-only after open.
    pub incremental_verification: bool,
}

impl Default for SqliteStoreOptions {
    fn default() -> Self {
        Self {
            pool: SqlitePoolConfig::default(),
            incremental_verification: true,
        }
    }
}

pub use approval_store::SqliteApprovalStore;
pub use authority::SqliteCapabilityAuthority;
pub use batch_approval_store::SqliteBatchApprovalStore;
pub use budget_store::SqliteBudgetStore;
pub use encrypted_blob::{
    decrypt_blob, encrypt_blob, BlobHandle, BlobStoreError, DecryptError, EncryptError,
    EncryptedBlob, SqliteEncryptedBlobStore, TenantId, TenantKey,
};
pub use execution_nonce_store::{SqliteExecutionNonceStore, SqliteExecutionNonceStoreError};
pub use iou_store::{SqliteIouEnvelopeStore, IOU_ENVELOPE_MIGRATION};
pub use memory_provenance_store::{SqliteMemoryProvenanceStore, SqliteMemoryProvenanceStoreError};
pub use receipt_store::{BackgroundCheckpointSigner, SqliteReceiptStore};
pub use revocation_store::SqliteRevocationStore;
