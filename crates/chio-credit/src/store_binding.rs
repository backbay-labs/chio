//! Store binding for IOU envelopes.
//!
//! A small abstraction over the durable store that persists IOU
//! envelopes minted by [`CreditEvaluatorHook`].
//! The binding lives in `chio-credit` so the trait surface stays
//! economic-crate-owned: the SQLite implementation lives in
//! `chio-store-sqlite::iou_store`.
//!
//! The binding is deliberately narrow: it does not expose query or
//! lifecycle methods, only the idempotent insert and a single
//! lookup keyed by `receipt_id`. A richer lifecycle surface can be
//! layered on top.

use thiserror::Error;

use crate::hook::IouEnvelope;

/// Errors surfaced by an [`IouEnvelopeStore`] implementation.
///
/// Implementations should map their underlying transport / driver
/// errors into this enum so consumers in `chio-credit` can pattern
/// match without taking a hard dep on a specific store crate.
#[derive(Debug, Error)]
pub enum IouEnvelopeStoreError {
    /// The store rejected the envelope as malformed or as having
    /// already been inserted with conflicting bytes.
    #[error("conflict persisting iou envelope: {0}")]
    Conflict(String),
    /// Underlying transport / driver error.
    #[error("iou envelope store: {0}")]
    Backend(String),
}

/// Persistence surface for [`IouEnvelope`] values.
///
/// Implementations MUST:
///
/// - Treat insertion as idempotent on `receipt_id`. Re-inserting the
///   same envelope (byte-equivalent body) returns `Ok(false)`. A
///   first insertion returns `Ok(true)`.
/// - Reject insertion with [`IouEnvelopeStoreError::Conflict`] if a
///   different envelope is already persisted for the same
///   `receipt_id`. Receipt finalization is append-only and the IOU
///   is bound to it; mismatching IOUs MUST NOT silently overwrite.
///
/// Lookup returns the previously-inserted envelope for the receipt
/// when one exists.
pub trait IouEnvelopeStore: Send + Sync {
    /// Persist `envelope`. Returns `Ok(true)` when the envelope was
    /// inserted, or `Ok(false)` when an identical envelope already
    /// exists. Returns [`IouEnvelopeStoreError::Conflict`] when a
    /// different envelope is recorded for the same `receipt_id`.
    fn insert(&self, envelope: &IouEnvelope) -> Result<bool, IouEnvelopeStoreError>;

    /// Fetch the IOU envelope previously persisted for `receipt_id`,
    /// or `Ok(None)` when no envelope is recorded.
    fn get_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<IouEnvelope>, IouEnvelopeStoreError>;
}
