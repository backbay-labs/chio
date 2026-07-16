//! Kernel-facing seam for the durable settlement retry/dead-letter sink.
//!
//! The kernel holds an optional `Arc<dyn SettlementRetryStore>`. When one is
//! installed, the settlement routing consumer persists a bounded attempt
//! envelope for retryable outcomes and dead-letters terminal failures. When
//! absent, unresolved outcomes still fail loud (a warning plus a metric),
//! never silently dropped.

/// A persisted settlement-retry attempt row keyed by receipt id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleAttemptRecord {
    /// Receipt whose settlement outcome is pending resolution.
    pub receipt_id: String,
    /// Unix seconds at which the receipt was finalized.
    pub finalized_at: u64,
    /// Attempts consumed so far.
    pub attempts: u32,
    /// Unix seconds before which the driver must not retry this row.
    pub next_visible_at: u64,
    /// Most recent classification reason, for operators.
    pub last_reason: Option<String>,
}

/// Typed, fail-closed errors from the retry sink.
#[derive(Debug, thiserror::Error)]
pub enum SettlementRetryError {
    /// Connection, SQLite, or serialization failure.
    #[error("settlement retry backend error: {0}")]
    Backend(String),
    /// A divergent row already exists for the same key.
    #[error("settlement retry conflict: {0}")]
    Conflict(String),
}

/// Durable sink the settlement routing consumer writes to. Implemented over
/// SQLite in `chio-store-sqlite`.
pub trait SettlementRetryStore: Send + Sync {
    /// Load the attempt row for a receipt, if one exists.
    fn load_attempt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<SettleAttemptRecord>, SettlementRetryError>;

    /// Insert or replace the attempt row for a receipt.
    fn upsert_attempt(&self, record: &SettleAttemptRecord) -> Result<(), SettlementRetryError>;

    /// Remove the attempt row for a receipt. Removing an absent row is a no-op.
    fn clear_attempt(&self, receipt_id: &str) -> Result<(), SettlementRetryError>;

    /// Persist a dead-letter record. Returns `Ok(true)` for a new row,
    /// `Ok(false)` for a byte-identical replay, and `Err(Conflict)` when a
    /// divergent row already exists for the receipt.
    fn insert_dead_letter(
        &self,
        record: &chio_settle::DeadLetterRecord,
    ) -> Result<bool, SettlementRetryError>;

    /// Attempt rows whose `next_visible_at` has passed, oldest first.
    fn due_attempts(
        &self,
        now_unix_secs: u64,
        limit: usize,
    ) -> Result<Vec<SettleAttemptRecord>, SettlementRetryError>;
}
