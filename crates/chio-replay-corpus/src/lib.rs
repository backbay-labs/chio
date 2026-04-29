//! Replay corpus helpers for TEE capture graduation.
//!
//! The bless pipeline records redacted frames, deduplicates them by the
//! canonical JSON hash of `invocation`, then re-redacts payload bytes under
//! the current default redactor set before writing fixtures.

#![forbid(unsafe_code)]

pub mod audit;
pub mod dedupe;
pub mod m04_writer;
pub mod reredact;

pub use audit::{
    write_tee_bless_audit_entry, BlessAuditError, BlessCapture, BlessFixture, BlessOperator,
    TeeBlessAuditBody, TeeBlessAuditEntry, TEE_BLESS_CAPABILITY, TEE_BLESS_EVENT,
};
pub use dedupe::{dedupe_last_wins, invocation_hash, DedupedFrame};
pub use m04_writer::{
    scenario_from_dir, validate_m04_scenario_dir, write_m04_fixture, M04ByteSizes,
    M04FixtureSummary, M04Scenario, M04WriterError, CHECKPOINT_FILENAME, RECEIPTS_FILENAME,
    ROOT_FILENAME,
};
pub use reredact::{reredact_default, ReredactedPayload};

/// Errors surfaced by replay corpus normalization helpers.
#[derive(Debug, thiserror::Error)]
pub enum ReplayCorpusError {
    /// Canonical JSON serialization or hashing failed.
    #[error("canonical invocation hash failed: {0}")]
    Canonical(#[from] chio_core::Error),
    /// The default redactor failed closed.
    #[error("default redactor failed: {0}")]
    Redact(#[from] chio_tee::RedactError),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, ReplayCorpusError>;
