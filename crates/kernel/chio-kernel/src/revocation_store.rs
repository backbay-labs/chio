#[derive(Debug, thiserror::Error)]
pub enum RevocationStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare revocation store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("revocation store synchronization error: {0}")]
    Sync(String),

    #[error("revocation mutation durable outcome is unknown: {0}")]
    OutcomeUnknown(String),

    #[error(
        "revocation store serving owner fenced (expected epoch {expected_epoch}, actual {actual_epoch:?})"
    )]
    Fenced {
        expected_epoch: u64,
        actual_epoch: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    pub capability_id: String,
    pub revoked_at: i64,
}
