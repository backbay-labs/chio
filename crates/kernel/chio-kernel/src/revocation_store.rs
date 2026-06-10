#[derive(Debug, thiserror::Error)]
pub enum RevocationStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare revocation store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("revocation store synchronization error: {0}")]
    Sync(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    pub capability_id: String,
    pub revoked_at: i64,
}
