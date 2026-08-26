//! Encrypted durable storage for sealed cognition-market payloads.
//!
//! The public Finding commits to a payload digest while the payload itself
//! remains seller-private until an authorized purchase reaches the reveal
//! kernel. This store binds ciphertext to the operator tenant, Finding id,
//! media type, and committed digest with AEAD associated data. Reads verify the
//! plaintext digest again and fail closed on missing, altered, or cross-tenant
//! records.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_finding::finding_payload_sha256;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use thiserror::Error;

fn configure_pooled_connection(connection: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA busy_timeout = 5000;")
}

use crate::encrypted_blob::{
    decrypt_blob_with_aad, try_encrypt_blob_with_aad, BlobStoreError, EncryptedBlob, TenantId,
    TenantKey,
};

const FINDING_PAYLOAD_SCHEMA_KEY: &str = "finding_payload";
const FINDING_PAYLOAD_SUPPORTED_SCHEMA_VERSION: i32 = 0;
const FINDING_PAYLOAD_SCHEMA_ANCHORS: &[&str] = &[
    "chio_finding_operator_bundles",
    "chio_finding_payloads",
    "chio_finding_operator_payments",
];
const MAX_FINDING_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// One decrypted payload resolved for an authorized reveal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingPayloadRecord {
    pub finding_id: String,
    pub media_type: String,
    pub payload_sha256: String,
    pub payload: Vec<u8>,
}

/// Whether a write inserted a payload or replayed the exact prior write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingPayloadPutOutcome {
    Inserted,
    ExactReplay,
}

/// Fail-closed errors returned by sealed Finding payload persistence.
#[derive(Debug, Error)]
pub enum FindingPayloadStoreError {
    #[error("finding payload store is unavailable: {0}")]
    Unavailable(String),
    #[error("finding payload record not found")]
    NotFound,
    #[error("invalid finding payload input: {0}")]
    InvalidInput(&'static str),
    #[error("finding payload exceeds the {MAX_FINDING_PAYLOAD_BYTES}-byte limit")]
    PayloadTooLarge,
    #[error("finding payload digest does not match its commitment")]
    DigestMismatch,
    #[error("finding payload conflicts with an existing sealed payload")]
    Conflict,
    #[error("finding payload authentication failed")]
    AuthenticationFailed,
}

impl From<r2d2::Error> for FindingPayloadStoreError {
    fn from(error: r2d2::Error) -> Self {
        Self::Unavailable(error.to_string())
    }
}

impl From<rusqlite::Error> for FindingPayloadStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Unavailable(error.to_string())
    }
}

impl From<std::io::Error> for FindingPayloadStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Unavailable(error.to_string())
    }
}

impl From<BlobStoreError> for FindingPayloadStoreError {
    fn from(_: BlobStoreError) -> Self {
        Self::AuthenticationFailed
    }
}

/// SQLite-backed encrypted sealed-payload store.
pub struct SqliteFindingPayloadStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteFindingPayloadStore {
    /// Open a durable store, creating its parent directory when needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, FindingPayloadStoreError> {
        let path = path.as_ref();
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(parent)?;
        }
        let manager = SqliteConnectionManager::file(path).with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open an isolated in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, FindingPayloadStoreError> {
        let manager = SqliteConnectionManager::memory().with_init(configure_pooled_connection);
        let pool = Pool::builder().max_size(1).build(manager)?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), FindingPayloadStoreError> {
        let conn = self.pool.get()?;
        crate::check_schema_version(
            &conn,
            FINDING_PAYLOAD_SCHEMA_KEY,
            FINDING_PAYLOAD_SUPPORTED_SCHEMA_VERSION,
            FINDING_PAYLOAD_SCHEMA_ANCHORS,
        )
        .map_err(|error| FindingPayloadStoreError::Unavailable(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_finding_payloads (
                finding_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                media_type TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
                nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                ciphertext BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_finding_payloads_tenant
                ON chio_finding_payloads(tenant_id, created_at);
            "#,
        )?;
        crate::stamp_schema_version(
            &conn,
            FINDING_PAYLOAD_SCHEMA_KEY,
            FINDING_PAYLOAD_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| FindingPayloadStoreError::Unavailable(error.to_string()))?;
        Ok(())
    }

    /// Seal a Finding payload. Exact retries are idempotent while any changed
    /// field or payload is rejected as a conflict.
    pub fn put(
        &self,
        tenant_id: &TenantId,
        key: &TenantKey,
        finding_id: &str,
        media_type: &str,
        payload_sha256: &str,
        payload: &[u8],
    ) -> Result<FindingPayloadPutOutcome, FindingPayloadStoreError> {
        validate_input(tenant_id, finding_id, media_type, payload_sha256, payload)?;
        if finding_payload_sha256(media_type, payload)
            .map_err(|_| FindingPayloadStoreError::AuthenticationFailed)?
            != payload_sha256
        {
            return Err(FindingPayloadStoreError::DigestMismatch);
        }

        let mut conn = self.pool.get()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_encrypted(&tx, tenant_id, finding_id)?;
        if let Some(existing) = existing {
            let aad = payload_aad(
                tenant_id,
                finding_id,
                &existing.media_type,
                &existing.payload_sha256,
            );
            let plaintext = decrypt_blob_with_aad(key, &existing.blob, &aad)
                .map_err(|_| FindingPayloadStoreError::AuthenticationFailed)?;
            if existing.media_type == media_type
                && existing.payload_sha256 == payload_sha256
                && plaintext == payload
            {
                tx.commit()?;
                return Ok(FindingPayloadPutOutcome::ExactReplay);
            }
            return Err(FindingPayloadStoreError::Conflict);
        }

        let aad = payload_aad(tenant_id, finding_id, media_type, payload_sha256);
        let encrypted = try_encrypt_blob_with_aad(key, payload, &aad)
            .map_err(|_| FindingPayloadStoreError::AuthenticationFailed)?;
        tx.execute(
            r#"
            INSERT INTO chio_finding_payloads
                (finding_id, tenant_id, media_type, payload_sha256, nonce, ciphertext, created_at)
            VALUES
                (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                finding_id,
                tenant_id.as_str(),
                media_type,
                payload_sha256,
                encrypted.nonce.as_slice(),
                encrypted.ciphertext,
                now_secs(),
            ],
        )?;
        tx.commit()?;
        Ok(FindingPayloadPutOutcome::Inserted)
    }

    /// Resolve and authenticate a sealed payload for one tenant and Finding.
    pub fn get(
        &self,
        tenant_id: &TenantId,
        key: &TenantKey,
        finding_id: &str,
    ) -> Result<FindingPayloadRecord, FindingPayloadStoreError> {
        validate_identifier("finding_id", finding_id)?;
        validate_identifier("tenant_id", tenant_id.as_str())?;
        let conn = self.pool.get()?;
        let Some(encrypted) = load_encrypted(&conn, tenant_id, finding_id)? else {
            return Err(FindingPayloadStoreError::NotFound);
        };
        let aad = payload_aad(
            tenant_id,
            finding_id,
            &encrypted.media_type,
            &encrypted.payload_sha256,
        );
        let payload = decrypt_blob_with_aad(key, &encrypted.blob, &aad)
            .map_err(|_| FindingPayloadStoreError::AuthenticationFailed)?;
        if finding_payload_sha256(&encrypted.media_type, &payload)
            .map_err(|_| FindingPayloadStoreError::AuthenticationFailed)?
            != encrypted.payload_sha256
        {
            return Err(FindingPayloadStoreError::DigestMismatch);
        }
        Ok(FindingPayloadRecord {
            finding_id: finding_id.to_owned(),
            media_type: encrypted.media_type,
            payload_sha256: encrypted.payload_sha256,
            payload,
        })
    }
}

struct StoredPayload {
    media_type: String,
    payload_sha256: String,
    blob: EncryptedBlob,
}

fn load_encrypted(
    conn: &rusqlite::Connection,
    tenant_id: &TenantId,
    finding_id: &str,
) -> Result<Option<StoredPayload>, FindingPayloadStoreError> {
    let row = conn
        .query_row(
            r#"
            SELECT media_type, payload_sha256, nonce, ciphertext
            FROM chio_finding_payloads
            WHERE finding_id = ?1 AND tenant_id = ?2
            "#,
            params![finding_id, tenant_id.as_str()],
            |row| {
                let media_type: String = row.get("media_type")?;
                let payload_sha256: String = row.get("payload_sha256")?;
                let nonce: Vec<u8> = row.get("nonce")?;
                let ciphertext: Vec<u8> = row.get("ciphertext")?;
                Ok((media_type, payload_sha256, nonce, ciphertext))
            },
        )
        .optional()?;
    let Some((media_type, payload_sha256, nonce, ciphertext)) = row else {
        return Ok(None);
    };
    let nonce =
        <[u8; 12]>::try_from(nonce).map_err(|_| FindingPayloadStoreError::AuthenticationFailed)?;
    Ok(Some(StoredPayload {
        media_type,
        payload_sha256,
        blob: EncryptedBlob { nonce, ciphertext },
    }))
}

fn validate_input(
    tenant_id: &TenantId,
    finding_id: &str,
    media_type: &str,
    payload_sha256: &str,
    payload: &[u8],
) -> Result<(), FindingPayloadStoreError> {
    validate_identifier("tenant_id", tenant_id.as_str())?;
    validate_identifier("finding_id", finding_id)?;
    validate_identifier("media_type", media_type)?;
    if payload_sha256.len() != 64
        || !payload_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FindingPayloadStoreError::InvalidInput("payload_sha256"));
    }
    if payload.len() > MAX_FINDING_PAYLOAD_BYTES {
        return Err(FindingPayloadStoreError::PayloadTooLarge);
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), FindingPayloadStoreError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > 512
        || value.chars().any(char::is_control)
    {
        return Err(FindingPayloadStoreError::InvalidInput(field));
    }
    Ok(())
}

fn payload_aad(
    tenant_id: &TenantId,
    finding_id: &str,
    media_type: &str,
    payload_sha256: &str,
) -> Vec<u8> {
    format!(
        "chio.finding.payload.v1\0{}\0{finding_id}\0{media_type}\0{payload_sha256}",
        tenant_id.as_str()
    )
    .into_bytes()
}

fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::new("operator-alpha")
    }

    fn key(byte: u8) -> TenantKey {
        TenantKey::from_bytes([byte; 32])
    }

    #[test]
    fn sealed_payload_survives_restart_and_exact_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        let payload = b"diff --git a/a.rs b/a.rs\n";
        let digest = finding_payload_sha256("text/x-diff", payload).unwrap();
        let store = SqliteFindingPayloadStore::open(&path).unwrap();
        assert_eq!(
            store
                .put(
                    &tenant(),
                    &key(7),
                    "finding-1",
                    "text/x-diff",
                    &digest,
                    payload
                )
                .unwrap(),
            FindingPayloadPutOutcome::Inserted
        );
        drop(store);

        let reopened = SqliteFindingPayloadStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .put(
                    &tenant(),
                    &key(7),
                    "finding-1",
                    "text/x-diff",
                    &digest,
                    payload
                )
                .unwrap(),
            FindingPayloadPutOutcome::ExactReplay
        );
        assert_eq!(
            reopened.get(&tenant(), &key(7), "finding-1").unwrap(),
            FindingPayloadRecord {
                finding_id: "finding-1".to_owned(),
                media_type: "text/x-diff".to_owned(),
                payload_sha256: digest,
                payload: payload.to_vec(),
            }
        );
    }

    #[test]
    fn every_pooled_connection_has_busy_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteFindingPayloadStore::open(dir.path().join("operator.db")).unwrap();
        let first = store.pool.get().unwrap();
        let second = store.pool.get().unwrap();

        for connection in [&first, &second] {
            let busy_timeout = connection
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap();
            assert!(busy_timeout >= 5_000);
        }
    }

    #[test]
    fn changed_retry_and_wrong_key_fail_closed() {
        let store = SqliteFindingPayloadStore::open_in_memory().unwrap();
        let payload = b"patch";
        let digest = finding_payload_sha256("text/x-diff", payload).unwrap();
        store
            .put(
                &tenant(),
                &key(3),
                "finding-1",
                "text/x-diff",
                &digest,
                payload,
            )
            .unwrap();

        assert!(matches!(
            store.put(
                &tenant(),
                &key(3),
                "finding-1",
                "application/octet-stream",
                &finding_payload_sha256("application/octet-stream", payload).unwrap(),
                payload,
            ),
            Err(FindingPayloadStoreError::Conflict)
        ));
        assert!(matches!(
            store.get(&tenant(), &key(4), "finding-1"),
            Err(FindingPayloadStoreError::AuthenticationFailed)
        ));
    }

    #[test]
    fn commitment_mismatch_is_rejected_before_persistence() {
        let store = SqliteFindingPayloadStore::open_in_memory().unwrap();
        assert!(matches!(
            store.put(
                &tenant(),
                &key(1),
                "finding-1",
                "text/x-diff",
                &"0".repeat(64),
                b"patch",
            ),
            Err(FindingPayloadStoreError::DigestMismatch)
        ));
        assert!(matches!(
            store.get(&tenant(), &key(1), "finding-1"),
            Err(FindingPayloadStoreError::NotFound)
        ));
    }
}
