//! SQLite-backed persistence for IOU envelopes.
//!
//! The `iou_envelope` table is keyed by `receipt_id` so a finalized
//! receipt maps to exactly one row. Re-processing the same finalized
//! receipt is idempotent: a byte-identical envelope returns `Ok(false)`;
//! a different envelope returns [`IouEnvelopeStoreError::Conflict`].
//!
//! The migration is `CREATE TABLE IF NOT EXISTS` plus
//! `CREATE INDEX IF NOT EXISTS`, so it can run repeatedly against a
//! receipt-store database that already holds other tables.

use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_credit::{IouEnvelope, IouEnvelopeStore, IouEnvelopeStoreError};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

/// SQL migration applied by [`SqliteIouEnvelopeStore::open_with_pool`]
/// to create the `iou_envelope` table.
pub const IOU_ENVELOPE_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS iou_envelope (
    receipt_id TEXT PRIMARY KEY,
    iou_id TEXT NOT NULL,
    receipt_timestamp INTEGER NOT NULL,
    tenant_id TEXT,
    amount_units INTEGER NOT NULL,
    currency TEXT NOT NULL,
    issuer_key TEXT NOT NULL,
    canonical_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iou_envelope_receipt_timestamp
    ON iou_envelope(receipt_timestamp);
CREATE INDEX IF NOT EXISTS idx_iou_envelope_tenant
    ON iou_envelope(tenant_id);
"#;

/// SQLite-backed [`IouEnvelopeStore`] implementation. Wraps an
/// existing connection pool from [`crate::SqliteReceiptStore`] so
/// IOU writes share the same SQLite database and journal mode.
pub struct SqliteIouEnvelopeStore {
    pool: Pool<SqliteConnectionManager>,
    /// Present when opened alongside a receipt store: all writes are
    /// serialized through the receipt store's single writer connection.
    /// `None` only for the standalone `open_with_pool` path.
    writer: Option<crate::receipt_store::WriterHandle>,
}

impl SqliteIouEnvelopeStore {
    /// Open a store backed by the same pool as a sibling receipt
    /// store. Runs the additive migration if the table is absent.
    pub fn open_with_pool(
        pool: Pool<SqliteConnectionManager>,
    ) -> Result<Self, IouEnvelopeStoreError> {
        let connection = pool
            .get()
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        connection
            .execute_batch(IOU_ENVELOPE_MIGRATION)
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        Ok(Self { pool, writer: None })
    }

    /// Construct the store sharing the connection pool of an
    /// existing [`crate::SqliteReceiptStore`]. The receipt store has
    /// already configured WAL / synchronous=FULL on every connection
    /// out of the pool, so no additional connection setup is needed.
    /// Writes are routed through the receipt store's writer handle so
    /// they serialize with receipt commits on the single writer
    /// connection; reads keep using the reader pool.
    pub fn open_alongside(
        store: &crate::SqliteReceiptStore,
    ) -> Result<Self, IouEnvelopeStoreError> {
        let writer = store.writer_handle();
        // Run the additive migration on the writer connection so the reader
        // pool never executes DDL.
        writer
            .run_write(|connection| {
                connection
                    .execute_batch(IOU_ENVELOPE_MIGRATION)
                    .map_err(chio_kernel::ReceiptStoreError::from)
            })
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        Ok(Self {
            pool: store.pool.clone(),
            writer: Some(writer),
        })
    }
}

fn encode_envelope(envelope: &IouEnvelope) -> Result<Arc<[u8]>, IouEnvelopeStoreError> {
    let canonical = canonical_json_bytes(envelope)
        .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
    Ok(Arc::from(canonical.into_boxed_slice()))
}

fn decode_envelope(canonical: &str) -> Result<IouEnvelope, IouEnvelopeStoreError> {
    serde_json::from_str(canonical).map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn insert_envelope_on_connection(
    connection: &rusqlite::Connection,
    receipt_id: &str,
    iou_id: &str,
    receipt_ts: i64,
    tenant_id: Option<&str>,
    amount: i64,
    currency: &str,
    issuer_key_str: &str,
    canonical_str: &str,
) -> Result<bool, IouEnvelopeStoreError> {
    let inserted = connection
        .execute(
            r#"
            INSERT INTO iou_envelope (
                receipt_id,
                iou_id,
                receipt_timestamp,
                tenant_id,
                amount_units,
                currency,
                issuer_key,
                canonical_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt_id,
                iou_id,
                receipt_ts,
                tenant_id,
                amount,
                currency,
                issuer_key_str,
                canonical_str,
            ],
        )
        .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
    if inserted == 1 {
        return Ok(true);
    }

    let existing = connection
        .query_row(
            "SELECT canonical_json FROM iou_envelope WHERE receipt_id = ?1",
            params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
    match existing {
        Some(existing_canonical) if existing_canonical == canonical_str => Ok(false),
        Some(_) => Err(IouEnvelopeStoreError::Conflict(format!(
            "iou_envelope row for receipt_id={receipt_id} already exists with different bytes"
        ))),
        None => Err(IouEnvelopeStoreError::Backend(format!(
            "iou_envelope conflict for receipt_id={receipt_id} but no row was readable"
        ))),
    }
}

impl IouEnvelopeStore for SqliteIouEnvelopeStore {
    fn insert(&self, envelope: &IouEnvelope) -> Result<bool, IouEnvelopeStoreError> {
        let canonical_bytes = encode_envelope(envelope)?;
        let canonical_str = std::str::from_utf8(&canonical_bytes)
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        let issuer_key_str = serde_json::to_string(&envelope.body.issuer_key)
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        let amount: i64 =
            envelope
                .body
                .amount_units
                .try_into()
                .map_err(|err: std::num::TryFromIntError| {
                    IouEnvelopeStoreError::Backend(err.to_string())
                })?;
        let receipt_ts: i64 = envelope.body.receipt_timestamp.try_into().map_err(
            |err: std::num::TryFromIntError| IouEnvelopeStoreError::Backend(err.to_string()),
        )?;

        match &self.writer {
            Some(writer) => {
                let receipt_id = envelope.body.receipt_id.clone();
                let iou_id = envelope.body.iou_id.clone();
                let tenant_id = envelope.body.tenant_id.clone();
                let currency = envelope.body.currency.clone();
                let issuer_key = issuer_key_str.clone();
                let canonical = canonical_str.to_string();
                writer
                    .run_write(move |connection| {
                        // Propagate the IOU insert result to the writer.
                        // Wrapping the inner result in `Ok(...)` would make the
                        // writer actor record EVERY insert as committed -
                        // refreshing `committed_total`/`last_commit_unix_ms` -
                        // even when the inner insert returned a conflict or
                        // backend error, so the receipt writer health telemetry
                        // would misreport failed IOU persistence. Surface the
                        // failure to the actor as a
                        // `ReceiptStoreError` (fail-closed) so it is counted as
                        // `failed_total`. The reverse mapping below restores the
                        // original `IouEnvelopeStoreError` variant for the caller,
                        // so a mismatched re-insert still returns `Conflict`
                        // exactly as the standalone path and the trait contract
                        // require.
                        insert_envelope_on_connection(
                            connection,
                            &receipt_id,
                            &iou_id,
                            receipt_ts,
                            tenant_id.as_deref(),
                            amount,
                            &currency,
                            &issuer_key,
                            &canonical,
                        )
                        .map_err(|err| match err {
                            IouEnvelopeStoreError::Conflict(message) => {
                                chio_kernel::ReceiptStoreError::Conflict(message)
                            }
                            IouEnvelopeStoreError::Backend(message) => {
                                chio_kernel::ReceiptStoreError::Canonical(message)
                            }
                        })
                    })
                    .map_err(|err| match err {
                        chio_kernel::ReceiptStoreError::Conflict(message) => {
                            IouEnvelopeStoreError::Conflict(message)
                        }
                        chio_kernel::ReceiptStoreError::Canonical(message) => {
                            IouEnvelopeStoreError::Backend(message)
                        }
                        other => IouEnvelopeStoreError::Backend(other.to_string()),
                    })
            }
            None => {
                let connection = self
                    .pool
                    .get()
                    .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
                insert_envelope_on_connection(
                    &connection,
                    envelope.body.receipt_id.as_str(),
                    envelope.body.iou_id.as_str(),
                    receipt_ts,
                    envelope.body.tenant_id.as_deref(),
                    amount,
                    envelope.body.currency.as_str(),
                    issuer_key_str.as_str(),
                    canonical_str,
                )
            }
        }
    }

    fn get_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<IouEnvelope>, IouEnvelopeStoreError> {
        let connection = self
            .pool
            .get()
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        let row = connection
            .query_row(
                "SELECT canonical_json FROM iou_envelope WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        match row {
            Some(canonical) => Ok(Some(decode_envelope(&canonical)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::crypto::{sha256_hex, Ed25519Backend, Keypair};
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        economics::FinancialReceiptMetadata, economics::SettlementStatus, kinds::TrustLevel,
        metadata::GuardEvidence,
    };
    use chio_credit::{CreditEvaluatorHook, LocalCreditAccount};
    use tempfile::tempdir;

    fn make_priced_receipt(kp: &Keypair, receipt_id: &str, cost: u64) -> ChioReceipt {
        let financial = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: cost,
            currency: "USD".to_string(),
            budget_remaining: 1000 - cost,
            budget_total: 1000,
            delegation_depth: 1,
            root_budget_holder: "tenant-a".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        let body = ChioReceiptBody {
            id: receipt_id.to_string(),
            timestamp: 1_710_000_000,
            capability_id: "cap-001".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"{}"),
            policy_hash: "policy".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "G".to_string(),
                verdict: true,
                details: None,
            }],
            metadata: Some(serde_json::json!({"financial": financial})),
            trust_level: TrustLevel::default(),
            tenant_id: Some("tenant-a".to_string()),
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, kp).unwrap()
    }

    fn open_store() -> SqliteIouEnvelopeStore {
        let dir = tempdir().unwrap();
        let path = dir.path().join("iou.sqlite");
        // Construct a pool directly so the test does not require a
        // sibling receipt store.
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(2).build(manager).unwrap();
        // Leak the tempdir so the file outlives the test.
        std::mem::forget(dir);
        SqliteIouEnvelopeStore::open_with_pool(pool).unwrap()
    }

    #[test]
    fn insert_then_get_round_trip() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_priced_receipt(&kp, "rcpt-store-1", 250);
        let envelope = account.evaluate(&receipt).unwrap().unwrap();
        let store = open_store();
        assert!(store.insert(&envelope).unwrap());
        let fetched = store
            .get_by_receipt_id(&receipt.id)
            .unwrap()
            .expect("envelope was inserted");
        assert_eq!(fetched, envelope);
    }

    #[test]
    fn duplicate_insert_is_idempotent() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_priced_receipt(&kp, "rcpt-store-2", 100);
        let envelope = account.evaluate(&receipt).unwrap().unwrap();
        let store = open_store();
        assert!(store.insert(&envelope).unwrap());
        assert!(!store.insert(&envelope).unwrap());
    }

    #[test]
    fn conflicting_envelope_for_same_receipt_id_errors() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt_a = make_priced_receipt(&kp_a, "rcpt-store-3", 100);
        let env_a = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp_a.clone()),
            [kp_a.public_key()],
        )
        .evaluate(&receipt_a)
        .unwrap()
        .unwrap();
        let env_b = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp_b),
            [kp_a.public_key()],
        )
        .evaluate(&receipt_a)
        .unwrap()
        .unwrap();
        assert_eq!(env_a.body.receipt_id, env_b.body.receipt_id);
        assert_ne!(env_a.body.issuer_key, env_b.body.issuer_key);
        let store = open_store();
        assert!(store.insert(&env_a).unwrap());
        match store.insert(&env_b) {
            Err(IouEnvelopeStoreError::Conflict(_)) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn get_missing_returns_none() {
        let store = open_store();
        assert!(store.get_by_receipt_id("nope").unwrap().is_none());
    }

    #[test]
    fn open_alongside_routes_writes_through_the_receipt_writer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("iou-alongside.sqlite3");
        let receipt_store = crate::SqliteReceiptStore::open(&path).unwrap();
        let store = SqliteIouEnvelopeStore::open_alongside(&receipt_store).unwrap();
        assert!(
            store.writer.is_some(),
            "open_alongside must carry the receipt writer handle"
        );

        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_priced_receipt(&kp, "rcpt-alongside-1", 42);
        let envelope = account.evaluate(&receipt).unwrap().unwrap();
        assert!(store.insert(&envelope).unwrap());
        assert!(!store.insert(&envelope).unwrap());
        let fetched = store
            .get_by_receipt_id(&receipt.id)
            .unwrap()
            .expect("envelope was inserted");
        assert_eq!(fetched, envelope);
        std::mem::forget(dir);
    }

    #[test]
    fn failed_writer_routed_insert_is_recorded_as_a_writer_failure() {
        // When an IOU store is opened alongside a
        // receipt store, a failed insert routed through the shared writer must
        // surface as a writer FAILURE, not be swallowed as a committed write, so
        // the receipt writer health telemetry stays accurate. The caller still
        // receives the original Conflict variant.
        let dir = tempdir().unwrap();
        let path = dir.path().join("iou-writer-failure.sqlite3");
        let receipt_store = crate::SqliteReceiptStore::open(&path).unwrap();
        let store = SqliteIouEnvelopeStore::open_alongside(&receipt_store).unwrap();
        assert!(store.writer.is_some());

        // Two envelopes share a receipt_id but carry different bytes (different
        // kernel signer), so the second insert conflicts.
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = make_priced_receipt(&kp_a, "rcpt-writer-fail-1", 100);
        let env_a = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp_a.clone()),
            [kp_a.public_key()],
        )
        .evaluate(&receipt)
        .unwrap()
        .unwrap();
        let env_b = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp_b),
            [kp_a.public_key()],
        )
        .evaluate(&receipt)
        .unwrap()
        .unwrap();
        assert_eq!(env_a.body.receipt_id, env_b.body.receipt_id);
        assert_ne!(env_a.body.issuer_key, env_b.body.issuer_key);

        assert!(store.insert(&env_a).unwrap());

        // `flush_receipt_writes` is a writer barrier, so its snapshot reflects the
        // fully-processed job outcome (no race with `record_write_job_outcome`).
        let failed_before = receipt_store
            .flush_receipt_writes()
            .unwrap()
            .writer
            .failed_total;

        // The conflicting insert must surface as a Conflict to the caller AND be
        // recorded as a writer failure.
        match store.insert(&env_b) {
            Err(IouEnvelopeStoreError::Conflict(_)) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }

        let failed_after = receipt_store
            .flush_receipt_writes()
            .unwrap()
            .writer
            .failed_total;
        assert_eq!(
            failed_after,
            failed_before + 1,
            "a failed IOU insert must increment the receipt writer failed_total"
        );
        std::mem::forget(dir);
    }
}
