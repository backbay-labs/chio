use rusqlite::{params, OptionalExtension, TransactionBehavior};

use super::{sqlite_error, sqlite_i64, sqlite_u64, SqliteRuntimeOrchestrationStore};
use crate::admission::validate_runtime_trust_floor_transition;
use crate::types::RuntimeTrustFloorEntry;
use crate::ChiodosRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub(super) fn load_runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        let row: Option<(String, String, i64, String, String)> = connection
            .query_row(
                r#"
                SELECT verifier_id, key_id, highest_version, latest_bundle_sha256,
                       latest_revocation_checkpoint_sha256
                FROM runtime_trust_floors
                WHERE verifier_id = ?1 AND key_id = ?2
                "#,
                params![verifier_id, key_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(
            |(
                verifier_id,
                key_id,
                highest_version,
                latest_bundle_sha256,
                latest_revocation_checkpoint_sha256,
            )| {
                Ok(RuntimeTrustFloorEntry {
                    verifier_id,
                    key_id,
                    highest_version: sqlite_u64(highest_version, "runtime trust floor version")?,
                    latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256,
                })
            },
        )
        .transpose()
    }

    pub(super) fn store_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        let connection = self.lock_connection()?;
        connection
            .execute(
                r#"
                INSERT INTO runtime_trust_floors (
                    verifier_id, key_id, highest_version, latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256
                )
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(verifier_id, key_id) DO UPDATE SET
                    highest_version = excluded.highest_version,
                    latest_bundle_sha256 = excluded.latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256 = excluded.latest_revocation_checkpoint_sha256
                "#,
                params![
                    entry.verifier_id,
                    entry.key_id,
                    sqlite_i64(entry.highest_version, "runtime trust floor version")?,
                    entry.latest_bundle_sha256,
                    entry.latest_revocation_checkpoint_sha256
                ],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub(super) fn validate_and_store_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<(String, String, i64, String, String)> = tx
            .query_row(
                r#"
                SELECT verifier_id, key_id, highest_version, latest_bundle_sha256,
                       latest_revocation_checkpoint_sha256
                FROM runtime_trust_floors
                WHERE verifier_id = ?1 AND key_id = ?2
                "#,
                params![entry.verifier_id, entry.key_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let existing = existing
            .map(
                |(
                    verifier_id,
                    key_id,
                    highest_version,
                    latest_bundle_sha256,
                    latest_revocation_checkpoint_sha256,
                )| {
                    Ok(RuntimeTrustFloorEntry {
                        verifier_id,
                        key_id,
                        highest_version: sqlite_u64(
                            highest_version,
                            "runtime trust floor version",
                        )?,
                        latest_bundle_sha256,
                        latest_revocation_checkpoint_sha256,
                    })
                },
            )
            .transpose()?;
        validate_runtime_trust_floor_transition(existing, &entry, previous_hash_sha256)?;
        tx.execute(
            r#"
            INSERT INTO runtime_trust_floors (
                verifier_id, key_id, highest_version, latest_bundle_sha256,
                latest_revocation_checkpoint_sha256
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(verifier_id, key_id) DO UPDATE SET
                highest_version = excluded.highest_version,
                latest_bundle_sha256 = excluded.latest_bundle_sha256,
                latest_revocation_checkpoint_sha256 = excluded.latest_revocation_checkpoint_sha256
            "#,
            params![
                entry.verifier_id,
                entry.key_id,
                sqlite_i64(entry.highest_version, "runtime trust floor version")?,
                entry.latest_bundle_sha256,
                entry.latest_revocation_checkpoint_sha256
            ],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }
}
