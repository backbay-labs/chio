use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Serialize;

use super::{sqlite_error, SqliteRuntimeOrchestrationStore};
use crate::hash::canonical_sha256;
use crate::types::TreatyRuntimeArtifactRecord;
use crate::validation::{validate_non_empty, validate_state_label};
use crate::ChioRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    pub fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChioRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let artifact_sha256 = canonical_sha256(artifact)?;
        let raw_json = serde_json::to_string(artifact)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT artifact_sha256 FROM runtime_treaty_artifacts WHERE evidence_kind = ?1 AND evidence_id = ?2",
                params![evidence_kind, evidence_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing) = existing {
            if existing == artifact_sha256 {
                tx.commit().map_err(sqlite_error)?;
                return Ok(());
            }
            return Err(ChioRuntimeError::Rejected {
                code: "duplicate_treaty_runtime_artifact_mismatch",
                detail: "runtime treaty artifact id already exists with a different hash"
                    .to_string(),
            });
        }
        tx.execute(
            r#"
            INSERT INTO runtime_treaty_artifacts (
                evidence_kind, evidence_id, artifact_sha256, raw_json, created_at_unix_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![evidence_kind, evidence_id, artifact_sha256, raw_json, 0_i64],
        )
        .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }

    pub fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                r#"
                SELECT artifact_sha256, raw_json
                FROM runtime_treaty_artifacts
                WHERE evidence_kind = ?1 AND evidence_id = ?2
                "#,
                params![evidence_kind, evidence_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        row.map(|(artifact_sha256, raw_json)| {
            let raw_json = serde_json::from_str(&raw_json)
                .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
            Ok(TreatyRuntimeArtifactRecord {
                evidence_kind: evidence_kind.to_string(),
                evidence_id: evidence_id.to_string(),
                artifact_sha256,
                raw_json,
            })
        })
        .transpose()
    }
}
