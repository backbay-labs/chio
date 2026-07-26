use super::*;

pub(crate) fn update_stage(
    transaction: &Transaction<'_>,
    record: &EconomicStateStageRecord,
    committed_view_bytes: Option<Vec<u8>>,
    reason: Option<&str>,
    expected_status: EconomicStateStageStatus,
) -> Result<(), EconomicStateCacheError> {
    let expected_version = record
        .version
        .checked_sub(1)
        .ok_or_else(|| invariant("economic stage version underflowed"))?;
    let changed = transaction
        .execute(
            r#"
            UPDATE economic_state_stages
            SET committed_view_json = COALESCE(?1, committed_view_json),
                status = ?2, reason = ?3, stage_version = ?4,
                snapshot_digest = ?5, updated_at_unix_ms = ?6
            WHERE batch_id = ?7 AND status = ?8 AND stage_version = ?9
            "#,
            params![
                committed_view_bytes,
                record.status.as_str(),
                reason,
                sqlite_i64(record.version, "stage_version")?,
                &record.snapshot_digest,
                sqlite_i64(record.updated_at_unix_ms, "updated_at_unix_ms")?,
                &record.batch.batch_id,
                expected_status.as_str(),
                sqlite_i64(expected_version, "expected_stage_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(EconomicStateCacheError::Conflict);
    }
    Ok(())
}

pub(crate) fn load_stage_tx(
    transaction: &Transaction<'_>,
    batch_id: &str,
) -> Result<Option<EconomicStateStageRecord>, EconomicStateCacheError> {
    let stored = transaction
        .query_row(
            r#"
            SELECT base_view_json, batch_json, committed_view_json,
                   operation_binding_json, descriptor_kind, descriptor_key,
                   descriptor_digest, descriptor_json, status, reason,
                   stage_version, snapshot_digest, created_at_unix_ms,
                   updated_at_unix_ms
            FROM economic_state_stages WHERE batch_id = ?1
            "#,
            [batch_id],
            read_stored_stage,
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let record = stored.decode()?;
    let head_digests = load_stage_head_digests(transaction, batch_id)?;
    if record.snapshot_digest != stage_snapshot_digest(&record, &head_digests)? {
        return Err(invariant("economic stage snapshot digest is invalid"));
    }
    let latest_commit: Option<(i64, String)> = transaction
        .query_row(
            r#"
            SELECT stage_version, snapshot_digest
            FROM economic_state_stage_commits
            WHERE batch_id = ?1 ORDER BY stage_version DESC LIMIT 1
            "#,
            [batch_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    if latest_commit
        != Some((
            sqlite_i64(record.version, "stage_version")?,
            record.snapshot_digest.clone(),
        ))
    {
        return Err(invariant("economic stage lost its exact latest commit"));
    }
    Ok(Some(record))
}

struct StoredStage {
    base_view: Vec<u8>,
    batch: Vec<u8>,
    committed_view: Option<Vec<u8>>,
    operation_binding: Option<Vec<u8>>,
    descriptor_kind: Option<String>,
    descriptor_key: Option<String>,
    descriptor_digest: Option<String>,
    descriptor_json: Option<Vec<u8>>,
    status: String,
    reason: Option<String>,
    version: i64,
    snapshot_digest: String,
    created_at: i64,
    updated_at: i64,
}

impl StoredStage {
    fn decode(self) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        let base_view = decode_exact(&self.base_view, "base anchor view")?;
        let batch: EconomicStateBatchV1 = decode_exact(&self.batch, "economic batch")?;
        batch.validate()?;
        let committed_view = self
            .committed_view
            .as_deref()
            .map(|bytes| decode_exact(bytes, "committed anchor view"))
            .transpose()?;
        let operation_binding: Option<EconomicOperationStageBinding> = self
            .operation_binding
            .as_deref()
            .map(|bytes| decode_exact(bytes, "economic operation binding"))
            .transpose()?;
        if let Some(binding) = &operation_binding {
            binding.validate()?;
        }
        let created_at_unix_ms = stored_u64(self.created_at, "created_at_unix_ms")?;
        if operation_binding.as_ref().is_some_and(|binding| {
            binding.recovery_expires_at_unix_ms() <= created_at_unix_ms
                || binding
                    .not_after_unix_ms()
                    .is_some_and(|not_after| not_after <= created_at_unix_ms)
        }) {
            return Err(invariant("economic operation binding window is invalid"));
        }
        let descriptor = match (
            self.descriptor_kind,
            self.descriptor_key,
            self.descriptor_digest,
            self.descriptor_json,
        ) {
            (Some(kind), Some(key), Some(digest), Some(json)) => Some(
                EconomicStateStageDescriptor::from_stored(kind, key, digest, json)?,
            ),
            (None, None, None, None) => None,
            _ => return Err(invariant("economic stage descriptor is incomplete")),
        };
        Ok(EconomicStateStageRecord {
            base_view,
            batch,
            committed_view,
            operation_binding,
            descriptor,
            status: EconomicStateStageStatus::parse(&self.status)?,
            reason: self.reason,
            version: stored_u64(self.version, "stage_version")?,
            created_at_unix_ms,
            updated_at_unix_ms: stored_u64(self.updated_at, "updated_at_unix_ms")?,
            snapshot_digest: self.snapshot_digest,
        })
    }
}

fn read_stored_stage(row: &Row<'_>) -> rusqlite::Result<StoredStage> {
    Ok(StoredStage {
        base_view: row.get(0)?,
        batch: row.get(1)?,
        committed_view: row.get(2)?,
        operation_binding: row.get(3)?,
        descriptor_kind: row.get(4)?,
        descriptor_key: row.get(5)?,
        descriptor_digest: row.get(6)?,
        descriptor_json: row.get(7)?,
        status: row.get(8)?,
        reason: row.get(9)?,
        version: row.get(10)?,
        snapshot_digest: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

pub(super) fn load_stage_head_digests(
    transaction: &Transaction<'_>,
    batch_id: &str,
) -> Result<Vec<(String, String)>, EconomicStateCacheError> {
    let mut statement = transaction
        .prepare(
            r#"
            SELECT resource_key_digest, resource_key_json, head_digest, head_json
            FROM economic_state_stage_heads
            WHERE batch_id = ?1 ORDER BY resource_key_digest
            "#,
        )
        .map_err(sqlite_error)?;
    let stored = statement
        .query_map([batch_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    stored
        .into_iter()
        .map(|(key_digest, key_bytes, head_digest, head_bytes)| {
            let key: EconomicResourceKeyV1 = decode_exact(&key_bytes, "resource key")?;
            key.validate()?;
            let head: EconomicResourceHeadV1 = decode_exact(&head_bytes, "resource head")?;
            head.validate()?;
            if sha256_hex(&key_bytes) != key_digest
                || head.resource_key != key
                || head.digest()? != head_digest
            {
                return Err(invariant("staged economic resource head is corrupt"));
            }
            Ok((key_digest, head_digest))
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StageSnapshot<'a> {
    format: &'static str,
    batch_id: &'a str,
    base_view_sha256: String,
    batch_sha256: String,
    committed_view_sha256: Option<String>,
    operation_binding_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor_kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptor_digest: Option<&'a str>,
    status: EconomicStateStageStatus,
    reason: Option<&'a str>,
    version: u64,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    head_digests: &'a [(String, String)],
}

pub(super) fn stage_snapshot_digest(
    record: &EconomicStateStageRecord,
    head_digests: &[(String, String)],
) -> Result<String, EconomicStateCacheError> {
    let base = canonical_json_bytes(&record.base_view).map_err(canonical_error)?;
    let batch = record.batch.canonical_bytes()?;
    let committed = record
        .committed_view
        .as_ref()
        .map(canonical_json_bytes)
        .transpose()
        .map_err(canonical_error)?;
    let binding = record
        .operation_binding
        .as_ref()
        .map(canonical_json_bytes)
        .transpose()
        .map_err(canonical_error)?;
    let snapshot = StageSnapshot {
        format: "chio.sqlite-economic-stage-snapshot.v1",
        batch_id: &record.batch.batch_id,
        base_view_sha256: sha256_hex(&base),
        batch_sha256: sha256_hex(&batch),
        committed_view_sha256: committed.as_deref().map(sha256_hex),
        operation_binding_sha256: binding.as_deref().map(sha256_hex),
        descriptor_kind: record.descriptor.as_ref().map(|value| value.kind.as_str()),
        descriptor_key: record.descriptor.as_ref().map(|value| value.key.as_str()),
        descriptor_digest: record
            .descriptor
            .as_ref()
            .map(|value| value.digest.as_str()),
        status: record.status,
        reason: record.reason.as_deref(),
        version: record.version,
        created_at_unix_ms: record.created_at_unix_ms,
        updated_at_unix_ms: record.updated_at_unix_ms,
        head_digests,
    };
    canonical_json_bytes(&snapshot)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(canonical_error)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StageCommit<'a> {
    format: &'static str,
    batch_id: &'a str,
    stage_version: u64,
    status: EconomicStateStageStatus,
    snapshot_digest: &'a str,
    previous_commit_digest: &'a str,
    mutation_kind: &'a str,
    store_fence: &'a StoreMutationFence,
    recorded_at_unix_ms: u64,
}

pub(crate) fn append_stage_commit(
    transaction: &Transaction<'_>,
    record: &EconomicStateStageRecord,
    mutation_kind: &'static str,
    owner: &SqliteServingOwner,
) -> Result<(), EconomicStateCacheError> {
    let previous = if record.version == 1 {
        GENESIS_STAGE_COMMIT_DIGEST.to_owned()
    } else {
        let previous_version = record
            .version
            .checked_sub(1)
            .ok_or_else(|| invariant("economic stage version underflowed"))?;
        transaction
            .query_row(
                r#"
                SELECT commit_digest FROM economic_state_stage_commits
                WHERE batch_id = ?1 AND stage_version = ?2
                "#,
                params![
                    &record.batch.batch_id,
                    sqlite_i64(previous_version, "previous_stage_version")?,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| invariant("economic stage commit predecessor is absent"))?
    };
    let body = StageCommit {
        format: "chio.sqlite-economic-stage-commit.v1",
        batch_id: &record.batch.batch_id,
        stage_version: record.version,
        status: record.status,
        snapshot_digest: &record.snapshot_digest,
        previous_commit_digest: &previous,
        mutation_kind,
        store_fence: &owner.fence,
        recorded_at_unix_ms: record.updated_at_unix_ms,
    };
    let commit_digest = canonical_json_bytes(&body)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(canonical_error)?;
    transaction
        .execute(
            r#"
            INSERT INTO economic_state_stage_commits (
                batch_id, stage_version, status, snapshot_digest,
                previous_commit_digest, commit_digest, store_uuid,
                store_lease_id, store_owner_epoch, recorded_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                &record.batch.batch_id,
                sqlite_i64(record.version, "stage_version")?,
                record.status.as_str(),
                &record.snapshot_digest,
                previous,
                commit_digest,
                &owner.fence.store_uuid,
                &owner.fence.lease_id,
                sqlite_i64(owner.fence.owner_epoch, "store_owner_epoch")?,
                sqlite_i64(record.updated_at_unix_ms, "recorded_at_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    owner
        .append_global_commit(
            transaction,
            mutation_kind,
            "economic",
            &record.batch.batch_id,
            record.version,
        )
        .map_err(map_owner_error)
}

pub(crate) fn verify_cache_sql_invariants(
    connection: &Connection,
) -> Result<(), EconomicStateCacheError> {
    let invalid = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM economic_state_stages AS stage
                WHERE NOT EXISTS(
                    SELECT 1 FROM economic_state_stage_commits AS stage_commit
                    WHERE stage_commit.batch_id = stage.batch_id
                      AND stage_commit.stage_version = stage.stage_version
                      AND stage_commit.status = stage.status
                      AND stage_commit.snapshot_digest = stage.snapshot_digest
                )
            )
            OR EXISTS(
                SELECT 1 FROM economic_state_heads AS head
                JOIN economic_state_stages AS stage
                  ON stage.batch_id = head.source_batch_id
                WHERE stage.status <> 'db_finalized'
                   OR NOT EXISTS(
                       SELECT 1 FROM economic_state_stage_heads AS staged
                       WHERE staged.batch_id = head.source_batch_id
                         AND staged.resource_key_digest = head.resource_key_digest
                         AND staged.resource_key_json = head.resource_key_json
                         AND staged.head_digest = head.head_digest
                         AND staged.head_json = head.head_json
                   )
            )
            OR EXISTS(
                SELECT 1 FROM economic_state_stages
                WHERE (descriptor_kind IS NULL) <> (descriptor_key IS NULL)
                   OR (descriptor_kind IS NULL) <> (descriptor_digest IS NULL)
                   OR (descriptor_kind IS NULL) <> (descriptor_json IS NULL)
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid {
        Err(invariant("economic state cache projection is inconsistent"))
    } else {
        Ok(())
    }
}

pub(super) fn verify_active_owner(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    requested: Option<&StoreMutationFence>,
) -> Result<(), EconomicStateCacheError> {
    crate::admission_operation_store::verify_active_owner(transaction, owner, requested).map_err(
        |error| match error {
            chio_kernel::admission_operation::AdmissionOperationStoreError::Fenced => {
                EconomicStateCacheError::Fenced
            }
            other => invariant(other.to_string()),
        },
    )
}

pub(super) fn require_transition(
    from: EconomicStateStageStatus,
    to: EconomicStateStageStatus,
) -> Result<(), EconomicStateCacheError> {
    let legal = matches!(
        (from, to),
        (
            EconomicStateStageStatus::DbStaged,
            EconomicStateStageStatus::EconomicAnchorAdvanced
                | EconomicStateStageStatus::Discarded
                | EconomicStateStageStatus::Quarantined
        ) | (
            EconomicStateStageStatus::EconomicAnchorAdvanced,
            EconomicStateStageStatus::DbFinalized | EconomicStateStageStatus::Quarantined
        )
    );
    if legal {
        Ok(())
    } else {
        Err(EconomicStateCacheError::InvalidTransition { from, to })
    }
}

pub(super) fn monotonic_time(
    record: &EconomicStateStageRecord,
    trusted_now_unix_ms: u64,
) -> Result<u64, EconomicStateCacheError> {
    if trusted_now_unix_ms < record.updated_at_unix_ms {
        Err(invariant("economic stage trusted time regressed"))
    } else {
        Ok(trusted_now_unix_ms)
    }
}

pub(super) fn validate_trusted_time(value: u64) -> Result<(), EconomicStateCacheError> {
    if value == 0 || value > MAX_TRUSTED_UNIX_MS {
        Err(invariant("trusted_now_unix_ms is outside the I-JSON range"))
    } else {
        Ok(())
    }
}

pub(super) fn validate_reason(value: &str) -> Result<(), EconomicStateCacheError> {
    if value.is_empty() || value.len() > MAX_REASON_BYTES || value.chars().any(char::is_control) {
        Err(invariant("economic stage reason is invalid"))
    } else {
        Ok(())
    }
}

pub(super) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), EconomicStateCacheError> {
    if value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(invariant(format!("{field} is not a canonical digest")))
    }
}

pub(super) fn canonical_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    field: &'static str,
) -> Result<Vec<u8>, EconomicStateCacheError> {
    let bytes = canonical_json_bytes(value).map_err(canonical_error)?;
    if bytes.is_empty() || bytes.len() > maximum {
        Err(invariant(format!("{field} exceeds its storage bound")))
    } else {
        Ok(bytes)
    }
}

pub(super) fn decode_exact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<T, EconomicStateCacheError> {
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| invariant(format!("{field} decoding failed: {error}")))?;
    let canonical = canonical_json_bytes(&value).map_err(canonical_error)?;
    if canonical != bytes {
        return Err(invariant(format!("{field} is not canonical JSON")));
    }
    Ok(value)
}

pub(super) fn next_version(value: u64) -> Result<u64, EconomicStateCacheError> {
    value
        .checked_add(1)
        .ok_or_else(|| invariant("economic stage version overflowed"))
}

pub(super) fn optional_u64(
    value: Option<i64>,
    field: &'static str,
) -> Result<Option<u64>, EconomicStateCacheError> {
    value.map(|value| stored_u64(value, field)).transpose()
}

pub(super) fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, EconomicStateCacheError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite INTEGER range")))
}

pub(super) fn stored_u64(value: i64, field: &'static str) -> Result<u64, EconomicStateCacheError> {
    u64::try_from(value).map_err(|_| invariant(format!("stored {field} is negative")))
}

pub(super) fn canonical_error(error: impl std::fmt::Display) -> EconomicStateCacheError {
    invariant(format!("economic state canonical encoding failed: {error}"))
}

pub(super) fn map_owner_error(error: SqliteServingOwnerError) -> EconomicStateCacheError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            EconomicStateCacheError::OutcomeUnknown(detail)
        }
        SqliteServingOwnerError::AlreadyServing(_) => EconomicStateCacheError::Fenced,
        other => invariant(other.to_string()),
    }
}

pub(super) fn sqlite_error(error: rusqlite::Error) -> EconomicStateCacheError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => EconomicStateCacheError::Unavailable(other.to_string()),
    }
}

pub(super) fn invariant(detail: impl Into<String>) -> EconomicStateCacheError {
    EconomicStateCacheError::Invariant(detail.into())
}
