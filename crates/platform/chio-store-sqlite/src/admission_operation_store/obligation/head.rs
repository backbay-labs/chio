use super::*;

pub(super) const GENESIS_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize)]
pub(super) struct CommitPreimageV1<'a> {
    pub(super) domain: &'static str,
    pub(super) obligation_id: &'a str,
    pub(super) head_sequence: u64,
    pub(super) previous_head_digest: &'a str,
    pub(super) atom_digest: &'a str,
    pub(super) disposition_version: u64,
    pub(super) disposition_lifecycle_fence: u64,
    pub(super) disposition_digest: &'a str,
    pub(super) settlement_version: u64,
    pub(super) settlement_lifecycle_fence: u64,
    pub(super) settlement_lifecycle_digest: &'a str,
    pub(super) snapshot_version: u64,
    pub(super) resource_fence: u64,
    pub(super) source_kind: &'a str,
    pub(super) source_operation_id: &'a str,
    pub(super) participant_digest: Option<&'a str>,
    pub(super) participant_commit_sequence: Option<u64>,
    pub(super) committed_at_unix_ms: u64,
    pub(super) store_uuid: &'a str,
    pub(super) store_lease_id: &'a str,
    pub(super) store_owner_epoch: u64,
}

pub(super) struct StoredRow {
    pub(super) head_sequence: i64,
    pub(super) head_digest: String,
    pub(super) atom_digest: String,
    pub(super) disposition_version: i64,
    pub(super) disposition_lifecycle_fence: i64,
    pub(super) settlement_version: i64,
    pub(super) settlement_lifecycle_fence: i64,
    pub(super) snapshot_version: i64,
    pub(super) resource_fence: i64,
    pub(super) updated_at_unix_ms: i64,
    pub(super) store_uuid: String,
    pub(super) store_lease_id: String,
    pub(super) store_owner_epoch: i64,
}

pub(super) struct CommitRow {
    pub(super) head_sequence: i64,
    pub(super) previous_head_digest: String,
    pub(super) head_digest: String,
    pub(super) atom_digest: String,
    pub(super) disposition_version: i64,
    pub(super) disposition_lifecycle_fence: i64,
    pub(super) disposition_digest: String,
    pub(super) settlement_version: i64,
    pub(super) settlement_lifecycle_fence: i64,
    pub(super) settlement_lifecycle_digest: String,
    pub(super) snapshot_version: i64,
    pub(super) resource_fence: i64,
    pub(super) source_kind: String,
    pub(super) source_operation_id: String,
    pub(super) participant_digest: Option<String>,
    pub(super) participant_commit_sequence: Option<i64>,
    pub(super) committed_at_unix_ms: i64,
    pub(super) store_uuid: String,
    pub(super) store_lease_id: String,
    pub(super) store_owner_epoch: i64,
}

pub(super) fn load_row(
    connection: &Connection,
    obligation_id: &str,
) -> Result<Option<StoredRow>, AdmissionOperationStoreError> {
    connection
        .query_row(
            r#"
            SELECT head_sequence, head_digest, atom_digest,
                   disposition_version, disposition_lifecycle_fence,
                   settlement_version, settlement_lifecycle_fence, snapshot_version,
                   resource_fence, updated_at_unix_ms, store_uuid, store_lease_id,
                   store_owner_epoch
            FROM obligation_heads
            WHERE obligation_id = ?1
            "#,
            [obligation_id],
            |row| {
                Ok(StoredRow {
                    head_sequence: row.get(0)?,
                    head_digest: row.get(1)?,
                    atom_digest: row.get(2)?,
                    disposition_version: row.get(3)?,
                    disposition_lifecycle_fence: row.get(4)?,
                    settlement_version: row.get(5)?,
                    settlement_lifecycle_fence: row.get(6)?,
                    snapshot_version: row.get(7)?,
                    resource_fence: row.get(8)?,
                    updated_at_unix_ms: row.get(9)?,
                    store_uuid: row.get(10)?,
                    store_lease_id: row.get(11)?,
                    store_owner_epoch: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)
}

pub(super) fn insert_initial(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    atom: &ObligationAtomV1,
    disposition: &ObligationDispositionRecordV1,
    settlement_lifecycle: &ObligationSettlementLifecycleV1,
    updated_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let atom_digest = atom.digest().map_err(obligation_error)?;
    let disposition_digest = disposition.digest(atom).map_err(obligation_error)?;
    let settlement_lifecycle_digest = settlement_lifecycle
        .digest(atom)
        .map_err(obligation_error)?;
    let preimage = CommitPreimageV1 {
        domain: "chio.obligation.head-commit.v1",
        obligation_id: atom.obligation_id(),
        head_sequence: 1,
        previous_head_digest: GENESIS_DIGEST,
        atom_digest: &atom_digest,
        disposition_version: disposition.version(),
        disposition_lifecycle_fence: disposition.lifecycle_fence(),
        disposition_digest: &disposition_digest,
        settlement_version: settlement_lifecycle.version(),
        settlement_lifecycle_fence: settlement_lifecycle.lifecycle_fence(),
        settlement_lifecycle_digest: &settlement_lifecycle_digest,
        snapshot_version: 1,
        resource_fence: 1,
        source_kind: "initial_projection",
        source_operation_id: operation_id.as_str(),
        participant_digest: None,
        participant_commit_sequence: None,
        committed_at_unix_ms: updated_at_unix_ms,
        store_uuid: &fence.store_uuid,
        store_lease_id: &fence.lease_id,
        store_owner_epoch: fence.owner_epoch,
    };
    let head_digest = digest(&preimage)?;
    insert_commit(transaction, &preimage, &head_digest)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO obligation_heads (
                obligation_id, head_sequence, head_digest, atom_digest, disposition_version,
                disposition_lifecycle_fence, settlement_version,
                settlement_lifecycle_fence, snapshot_version, resource_fence,
                updated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 1, ?8, ?9, ?10, ?11)
            "#,
            params![
                atom.obligation_id(),
                &head_digest,
                &atom_digest,
                sqlite_i64(disposition.version(), "obligation_disposition_version")?,
                sqlite_i64(
                    disposition.lifecycle_fence(),
                    "obligation_disposition_lifecycle_fence"
                )?,
                sqlite_i64(
                    settlement_lifecycle.version(),
                    "obligation_settlement_version"
                )?,
                sqlite_i64(
                    settlement_lifecycle.lifecycle_fence(),
                    "obligation_settlement_lifecycle_fence"
                )?,
                sqlite_i64(updated_at_unix_ms, "obligation_head_updated_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if inserted != 1 {
        return Err(invariant("obligation head did not insert exactly once"));
    }
    Ok(())
}

fn insert_commit(
    transaction: &Transaction<'_>,
    preimage: &CommitPreimageV1<'_>,
    head_digest: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO obligation_head_commits (
                obligation_id, head_sequence, previous_head_digest, head_digest,
                atom_digest, disposition_version, disposition_lifecycle_fence,
                disposition_digest, settlement_version, settlement_lifecycle_fence,
                settlement_lifecycle_digest, snapshot_version, resource_fence,
                source_kind, source_operation_id, participant_digest,
                participant_commit_sequence, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
            )
            "#,
            params![
                preimage.obligation_id,
                sqlite_i64(preimage.head_sequence, "obligation_head_sequence")?,
                preimage.previous_head_digest,
                head_digest,
                preimage.atom_digest,
                sqlite_i64(
                    preimage.disposition_version,
                    "obligation_disposition_version"
                )?,
                sqlite_i64(
                    preimage.disposition_lifecycle_fence,
                    "obligation_disposition_lifecycle_fence"
                )?,
                preimage.disposition_digest,
                sqlite_i64(preimage.settlement_version, "obligation_settlement_version")?,
                sqlite_i64(
                    preimage.settlement_lifecycle_fence,
                    "obligation_settlement_lifecycle_fence"
                )?,
                preimage.settlement_lifecycle_digest,
                sqlite_i64(preimage.snapshot_version, "obligation_snapshot_version")?,
                sqlite_i64(preimage.resource_fence, "obligation_resource_fence")?,
                preimage.source_kind,
                preimage.source_operation_id,
                preimage.participant_digest,
                preimage
                    .participant_commit_sequence
                    .map(|sequence| sqlite_i64(sequence, "participant_commit_sequence"))
                    .transpose()?,
                sqlite_i64(
                    preimage.committed_at_unix_ms,
                    "obligation_head_committed_at_unix_ms"
                )?,
                preimage.store_uuid,
                preimage.store_lease_id,
                sqlite_i64(preimage.store_owner_epoch, "obligation_store_owner_epoch")?,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "obligation head commit did not insert exactly once",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_disposition_transition(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    atom: &ObligationAtomV1,
    current: &ObligationDispositionRecordV1,
    successor: &ObligationDispositionRecordV1,
    settlement_lifecycle: &ObligationSettlementLifecycleV1,
    expected_snapshot_version: u64,
    expected_resource_fence: u64,
    participant_digest: &str,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    current
        .validate_successor(atom, successor)
        .map_err(obligation_error)?;
    settlement_lifecycle
        .validate_against(atom)
        .map_err(obligation_error)?;
    let durable = load_durable_obligation(transaction, atom.obligation_id())?
        .ok_or_else(|| invariant("stored obligation is absent"))?;
    if durable.atom() != atom
        || durable.disposition() != current
        || durable.settlement_lifecycle() != settlement_lifecycle
        || durable.snapshot_version() != expected_snapshot_version
        || durable.resource_fence() != expected_resource_fence
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    if matches!(
        successor.last_transition(),
        ObligationDispositionTransitionV1::Assign {
            operation_id: assigned_operation_id,
            ..
        } if assigned_operation_id != operation_id.as_str()
    ) {
        return Err(invariant(
            "assignment disposition has different operation provenance",
        ));
    }
    let participant_commit_sequence = load_participant_commit_sequence(
        transaction,
        operation_id,
        participant_digest,
        committed_at_unix_ms,
        fence,
    )?;
    let head = load_row(transaction, atom.obligation_id())?
        .ok_or_else(|| invariant("stored obligation lacks its authoritative head"))?;
    if head.atom_digest != atom.digest().map_err(obligation_error)?
        || stored_u64(
            head.disposition_version,
            "obligation_head_disposition_version",
        )? != current.version()
        || stored_u64(
            head.disposition_lifecycle_fence,
            "obligation_head_disposition_lifecycle_fence",
        )? != current.lifecycle_fence()
        || stored_u64(
            head.settlement_version,
            "obligation_head_settlement_version",
        )? != settlement_lifecycle.version()
        || stored_u64(
            head.settlement_lifecycle_fence,
            "obligation_head_settlement_lifecycle_fence",
        )? != settlement_lifecycle.lifecycle_fence()
        || stored_u64(head.snapshot_version, "obligation_snapshot_version")?
            != expected_snapshot_version
        || stored_u64(head.resource_fence, "obligation_resource_fence")? != expected_resource_fence
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    insert_disposition(
        transaction,
        operation_id,
        atom,
        successor,
        committed_at_unix_ms,
        fence,
    )?;
    let head_sequence = stored_u64(head.head_sequence, "obligation_head_sequence")?
        .checked_add(1)
        .ok_or_else(|| invariant("obligation head sequence overflow"))?;
    let snapshot_version = expected_snapshot_version
        .checked_add(1)
        .ok_or_else(|| invariant("obligation snapshot version overflow"))?;
    let resource_fence = expected_resource_fence
        .checked_add(1)
        .ok_or_else(|| invariant("obligation resource fence overflow"))?;
    let atom_digest = atom.digest().map_err(obligation_error)?;
    let disposition_digest = successor.digest(atom).map_err(obligation_error)?;
    let settlement_lifecycle_digest = settlement_lifecycle
        .digest(atom)
        .map_err(obligation_error)?;
    let preimage = CommitPreimageV1 {
        domain: "chio.obligation.head-commit.v1",
        obligation_id: atom.obligation_id(),
        head_sequence,
        previous_head_digest: &head.head_digest,
        atom_digest: &atom_digest,
        disposition_version: successor.version(),
        disposition_lifecycle_fence: successor.lifecycle_fence(),
        disposition_digest: &disposition_digest,
        settlement_version: settlement_lifecycle.version(),
        settlement_lifecycle_fence: settlement_lifecycle.lifecycle_fence(),
        settlement_lifecycle_digest: &settlement_lifecycle_digest,
        snapshot_version,
        resource_fence,
        source_kind: "disposition_transition",
        source_operation_id: operation_id.as_str(),
        participant_digest: Some(participant_digest),
        participant_commit_sequence: Some(participant_commit_sequence),
        committed_at_unix_ms,
        store_uuid: &fence.store_uuid,
        store_lease_id: &fence.lease_id,
        store_owner_epoch: fence.owner_epoch,
    };
    let head_digest = digest(&preimage)?;
    insert_commit(transaction, &preimage, &head_digest)?;
    let changed = transaction
        .execute(
            r#"
            UPDATE obligation_heads
            SET head_sequence = ?1, head_digest = ?2,
                disposition_version = ?3, disposition_lifecycle_fence = ?4,
                snapshot_version = ?5, resource_fence = ?6,
                updated_at_unix_ms = ?7, store_uuid = ?8,
                store_lease_id = ?9, store_owner_epoch = ?10
            WHERE obligation_id = ?11
              AND head_sequence = ?12 AND head_digest = ?13
              AND disposition_version = ?14
              AND disposition_lifecycle_fence = ?15
              AND settlement_version = ?16
              AND settlement_lifecycle_fence = ?17
              AND snapshot_version = ?18 AND resource_fence = ?19
            "#,
            params![
                sqlite_i64(head_sequence, "obligation_head_sequence")?,
                &head_digest,
                sqlite_i64(successor.version(), "obligation_disposition_version")?,
                sqlite_i64(
                    successor.lifecycle_fence(),
                    "obligation_disposition_lifecycle_fence"
                )?,
                sqlite_i64(snapshot_version, "obligation_snapshot_version")?,
                sqlite_i64(resource_fence, "obligation_resource_fence")?,
                sqlite_i64(committed_at_unix_ms, "obligation_head_updated_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
                atom.obligation_id(),
                head.head_sequence,
                &head.head_digest,
                head.disposition_version,
                head.disposition_lifecycle_fence,
                head.settlement_version,
                head.settlement_lifecycle_fence,
                head.snapshot_version,
                head.resource_fence,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn append_settlement_transition(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    atom: &ObligationAtomV1,
    disposition: &ObligationDispositionRecordV1,
    current: &ObligationSettlementLifecycleV1,
    successor: &ObligationSettlementLifecycleV1,
    expected_snapshot_version: u64,
    expected_resource_fence: u64,
    participant_digest: &str,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    disposition
        .validate_against(atom)
        .map_err(obligation_error)?;
    current
        .validate_successor(atom, successor)
        .map_err(obligation_error)?;
    let durable = load_durable_obligation(transaction, atom.obligation_id())?
        .ok_or_else(|| invariant("stored obligation is absent"))?;
    if durable.atom() != atom
        || durable.disposition() != disposition
        || durable.settlement_lifecycle() != current
        || durable.snapshot_version() != expected_snapshot_version
        || durable.resource_fence() != expected_resource_fence
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let participant_commit_sequence = load_participant_commit_sequence(
        transaction,
        operation_id,
        participant_digest,
        committed_at_unix_ms,
        fence,
    )?;
    let head = load_row(transaction, atom.obligation_id())?
        .ok_or_else(|| invariant("stored obligation lacks its authoritative head"))?;
    if head.atom_digest != atom.digest().map_err(obligation_error)?
        || stored_u64(
            head.disposition_version,
            "obligation_head_disposition_version",
        )? != disposition.version()
        || stored_u64(
            head.disposition_lifecycle_fence,
            "obligation_head_disposition_lifecycle_fence",
        )? != disposition.lifecycle_fence()
        || stored_u64(
            head.settlement_version,
            "obligation_head_settlement_version",
        )? != current.version()
        || stored_u64(
            head.settlement_lifecycle_fence,
            "obligation_head_settlement_lifecycle_fence",
        )? != current.lifecycle_fence()
        || stored_u64(head.snapshot_version, "obligation_snapshot_version")?
            != expected_snapshot_version
        || stored_u64(head.resource_fence, "obligation_resource_fence")? != expected_resource_fence
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    insert_settlement_lifecycle(
        transaction,
        operation_id,
        atom,
        successor,
        committed_at_unix_ms,
        fence,
    )?;
    let head_sequence = stored_u64(head.head_sequence, "obligation_head_sequence")?
        .checked_add(1)
        .ok_or_else(|| invariant("obligation head sequence overflow"))?;
    let snapshot_version = expected_snapshot_version
        .checked_add(1)
        .ok_or_else(|| invariant("obligation snapshot version overflow"))?;
    let resource_fence = expected_resource_fence
        .checked_add(1)
        .ok_or_else(|| invariant("obligation resource fence overflow"))?;
    let atom_digest = atom.digest().map_err(obligation_error)?;
    let disposition_digest = disposition.digest(atom).map_err(obligation_error)?;
    let settlement_lifecycle_digest = successor.digest(atom).map_err(obligation_error)?;
    let preimage = CommitPreimageV1 {
        domain: "chio.obligation.head-commit.v1",
        obligation_id: atom.obligation_id(),
        head_sequence,
        previous_head_digest: &head.head_digest,
        atom_digest: &atom_digest,
        disposition_version: disposition.version(),
        disposition_lifecycle_fence: disposition.lifecycle_fence(),
        disposition_digest: &disposition_digest,
        settlement_version: successor.version(),
        settlement_lifecycle_fence: successor.lifecycle_fence(),
        settlement_lifecycle_digest: &settlement_lifecycle_digest,
        snapshot_version,
        resource_fence,
        source_kind: "settlement_lifecycle",
        source_operation_id: operation_id.as_str(),
        participant_digest: Some(participant_digest),
        participant_commit_sequence: Some(participant_commit_sequence),
        committed_at_unix_ms,
        store_uuid: &fence.store_uuid,
        store_lease_id: &fence.lease_id,
        store_owner_epoch: fence.owner_epoch,
    };
    let head_digest = digest(&preimage)?;
    insert_commit(transaction, &preimage, &head_digest)?;
    let changed = transaction
        .execute(
            r#"
            UPDATE obligation_heads
            SET head_sequence = ?1, head_digest = ?2,
                settlement_version = ?3, settlement_lifecycle_fence = ?4,
                snapshot_version = ?5, resource_fence = ?6,
                updated_at_unix_ms = ?7, store_uuid = ?8,
                store_lease_id = ?9, store_owner_epoch = ?10
            WHERE obligation_id = ?11
              AND head_sequence = ?12 AND head_digest = ?13
              AND disposition_version = ?14
              AND disposition_lifecycle_fence = ?15
              AND settlement_version = ?16
              AND settlement_lifecycle_fence = ?17
              AND snapshot_version = ?18 AND resource_fence = ?19
            "#,
            params![
                sqlite_i64(head_sequence, "obligation_head_sequence")?,
                &head_digest,
                sqlite_i64(successor.version(), "obligation_settlement_version")?,
                sqlite_i64(
                    successor.lifecycle_fence(),
                    "obligation_settlement_lifecycle_fence"
                )?,
                sqlite_i64(snapshot_version, "obligation_snapshot_version")?,
                sqlite_i64(resource_fence, "obligation_resource_fence")?,
                sqlite_i64(committed_at_unix_ms, "obligation_head_updated_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
                atom.obligation_id(),
                head.head_sequence,
                &head.head_digest,
                head.disposition_version,
                head.disposition_lifecycle_fence,
                head.settlement_version,
                head.settlement_lifecycle_fence,
                head.snapshot_version,
                head.resource_fence,
            ],
        )
        .map_err(obligation_sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

fn load_participant_commit_sequence(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    participant_digest: &str,
    committed_at_unix_ms: u64,
    fence: &StoreMutationFence,
) -> Result<u64, AdmissionOperationStoreError> {
    let sequence = transaction
        .query_row(
            r#"
            SELECT commit_sequence FROM admission_operation_commits
            WHERE operation_id = ?1
              AND mutation_kind = 'participant_update'
              AND participant_digest = ?2
              AND recorded_at_unix_ms = ?3
              AND store_uuid = ?4
              AND store_lease_id = ?5
              AND store_owner_epoch = ?6
            ORDER BY commit_sequence DESC
            LIMIT 1
            "#,
            params![
                operation_id.as_str(),
                participant_digest,
                sqlite_i64(committed_at_unix_ms, "obligation_head_committed_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "obligation_store_owner_epoch")?,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("obligation head lacks its admission participant commit"))?;
    stored_u64(sequence, "participant_commit_sequence")
}

pub(super) fn digest(
    preimage: &CommitPreimageV1<'_>,
) -> Result<String, AdmissionOperationStoreError> {
    canonical_json_bytes(preimage)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| invariant(format!("obligation head commit encoding failed: {error}")))
}
