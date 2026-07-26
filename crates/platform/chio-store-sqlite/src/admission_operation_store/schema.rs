use super::*;

pub(crate) fn initialize_admission_operation_schema(
    connection: &mut Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        ADMISSION_OPERATION_SCHEMA_KEY,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
        ADMISSION_OPERATION_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION {
        return verify_admission_operation_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    if on_disk < 9 && table_exists(&transaction, "threshold_approval_tokens")? {
        migrate_threshold_approval_token_scope(&transaction)?;
    }
    if obligation_disposition_references_terminal_projection(&transaction)? {
        migrate_obligation_lifecycle_foundation(&transaction)?;
    }
    if on_disk == 2 {
        migrate_admission_commit_participant_digest(&transaction)?;
    }
    if on_disk == 3 {
        migrate_admission_commit_begin_participant_digest(&transaction)?;
    }
    if matches!(on_disk, 1 | 4) {
        migrate_admission_commit_channel_reservation_kind(&transaction)?;
    }
    if matches!(on_disk, 2 | 3) {
        migrate_terminal_record_kinds(&transaction)?;
    }
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        ADMISSION_OPERATION_SCHEMA_KEY,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_admission_operation_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

fn table_exists(
    transaction: &Transaction<'_>,
    table_name: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = ?1
            )
            "#,
            [table_name],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn migrate_threshold_approval_token_scope(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS threshold_approval_tokens_immutable;
            DROP TRIGGER IF EXISTS threshold_approval_tokens_no_delete;
            ALTER TABLE threshold_approval_tokens
                RENAME TO threshold_approval_tokens_v8;
            CREATE TABLE threshold_approval_tokens (
                proposal_id TEXT NOT NULL,
                token_id TEXT NOT NULL
                    CHECK (length(token_id) BETWEEN 1 AND 512),
                approver_fingerprint TEXT NOT NULL
                    CHECK (approver_fingerprint <> ''),
                canonical_token_digest TEXT NOT NULL UNIQUE CHECK (
                    length(canonical_token_digest) = 64
                    AND canonical_token_digest NOT GLOB '*[^0-9a-f]*'
                ),
                token_json BLOB NOT NULL
                    CHECK (length(token_json) BETWEEN 1 AND 262144),
                PRIMARY KEY (proposal_id, token_id),
                UNIQUE (proposal_id, approver_fingerprint),
                UNIQUE (proposal_id, canonical_token_digest),
                FOREIGN KEY (proposal_id)
                    REFERENCES threshold_approval_proposals(proposal_id)
            );
            INSERT INTO threshold_approval_tokens (
                proposal_id, token_id, approver_fingerprint,
                canonical_token_digest, token_json
            )
            SELECT proposal_id, token_id, approver_fingerprint,
                   canonical_token_digest, token_json
            FROM threshold_approval_tokens_v8;
            DROP TABLE threshold_approval_tokens_v8;
            "#,
        )
        .map_err(sqlite_error)
}

fn obligation_disposition_references_terminal_projection(
    transaction: &Transaction<'_>,
) -> Result<bool, AdmissionOperationStoreError> {
    transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM pragma_foreign_key_list('obligation_disposition_records')
                WHERE "table" = 'admission_operation_terminal_projections'
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn migrate_obligation_lifecycle_foundation(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let obligation_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM obligation_atoms", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)?;
    if obligation_count != 0 {
        return Err(invariant(
            "populated admission schema v5 requires offline authoritative settlement reconciliation",
        ));
    }
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER obligation_disposition_records_exact_lease;
            DROP TRIGGER obligation_disposition_records_immutable;
            DROP TRIGGER obligation_disposition_records_no_delete;
            DROP INDEX obligation_disposition_records_operation;
            ALTER TABLE obligation_disposition_records
                RENAME TO obligation_disposition_records_v5;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER obligation_settlement_lifecycle_records_exact_lease;
            DROP TRIGGER obligation_heads_exact_lease_insert;
            DROP TRIGGER obligation_heads_exact_lease_update;
            DROP TRIGGER obligation_disposition_records_exact_lease;
            INSERT INTO obligation_disposition_records (
                obligation_id, version, lifecycle_fence, atom_digest,
                disposition_digest, operation_id, record_json, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            )
            SELECT obligation_id, version, lifecycle_fence, atom_digest,
                   disposition_digest, operation_id, record_json, committed_at_unix_ms,
                   store_uuid, store_lease_id, store_owner_epoch
            FROM obligation_disposition_records_v5
            ORDER BY obligation_id, version;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            DROP TABLE obligation_disposition_records_v5;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}

fn migrate_terminal_record_kinds(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS admission_operation_terminal_records_immutable;
            DROP TRIGGER IF EXISTS admission_operation_terminal_records_no_delete;
            DROP INDEX IF EXISTS admission_operation_terminal_records_kind;
            ALTER TABLE admission_operation_terminal_records
                RENAME TO admission_operation_terminal_records_v3;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO admission_operation_terminal_records (
                operation_id, record_kind, record_id, record_digest, record_json
            )
            SELECT operation_id, record_kind, record_id, record_digest, record_json
            FROM admission_operation_terminal_records_v3;
            DROP TABLE admission_operation_terminal_records_v3;
            "#,
        )
        .map_err(sqlite_error)
}

fn migrate_admission_commit_participant_digest(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v2;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;")
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, participant_digest,
                previous_chain_digest, chain_digest,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            )
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, NULL,
                   previous_chain_digest, chain_digest,
                   store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits_v2
            ORDER BY commit_sequence;
            DROP TABLE admission_operation_commits_v2;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}

fn migrate_admission_commit_begin_participant_digest(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v3;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;")
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, participant_digest,
                previous_chain_digest, chain_digest,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            )
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, participant_digest,
                   previous_chain_digest, chain_digest,
                   store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits_v3
            ORDER BY commit_sequence;
            DROP TABLE admission_operation_commits_v3;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}

fn migrate_admission_commit_channel_reservation_kind(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v4;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;")
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, participant_digest,
                previous_chain_digest, chain_digest,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            )
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, participant_digest,
                   previous_chain_digest, chain_digest,
                   store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits_v4
            ORDER BY commit_sequence;
            DROP TABLE admission_operation_commits_v4;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}

pub(crate) fn verify_admission_operation_invariants(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    if admission_operation_schema_catalog(connection)?
        != admission_operation_schema_catalog(&expected)?
    {
        return Err(invariant(
            "admission operation schema differs from the canonical definition",
        ));
    }

    let (head, high_water, commit_count, max_commit, max_recorded_at): (i64, i64, i64, i64, i64) =
        connection
            .query_row(
                r#"
            SELECT
                (SELECT head_sequence FROM admission_operation_commit_meta
                 WHERE singleton = 1),
                (SELECT trusted_time_high_water_unix_ms
                 FROM admission_operation_commit_meta WHERE singleton = 1),
                (SELECT COUNT(*) FROM admission_operation_commits),
                (SELECT COALESCE(MAX(commit_sequence), 0)
                 FROM admission_operation_commits),
                (SELECT COALESCE(MAX(recorded_at_unix_ms), 0)
                 FROM admission_operation_commits)
            "#,
                [],
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
            .map_err(sqlite_error)?;
    let serving_leases_exist: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'chio_serving_leases'
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let invalid_lease = if serving_leases_exist {
        connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM admission_operation_commits AS committed
                    WHERE NOT EXISTS (
                        SELECT 1 FROM chio_serving_leases AS lease
                        WHERE lease.store_uuid = committed.store_uuid
                          AND lease.owner_epoch = committed.store_owner_epoch
                          AND lease.lease_id = committed.store_lease_id
                    )
                )
                "#,
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?
    } else {
        commit_count != 0
    };
    if head < 0
        || high_water < 0
        || u64::try_from(high_water).map_or(true, |value| value > MAX_TRUSTED_UNIX_MS)
        || high_water != max_recorded_at
        || (head == 0) != (high_water == 0)
        || commit_count != head
        || max_commit != head
        || invalid_lease
    {
        return Err(invariant(
            "admission operation commit log is not a dense fenced sequence",
        ));
    }
    let invalid_commit_order: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM (
                    SELECT mutation_kind, operation_version, recorded_at_unix_ms,
                           LAG(operation_version) OVER (
                               PARTITION BY operation_id ORDER BY commit_sequence
                           ) AS previous_version,
                           LAG(recorded_at_unix_ms) OVER (
                               PARTITION BY operation_id ORDER BY commit_sequence
                           ) AS previous_time
                    FROM admission_operation_commits
                )
                WHERE (previous_version IS NULL
                       AND (mutation_kind <> 'begin' OR operation_version <> 1))
                   OR (previous_version IS NOT NULL
                       AND (mutation_kind = 'begin'
                            OR (mutation_kind = 'recovery_claim'
                                AND operation_version <> previous_version)
                            OR (mutation_kind = 'participant_update'
                                AND operation_version <> previous_version)
                            OR (mutation_kind = 'compare_and_swap'
                                AND operation_version <> previous_version + 1)
                            OR (mutation_kind = 'channel_reservation_finalized'
                                AND operation_version <> previous_version + 1)
                            OR recorded_at_unix_ms < previous_time))
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if invalid_commit_order {
        return Err(invariant(
            "admission operation commits regress version or trusted time",
        ));
    }
    let global_time_regression: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM (
                    SELECT recorded_at_unix_ms,
                           LAG(recorded_at_unix_ms) OVER (
                               ORDER BY commit_sequence
                           ) AS previous_time
                    FROM admission_operation_commits
                )
                WHERE previous_time IS NOT NULL
                  AND recorded_at_unix_ms < previous_time
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if global_time_regression {
        return Err(invariant(
            "admission operation trusted time regresses across commits",
        ));
    }
    verify_admission_commit_chain(connection)?;

    let mut statement = connection
        .prepare(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
        verify_latest_commit(connection, &stored)?;
        verify_stored_terminal_projection(connection, &stored)?;
    }
    drop(rows);
    drop(statement);
    super::credit_exposure::verify_credit_exposure_account_invariants(connection)
}

pub(crate) fn verify_trusted_time(
    transaction: &Transaction<'_>,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    validate_trusted_now(trusted_now_unix_ms, "trusted_now_unix_ms")?;
    let high_water: i64 = transaction
        .query_row(
            r#"
            SELECT trusted_time_high_water_unix_ms
            FROM admission_operation_commit_meta WHERE singleton = 1
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")? < high_water {
        return Err(invariant("trusted admission operation time regressed"));
    }
    Ok(())
}

fn validate_trusted_now(
    value: u64,
    field: &'static str,
) -> Result<(), AdmissionOperationStoreError> {
    validate_trusted_time(value, field)?;
    let system_now = match chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
        Some(fixed) => fixed.saturating_mul(1_000),
        None => {
            let system_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| invariant("system clock precedes the Unix epoch"))?
                .as_millis();
            u64::try_from(system_now)
                .map_err(|_| invariant("system clock exceeds the persisted trusted-time range"))?
        }
    };
    if value.abs_diff(system_now) > MAX_TRUSTED_CLOCK_SKEW_MS {
        return Err(invariant(format!(
            "{field} exceeds the permitted system-clock skew"
        )));
    }
    Ok(())
}

pub(crate) fn validate_trusted_time(
    value: u64,
    field: &'static str,
) -> Result<(), AdmissionOperationStoreError> {
    if value == 0 || value > MAX_TRUSTED_UNIX_MS {
        return Err(invariant(format!(
            "{field} is outside the persisted trusted-time range"
        )));
    }
    Ok(())
}

pub(super) fn verify_latest_commit(
    connection: &Connection,
    stored: &StoredOperation,
) -> Result<(), AdmissionOperationStoreError> {
    let latest = connection
        .query_row(
            r#"
            SELECT operation_version, operation_digest, recovery_claim_digest,
                   recorded_at_unix_ms
            FROM admission_operation_commits
            WHERE operation_id = ?1
            ORDER BY commit_sequence DESC
            LIMIT 1
            "#,
            [stored.operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("admission operation has no commit record"))?;
    let encoded = encode_operation(&stored.operation)?;
    let claim_digest = stored
        .recovery_claim
        .as_ref()
        .map(recovery_claim_digest)
        .transpose()?;
    if stored_u64(latest.0, "commit operation_version")? != stored.operation.version()
        || latest.1 != sha256_hex(&encoded)
        || latest.2 != claim_digest
        || stored_u64(latest.3, "commit recorded_at_unix_ms")? != stored.updated_at_unix_ms
    {
        return Err(invariant(
            "latest admission operation commit does not match its projection",
        ));
    }
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn admission_operation_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'admission_operation*'
               OR tbl_name GLOB 'admission_operation*'
               OR name GLOB 'obligation_*'
               OR tbl_name GLOB 'obligation_*'
               OR name GLOB 'credit_exposure_*'
               OR tbl_name GLOB 'credit_exposure_*'
            ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

pub(super) fn recovery_claim_digest(
    claim: &UntrustedAdmissionRecoveryClaim,
) -> Result<String, AdmissionOperationStoreError> {
    #[derive(Serialize)]
    struct ClaimDigestBody<'a> {
        operation_id: &'a str,
        claimant_id: &'a str,
        coordinator_lease_id: &'a str,
        coordinator_lease_epoch: u64,
        claimed_version: u64,
        expires_at_unix_ms: u64,
        store_uuid: &'a str,
        store_lease_id: &'a str,
        store_owner_epoch: u64,
    }

    let body = ClaimDigestBody {
        operation_id: claim.operation_id().as_str(),
        claimant_id: claim.claimant_id().as_str(),
        coordinator_lease_id: claim.coordinator_lease_id().as_str(),
        coordinator_lease_epoch: claim.coordinator_lease_epoch(),
        claimed_version: claim.claimed_version(),
        expires_at_unix_ms: claim.expires_at_unix_ms(),
        store_uuid: &claim.store_fence().store_uuid,
        store_lease_id: &claim.store_fence().lease_id,
        store_owner_epoch: claim.store_fence().owner_epoch,
    };
    let canonical = canonical_json_bytes(&body)
        .map_err(|error| invariant(format!("recovery claim encoding failed: {error}")))?;
    Ok(sha256_hex(&canonical))
}

pub(crate) fn verify_active_owner(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    requested: Option<&StoreMutationFence>,
) -> Result<(), AdmissionOperationStoreError> {
    crate::serving_owner::verify_budget_fence(transaction, Some(owner)).map_err(|error| {
        if matches!(error, chio_kernel::BudgetStoreError::Fenced { .. }) {
            AdmissionOperationStoreError::Fenced
        } else {
            AdmissionOperationStoreError::Unavailable(error.to_string())
        }
    })?;
    if requested.is_some_and(|fence| fence != &owner.fence) {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let active_lease: i64 = transaction
        .query_row(
            r#"
            SELECT COUNT(*) FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
              AND end_head_index IS NULL
            "#,
            params![
                &owner.fence.store_uuid,
                sqlite_i64(owner.fence.owner_epoch, "store_owner_epoch")?,
                &owner.fence.lease_id,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if active_lease != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

pub(super) fn coordinator_lease_id_for_epoch(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    coordinator_lease_epoch: u64,
) -> Result<AdmissionIdentifier, AdmissionOperationStoreError> {
    let lease_id = transaction
        .query_row(
            r#"
            SELECT lease_id
            FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2
            "#,
            params![
                &owner.fence.store_uuid,
                sqlite_i64(coordinator_lease_epoch, "coordinator_lease_epoch")?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("operation coordinator lease is absent from lease history"))?;
    AdmissionIdentifier::try_new("coordinator_lease_id", lease_id).map_err(Into::into)
}
