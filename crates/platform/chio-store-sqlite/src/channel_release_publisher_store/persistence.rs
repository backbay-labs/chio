use super::*;

type SchemaCatalogEntry = (String, String, String, Option<String>);

#[cfg(test)]
pub(super) fn insert_publication(
    transaction: &Transaction<'_>,
    candidate: &ChannelReleasePublisherCandidate,
    binding_digest: &str,
    lifecycle_json: &[u8],
    escrow_json: &[u8],
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelReleasePublisherError> {
    transaction
        .execute(
            r#"
            INSERT INTO chio_channel_release_publications (
                channel_id, chain_id, escrow_contract, escrow_id,
                open_digest, close_digest, close_body_digest, effective_close_digest,
                final_state_digest, final_state_sequence,
                source_channel_state_version, source_escrow_reservation_version,
                source_lifecycle_fence, source_checkpoint_sequence, source_checkpoint_digest,
                source_channel_head_digest, source_escrow_head_digest,
                closing_checkpoint_sequence, closing_checkpoint_digest,
                closing_channel_head_digest, closing_escrow_head_digest,
                closing_lifecycle_json, closing_escrow_json,
                bound_token_base_units, release_token_base_units, refund_token_base_units,
                original_operator, original_operator_key_hash, beneficiary_address,
                asset_binding_digest, original_dispatch_digest,
                close_submission_cutoff_unix_ms, escrow_deadline_unix_ms,
                publisher_fence, authorized_at_unix_ms,
                frost_slot_id, frost_authorization_id, frost_action_digest,
                frost_envelope_digest, frost_scope_id, frost_resource_id,
                frost_resource_version, frost_resource_fence, frost_roster_digest,
                frost_key_epoch, frost_issued_at_unix_ms,
                authorization_digest, authorization_json, publication_binding_digest,
                prepared_call_digest, prepared_call_json,
                status, transaction_hash, failure_detail, record_version,
                store_uuid, store_lease_id, store_owner_epoch,
                created_at_unix_ms, updated_at_unix_ms
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30,
                ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40,
                ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48, ?49, ?50,
                ?51, 'dispatch_committed', NULL, NULL, 1,
                ?52, ?53, ?54, ?55, ?55
            )
            "#,
            params![
                &candidate.channel_id,
                &candidate.chain_id,
                &candidate.escrow_contract,
                &candidate.escrow_id,
                &candidate.open_digest,
                &candidate.close_digest,
                &candidate.close_body_digest,
                &candidate.effective_close_digest,
                &candidate.final_state_digest,
                sqlite_i64(candidate.final_state_sequence, "final_state_sequence")?,
                sqlite_i64(
                    candidate.source_channel_state_version,
                    "source_channel_state_version"
                )?,
                sqlite_i64(
                    candidate.source_escrow_reservation_version,
                    "source_escrow_reservation_version"
                )?,
                sqlite_i64(candidate.source_lifecycle_fence, "source_lifecycle_fence")?,
                sqlite_i64(
                    candidate.source_checkpoint_sequence,
                    "source_checkpoint_sequence"
                )?,
                &candidate.source_checkpoint_digest,
                &candidate.source_channel_head_digest,
                &candidate.source_escrow_head_digest,
                sqlite_i64(
                    candidate.closing_checkpoint_sequence,
                    "closing_checkpoint_sequence"
                )?,
                &candidate.closing_checkpoint_digest,
                &candidate.closing_channel_head_digest,
                &candidate.closing_escrow_head_digest,
                lifecycle_json,
                escrow_json,
                &candidate.bound_token_base_units,
                &candidate.release_token_base_units,
                &candidate.refund_token_base_units,
                &candidate.original_operator,
                &candidate.original_operator_key_hash,
                &candidate.beneficiary_address,
                &candidate.asset_binding_digest,
                &candidate.original_dispatch_digest,
                sqlite_i64(
                    candidate.close_submission_cutoff_unix_ms,
                    "close_submission_cutoff_unix_ms"
                )?,
                sqlite_i64(candidate.escrow_deadline_unix_ms, "escrow_deadline_unix_ms")?,
                sqlite_i64(candidate.publisher_fence, "publisher_fence")?,
                sqlite_i64(candidate.authorized_at_unix_ms, "authorized_at_unix_ms")?,
                &candidate.frost_slot_id,
                &candidate.frost_authorization_id,
                &candidate.frost_action_digest,
                &candidate.frost_envelope_digest,
                &candidate.frost_scope_id,
                &candidate.frost_resource_id,
                sqlite_i64(candidate.frost_resource_version, "frost_resource_version")?,
                sqlite_i64(candidate.frost_resource_fence, "frost_resource_fence")?,
                &candidate.frost_roster_digest,
                sqlite_i64(candidate.frost_key_epoch, "frost_key_epoch")?,
                sqlite_i64(candidate.frost_issued_at_unix_ms, "frost_issued_at_unix_ms")?,
                &candidate.authorization_digest,
                &candidate.authorization_json,
                binding_digest,
                &candidate.prepared_call_digest,
                &candidate.prepared_call_json,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn load_record(
    connection: &Connection,
    channel_id: &str,
) -> Result<Option<ChannelReleasePublicationRecordV1>, ChannelReleasePublisherError> {
    connection
        .query_row(
            r#"
            SELECT channel_id, publication_binding_digest, authorization_digest,
                   prepared_call_digest, publisher_fence, status,
                   transaction_hash, failure_detail, record_version,
                   created_at_unix_ms, updated_at_unix_ms
            FROM chio_channel_release_publications
            WHERE channel_id = ?1
            "#,
            [channel_id],
            decode_record,
        )
        .optional()
        .map_err(sqlite_error)
}

pub(super) fn record_matches_candidate(
    record: &ChannelReleasePublicationRecordV1,
    candidate: &ChannelReleasePublisherCandidate,
    binding_digest: &str,
) -> bool {
    record.publication_binding_digest == binding_digest
        && record.authorization_digest == candidate.authorization_digest
        && record.prepared_call_digest == candidate.prepared_call_digest
        && record.publisher_fence == candidate.publisher_fence
}

pub(super) fn decode_record(row: &Row<'_>) -> rusqlite::Result<ChannelReleasePublicationRecordV1> {
    let status = row.get::<_, String>(5)?;
    Ok(ChannelReleasePublicationRecordV1 {
        channel_id: row.get(0)?,
        publication_binding_digest: row.get(1)?,
        authorization_digest: row.get(2)?,
        prepared_call_digest: row.get(3)?,
        publisher_fence: stored_u64_sql(row.get(4)?, "publisher_fence")?,
        status: ChannelReleasePublicationStatusV1::parse(&status)
            .map_err(|error| conversion_error(error.to_string()))?,
        transaction_hash: row.get(6)?,
        failure_detail: row.get(7)?,
        record_version: stored_u64_sql(row.get(8)?, "record_version")?,
        created_at_unix_ms: stored_u64_sql(row.get(9)?, "created_at_unix_ms")?,
        updated_at_unix_ms: stored_u64_sql(row.get(10)?, "updated_at_unix_ms")?,
    })
}

pub(super) fn encode(
    value: &impl Serialize,
    label: &'static str,
) -> Result<Vec<u8>, ChannelReleasePublisherError> {
    let encoded = canonical_json_bytes(value)
        .map_err(|error| invalid(format!("{label} encoding failed: {error}")))?;
    if encoded.is_empty() || encoded.len() > MAX_PUBLISHER_ARTIFACT_BYTES {
        return Err(invalid(format!("{label} exceeds its size limit")));
    }
    Ok(encoded)
}

pub(super) fn canonicalize_json(bytes: &[u8]) -> Result<Vec<u8>, ChannelReleasePublisherError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("channel release authorization is invalid: {error}")))?;
    canonical_json_bytes(&value)
        .map_err(|error| invalid(format!("channel release authorization is invalid: {error}")))
}

pub(super) fn authorization_digest(canonical_authorization: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(
        CHANNEL_RELEASE_AUTHORIZATION_DIGEST_DOMAIN.len() + canonical_authorization.len(),
    );
    bytes.extend_from_slice(CHANNEL_RELEASE_AUTHORIZATION_DIGEST_DOMAIN);
    bytes.extend_from_slice(canonical_authorization);
    sha256_hex(&bytes)
}

pub(super) fn parse_base_units(value: &str) -> Result<u128, ChannelReleasePublisherError> {
    if value.is_empty()
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("channel release token amount is not canonical"));
    }
    value
        .parse::<u128>()
        .map_err(|_| invalid("channel release token amount overflows u128"))
}

pub(super) fn verify_trusted_time(
    transaction: &Transaction<'_>,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelReleasePublisherError> {
    crate::admission_operation_store::verify_trusted_time(transaction, trusted_now_unix_ms)
        .map_err(admission_error)?;
    let high_water = transaction
        .query_row(
            r#"
            SELECT trusted_time_high_water_unix_ms
            FROM chio_channel_release_publisher_meta
            WHERE singleton = 1
            "#,
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    if sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")? < high_water {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn advance_trusted_time(
    transaction: &Transaction<'_>,
    trusted_now_unix_ms: u64,
) -> Result<(), ChannelReleasePublisherError> {
    let current = transaction
        .query_row(
            r#"
            SELECT trusted_time_high_water_unix_ms
            FROM chio_channel_release_publisher_meta
            WHERE singleton = 1
            "#,
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    let trusted = sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?;
    if trusted < current {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    let changed = transaction
        .execute(
            r#"
            UPDATE chio_channel_release_publisher_meta
            SET trusted_time_high_water_unix_ms = ?1
            WHERE singleton = 1 AND trusted_time_high_water_unix_ms = ?2
            "#,
            params![trusted, current],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(ChannelReleasePublisherError::Fenced);
    }
    Ok(())
}

pub(super) fn is_evm_transaction_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn validate_digest(
    field: &'static str,
    value: &str,
) -> Result<(), ChannelReleasePublisherError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{field} is not a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

pub(super) fn sqlite_i64(
    value: u64,
    field: &'static str,
) -> Result<i64, ChannelReleasePublisherError> {
    i64::try_from(value).map_err(|_| invalid(format!("{field} exceeds SQLite integer range")))
}

pub(super) fn stored_u64_sql(value: i64, field: &'static str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| conversion_error(format!("{field} is negative")))
}

pub(super) fn conversion_error(detail: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Integer,
        std::io::Error::new(std::io::ErrorKind::InvalidData, detail).into(),
    )
}

pub(super) fn sqlite_error(error: rusqlite::Error) -> ChannelReleasePublisherError {
    if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
        ChannelReleasePublisherError::Conflict
    } else {
        ChannelReleasePublisherError::Unavailable(error.to_string())
    }
}

pub(super) fn invalid(detail: impl Into<String>) -> ChannelReleasePublisherError {
    ChannelReleasePublisherError::Invalid(detail.into())
}

pub(super) fn owner_error(error: SqliteServingOwnerError) -> ChannelReleasePublisherError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            ChannelReleasePublisherError::OutcomeUnknown(detail)
        }
        SqliteServingOwnerError::Invalid(detail) => invalid(detail),
        error => ChannelReleasePublisherError::Unavailable(error.to_string()),
    }
}

pub(super) fn admission_error(
    error: chio_kernel::admission_operation::AdmissionOperationStoreError,
) -> ChannelReleasePublisherError {
    use chio_kernel::admission_operation::AdmissionOperationStoreError;

    match error {
        AdmissionOperationStoreError::Fenced => ChannelReleasePublisherError::Fenced,
        AdmissionOperationStoreError::Invariant(_) => ChannelReleasePublisherError::Fenced,
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            ChannelReleasePublisherError::OutcomeUnknown(detail)
        }
        error => ChannelReleasePublisherError::Unavailable(error.to_string()),
    }
}

pub(crate) fn initialize_channel_release_publisher_schema(
    connection: &mut Connection,
) -> Result<(), SqliteServingOwnerError> {
    let on_disk = crate::check_schema_version(
        connection,
        CHANNEL_RELEASE_PUBLISHER_SCHEMA_KEY,
        CHANNEL_RELEASE_PUBLISHER_SUPPORTED_SCHEMA_VERSION,
        CHANNEL_RELEASE_PUBLISHER_SCHEMA_ANCHORS,
    )
    .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    if on_disk == CHANNEL_RELEASE_PUBLISHER_SUPPORTED_SCHEMA_VERSION {
        return verify_channel_release_publisher_invariants(connection);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(CHANNEL_RELEASE_PUBLISHER_SCHEMA)?;
    crate::stamp_schema_version(
        &transaction,
        CHANNEL_RELEASE_PUBLISHER_SCHEMA_KEY,
        CHANNEL_RELEASE_PUBLISHER_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    verify_channel_release_publisher_invariants(&transaction)?;
    transaction.commit().map_err(|error| {
        SqliteServingOwnerError::OutcomeUnknown(format!(
            "sqlite channel release publisher schema commit outcome is unknown: {error}"
        ))
    })
}

pub(crate) fn verify_channel_release_publisher_invariants(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(CHANNEL_RELEASE_PUBLISHER_SCHEMA)?;
    if publisher_schema_catalog(connection)? != publisher_schema_catalog(&expected)? {
        return Err(SqliteServingOwnerError::Invalid(
            "channel release publisher schema differs from the canonical definition".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn publisher_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        r#"
        SELECT type, name, tbl_name, sql
        FROM sqlite_schema
        WHERE name GLOB 'chio_channel_release_*'
           OR tbl_name GLOB 'chio_channel_release_*'
        ORDER BY type, name, tbl_name
        "#,
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into);
    rows
}
