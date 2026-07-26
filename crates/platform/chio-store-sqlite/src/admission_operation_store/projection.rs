use super::obligation::{insert_obligation_projection, verify_obligation_projection};
use super::*;

pub(super) fn full_projection_capabilities() -> AdmissionProjectionCapabilities {
    AdmissionProjectionCapabilities {
        operation_terminal: true,
        incident_terminal: true,
        tool_outcome: true,
        payment_terminal: true,
        authorization_consumption: true,
        outcome_eligibility: true,
        observation_attempt_zero: true,
        obligation: true,
        channel_terminal: true,
        credit_exposure_terminal: true,
        economic_mutation_terminal: true,
    }
}

pub(super) fn validate_canonical_projection_size(
    projection: &CanonicalAdmissionTerminalProjection,
) -> Result<(), AdmissionOperationStoreError> {
    if projection.projection_bytes().is_empty()
        || projection.projection_bytes().len() > MAX_TERMINAL_PROJECTION_BYTES
        || projection.manifest_bytes().is_empty()
        || projection.manifest_bytes().len() > MAX_TERMINAL_MANIFEST_BYTES
        || projection.records().is_empty()
        || projection.records().len() > MAX_TERMINAL_RECORDS
        || projection.records().iter().any(|record| {
            record.canonical_bytes().is_empty()
                || record.canonical_bytes().len() > MAX_TERMINAL_RECORD_BYTES
        })
    {
        return Err(invariant("terminal projection exceeds its storage bounds"));
    }
    Ok(())
}

pub(super) fn ensure_projection_absent(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<(), AdmissionOperationStoreError> {
    let present: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM admission_operation_terminal_projections
                WHERE operation_id = ?1
                UNION ALL
                SELECT 1 FROM admission_operation_terminal_records
                WHERE operation_id = ?1
                UNION ALL
                SELECT 1 FROM admission_operation_authorization_consumptions
                WHERE operation_id = ?1
                UNION ALL
                SELECT 1 FROM admission_operation_observer_attempts
                WHERE operation_id = ?1
                UNION ALL
                SELECT 1 FROM obligation_atoms
                WHERE operation_id = ?1
                UNION ALL
                SELECT 1 FROM obligation_disposition_records
                WHERE operation_id = ?1
            )
            "#,
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if present {
        return Err(invariant(
            "nonterminal admission operation has a partial terminal projection",
        ));
    }
    Ok(())
}

pub(super) fn insert_terminal_projection(
    transaction: &Transaction<'_>,
    projection: &AdmissionTerminalProjection,
    canonical: &CanonicalAdmissionTerminalProjection,
    terminal_operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let context = projection.context();
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO admission_operation_terminal_projections (
                operation_id, source_operation_version, terminal_operation_version,
                terminal_state, projection_body_digest, projection_digest,
                projection_json, manifest_json, record_count, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                context.operation_id.as_str(),
                sqlite_i64(
                    context.expected_operation_version,
                    "source_operation_version"
                )?,
                sqlite_i64(terminal_operation.version(), "terminal_operation_version")?,
                state_name(terminal_operation.state()),
                canonical.manifest().projection_body_digest().as_str(),
                canonical.projection_digest().as_str(),
                canonical.projection_bytes(),
                canonical.manifest_bytes(),
                i64::try_from(canonical.records().len())
                    .map_err(|_| invariant("terminal record count overflow"))?,
                sqlite_i64(context.trusted_time_unix_ms, "committed_at_unix_ms")?,
                &context.store_fence.store_uuid,
                &context.store_fence.lease_id,
                sqlite_i64(context.store_fence.owner_epoch, "store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "terminal projection did not insert exactly one row",
        ));
    }

    for record in canonical.records() {
        let commitment = record.commitment();
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO admission_operation_terminal_records (
                    operation_id, record_kind, record_id, record_digest, record_json
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    context.operation_id.as_str(),
                    commitment.kind().as_str(),
                    commitment.record_id().as_str(),
                    commitment.record_digest().as_str(),
                    record.canonical_bytes(),
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "terminal projection record did not insert exactly one row",
            ));
        }
    }

    let obligation_record = canonical
        .records()
        .iter()
        .find(|record| record.commitment().kind() == AdmissionProjectionRecordKind::Obligation)
        .map(CanonicalAdmissionProjectionRecord::canonical_bytes);
    let channel_record = canonical
        .records()
        .iter()
        .find(|record| record.commitment().kind() == AdmissionProjectionRecordKind::ChannelTerminal)
        .map(CanonicalAdmissionProjectionRecord::canonical_bytes);
    insert_obligation_projection(
        transaction,
        &context.operation_id,
        obligation_record,
        channel_record,
        context.trusted_time_unix_ms,
        context.trusted_time_unix_ms,
        &context.store_fence,
    )?;

    if let AdmissionTerminalProjection::Completed(completed) = projection {
        if let Some(authorization) = &completed.authorization {
            let record = require_canonical_record(
                canonical,
                AdmissionProjectionRecordKind::AuthorizationConsumption,
            )?;
            let consumption = authorization.consumption();
            let inserted = transaction
                .execute(
                    r#"
                    INSERT INTO admission_operation_authorization_consumptions (
                        operation_id, authorization_receipt_id, consumer_receipt_id,
                        request_id, session_id, tool_call_id, tenant_id,
                        parameter_hash, consumed_at_unix_ms, record_digest, record_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                    "#,
                    params![
                        context.operation_id.as_str(),
                        &consumption.authorization_receipt_id,
                        &consumption.consumer_receipt_id,
                        &consumption.request_id,
                        &consumption.session_id,
                        &consumption.tool_call_id,
                        consumption.tenant_id.as_deref(),
                        &consumption.parameter_hash,
                        sqlite_i64(consumption.consumed_at_unix_ms, "consumed_at_unix_ms")?,
                        record.commitment().record_digest().as_str(),
                        record.canonical_bytes(),
                    ],
                )
                .map_err(sqlite_error)?;
            if inserted != 1 {
                return Err(invariant(
                    "authorization consumption did not insert exactly one row",
                ));
            }
        }
        if let Some(observer) = &completed.observer_work {
            let record = require_canonical_record(
                canonical,
                AdmissionProjectionRecordKind::ObservationAttemptZero,
            )?;
            let inserted = transaction
                .execute(
                    r#"
                    INSERT INTO admission_operation_observer_attempts (
                        operation_id, receipt_id, work_state, attempts,
                        next_visible_at_unix_ms, row_version, last_error,
                        record_digest, record_json, created_at_unix_ms,
                        updated_at_unix_ms, store_uuid, store_lease_id,
                        store_owner_epoch
                    ) VALUES (?1, ?2, 'pending', 0, ?3, 0, NULL, ?4, ?5,
                              ?6, ?6, ?7, ?8, ?9)
                    "#,
                    params![
                        context.operation_id.as_str(),
                        &completed.receipt.receipt().id,
                        sqlite_i64(
                            observer.pending().next_visible_at_ms,
                            "observer_next_visible_at_unix_ms"
                        )?,
                        record.commitment().record_digest().as_str(),
                        record.canonical_bytes(),
                        sqlite_i64(context.trusted_time_unix_ms, "observer_created_at_unix_ms")?,
                        &context.store_fence.store_uuid,
                        &context.store_fence.lease_id,
                        sqlite_i64(context.store_fence.owner_epoch, "store_owner_epoch")?,
                    ],
                )
                .map_err(sqlite_error)?;
            if inserted != 1 {
                return Err(invariant(
                    "observer attempt zero did not insert exactly one row",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn insert_verified_terminal_projection(
    transaction: &Transaction<'_>,
    projection: &VerifiedAdmissionTerminalProjectionV1,
    apply_time_unix_ms: u64,
    apply_fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let context = projection.context();
    let terminal_operation = projection.terminal_operation();
    let manifest = AdmissionProjectionManifestV1::from_canonical_bytes(projection.manifest_json())?;
    let projection_digest = manifest.projection_digest()?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO admission_operation_terminal_projections (
                operation_id, source_operation_version, terminal_operation_version,
                terminal_state, projection_body_digest, projection_digest,
                projection_json, manifest_json, record_count, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                context.operation_id.as_str(),
                sqlite_i64(
                    context.expected_operation_version,
                    "source_operation_version"
                )?,
                sqlite_i64(terminal_operation.version(), "terminal_operation_version")?,
                state_name(terminal_operation.state()),
                manifest.projection_body_digest().as_str(),
                projection_digest.as_str(),
                projection.projection_json(),
                projection.manifest_json(),
                i64::try_from(projection.records().len())
                    .map_err(|_| invariant("terminal record count overflow"))?,
                sqlite_i64(apply_time_unix_ms, "committed_at_unix_ms")?,
                &apply_fence.store_uuid,
                &apply_fence.lease_id,
                sqlite_i64(apply_fence.owner_epoch, "store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "terminal projection did not insert exactly one row",
        ));
    }

    for record in projection.records() {
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO admission_operation_terminal_records (
                    operation_id, record_kind, record_id, record_digest, record_json
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    context.operation_id.as_str(),
                    record.kind().as_str(),
                    record.record_id().as_str(),
                    record.record_digest().as_str(),
                    record.canonical_json(),
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "terminal projection record did not insert exactly one row",
            ));
        }
    }

    let obligation_record = projection
        .records()
        .iter()
        .find(|record| record.kind() == AdmissionProjectionRecordKind::Obligation)
        .map(VerifiedAdmissionTerminalProjectionRecordV1::canonical_json);
    let channel_record = projection
        .records()
        .iter()
        .find(|record| record.kind() == AdmissionProjectionRecordKind::ChannelTerminal)
        .map(VerifiedAdmissionTerminalProjectionRecordV1::canonical_json);
    insert_obligation_projection(
        transaction,
        &context.operation_id,
        obligation_record,
        channel_record,
        context.trusted_time_unix_ms,
        apply_time_unix_ms,
        apply_fence,
    )?;

    if let Some(consumption) = projection.authorization_consumption() {
        let record = require_verified_record(
            projection,
            AdmissionProjectionRecordKind::AuthorizationConsumption,
        )?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO admission_operation_authorization_consumptions (
                    operation_id, authorization_receipt_id, consumer_receipt_id,
                    request_id, session_id, tool_call_id, tenant_id,
                    parameter_hash, consumed_at_unix_ms, record_digest, record_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
                params![
                    context.operation_id.as_str(),
                    &consumption.authorization_receipt_id,
                    &consumption.consumer_receipt_id,
                    &consumption.request_id,
                    &consumption.session_id,
                    &consumption.tool_call_id,
                    consumption.tenant_id.as_deref(),
                    &consumption.parameter_hash,
                    sqlite_i64(consumption.consumed_at_unix_ms, "consumed_at_unix_ms")?,
                    record.record_digest().as_str(),
                    record.canonical_json(),
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "authorization consumption did not insert exactly one row",
            ));
        }
    }
    if let Some(observer) = projection.observer() {
        let record = require_verified_record(
            projection,
            AdmissionProjectionRecordKind::ObservationAttemptZero,
        )?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO admission_operation_observer_attempts (
                    operation_id, receipt_id, work_state, attempts,
                    next_visible_at_unix_ms, row_version, last_error,
                    record_digest, record_json, created_at_unix_ms,
                    updated_at_unix_ms, store_uuid, store_lease_id,
                    store_owner_epoch
                ) VALUES (?1, ?2, 'pending', 0, ?3, 0, NULL, ?4, ?5,
                          ?6, ?6, ?7, ?8, ?9)
                "#,
                params![
                    context.operation_id.as_str(),
                    observer.receipt_id.as_str(),
                    sqlite_i64(
                        observer.pending.next_visible_at_ms,
                        "observer_next_visible_at_unix_ms"
                    )?,
                    record.record_digest().as_str(),
                    record.canonical_json(),
                    sqlite_i64(apply_time_unix_ms, "observer_created_at_unix_ms")?,
                    &apply_fence.store_uuid,
                    &apply_fence.lease_id,
                    sqlite_i64(apply_fence.owner_epoch, "store_owner_epoch")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "observer attempt zero did not insert exactly one row",
            ));
        }
    }
    Ok(())
}

fn require_verified_record(
    projection: &VerifiedAdmissionTerminalProjectionV1,
    kind: AdmissionProjectionRecordKind,
) -> Result<&VerifiedAdmissionTerminalProjectionRecordV1, AdmissionOperationStoreError> {
    let mut matches = projection
        .records()
        .iter()
        .filter(|record| record.kind() == kind);
    let record = matches
        .next()
        .ok_or_else(|| invariant(format!("terminal projection lacks {}", kind.as_str())))?;
    if matches.next().is_some() {
        return Err(invariant(format!(
            "terminal projection repeats {}",
            kind.as_str()
        )));
    }
    Ok(record)
}

fn require_canonical_record(
    projection: &CanonicalAdmissionTerminalProjection,
    kind: AdmissionProjectionRecordKind,
) -> Result<&CanonicalAdmissionProjectionRecord, AdmissionOperationStoreError> {
    let mut matches = projection
        .records()
        .iter()
        .filter(|record| record.commitment().kind() == kind);
    let record = matches
        .next()
        .ok_or_else(|| invariant(format!("terminal projection lacks {}", kind.as_str())))?;
    if matches.next().is_some() {
        return Err(invariant(format!(
            "terminal projection repeats {}",
            kind.as_str()
        )));
    }
    Ok(record)
}

pub(super) fn terminal_from_operation(
    operation: &AdmissionOperationV1,
) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
    if !operation.state().is_terminal() {
        return Err(invariant("admission operation is not terminal"));
    }
    let replay = operation
        .terminal_replay()
        .cloned()
        .ok_or_else(|| invariant("terminal admission operation lacks replay evidence"))?;
    Ok(AdmissionTerminal {
        operation_id: operation.binding().operation_id().clone(),
        state: operation.state(),
        replay,
    })
}

struct StoredTerminalProjection {
    source_operation_version: i64,
    terminal_operation_version: i64,
    terminal_state: String,
    projection_body_digest: String,
    projection_digest: String,
    projection_json: Vec<u8>,
    manifest_json: Vec<u8>,
    record_count: i64,
    committed_at_unix_ms: i64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: i64,
}

#[derive(Deserialize)]
struct StoredTerminalProjectionBody {
    context: AdmissionProjectionContext,
}

fn load_terminal_projection_tx(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
) -> Result<Option<StoredTerminalProjection>, AdmissionOperationStoreError> {
    connection
        .query_row(
            r#"
            SELECT source_operation_version, terminal_operation_version,
                   terminal_state, projection_body_digest, projection_digest,
                   projection_json, manifest_json, record_count,
                   committed_at_unix_ms, store_uuid, store_lease_id,
                   store_owner_epoch
            FROM admission_operation_terminal_projections
            WHERE operation_id = ?1
            "#,
            [operation_id.as_str()],
            |row| {
                Ok(StoredTerminalProjection {
                    source_operation_version: row.get(0)?,
                    terminal_operation_version: row.get(1)?,
                    terminal_state: row.get(2)?,
                    projection_body_digest: row.get(3)?,
                    projection_digest: row.get(4)?,
                    projection_json: row.get(5)?,
                    manifest_json: row.get(6)?,
                    record_count: row.get(7)?,
                    committed_at_unix_ms: row.get(8)?,
                    store_uuid: row.get(9)?,
                    store_lease_id: row.get(10)?,
                    store_owner_epoch: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)
}

pub(super) fn verify_exact_terminal_replay(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    projection: &AdmissionTerminalProjection,
    canonical: &CanonicalAdmissionTerminalProjection,
) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
    let context = projection.context();
    if context.operation_id != *operation.binding().operation_id()
        || context.request_id != operation.replay_key().request_id
        || context
            .expected_operation_version
            .checked_add(1)
            .is_none_or(|version| version != operation.version())
        || projected_terminal_state(projection) != operation.state()
        || operation
            .terminal_replay()
            .is_none_or(|replay| replay.projection_digest() != canonical.projection_digest())
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }

    let stored = load_terminal_projection_tx(transaction, operation.binding().operation_id())?
        .ok_or_else(|| invariant("terminal admission operation lacks its projection"))?;
    if stored.source_operation_version
        != sqlite_i64(
            context.expected_operation_version,
            "source_operation_version",
        )?
        || stored.terminal_operation_version
            != sqlite_i64(operation.version(), "terminal_operation_version")?
        || stored.terminal_state != state_name(operation.state())
        || stored.projection_body_digest != canonical.manifest().projection_body_digest().as_str()
        || stored.projection_digest != canonical.projection_digest().as_str()
        || stored.projection_json != canonical.projection_bytes()
        || stored.manifest_json != canonical.manifest_bytes()
        || stored.record_count
            != i64::try_from(canonical.records().len())
                .map_err(|_| invariant("terminal record count overflow"))?
        || stored.committed_at_unix_ms
            != sqlite_i64(context.trusted_time_unix_ms, "committed_at_unix_ms")?
        || stored.store_uuid != context.store_fence.store_uuid
        || stored.store_lease_id != context.store_fence.lease_id
        || stored.store_owner_epoch
            != sqlite_i64(context.store_fence.owner_epoch, "store_owner_epoch")?
    {
        return Err(invariant(
            "terminal admission operation projection differs from its replay",
        ));
    }
    verify_exact_terminal_records(transaction, &context.operation_id, canonical)?;
    verify_exact_typed_projection_rows(transaction, projection, canonical)?;
    terminal_from_operation(operation)
}

pub(super) fn verify_exact_signed_terminal_replay(
    transaction: &Transaction<'_>,
    stored_operation: &StoredOperation,
    projection: &VerifiedAdmissionTerminalProjectionV1,
) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
    let recovery_claim = stored_operation
        .recovery_claim
        .as_ref()
        .ok_or(AdmissionOperationStoreError::Fenced)?;
    let expected_claimant = format!("kernel:{}", projection.signer_key().to_hex());
    if recovery_claim.claimant_id().as_str() != expected_claimant
        || recovery_claim.coordinator_lease_id() != &projection.context().coordinator_lease_id
        || recovery_claim.store_fence() != &projection.context().store_fence
        || stored_operation.operation != *projection.terminal_operation()
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    verify_stored_terminal_projection(transaction, stored_operation)?;
    let stored = load_terminal_projection_tx(
        transaction,
        stored_operation.operation.binding().operation_id(),
    )?
    .ok_or_else(|| invariant("terminal admission operation lacks its projection"))?;
    let manifest = AdmissionProjectionManifestV1::from_canonical_bytes(projection.manifest_json())?;
    if stored.source_operation_version
        != sqlite_i64(
            projection.context().expected_operation_version,
            "source_operation_version",
        )?
        || stored.terminal_operation_version
            != sqlite_i64(
                projection.terminal_operation().version(),
                "terminal_operation_version",
            )?
        || stored.projection_json != projection.projection_json()
        || stored.manifest_json != projection.manifest_json()
        || stored.projection_digest != manifest.projection_digest()?.as_str()
        || stored.record_count
            != i64::try_from(projection.records().len())
                .map_err(|_| invariant("terminal record count overflow"))?
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    let stored_records = load_terminal_records(
        transaction,
        stored_operation.operation.binding().operation_id(),
    )?;
    if stored_records.len() != projection.records().len()
        || stored_records
            .iter()
            .zip(projection.records())
            .any(|(stored, expected)| {
                stored.kind != expected.kind().as_str()
                    || stored.record_id != expected.record_id().as_str()
                    || stored.record_digest != expected.record_digest().as_str()
                    || stored.record_json != expected.canonical_json()
            })
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    terminal_from_operation(&stored_operation.operation)
}

pub(super) fn projected_terminal_state(
    projection: &AdmissionTerminalProjection,
) -> AdmissionOperationState {
    match projection {
        AdmissionTerminalProjection::Completed(_) => AdmissionOperationState::Completed,
        AdmissionTerminalProjection::CompensatedBeforeDispatch { .. } => {
            AdmissionOperationState::CompensatedBeforeDispatch
        }
        AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit { .. } => {
            AdmissionOperationState::NotAcceptedAfterDispatchCommit
        }
        AdmissionTerminalProjection::OutcomeUnknownAfterDispatch { .. } => {
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        }
        AdmissionTerminalProjection::EconomicMutationApplied { .. } => {
            AdmissionOperationState::EconomicMutationApplied
        }
        AdmissionTerminalProjection::EconomicMutationNotApplied { .. } => {
            AdmissionOperationState::EconomicMutationNotApplied
        }
    }
}

fn verify_exact_terminal_records(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
    canonical: &CanonicalAdmissionTerminalProjection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT record_kind, record_id, record_digest, record_json
            FROM admission_operation_terminal_records
            WHERE operation_id = ?1
            ORDER BY record_kind, record_id
            "#,
        )
        .map_err(sqlite_error)?;
    let stored = statement
        .query_map([operation_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if stored.len() != canonical.records().len()
        || stored
            .iter()
            .zip(canonical.records())
            .any(|(stored, expected)| {
                let commitment = expected.commitment();
                stored.0 != commitment.kind().as_str()
                    || stored.1 != commitment.record_id().as_str()
                    || stored.2 != commitment.record_digest().as_str()
                    || stored.3 != expected.canonical_bytes()
            })
    {
        return Err(invariant(
            "terminal projection records differ from their manifest",
        ));
    }
    Ok(())
}

fn verify_exact_typed_projection_rows(
    connection: &Connection,
    projection: &AdmissionTerminalProjection,
    canonical: &CanonicalAdmissionTerminalProjection,
) -> Result<(), AdmissionOperationStoreError> {
    let context = projection.context();
    let authorization = connection
        .query_row(
            r#"
            SELECT authorization_receipt_id, consumer_receipt_id, request_id,
                   session_id, tool_call_id, tenant_id, parameter_hash,
                   consumed_at_unix_ms, record_digest, record_json
            FROM admission_operation_authorization_consumptions
            WHERE operation_id = ?1
            "#,
            [context.operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let observer = connection
        .query_row(
            r#"
            SELECT receipt_id, work_state, attempts, next_visible_at_unix_ms,
                   row_version, last_error, record_digest, record_json,
                   created_at_unix_ms, updated_at_unix_ms, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM admission_operation_observer_attempts
            WHERE operation_id = ?1
            "#,
            [context.operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;

    let AdmissionTerminalProjection::Completed(completed) = projection else {
        if authorization.is_some() || observer.is_some() {
            return Err(invariant(
                "non-completed projection has completed-only sidecars",
            ));
        }
        return Ok(());
    };
    match (&completed.authorization, authorization) {
        (None, None) => {}
        (Some(expected), Some(stored)) => {
            let record = require_canonical_record(
                canonical,
                AdmissionProjectionRecordKind::AuthorizationConsumption,
            )?;
            let expected = expected.consumption();
            if stored.0 != expected.authorization_receipt_id
                || stored.1 != expected.consumer_receipt_id
                || stored.2 != expected.request_id
                || stored.3 != expected.session_id
                || stored.4 != expected.tool_call_id
                || stored.5 != expected.tenant_id
                || stored.6 != expected.parameter_hash
                || stored_u64(stored.7, "consumed_at_unix_ms")? != expected.consumed_at_unix_ms
                || stored.8 != record.commitment().record_digest().as_str()
                || stored.9 != record.canonical_bytes()
            {
                return Err(invariant(
                    "authorization consumption differs from terminal projection",
                ));
            }
        }
        _ => {
            return Err(invariant(
                "authorization consumption presence differs from terminal projection",
            ));
        }
    }
    match (&completed.observer_work, observer) {
        (None, None) => {}
        (Some(_), Some(stored)) => {
            let record = require_canonical_record(
                canonical,
                AdmissionProjectionRecordKind::ObservationAttemptZero,
            )?;
            let committed_at = sqlite_i64(context.trusted_time_unix_ms, "committed_at_unix_ms")?;
            if stored.0 != completed.receipt.receipt().id
                || stored.6 != record.commitment().record_digest().as_str()
                || stored.7 != record.canonical_bytes()
                || stored.8 != committed_at
                || stored.10 != context.store_fence.store_uuid
            {
                return Err(invariant(
                    "observer attempt zero differs from terminal projection",
                ));
            }
        }
        _ => {
            return Err(invariant(
                "observer attempt presence differs from terminal projection",
            ));
        }
    }
    let obligation_record = canonical
        .records()
        .iter()
        .find(|record| record.commitment().kind() == AdmissionProjectionRecordKind::Obligation)
        .map(CanonicalAdmissionProjectionRecord::canonical_bytes);
    let channel_record = canonical
        .records()
        .iter()
        .find(|record| record.commitment().kind() == AdmissionProjectionRecordKind::ChannelTerminal)
        .map(CanonicalAdmissionProjectionRecord::canonical_bytes);
    verify_obligation_projection(
        connection,
        &context.operation_id,
        obligation_record,
        channel_record,
        context.trusted_time_unix_ms,
        context.trusted_time_unix_ms,
        &context.store_fence,
    )
}

struct StoredProjectionRecord {
    kind: String,
    record_id: String,
    record_digest: String,
    record_json: Vec<u8>,
}

fn load_terminal_records(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
) -> Result<Vec<StoredProjectionRecord>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT record_kind, record_id, record_digest, record_json
            FROM admission_operation_terminal_records
            WHERE operation_id = ?1
            ORDER BY record_kind, record_id
            "#,
        )
        .map_err(sqlite_error)?;
    let records = statement
        .query_map([operation_id.as_str()], |row| {
            Ok(StoredProjectionRecord {
                kind: row.get(0)?,
                record_id: row.get(1)?,
                record_digest: row.get(2)?,
                record_json: row.get(3)?,
            })
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(records)
}

pub(super) fn verify_stored_terminal_projection(
    connection: &Connection,
    stored_operation: &StoredOperation,
) -> Result<(), AdmissionOperationStoreError> {
    let operation = &stored_operation.operation;
    let projection = load_terminal_projection_tx(connection, operation.binding().operation_id())?;
    if !operation.state().is_terminal() {
        if projection.is_some() || projection_sidecar_count(connection, operation)? != 0 {
            return Err(invariant(
                "nonterminal admission operation has terminal projection rows",
            ));
        }
        return super::credit_exposure::verify_credit_exposure_operation_state(
            connection, operation, None,
        );
    }
    let projection = projection
        .ok_or_else(|| invariant("terminal admission operation lacks its projection row"))?;
    if projection.projection_json.is_empty()
        || projection.projection_json.len() > MAX_TERMINAL_PROJECTION_BYTES
        || projection.manifest_json.is_empty()
        || projection.manifest_json.len() > MAX_TERMINAL_MANIFEST_BYTES
    {
        return Err(invariant("stored terminal projection exceeds its bounds"));
    }
    let manifest = AdmissionProjectionManifestV1::from_canonical_bytes(&projection.manifest_json)?;
    manifest.verify_projection_body(&projection.projection_json)?;
    let projection_digest = manifest.projection_digest()?;
    let replay_digest = operation
        .terminal_replay()
        .ok_or_else(|| invariant("terminal operation lacks replay evidence"))?
        .projection_digest();
    let source_version = operation
        .version()
        .checked_sub(1)
        .ok_or_else(|| invariant("terminal operation version underflow"))?;
    let exact_lease: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*) FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
            "#,
            params![
                &projection.store_uuid,
                projection.store_owner_epoch,
                &projection.store_lease_id,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if stored_u64(
        projection.source_operation_version,
        "source_operation_version",
    )? != source_version
        || stored_u64(
            projection.terminal_operation_version,
            "terminal_operation_version",
        )? != operation.version()
        || projection.terminal_state != state_name(operation.state())
        || projection.projection_body_digest != manifest.projection_body_digest().as_str()
        || projection.projection_digest != projection_digest.as_str()
        || replay_digest != &projection_digest
        || stored_u64(projection.record_count, "terminal_record_count")?
            != u64::try_from(manifest.records().len())
                .map_err(|_| invariant("terminal record count overflow"))?
        || stored_u64(
            projection.committed_at_unix_ms,
            "projection_committed_at_unix_ms",
        )? != stored_operation.updated_at_unix_ms
        || exact_lease != 1
    {
        return Err(invariant(
            "terminal projection does not match its admission operation",
        ));
    }

    let records = load_terminal_records(connection, operation.binding().operation_id())?;
    if records.len() != manifest.records().len() {
        return Err(invariant(
            "terminal projection record count differs from its manifest",
        ));
    }
    for (record, commitment) in records.iter().zip(manifest.records()) {
        let value: serde_json::Value = serde_json::from_slice(&record.record_json)
            .map_err(|error| invariant(format!("terminal record is invalid: {error}")))?;
        let canonical = canonical_json_bytes(&value)
            .map_err(|error| invariant(format!("terminal record encoding failed: {error}")))?;
        if record.record_json.is_empty()
            || record.record_json.len() > MAX_TERMINAL_RECORD_BYTES
            || canonical != record.record_json
            || sha256_hex(&record.record_json) != record.record_digest
            || record.kind != commitment.kind().as_str()
            || record.record_id != commitment.record_id().as_str()
            || record.record_digest != commitment.record_digest().as_str()
        {
            return Err(invariant(
                "terminal projection record differs from its commitment",
            ));
        }
    }
    verify_stored_authorization_projection(connection, operation, &records)?;
    verify_stored_observer_projection(connection, operation, &projection, &records)?;
    let obligation_record = projection_record(&records, AdmissionProjectionRecordKind::Obligation)?
        .map(|record| record.record_json.as_slice());
    let channel_record =
        projection_record(&records, AdmissionProjectionRecordKind::ChannelTerminal)?
            .map(|record| record.record_json.as_slice());
    let projection_body: StoredTerminalProjectionBody =
        serde_json::from_slice(&projection.projection_json)
            .map_err(|error| invariant(format!("terminal projection body is invalid: {error}")))?;
    projection_body.context.validate()?;
    if projection_body.context.operation_id != *operation.binding().operation_id() {
        return Err(invariant(
            "terminal projection context does not match its operation",
        ));
    }
    verify_obligation_projection(
        connection,
        operation.binding().operation_id(),
        obligation_record,
        channel_record,
        projection_body.context.trusted_time_unix_ms,
        stored_u64(
            projection.committed_at_unix_ms,
            "projection_committed_at_unix_ms",
        )?,
        &StoreMutationFence {
            store_uuid: projection.store_uuid.clone(),
            lease_id: projection.store_lease_id.clone(),
            owner_epoch: stored_u64(projection.store_owner_epoch, "projection_store_owner_epoch")?,
        },
    )?;
    super::credit_exposure::verify_credit_exposure_operation_state(
        connection,
        operation,
        Some(&projection_digest),
    )
}

fn projection_sidecar_count(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<i64, AdmissionOperationStoreError> {
    connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM admission_operation_terminal_records
                 WHERE operation_id = ?1)
              + (SELECT COUNT(*) FROM admission_operation_authorization_consumptions
                 WHERE operation_id = ?1)
              + (SELECT COUNT(*) FROM admission_operation_observer_attempts
                 WHERE operation_id = ?1)
              + (SELECT COUNT(*) FROM obligation_atoms
                 WHERE operation_id = ?1)
              + (SELECT COUNT(*) FROM obligation_disposition_records
                 WHERE operation_id = ?1)
            "#,
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn projection_record(
    records: &[StoredProjectionRecord],
    kind: AdmissionProjectionRecordKind,
) -> Result<Option<&StoredProjectionRecord>, AdmissionOperationStoreError> {
    let mut matches = records.iter().filter(|record| record.kind == kind.as_str());
    let first = matches.next();
    if matches.next().is_some() {
        return Err(invariant(format!(
            "terminal projection repeats {}",
            kind.as_str()
        )));
    }
    Ok(first)
}

fn verify_stored_authorization_projection(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    records: &[StoredProjectionRecord],
) -> Result<(), AdmissionOperationStoreError> {
    let record = projection_record(
        records,
        AdmissionProjectionRecordKind::AuthorizationConsumption,
    )?;
    let stored = connection
        .query_row(
            r#"
            SELECT authorization_receipt_id, consumer_receipt_id, request_id,
                   session_id, tool_call_id, tenant_id, parameter_hash,
                   consumed_at_unix_ms, record_digest, record_json
            FROM admission_operation_authorization_consumptions
            WHERE operation_id = ?1
            "#,
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    match (record, stored) {
        (None, None) => Ok(()),
        (Some(record), Some(stored)) => {
            let consumption: AuthorizationReceiptConsumption =
                serde_json::from_slice(&record.record_json).map_err(|error| {
                    invariant(format!("authorization consumption is invalid: {error}"))
                })?;
            if stored.0 != consumption.authorization_receipt_id
                || stored.0 != record.record_id
                || stored.1 != consumption.consumer_receipt_id
                || stored.2 != consumption.request_id
                || stored.2 != operation.replay_key().request_id.as_str()
                || stored.3 != consumption.session_id
                || stored.4 != consumption.tool_call_id
                || stored.5 != consumption.tenant_id
                || stored.6 != consumption.parameter_hash
                || stored_u64(stored.7, "consumed_at_unix_ms")? != consumption.consumed_at_unix_ms
                || stored.8 != record.record_digest
                || stored.9 != record.record_json
            {
                return Err(invariant(
                    "authorization consumption projection is inconsistent",
                ));
            }
            Ok(())
        }
        _ => Err(invariant("authorization consumption projection is partial")),
    }
}

fn verify_stored_observer_projection(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    projection: &StoredTerminalProjection,
    records: &[StoredProjectionRecord],
) -> Result<(), AdmissionOperationStoreError> {
    let record = projection_record(
        records,
        AdmissionProjectionRecordKind::ObservationAttemptZero,
    )?;
    let stored = connection
        .query_row(
            r#"
            SELECT receipt_id, work_state, attempts, next_visible_at_unix_ms,
                   row_version, last_error, record_digest, record_json,
                   created_at_unix_ms, updated_at_unix_ms, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM admission_operation_observer_attempts
            WHERE operation_id = ?1
            "#,
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    match (record, stored) {
        (None, None) => Ok(()),
        (Some(record), Some(stored)) => {
            let pending: PendingSettlementObservation = serde_json::from_slice(&record.record_json)
                .map_err(|error| invariant(format!("observer attempt zero is invalid: {error}")))?;
            let lease_exists: i64 = connection
                .query_row(
                    r#"
                    SELECT COUNT(*) FROM chio_serving_leases
                    WHERE store_uuid = ?1 AND lease_id = ?2 AND owner_epoch = ?3
                    "#,
                    params![&stored.10, &stored.11, stored.12],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            let created_at = stored_u64(stored.8, "observer_created_at_unix_ms")?;
            let updated_at = stored_u64(stored.9, "observer_updated_at_unix_ms")?;
            let row_version = stored_u64(stored.4, "observer_row_version")?;
            if stored.0 != record.record_id
                || stored.6 != record.record_digest
                || stored.7 != record.record_json
                || created_at
                    != stored_u64(
                        projection.committed_at_unix_ms,
                        "projection_committed_at_unix_ms",
                    )?
                || updated_at < created_at
                || stored.10 != projection.store_uuid
                || lease_exists != 1
                || (row_version == 0
                    && (stored.1 != "pending"
                        || stored.2 != 0
                        || stored_u64(stored.3, "observer_next_visible_at_unix_ms")?
                            != pending.next_visible_at_ms
                        || stored.5.is_some()))
            {
                return Err(invariant("observer attempt projection is inconsistent"));
            }
            Ok(())
        }
        _ => Err(invariant("observer attempt projection is partial")),
    }
}

impl SqliteAdmissionOperationStore {
    pub(crate) fn list_terminal_receipts_after(
        &self,
        after_receipt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError> {
        if limit == 0 || limit > MAX_RECOVERY_BATCH {
            return Err(ReceiptStoreError::Conflict(format!(
                "admission receipt page limit must be between 1 and {MAX_RECOVERY_BATCH}"
            )));
        }
        if let Some(receipt_id) = after_receipt_id {
            AdmissionIdentifier::try_new("after_receipt_id", receipt_id.to_owned())
                .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        }
        let limit = i64::try_from(limit).map_err(|_| {
            ReceiptStoreError::Conflict("admission receipt page limit overflow".to_owned())
        })?;
        let mut connection = self.connection().map_err(receipt_projection_error)?;
        let transaction = self
            .begin_read(&mut connection)
            .map_err(receipt_projection_error)?;
        let receipts = {
            let mut statement = transaction.prepare(
                r#"
                SELECT records.operation_id, records.record_id, records.record_json
                FROM admission_operation_terminal_records AS records
                INNER JOIN admission_operations AS operations
                    ON operations.operation_id = records.operation_id
                WHERE records.record_kind = 'receipt'
                  AND (?1 IS NULL OR records.record_id > ?1)
                  AND operations.terminal = 1
                ORDER BY records.record_id ASC
                LIMIT ?2
                "#,
            )?;
            let rows = statement.query_map(params![after_receipt_id, limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            let mut receipts = Vec::new();
            for row in rows {
                let (operation_id, record_id, bytes) = row?;
                let operation_id = AdmissionOperationId::from_persisted(operation_id)
                    .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
                let operation = load_by_operation_id_tx(&transaction, &operation_id)
                    .map_err(receipt_projection_error)?
                    .ok_or_else(|| {
                        ReceiptStoreError::Conflict(
                            "admission receipt references a missing operation".to_owned(),
                        )
                    })?;
                let receipt = decode_projection_receipt(bytes)?;
                let replay_matches = matches!(
                    operation.operation.terminal_replay(),
                    Some(AdmissionTerminalReplay::Receipt { receipt_id, .. })
                        if receipt_id.as_str() == record_id
                );
                if receipt.id != record_id || !replay_matches {
                    return Err(ReceiptStoreError::Conflict(
                        "admission receipt does not match its terminal operation".to_owned(),
                    ));
                }
                receipts.push(receipt);
            }
            receipts
        };
        transaction.commit()?;
        Ok(receipts)
    }
}

impl QualifiedAdmissionOperationStore for SqliteAdmissionOperationStore {}

impl ReceiptStore for SqliteAdmissionOperationStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "receipts must be committed through an admission terminal projection".to_string(),
        ))
    }

    fn admission_projection_capabilities(&self) -> AdmissionProjectionCapabilities {
        full_projection_capabilities()
    }

    fn commit_admission_projection(
        &self,
        projection: &AdmissionTerminalProjection,
    ) -> Result<AdmissionTerminal, ReceiptStoreError> {
        self.commit_terminal_projection(projection)
            .map_err(receipt_projection_error)
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let receipt_id = AdmissionIdentifier::try_new("receipt_id", receipt_id.to_owned())
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let mut connection = self.connection().map_err(receipt_projection_error)?;
        let transaction = self
            .begin_read(&mut connection)
            .map_err(receipt_projection_error)?;
        let stored = transaction
            .query_row(
                r#"
                SELECT operation_id, record_json
                FROM admission_operation_terminal_records
                WHERE record_kind = 'receipt' AND record_id = ?1
                "#,
                [receipt_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let receipt = match stored {
            None => None,
            Some((operation_id, bytes)) => {
                let operation_id = AdmissionOperationId::from_persisted(operation_id)
                    .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
                load_by_operation_id_tx(&transaction, &operation_id)
                    .map_err(receipt_projection_error)?
                    .ok_or_else(|| {
                        ReceiptStoreError::Conflict(
                            "admission receipt references a missing operation".to_string(),
                        )
                    })?;
                let receipt = decode_projection_receipt(bytes)?;
                if receipt.id != receipt_id.as_str() {
                    return Err(ReceiptStoreError::Conflict(
                        "admission receipt id does not match its projection key".to_owned(),
                    ));
                }
                Some(receipt)
            }
        };
        transaction.commit()?;
        Ok(receipt)
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "child receipts are not admission terminal projections".to_string(),
        ))
    }
}
