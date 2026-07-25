use chio_credit::obligation::{
    CreditExposureReservationRecordV1, CreditExposureReservationStateV1,
};

use super::*;

const MAX_CREDIT_EXPOSURE_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditExposureAccountSnapshot {
    pub(crate) debtor_id: String,
    pub(crate) scope_digest: String,
    pub(crate) currency: String,
    pub(crate) open_units: u64,
    pub(crate) reserved_units: u64,
    pub(crate) effective_ceiling_units: u64,
    pub(crate) authority_configuration_digest: String,
    pub(crate) authority_set_digest: String,
    pub(crate) authority_evidence_digest: String,
    pub(crate) authority_expires_at_unix_seconds: u64,
    pub(crate) account_version: u64,
    pub(crate) resource_fence: u64,
}

impl CreditExposureAccountSnapshot {
    fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        validate_credit_text("credit_exposure_debtor_id", &self.debtor_id)?;
        validate_credit_digest("credit_exposure_scope_digest", &self.scope_digest)?;
        validate_credit_currency(&self.currency)?;
        validate_credit_digest(
            "credit_exposure_authority_configuration_digest",
            &self.authority_configuration_digest,
        )?;
        validate_credit_digest(
            "credit_exposure_authority_set_digest",
            &self.authority_set_digest,
        )?;
        validate_credit_digest(
            "credit_exposure_authority_evidence_digest",
            &self.authority_evidence_digest,
        )?;
        validate_credit_counter(
            self.authority_expires_at_unix_seconds,
            "credit_exposure_authority_expires_at_unix_seconds",
            false,
        )?;
        validate_credit_counter(self.open_units, "credit_exposure_open_units", true)?;
        validate_credit_counter(self.reserved_units, "credit_exposure_reserved_units", true)?;
        validate_credit_counter(
            self.effective_ceiling_units,
            "credit_exposure_effective_ceiling_units",
            false,
        )?;
        validate_credit_counter(
            self.account_version,
            "credit_exposure_account_version",
            false,
        )?;
        validate_credit_counter(self.resource_fence, "credit_exposure_resource_fence", false)?;
        let total = self
            .open_units
            .checked_add(self.reserved_units)
            .ok_or_else(|| invariant("credit exposure total overflowed"))?;
        if total > self.effective_ceiling_units || self.account_version != self.resource_fence {
            return Err(invariant(
                "credit exposure account snapshot is inconsistent",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn debtor_id(&self) -> &str {
        &self.debtor_id
    }

    #[must_use]
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    #[must_use]
    pub const fn open_units(&self) -> u64 {
        self.open_units
    }

    #[must_use]
    pub const fn reserved_units(&self) -> u64 {
        self.reserved_units
    }

    #[must_use]
    pub const fn effective_ceiling_units(&self) -> u64 {
        self.effective_ceiling_units
    }

    #[must_use]
    pub fn authority_configuration_digest(&self) -> &str {
        &self.authority_configuration_digest
    }

    #[must_use]
    pub fn authority_set_digest(&self) -> &str {
        &self.authority_set_digest
    }

    #[must_use]
    pub fn authority_evidence_digest(&self) -> &str {
        &self.authority_evidence_digest
    }

    #[must_use]
    pub const fn authority_expires_at_unix_seconds(&self) -> u64 {
        self.authority_expires_at_unix_seconds
    }

    #[must_use]
    pub const fn account_version(&self) -> u64 {
        self.account_version
    }

    #[must_use]
    pub const fn resource_fence(&self) -> u64 {
        self.resource_fence
    }
}

#[cfg(test)]
pub(crate) fn initialize_credit_exposure_account_tx(
    transaction: &Transaction<'_>,
    reservation: &CreditExposureReservationRecordV1,
    open_units: u64,
    reserved_units: u64,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<CreditExposureAccountSnapshot, AdmissionOperationStoreError> {
    reservation.validate().map_err(credit_error)?;
    if reservation.state() != CreditExposureReservationStateV1::Reserved {
        return Err(invariant(
            "credit exposure account initialization requires a reserved record",
        ));
    }
    verify_credit_exposure_fence_tx(transaction, fence)?;
    validate_trusted_time(
        trusted_now_unix_ms,
        "credit_exposure_initialized_at_unix_ms",
    )?;
    let snapshot = CreditExposureAccountSnapshot {
        debtor_id: reservation.debtor_id().to_owned(),
        scope_digest: reservation.scope_digest().to_owned(),
        currency: reservation.amount().currency.clone(),
        open_units,
        reserved_units,
        effective_ceiling_units: reservation.effective_ceiling().units,
        authority_configuration_digest: reservation.authority_configuration_digest().to_owned(),
        authority_set_digest: reservation.authority_set_digest().to_owned(),
        authority_evidence_digest: credit_authority_evidence_digest(reservation)?,
        authority_expires_at_unix_seconds: reservation.authority_expires_at_unix_seconds(),
        account_version: reservation.source_account_version(),
        resource_fence: reservation.source_resource_fence(),
    };
    snapshot.validate()?;
    if let Some(existing) = load_credit_exposure_account_tx(
        transaction,
        &snapshot.debtor_id,
        &snapshot.scope_digest,
        &snapshot.currency,
    )? {
        return if existing == snapshot {
            Ok(existing)
        } else {
            Err(invariant(
                "credit exposure account already exists with different state",
            ))
        };
    }
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO credit_exposure_accounts (
                debtor_id, scope_digest, currency, open_units, reserved_units,
                effective_ceiling_units, authority_configuration_digest,
                authority_set_digest, authority_evidence_digest,
                authority_expires_at_unix_seconds, account_version, resource_fence,
                updated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
            )
            "#,
            params![
                &snapshot.debtor_id,
                &snapshot.scope_digest,
                &snapshot.currency,
                sqlite_i64(snapshot.open_units, "credit_exposure_open_units")?,
                sqlite_i64(snapshot.reserved_units, "credit_exposure_reserved_units")?,
                sqlite_i64(
                    snapshot.effective_ceiling_units,
                    "credit_exposure_effective_ceiling_units"
                )?,
                &snapshot.authority_configuration_digest,
                &snapshot.authority_set_digest,
                &snapshot.authority_evidence_digest,
                sqlite_i64(
                    snapshot.authority_expires_at_unix_seconds,
                    "credit_exposure_authority_expires_at_unix_seconds"
                )?,
                sqlite_i64(snapshot.account_version, "credit_exposure_account_version")?,
                sqlite_i64(snapshot.resource_fence, "credit_exposure_resource_fence")?,
                sqlite_i64(
                    trusted_now_unix_ms,
                    "credit_exposure_initialized_at_unix_ms"
                )?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "credit_exposure_store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(snapshot)
}

pub(crate) fn load_credit_exposure_account_tx(
    transaction: &Connection,
    debtor_id: &str,
    scope_digest: &str,
    currency: &str,
) -> Result<Option<CreditExposureAccountSnapshot>, AdmissionOperationStoreError> {
    let snapshot = transaction
        .query_row(
            r#"
            SELECT debtor_id, scope_digest, currency, open_units, reserved_units,
                   effective_ceiling_units, authority_configuration_digest,
                   authority_set_digest, authority_evidence_digest,
                   authority_expires_at_unix_seconds, account_version, resource_fence
            FROM credit_exposure_accounts
            WHERE debtor_id = ?1 AND scope_digest = ?2 AND currency = ?3
            "#,
            params![debtor_id, scope_digest, currency],
            |row| {
                Ok(CreditExposureAccountSnapshot {
                    debtor_id: row.get(0)?,
                    scope_digest: row.get(1)?,
                    currency: row.get(2)?,
                    open_units: stored_u64(row.get(3)?, "credit_exposure_open_units")
                        .map_err(to_sql_conversion_error)?,
                    reserved_units: stored_u64(row.get(4)?, "credit_exposure_reserved_units")
                        .map_err(to_sql_conversion_error)?,
                    effective_ceiling_units: stored_u64(
                        row.get(5)?,
                        "credit_exposure_effective_ceiling_units",
                    )
                    .map_err(to_sql_conversion_error)?,
                    authority_configuration_digest: row.get(6)?,
                    authority_set_digest: row.get(7)?,
                    authority_evidence_digest: row.get(8)?,
                    authority_expires_at_unix_seconds: stored_u64(
                        row.get(9)?,
                        "credit_exposure_authority_expires_at_unix_seconds",
                    )
                    .map_err(to_sql_conversion_error)?,
                    account_version: stored_u64(row.get(10)?, "credit_exposure_account_version")
                        .map_err(to_sql_conversion_error)?,
                    resource_fence: stored_u64(row.get(11)?, "credit_exposure_resource_fence")
                        .map_err(to_sql_conversion_error)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    snapshot
        .map(|snapshot| {
            snapshot.validate()?;
            Ok(snapshot)
        })
        .transpose()
}

pub(crate) fn reserve_credit_exposure_tx(
    transaction: &Transaction<'_>,
    reservation: &CreditExposureReservationRecordV1,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<CreditExposureReservationRecordV1, AdmissionOperationStoreError> {
    reservation.validate().map_err(credit_error)?;
    if reservation.state() != CreditExposureReservationStateV1::Reserved
        || reservation.obligation_id().is_some()
    {
        return Err(invariant(
            "credit exposure reserve requires a reserved record",
        ));
    }
    verify_credit_exposure_fence_tx(transaction, fence)?;
    validate_trusted_time(trusted_now_unix_ms, "credit_exposure_reserved_at_unix_ms")?;
    if trusted_now_unix_ms / 1_000 >= reservation.authority_expires_at_unix_seconds() {
        return Err(invariant("credit exposure authority set is expired"));
    }
    if let Some(existing) =
        load_credit_exposure_reservation_tx(transaction, reservation.operation_id())?
    {
        return if existing == *reservation {
            Ok(existing)
        } else {
            Err(invariant("credit exposure reservation replay conflicts"))
        };
    }
    let nonce_operation: Option<String> = transaction
        .query_row(
            r#"
            SELECT operation_id
            FROM credit_exposure_reservations
            WHERE debtor_id = ?1 AND scope_digest = ?2 AND currency = ?3 AND action_nonce = ?4
            "#,
            params![
                reservation.debtor_id(),
                reservation.scope_digest(),
                &reservation.amount().currency,
                reservation.action_nonce(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if nonce_operation.is_some() {
        return Err(invariant(
            "credit exposure action nonce was already consumed",
        ));
    }
    let account = load_credit_exposure_account_tx(
        transaction,
        reservation.debtor_id(),
        reservation.scope_digest(),
        &reservation.amount().currency,
    )?
    .ok_or(AdmissionOperationStoreError::NotFound)?;
    if account.account_version != reservation.source_account_version()
        || account.resource_fence != reservation.source_resource_fence()
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let next_reserved_units = account
        .reserved_units
        .checked_add(reservation.amount().units)
        .ok_or_else(|| invariant("credit exposure reserved units overflowed"))?;
    let total = account
        .open_units
        .checked_add(next_reserved_units)
        .ok_or_else(|| invariant("credit exposure total overflowed"))?;
    if total > reservation.effective_ceiling().units {
        return Err(invariant("credit exposure exceeds the effective ceiling"));
    }
    let encoded = encode_credit_exposure_record(reservation)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO credit_exposure_reservations (
                operation_id, reservation_digest, debtor_id, scope_digest, currency,
                action_nonce, amount_units, source_account_version,
                source_resource_fence, reserved_account_version,
                reserved_resource_fence, reservation_json, reserved_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
            )
            "#,
            params![
                reservation.operation_id(),
                reservation.reservation_digest(),
                reservation.debtor_id(),
                reservation.scope_digest(),
                &reservation.amount().currency,
                reservation.action_nonce(),
                sqlite_i64(reservation.amount().units, "credit_exposure_amount_units")?,
                sqlite_i64(
                    reservation.source_account_version(),
                    "credit_exposure_source_account_version"
                )?,
                sqlite_i64(
                    reservation.source_resource_fence(),
                    "credit_exposure_source_resource_fence"
                )?,
                sqlite_i64(
                    reservation.account_version(),
                    "credit_exposure_reserved_account_version"
                )?,
                sqlite_i64(
                    reservation.resource_fence(),
                    "credit_exposure_reserved_resource_fence"
                )?,
                encoded,
                sqlite_i64(trusted_now_unix_ms, "credit_exposure_reserved_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "credit_exposure_store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let changed = transaction
        .execute(
            r#"
            UPDATE credit_exposure_accounts
            SET reserved_units = ?1,
                effective_ceiling_units = ?2,
                authority_configuration_digest = ?3,
                authority_set_digest = ?4,
                authority_evidence_digest = ?5,
                authority_expires_at_unix_seconds = ?6,
                account_version = ?7,
                resource_fence = ?8,
                updated_at_unix_ms = ?9,
                store_lease_id = ?10,
                store_owner_epoch = ?11
            WHERE debtor_id = ?12 AND scope_digest = ?13 AND currency = ?14
              AND account_version = ?15 AND resource_fence = ?16
              AND open_units = ?17 AND reserved_units = ?18
            "#,
            params![
                sqlite_i64(next_reserved_units, "credit_exposure_reserved_units")?,
                sqlite_i64(
                    reservation.effective_ceiling().units,
                    "credit_exposure_effective_ceiling_units"
                )?,
                reservation.authority_configuration_digest(),
                reservation.authority_set_digest(),
                credit_authority_evidence_digest(reservation)?,
                sqlite_i64(
                    reservation.authority_expires_at_unix_seconds(),
                    "credit_exposure_authority_expires_at_unix_seconds"
                )?,
                sqlite_i64(
                    reservation.account_version(),
                    "credit_exposure_account_version"
                )?,
                sqlite_i64(
                    reservation.resource_fence(),
                    "credit_exposure_resource_fence"
                )?,
                sqlite_i64(trusted_now_unix_ms, "credit_exposure_reserved_at_unix_ms")?,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "credit_exposure_store_owner_epoch")?,
                reservation.debtor_id(),
                reservation.scope_digest(),
                &reservation.amount().currency,
                sqlite_i64(
                    account.account_version,
                    "credit_exposure_source_account_version"
                )?,
                sqlite_i64(
                    account.resource_fence,
                    "credit_exposure_source_resource_fence"
                )?,
                sqlite_i64(account.open_units, "credit_exposure_open_units")?,
                sqlite_i64(account.reserved_units, "credit_exposure_reserved_units")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(reservation.clone())
}

pub(crate) fn load_credit_exposure_reservation_tx(
    transaction: &Connection,
    operation_id: &str,
) -> Result<Option<CreditExposureReservationRecordV1>, AdmissionOperationStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT reserved.reservation_digest, reserved.debtor_id,
                   reserved.scope_digest, reserved.currency, reserved.action_nonce,
                   reserved.amount_units, reserved.source_account_version,
                   reserved.source_resource_fence, reserved.reserved_account_version,
                   reserved.reserved_resource_fence,
                   COALESCE(terminal.transition_json, reserved.reservation_json),
                   terminal.terminal_state, terminal.obligation_id,
                   terminal.account_version, terminal.resource_fence
            FROM credit_exposure_reservations AS reserved
            LEFT JOIN credit_exposure_terminal_transitions AS terminal
              ON terminal.operation_id = reserved.operation_id
            WHERE reserved.operation_id = ?1
            "#,
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Option<i64>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let record = decode_credit_exposure_record(&row.10)?;
    let expected_state = row
        .11
        .as_deref()
        .map(parse_credit_exposure_state)
        .transpose()?
        .unwrap_or(CreditExposureReservationStateV1::Reserved);
    let account_version = row.13.unwrap_or(row.8);
    let resource_fence = row.14.unwrap_or(row.9);
    if record.operation_id() != operation_id
        || record.reservation_digest() != row.0
        || record.debtor_id() != row.1
        || record.scope_digest() != row.2
        || record.amount().currency != row.3
        || record.action_nonce() != row.4
        || sqlite_i64(record.amount().units, "credit_exposure_amount_units")? != row.5
        || sqlite_i64(
            record.source_account_version(),
            "credit_exposure_source_account_version",
        )? != row.6
        || sqlite_i64(
            record.source_resource_fence(),
            "credit_exposure_source_resource_fence",
        )? != row.7
        || record.state() != expected_state
        || record.obligation_id() != row.12.as_deref()
        || sqlite_i64(record.account_version(), "credit_exposure_account_version")?
            != account_version
        || sqlite_i64(record.resource_fence(), "credit_exposure_resource_fence")? != resource_fence
    {
        return Err(invariant(
            "persisted credit exposure reservation differs from its indexes",
        ));
    }
    if record.state() == CreditExposureReservationStateV1::Committed {
        let obligation_id = record
            .obligation_id()
            .ok_or_else(|| invariant("committed credit exposure has no obligation id"))?;
        let stored_atom_digest = transaction
            .query_row(
                r#"
                SELECT atom_digest
                FROM obligation_atoms
                WHERE operation_id = ?1 AND obligation_id = ?2
                "#,
                params![operation_id, obligation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| {
                invariant("committed credit exposure has no durable obligation mapping")
            })?;
        if record.obligation_atom_digest() != Some(stored_atom_digest.as_str()) {
            return Err(invariant(
                "committed credit exposure differs from its durable obligation mapping",
            ));
        }
        let obligation = super::obligation::load_durable_obligation(transaction, obligation_id)?
            .ok_or_else(|| invariant("committed credit exposure obligation is absent"))?;
        record
            .validate_committed_obligation(obligation.atom())
            .map_err(credit_error)?;
    }
    Ok(Some(record))
}

fn load_reserved_credit_exposure_record_tx(
    transaction: &Connection,
    operation_id: &str,
) -> Result<Option<CreditExposureReservationRecordV1>, AdmissionOperationStoreError> {
    let bytes = transaction
        .query_row(
            "SELECT reservation_json FROM credit_exposure_reservations WHERE operation_id = ?1",
            [operation_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let record = bytes
        .map(|bytes| decode_credit_exposure_record(&bytes))
        .transpose()?;
    if record.as_ref().is_some_and(|record| {
        record.operation_id() != operation_id
            || record.state() != CreditExposureReservationStateV1::Reserved
            || record.obligation_id().is_some()
    }) {
        return Err(invariant(
            "persisted credit exposure reservation source is invalid",
        ));
    }
    Ok(record)
}

pub(crate) fn commit_credit_exposure_tx(
    transaction: &Transaction<'_>,
    committed: &CreditExposureReservationRecordV1,
    projection_digest: &AdmissionDigest,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<CreditExposureReservationRecordV1, AdmissionOperationStoreError> {
    transition_credit_exposure_tx(
        transaction,
        committed,
        CreditExposureReservationStateV1::Committed,
        AdmissionOperationState::Completed,
        projection_digest,
        fence,
        trusted_now_unix_ms,
    )
}

pub(crate) fn mark_credit_exposure_outcome_unknown_tx(
    transaction: &Transaction<'_>,
    outcome_unknown: &CreditExposureReservationRecordV1,
    admission_terminal_state: AdmissionOperationState,
    projection_digest: &AdmissionDigest,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<CreditExposureReservationRecordV1, AdmissionOperationStoreError> {
    transition_credit_exposure_tx(
        transaction,
        outcome_unknown,
        CreditExposureReservationStateV1::OutcomeUnknown,
        admission_terminal_state,
        projection_digest,
        fence,
        trusted_now_unix_ms,
    )
}

pub(crate) fn apply_credit_exposure_terminal_tx(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    projection_digest: &AdmissionDigest,
    pre_dispatch_release_proof: Option<&chio_kernel::tool_outcome::VerifiedPreDispatchNoEffect>,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let requirements = operation.binding().participant_requirements();
    let reservation_digest = operation.credit_exposure_reservation_digest();
    if !requirements.credit_exposure {
        if reservation_digest.is_some() {
            return Err(invariant(
                "admission operation has an unexpected credit exposure reservation",
            ));
        }
        if load_credit_exposure_reservation_tx(
            transaction,
            operation.binding().operation_id().as_str(),
        )?
        .is_some()
        {
            return Err(invariant(
                "non-credit admission operation has persisted credit exposure state",
            ));
        }
        return Ok(());
    }
    let Some(reservation_digest) = reservation_digest else {
        if operation.state() != AdmissionOperationState::CompensatedBeforeDispatch
            || load_credit_exposure_reservation_tx(
                transaction,
                operation.binding().operation_id().as_str(),
            )?
            .is_some()
        {
            return Err(invariant(
                "credit exposure terminal operation lost its reservation",
            ));
        }
        return Ok(());
    };
    let current = load_credit_exposure_reservation_tx(
        transaction,
        operation.binding().operation_id().as_str(),
    )?
    .ok_or(AdmissionOperationStoreError::NotFound)?;
    if current.reservation_digest() != reservation_digest.as_str() {
        return Err(invariant(
            "credit exposure terminal operation changed its reservation digest",
        ));
    }
    if current.state() != CreditExposureReservationStateV1::Reserved {
        return verify_credit_exposure_terminal_replay_tx(
            transaction,
            operation,
            &current,
            projection_digest,
        );
    }
    let account = load_credit_exposure_account_tx(
        transaction,
        current.debtor_id(),
        current.scope_digest(),
        &current.amount().currency,
    )?
    .ok_or(AdmissionOperationStoreError::NotFound)?;
    let next_version = account
        .account_version
        .checked_add(1)
        .ok_or_else(|| invariant("credit exposure account version overflowed"))?;
    match operation.state() {
        AdmissionOperationState::Completed => {
            let atom = super::obligation::load_obligation_atom_by_operation(
                transaction,
                operation.binding().operation_id(),
            )?
            .ok_or_else(|| {
                invariant("completed credit exposure operation has no obligation atom")
            })?;
            let committed = current
                .prepare_committed(&atom, next_version, next_version)
                .map_err(credit_error)?;
            commit_credit_exposure_tx(
                transaction,
                &committed,
                projection_digest,
                fence,
                trusted_now_unix_ms,
            )?;
        }
        AdmissionOperationState::NotAcceptedAfterDispatchCommit
        | AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            let outcome_unknown = current
                .prepare_outcome_unknown(next_version, next_version)
                .map_err(credit_error)?;
            mark_credit_exposure_outcome_unknown_tx(
                transaction,
                &outcome_unknown,
                operation.state(),
                projection_digest,
                fence,
                trusted_now_unix_ms,
            )?;
        }
        AdmissionOperationState::CompensatedBeforeDispatch => {
            let proof = pre_dispatch_release_proof.ok_or_else(|| {
                invariant(
                    "credit exposure release requires verified pre-dispatch no-effect evidence",
                )
            })?;
            if proof.operation_id() != operation.binding().operation_id() {
                return Err(invariant(
                    "credit exposure release proof names a different operation",
                ));
            }
            let released = current
                .prepare_released_before_dispatch_from_kernel_projection(
                    proof.operation_id().as_str(),
                    next_version,
                    next_version,
                )
                .map_err(credit_error)?;
            transition_credit_exposure_tx(
                transaction,
                &released,
                CreditExposureReservationStateV1::ReleasedBeforeDispatch,
                operation.state(),
                projection_digest,
                fence,
                trusted_now_unix_ms,
            )?;
        }
        _ => {
            return Err(invariant(
                "credit exposure operation has a nonterminal projection state",
            ));
        }
    }
    Ok(())
}

fn verify_credit_exposure_terminal_replay_tx(
    transaction: &Connection,
    operation: &AdmissionOperationV1,
    current: &CreditExposureReservationRecordV1,
    projection_digest: &AdmissionDigest,
) -> Result<(), AdmissionOperationStoreError> {
    let expected_state = match operation.state() {
        AdmissionOperationState::Completed => CreditExposureReservationStateV1::Committed,
        AdmissionOperationState::CompensatedBeforeDispatch => {
            CreditExposureReservationStateV1::ReleasedBeforeDispatch
        }
        AdmissionOperationState::NotAcceptedAfterDispatchCommit
        | AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            CreditExposureReservationStateV1::OutcomeUnknown
        }
        _ => {
            return Err(invariant(
                "credit exposure replay has a nonterminal admission state",
            ));
        }
    };
    if current.state() != expected_state
        || !credit_exposure_terminal_source_matches_tx(
            transaction,
            current.operation_id(),
            operation.state(),
            projection_digest,
        )?
    {
        return Err(invariant("credit exposure terminal replay conflicts"));
    }
    if expected_state == CreditExposureReservationStateV1::Committed {
        let atom = super::obligation::load_obligation_atom_by_operation(
            transaction,
            operation.binding().operation_id(),
        )?
        .ok_or_else(|| invariant("credit exposure replay lost its obligation atom"))?;
        if current.obligation_id() != Some(atom.obligation_id()) {
            return Err(invariant(
                "credit exposure replay changed its obligation atom",
            ));
        }
        let reserved = load_reserved_credit_exposure_record_tx(
            transaction,
            operation.binding().operation_id().as_str(),
        )?
        .ok_or_else(|| invariant("credit exposure replay lost its reserved source"))?;
        let expected = reserved
            .prepare_committed(&atom, current.account_version(), current.resource_fence())
            .map_err(credit_error)?;
        if expected != *current {
            return Err(invariant(
                "credit exposure replay changed its committed transition",
            ));
        }
    } else if expected_state == CreditExposureReservationStateV1::OutcomeUnknown {
        let reserved = load_reserved_credit_exposure_record_tx(
            transaction,
            operation.binding().operation_id().as_str(),
        )?
        .ok_or_else(|| invariant("credit exposure replay lost its reserved source"))?;
        let expected = reserved
            .prepare_outcome_unknown(current.account_version(), current.resource_fence())
            .map_err(credit_error)?;
        if expected != *current {
            return Err(invariant(
                "credit exposure replay changed its outcome-unknown transition",
            ));
        }
    }
    Ok(())
}

pub(super) fn verify_credit_exposure_operation_state(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    projection_digest: Option<&AdmissionDigest>,
) -> Result<(), AdmissionOperationStoreError> {
    let requirements = operation.binding().participant_requirements();
    let attached = operation.credit_exposure_reservation_digest();
    let stored = load_credit_exposure_reservation_tx(
        connection,
        operation.binding().operation_id().as_str(),
    )?;
    if !requirements.credit_exposure {
        if attached.is_some() || stored.is_some() {
            return Err(invariant(
                "non-credit admission operation has credit exposure state",
            ));
        }
        return Ok(());
    }
    let Some(attached) = attached else {
        if stored.is_some()
            || !matches!(
                operation.state(),
                AdmissionOperationState::Prepared
                    | AdmissionOperationState::BrokerAttemptRegistered
                    | AdmissionOperationState::CompensatedBeforeDispatch
            )
        {
            return Err(invariant(
                "credit admission operation lost its reservation attachment",
            ));
        }
        return Ok(());
    };
    let stored = stored
        .ok_or_else(|| invariant("credit admission operation lost its persisted reservation"))?;
    if stored.reservation_digest() != attached.as_str() {
        return Err(invariant(
            "credit admission operation reservation digest differs from storage",
        ));
    }
    if operation.state().is_terminal() {
        let projection_digest = projection_digest.ok_or_else(|| {
            invariant("terminal credit admission operation lacks a projection digest")
        })?;
        verify_credit_exposure_terminal_replay_tx(connection, operation, &stored, projection_digest)
    } else if stored.state() == CreditExposureReservationStateV1::Reserved {
        Ok(())
    } else {
        Err(invariant(
            "nonterminal credit admission operation has terminal credit exposure state",
        ))
    }
}

pub(super) fn verify_credit_exposure_account_invariants(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare("SELECT debtor_id, scope_digest, currency FROM credit_exposure_accounts")
        .map_err(sqlite_error)?;
    let keys = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    for (debtor_id, scope_digest, currency) in keys {
        let account =
            load_credit_exposure_account_tx(connection, &debtor_id, &scope_digest, &currency)?
                .ok_or_else(|| {
                    invariant("credit exposure account disappeared during verification")
                })?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT reserved.operation_id, reserved.amount_units,
                       reserved.reserved_account_version,
                       terminal.terminal_state, terminal.account_version
                FROM credit_exposure_reservations AS reserved
                LEFT JOIN credit_exposure_terminal_transitions AS terminal
                  ON terminal.operation_id = reserved.operation_id
                WHERE reserved.debtor_id = ?1
                  AND reserved.scope_digest = ?2
                  AND reserved.currency = ?3
                ORDER BY reserved.reserved_account_version
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![&debtor_id, &scope_digest, &currency], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        if rows.is_empty() {
            return Err(invariant(
                "credit exposure account has no immutable reservation history",
            ));
        }
        let mut open_units = 0_u64;
        let mut reserved_units = 0_u64;
        let mut event_versions = Vec::with_capacity(rows.len().saturating_mul(2));
        let mut latest_reservation: Option<(u64, CreditExposureReservationRecordV1)> = None;
        for (operation_id, amount, reserved_version, terminal_state, terminal_version) in rows {
            let amount = stored_u64(amount, "credit_exposure_amount_units")?;
            let reserved_version =
                stored_u64(reserved_version, "credit_exposure_reserved_account_version")?;
            event_versions.push(reserved_version);
            let reservation = load_reserved_credit_exposure_record_tx(connection, &operation_id)?
                .ok_or_else(|| {
                invariant("credit exposure account lost a reservation source")
            })?;
            if reservation.amount().units != amount {
                return Err(invariant(
                    "credit exposure account amount differs from its reservation",
                ));
            }
            if latest_reservation
                .as_ref()
                .is_none_or(|(version, _)| reserved_version > *version)
            {
                latest_reservation = Some((reserved_version, reservation));
            }
            match terminal_state.as_deref() {
                None | Some("outcome_unknown") => {
                    reserved_units = reserved_units
                        .checked_add(amount)
                        .ok_or_else(|| invariant("credit exposure reserved units overflowed"))?;
                }
                Some("committed") => {
                    open_units = open_units
                        .checked_add(amount)
                        .ok_or_else(|| invariant("credit exposure open units overflowed"))?;
                }
                Some("released_before_dispatch") => {}
                Some(_) => {
                    return Err(invariant(
                        "credit exposure account has an invalid terminal state",
                    ));
                }
            }
            if let Some(version) = terminal_version {
                event_versions.push(stored_u64(
                    version,
                    "credit_exposure_terminal_account_version",
                )?);
            } else if terminal_state.is_some() {
                return Err(invariant(
                    "credit exposure terminal transition lost its account version",
                ));
            }
        }
        event_versions.sort_unstable();
        if event_versions.windows(2).any(|pair| {
            pair[0]
                .checked_add(1)
                .is_none_or(|expected| expected != pair[1])
        }) || event_versions
            .last()
            .is_some_and(|version| *version != account.account_version)
            || account.open_units != open_units
            || account.reserved_units != reserved_units
        {
            return Err(invariant(
                "credit exposure account does not match its dense event history",
            ));
        }
        if let Some((_, latest)) = latest_reservation {
            if account.effective_ceiling_units != latest.effective_ceiling().units
                || account.authority_configuration_digest != latest.authority_configuration_digest()
                || account.authority_set_digest != latest.authority_set_digest()
                || account.authority_evidence_digest != credit_authority_evidence_digest(&latest)?
                || account.authority_expires_at_unix_seconds
                    != latest.authority_expires_at_unix_seconds()
            {
                return Err(invariant(
                    "credit exposure account authority differs from its latest reservation",
                ));
            }
        }
    }
    Ok(())
}

fn transition_credit_exposure_tx(
    transaction: &Transaction<'_>,
    next: &CreditExposureReservationRecordV1,
    expected_state: CreditExposureReservationStateV1,
    admission_terminal_state: AdmissionOperationState,
    projection_digest: &AdmissionDigest,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<CreditExposureReservationRecordV1, AdmissionOperationStoreError> {
    next.validate().map_err(credit_error)?;
    if next.state() != expected_state {
        return Err(invariant(
            "credit exposure transition state does not match its action",
        ));
    }
    let admission_state_matches = match expected_state {
        CreditExposureReservationStateV1::Committed => {
            admission_terminal_state == AdmissionOperationState::Completed
        }
        CreditExposureReservationStateV1::ReleasedBeforeDispatch => {
            admission_terminal_state == AdmissionOperationState::CompensatedBeforeDispatch
        }
        CreditExposureReservationStateV1::OutcomeUnknown => matches!(
            admission_terminal_state,
            AdmissionOperationState::NotAcceptedAfterDispatchCommit
                | AdmissionOperationState::OutcomeUnknownAfterDispatch
        ),
        CreditExposureReservationStateV1::Reserved => false,
    };
    if !admission_state_matches {
        return Err(invariant(
            "credit exposure transition does not match the admission terminal state",
        ));
    }
    verify_credit_exposure_fence_tx(transaction, fence)?;
    validate_trusted_time(
        trusted_now_unix_ms,
        "credit_exposure_transitioned_at_unix_ms",
    )?;
    let current = load_credit_exposure_reservation_tx(transaction, next.operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    if current.state() != CreditExposureReservationStateV1::Reserved {
        let source_matches = credit_exposure_terminal_source_matches_tx(
            transaction,
            next.operation_id(),
            admission_terminal_state,
            projection_digest,
        )?;
        return if current == *next && source_matches {
            Ok(current)
        } else {
            Err(invariant("credit exposure terminal replay conflicts"))
        };
    }
    if current.reservation_digest() != next.reservation_digest()
        || current.source_account_version() != next.source_account_version()
        || current.source_resource_fence() != next.source_resource_fence()
        || current.debtor_id() != next.debtor_id()
        || current.scope_digest() != next.scope_digest()
        || current.amount() != next.amount()
    {
        return Err(invariant(
            "credit exposure transition changes reservation identity",
        ));
    }
    let account = load_credit_exposure_account_tx(
        transaction,
        current.debtor_id(),
        current.scope_digest(),
        &current.amount().currency,
    )?
    .ok_or(AdmissionOperationStoreError::NotFound)?;
    let next_version = account
        .account_version
        .checked_add(1)
        .ok_or_else(|| invariant("credit exposure account version overflowed"))?;
    if next.account_version() != next_version
        || next.resource_fence() != next_version
        || account.reserved_units < current.amount().units
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let released_reserved_units = account
        .reserved_units
        .checked_sub(current.amount().units)
        .ok_or_else(|| invariant("credit exposure reserved units underflowed"))?;
    let (next_open_units, next_reserved_units) = match expected_state {
        CreditExposureReservationStateV1::Committed => (
            account
                .open_units
                .checked_add(current.amount().units)
                .ok_or_else(|| invariant("credit exposure open units overflowed"))?,
            released_reserved_units,
        ),
        CreditExposureReservationStateV1::ReleasedBeforeDispatch => {
            (account.open_units, released_reserved_units)
        }
        CreditExposureReservationStateV1::OutcomeUnknown => {
            (account.open_units, account.reserved_units)
        }
        CreditExposureReservationStateV1::Reserved => {
            return Err(invariant("credit exposure transition remained reserved"));
        }
    };
    let encoded = encode_credit_exposure_record(next)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO credit_exposure_terminal_transitions (
                operation_id, reservation_digest, terminal_state,
                admission_terminal_state, projection_digest, obligation_id,
                account_version, resource_fence, transition_json,
                transitioned_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
            )
            "#,
            params![
                next.operation_id(),
                next.reservation_digest(),
                credit_exposure_state_name(expected_state),
                state_name(admission_terminal_state),
                projection_digest.as_str(),
                next.obligation_id(),
                sqlite_i64(next.account_version(), "credit_exposure_account_version")?,
                sqlite_i64(next.resource_fence(), "credit_exposure_resource_fence")?,
                encoded,
                sqlite_i64(
                    trusted_now_unix_ms,
                    "credit_exposure_transitioned_at_unix_ms"
                )?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "credit_exposure_store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let changed = transaction
        .execute(
            r#"
            UPDATE credit_exposure_accounts
            SET open_units = ?1, reserved_units = ?2,
                account_version = ?3, resource_fence = ?4,
                updated_at_unix_ms = ?5,
                store_lease_id = ?6, store_owner_epoch = ?7
            WHERE debtor_id = ?8 AND scope_digest = ?9 AND currency = ?10
              AND account_version = ?11 AND resource_fence = ?12
              AND open_units = ?13 AND reserved_units = ?14
            "#,
            params![
                sqlite_i64(next_open_units, "credit_exposure_open_units")?,
                sqlite_i64(next_reserved_units, "credit_exposure_reserved_units")?,
                sqlite_i64(next.account_version(), "credit_exposure_account_version")?,
                sqlite_i64(next.resource_fence(), "credit_exposure_resource_fence")?,
                sqlite_i64(
                    trusted_now_unix_ms,
                    "credit_exposure_transitioned_at_unix_ms"
                )?,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "credit_exposure_store_owner_epoch")?,
                current.debtor_id(),
                current.scope_digest(),
                &current.amount().currency,
                sqlite_i64(account.account_version, "credit_exposure_account_version")?,
                sqlite_i64(account.resource_fence, "credit_exposure_resource_fence")?,
                sqlite_i64(account.open_units, "credit_exposure_open_units")?,
                sqlite_i64(account.reserved_units, "credit_exposure_reserved_units")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(next.clone())
}

fn encode_credit_exposure_record(
    record: &CreditExposureReservationRecordV1,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    record.validate().map_err(credit_error)?;
    let bytes = canonical_json_bytes(record)
        .map_err(|error| invariant(format!("credit exposure record encoding failed: {error}")))?;
    if bytes.is_empty() || bytes.len() > MAX_CREDIT_EXPOSURE_RECORD_BYTES {
        return Err(invariant("credit exposure record exceeds its size limit"));
    }
    Ok(bytes)
}

fn decode_credit_exposure_record(
    bytes: &[u8],
) -> Result<CreditExposureReservationRecordV1, AdmissionOperationStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_CREDIT_EXPOSURE_RECORD_BYTES {
        return Err(invariant(
            "persisted credit exposure record has invalid size",
        ));
    }
    let record: CreditExposureReservationRecordV1 = serde_json::from_slice(bytes)
        .map_err(|error| invariant(format!("credit exposure record decoding failed: {error}")))?;
    record.validate().map_err(credit_error)?;
    if encode_credit_exposure_record(&record)? != bytes {
        return Err(invariant(
            "persisted credit exposure record is not canonical",
        ));
    }
    Ok(record)
}

fn verify_credit_exposure_fence_tx(
    transaction: &Transaction<'_>,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let active: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM chio_serving_owner AS owner
                JOIN chio_serving_leases AS lease
                  ON lease.store_uuid = owner.store_uuid
                 AND lease.owner_epoch = owner.owner_epoch
                 AND lease.lease_id = owner.lease_id
                WHERE owner.singleton = 1
                  AND owner.store_uuid = ?1
                  AND owner.lease_id = ?2
                  AND owner.owner_epoch = ?3
                  AND lease.end_head_index IS NULL
            )
            "#,
            params![
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_i64(fence.owner_epoch, "credit_exposure_store_owner_epoch")?,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if active {
        Ok(())
    } else {
        Err(AdmissionOperationStoreError::Fenced)
    }
}

fn credit_exposure_terminal_source_matches_tx(
    transaction: &Connection,
    operation_id: &str,
    admission_terminal_state: AdmissionOperationState,
    projection_digest: &AdmissionDigest,
) -> Result<bool, AdmissionOperationStoreError> {
    transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM credit_exposure_terminal_transitions
                WHERE operation_id = ?1
                  AND admission_terminal_state = ?2
                  AND projection_digest = ?3
            )
            "#,
            params![
                operation_id,
                state_name(admission_terminal_state),
                projection_digest.as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn credit_authority_evidence_digest(
    reservation: &CreditExposureReservationRecordV1,
) -> Result<String, AdmissionOperationStoreError> {
    let canonical = canonical_json_bytes(&reservation.authority_evidence()).map_err(|error| {
        invariant(format!(
            "credit authority evidence encoding failed: {error}"
        ))
    })?;
    Ok(sha256_hex(&canonical))
}

fn credit_exposure_state_name(state: CreditExposureReservationStateV1) -> &'static str {
    match state {
        CreditExposureReservationStateV1::Reserved => "reserved",
        CreditExposureReservationStateV1::Committed => "committed",
        CreditExposureReservationStateV1::ReleasedBeforeDispatch => "released_before_dispatch",
        CreditExposureReservationStateV1::OutcomeUnknown => "outcome_unknown",
    }
}

fn parse_credit_exposure_state(
    value: &str,
) -> Result<CreditExposureReservationStateV1, AdmissionOperationStoreError> {
    match value {
        "committed" => Ok(CreditExposureReservationStateV1::Committed),
        "released_before_dispatch" => Ok(CreditExposureReservationStateV1::ReleasedBeforeDispatch),
        "outcome_unknown" => Ok(CreditExposureReservationStateV1::OutcomeUnknown),
        _ => Err(invariant("persisted credit exposure state is invalid")),
    }
}

fn validate_credit_text(
    field: &'static str,
    value: &str,
) -> Result<(), AdmissionOperationStoreError> {
    AdmissionIdentifier::try_new(field, value.to_owned())
        .map(|_| ())
        .map_err(Into::into)
}

fn validate_credit_currency(value: &str) -> Result<(), AdmissionOperationStoreError> {
    if value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(invariant("credit exposure currency is invalid"))
    }
}

fn validate_credit_digest(
    field: &'static str,
    value: &str,
) -> Result<(), AdmissionOperationStoreError> {
    AdmissionDigest::try_new(field, value.to_owned())
        .map(|_| ())
        .map_err(Into::into)
}

fn validate_credit_counter(
    value: u64,
    field: &'static str,
    allow_zero: bool,
) -> Result<(), AdmissionOperationStoreError> {
    if (!allow_zero && value == 0) || value > MAX_TRUSTED_UNIX_MS {
        return Err(invariant(format!(
            "{field} is outside the I-JSON integer range"
        )));
    }
    Ok(())
}

fn credit_error(
    error: chio_credit::obligation::CreditAdmissionError,
) -> AdmissionOperationStoreError {
    invariant(error.to_string())
}

fn to_sql_conversion_error(error: AdmissionOperationStoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(error))
}
