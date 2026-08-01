use super::*;

impl SqliteAdmissionOperationStore {
    pub fn stage_anchored_terminal_projection(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        recovery_lease: &AdmissionRecoveryLease,
        envelope: &SignedAdmissionTerminalProjectionV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let verified = envelope.verify()?;
        let cache = crate::economic_state_cache::SqliteEconomicStateCache::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        cache
            .stage_admission_terminal_projection(
                advance,
                crate::economic_state_cache::EconomicOperationStageContext::new(
                    verified.source_operation(),
                    recovery_lease,
                ),
                envelope,
                active_fence,
                trusted_now_unix_ms,
            )
            .map(|_| ())
            .map_err(map_economic_cache_error)
    }

    pub fn qualify_anchored_terminal_projection(
        &self,
        batch_id: &str,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let (verified, binding) =
            crate::economic_state_cache::load_anchored_terminal_projection_in_transaction(
                &transaction,
                batch_id,
                active_fence,
                false,
            )
            .map_err(map_economic_cache_error)?;
        verify_anchored_terminal_authority(
            &transaction,
            &self.serving_owner,
            &verified,
            &binding,
            trusted_now_unix_ms,
        )?;
        transaction.commit().map_err(sqlite_error)
    }

    pub fn record_anchored_terminal_projection(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        committed: &chio_core::economic_continuity::VerifiedEconomicStateView,
        pins: &chio_core::economic_continuity::EconomicStateAnchorPins,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let cache = crate::economic_state_cache::SqliteEconomicStateCache::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        cache
            .record_anchor_advanced(advance, committed, pins, active_fence, trusted_now_unix_ms)
            .map(|_| ())
            .map_err(map_economic_cache_error)
    }

    pub fn commit_anchored_terminal_projection(
        &self,
        batch_id: &str,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let (verified, binding) =
            crate::economic_state_cache::load_anchored_terminal_projection_in_transaction(
                &transaction,
                batch_id,
                active_fence,
                true,
            )
            .map_err(map_economic_cache_error)?;
        let terminal = self.commit_verified_signed_terminal_projection_in_transaction(
            &transaction,
            &verified,
            trusted_now_unix_ms,
            Some(&binding),
        )?;
        crate::economic_state_cache::finalize_stage_in_transaction(
            &transaction,
            batch_id,
            &self.serving_owner,
            trusted_now_unix_ms,
        )
        .map_err(map_economic_cache_error)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(terminal)
    }

    pub(super) fn commit_verified_signed_terminal_projection_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        verified: &VerifiedAdmissionTerminalProjectionV1,
        apply_time_unix_ms: u64,
        anchored_binding: Option<&crate::economic_state_cache::EconomicOperationStageBinding>,
    ) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
        let context = verified.context();
        if anchored_binding.is_none() && verified.requires_anchored_economic_commit() {
            return Err(invariant(
                "terminal projection requires an advanced economic anchor",
            ));
        }
        verify_trusted_time(transaction, apply_time_unix_ms)?;
        let stored = load_by_operation_id_tx(transaction, &context.operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        verify_payment_terminal_source(
            transaction,
            &stored.operation,
            context,
            verified.terminal_operation().state(),
            verified.records().iter().filter_map(|record| {
                (record.kind() == AdmissionProjectionRecordKind::PaymentTerminal)
                    .then_some((record.record_id(), record.canonical_json()))
            }),
            verified
                .records()
                .iter()
                .find(|record| record.kind() == AdmissionProjectionRecordKind::Receipt)
                .map(VerifiedAdmissionTerminalProjectionRecordV1::canonical_json),
            verified.projection_json(),
        )?;

        if stored.operation.state().is_terminal() {
            let terminal = verify_exact_signed_terminal_replay(transaction, &stored, verified)?;
            let manifest =
                AdmissionProjectionManifestV1::from_canonical_bytes(verified.manifest_json())?;
            apply_credit_exposure_terminal_tx(
                transaction,
                &stored.operation,
                &manifest.projection_digest()?,
                verified.pre_dispatch_release_proof(),
                &context.store_fence,
                apply_time_unix_ms,
            )?;
            if let Some(channel) = verified.channel_terminal() {
                crate::channel_lifecycle_store::verify_consumed_channel_terminal_projection_tx(
                    transaction,
                    channel,
                )
                .map_err(map_channel_terminal_error)?;
            }
            return Ok(terminal);
        }
        if stored.operation != *verified.source_operation()
            || apply_time_unix_ms < stored.updated_at_unix_ms
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        let recovery_claim = match anchored_binding {
            Some(binding) => verify_historical_recovery_claim(
                transaction,
                &self.serving_owner,
                &stored,
                verified,
                binding,
            )?,
            None => {
                ensure_no_reserved_terminal_stage(transaction, &context.operation_id)?;
                let recovery_claim = stored
                    .recovery_claim
                    .as_ref()
                    .ok_or(AdmissionOperationStoreError::Fenced)?;
                let expected_claimant = format!("kernel:{}", verified.signer_key().to_hex());
                if recovery_claim.claimant_id().as_str() != expected_claimant
                    || recovery_claim.coordinator_lease_id() != &context.coordinator_lease_id
                    || recovery_claim.coordinator_lease_epoch() != context.coordinator_lease_epoch
                    || recovery_claim.store_fence() != &context.store_fence
                {
                    return Err(AdmissionOperationStoreError::Fenced);
                }
                verify_stored_recovery_claim(
                    transaction,
                    &self.serving_owner,
                    &stored,
                    recovery_claim,
                    context.trusted_time_unix_ms,
                    &context.store_fence,
                )?;
                recovery_claim
            }
        };
        ensure_projection_absent(transaction, &context.operation_id)?;

        let updated = verified.terminal_operation();
        let encoded = encode_operation(updated)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET operation_json = ?1, state = ?2, terminal = 1,
                    coordinator_lease_epoch = ?3, version = ?4,
                    updated_at_unix_ms = ?5
                WHERE operation_id = ?6 AND version = ?7 AND terminal = 0
                "#,
                params![
                    &encoded,
                    state_name(updated.state()),
                    sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(updated.version(), "terminal_operation_version")?,
                    sqlite_i64(apply_time_unix_ms, "trusted_now_unix_ms")?,
                    context.operation_id.as_str(),
                    sqlite_i64(stored.operation.version(), "expected_operation_version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        insert_verified_terminal_projection(
            transaction,
            verified,
            apply_time_unix_ms,
            &self.serving_owner.fence,
        )?;
        let manifest =
            AdmissionProjectionManifestV1::from_canonical_bytes(verified.manifest_json())?;
        apply_credit_exposure_terminal_tx(
            transaction,
            updated,
            &manifest.projection_digest()?,
            verified.pre_dispatch_release_proof(),
            &self.serving_owner.fence,
            apply_time_unix_ms,
        )?;
        if let Some(channel) = verified.channel_terminal() {
            crate::channel_lifecycle_store::consume_channel_terminal_projection_tx(
                transaction,
                channel,
                &self.serving_owner.fence,
                apply_time_unix_ms,
            )
            .map_err(map_channel_terminal_error)?;
        }
        append_operation_commit(
            transaction,
            updated,
            &encoded,
            Some(recovery_claim),
            "compare_and_swap",
            &self.serving_owner,
            apply_time_unix_ms,
        )?;
        terminal_from_operation(updated)
    }
}

fn map_channel_terminal_error(
    error: crate::channel_lifecycle_store::ChannelLifecycleStoreError,
) -> AdmissionOperationStoreError {
    use crate::channel_lifecycle_store::ChannelLifecycleStoreError;

    match error {
        ChannelLifecycleStoreError::Fenced => AdmissionOperationStoreError::Fenced,
        ChannelLifecycleStoreError::NotFound => AdmissionOperationStoreError::NotFound,
        ChannelLifecycleStoreError::Unavailable(detail) => {
            AdmissionOperationStoreError::Unavailable(detail)
        }
        ChannelLifecycleStoreError::OutcomeUnknown(detail) => {
            AdmissionOperationStoreError::OutcomeUnknown(detail)
        }
        error => invariant(error.to_string()),
    }
}

fn verify_anchored_terminal_authority(
    transaction: &Transaction<'_>,
    serving_owner: &SqliteServingOwner,
    verified: &VerifiedAdmissionTerminalProjectionV1,
    binding: &crate::economic_state_cache::EconomicOperationStageBinding,
    apply_time_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let context = verified.context();
    let stored = load_by_operation_id_tx(transaction, &context.operation_id)?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    verify_payment_terminal_source(
        transaction,
        &stored.operation,
        context,
        verified.terminal_operation().state(),
        verified.records().iter().filter_map(|record| {
            (record.kind() == AdmissionProjectionRecordKind::PaymentTerminal)
                .then_some((record.record_id(), record.canonical_json()))
        }),
        verified
            .records()
            .iter()
            .find(|record| record.kind() == AdmissionProjectionRecordKind::Receipt)
            .map(VerifiedAdmissionTerminalProjectionRecordV1::canonical_json),
        verified.projection_json(),
    )?;
    if stored.operation.state().is_terminal() {
        verify_exact_signed_terminal_replay(transaction, &stored, verified)?;
        return Ok(());
    }
    if stored.operation != *verified.source_operation()
        || apply_time_unix_ms < stored.updated_at_unix_ms
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    verify_historical_recovery_claim(transaction, serving_owner, &stored, verified, binding)?;
    ensure_projection_absent(transaction, &context.operation_id)
}

fn verify_historical_recovery_claim<'a>(
    transaction: &Transaction<'_>,
    serving_owner: &SqliteServingOwner,
    stored: &'a StoredOperation,
    verified: &VerifiedAdmissionTerminalProjectionV1,
    binding: &crate::economic_state_cache::EconomicOperationStageBinding,
) -> Result<&'a UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
    let context = verified.context();
    let source = verified.source_operation();
    let recovery_claim = stored
        .recovery_claim
        .as_ref()
        .ok_or(AdmissionOperationStoreError::Fenced)?;
    let expected_claimant = format!("kernel:{}", verified.signer_key().to_hex());
    if binding.operation_id() != source.binding().operation_id().as_str()
        || binding.operation_state() != source.state()
        || binding.operation_version() != source.version()
        || binding.coordinator_lease_epoch() != source.coordinator_lease_epoch()
        || binding.coordinator_lease_id() != context.coordinator_lease_id.as_str()
        || binding.recovery_claimant_id() != expected_claimant
        || binding.recovery_expires_at_unix_ms() <= context.trusted_time_unix_ms
        || binding.store_fence() != &context.store_fence
        || recovery_claim.operation_id() != source.binding().operation_id()
        || recovery_claim.claimant_id().as_str() != binding.recovery_claimant_id()
        || recovery_claim.coordinator_lease_id().as_str() != binding.coordinator_lease_id()
        || recovery_claim.coordinator_lease_epoch() != binding.coordinator_lease_epoch()
        || recovery_claim.claimed_version() != binding.operation_version()
        || recovery_claim.expires_at_unix_ms() != binding.recovery_expires_at_unix_ms()
        || recovery_claim.store_fence() != binding.store_fence()
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let historical_lease_id = coordinator_lease_id_for_epoch(
        transaction,
        serving_owner,
        source.coordinator_lease_epoch(),
    )?;
    if &historical_lease_id != recovery_claim.coordinator_lease_id() {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(recovery_claim)
}

pub(super) fn ensure_no_reserved_terminal_stage(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<(), AdmissionOperationStoreError> {
    if crate::economic_state_cache::has_reserved_terminal_stage(transaction, operation_id.as_str())
        .map_err(map_economic_cache_error)?
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

pub(super) fn qualify_generic_channel_command(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    command: &AdmissionOperationCommand,
) -> Result<(), AdmissionOperationStoreError> {
    if !operation.binding().participant_requirements().channel {
        return Ok(());
    }
    if command
        .attachments()
        .iter()
        .any(|attachment| matches!(attachment, AdmissionAttachment::ChannelReservationDigest(_)))
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let retained = transaction
        .query_row(
            r#"
            SELECT reservation_digest, disposition
            FROM channel_reservation_records WHERE operation_id = ?1
            "#,
            [operation.binding().operation_id().as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    if retained
        .as_ref()
        .is_some_and(|(_, disposition)| disposition == "pending_anchor")
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let requires_live = command
        .next_state()
        .is_some_and(state_requires_channel_reservation)
        || state_requires_channel_reservation(operation.state());
    if requires_live {
        let Some((reservation_digest, disposition)) = retained else {
            return Err(AdmissionOperationStoreError::Fenced);
        };
        if disposition != "live"
            || operation
                .channel_reservation_digest()
                .is_none_or(|digest| digest.as_str() != reservation_digest)
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
    }
    Ok(())
}

fn state_requires_channel_reservation(state: AdmissionOperationState) -> bool {
    matches!(
        state,
        AdmissionOperationState::ReadyToDispatch
            | AdmissionOperationState::CapturePending
            | AdmissionOperationState::DispatchCommitted
            | AdmissionOperationState::Finalizing
            | AdmissionOperationState::Completed
            | AdmissionOperationState::CompensatedBeforeDispatch
            | AdmissionOperationState::NotAcceptedAfterDispatchCommit
            | AdmissionOperationState::OutcomeUnknownAfterDispatch
    )
}

pub(super) fn verify_payment_write_context(
    transaction: &Transaction<'_>,
    serving_owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    active_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionPaymentJournalError> {
    let stored = load_by_operation_id_tx(transaction, operation.binding().operation_id())
        .map_err(map_payment_operation_error)?
        .ok_or_else(|| {
            AdmissionPaymentJournalError::Invariant(
                "payment journal admission operation is absent".to_owned(),
            )
        })?;
    ensure_no_reserved_terminal_stage(transaction, operation.binding().operation_id())
        .map_err(map_payment_operation_error)?;
    if stored.operation != *operation {
        return Err(AdmissionPaymentJournalError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        serving_owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        active_fence,
    )
    .map_err(map_payment_operation_error)
}

pub(super) fn validate_payment_reconcile_binding(
    journal: &PaymentJournalRecord,
    transition: Option<&PaymentJournalTransition>,
    budget: &BudgetReconcileHoldRequest,
) -> Result<(), AdmissionPaymentJournalError> {
    journal
        .validate()
        .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
    budget
        .validate()
        .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
    let grant_index = usize::try_from(journal.grant_index).map_err(|_| {
        AdmissionPaymentJournalError::Invariant(
            "payment journal grant index exceeds the budget range".to_owned(),
        )
    })?;
    let hold_id = journal.hold_id.as_deref().ok_or_else(|| {
        AdmissionPaymentJournalError::Invariant("payment journal omitted hold_id".to_owned())
    })?;
    if budget.capability_id != journal.capability_id
        || budget.grant_index != grant_index
        || budget.exposed_cost_units != journal.amount_units
        || budget.hold_id.as_deref() != Some(hold_id)
        || budget.event_id.as_deref() != Some(format!("{hold_id}:reconcile").as_str())
    {
        return Err(AdmissionPaymentJournalError::Invariant(
            "budget reconciliation does not match the payment journal".to_owned(),
        ));
    }
    let realized_units = match transition {
        Some(PaymentJournalTransition::BeginCapture { amount_units }) => *amount_units,
        Some(PaymentJournalTransition::BeginRelease { .. }) => 0,
        Some(_) => {
            return Err(AdmissionPaymentJournalError::Invariant(
                "payment settlement can only begin with capture or release intent".to_owned(),
            ));
        }
        None => match (journal.rail_mode, journal.state, journal.settle_action) {
            (
                chio_kernel::payment::PaymentRailMode::PrepaidFinal,
                chio_kernel::payment::PaymentJournalState::Settled,
                None,
            ) => journal.amount_units,
            (
                chio_kernel::payment::PaymentRailMode::ReversibleHold,
                chio_kernel::payment::PaymentJournalState::Settling
                | chio_kernel::payment::PaymentJournalState::Settled,
                Some(chio_kernel::payment::PaymentSettleAction::Capture),
            ) => journal.settle_amount_units.ok_or_else(|| {
                AdmissionPaymentJournalError::Invariant(
                    "capturing payment journal omitted settlement amount".to_owned(),
                )
            })?,
            (
                chio_kernel::payment::PaymentRailMode::ReversibleHold,
                chio_kernel::payment::PaymentJournalState::Settling
                | chio_kernel::payment::PaymentJournalState::Settled,
                Some(chio_kernel::payment::PaymentSettleAction::Release),
            ) => 0,
            _ => {
                return Err(AdmissionPaymentJournalError::Invariant(
                    "payment journal has no replayable settlement intent".to_owned(),
                ));
            }
        },
    };
    if budget.realized_spend_units != realized_units {
        return Err(AdmissionPaymentJournalError::Invariant(
            "budget reconciliation spend does not match the payment intent".to_owned(),
        ));
    }
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct UntrustedAdmissionExactProjectionBindingV1 {
    operation_id: AdmissionOperationId,
    request_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    source_operation_version: u64,
    projected_operation_version: u64,
    projected_state: AdmissionOperationState,
    trusted_time_unix_ms: u64,
    coordinator_lease_id: AdmissionIdentifier,
    coordinator_lease_epoch: u64,
    store_fence: StoreMutationFence,
    retained_dispatch_commit:
        Option<chio_kernel::admission_operation::AdmissionDispatchCommitBindingV1>,
}

impl UntrustedAdmissionExactProjectionBindingV1 {
    fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        projected_state: AdmissionOperationState,
    ) -> Result<(), AdmissionOperationStoreError> {
        operation.validate()?;
        context.validate()?;
        let operation_is_projected = operation.state().is_terminal();
        let expected_source_version = if operation_is_projected {
            operation
                .version()
                .checked_sub(1)
                .ok_or_else(|| invariant("terminal operation version underflow"))?
        } else {
            operation.version()
        };
        let expected_projected_version = expected_source_version
            .checked_add(1)
            .ok_or_else(|| invariant("terminal operation version overflow"))?;
        if self.operation_id != *operation.binding().operation_id()
            || self.request_id != operation.replay_key().request_id
            || self.request_binding_hash != *operation.binding().request_binding_hash()
            || self.source_operation_version != expected_source_version
            || self.projected_operation_version != expected_projected_version
            || self.projected_state != projected_state
            || self.trusted_time_unix_ms != context.trusted_time_unix_ms
            || self.coordinator_lease_id != context.coordinator_lease_id
            || self.coordinator_lease_epoch != context.coordinator_lease_epoch
            || self.coordinator_lease_epoch != operation.coordinator_lease_epoch()
            || self.store_fence != context.store_fence
            || self.retained_dispatch_commit.as_ref() != operation.dispatch_commit()
            || context.operation_id != *operation.binding().operation_id()
            || context.request_id != operation.replay_key().request_id
            || context.expected_operation_version != expected_source_version
            || (operation_is_projected && operation.state() != projected_state)
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        Ok(())
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct UntrustedPaymentTerminalSourceV1 {
    binding: UntrustedAdmissionExactProjectionBindingV1,
    source_authority_digest: AdmissionDigest,
    source_record_id: AdmissionIdentifier,
    source_record_digest: AdmissionDigest,
    source_recorded_at_unix_ms: u64,
    consumer_receipt_id: AdmissionIdentifier,
    consumer_receipt_digest: AdmissionDigest,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct UntrustedPaymentTerminalEvidenceV1 {
    source: UntrustedPaymentTerminalSourceV1,
    payment_participant_id: AdmissionIdentifier,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UntrustedObservationAttemptZeroV1 {
    binding: UntrustedAdmissionExactProjectionBindingV1,
    pending: PendingSettlementObservation,
    consumer_receipt_id: AdmissionIdentifier,
    consumer_receipt_digest: AdmissionDigest,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

#[derive(serde::Deserialize)]
struct UntrustedTerminalParticipantProjectionV1 {
    terminal: String,
    evidence: serde_json::Value,
    payment_evidence: Option<UntrustedPaymentTerminalEvidenceV1>,
    observer_work: Option<UntrustedObservationAttemptZeroV1>,
}

struct AuthoritativeToolOutcomeBindingV1 {
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

pub(super) fn verify_payment_terminal_source<'a>(
    transaction: &Connection,
    operation: &AdmissionOperationV1,
    context: &chio_kernel::admission_operation::AdmissionProjectionContext,
    terminal_state: AdmissionOperationState,
    records: impl Iterator<Item = (&'a AdmissionIdentifier, &'a [u8])>,
    receipt_record: Option<&'a [u8]>,
    projection_json: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    let records = records.collect::<Vec<_>>();
    let requires_payment = operation.binding().participant_requirements().payment;
    let authoritative_outcome = if terminal_state == AdmissionOperationState::DeniedAfterDelivery {
        Some(verify_denied_participant_outcome_bindings(
            transaction,
            operation,
            context,
            &records,
            receipt_record,
            projection_json,
        )?)
    } else {
        None
    };
    if terminal_state == AdmissionOperationState::OutcomeUnknownAfterDispatch {
        if !records.is_empty() {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        if !requires_payment {
            return Ok(());
        }
        let journal = crate::budget_store::load_payment_journal(
            transaction,
            operation.binding().operation_id().as_str(),
        )
        .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?
        .ok_or_else(|| {
            AdmissionOperationStoreError::Invariant(
                "unknown payment outcome lost its authorization journal".to_owned(),
            )
        })?;
        journal
            .validate()
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
        if journal.state != chio_kernel::payment::PaymentJournalState::Authorized
            || journal.settle_action.is_some()
            || journal.settle_amount_units.is_some()
            || journal.release_authority.is_some()
            || journal.transaction_id.is_some()
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "unknown payment outcome must retain an unmoved authorization".to_owned(),
            ));
        }
        return Ok(());
    }
    if terminal_state == AdmissionOperationState::CompensatedBeforeDispatch {
        // A pre-dispatch compensation carries a release proof, not a
        // payment-terminal record. The money outcome lives in the fenced
        // journal: either the hold was cancelled before any rail
        // authorization existed (closed, nothing assigned) or an
        // authorized hold was released to a settled zero.
        if !records.is_empty() {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        if !requires_payment {
            return Ok(());
        }
        let journal = crate::budget_store::load_payment_journal(
            transaction,
            operation.binding().operation_id().as_str(),
        )
        .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
        let payment_acquired = operation.payment_participant_id().is_some();
        let Some(journal) = journal else {
            if payment_acquired {
                return Err(AdmissionOperationStoreError::Invariant(
                    "pre-dispatch compensation lost its acquired payment journal".to_owned(),
                ));
            }
            return Ok(());
        };
        if !payment_acquired {
            return Err(AdmissionOperationStoreError::Invariant(
                "pre-dispatch compensation found a journal for a payment participant that was never acquired"
                    .to_owned(),
            ));
        }
        journal
            .validate()
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
        let cancelled_before_authorization = journal.state
            == chio_kernel::payment::PaymentJournalState::Closed
            && journal.authorization_id.is_none()
            && journal.settle_action.is_none();
        let released_after_authorization = journal.state
            == chio_kernel::payment::PaymentJournalState::Settled
            && journal.settle_action == Some(chio_kernel::payment::PaymentSettleAction::Release);
        if !cancelled_before_authorization && !released_after_authorization {
            return Err(AdmissionOperationStoreError::Invariant(
                "pre-dispatch compensation must cancel or release its payment hold".to_owned(),
            ));
        }
        return Ok(());
    }
    if terminal_state == AdmissionOperationState::DeniedAfterDelivery {
        // A rejected delivery releases the open hold to a contractual zero
        // charge, and the terminal carries the payment-terminal record
        // binding that released journal, exactly as a completed capture
        // binds its settled journal.
        if records.len() != usize::from(requires_payment) {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        let Some((record_id, bytes)) = records.first() else {
            return Ok(());
        };
        let journal = crate::budget_store::load_payment_journal(
            transaction,
            operation.binding().operation_id().as_str(),
        )
        .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?
        .ok_or_else(|| {
            AdmissionOperationStoreError::Invariant(
                "delivery-denied terminal lost its payment journal".to_owned(),
            )
        })?;
        journal
            .validate()
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
        if journal.state != chio_kernel::payment::PaymentJournalState::Settled
            || journal.settle_action != Some(chio_kernel::payment::PaymentSettleAction::Release)
            || journal
                .release_authority
                .as_ref()
                .map(|authority| authority.kind)
                != Some(chio_kernel::payment::PaymentReleaseAuthorityKind::ContractualZeroCharge)
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "delivery-denied terminal must release its hold at a contractual zero charge"
                    .to_owned(),
            ));
        }
        return verify_payment_terminal_record(
            record_id,
            bytes,
            PaymentTerminalVerificationV1 {
                receipt_record,
                operation,
                context,
                terminal_state,
                journal: &journal,
                authoritative_outcome: authoritative_outcome.as_ref(),
            },
        );
    }
    if records.len() != usize::from(requires_payment) {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    let Some((record_id, bytes)) = records.first() else {
        return Ok(());
    };
    let journal = crate::budget_store::load_payment_journal(
        transaction,
        operation.binding().operation_id().as_str(),
    )
    .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?
    .ok_or_else(|| {
        AdmissionOperationStoreError::Invariant(
            "terminal payment source journal is absent".to_owned(),
        )
    })?;
    journal
        .validate()
        .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
    if !matches!(
        journal.state,
        chio_kernel::payment::PaymentJournalState::Settled
            | chio_kernel::payment::PaymentJournalState::Closed
    ) {
        return Err(AdmissionOperationStoreError::Invariant(
            "terminal payment source journal is not settled".to_owned(),
        ));
    }
    verify_payment_terminal_record(
        record_id,
        bytes,
        PaymentTerminalVerificationV1 {
            receipt_record,
            operation,
            context,
            terminal_state,
            journal: &journal,
            authoritative_outcome: None,
        },
    )
}

struct PaymentTerminalVerificationV1<'a> {
    receipt_record: Option<&'a [u8]>,
    operation: &'a AdmissionOperationV1,
    context: &'a chio_kernel::admission_operation::AdmissionProjectionContext,
    terminal_state: AdmissionOperationState,
    journal: &'a chio_kernel::payment::PaymentJournalRecord,
    authoritative_outcome: Option<&'a AuthoritativeToolOutcomeBindingV1>,
}

/// Cross-check one payment-terminal projection record against the fenced
/// journal it claims to bind: the participant identity, the source record
/// naming, the journal digest, the fence authority digest, and a recording
/// time inside the journal's lifetime.
fn verify_payment_terminal_record(
    record_id: &AdmissionIdentifier,
    bytes: &[u8],
    verification: PaymentTerminalVerificationV1<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let PaymentTerminalVerificationV1 {
        receipt_record,
        operation,
        context,
        terminal_state,
        journal,
        authoritative_outcome,
    } = verification;
    let evidence: UntrustedPaymentTerminalEvidenceV1 =
        serde_json::from_slice(bytes).map_err(|error| {
            AdmissionOperationStoreError::Invariant(format!(
                "terminal payment evidence is invalid JSON: {error}"
            ))
        })?;
    evidence
        .source
        .binding
        .validate_against(operation, context, terminal_state)?;
    let receipt_bytes = receipt_record.ok_or_else(|| {
        AdmissionOperationStoreError::Invariant(
            "terminal payment evidence has no consumer receipt".to_owned(),
        )
    })?;
    let receipt: ChioReceipt = serde_json::from_slice(receipt_bytes).map_err(|error| {
        AdmissionOperationStoreError::Invariant(format!(
            "terminal payment consumer receipt is invalid JSON: {error}"
        ))
    })?;
    let expected_source_record_id = format!("payment:{}", journal.operation_id);
    let journal_digest = sha256_hex(
        &canonical_json_bytes(&journal)
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?,
    );
    let authority_digest = sha256_hex(
        &canonical_json_bytes(&context.store_fence)
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?,
    );
    let receipt_digest = sha256_hex(
        &canonical_json_bytes(&receipt)
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?,
    );
    let outcome_id = operation
        .tool_outcome_id()
        .ok_or_else(|| invariant("terminal payment evidence lost its tool outcome"))?;
    if record_id.as_str() != operation.binding().operation_id().as_str()
        || evidence.payment_participant_id.as_str() != operation.binding().operation_id().as_str()
        || evidence.source.source_record_id.as_str() != expected_source_record_id
        || evidence.source.source_record_digest.as_str() != journal_digest
        || evidence.source.source_authority_digest.as_str() != authority_digest
        || evidence.source.source_recorded_at_unix_ms < journal.created_at_unix_ms
        || evidence.source.source_recorded_at_unix_ms > context.trusted_time_unix_ms
        || evidence.source.consumer_receipt_id.as_str() != receipt.id
        || evidence.source.consumer_receipt_digest.as_str() != receipt_digest
        || evidence.source.outcome_id != *outcome_id
        || evidence.source.outcome_version == 0
        || evidence.source.outcome_version > ((1_u64 << 53) - 1)
        || authoritative_outcome.is_some_and(|authoritative| {
            evidence.source.outcome_id != authoritative.outcome_id
                || evidence.source.outcome_version != authoritative.outcome_version
        })
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    Ok(())
}

fn verify_denied_participant_outcome_bindings(
    transaction: &Connection,
    operation: &AdmissionOperationV1,
    context: &chio_kernel::admission_operation::AdmissionProjectionContext,
    payment_records: &[(&AdmissionIdentifier, &[u8])],
    receipt_record: Option<&[u8]>,
    projection_json: &[u8],
) -> Result<AuthoritativeToolOutcomeBindingV1, AdmissionOperationStoreError> {
    let projection: UntrustedTerminalParticipantProjectionV1 =
        serde_json::from_slice(projection_json).map_err(|error| {
            invariant(format!(
                "delivery-denied participant projection is invalid JSON: {error}"
            ))
        })?;
    if projection.terminal != "denied_after_delivery" {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    let receipt_bytes = receipt_record
        .ok_or_else(|| invariant("delivery-denied participant projection has no receipt record"))?;
    let mut evidence = projection
        .evidence
        .as_object()
        .cloned()
        .ok_or_else(|| invariant("delivery-denied receipt evidence is not an object"))?;
    if evidence
        .remove("kind")
        .and_then(|kind| kind.as_str().map(str::to_owned))
        .as_deref()
        != Some("receipt")
        || canonical_json_bytes(&serde_json::Value::Object(evidence))
            .map_err(|error| invariant(error.to_string()))?
            != receipt_bytes
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    let receipt: ChioReceipt = serde_json::from_slice(receipt_bytes).map_err(|error| {
        invariant(format!(
            "delivery-denied participant receipt is invalid JSON: {error}"
        ))
    })?;
    let receipt_digest =
        sha256_hex(&canonical_json_bytes(&receipt).map_err(|error| invariant(error.to_string()))?);
    let authoritative = load_authoritative_tool_outcome_binding(transaction, operation)?;
    match (&projection.payment_evidence, payment_records) {
        (None, []) => {}
        (Some(evidence), [(_, record_json)]) => {
            evidence.source.binding.validate_against(
                operation,
                context,
                AdmissionOperationState::DeniedAfterDelivery,
            )?;
            verify_participant_outcome_binding(
                &evidence.source.outcome_id,
                evidence.source.outcome_version,
                &authoritative,
            )?;
            let canonical =
                canonical_json_bytes(evidence).map_err(|error| invariant(error.to_string()))?;
            if canonical != *record_json {
                return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
            }
        }
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into()),
    }
    if let Some(observer) = &projection.observer_work {
        observer.binding.validate_against(
            operation,
            context,
            AdmissionOperationState::DeniedAfterDelivery,
        )?;
        verify_participant_outcome_binding(
            &observer.outcome_id,
            observer.outcome_version,
            &authoritative,
        )?;
        if observer.pending.next_visible_at_ms != context.trusted_time_unix_ms
            || observer.consumer_receipt_id.as_str() != receipt.id
            || observer.consumer_receipt_digest.as_str() != receipt_digest
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
    }
    Ok(authoritative)
}

fn verify_participant_outcome_binding(
    outcome_id: &AdmissionDigest,
    outcome_version: u64,
    authoritative: &AuthoritativeToolOutcomeBindingV1,
) -> Result<(), AdmissionOperationStoreError> {
    if outcome_id != &authoritative.outcome_id || outcome_version != authoritative.outcome_version {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    Ok(())
}

fn load_authoritative_tool_outcome_binding(
    transaction: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<AuthoritativeToolOutcomeBindingV1, AdmissionOperationStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT outcome_id, request_id, raw_output_digest, outcome_version,
                   lifecycle_digest, outcome_json, recorded_at_unix_ms
            FROM tool_outcomes WHERE operation_id = ?1
            "#,
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((outcome_id, request_id, raw_digest, version, lifecycle, encoded, recorded_at)) = row
    else {
        return Err(invariant(
            "delivery-denied participant evidence lost its persisted tool outcome",
        ));
    };
    let persisted: chio_kernel::tool_outcome::PersistedToolOutcomeRecordV1 =
        serde_json::from_slice(&encoded)
            .map_err(|error| invariant(format!("tool outcome decode failed: {error}")))?;
    let record = chio_kernel::tool_outcome::ToolOutcomeRecordV1::from_persisted(persisted)
        .map_err(|error| invariant(error.to_string()))?;
    record
        .validate_against(operation)
        .map_err(|error| invariant(error.to_string()))?;
    let persisted = record.to_persisted();
    if record.outcome_id().as_str() != outcome_id
        || persisted.request_id.as_str() != request_id
        || record.raw_output_digest().as_str() != raw_digest
        || record.version() != stored_u64(version, "outcome_version")?
        || record.lifecycle_digest().as_str() != lifecycle
        || record.recorded_at_unix_ms() != stored_u64(recorded_at, "recorded_at_unix_ms")?
        || canonical_json_bytes(&persisted).map_err(|error| invariant(error.to_string()))?
            != encoded
        || operation.tool_outcome_id() != Some(record.outcome_id())
    {
        return Err(invariant(
            "persisted tool outcome differs from its authoritative columns",
        ));
    }
    Ok(AuthoritativeToolOutcomeBindingV1 {
        outcome_id: record.outcome_id().clone(),
        outcome_version: record.version(),
    })
}

#[cfg(test)]
mod participant_outcome_binding_tests {
    use super::*;

    #[test]
    fn participant_versions_must_equal_the_authoritative_outcome(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let outcome_id = AdmissionDigest::try_new("outcome_id", "a".repeat(64))?;
        let other_outcome_id = AdmissionDigest::try_new("outcome_id", "b".repeat(64))?;
        let authoritative = AuthoritativeToolOutcomeBindingV1 {
            outcome_id: outcome_id.clone(),
            outcome_version: 7,
        };

        assert!(verify_participant_outcome_binding(&outcome_id, 7, &authoritative).is_ok());
        assert!(verify_participant_outcome_binding(&outcome_id, 8, &authoritative).is_err());
        assert!(verify_participant_outcome_binding(&other_outcome_id, 7, &authoritative).is_err());
        Ok(())
    }
}

pub(crate) fn advance_tool_outcome_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    outcome_id: AdmissionDigest,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, expected.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    ensure_no_reserved_terminal_stage(transaction, expected.binding().operation_id())?;
    if stored.operation != *expected || trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        recovery_lease.store_fence(),
    )?;
    let command = AdmissionOperationCommand::new(
        expected.binding().operation_id().clone(),
        expected.version(),
        recovery_lease.clone(),
        vec![AdmissionAttachment::ToolOutcomeId(outcome_id.clone())],
        Some(AdmissionOperationState::Finalizing),
        None,
        None,
    )?;
    let updated = expected
        .apply_command(&command, trusted_now_unix_ms)?
        .into_operation();
    if updated.state() != AdmissionOperationState::Finalizing
        || updated.tool_outcome_id() != Some(&outcome_id)
    {
        return Err(invariant(
            "tool outcome transition did not bind the finalizing operation",
        ));
    }
    let encoded = encode_operation(&updated)?;
    let changed = transaction
        .execute(
            r#"
            UPDATE admission_operations
            SET operation_json = ?1, state = ?2, terminal = 0,
                coordinator_lease_epoch = ?3, version = ?4,
                updated_at_unix_ms = ?5
            WHERE operation_id = ?6 AND version = ?7 AND terminal = 0
            "#,
            params![
                &encoded,
                state_name(updated.state()),
                sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                sqlite_i64(updated.version(), "version")?,
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                updated.binding().operation_id().as_str(),
                sqlite_i64(expected.version(), "expected_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    commit_chain::append_operation_commit_with_participant(
        transaction,
        &updated,
        &encoded,
        stored.recovery_claim.as_ref(),
        "compare_and_swap",
        Some(participant_digest),
        owner,
        trusted_now_unix_ms,
    )?;
    Ok(updated)
}

pub(crate) fn advance_budget_capture_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    if expected.state() != AdmissionOperationState::CapturePending {
        return Err(invariant(
            "combined budget capture requires a CapturePending operation",
        ));
    }
    let command = AdmissionOperationCommand::new(
        expected.binding().operation_id().clone(),
        expected.version(),
        recovery_lease.clone(),
        Vec::new(),
        Some(AdmissionOperationState::DispatchCommitted),
        None,
        None,
    )?;
    let updated = expected
        .apply_command(&command, trusted_now_unix_ms)?
        .into_operation();
    advance_participant_bound_operation_tx(
        transaction,
        owner,
        expected,
        recovery_lease,
        &updated,
        participant_digest,
        trusted_now_unix_ms,
    )
}

pub(crate) struct BudgetAuthorizationAdvance<'a> {
    pub(crate) expected: &'a AdmissionOperationV1,
    pub(crate) recovery_lease: &'a AdmissionRecoveryLease,
    pub(crate) hold_id: &'a str,
    pub(crate) payment_required: bool,
    pub(crate) credit_exposure_reservation_digest: Option<&'a str>,
    pub(crate) participant_digest: &'a str,
    pub(crate) trusted_now_unix_ms: u64,
}

pub(crate) fn advance_budget_authorization_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    advance: BudgetAuthorizationAdvance<'_>,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let BudgetAuthorizationAdvance {
        expected,
        recovery_lease,
        hold_id,
        payment_required,
        credit_exposure_reservation_digest,
        participant_digest,
        trusted_now_unix_ms,
    } = advance;
    let requirements = expected.binding().participant_requirements();
    let required_state = if requirements.broker_attempt {
        AdmissionOperationState::BrokerAttemptRegistered
    } else {
        AdmissionOperationState::Prepared
    };
    if expected.state() != required_state
        || !requirements.budget_capture
        || requirements.payment != payment_required
        || requirements.credit_exposure != credit_exposure_reservation_digest.is_some()
    {
        return Err(invariant(
            "combined budget authorization does not match operation requirements",
        ));
    }
    let mut attachments = vec![AdmissionAttachment::BudgetHoldId(
        AdmissionIdentifier::try_new("budget_hold_id", hold_id)?,
    )];
    if payment_required {
        attachments.push(AdmissionAttachment::PaymentParticipantId(
            AdmissionIdentifier::try_new(
                "payment_participant_id",
                expected.binding().operation_id().as_str(),
            )?,
        ));
    }
    if let Some(reservation_digest) = credit_exposure_reservation_digest {
        attachments.push(AdmissionAttachment::CreditExposureReservationDigest(
            AdmissionDigest::try_new(
                "credit_exposure_reservation_digest",
                reservation_digest.to_owned(),
            )?,
        ));
    }
    let command = AdmissionOperationCommand::new(
        expected.binding().operation_id().clone(),
        expected.version(),
        recovery_lease.clone(),
        attachments,
        Some(AdmissionOperationState::BudgetAuthorized),
        None,
        None,
    )?;
    let updated = expected
        .apply_command(&command, trusted_now_unix_ms)?
        .into_operation();
    advance_participant_bound_operation_tx(
        transaction,
        owner,
        expected,
        recovery_lease,
        &updated,
        participant_digest,
        trusted_now_unix_ms,
    )
}

pub(crate) fn verify_budget_authorization_replay_tx(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    hold_id: &str,
    payment_required: bool,
    credit_exposure_reservation_digest: Option<&str>,
    participant_digest: &str,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let requirements = operation.binding().participant_requirements();
    if !matches!(
        operation.state(),
        AdmissionOperationState::BudgetAuthorized
            | AdmissionOperationState::ReadyToDispatch
            | AdmissionOperationState::CapturePending
            | AdmissionOperationState::DispatchCommitted
            | AdmissionOperationState::Finalizing
            | AdmissionOperationState::Completed
    ) || !requirements.budget_capture
        || requirements.payment != payment_required
        || requirements.credit_exposure != credit_exposure_reservation_digest.is_some()
        || operation
            .budget_hold_id()
            .is_none_or(|bound| bound.as_str() != hold_id)
        || operation
            .credit_exposure_reservation_digest()
            .map(AdmissionDigest::as_str)
            != credit_exposure_reservation_digest
    {
        return Err(invariant(
            "combined budget authorization replay does not match operation requirements",
        ));
    }
    let exact_commit = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1
            FROM admission_operation_commits
            WHERE operation_id = ?1 AND mutation_kind = ?2
              AND participant_digest = ?3
            "#,
            params![
                operation.binding().operation_id().as_str(),
                COMBINED_CAPTURE_OPERATION_MUTATION_KIND,
                participant_digest,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exact_commit {
        return Err(invariant(
            "combined budget authorization replay lost its exact participant commit",
        ));
    }
    Ok(operation.clone())
}

fn advance_participant_bound_operation_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    updated: &AdmissionOperationV1,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, expected.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;

    if stored.operation == *updated {
        let exact_commit = transaction
            .query_row(
                r#"
                SELECT COUNT(*) = 1
                FROM admission_operation_commits
                WHERE operation_id = ?1 AND operation_version = ?2
                  AND mutation_kind = ?3 AND participant_digest = ?4
                "#,
                params![
                    updated.binding().operation_id().as_str(),
                    sqlite_i64(updated.version(), "operation_version")?,
                    COMBINED_CAPTURE_OPERATION_MUTATION_KIND,
                    participant_digest,
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?;
        if !exact_commit {
            return Err(invariant(
                "participant-bound operation lost its exact projection commit",
            ));
        }
        return Ok(updated.clone());
    }
    ensure_no_reserved_terminal_stage(transaction, expected.binding().operation_id())?;
    if stored.operation != *expected || trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        recovery_lease.store_fence(),
    )?;
    let encoded = encode_operation(updated)?;
    let changed = transaction
        .execute(
            r#"
            UPDATE admission_operations
            SET operation_json = ?1, state = ?2, terminal = 0,
                coordinator_lease_epoch = ?3, version = ?4,
                updated_at_unix_ms = ?5
            WHERE operation_id = ?6 AND version = ?7 AND terminal = 0
            "#,
            params![
                &encoded,
                state_name(updated.state()),
                sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                sqlite_i64(updated.version(), "operation_version")?,
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                updated.binding().operation_id().as_str(),
                sqlite_i64(expected.version(), "expected_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    commit_chain::append_operation_commit_with_participant(
        transaction,
        updated,
        &encoded,
        stored.recovery_claim.as_ref(),
        COMBINED_CAPTURE_OPERATION_MUTATION_KIND,
        Some(participant_digest),
        owner,
        trusted_now_unix_ms,
    )?;
    Ok(updated.clone())
}

pub(crate) fn append_participant_update_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, expected.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    ensure_no_reserved_terminal_stage(transaction, expected.binding().operation_id())?;
    if stored.operation != *expected || trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        recovery_lease.store_fence(),
    )?;
    let changed = transaction
        .execute(
            r#"
            UPDATE admission_operations
            SET updated_at_unix_ms = ?1
            WHERE operation_id = ?2 AND version = ?3 AND terminal = 0
            "#,
            params![
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                expected.binding().operation_id().as_str(),
                sqlite_i64(expected.version(), "expected_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let encoded = encode_operation(expected)?;
    commit_chain::append_operation_commit_with_participant(
        transaction,
        expected,
        &encoded,
        stored.recovery_claim.as_ref(),
        "participant_update",
        Some(participant_digest),
        owner,
        trusted_now_unix_ms,
    )
}

pub(crate) fn verify_participant_recovery_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, expected.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    if stored.operation != *expected || trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        recovery_lease.store_fence(),
    )
}

pub(crate) fn finalize_channel_reservation_operation_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    command: &AdmissionOperationCommand,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, expected.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    let reservation_digest = command
        .attachments()
        .iter()
        .find_map(|attachment| match attachment {
            AdmissionAttachment::ChannelReservationDigest(digest) => Some(digest.as_str()),
            _ => None,
        })
        .ok_or_else(|| invariant("channel finalization omitted its reservation digest"))?;
    let exact_pending = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1 FROM channel_reservation_records
            WHERE operation_id = ?1 AND reservation_digest = ?2
              AND disposition = 'pending_anchor'
            "#,
            params![
                expected.binding().operation_id().as_str(),
                reservation_digest
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exact_pending
        || command.operation_id() != expected.binding().operation_id()
        || command.expected_version() != expected.version()
        || command.next_state() != Some(AdmissionOperationState::ReadyToDispatch)
        || command.attachments().len() != 1
        || stored.operation != *expected
        || trusted_now_unix_ms < stored.updated_at_unix_ms
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        owner,
        &stored,
        command.recovery_lease().untrusted_claim(),
        trusted_now_unix_ms,
        command.recovery_lease().store_fence(),
    )?;
    let AdmissionCommandResult::Applied(updated) =
        expected.apply_command(command, trusted_now_unix_ms)?
    else {
        return Err(AdmissionOperationStoreError::Fenced);
    };
    let encoded = encode_operation(&updated)?;
    let changed = transaction
        .execute(
            r#"
            UPDATE admission_operations
            SET operation_json = ?1, state = ?2, terminal = 0,
                coordinator_lease_epoch = ?3, version = ?4,
                updated_at_unix_ms = ?5
            WHERE operation_id = ?6 AND version = ?7 AND terminal = 0
            "#,
            params![
                &encoded,
                state_name(updated.state()),
                sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                sqlite_i64(updated.version(), "operation_version")?,
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                updated.binding().operation_id().as_str(),
                sqlite_i64(expected.version(), "expected_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    append_operation_commit_with_participant(
        transaction,
        &updated,
        &encoded,
        stored.recovery_claim.as_ref(),
        "channel_reservation_finalized",
        Some(participant_digest),
        owner,
        trusted_now_unix_ms,
    )?;
    Ok(updated)
}
