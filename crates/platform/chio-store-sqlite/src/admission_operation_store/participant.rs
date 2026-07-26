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
                    .then_some(record.canonical_json())
            }),
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
                .then_some(record.canonical_json())
        }),
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

pub(super) fn verify_payment_terminal_source<'a>(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    context: &chio_kernel::admission_operation::AdmissionProjectionContext,
    terminal_state: AdmissionOperationState,
    records: impl Iterator<Item = &'a [u8]>,
) -> Result<(), AdmissionOperationStoreError> {
    let records = records.collect::<Vec<_>>();
    let requires_payment = operation.binding().participant_requirements().payment;
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
    if records.len() != usize::from(requires_payment) {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    let Some(bytes) = records.first() else {
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
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        AdmissionOperationStoreError::Invariant(format!(
            "terminal payment evidence is invalid JSON: {error}"
        ))
    })?;
    let source = value.get("source").and_then(serde_json::Value::as_object);
    let expected_source_record_id = format!("payment:{}", journal.operation_id);
    let journal_digest = sha256_hex(
        &canonical_json_bytes(&journal)
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?,
    );
    let authority_digest = sha256_hex(
        &canonical_json_bytes(&context.store_fence)
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?,
    );
    let source_recorded_at = source
        .and_then(|source| source.get("source_recorded_at_unix_ms"))
        .and_then(serde_json::Value::as_u64);
    if value
        .get("payment_participant_id")
        .and_then(serde_json::Value::as_str)
        != Some(operation.binding().operation_id().as_str())
        || source
            .and_then(|source| source.get("source_record_id"))
            .and_then(serde_json::Value::as_str)
            != Some(expected_source_record_id.as_str())
        || source
            .and_then(|source| source.get("source_record_digest"))
            .and_then(serde_json::Value::as_str)
            != Some(journal_digest.as_str())
        || source
            .and_then(|source| source.get("source_authority_digest"))
            .and_then(serde_json::Value::as_str)
            != Some(authority_digest.as_str())
        || source_recorded_at.is_none_or(|recorded_at| {
            recorded_at < journal.created_at_unix_ms || recorded_at > context.trusted_time_unix_ms
        })
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    Ok(())
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
