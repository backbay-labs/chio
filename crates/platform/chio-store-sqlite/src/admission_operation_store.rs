use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::economic_continuity::VerifiedEconomicStateBatchAdvance;
use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
use chio_core::{sha256_hex, StoreMutationFence};
#[cfg(test)]
use chio_credit::obligation::CreditExposureReservationRequest;
use chio_credit::obligation::{
    CreditExposureReservationRecordV1, ObligationAtomV1, ObligationDispositionRecordV1,
    ObligationSettlementLifecycleV1,
};
use chio_kernel::admission_operation::{
    AdmissionAttachment, AdmissionBeginResult, AdmissionCaptureError, AdmissionCommandResult,
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationCommand, AdmissionOperationError,
    AdmissionOperationId, AdmissionOperationKind, AdmissionOperationState, AdmissionOperationStore,
    AdmissionOperationStoreError, AdmissionOperationV1, AdmissionProjectionCapabilities,
    AdmissionProjectionContext, AdmissionProjectionManifestV1, AdmissionProjectionRecordKind,
    AdmissionRecoveryLease, AdmissionReplayClassification, AdmissionReplayKey, AdmissionTerminal,
    AdmissionTerminalProjection, AdmissionTerminalReplay, CanonicalAdmissionProjectionRecord,
    CanonicalAdmissionTerminalProjection, PersistedAdmissionOperationV1,
    QualifiedAdmissionOperationStore, SideEffectClass, SignedAdmissionTerminalProjectionV1,
    UntrustedAdmissionRecoveryClaim, VerifiedAdmissionTerminalProjectionRecordV1,
    VerifiedAdmissionTerminalProjectionV1,
};
use chio_kernel::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureInvocationRequest,
    BudgetReconcileHoldRequest, BudgetStoreError,
};
use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalTransition};
use chio_kernel::receipt_store::{
    AdmissionPaymentJournalAdvance, AdmissionPaymentJournalError, AdmissionPaymentSettlement,
    AdmissionPaymentSettlementBegin, AuthorizationReceiptConsumption, PendingSettlementObservation,
    ReceiptStore, ReceiptStoreError,
};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};

mod commit_chain;
mod credit_exposure;
mod errors;
mod factor_assignment;
mod obligation;
mod participant;
mod projection;
mod schema;
mod store;
mod threshold_approval;

use commit_chain::append_operation_commit;
pub(crate) use commit_chain::{
    append_operation_commit_with_participant, load_admission_commit_head,
    verify_admission_commit_chain, verify_admission_commit_suffix, AdmissionCommitHead,
    GENESIS_CHAIN_DIGEST,
};
pub use credit_exposure::CreditExposureAccountSnapshot;
pub(crate) use credit_exposure::{
    apply_credit_exposure_terminal_tx, load_credit_exposure_reservation_tx,
    reserve_credit_exposure_tx,
};
use errors::*;
pub use factor_assignment::{
    DurableFactorAssignmentResultV1, FactorAssignmentAuthorityRegistryV1,
    FactorAssignmentAuthoritySetHeadV1, FactorAssignmentCommitV1,
    FactorAssignmentSigningAuthorityV1, FactorAssignmentVerificationAuthorityV1,
    SqliteFactorAssignmentStore, StoredFactorAssignmentResultV1,
};
use obligation::load_durable_obligation;
pub(crate) use participant::{
    advance_budget_authorization_tx, advance_budget_capture_tx, advance_tool_outcome_tx,
    append_participant_update_tx, finalize_channel_reservation_operation_tx,
    verify_budget_authorization_replay_tx, verify_participant_recovery_tx,
    BudgetAuthorizationAdvance,
};
use participant::{
    ensure_no_reserved_terminal_stage, qualify_generic_channel_command,
    validate_payment_reconcile_binding, verify_payment_terminal_source,
    verify_payment_write_context,
};
use projection::{
    ensure_projection_absent, full_projection_capabilities, insert_terminal_projection,
    insert_verified_terminal_projection, projected_terminal_state, terminal_from_operation,
    validate_canonical_projection_size, verify_exact_signed_terminal_replay,
    verify_exact_terminal_replay, verify_stored_terminal_projection,
};
use schema::{coordinator_lease_id_for_epoch, recovery_claim_digest, verify_latest_commit};
pub(crate) use schema::{
    initialize_admission_operation_schema, validate_trusted_time, verify_active_owner,
    verify_admission_operation_invariants, verify_trusted_time,
};

const ADMISSION_OPERATION_SCHEMA_KEY: &str = "admission_operation";
pub(crate) const ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION: i32 = 9;
const ADMISSION_OPERATION_SCHEMA_ANCHORS: &[&str] = &[
    "admission_operations",
    "admission_operation_commits",
    "threshold_approval_proposals",
    "chio_serving_owner",
    "capability_grant_budgets",
];
const MAX_PERSISTED_OPERATION_BYTES: usize = 256 * 1024;
const MAX_TERMINAL_PROJECTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_TERMINAL_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_TERMINAL_RECORD_BYTES: usize = 1024 * 1024;
const MAX_TERMINAL_RECORDS: usize = 32;
const MAX_RECOVERY_BATCH: usize = 256;
const MAX_TRUSTED_UNIX_MS: u64 = (1_u64 << 53) - 1;
const MAX_TRUSTED_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
const MAX_RECOVERY_LEASE_DURATION_MS: u64 = 5 * 60 * 1_000;
const COMBINED_CAPTURE_OPERATION_MUTATION_KIND: &str = "compare_and_swap";

const ADMISSION_OPERATION_SCHEMA: &str = include_str!("admission_operation_store.sql");

#[derive(Clone)]
pub struct SqliteAdmissionOperationStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableObligationV1 {
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    settlement_lifecycle: ObligationSettlementLifecycleV1,
    head_sequence: u64,
    head_digest: String,
    snapshot_version: u64,
    resource_fence: u64,
}

impl DurableObligationV1 {
    #[must_use]
    pub const fn atom(&self) -> &ObligationAtomV1 {
        &self.atom
    }

    #[must_use]
    pub const fn disposition(&self) -> &ObligationDispositionRecordV1 {
        &self.disposition
    }

    #[must_use]
    pub const fn settlement_lifecycle(&self) -> &ObligationSettlementLifecycleV1 {
        &self.settlement_lifecycle
    }

    #[must_use]
    pub const fn head_sequence(&self) -> u64 {
        self.head_sequence
    }

    #[must_use]
    pub fn head_digest(&self) -> &str {
        &self.head_digest
    }

    #[must_use]
    pub const fn snapshot_version(&self) -> u64 {
        self.snapshot_version
    }

    #[must_use]
    pub const fn resource_fence(&self) -> u64 {
        self.resource_fence
    }
}

impl SqliteAdmissionOperationStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, AdmissionOperationStoreError> {
        self.connection.lock().map_err(|_| {
            AdmissionOperationStoreError::Invariant(
                "sqlite admission operation lock poisoned".to_string(),
            )
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, AdmissionOperationStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
        fence: Option<&StoreMutationFence>,
    ) -> Result<Transaction<'a>, AdmissionOperationStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, fence)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        Ok(transaction)
    }

    fn sync_after_write(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(map_owner_error)
    }

    fn commit_write(
        &self,
        transaction: Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        transaction.commit().map_err(|error| {
            map_owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite admission operation commit outcome is unknown: {error}"
            )))
        })
    }

    pub fn load_obligation(
        &self,
        obligation_id: &str,
    ) -> Result<Option<DurableObligationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_durable_obligation(&transaction, obligation_id)
    }

    #[cfg(test)]
    pub(crate) fn provision_credit_exposure_account(
        &self,
        request: &CreditExposureReservationRequest,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<CreditExposureAccountSnapshot, AdmissionOperationStoreError> {
        if active_fence != &self.serving_owner.fence {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        request
            .validate()
            .map_err(|error| invariant(error.to_string()))?;
        request
            .authorities
            .ensure_current_at(trusted_now_unix_ms / 1_000)
            .map_err(|error| invariant(error.to_string()))?;
        request
            .credit_facility_bind
            .ensure_current_at(trusted_now_unix_ms)
            .map_err(|error| invariant(error.to_string()))?;
        let bind = request.credit_facility_bind.body();
        let reservation = CreditExposureReservationRecordV1::prepare_reserved(
            request,
            bind.expected_exposure_version()
                .checked_add(1)
                .ok_or_else(|| invariant("credit exposure account version overflowed"))?,
            bind.expected_exposure_fence()
                .checked_add(1)
                .ok_or_else(|| invariant("credit exposure resource fence overflowed"))?,
        )
        .map_err(|error| invariant(error.to_string()))?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(active_fence))?;
        let snapshot = credit_exposure::initialize_credit_exposure_account_tx(
            &transaction,
            &reservation,
            0,
            0,
            active_fence,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(snapshot)
    }

    pub fn load_credit_exposure_account(
        &self,
        debtor_id: &str,
        scope_digest: &str,
        currency: &str,
    ) -> Result<Option<CreditExposureAccountSnapshot>, AdmissionOperationStoreError> {
        AdmissionIdentifier::try_new("credit_exposure_debtor_id", debtor_id.to_owned())?;
        AdmissionDigest::try_new("credit_exposure_scope_digest", scope_digest.to_owned())?;
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(invariant("credit exposure currency is invalid"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        credit_exposure::load_credit_exposure_account_tx(
            &transaction,
            debtor_id,
            scope_digest,
            currency,
        )
    }

    pub fn load_credit_exposure_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<CreditExposureReservationRecordV1>, AdmissionOperationStoreError> {
        AdmissionDigest::try_new("credit_exposure_operation_id", operation_id.to_owned())?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_credit_exposure_reservation_tx(&transaction, operation_id)
    }

    pub fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        request: BudgetCaptureInvocationRequest,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        (
            chio_kernel::budget_store::BudgetInvocationCaptureDecision,
            AdmissionOperationV1,
        ),
        AdmissionCaptureError,
    > {
        if active_fence != &self.serving_owner.fence
            || recovery_lease.store_fence() != active_fence
            || operation.state() != AdmissionOperationState::CapturePending
            || operation.binding().capability_id().as_str() != request.capability_id
            || operation
                .budget_hold_id()
                .is_none_or(|hold_id| hold_id.as_str() != request.hold_id)
        {
            return Err(AdmissionCaptureError::Fenced);
        }
        let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        budget
            .capture_composite_invocation_and_commit_dispatch(
                request,
                crate::budget_store::AdmissionCaptureBinding {
                    operation,
                    recovery_lease,
                    trusted_now_unix_ms,
                },
            )
            .map_err(map_budget_capture_error)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_budget_and_commit_admission(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        request: BudgetAuthorizeHoldRequest,
        payment_journal: Option<PaymentJournalRecord>,
        credit_exposure: Option<chio_credit::obligation::CreditExposureReservationRequest>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(BudgetAuthorizeHoldDecision, AdmissionOperationV1), AdmissionCaptureError> {
        if active_fence != &self.serving_owner.fence || recovery_lease.store_fence() != active_fence
        {
            return Err(AdmissionCaptureError::Fenced);
        }
        let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        budget
            .authorize_composite_hold_and_commit_admission(
                request,
                crate::budget_store::AdmissionAuthorizationBinding {
                    operation,
                    recovery_lease,
                    payment_journal: payment_journal.as_ref(),
                    credit_exposure: credit_exposure.as_ref(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(map_budget_capture_error)
    }

    pub fn load_payment_journal(
        &self,
        operation_id: &str,
        active_fence: &StoreMutationFence,
    ) -> Result<Option<PaymentJournalRecord>, AdmissionPaymentJournalError> {
        if active_fence != &self.serving_owner.fence {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        let mut connection = self.connection().map_err(map_payment_operation_error)?;
        let transaction = self
            .begin_read(&mut connection)
            .map_err(map_payment_operation_error)?;
        let journal = crate::budget_store::load_payment_journal(&transaction, operation_id)
            .map_err(map_payment_budget_error)?;
        transaction
            .commit()
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        Ok(journal)
    }

    pub fn advance_payment_journal(
        &self,
        advance: AdmissionPaymentJournalAdvance<'_>,
    ) -> Result<PaymentJournalRecord, AdmissionPaymentJournalError> {
        let AdmissionPaymentJournalAdvance {
            operation,
            recovery_lease,
            expected,
            transition,
            release_evidence,
            active_fence,
            trusted_now_unix_ms,
        } = advance;
        if active_fence != &self.serving_owner.fence
            || recovery_lease.store_fence() != active_fence
            || expected.operation_id != operation.binding().operation_id().as_str()
        {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        let mut connection = self.connection().map_err(map_payment_operation_error)?;
        let transaction = self
            .begin_write(&mut connection, Some(active_fence))
            .map_err(map_payment_operation_error)?;
        verify_payment_write_context(
            &transaction,
            &self.serving_owner,
            operation,
            recovery_lease,
            active_fence,
            trusted_now_unix_ms,
        )?;
        let (updated, changed) = crate::budget_store::advance_payment_journal(
            &transaction,
            expected,
            transition,
            release_evidence,
            trusted_now_unix_ms,
        )
        .map_err(map_payment_budget_error)?;
        if changed {
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    "payment_journal_transition",
                    "payment",
                    &updated.operation_id,
                    updated.journal_version,
                )
                .map_err(map_payment_owner_error)?;
        }
        self.commit_write(transaction)
            .map_err(map_payment_operation_error)?;
        if changed {
            self.sync_after_write(&connection)
                .map_err(map_payment_operation_error)?;
        }
        Ok(updated)
    }

    pub fn begin_payment_settlement(
        &self,
        begin: AdmissionPaymentSettlementBegin<'_>,
    ) -> Result<AdmissionPaymentSettlement, AdmissionPaymentJournalError> {
        let AdmissionPaymentSettlementBegin {
            operation,
            recovery_lease,
            expected,
            transition,
            release_evidence,
            budget_reconcile,
            active_fence,
            trusted_now_unix_ms,
        } = begin;
        if active_fence != &self.serving_owner.fence
            || recovery_lease.store_fence() != active_fence
            || expected.operation_id != operation.binding().operation_id().as_str()
        {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        validate_payment_reconcile_binding(expected, transition, &budget_reconcile)?;
        let mut connection = self.connection().map_err(map_payment_operation_error)?;
        let transaction = self
            .begin_write(&mut connection, Some(active_fence))
            .map_err(map_payment_operation_error)?;
        verify_payment_write_context(
            &transaction,
            &self.serving_owner,
            operation,
            recovery_lease,
            active_fence,
            trusted_now_unix_ms,
        )?;
        let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        let (budget, budget_changed) = budget
            .reconcile_composite_hold_in_transaction(&transaction, &budget_reconcile)
            .map_err(map_payment_budget_error)?;
        let (journal, payment_changed) = match transition {
            Some(transition) => crate::budget_store::advance_payment_journal(
                &transaction,
                expected,
                transition,
                release_evidence,
                trusted_now_unix_ms,
            )
            .map_err(map_payment_budget_error)?,
            None => {
                if release_evidence.is_some() {
                    return Err(AdmissionPaymentJournalError::Invariant(
                        "payment release evidence requires a journal transition".to_owned(),
                    ));
                }
                let stored = crate::budget_store::load_payment_journal(
                    &transaction,
                    operation.binding().operation_id().as_str(),
                )
                .map_err(map_payment_budget_error)?
                .ok_or_else(|| {
                    AdmissionPaymentJournalError::Invariant(
                        "payment settlement journal is absent".to_owned(),
                    )
                })?;
                if stored != *expected {
                    return Err(AdmissionPaymentJournalError::Conflict(
                        "payment settlement journal changed".to_owned(),
                    ));
                }
                (stored, false)
            }
        };
        if payment_changed {
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    "payment_settlement_intent",
                    "payment",
                    &journal.operation_id,
                    journal.journal_version,
                )
                .map_err(map_payment_owner_error)?;
        }
        self.commit_write(transaction)
            .map_err(map_payment_operation_error)?;
        if budget_changed || payment_changed {
            self.sync_after_write(&connection)
                .map_err(map_payment_operation_error)?;
        }
        Ok(AdmissionPaymentSettlement {
            journal,
            budget,
            budget_already_reconciled: !budget_changed,
        })
    }

    pub fn commit_terminal_projection(
        &self,
        projection: &AdmissionTerminalProjection,
    ) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
        if projection.requires_anchored_economic_commit() {
            return Err(invariant(
                "terminal projection requires an advanced economic anchor",
            ));
        }
        projection.context().validate()?;
        let mut connection = self.connection()?;
        let transaction =
            self.begin_write(&mut connection, Some(&projection.context().store_fence))?;
        let (terminal, changed) =
            self.commit_terminal_projection_in_transaction(&transaction, projection)?;
        self.commit_write(transaction)?;
        if changed {
            self.sync_after_write(&connection)?;
        }
        Ok(terminal)
    }

    pub(super) fn commit_terminal_projection_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        projection: &AdmissionTerminalProjection,
    ) -> Result<(AdmissionTerminal, bool), AdmissionOperationStoreError> {
        let stored = load_by_operation_id_tx(transaction, &projection.context().operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        self.commit_terminal_projection_from_source_in_transaction(transaction, projection, &stored)
    }

    fn commit_terminal_projection_from_source_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        projection: &AdmissionTerminalProjection,
        stored: &StoredOperation,
    ) -> Result<(AdmissionTerminal, bool), AdmissionOperationStoreError> {
        if projection.requires_anchored_economic_commit() {
            return Err(invariant(
                "terminal projection requires an advanced economic anchor",
            ));
        }
        let canonical = projection.canonical_projection()?;
        validate_canonical_projection_size(&canonical)?;
        let context = projection.context();
        context.validate()?;
        verify_trusted_time(transaction, context.trusted_time_unix_ms)?;
        verify_payment_terminal_source(
            transaction,
            &stored.operation,
            context,
            projected_terminal_state(projection),
            canonical.records().iter().filter_map(|record| {
                (record.commitment().kind() == AdmissionProjectionRecordKind::PaymentTerminal)
                    .then_some(record.canonical_bytes())
            }),
        )?;

        if stored.operation.state().is_terminal() {
            let terminal = verify_exact_terminal_replay(
                transaction,
                &stored.operation,
                projection,
                &canonical,
            )?;
            apply_credit_exposure_terminal_tx(
                transaction,
                &stored.operation,
                canonical.projection_digest(),
                projection.pre_dispatch_release_proof(),
                &context.store_fence,
                context.trusted_time_unix_ms,
            )?;
            return Ok((terminal, false));
        }
        if context.request_id != stored.operation.replay_key().request_id
            || context.expected_operation_version != stored.operation.version()
            || context.coordinator_lease_epoch != stored.operation.coordinator_lease_epoch()
            || context.trusted_time_unix_ms < stored.updated_at_unix_ms
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        let recovery_claim = stored
            .recovery_claim
            .as_ref()
            .ok_or(AdmissionOperationStoreError::Fenced)?;
        if recovery_claim.coordinator_lease_id() != &context.coordinator_lease_id
            || recovery_claim.coordinator_lease_epoch() != context.coordinator_lease_epoch
            || recovery_claim.store_fence() != &context.store_fence
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        verify_stored_recovery_claim(
            transaction,
            &self.serving_owner,
            stored,
            recovery_claim,
            context.trusted_time_unix_ms,
            &context.store_fence,
        )?;
        let capabilities = full_projection_capabilities();
        let updated = stored
            .operation
            .apply_terminal_projection(projection, &capabilities)?;
        if updated
            .terminal_replay()
            .is_none_or(|replay| replay.projection_digest() != canonical.projection_digest())
        {
            return Err(invariant(
                "terminal operation does not retain its exact projection digest",
            ));
        }
        let encoded = encode_operation(&updated)?;
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
                    sqlite_i64(context.trusted_time_unix_ms, "trusted_now_unix_ms")?,
                    context.operation_id.as_str(),
                    sqlite_i64(stored.operation.version(), "expected_operation_version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        insert_terminal_projection(transaction, projection, &canonical, &updated)?;
        apply_credit_exposure_terminal_tx(
            transaction,
            &updated,
            canonical.projection_digest(),
            projection.pre_dispatch_release_proof(),
            &context.store_fence,
            context.trusted_time_unix_ms,
        )?;
        append_operation_commit(
            transaction,
            &updated,
            &encoded,
            Some(recovery_claim),
            "compare_and_swap",
            &self.serving_owner,
            context.trusted_time_unix_ms,
        )?;
        terminal_from_operation(&updated).map(|terminal| (terminal, true))
    }

    pub fn commit_signed_terminal_projection(
        &self,
        envelope: &SignedAdmissionTerminalProjectionV1,
    ) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
        let verified = envelope.verify()?;
        let context = verified.context();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(&context.store_fence))?;
        let terminal = self.commit_verified_signed_terminal_projection_in_transaction(
            &transaction,
            &verified,
            context.trusted_time_unix_ms,
            None,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(terminal)
    }
}

fn verify_stored_recovery_claim(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    stored: &StoredOperation,
    claim: &UntrustedAdmissionRecoveryClaim,
    trusted_now_unix_ms: u64,
    current_store_fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(invariant("trusted operation time regressed"));
    }
    if stored.recovery_claim.as_ref() != Some(claim)
        || stored.operation.binding().operation_id() != claim.operation_id()
        || stored.operation.version() != claim.claimed_version()
        || stored.operation.coordinator_lease_epoch() != claim.coordinator_lease_epoch()
        || claim.store_fence() != current_store_fence
        || current_store_fence != &owner.fence
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let historical_lease_id = coordinator_lease_id_for_epoch(
        transaction,
        owner,
        stored.operation.coordinator_lease_epoch(),
    )?;
    if &historical_lease_id != claim.coordinator_lease_id() {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    if trusted_now_unix_ms >= claim.expires_at_unix_ms() {
        return Err(AdmissionOperationError::LeaseExpired.into());
    }
    Ok(())
}

struct StoredOperation {
    operation: AdmissionOperationV1,
    recovery_claim: Option<UntrustedAdmissionRecoveryClaim>,
    updated_at_unix_ms: u64,
}

pub(crate) enum PreparedAdmissionBeginTxResult {
    Created {
        encoded: Vec<u8>,
    },
    ExactReplay {
        operation: Box<AdmissionOperationV1>,
        terminal_replay: Option<AdmissionTerminalReplay>,
    },
    Conflict {
        existing_operation_id: AdmissionOperationId,
    },
}

struct RawOperationRow {
    operation_id: String,
    request_namespace_digest: String,
    request_id: String,
    operation_json: Vec<u8>,
    state: String,
    terminal: i64,
    coordinator_lease_epoch: i64,
    version: i64,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    recovery_claimant_id: Option<String>,
    recovery_coordinator_lease_id: Option<String>,
    recovery_coordinator_lease_epoch: Option<i64>,
    recovery_claimed_version: Option<i64>,
    recovery_expires_at_unix_ms: Option<i64>,
    recovery_store_uuid: Option<String>,
    recovery_store_lease_id: Option<String>,
    recovery_store_owner_epoch: Option<i64>,
}

fn read_raw_row(row: &Row<'_>) -> rusqlite::Result<RawOperationRow> {
    Ok(RawOperationRow {
        operation_id: row.get(0)?,
        request_namespace_digest: row.get(1)?,
        request_id: row.get(2)?,
        operation_json: row.get(3)?,
        state: row.get(4)?,
        terminal: row.get(5)?,
        coordinator_lease_epoch: row.get(6)?,
        version: row.get(7)?,
        created_at_unix_ms: row.get(8)?,
        updated_at_unix_ms: row.get(9)?,
        recovery_claimant_id: row.get(10)?,
        recovery_coordinator_lease_id: row.get(11)?,
        recovery_coordinator_lease_epoch: row.get(12)?,
        recovery_claimed_version: row.get(13)?,
        recovery_expires_at_unix_ms: row.get(14)?,
        recovery_store_uuid: row.get(15)?,
        recovery_store_lease_id: row.get(16)?,
        recovery_store_owner_epoch: row.get(17)?,
    })
}

fn decode_row(raw: RawOperationRow) -> Result<StoredOperation, AdmissionOperationStoreError> {
    if raw.operation_json.is_empty() || raw.operation_json.len() > MAX_PERSISTED_OPERATION_BYTES {
        return Err(invariant("persisted admission operation size is invalid"));
    }
    let persisted: PersistedAdmissionOperationV1 = serde_json::from_slice(&raw.operation_json)
        .map_err(|error| invariant(format!("persisted admission operation is invalid: {error}")))?;
    let operation = AdmissionOperationV1::from_persisted(persisted)?;
    let canonical = encode_operation(&operation)?;
    if canonical != raw.operation_json {
        return Err(invariant(
            "persisted admission operation encoding is not canonical",
        ));
    }
    let replay_key = operation.replay_key();
    if operation.binding().operation_id().as_str() != raw.operation_id
        || replay_key.request_namespace_digest.as_str() != raw.request_namespace_digest
        || replay_key.request_id.as_str() != raw.request_id
        || state_name(operation.state()) != raw.state
        || i64::from(operation.state().is_terminal()) != raw.terminal
        || operation.coordinator_lease_epoch()
            != stored_u64(raw.coordinator_lease_epoch, "coordinator_lease_epoch")?
        || operation.version() != stored_u64(raw.version, "version")?
    {
        return Err(invariant(
            "admission operation columns do not match the checked record",
        ));
    }
    let created_at = stored_u64(raw.created_at_unix_ms, "created_at_unix_ms")?;
    let updated_at = stored_u64(raw.updated_at_unix_ms, "updated_at_unix_ms")?;
    validate_trusted_time(created_at, "created_at_unix_ms")?;
    validate_trusted_time(updated_at, "updated_at_unix_ms")?;
    if updated_at < created_at {
        return Err(invariant("admission operation timestamp regressed"));
    }

    let recovery_claim = match (
        raw.recovery_claimant_id,
        raw.recovery_coordinator_lease_id,
        raw.recovery_coordinator_lease_epoch,
        raw.recovery_claimed_version,
        raw.recovery_expires_at_unix_ms,
        raw.recovery_store_uuid,
        raw.recovery_store_lease_id,
        raw.recovery_store_owner_epoch,
    ) {
        (None, None, None, None, None, None, None, None) => None,
        (
            Some(claimant_id),
            Some(coordinator_lease_id),
            Some(coordinator_lease_epoch),
            Some(claimed_version),
            Some(expires_at_unix_ms),
            Some(store_uuid),
            Some(store_lease_id),
            Some(store_owner_epoch),
        ) => {
            let claimed_version = stored_u64(claimed_version, "recovery_claimed_version")?;
            if claimed_version > operation.version()
                || claimed_version
                    .checked_add(1)
                    .is_some_and(|next| next < operation.version())
            {
                return Err(invariant(
                    "recovery claim is not for the current or immediately preceding version",
                ));
            }
            let expires_at_unix_ms = stored_u64(expires_at_unix_ms, "recovery_expires_at_unix_ms")?;
            validate_trusted_time(expires_at_unix_ms, "recovery_expires_at_unix_ms")?;
            Some(UntrustedAdmissionRecoveryClaim::new(
                operation.binding().operation_id().clone(),
                AdmissionIdentifier::try_new("recovery_claimant_id", claimant_id)?,
                AdmissionIdentifier::try_new(
                    "recovery_coordinator_lease_id",
                    coordinator_lease_id,
                )?,
                stored_u64(coordinator_lease_epoch, "recovery_coordinator_lease_epoch")?,
                claimed_version,
                expires_at_unix_ms,
                StoreMutationFence {
                    store_uuid,
                    lease_id: store_lease_id,
                    owner_epoch: stored_u64(store_owner_epoch, "recovery_store_owner_epoch")?,
                },
            )?)
        }
        _ => return Err(invariant("recovery claim tuple is partial")),
    };
    Ok(StoredOperation {
        operation,
        recovery_claim,
        updated_at_unix_ms: updated_at,
    })
}

fn load_by_operation_id_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<Option<StoredOperation>, AdmissionOperationStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations WHERE operation_id = ?1
            "#,
            [operation_id.as_str()],
            read_raw_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored = raw.map(decode_row).transpose()?;
    if let Some(stored) = &stored {
        verify_latest_commit(transaction, stored)?;
        verify_stored_terminal_projection(transaction, stored)?;
    }
    Ok(stored)
}

pub(crate) fn begin_prepared_operation_tx(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<PreparedAdmissionBeginTxResult, AdmissionOperationStoreError> {
    operation.validate()?;
    if operation.state() != AdmissionOperationState::Prepared || operation.version() != 1 {
        return Err(invariant("begin requires a version-one Prepared operation"));
    }
    if operation.coordinator_lease_epoch() != fence.owner_epoch {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_trusted_time(transaction, trusted_now_unix_ms)?;
    let encoded = encode_operation(operation)?;
    let replay_key = operation.replay_key();
    if let Some(existing) = load_by_replay_key_tx(transaction, &replay_key)? {
        return Ok(match existing.operation.classify_replay(operation) {
            AdmissionReplayClassification::Exact { terminal_replay } => {
                PreparedAdmissionBeginTxResult::ExactReplay {
                    operation: Box::new(existing.operation),
                    terminal_replay,
                }
            }
            AdmissionReplayClassification::Conflict => PreparedAdmissionBeginTxResult::Conflict {
                existing_operation_id: existing.operation.binding().operation_id().clone(),
            },
        });
    }
    if load_by_operation_id_tx(transaction, operation.binding().operation_id())?.is_some() {
        return Err(invariant(
            "operation id is already bound to a different replay key",
        ));
    }
    let changed = transaction
        .execute(
            r#"
            INSERT INTO admission_operations (
                operation_id, request_namespace_digest, request_id,
                operation_json, state, terminal, coordinator_lease_epoch,
                version, created_at_unix_ms, updated_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?8)
            "#,
            params![
                operation.binding().operation_id().as_str(),
                replay_key.request_namespace_digest.as_str(),
                replay_key.request_id.as_str(),
                encoded,
                state_name(operation.state()),
                sqlite_i64(
                    operation.coordinator_lease_epoch(),
                    "coordinator_lease_epoch"
                )?,
                sqlite_i64(operation.version(), "version")?,
                sqlite_i64(trusted_now_unix_ms, "created_at_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("begin did not insert exactly one operation"));
    }
    Ok(PreparedAdmissionBeginTxResult::Created { encoded })
}

pub(crate) fn load_operation_for_participant_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
    load_by_operation_id_tx(transaction, operation_id)
        .map(|stored| stored.map(|stored| stored.operation))
}

fn load_by_replay_key_tx(
    transaction: &Transaction<'_>,
    replay_key: &AdmissionReplayKey,
) -> Result<Option<StoredOperation>, AdmissionOperationStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations
            WHERE request_namespace_digest = ?1 AND request_id = ?2
            "#,
            params![
                replay_key.request_namespace_digest.as_str(),
                replay_key.request_id.as_str(),
            ],
            read_raw_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored = raw.map(decode_row).transpose()?;
    if let Some(stored) = &stored {
        verify_latest_commit(transaction, stored)?;
        verify_stored_terminal_projection(transaction, stored)?;
    }
    Ok(stored)
}

fn encode_operation(
    operation: &AdmissionOperationV1,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    operation.validate()?;
    let encoded = canonical_json_bytes(&operation.to_persisted())
        .map_err(|error| invariant(format!("admission operation encoding failed: {error}")))?;
    if encoded.is_empty() || encoded.len() > MAX_PERSISTED_OPERATION_BYTES {
        return Err(invariant(
            "persisted admission operation exceeds its size limit",
        ));
    }
    Ok(encoded)
}

fn state_name(state: AdmissionOperationState) -> &'static str {
    match state {
        AdmissionOperationState::Prepared => "prepared",
        AdmissionOperationState::BrokerAttemptRegistered => "broker_attempt_registered",
        AdmissionOperationState::ApprovalRequired => "approval_required",
        AdmissionOperationState::BudgetAuthorized => "budget_authorized",
        AdmissionOperationState::ApprovalReserved => "approval_reserved",
        AdmissionOperationState::ReadyToDispatch => "ready_to_dispatch",
        AdmissionOperationState::CapturePending => "capture_pending",
        AdmissionOperationState::DispatchCommitted => "dispatch_committed",
        AdmissionOperationState::Finalizing => "finalizing",
        AdmissionOperationState::Completed => "completed",
        AdmissionOperationState::CompensatedBeforeDispatch => "compensated_before_dispatch",
        AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            "not_accepted_after_dispatch_commit"
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => "outcome_unknown_after_dispatch",
        AdmissionOperationState::MutationReady => "mutation_ready",
        AdmissionOperationState::MutationSubmitted => "mutation_submitted",
        AdmissionOperationState::EconomicMutationApplied => "economic_mutation_applied",
        AdmissionOperationState::EconomicMutationNotApplied => "economic_mutation_not_applied",
    }
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, AdmissionOperationStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, AdmissionOperationStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn invariant(detail: impl Into<String>) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(detail.into())
}

pub(crate) fn receipt_projection_error(error: AdmissionOperationStoreError) -> ReceiptStoreError {
    match error {
        AdmissionOperationStoreError::Unavailable(detail) => ReceiptStoreError::Pool(detail),
        AdmissionOperationStoreError::Fenced => ReceiptStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => {
            ReceiptStoreError::NotFound("admission operation".to_string())
        }
        AdmissionOperationStoreError::Invariant(detail) => ReceiptStoreError::Conflict(detail),
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            ReceiptStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Operation(error) => {
            ReceiptStoreError::Conflict(error.to_string())
        }
    }
}

fn decode_projection_receipt(bytes: Vec<u8>) -> Result<ChioReceipt, ReceiptStoreError> {
    let receipt: ChioReceipt = serde_json::from_slice(&bytes)?;
    if canonical_json_bytes(&receipt)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        != bytes
        || !receipt
            .verify_signature()
            .map_err(|error| ReceiptStoreError::CryptoDecode(error.to_string()))?
    {
        return Err(ReceiptStoreError::Conflict(
            "persisted admission receipt is invalid".to_string(),
        ));
    }
    Ok(receipt)
}

fn map_owner_error(error: SqliteServingOwnerError) -> AdmissionOperationStoreError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            AdmissionOperationStoreError::OutcomeUnknown(detail)
        }
        error => invariant(error.to_string()),
    }
}

fn map_economic_cache_error(
    error: crate::economic_state_cache::EconomicStateCacheError,
) -> AdmissionOperationStoreError {
    match error {
        crate::economic_state_cache::EconomicStateCacheError::Unavailable(detail) => {
            AdmissionOperationStoreError::Unavailable(detail)
        }
        crate::economic_state_cache::EconomicStateCacheError::Fenced => {
            AdmissionOperationStoreError::Fenced
        }
        crate::economic_state_cache::EconomicStateCacheError::NotFound => {
            AdmissionOperationStoreError::NotFound
        }
        crate::economic_state_cache::EconomicStateCacheError::OutcomeUnknown(detail) => {
            AdmissionOperationStoreError::OutcomeUnknown(detail)
        }
        error => invariant(error.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> AdmissionOperationStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => AdmissionOperationStoreError::Unavailable(other.to_string()),
    }
}

impl From<AdmissionOperationStoreError> for SqliteServingOwnerError {
    fn from(error: AdmissionOperationStoreError) -> Self {
        Self::Invalid(error.to_string())
    }
}

#[cfg(test)]
#[path = "admission_operation_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
