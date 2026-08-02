//! SQLite-backed persistence, query, and report layer for the Chio protocol.
//!
//! This crate is the concrete persistent backend for the kernel's receipt log
//! and its supporting state. It implements the receipt store and query path,
//! budget and approval stores, capability-lineage and revocation stores, an
//! execution-nonce store, an encrypted-blob store, IOU and dead-letter stores,
//! and evidence-export queries. The store traits it implements are defined by
//! `chio-kernel` and `chio-core`. Reader-heavy receipt queries use a
//! connection pool (eight readers by default); writes are serialized through a
//! group-commit actor onto a single writer connection.
//!
//! # Modules
//!
//! - [`receipt_store`] / [`receipt_query`] -- receipt persistence and the
//!   query path.
//! - [`budget_store`] -- durable budget state.
//! - [`approval_store`] / [`batch_approval_store`] -- human-approval state.
//! - [`capability_lineage`] / [`revocation_store`] -- capability provenance and
//!   revocation.
//! - [`execution_nonce_store`] / [`dead_letters`] / [`iou_store`] -- nonce
//!   replay guard, settlement dead letters, and IOU envelopes.
//! - [`encrypted_blob`] / [`memory_provenance_store`] / [`evidence_export`] --
//!   encrypted payloads, memory provenance, and evidence export.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

pub mod admission_operation_store;
mod agent_web_replay_store;
pub mod approval_store;
pub mod authority;
pub mod batch_approval_store;
pub mod budget_store;
pub mod capability_lineage;
pub mod channel_lifecycle_store;
pub mod channel_release_publisher_store;
pub mod clearing_lifecycle_store;
pub mod dead_letters;
pub mod economic_state_cache;
pub mod encrypted_blob;
pub mod evidence_export;
pub mod execution_nonce_store;
#[cfg(feature = "cognition-market-experimental")]
pub mod finding_challenge_store;
#[cfg(feature = "cognition-market-experimental")]
pub mod finding_market_store;
#[cfg(feature = "cognition-market-experimental")]
pub mod finding_purchase_store;
#[cfg(feature = "cognition-market-experimental")]
pub mod finding_recovery_store;
pub mod fiscal_store;
pub mod frost_store;
mod governed_approval_replay_store;
pub mod iou_store;
#[cfg(feature = "lineage")]
pub mod lineage_cte;
pub mod memory_provenance_store;
pub mod receipt_query;
pub mod receipt_store;
mod replay_clock;
pub mod revocation_store;
pub mod schema_version;
pub mod serving_owner;
pub mod settle_attempts;
pub mod tool_outcome_store;

pub use chio_core::crypto::SharedCanonicalBytes;
pub use chio_core::{CanonicalBytes, CanonicalJsonWitness};
pub use chio_kernel::{EvidenceChildReceiptScope, EvidenceExportQuery};

/// Default SQLite reader pool size.
///
/// Reader-heavy receipt queries keep the existing eight-connection default.
pub const DEFAULT_READER_POOL_MAX_SIZE: u32 = 8;

/// Default SQLite writer pool size.
///
/// Receipt writes are serialized through the group-commit actor, so the
/// writer pool defaults to a single connection.
pub const DEFAULT_WRITER_POOL_MAX_SIZE: u32 = 1;

/// SQLite pool sizing and per-connection growth bound for receipt-store read
/// and write paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlitePoolConfig {
    pub reader_pool_max_size: u32,
    pub writer_pool_max_size: u32,
    /// Optional `PRAGMA max_page_count` ceiling applied to every pooled
    /// connection. An operational bound on the logical page count of the MAIN
    /// database file: a write that would push the main file past the cap fails
    /// closed with a full-database error. This bounds the main file only, not the
    /// `-wal` sidecar, so it is not a whole-volume guard: under checkpoint
    /// starvation the WAL can still grow unbounded. `None` (the default) leaves
    /// SQLite's built-in page ceiling in place, so a store opened without this
    /// knob behaves exactly as before.
    pub max_page_count: Option<u32>,
}

impl Default for SqlitePoolConfig {
    fn default() -> Self {
        Self {
            reader_pool_max_size: DEFAULT_READER_POOL_MAX_SIZE,
            writer_pool_max_size: DEFAULT_WRITER_POOL_MAX_SIZE,
            max_page_count: None,
        }
    }
}

/// Receipt-store construction options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteStoreOptions {
    pub pool: SqlitePoolConfig,
    /// When true (default), the append path uses the actor-owned verified
    /// head (O(1) predecessor check + O(b) delta cross-check). When false,
    /// the store keeps today's full per-append verification so operators can
    /// A/B a suspect database. Read-only after open.
    pub incremental_verification: bool,
}

impl Default for SqliteStoreOptions {
    fn default() -> Self {
        Self {
            pool: SqlitePoolConfig::default(),
            incremental_verification: true,
        }
    }
}

/// Whether a SQLite path opens a database that lives only in memory for the life
/// of the process. rusqlite enables URI filenames, so the bare `:memory:`
/// sentinel, `file::memory:`, and any `file:...?mode=memory` URI all open a
/// non-durable database that loses its contents on restart and must not be
/// mistaken for a durable store. Durability gates use this to refuse an in-memory
/// path where they would otherwise advertise durable persistence.
#[must_use]
pub fn is_in_memory_sqlite_path(path: &str) -> bool {
    if path.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    let Some(rest) = path.strip_prefix("file:") else {
        return false;
    };
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };
    if name.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|param| param.eq_ignore_ascii_case("mode=memory"))
    })
}

/// The directory that must exist before SQLite opens `path`, or `None` when
/// there is nothing to create.
///
/// rusqlite accepts `file:` URIs whose query string (`?mode=rwc`) and optional
/// `//authority` are not part of the on-disk filename. Treating such a URI as a
/// plain [`Path`] makes `parent()` resolve to a bogus directory (for example
/// `file:/var/lib/chio`) and skips creating the real one, so SQLite then fails
/// to open the database. This strips the `file:` scheme, any authority, and the
/// query so callers create the directory that actually backs the database. An
/// in-memory database (`:memory:`, `file:...?mode=memory`) has no backing
/// directory and returns `None`.
#[must_use]
pub(crate) fn sqlite_parent_dir_to_create(path: &Path) -> Option<PathBuf> {
    let Some(text) = path.to_str() else {
        // A non-UTF8 path cannot be a `file:` URI, so use it verbatim.
        return non_empty_parent(path);
    };
    if is_in_memory_sqlite_path(text) {
        return None;
    }
    non_empty_parent(&sqlite_filesystem_path(text))
}

/// The parent of `path`, unless it is empty (a bare filename with no directory
/// component), in which case there is nothing to create.
fn non_empty_parent(path: &Path) -> Option<PathBuf> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
}

/// The filesystem path a rusqlite path points at, resolving a `file:` URI to
/// its on-disk filename by stripping the scheme, any `//authority`, and the
/// `?query`. A plain path (no `file:` scheme) is returned unchanged.
#[must_use]
pub fn sqlite_filesystem_path(text: &str) -> PathBuf {
    let Some(rest) = text.strip_prefix("file:") else {
        return PathBuf::from(text);
    };
    // Drop the URI query (`?mode=rwc`, `?cache=shared`); it is not part of the
    // filename.
    let without_query = rest.split_once('?').map_or(rest, |(name, _query)| name);
    // `file://authority/path` places the filesystem path after the authority;
    // `file:/path` and `file:path` have no authority. Strip a leading `//` and
    // the authority up to the next `/`.
    let filesystem = match without_query.strip_prefix("//") {
        Some(after_authority_marker) => match after_authority_marker.find('/') {
            Some(path_start) => &after_authority_marker[path_start..],
            None => "",
        },
        None => without_query,
    };
    PathBuf::from(filesystem)
}

pub use admission_operation_store::{
    CreditExposureAccountSnapshot, DurableObligationV1, SqliteAdmissionOperationStore,
};
pub use agent_web_replay_store::{
    SqliteAgentWebReplayReservationState, SqliteAgentWebReplayStore, SqliteAgentWebReplayStoreError,
};
pub use approval_store::SqliteApprovalStore;
pub use authority::SqliteCapabilityAuthority;
pub use batch_approval_store::SqliteBatchApprovalStore;
pub use budget_store::{BudgetStoreSnapshot, SqliteBudgetStore};
pub use channel_lifecycle_store::{
    ChannelLifecycleStoreError, ChannelPreparedAdmissionRecordV1, ChannelPreparedBeginResult,
    ChannelReservationDispositionV1, ChannelReservationStageRecordV1, SqliteChannelLifecycleStore,
};
pub use channel_release_publisher_store::{
    ChannelReleasePublicationRecordV1, ChannelReleasePublicationStatusV1,
    ChannelReleasePublisherError, ChannelReleaseSubmissionOutcomeV1,
    SqliteChannelReleasePublisherStore, VerifiedChannelReleasePublicationV1,
};
pub use clearing_lifecycle_store::{ClearingLifecycleStoreError, SqliteClearingLifecycleStore};
pub use economic_state_cache::{
    admission_terminal_projection_effect_result, EconomicOperationStageBinding,
    EconomicOperationStageContext, EconomicStateCacheError, EconomicStateStageDescriptor,
    EconomicStateStageRecord, EconomicStateStageStatus, SqliteEconomicStateCache,
};
pub use encrypted_blob::{
    decrypt_blob, encrypt_blob, BlobHandle, BlobStoreError, DecryptError, EncryptError,
    EncryptedBlob, SqliteEncryptedBlobStore, TenantId, TenantKey,
};
pub use execution_nonce_store::{SqliteExecutionNonceStore, SqliteExecutionNonceStoreError};
#[cfg(feature = "cognition-market-experimental")]
pub use finding_challenge_store::{
    derive_dispute_bond_funding_intent_key, derive_dispute_bond_return_intent_key,
    dispute_bond_funding_intent_digest, dispute_bond_return_intent_digest,
    FindingChallengeAuthorizationBranch, FindingChallengeEvaluationStart,
    FindingChallengeEvidenceClass, FindingChallengeRecord, FindingChallengeState,
    FindingChallengeStoreError, FindingChallengeSubmission, FindingChallengeVerdict,
    FindingChallengeWriteOutcome, FindingClaimSnapshotInput, FindingClaimSnapshotRecord,
    FindingDisputeLockDisposition, FindingDisputeLockInput, FindingDisputeLockRecord,
    FindingDisputeLockState, FindingEffectIntentKind, FindingEffectIntentRecord,
    FindingEffectIntentState, FindingGovernanceCaseInput, FindingGovernanceCaseKind,
    FindingGovernanceCaseRecord, FindingLiabilityInput, FindingLiabilityRecord,
    FindingLiabilityState, SqliteFindingChallengeStore,
};
#[cfg(feature = "cognition-market-experimental")]
pub use finding_market_store::{
    finding_fee_idempotency_key, FindingActivationAttemptSnapshot, FindingActivationAttemptState,
    FindingActivationOutcome, FindingActivationPreparationOutcome, FindingAdmissionSnapshot,
    FindingAllocationSnapshot, FindingAllocationState, FindingFeeEventRecord, FindingFeeIntent,
    FindingFeeIntentOutcome, FindingFeeIntentResult, FindingFeeState, FindingMarketStoreError,
    FindingPutOutcome, FindingRecordInput, FindingSearchRow, SqliteFindingMarketStore,
};
#[cfg(feature = "cognition-market-experimental")]
pub use finding_purchase_store::{
    FindingFailedDeliveryRow, FindingPayoutDestinationAdmission, FindingPurchaseDeliveryInput,
    FindingPurchaseDenyInput, FindingPurchaseEncumbranceRecord, FindingPurchaseEncumbranceState,
    FindingPurchaseRecordRow, FindingPurchaseReservationInput, FindingPurchaseReservationRecord,
    FindingPurchaseReservationState, FindingPurchaseSlotRecord, FindingPurchaseSlotState,
    FindingPurchaseStoreError, FindingPurchaseWriteOutcome, SqliteFindingPurchaseStore,
};
#[cfg(feature = "cognition-market-experimental")]
pub use finding_recovery_store::{
    FindingRecoveryIssuanceInput, FindingRecoveryIssuanceRecord,
    FindingRecoveryReceiptLineageInput, FindingRecoveryReceiptLineageRecord,
    FindingRecoveryStoreError, FindingRecoveryWriteOutcome, SqliteFindingRecoveryStore,
};
pub use frost_store::{
    FrostActiveRosterRecord, FrostCeremonyRecord, FrostCeremonyRound1Record,
    FrostCeremonyRound2Record, FrostCeremonyState, FrostCoordinatorCancellation,
    FrostCoordinatorCommitment, FrostCoordinatorLease, FrostCoordinatorSessionRecord,
    FrostCoordinatorSessionRequest, FrostCoordinatorSessionState, FrostCoordinatorShare,
    FrostCoordinatorSigningPackage, FrostCustodyKey, FrostRotationRecord, FrostRotationState,
    FrostSignerCommitment, FrostSignerSessionRecord, FrostSignerSessionRequest,
    FrostSignerSessionState, FrostSignerShare, FrostStoreError, SqliteFrostStore,
    StagedFrostRotation, StoredFrostCeremonyCompletion,
};
pub use governed_approval_replay_store::{
    SqliteGovernedApprovalReplayStore, SqliteGovernedApprovalReplayStoreError,
};
pub use iou_store::{SqliteIouEnvelopeStore, IOU_ENVELOPE_MIGRATION};
pub use memory_provenance_store::{SqliteMemoryProvenanceStore, SqliteMemoryProvenanceStoreError};
pub use receipt_store::{BackgroundCheckpointSigner, SqliteReceiptStore};
pub use revocation_store::SqliteRevocationStore;
pub use schema_version::{
    check_schema_version, stamp_schema_version, SchemaVersionError, CHIO_SQLITE_APPLICATION_ID,
};
pub use serving_owner::{
    scope_fixed_authority_ids_for_current_thread, FixedAuthorityIdScope, SqliteAuthorityStore,
    SqliteServingOwnerError,
};

impl chio_kernel::QualifiedAdmissionProjectionStore
    for admission_operation_store::SqliteAdmissionOperationStore
{
    fn load_payment_journal(
        &self,
        operation_id: &str,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
    ) -> Result<
        Option<chio_kernel::payment::PaymentJournalRecord>,
        chio_kernel::AdmissionPaymentJournalError,
    > {
        admission_operation_store::SqliteAdmissionOperationStore::load_payment_journal(
            self,
            operation_id,
            active_fence,
        )
    }

    fn advance_payment_journal(
        &self,
        advance: chio_kernel::AdmissionPaymentJournalAdvance<'_>,
    ) -> Result<chio_kernel::payment::PaymentJournalRecord, chio_kernel::AdmissionPaymentJournalError>
    {
        admission_operation_store::SqliteAdmissionOperationStore::advance_payment_journal(
            self, advance,
        )
    }

    fn begin_payment_settlement(
        &self,
        begin: chio_kernel::AdmissionPaymentSettlementBegin<'_>,
    ) -> Result<chio_kernel::AdmissionPaymentSettlement, chio_kernel::AdmissionPaymentJournalError>
    {
        admission_operation_store::SqliteAdmissionOperationStore::begin_payment_settlement(
            self, begin,
        )
    }

    fn authorize_budget_and_commit_admission(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        request: chio_kernel::budget_store::BudgetAuthorizeHoldRequest,
        payment_journal: Option<chio_kernel::payment::PaymentJournalRecord>,
        credit_exposure: Option<chio_kernel::CreditExposureReservationRequest>,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::AdmissionBudgetAuthorization,
        chio_kernel::AdmissionBudgetAuthorizationError,
    > {
        admission_operation_store::SqliteAdmissionOperationStore::authorize_budget_and_commit_admission(
            self,
            operation,
            recovery_lease,
            request,
            payment_journal,
            credit_exposure,
            active_fence,
            trusted_now_unix_ms,
        )
        .map(|(decision, operation)| chio_kernel::AdmissionBudgetAuthorization {
            decision,
            operation,
        })
        .map_err(|error| match error {
            chio_kernel::admission_operation::AdmissionCaptureError::Unavailable(detail) => {
                chio_kernel::AdmissionBudgetAuthorizationError::Unavailable(detail)
            }
            chio_kernel::admission_operation::AdmissionCaptureError::Fenced => {
                chio_kernel::AdmissionBudgetAuthorizationError::Fenced
            }
            chio_kernel::admission_operation::AdmissionCaptureError::OutcomeUnknown(detail) => {
                chio_kernel::AdmissionBudgetAuthorizationError::OutcomeUnknown(detail)
            }
            chio_kernel::admission_operation::AdmissionCaptureError::Invariant(detail) => {
                chio_kernel::AdmissionBudgetAuthorizationError::Invariant(detail)
            }
            chio_kernel::admission_operation::AdmissionCaptureError::Operation(error) => {
                chio_kernel::AdmissionBudgetAuthorizationError::Operation(error)
            }
        })
    }

    fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        request: chio_kernel::budget_store::BudgetCaptureInvocationRequest,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::AdmissionBudgetCapture,
        chio_kernel::admission_operation::AdmissionCaptureError,
    > {
        admission_operation_store::SqliteAdmissionOperationStore::capture_invocation_and_commit_dispatch(
            self,
            operation,
            recovery_lease,
            request,
            active_fence,
            trusted_now_unix_ms,
        )
        .map(|(decision, operation)| chio_kernel::AdmissionBudgetCapture {
            decision,
            operation,
        })
    }

    fn reserve_threshold_approval_and_commit_admission(
        &self,
        command: &chio_kernel::admission_operation::AdmissionOperationCommand,
        reservation: &chio_kernel::ThresholdApprovalReplayReservationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::admission_operation::AdmissionCommandResult,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        admission_operation_store::SqliteAdmissionOperationStore::reserve_threshold_approval_and_commit_admission(
            self,
            command,
            reservation,
            trusted_now_unix_ms,
        )
    }

    fn list_admission_receipts_after(
        &self,
        after_receipt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<chio_core::receipt::body::ChioReceipt>, chio_kernel::ReceiptStoreError> {
        self.list_terminal_receipts_after(after_receipt_id, limit)
    }
}

impl chio_credit::obligation::CreditAdmissionStore
    for admission_operation_store::SqliteAdmissionOperationStore
{
    fn lookup_record_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<
        Option<chio_credit::obligation::CreditExposureReservationRecordV1>,
        chio_credit::obligation::CreditAdmissionError,
    > {
        self.load_credit_exposure_reservation(operation_id)
            .map_err(|error| {
                chio_credit::obligation::CreditAdmissionError::Store(error.to_string())
            })
    }
}

impl chio_kernel::receipt_store::AnchoredAdmissionProjectionStore
    for admission_operation_store::SqliteAdmissionOperationStore
{
    fn stage_anchored_terminal_projection(
        &self,
        advance: &chio_core::economic_continuity::VerifiedEconomicStateBatchAdvance,
        recovery_lease: &chio_kernel::admission_operation::AdmissionRecoveryLease,
        envelope: &chio_kernel::admission_operation::SignedAdmissionTerminalProjectionV1,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), chio_kernel::ReceiptStoreError> {
        admission_operation_store::SqliteAdmissionOperationStore::stage_anchored_terminal_projection(
            self,
            advance,
            recovery_lease,
            envelope,
            active_fence,
            trusted_now_unix_ms,
        )
        .map_err(admission_operation_store::receipt_projection_error)
    }

    fn qualify_anchored_terminal_projection(
        &self,
        batch_id: &str,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), chio_kernel::ReceiptStoreError> {
        admission_operation_store::SqliteAdmissionOperationStore::qualify_anchored_terminal_projection(
            self,
            batch_id,
            active_fence,
            trusted_now_unix_ms,
        )
        .map_err(admission_operation_store::receipt_projection_error)
    }

    fn record_anchored_terminal_projection(
        &self,
        advance: &chio_core::economic_continuity::VerifiedEconomicStateBatchAdvance,
        committed: &chio_core::economic_continuity::VerifiedEconomicStateView,
        pins: &chio_core::economic_continuity::EconomicStateAnchorPins,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), chio_kernel::ReceiptStoreError> {
        admission_operation_store::SqliteAdmissionOperationStore::record_anchored_terminal_projection(
            self,
            advance,
            committed,
            pins,
            active_fence,
            trusted_now_unix_ms,
        )
        .map_err(admission_operation_store::receipt_projection_error)
    }

    fn commit_anchored_terminal_projection(
        &self,
        batch_id: &str,
        active_fence: &chio_kernel::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<chio_kernel::admission_operation::AdmissionTerminal, chio_kernel::ReceiptStoreError>
    {
        admission_operation_store::SqliteAdmissionOperationStore::commit_anchored_terminal_projection(
            self,
            batch_id,
            active_fence,
            trusted_now_unix_ms,
        )
        .map_err(admission_operation_store::receipt_projection_error)
    }
}
pub use settle_attempts::{SqliteSettlementOutcomeStore, SETTLE_ATTEMPTS_MIGRATION};
pub use tool_outcome_store::SqliteToolOutcomeStore;

#[cfg(test)]
mod tests {
    use super::{is_in_memory_sqlite_path, sqlite_parent_dir_to_create};
    use std::path::{Path, PathBuf};

    #[test]
    fn resolves_parent_dir_from_file_uris_and_plain_paths() {
        // A `file:` URI with a query resolves to the real filesystem parent, not
        // a `file:`-prefixed directory folded out of the raw string.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new(
                "file:/var/lib/chio/receipts.db.revocations?mode=rwc"
            )),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A `file://` URI with an empty authority drops the `//`.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:///var/lib/chio/db?cache=shared")),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A plain filesystem path keeps its parent unchanged.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("/var/lib/chio/receipts.db")),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A bare filename has no directory component to create.
        assert_eq!(sqlite_parent_dir_to_create(Path::new("receipts.db")), None);
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:receipts.db?mode=rwc")),
            None
        );
        // In-memory databases have no backing directory.
        assert_eq!(sqlite_parent_dir_to_create(Path::new(":memory:")), None);
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:receipts.db?mode=memory")),
            None
        );
    }

    #[test]
    fn classifies_in_memory_sqlite_paths() {
        for path in [
            ":memory:",
            ":MEMORY:",
            "file::memory:",
            "file:receipts.db?mode=memory",
            "file:receipts.db?cache=shared&mode=memory",
        ] {
            assert!(
                is_in_memory_sqlite_path(path),
                "{path} must classify as in-memory"
            );
        }
    }

    #[test]
    fn classifies_durable_sqlite_paths() {
        for path in [
            "receipts.db",
            "/var/lib/chio/receipts.db",
            "file:/var/lib/chio/receipts.db?mode=rwc",
            "file:receipts.db",
            "memory-notes.db",
        ] {
            assert!(
                !is_in_memory_sqlite_path(path),
                "{path} must classify as durable"
            );
        }
    }
}
