use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionBeginResult {
    Created(AdmissionOperationV1),
    ExactReplay {
        operation: AdmissionOperationV1,
        terminal_replay: Option<AdmissionTerminalReplay>,
    },
    Conflict {
        existing_operation_id: AdmissionOperationId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionOperationStoreError {
    #[error("admission operation store is unavailable: {0}")]
    Unavailable(String),
    #[error("admission operation mutation was fenced")]
    Fenced,
    #[error("admission operation was not found")]
    NotFound,
    #[error("admission operation invariant failed: {0}")]
    Invariant(String),
    #[error("admission operation durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error(transparent)]
    Operation(#[from] AdmissionOperationError),
}

pub trait AdmissionOperationStore: Send + Sync {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError>;

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError>;

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError>;

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError>;

    /// Persist a structurally checked claim. The returned value remains
    /// untrusted until `QualifiedAdmissionOperationStore::claim_recovery`
    /// rechecks it through this store.
    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError>;

    /// Re-read the durable claim under the current store fence and verify its
    /// exact operation snapshot and historical coordinator lease.
    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError>;

    /// Lists non-terminal operations that require startup recovery work.
    ///
    /// Quiescent `ApprovalRequired` operations must be excluded before applying
    /// `limit`: they are waiting for external approval rather than recovery, and
    /// allowing them to occupy a page can starve later operations that do need
    /// reconciliation.
    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError>;

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError>;
}

/// Explicit trust boundary for stores allowed to qualify durable recovery
/// claims.
///
/// # Implementation contract
///
/// Implementations must durably serialize claims with operation mutations,
/// enforce the current serving-owner fence and trusted time, and revalidate the
/// exact persisted claim and historical coordinator lease. An implementation
/// that returns success without those guarantees can authorize an unsafe
/// recovery transition.
pub trait QualifiedAdmissionOperationStore: AdmissionOperationStore {}

/// Non-overridable recovery qualification for explicitly trusted stores.
pub trait QualifiedAdmissionOperationStoreExt: QualifiedAdmissionOperationStore {
    fn claim_recovery(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<AdmissionRecoveryLease, AdmissionOperationStoreError> {
        let claim = self.claim_recovery_untrusted(
            operation_id,
            expected_version,
            claimant_id,
            trusted_now_unix_ms,
            expires_at_unix_ms,
            current_store_fence,
        )?;
        let operation = self
            .load_by_operation_id(operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        claim.validate_for_qualification(
            &operation,
            expected_version,
            claimant_id,
            trusted_now_unix_ms,
            expires_at_unix_ms,
            current_store_fence,
        )?;
        self.revalidate_recovery_claim(
            &operation,
            &claim,
            trusted_now_unix_ms,
            current_store_fence,
        )?;
        Ok(AdmissionRecoveryLease::from_qualified(claim))
    }
}

impl<T: QualifiedAdmissionOperationStore + ?Sized> QualifiedAdmissionOperationStoreExt for T {}
