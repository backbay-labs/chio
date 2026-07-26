use thiserror::Error;

use crate::hook::{SettlementFailureReason, SettlementSkipReason};
use crate::retry::RetryPolicy;

/// Maximum UTF-8 byte length of a settlement worker identifier.
pub const MAX_SETTLEMENT_WORKER_ID_BYTES: usize = 128;

/// Maximum settlement claim lease duration in milliseconds.
pub const MAX_SETTLEMENT_LEASE_MS: u64 = 86_400_000;

/// Maximum number of rows returned by one settlement claim.
pub const MAX_SETTLEMENT_CLAIM_BATCH: usize = 1024;

/// Invalid settlement claim parameters.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SettlementClaimValidationError {
    /// Worker identifier is empty or exceeds its UTF-8 byte bound.
    #[error("settlement worker id length is out of bounds")]
    WorkerIdLength,
    /// Lease duration is zero or exceeds the one-day bound.
    #[error("settlement lease duration is out of bounds")]
    LeaseDuration,
    /// Claim batch is zero or exceeds the row-count bound.
    #[error("settlement claim batch size is out of bounds")]
    ClaimBatch,
}

/// Validate parameters shared by settlement claim operations.
pub fn validate_settlement_claim(
    worker_id: &str,
    lease_ms: u64,
    limit: usize,
) -> Result<(), SettlementClaimValidationError> {
    if worker_id.is_empty() || worker_id.len() > MAX_SETTLEMENT_WORKER_ID_BYTES {
        return Err(SettlementClaimValidationError::WorkerIdLength);
    }
    if lease_ms == 0 || lease_ms > MAX_SETTLEMENT_LEASE_MS {
        return Err(SettlementClaimValidationError::LeaseDuration);
    }
    if limit == 0 || limit > MAX_SETTLEMENT_CLAIM_BATCH {
        return Err(SettlementClaimValidationError::ClaimBatch);
    }
    Ok(())
}

/// Opaque identity shared by receipt and outcome views of one durable writer.
///
/// Backends generate one value per writer instance and copy it into every
/// handle that participates in the same atomic settlement ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SettlementStoreBinding([u8; 32]);

impl SettlementStoreBinding {
    /// Construct a binding from a backend-generated digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Return the backend-generated digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Normalized outcome accepted by durable settlement routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementRoutingInput {
    /// The hook durably accepted the observation.
    Accepted,
    /// The observation legitimately requires no settlement work.
    Skipped { reason: SettlementSkipReason },
    /// The observation may succeed when replayed.
    Retryable { reason: SettlementFailureReason },
    /// The observation must terminate without replay.
    Permanent { reason: SettlementFailureReason },
}

/// Persisted row and lease state required to commit a settlement transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementAttemptClaim {
    /// Receipt bound to the claimed row.
    pub receipt_id: String,
    /// Receipt finalization timestamp persisted with the row.
    pub finalized_at: u64,
    /// Completed hook invocations persisted before this claim.
    pub attempts: u32,
    /// Version incremented when the claim was acquired.
    pub row_version: u64,
    /// Worker that owns the lease.
    pub lease_owner: String,
    /// Unpredictable token required by the outcome CAS.
    pub lease_token: String,
    /// Exclusive lease deadline in milliseconds.
    pub lease_until_ms: u64,
}

/// Result of atomically recording a claimed settlement outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementRoute {
    /// The claimed row was removed without further work.
    NoAction,
    /// The claimed row was rescheduled for retry.
    RetryScheduled {
        /// Persisted attempt number for the next invocation.
        attempt: u32,
        /// Earliest visibility time in milliseconds.
        next_visible_at_ms: u64,
    },
    /// The failure was committed as terminal.
    DeadLettered {
        /// Total hook invocations represented by the dead letter.
        attempts: u32,
    },
}

/// Bounded class for settlement routing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementRouteErrorClass {
    /// Persistence backend failure.
    Backend,
    /// Lease, version, or terminal-state conflict.
    Conflict,
    /// Invalid or overflowing durable data.
    InvalidRecord,
}

/// Failure returned by the durable settlement router.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SettlementRouteError {
    #[error("settlement routing backend failure: {detail}")]
    Backend { detail: String },
    #[error("settlement routing conflict: {detail}")]
    Conflict { detail: String },
    #[error("invalid settlement routing record: {detail}")]
    InvalidRecord { detail: String },
}

impl SettlementRouteError {
    /// Return the stable class suitable for bounded telemetry.
    #[must_use]
    pub const fn class(&self) -> SettlementRouteErrorClass {
        match self {
            Self::Backend { .. } => SettlementRouteErrorClass::Backend,
            Self::Conflict { .. } => SettlementRouteErrorClass::Conflict,
            Self::InvalidRecord { .. } => SettlementRouteErrorClass::InvalidRecord,
        }
    }
}

/// Atomic leased store for settlement outcomes.
pub trait SettlementOutcomeStore: Send + Sync {
    /// Identify the durable writer that owns this outcome store.
    fn settlement_store_binding(&self) -> SettlementStoreBinding;

    /// Claim one due row by receipt id, or return `None` when a live lease owns it.
    fn claim_receipt(
        &self,
        receipt_id: &str,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError>;

    /// Claim a bounded due batch using the same lease and version rules.
    fn claim_due(
        &self,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError>;

    /// Atomically commit an outcome for an exact, unexpired claim.
    ///
    /// Terminal timestamps and attempt counts come from the persisted claim,
    /// not from caller-supplied duplicates.
    ///
    /// `observed_at_ms` is both the lease-validity check time and the base for
    /// any retry visibility deadline.
    fn record_claimed_outcome(
        &self,
        claim: &SettlementAttemptClaim,
        outcome: &SettlementRoutingInput,
        policy: RetryPolicy,
        observed_at_ms: u64,
    ) -> Result<SettlementRoute, SettlementRouteError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_claim_carries_the_persisted_cas_state() {
        let claim = SettlementAttemptClaim {
            receipt_id: "receipt-1".to_string(),
            finalized_at: 41,
            attempts: 2,
            row_version: 3,
            lease_owner: "worker-1".to_string(),
            lease_token: "token-1".to_string(),
            lease_until_ms: 50,
        };

        assert_eq!(claim.finalized_at, 41);
        assert_eq!(claim.attempts, 2);
        assert_eq!(claim.lease_owner, "worker-1");
    }

    #[test]
    fn claim_parameters_are_bounded() {
        assert!(validate_settlement_claim("worker", 1, 1).is_ok());
        assert!(validate_settlement_claim(
            &"w".repeat(MAX_SETTLEMENT_WORKER_ID_BYTES),
            MAX_SETTLEMENT_LEASE_MS,
            MAX_SETTLEMENT_CLAIM_BATCH,
        )
        .is_ok());
        assert!(validate_settlement_claim(&"\u{e9}".repeat(64), 1, 1).is_ok());

        let invalid = [
            (
                validate_settlement_claim("", 1, 1),
                SettlementClaimValidationError::WorkerIdLength,
            ),
            (
                validate_settlement_claim(&"w".repeat(MAX_SETTLEMENT_WORKER_ID_BYTES + 1), 1, 1),
                SettlementClaimValidationError::WorkerIdLength,
            ),
            (
                validate_settlement_claim(&"\u{e9}".repeat(65), 1, 1),
                SettlementClaimValidationError::WorkerIdLength,
            ),
            (
                validate_settlement_claim("worker", 0, 1),
                SettlementClaimValidationError::LeaseDuration,
            ),
            (
                validate_settlement_claim("worker", MAX_SETTLEMENT_LEASE_MS + 1, 1),
                SettlementClaimValidationError::LeaseDuration,
            ),
            (
                validate_settlement_claim("worker", 1, 0),
                SettlementClaimValidationError::ClaimBatch,
            ),
            (
                validate_settlement_claim("worker", 1, MAX_SETTLEMENT_CLAIM_BATCH + 1),
                SettlementClaimValidationError::ClaimBatch,
            ),
        ];

        for (result, expected) in invalid {
            assert_eq!(result, Err(expected));
        }
    }

    #[test]
    fn outcome_store_error_classes_are_bounded() {
        let cases = [
            (
                SettlementRouteError::Backend {
                    detail: "db unavailable".to_string(),
                },
                SettlementRouteErrorClass::Backend,
            ),
            (
                SettlementRouteError::Conflict {
                    detail: "stale lease".to_string(),
                },
                SettlementRouteErrorClass::Conflict,
            ),
            (
                SettlementRouteError::InvalidRecord {
                    detail: "negative counter".to_string(),
                },
                SettlementRouteErrorClass::InvalidRecord,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.class(), expected);
        }
    }

    #[test]
    fn outcome_store_trait_is_object_safe() {
        fn accepts_trait_object(_store: &dyn SettlementOutcomeStore) {}

        let _ = accepts_trait_object;
    }
}
