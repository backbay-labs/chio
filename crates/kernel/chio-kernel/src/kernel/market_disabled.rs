//! Fail-closed stand-ins for the finding-market lane when the
//! `finding-market` feature is compiled out.
//!
//! Integration seams (dispatch, evaluation, the durable finalizer) call the
//! same methods in both builds. Without the feature, a grant that carries a
//! purchase or recovery marker denies with a configuration error before any
//! nonce, budget, or dispatch mutation, and evidence that could only have
//! been produced by the compiled lane is rejected rather than trusted.

use chio_core::capability::scope::{Constraint, ToolGrant};

use super::delivery_contract::{DeliveryEvaluation, VerifiedFindingRecoveryAdmission};
use super::{ChioKernel, KernelError};
use crate::finding_denial::FindingDenial;
use crate::finding_purchase::VerifiedFindingPurchase;
use crate::finding_purchase::VerifiedFindingStatusProof;
use crate::finding_recovery::VerifiedFindingRecovery;
use crate::runtime::ToolCallRequest;

const MARKET_DISABLED: &str = "finding market support is not compiled into this kernel";

fn market_marked(grant: &ToolGrant) -> bool {
    grant.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            Constraint::RequireFindingPurchase(_) | Constraint::RequireFindingRecovery(_)
        )
    })
}

impl ChioKernel {
    pub(crate) fn verify_purchase_admission(
        &self,
        grant: &ToolGrant,
        _request: &ToolCallRequest,
        _now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingPurchase>, FindingDenial> {
        if market_marked(grant) {
            return Err(FindingDenial::unavailable(MARKET_DISABLED));
        }
        Ok(None)
    }

    pub(crate) fn verify_recovery_admission(
        &self,
        grant: &ToolGrant,
        _request: &ToolCallRequest,
        _now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingRecovery>, FindingDenial> {
        if market_marked(grant) {
            return Err(FindingDenial::unavailable(MARKET_DISABLED));
        }
        Ok(None)
    }

    pub(crate) fn verify_recovery_status_admission(
        &self,
        grant: &ToolGrant,
        _request: &ToolCallRequest,
        _now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingRecoveryAdmission>, FindingDenial> {
        if market_marked(grant) {
            return Err(FindingDenial::unavailable(MARKET_DISABLED));
        }
        Ok(None)
    }

    pub(crate) fn capture_purchase_replay_metadata(
        &self,
        _request: &ToolCallRequest,
        _matched_grant_index: usize,
        verified_purchase: Option<&VerifiedFindingPurchase>,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        if verified_purchase.is_some() {
            return Err(KernelError::DurableAdmission(MARKET_DISABLED.to_owned()));
        }
        Ok(None)
    }

    pub(crate) fn capture_recovery_replay_metadata(
        &self,
        _request: &ToolCallRequest,
        _matched_grant_index: usize,
        verified_recovery: Option<&VerifiedFindingRecoveryAdmission>,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        if verified_recovery.is_some() {
            return Err(KernelError::DurableAdmission(MARKET_DISABLED.to_owned()));
        }
        Ok(None)
    }

    pub(crate) fn restore_purchase_replay_snapshot(
        &self,
        grant: &ToolGrant,
        _request: &ToolCallRequest,
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<VerifiedFindingPurchase>, KernelError> {
        let carries_snapshot =
            metadata
                .and_then(serde_json::Value::as_object)
                .is_some_and(|metadata| {
                    metadata.contains_key(
                        crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY,
                    )
                });
        if market_marked(grant) || carries_snapshot {
            return Err(KernelError::DurableAdmission(MARKET_DISABLED.to_owned()));
        }
        Ok(None)
    }

    pub(crate) fn restore_recovery_replay_snapshot(
        &self,
        grant: &ToolGrant,
        _request: &ToolCallRequest,
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<VerifiedFindingRecoveryAdmission>, KernelError> {
        let carries_snapshot =
            metadata
                .and_then(serde_json::Value::as_object)
                .is_some_and(|metadata| {
                    metadata.contains_key(
                        crate::finding_recovery::FINDING_RECOVERY_REPLAY_SNAPSHOT_METADATA_KEY,
                    )
                });
        if market_marked(grant) || carries_snapshot {
            return Err(KernelError::DurableAdmission(MARKET_DISABLED.to_owned()));
        }
        Ok(None)
    }

    pub(crate) fn revalidate_completed_purchase_status(
        &self,
        purchase: Option<&VerifiedFindingPurchase>,
        _now_unix_secs: u64,
    ) -> Result<(), String> {
        if purchase.is_some() {
            return Err(MARKET_DISABLED.to_owned());
        }
        Ok(())
    }

    pub(crate) fn revalidate_replayed_purchase_delivery(
        &self,
        _retained_decision: Option<&chio_core::receipt::decision::Decision>,
        _evaluation: &mut DeliveryEvaluation,
        purchase: Option<&VerifiedFindingPurchase>,
        _now_unix_secs: u64,
    ) -> Option<String> {
        purchase.map(|_| MARKET_DISABLED.to_owned())
    }

    pub(crate) fn revalidate_completed_recovery_status(
        &self,
        _matched_grant_index: usize,
        _request: &ToolCallRequest,
        expected: Option<&VerifiedFindingRecovery>,
        admitted_status: Option<&VerifiedFindingStatusProof>,
        _now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        if expected.is_some() || admitted_status.is_some() {
            return Err(FindingDenial::unavailable(MARKET_DISABLED));
        }
        Ok(())
    }

    /// Startup reconciliation has nothing to reconcile without a pool
    /// ledger.
    pub(crate) fn reconcile_finding_pool_terminal_claims(&self) -> Result<usize, KernelError> {
        Ok(0)
    }

    /// Startup reconciliation has nothing to flush without a pool ledger.
    pub(crate) fn reconcile_finding_pool_mutation_receipts(&self) -> Result<usize, KernelError> {
        Ok(0)
    }

    pub(crate) fn claim_finding_pool_delivery(
        &self,
        _purchase: &VerifiedFindingPurchase,
        _request_id: &str,
        _trusted_now_unix_ms: u64,
        _durable_admission_operation_id: Option<&str>,
    ) -> Result<(), crate::finding_pool::FindingPoolLedgerError> {
        Err(crate::finding_pool::FindingPoolLedgerError::Storage(
            MARKET_DISABLED.to_owned(),
        ))
    }

    pub(crate) fn release_finding_pool_claim_before_dispatch(
        &self,
        _durable_admission_operation_id: &str,
        _trusted_now_unix_ms: u64,
    ) -> Result<(), crate::finding_pool::FindingPoolLedgerError> {
        Err(crate::finding_pool::FindingPoolLedgerError::Storage(
            MARKET_DISABLED.to_owned(),
        ))
    }

    pub(crate) fn finalize_finding_pool_claim_after_unknown_dispatch(
        &self,
        _durable_admission_operation_id: &str,
        _trusted_now_unix_ms: u64,
    ) -> Result<(), crate::finding_pool::FindingPoolLedgerError> {
        Err(crate::finding_pool::FindingPoolLedgerError::Storage(
            MARKET_DISABLED.to_owned(),
        ))
    }

    pub(crate) fn settle_finding_pool_delivery_terminal(
        &self,
        _durable_admission_operation_id: &str,
        _purchase: &VerifiedFindingPurchase,
        _disposition: &crate::tool_outcome::SettlementDispositionV1,
    ) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(MARKET_DISABLED.to_owned()))
    }

    pub(crate) fn require_finding_pool_delivery_terminal(
        &self,
        _purchase: &VerifiedFindingPurchase,
        _disposition: &crate::tool_outcome::SettlementDispositionV1,
    ) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(MARKET_DISABLED.to_owned()))
    }
}
