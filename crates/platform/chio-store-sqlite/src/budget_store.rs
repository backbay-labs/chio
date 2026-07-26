use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::scope::MonetaryAmount;
use chio_kernel::budget_store::{
    ApprovalRequiredBudgetHold, AuthorizedBudgetHold, BudgetAdmissionBinding,
    BudgetAuthorizationOutcome, BudgetAuthorizeCumulativeApprovalRequest,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureHoldDecision, BudgetCaptureHoldRequest,
    BudgetCaptureInvocationRequest, BudgetCapturedBeforeDispatchCancellationDecision,
    BudgetCommitMetadata, BudgetCumulativeApprovalAccountKey, BudgetCumulativeApprovalAccountUsage,
    BudgetCumulativeApprovalAuthorizationDecision, BudgetCumulativeApprovalMutation,
    BudgetCumulativeApprovalRequest, BudgetCumulativeApprovalState, BudgetCumulativeApprovalUsage,
    BudgetEventAuthority, BudgetGuaranteeLevel, BudgetHoldDispositionView,
    BudgetHoldMutationDecision, BudgetHoldSnapshot, BudgetInvocationCaptureDecision,
    BudgetInvocationQuota, BudgetInvocationQuotaMutation, BudgetInvocationQuotaUsage,
    BudgetInvocationState, BudgetMonetaryState, BudgetMutationKind, BudgetMutationRecord,
    BudgetQuotaKey, BudgetQuotaProfile, BudgetReconcileHoldDecision, BudgetReconcileHoldRequest,
    BudgetReleaseHoldDecision, BudgetReleaseHoldRequest, BudgetReverseHoldDecision,
    BudgetReverseHoldRequest, DeniedBudgetHold, ReservedHoldEnvelope, RevocationCommitMetadata,
};
use chio_kernel::payment::{
    PaymentJournalRecord, PaymentJournalState, PaymentJournalTransition, PaymentRailMode,
    PaymentReleaseAuthorityBinding, PaymentReleaseAuthorityKind, PaymentSettleAction,
};
use chio_kernel::tool_outcome::{MonetaryReleaseEvidenceKindV1, MonetaryReleaseEvidenceV1};
use chio_kernel::{BudgetStore, BudgetStoreError, BudgetUsageRecord, CanonicalRevocationSet};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

mod authorization;
mod composite;
pub(crate) use composite::{AdmissionAuthorizationBinding, AdmissionCaptureBinding};
pub(crate) mod composite_schema;
mod import_hold_state;
mod import_validation;
mod joint_guard;
mod model;
mod payment_journal;
pub(crate) use payment_journal::{
    advance_payment_journal, insert_payment_journal, load_payment_journal,
};
mod reaper;
mod replication;
mod rows;
mod schema;
mod snapshot;
mod store;
mod trait_impl;

pub use reaper::ReapSummary;
pub use snapshot::{
    budget_snapshot_anchor_authenticator, budget_snapshot_anchor_chain_digest,
    budget_snapshot_anchor_set_digest, BudgetSnapshotAnchorCommitment,
    BudgetSnapshotAnchorProvenance, BudgetStoreSnapshot, SignedBudgetSnapshotAnchorCommitment,
};
pub(crate) use store::BUDGET_STORE_SUPPORTED_SCHEMA_VERSION;

#[cfg(test)]
#[path = "budget_store/tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;

use composite_schema::*;
use model::{HoldDisposition, SqliteBudgetHold};
use replication::*;
use rows::*;
use schema::*;

#[derive(Clone)]
pub struct SqliteBudgetStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Option<Arc<crate::serving_owner::SqliteServingOwner>>,
}
