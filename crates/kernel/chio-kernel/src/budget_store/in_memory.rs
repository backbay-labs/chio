use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    budget_commit_metadata, checked_committed_cost_units, validate_optional_budget_identity,
    ApprovalRequiredBudgetHold, AuthorizedBudgetHold, BudgetAdmissionBinding,
    BudgetAuthorizationOutcome, BudgetAuthorizeCumulativeApprovalRequest,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCancelCapturedBeforeDispatchRequest, BudgetCaptureHoldDecision, BudgetCaptureHoldRequest,
    BudgetCaptureInvocationRequest, BudgetCapturedBeforeDispatchCancellationDecision,
    BudgetCumulativeApprovalAccountKey, BudgetCumulativeApprovalAccountUsage,
    BudgetCumulativeApprovalAuthorizationDecision, BudgetCumulativeApprovalMutation,
    BudgetCumulativeApprovalRequest, BudgetCumulativeApprovalState, BudgetCumulativeApprovalUsage,
    BudgetEventAuthority, BudgetHoldDispositionView, BudgetHoldMutationDecision,
    BudgetHoldSnapshot, BudgetInvocationCaptureDecision, BudgetInvocationQuota,
    BudgetInvocationQuotaMutation, BudgetInvocationQuotaUsage, BudgetInvocationState,
    BudgetMonetaryState, BudgetMutationKind, BudgetMutationRecord, BudgetQuotaKey,
    BudgetReconcileHoldDecision, BudgetReconcileHoldRequest, BudgetReleaseHoldDecision,
    BudgetReleaseHoldRequest, BudgetReverseHoldDecision, BudgetReverseHoldRequest, BudgetStore,
    BudgetStoreError, BudgetUsageRecord, DeniedBudgetHold, ReservedHoldEnvelope,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetHoldState {
    capability_id: String,
    grant_index: usize,
    admission_binding: Option<BudgetAdmissionBinding>,
    authorized_exposure_units: u64,
    remaining_exposure_units: u64,
    invocation_state: BudgetInvocationState,
    invocation_quotas: Vec<BudgetInvocationQuota>,
    legacy_captured_invocation_quota: Option<BudgetInvocationQuota>,
    captured_cancellation_allowed: bool,
    cumulative_approval: Option<BudgetCumulativeApprovalHoldState>,
    monetary_state: BudgetMonetaryState,
    authority: Option<BudgetEventAuthority>,
    reserved_until: Option<i64>,
    reserved_currency: Option<String>,
    reserved_payment_reference: Option<String>,
    reserved_envelope: ReservedHoldEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetCumulativeApprovalHoldState {
    request: BudgetCumulativeApprovalRequest,
    state: BudgetCumulativeApprovalState,
    approval_set_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetInvocationQuotaState {
    max_invocations: u32,
    reserved_invocations: u32,
    captured_invocations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetCumulativeApprovalAccountState {
    authority_threshold_units: u64,
    reserved_authorized_units: u64,
    captured_authorized_units: u64,
    version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BudgetMutationRequest {
    Increment {
        capability_id: String,
        grant_index: usize,
        max_invocations: Option<u32>,
    },
    Authorize {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        cost_units: u64,
        max_invocations: Option<u32>,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        authority: Option<BudgetEventAuthority>,
    },
    AuthorizeComposite(Box<BudgetAuthorizeHoldRequest>),
    AuthorizeCumulativeApproval(Box<BudgetAuthorizeCumulativeApprovalRequest>),
    CaptureInvocation {
        capability_id: String,
        grant_index: usize,
        hold_id: String,
        trusted_time: Option<u64>,
        authority: Option<BudgetEventAuthority>,
    },
    CancelCapturedBeforeDispatch {
        capability_id: String,
        grant_index: usize,
        hold_id: String,
        authority: Option<BudgetEventAuthority>,
    },
    Reverse {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        cost_units: u64,
        expected_cumulative_approval_state: Option<BudgetCumulativeApprovalState>,
        authority: Option<BudgetEventAuthority>,
    },
    Release {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        cost_units: u64,
        authority: Option<BudgetEventAuthority>,
    },
    Reconcile {
        capability_id: String,
        grant_index: usize,
        hold_id: Option<String>,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        authority: Option<BudgetEventAuthority>,
    },
    CaptureMonetary(BudgetCaptureHoldRequest),
}

#[derive(Debug, Clone)]
struct RecordedBudgetMutation {
    request: BudgetMutationRequest,
    record: BudgetMutationRecord,
}

pub struct InMemoryBudgetStore {
    inner: Mutex<InMemoryBudgetStoreInner>,
}

impl Default for InMemoryBudgetStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(InMemoryBudgetStoreInner::default()),
        }
    }
}

impl InMemoryBudgetStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, InMemoryBudgetStoreInner>, BudgetStoreError> {
        self.inner.lock().map_err(|_| {
            BudgetStoreError::Invariant("in-memory budget store lock poisoned".to_string())
        })
    }

    fn recorded_mutation_decision(
        &self,
        inner: &InMemoryBudgetStoreInner,
        event_id: Option<&str>,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let event = match event_id {
            Some(event_id) => inner.events.iter().find(|event| event.event_id == event_id),
            None => inner.events.last(),
        }
        .cloned()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "mutation event disappeared while building decision".to_string(),
            )
        })?;
        Ok(BudgetHoldMutationDecision {
            hold_id: event.hold_id,
            admission_binding: event.admission_binding,
            exposure_units: event.exposure_units,
            realized_spend_units: event.realized_spend_units,
            committed_cost_units_after: checked_committed_cost_units(
                event.total_cost_exposed_after,
                event.total_cost_realized_spend_after,
            )?,
            invocation_count_after: event.invocation_count_after,
            invocation_quota_usages: event.invocation_quota_usages,
            cumulative_approval: event.cumulative_approval,
            invocation_state: event.invocation_state_after,
            monetary_state: event.monetary_state_after,
            metadata: budget_commit_metadata(
                self,
                event.authority,
                Some(event.event_seq),
                Some(event.event_id),
                Some(event.recorded_at),
            ),
        })
    }
}

#[derive(Default)]
struct InMemoryBudgetStoreInner {
    counts: HashMap<(String, usize), BudgetUsageRecord>,
    events: Vec<BudgetMutationRecord>,
    explicit_events: HashMap<String, RecordedBudgetMutation>,
    holds: HashMap<String, BudgetHoldState>,
    hold_authorizations: HashMap<String, BudgetMutationRequest>,
    operation_authorizations: HashMap<String, BudgetMutationRequest>,
    invocation_quotas: HashMap<BudgetQuotaKey, BudgetInvocationQuotaState>,
    legacy_reversible_invocations: HashMap<(String, usize), u32>,
    cumulative_approval_accounts:
        HashMap<BudgetCumulativeApprovalAccountKey, BudgetCumulativeApprovalAccountState>,
    next_seq: u64,
}

include!("in_memory/composite.rs");
include!("in_memory/admission.rs");
include!("in_memory/terminal.rs");
include!("in_memory/trait_impl.rs");

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
