use chio_core::capability::scope::MonetaryAmount;

use crate::supplemental_quota::CanonicalRevocationSet;

#[derive(Debug, thiserror::Error)]
pub enum BudgetStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare budget store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("budget arithmetic overflow: {0}")]
    Overflow(String),

    #[error(
        "budget mutation fenced: expected owner epoch {expected_epoch}, actual owner epoch {actual_epoch:?}"
    )]
    Fenced {
        expected_epoch: u64,
        actual_epoch: Option<u64>,
    },

    #[error("budget state invariant violated: {0}")]
    Invariant(String),

    #[error("budget mutation durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,
    pub total_cost_exposed: u64,
    pub total_cost_realized_spend: u64,
}

impl BudgetUsageRecord {
    pub fn committed_cost_units(&self) -> Result<u64, BudgetStoreError> {
        checked_committed_cost_units(self.total_cost_exposed, self.total_cost_realized_spend)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetMutationKind {
    IncrementInvocation,
    ReserveInvocation,
    AuthorizeExposure,
    CaptureInvocation,
    AuthorizeCumulativeApproval,
    ReverseInvocation,
    CancelCapturedBeforeDispatch,
    ReverseExposure,
    ReleaseExposure,
    ReconcileSpend,
    CaptureSpend,
}

impl BudgetMutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncrementInvocation => "increment_invocation",
            Self::ReserveInvocation => "reserve_invocation",
            Self::AuthorizeExposure => "authorize_exposure",
            Self::CaptureInvocation => "capture_invocation",
            Self::AuthorizeCumulativeApproval => "authorize_cumulative_approval",
            Self::ReverseInvocation => "reverse_invocation",
            Self::CancelCapturedBeforeDispatch => "cancel_captured_before_dispatch",
            Self::ReverseExposure => "reverse_exposure",
            Self::ReleaseExposure => "release_exposure",
            Self::ReconcileSpend => "reconcile_spend",
            Self::CaptureSpend => "capture_spend",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "increment_invocation" => Some(Self::IncrementInvocation),
            "reserve_invocation" => Some(Self::ReserveInvocation),
            "authorize_exposure" => Some(Self::AuthorizeExposure),
            "capture_invocation" => Some(Self::CaptureInvocation),
            "authorize_cumulative_approval" => Some(Self::AuthorizeCumulativeApproval),
            "reverse_invocation" => Some(Self::ReverseInvocation),
            "cancel_captured_before_dispatch" => Some(Self::CancelCapturedBeforeDispatch),
            "reverse_exposure" => Some(Self::ReverseExposure),
            "release_exposure" => Some(Self::ReleaseExposure),
            "reconcile_spend" => Some(Self::ReconcileSpend),
            "capture_spend" => Some(Self::CaptureSpend),
            _ => None,
        }
    }
}

include!("budget_store/model.rs");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAuthorizeHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub max_invocations: Option<u32>,
    pub invocation_quotas: Vec<BudgetInvocationQuota>,
    pub cumulative_approval: Option<BudgetCumulativeApprovalRequest>,
    pub admission_binding: Option<BudgetAdmissionBinding>,
    pub requested_exposure_units: u64,
    pub max_cost_per_invocation: Option<u64>,
    pub max_total_cost_units: Option<u64>,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

impl BudgetAuthorizeHoldRequest {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        self.validate_composite().map(|_| ())
    }

    fn validated_invocation_quotas(&self) -> Result<Vec<BudgetInvocationQuota>, BudgetStoreError> {
        if self.invocation_quotas.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
            return Err(BudgetStoreError::Invariant(format!(
                "at most {MAX_INVOCATION_QUOTAS_PER_ADMISSION} invocation quotas are allowed"
            )));
        }
        for quota in &self.invocation_quotas {
            quota.key.validate()?;
        }
        if self
            .invocation_quotas
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
        {
            return Err(BudgetStoreError::Invariant(
                "invocation quotas must be strictly sorted by unique key".to_string(),
            ));
        }

        if self.invocation_quotas.is_empty() {
            return self
                .max_invocations
                .map(|max_invocations| {
                    u32::try_from(self.grant_index)
                        .map(|grant_index| {
                            vec![BudgetInvocationQuota {
                                key: BudgetQuotaKey::grant(self.capability_id.clone(), grant_index),
                                max_invocations,
                            }]
                        })
                        .map_err(|_| {
                            BudgetStoreError::Invariant(
                                "grant_index does not fit the budget quota key".to_string(),
                            )
                        })
                })
                .transpose()
                .map(Option::unwrap_or_default);
        }

        let grant_index = u32::try_from(self.grant_index).map_err(|_| {
            BudgetStoreError::Invariant("grant_index does not fit the budget quota key".to_string())
        })?;
        let expected_key = BudgetQuotaKey::grant(self.capability_id.clone(), grant_index);
        let grant_quotas = self
            .invocation_quotas
            .iter()
            .filter(|quota| quota.key.profile == BudgetQuotaProfile::GrantInvocation)
            .collect::<Vec<_>>();
        if grant_quotas.len() > 1
            || grant_quotas
                .first()
                .is_some_and(|quota| quota.key != expected_key)
        {
            return Err(BudgetStoreError::Invariant(
                "structured grant quota must match the authorization capability and grant"
                    .to_string(),
            ));
        }

        if let Some(max_invocations) = self.max_invocations {
            if !self
                .invocation_quotas
                .iter()
                .any(|quota| quota.key == expected_key && quota.max_invocations == max_invocations)
            {
                return Err(BudgetStoreError::Invariant(
                    "legacy max_invocations must match the structured grant quota".to_string(),
                ));
            }
        }
        Ok(self.invocation_quotas.clone())
    }

    fn validate_composite(&self) -> Result<Vec<BudgetInvocationQuota>, BudgetStoreError> {
        let quotas = self.validated_invocation_quotas()?;
        validate_optional_budget_identity(
            self.hold_id.as_deref(),
            self.event_id.as_deref(),
            "budget authorization",
        )?;
        let durable = !quotas.is_empty()
            || self.cumulative_approval.is_some()
            || self.admission_binding.is_some();
        if durable
            && (self.hold_id.as_deref().is_none_or(str::is_empty)
                || self.event_id.as_deref().is_none_or(str::is_empty))
        {
            return Err(BudgetStoreError::Invariant(
                "composite budget authorization requires non-empty hold_id and event_id"
                    .to_string(),
            ));
        }
        let composite = !self.invocation_quotas.is_empty() || self.cumulative_approval.is_some();
        if composite && self.admission_binding.is_none() {
            return Err(BudgetStoreError::Invariant(
                "composite budget authorization requires an admission binding".to_string(),
            ));
        }
        if let Some(binding) = &self.admission_binding {
            binding.validate()?;
            if binding
                .revocation_set
                .ids()
                .binary_search(&self.capability_id)
                .is_err()
            {
                return Err(BudgetStoreError::Invariant(
                    "admission revocation set must contain the leaf capability".to_string(),
                ));
            }
            let has_supplemental = quotas.iter().any(|quota| {
                quota.key.profile == BudgetQuotaProfile::SupplementalBrokerCapabilityExecution
            });
            let supplemental_fields = [
                binding.supplemental_verifier_id.as_deref(),
                binding.supplemental_verifier_config_digest.as_deref(),
                binding
                    .supplemental_authorization_artifact_digest
                    .as_deref(),
            ];
            let has_complete_supplemental_binding = supplemental_fields
                .iter()
                .all(|value| value.is_some_and(|value| !value.is_empty()))
                && binding.supplemental_authorization_expires_at.is_some();
            let has_any_supplemental_binding = supplemental_fields.iter().any(Option::is_some)
                || binding.supplemental_authorization_expires_at.is_some();
            if has_supplemental != has_complete_supplemental_binding
                || has_any_supplemental_binding != has_complete_supplemental_binding
            {
                return Err(BudgetStoreError::Invariant(
                    "supplemental quota and verifier, artifact, and expiry bindings must be presented together"
                        .to_string(),
                ));
            }
        }
        if let Some(cumulative) = &self.cumulative_approval {
            cumulative.account_key.validate()?;
            if cumulative.operation_id.is_empty() {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval operation_id must not be empty".to_string(),
                ));
            }
            if self
                .admission_binding
                .as_ref()
                .is_none_or(|binding| binding.operation_id != cumulative.operation_id)
            {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval operation does not match admission binding".to_string(),
                ));
            }
            let currency = cumulative.account_key.currency.as_str();
            if cumulative.authority_threshold.currency != currency
                || cumulative.effective_threshold.currency != currency
                || cumulative.requested_authorized.currency != currency
            {
                return Err(BudgetStoreError::Invariant(
                    "cumulative approval amounts must use the account currency".to_string(),
                ));
            }
            if cumulative.effective_threshold.units > cumulative.authority_threshold.units {
                return Err(BudgetStoreError::Invariant(
                    "effective cumulative threshold exceeds authority threshold".to_string(),
                ));
            }
        }
        Ok(quotas)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReleaseHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub released_exposure_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReverseHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub reversed_exposure_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub expected_cumulative_approval_state: Option<BudgetCumulativeApprovalState>,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCaptureInvocationRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub hold_id: String,
    pub event_id: String,
    pub trusted_time: Option<u64>,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAuthorizeCumulativeApprovalRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub operation_id: String,
    pub hold_id: String,
    pub admission_binding: BudgetAdmissionBinding,
    pub approval_set_digest: String,
    pub event_id: String,
    pub authority: Option<BudgetEventAuthority>,
}

impl BudgetAuthorizeCumulativeApprovalRequest {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        if self.capability_id.is_empty()
            || self.operation_id.is_empty()
            || self.hold_id.is_empty()
            || !is_sha256_digest(&self.approval_set_digest)
            || self.event_id.is_empty()
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval attachment identity must not be empty".to_string(),
            ));
        }
        u32::try_from(self.grant_index).map_err(|_| {
            BudgetStoreError::Invariant(
                "cumulative approval grant_index does not fit u32".to_string(),
            )
        })?;
        self.admission_binding.validate()?;
        if self.admission_binding.operation_id != self.operation_id {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval operation does not match admission binding".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetCumulativeApprovalAuthorizationDecision {
    Authorized(BudgetHoldMutationDecision),
    AlreadyAuthorized(BudgetHoldMutationDecision),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetInvocationCaptureDecision {
    Captured(BudgetHoldMutationDecision),
    AlreadyCaptured(BudgetHoldMutationDecision),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCancelCapturedBeforeDispatchRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub hold_id: String,
    pub event_id: String,
    pub authority: Option<BudgetEventAuthority>,
}

fn validate_optional_budget_identity(
    hold_id: Option<&str>,
    event_id: Option<&str>,
    transition: &str,
) -> Result<(), BudgetStoreError> {
    match (hold_id, event_id) {
        (None, None) => Ok(()),
        (None, Some(event_id)) if !event_id.is_empty() => Ok(()),
        (Some(hold_id), Some(event_id)) if !hold_id.is_empty() && !event_id.is_empty() => Ok(()),
        _ => Err(BudgetStoreError::Invariant(format!(
            "{transition} requires non-empty identifiers and any hold_id requires an event_id"
        ))),
    }
}

fn validate_required_budget_identity(
    hold_id: &str,
    event_id: &str,
    transition: &str,
) -> Result<(), BudgetStoreError> {
    if hold_id.is_empty() || event_id.is_empty() {
        return Err(BudgetStoreError::Invariant(format!(
            "{transition} requires non-empty hold_id and event_id"
        )));
    }
    Ok(())
}

impl BudgetCaptureInvocationRequest {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        validate_required_budget_identity(&self.hold_id, &self.event_id, "invocation capture")
    }
}

impl BudgetCancelCapturedBeforeDispatchRequest {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        validate_required_budget_identity(
            &self.hold_id,
            &self.event_id,
            "captured invocation cancellation",
        )
    }
}

impl BudgetReverseHoldRequest {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        validate_optional_budget_identity(
            self.hold_id.as_deref(),
            self.event_id.as_deref(),
            "budget reversal",
        )
    }
}

impl BudgetReleaseHoldRequest {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        validate_optional_budget_identity(
            self.hold_id.as_deref(),
            self.event_id.as_deref(),
            "budget release",
        )
    }
}

impl BudgetReconcileHoldRequest {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        validate_optional_budget_identity(
            self.hold_id.as_deref(),
            self.event_id.as_deref(),
            "budget reconciliation",
        )
    }
}

impl BudgetCaptureHoldRequest {
    pub fn validate(&self) -> Result<(), BudgetStoreError> {
        validate_optional_budget_identity(
            self.hold_id.as_deref(),
            self.event_id.as_deref(),
            "monetary capture",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetCapturedBeforeDispatchCancellationDecision {
    Cancelled(BudgetHoldMutationDecision),
    AlreadyCancelled(BudgetHoldMutationDecision),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReconcileHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub exposed_cost_units: u64,
    pub realized_spend_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetCaptureHoldRequest {
    pub capability_id: String,
    pub grant_index: usize,
    pub exposed_cost_units: u64,
    pub realized_spend_units: u64,
    pub hold_id: Option<String>,
    pub event_id: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBudgetHold {
    pub hold_id: Option<String>,
    pub admission_binding: Option<BudgetAdmissionBinding>,
    pub authorized_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub invocation_quota_usages: Vec<BudgetInvocationQuotaUsage>,
    pub cumulative_approval: Option<BudgetCumulativeApprovalUsage>,
    pub invocation_state: BudgetInvocationState,
    pub monetary_state: BudgetMonetaryState,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequiredBudgetHold {
    pub hold_id: String,
    pub admission_binding: BudgetAdmissionBinding,
    pub authorized_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub invocation_quota_usages: Vec<BudgetInvocationQuotaUsage>,
    pub cumulative_approval: BudgetCumulativeApprovalUsage,
    pub invocation_state: BudgetInvocationState,
    pub monetary_state: BudgetMonetaryState,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedBudgetHold {
    pub hold_id: Option<String>,
    pub admission_binding: Option<BudgetAdmissionBinding>,
    pub attempted_exposure_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub invocation_quota_usages: Vec<BudgetInvocationQuotaUsage>,
    pub cumulative_approval: Option<BudgetCumulativeApprovalUsage>,
    pub invocation_state: BudgetInvocationState,
    pub monetary_state: BudgetMonetaryState,
    pub metadata: BudgetCommitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetAuthorizeHoldDecision {
    Authorized(AuthorizedBudgetHold),
    ApprovalRequired(ApprovalRequiredBudgetHold),
    Denied(DeniedBudgetHold),
    AlreadyCaptured(BudgetHoldMutationDecision),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetHoldMutationDecision {
    pub hold_id: Option<String>,
    pub admission_binding: Option<BudgetAdmissionBinding>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub committed_cost_units_after: u64,
    pub invocation_count_after: u32,
    pub invocation_quota_usages: Vec<BudgetInvocationQuotaUsage>,
    pub cumulative_approval: Option<BudgetCumulativeApprovalUsage>,
    pub invocation_state: BudgetInvocationState,
    pub monetary_state: BudgetMonetaryState,
    pub metadata: BudgetCommitMetadata,
}

pub type BudgetReleaseHoldDecision = BudgetHoldMutationDecision;
pub type BudgetReverseHoldDecision = BudgetHoldMutationDecision;
pub type BudgetReconcileHoldDecision = BudgetHoldMutationDecision;
pub type BudgetCaptureHoldDecision = BudgetHoldMutationDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetHoldDispositionView {
    Open,
    Released,
    Reversed,
    Reconciled,
    Expired,
}

impl BudgetHoldDispositionView {
    #[must_use]
    pub fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Released => "released",
            Self::Reversed => "reversed",
            Self::Reconciled => "reconciled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReservedHoldEnvelope {
    pub budget_total: Option<u64>,
    pub delegation_depth: u32,
    pub root_budget_holder: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetHoldSnapshot {
    pub hold_id: String,
    pub capability_id: String,
    pub grant_index: usize,
    pub authorized_exposure_units: u64,
    pub remaining_exposure_units: u64,
    pub disposition: BudgetHoldDispositionView,
    pub reserved_until: Option<i64>,
    pub reserved_currency: Option<String>,
    pub reserved_payment_reference: Option<String>,
    pub reserved_budget_total: Option<u64>,
    pub reserved_delegation_depth: Option<u32>,
    pub reserved_root_budget_holder: Option<String>,
    pub authority: Option<BudgetEventAuthority>,
}

pub trait BudgetStore: Send + Sync {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError>;

    /// Atomically check monetary budget limits and record provisional exposure if within bounds.
    ///
    /// Checks:
    /// 1. `invocation_count < max_invocations` (if set)
    /// 2. `cost_units <= max_cost_per_invocation` (if set)
    /// 3. `(total_cost_exposed + total_cost_realized_spend + cost_units)
    ///    <= max_total_cost_units` (if set)
    ///
    /// On pass: increments `invocation_count` by 1 and `total_cost_exposed` by
    /// `cost_units`, allocates a new replication seq, returns `Ok(true)`.
    /// On any limit exceeded: rolls back, returns `Ok(false)`.
    ///
    // SAFETY: HA overrun bound = max_cost_per_invocation x node_count
    // In a split-brain scenario, each HA node may independently approve up to
    // one invocation at the full per-invocation cap before the LWW merge
    // propagates the updated total. The maximum possible overrun is therefore
    // bounded by max_cost_per_invocation multiplied by the number of active
    // nodes in the HA cluster.
    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        if hold_id.is_some() || event_id.is_some() {
            return Err(BudgetStoreError::Invariant(
                "budget store does not support idempotent hold/event charging".to_string(),
            ));
        }
        self.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    /// Apply a charge under the caller's durable hold/event identity and
    /// authority fence. Implementations must preserve all three values or
    /// return an explicit unsupported error. This method is required so a
    /// backend upgrade cannot compile successfully and fail only on live calls.
    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError>;

    /// Reverse a previously applied provisional exposure for a pre-execution denial path.
    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        if hold_id.is_some() || event_id.is_some() {
            return Err(BudgetStoreError::Invariant(
                "budget store does not support idempotent hold/event reversal".to_string(),
            ));
        }
        self.reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    /// Reverse a charge under the exact durable identity and authority fence.
    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError>;

    /// Release a previously exposed monetary amount without changing invocation count.
    ///
    /// This is used when the kernel needs to release provisional exposure without
    /// realizing any spend in the budget store itself.
    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        if hold_id.is_some() || event_id.is_some() {
            return Err(BudgetStoreError::Invariant(
                "budget store does not support idempotent hold/event release".to_string(),
            ));
        }
        self.reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    /// Release exposure under the exact durable identity and authority fence.
    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError>;

    /// Atomically release provisional exposure and record realized spend.
    ///
    /// This removes `exposed_cost_units` from `total_cost_exposed` and adds
    /// `realized_cost_units` to `total_cost_realized_spend` without changing
    /// invocation count. `realized_cost_units` must not exceed
    /// `exposed_cost_units`.
    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError>;

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        if hold_id.is_some() || event_id.is_some() {
            return Err(BudgetStoreError::Invariant(
                "budget store does not support idempotent hold/event settlement".to_string(),
            ));
        }
        self.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    /// Reconcile exposure and spend under the exact durable identity and
    /// authority fence.
    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError>;

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError>;

    fn get_invocation_quota_usage(
        &self,
        _key: &BudgetQuotaKey,
    ) -> Result<Option<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "invocation quota usage is unavailable for this backend".to_string(),
        ))
    }

    fn get_cumulative_approval_account_usage(
        &self,
        _key: &BudgetCumulativeApprovalAccountKey,
    ) -> Result<Option<BudgetCumulativeApprovalAccountUsage>, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "cumulative approval account usage is unavailable for this backend".to_string(),
        ))
    }

    fn get_cumulative_approval_operation_usage(
        &self,
        _operation_id: &str,
    ) -> Result<Option<BudgetCumulativeApprovalUsage>, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "cumulative approval operation usage is unavailable for this backend".to_string(),
        ))
    }

    fn list_mutation_events(
        &self,
        _limit: usize,
        _capability_id: Option<&str>,
        _grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget mutation events unavailable for this backend".to_string(),
        ))
    }

    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        BudgetGuaranteeLevel::SingleNodeAtomic
    }

    fn budget_authority_profile(&self) -> BudgetAuthorityProfile {
        BudgetAuthorityProfile::AuthoritativeHoldEvent
    }

    fn budget_metering_profile(&self) -> BudgetMeteringProfile {
        BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual
    }

    fn capture_invocation_reservations(
        &self,
        _request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "invocation capture is not supported by this budget store".to_string(),
        ))
    }

    fn authorize_cumulative_approval(
        &self,
        _request: BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<BudgetCumulativeApprovalAuthorizationDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "cumulative approval attachment is not supported by this budget store".to_string(),
        ))
    }

    fn cancel_captured_before_dispatch(
        &self,
        _request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "captured-before-dispatch cancellation is not supported by this budget store"
                .to_string(),
        ))
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        request.validate()?;
        if !request.invocation_quotas.is_empty()
            || request.cumulative_approval.is_some()
            || request.admission_binding.is_some()
        {
            return Err(BudgetStoreError::Invariant(
                "composite budget authorization is not supported by this budget store".to_string(),
            ));
        }
        let allowed = self.try_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.max_invocations,
            request.requested_exposure_units,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            request.authority.as_ref(),
        )?;
        let usage = self.get_usage(&request.capability_id, request.grant_index)?;
        let committed_cost_units_after = usage
            .as_ref()
            .map(BudgetUsageRecord::committed_cost_units)
            .transpose()?
            .unwrap_or(0);
        let invocation_count_after = usage.as_ref().map_or(0, |usage| usage.invocation_count);
        let metadata = budget_commit_metadata(
            self,
            request.authority,
            allowed
                .then(|| usage.as_ref().map(|usage| usage.seq))
                .flatten(),
            request.event_id,
            None,
        );

        if allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    admission_binding: request.admission_binding,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after,
                    invocation_quota_usages: Vec::new(),
                    cumulative_approval: None,
                    invocation_state: BudgetInvocationState::Authorized,
                    monetary_state: if request.requested_exposure_units == 0 {
                        BudgetMonetaryState::None
                    } else {
                        BudgetMonetaryState::Exposed
                    },
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                admission_binding: request.admission_binding,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after,
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Denied,
                monetary_state: BudgetMonetaryState::None,
                metadata,
            }))
        }
    }

    fn reverse_budget_hold(
        &self,
        _request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget store does not support truthful rich reversal projections".to_string(),
        ))
    }

    fn release_budget_hold(
        &self,
        _request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget store does not support truthful rich release projections".to_string(),
        ))
    }

    fn reconcile_budget_hold(
        &self,
        _request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget store does not support truthful rich reconciliation projections".to_string(),
        ))
    }

    fn capture_budget_hold(
        &self,
        _request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget store does not support a distinct monetary capture transition".to_string(),
        ))
    }

    fn reap_orphaned_holds(
        &self,
        realized_by_hold: &std::collections::HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        let _ = realized_by_hold;
        Ok((0, 0))
    }

    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        Ok(0)
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        Ok(None)
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        let _ = request_id;
        Ok(None)
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        let _ = hold_id;
        Ok(None)
    }

    fn mark_hold_reserved(
        &self,
        _hold_id: &str,
        _reserved_until_unix_secs: i64,
        _currency: &str,
        _payment_reference: Option<&str>,
        _envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget store does not support durable monetary hold reservation".to_string(),
        ))
    }

    fn reserve_invocation_hold(
        &self,
        _hold_id: &str,
        _capability_id: &str,
        _grant_index: usize,
        _reserved_until_unix_secs: i64,
        _envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "budget store does not support durable invocation hold reservation".to_string(),
        ))
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        let _ = now_unix_secs;
        Ok(0)
    }
}

fn checked_committed_cost_units(
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> Result<u64, BudgetStoreError> {
    total_cost_exposed
        .checked_add(total_cost_realized_spend)
        .ok_or_else(|| {
            BudgetStoreError::Overflow(
                "total_cost_exposed + total_cost_realized_spend overflowed u64".to_string(),
            )
        })
}

mod in_memory;

pub use in_memory::InMemoryBudgetStore;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_admission_binding(operation_id: &str, capability_id: &str) -> BudgetAdmissionBinding {
        BudgetAdmissionBinding {
            operation_id: operation_id.to_string(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec![capability_id.to_string()])
                .unwrap(),
            authorization_artifact_digests: Vec::new(),
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }
    }

    #[test]
    fn synthesized_quota_requires_durable_identity() {
        let mut request = BudgetAuthorizeHoldRequest {
            capability_id: "cap-structured-validation".to_string(),
            grant_index: 0,
            max_invocations: Some(1),
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 0,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            hold_id: Some("hold-structured-validation".to_string()),
            event_id: Some("event-structured-validation".to_string()),
            authority: None,
        };
        assert_eq!(request.validate_composite().unwrap().len(), 1);
        request.hold_id = None;
        assert!(matches!(
            request.validate_composite(),
            Err(BudgetStoreError::Invariant(_))
        ));

        request.hold_id = Some("hold-structured-validation".to_string());
        request.event_id = None;
        assert!(matches!(
            request.validate_composite(),
            Err(BudgetStoreError::Invariant(_))
        ));

        request.event_id = Some("event-structured-validation".to_string());
        assert_eq!(request.validate_composite().unwrap().len(), 1);
    }

    #[test]
    fn admission_binding_requires_canonical_artifact_digests() {
        let mut binding = test_admission_binding("operation-artifacts", "cap-artifacts");
        binding.authorization_artifact_digests = vec!["b".repeat(64), "a".repeat(64)];
        assert!(matches!(
            binding.validate(),
            Err(BudgetStoreError::Invariant(_))
        ));

        let mut binding = test_admission_binding("operation-artifacts", "cap-artifacts");
        binding.supplemental_authorization_artifact_digest = Some("a".repeat(64));
        assert!(matches!(
            binding.validate(),
            Err(BudgetStoreError::Invariant(_))
        ));

        binding.authorization_artifact_digests = vec!["a".repeat(64)];
        binding.supplemental_verifier_id = Some("verifier:test".to_string());
        binding.supplemental_verifier_config_digest = Some("b".repeat(64));
        binding.supplemental_authorization_expires_at = Some(1_000);
        binding.last_observed_revocation = Some(RevocationCommitMetadata {
            authority: BudgetEventAuthority {
                authority_id: "authority-1".to_string(),
                lease_id: "lease-1".to_string(),
                lease_epoch: 1,
            },
            guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
            commit_index: 1,
        });
        assert!(binding.validate().is_ok());
    }

    #[test]
    fn unlimited_legacy_authorization_remains_unstructured() {
        let request = BudgetAuthorizeHoldRequest {
            capability_id: "cap-unlimited-legacy".to_string(),
            grant_index: 0,
            max_invocations: None,
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 0,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            hold_id: None,
            event_id: None,
            authority: None,
        };

        assert!(request.validate_composite().unwrap().is_empty());
    }

    #[test]
    fn rich_budget_identities_must_be_paired_and_non_empty() {
        let mut authorization = BudgetAuthorizeHoldRequest {
            capability_id: "cap-identity-validation".to_string(),
            grant_index: 0,
            max_invocations: None,
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 10,
            max_cost_per_invocation: Some(10),
            max_total_cost_units: Some(10),
            hold_id: Some(String::new()),
            event_id: Some(String::new()),
            authority: None,
        };
        assert!(matches!(
            authorization.validate(),
            Err(BudgetStoreError::Invariant(_))
        ));
        authorization.hold_id = Some("hold:identity-validation".to_string());
        authorization.event_id = None;
        assert!(matches!(
            authorization.validate(),
            Err(BudgetStoreError::Invariant(_))
        ));
        authorization.hold_id = None;
        authorization.event_id = Some("event:identity-validation".to_string());
        assert!(authorization.validate().is_ok());

        assert!(matches!(
            BudgetCaptureInvocationRequest {
                capability_id: authorization.capability_id.clone(),
                grant_index: 0,
                hold_id: "hold:identity-validation".to_string(),
                event_id: String::new(),
                trusted_time: None,
                authority: None,
            }
            .validate(),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert!(matches!(
            BudgetCancelCapturedBeforeDispatchRequest {
                capability_id: authorization.capability_id,
                grant_index: 0,
                hold_id: String::new(),
                event_id: "event:identity-validation:cancel".to_string(),
                authority: None,
            }
            .validate(),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn authorize_and_reconcile_hold_preserve_authority_metadata() {
        let store = InMemoryBudgetStore::new();
        let authority = BudgetEventAuthority {
            authority_id: "kernel:test-authority".to_string(),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        };

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                max_invocations: Some(4),
                invocation_quotas: Vec::new(),
                cumulative_approval: None,
                admission_binding: Some(test_admission_binding(
                    "budget-authority-metadata",
                    "cap-budget-1",
                )),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("hold-budget-1".to_string()),
                event_id: Some("hold-budget-1:authorize".to_string()),
                authority: Some(authority.clone()),
            })
            .unwrap();
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
            panic!("budget hold should be authorized");
        };
        assert_eq!(authorized.committed_cost_units_after, 100);
        assert_eq!(
            authorized.metadata.event_id.as_deref(),
            Some("hold-budget-1:authorize")
        );
        assert_eq!(authorized.metadata.budget_commit_index, Some(1));
        assert_eq!(
            authorized.metadata.budget_term().as_deref(),
            Some("kernel:test-authority:0")
        );

        let capture = store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                hold_id: "hold-budget-1".to_string(),
                event_id: "hold-budget-1:capture-invocation".to_string(),
                trusted_time: None,
                authority: Some(authority.clone()),
            })
            .unwrap();
        assert!(matches!(
            capture,
            BudgetInvocationCaptureDecision::Captured(_)
        ));

        let reconcile = store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 75,
                hold_id: Some("hold-budget-1".to_string()),
                event_id: Some("hold-budget-1:reconcile".to_string()),
                authority: Some(authority.clone()),
            })
            .unwrap();
        assert_eq!(reconcile.committed_cost_units_after, 75);
        assert_eq!(reconcile.realized_spend_units, 75);
        assert_eq!(
            reconcile.metadata.event_id.as_deref(),
            Some("hold-budget-1:reconcile")
        );
        assert_eq!(reconcile.metadata.budget_commit_index, Some(3));
        assert_eq!(reconcile.metadata.authority.as_ref(), Some(&authority));

        let usage = store.get_usage("cap-budget-1", 0).unwrap().unwrap();
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(usage.total_cost_realized_spend, 75);
        assert_eq!(usage.committed_cost_units().unwrap(), 75);

        let events = store
            .list_mutation_events(10, Some("cap-budget-1"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, BudgetMutationKind::ReserveInvocation);
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].kind, BudgetMutationKind::CaptureInvocation);
        assert_eq!(events[1].authority.as_ref(), Some(&authority));
        assert_eq!(events[2].kind, BudgetMutationKind::ReconcileSpend);
        assert_eq!(events[2].authority.as_ref(), Some(&authority));
        assert_eq!(events[2].realized_spend_units, 75);
    }

    #[test]
    fn denied_authorize_hold_reports_durable_commit_metadata() {
        let store = InMemoryBudgetStore::new();
        let authority = BudgetEventAuthority {
            authority_id: "kernel:test-authority".to_string(),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        };

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget-deny".to_string(),
                grant_index: 0,
                max_invocations: Some(1),
                invocation_quotas: Vec::new(),
                cumulative_approval: None,
                admission_binding: Some(test_admission_binding(
                    "budget-denial-metadata",
                    "cap-budget-deny",
                )),
                requested_exposure_units: 150,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("hold-budget-deny".to_string()),
                event_id: Some("hold-budget-deny:authorize".to_string()),
                authority: Some(authority.clone()),
            })
            .unwrap();
        let BudgetAuthorizeHoldDecision::Denied(denied) = decision else {
            panic!("budget hold should be denied");
        };
        assert_eq!(denied.committed_cost_units_after, 0);
        assert_eq!(denied.invocation_count_after, 0);
        assert_eq!(
            denied.metadata.event_id.as_deref(),
            Some("hold-budget-deny:authorize")
        );
        assert_eq!(denied.metadata.budget_commit_index, Some(1));
        assert_eq!(
            denied.metadata.guarantee_level,
            BudgetGuaranteeLevel::SingleNodeAtomic
        );
        assert_eq!(denied.metadata.authority.as_ref(), Some(&authority));

        let events = store
            .list_mutation_events(10, Some("cap-budget-deny"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].allowed, Some(false));
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert!(store.get_usage("cap-budget-deny", 0).unwrap().is_none());
    }
}
