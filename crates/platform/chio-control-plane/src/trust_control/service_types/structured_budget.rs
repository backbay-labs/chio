use super::*;

pub(crate) const STRUCTURED_BUDGET_REQUEST_SCHEMA: &str = "chio.structured-budget-request.v1";
pub(crate) const STRUCTURED_BUDGET_RESPONSE_SCHEMA: &str = "chio.structured-budget-response.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetEventAuthorityView {
    pub(crate) authority_id: String,
    pub(crate) lease_id: String,
    pub(crate) lease_epoch: u64,
}

impl From<BudgetEventAuthority> for StructuredBudgetEventAuthorityView {
    fn from(value: BudgetEventAuthority) -> Self {
        Self {
            authority_id: value.authority_id,
            lease_id: value.lease_id,
            lease_epoch: value.lease_epoch,
        }
    }
}

impl From<StructuredBudgetEventAuthorityView> for BudgetEventAuthority {
    fn from(value: StructuredBudgetEventAuthorityView) -> Self {
        Self {
            authority_id: value.authority_id,
            lease_id: value.lease_id,
            lease_epoch: value.lease_epoch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredRevocationCommitMetadataView {
    pub(crate) authority: StructuredBudgetEventAuthorityView,
    pub(crate) guarantee_level: String,
    pub(crate) commit_index: u64,
}

impl From<RevocationCommitMetadata> for StructuredRevocationCommitMetadataView {
    fn from(value: RevocationCommitMetadata) -> Self {
        Self {
            authority: value.authority.into(),
            guarantee_level: value.guarantee_level.as_str().to_string(),
            commit_index: value.commit_index,
        }
    }
}

impl TryFrom<StructuredRevocationCommitMetadataView> for RevocationCommitMetadata {
    type Error = String;

    fn try_from(value: StructuredRevocationCommitMetadataView) -> Result<Self, Self::Error> {
        let metadata = Self {
            authority: value.authority.into(),
            guarantee_level: parse_structured_guarantee(&value.guarantee_level)?,
            commit_index: value.commit_index,
        };
        metadata.validate().map_err(|error| error.to_string())?;
        Ok(metadata)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetQuotaKeyView {
    pub(crate) profile: String,
    pub(crate) owner_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant_index: Option<u32>,
}

impl From<BudgetQuotaKey> for StructuredBudgetQuotaKeyView {
    fn from(value: BudgetQuotaKey) -> Self {
        Self {
            profile: value.profile.as_str().to_string(),
            owner_id: value.owner_id,
            grant_index: value.grant_index,
        }
    }
}

impl TryFrom<StructuredBudgetQuotaKeyView> for BudgetQuotaKey {
    type Error = String;

    fn try_from(value: StructuredBudgetQuotaKeyView) -> Result<Self, Self::Error> {
        let profile = BudgetQuotaProfile::parse(&value.profile).ok_or_else(|| {
            format!(
                "unknown structured budget quota profile `{}`",
                value.profile
            )
        })?;
        Ok(Self {
            profile,
            owner_id: value.owner_id,
            grant_index: value.grant_index,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetInvocationQuotaView {
    pub(crate) key: StructuredBudgetQuotaKeyView,
    pub(crate) max_invocations: u32,
}

impl From<BudgetInvocationQuota> for StructuredBudgetInvocationQuotaView {
    fn from(value: BudgetInvocationQuota) -> Self {
        Self {
            key: value.key.into(),
            max_invocations: value.max_invocations,
        }
    }
}

impl TryFrom<StructuredBudgetInvocationQuotaView> for BudgetInvocationQuota {
    type Error = String;

    fn try_from(value: StructuredBudgetInvocationQuotaView) -> Result<Self, Self::Error> {
        Ok(Self {
            key: value.key.try_into()?,
            max_invocations: value.max_invocations,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetInvocationQuotaUsageView {
    pub(crate) quota: StructuredBudgetInvocationQuotaView,
    pub(crate) reserved_invocations: u32,
    pub(crate) captured_invocations: u32,
}

impl From<BudgetInvocationQuotaUsage> for StructuredBudgetInvocationQuotaUsageView {
    fn from(value: BudgetInvocationQuotaUsage) -> Self {
        Self {
            quota: value.quota.into(),
            reserved_invocations: value.reserved_invocations,
            captured_invocations: value.captured_invocations,
        }
    }
}

impl TryFrom<StructuredBudgetInvocationQuotaUsageView> for BudgetInvocationQuotaUsage {
    type Error = String;

    fn try_from(value: StructuredBudgetInvocationQuotaUsageView) -> Result<Self, Self::Error> {
        Ok(Self {
            quota: value.quota.try_into()?,
            reserved_invocations: value.reserved_invocations,
            captured_invocations: value.captured_invocations,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetAdmissionBindingView {
    pub(crate) operation_id: String,
    pub(crate) revocation_ids: Vec<String>,
    pub(crate) revocation_set_digest: String,
    pub(crate) authorization_artifact_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_observed_revocation: Option<StructuredRevocationCommitMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) supplemental_verifier_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) supplemental_verifier_config_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) supplemental_authorization_artifact_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) supplemental_authorization_expires_at: Option<u64>,
}

impl From<BudgetAdmissionBinding> for StructuredBudgetAdmissionBindingView {
    fn from(value: BudgetAdmissionBinding) -> Self {
        Self {
            operation_id: value.operation_id,
            revocation_ids: value.revocation_set.ids().to_vec(),
            revocation_set_digest: value.revocation_set.digest().to_string(),
            authorization_artifact_digests: value.authorization_artifact_digests,
            last_observed_revocation: value.last_observed_revocation.map(Into::into),
            supplemental_verifier_id: value.supplemental_verifier_id,
            supplemental_verifier_config_digest: value.supplemental_verifier_config_digest,
            supplemental_authorization_artifact_digest: value
                .supplemental_authorization_artifact_digest,
            supplemental_authorization_expires_at: value.supplemental_authorization_expires_at,
        }
    }
}

impl TryFrom<StructuredBudgetAdmissionBindingView> for BudgetAdmissionBinding {
    type Error = String;

    fn try_from(value: StructuredBudgetAdmissionBindingView) -> Result<Self, Self::Error> {
        let revocation_set = CanonicalRevocationSet::from_canonical_parts(
            value.revocation_ids,
            value.revocation_set_digest,
        )
        .map_err(|error| error.to_string())?;
        let binding = Self {
            operation_id: value.operation_id,
            revocation_set,
            authorization_artifact_digests: value.authorization_artifact_digests,
            last_observed_revocation: value
                .last_observed_revocation
                .map(TryInto::try_into)
                .transpose()?,
            supplemental_verifier_id: value.supplemental_verifier_id,
            supplemental_verifier_config_digest: value.supplemental_verifier_config_digest,
            supplemental_authorization_artifact_digest: value
                .supplemental_authorization_artifact_digest,
            supplemental_authorization_expires_at: value.supplemental_authorization_expires_at,
        };
        binding.validate().map_err(|error| error.to_string())?;
        Ok(binding)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetCumulativeAccountKeyView {
    pub(crate) authority_id: String,
    pub(crate) owner_id: String,
    pub(crate) approval_budget_id: String,
    pub(crate) approval_budget_epoch: u64,
    pub(crate) root_grant_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) delegation_root_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) root_binding_digest: Option<String>,
    pub(crate) currency: String,
}

impl From<BudgetCumulativeApprovalAccountKey> for StructuredBudgetCumulativeAccountKeyView {
    fn from(value: BudgetCumulativeApprovalAccountKey) -> Self {
        Self {
            authority_id: value.authority_id,
            owner_id: value.owner_id,
            approval_budget_id: value.approval_budget_id,
            approval_budget_epoch: value.approval_budget_epoch,
            root_grant_hash: value.root_grant_hash,
            delegation_root_id: value.delegation_root_id,
            root_binding_digest: value.root_binding_digest,
            currency: value.currency,
        }
    }
}

impl From<StructuredBudgetCumulativeAccountKeyView> for BudgetCumulativeApprovalAccountKey {
    fn from(value: StructuredBudgetCumulativeAccountKeyView) -> Self {
        Self {
            authority_id: value.authority_id,
            owner_id: value.owner_id,
            approval_budget_id: value.approval_budget_id,
            approval_budget_epoch: value.approval_budget_epoch,
            root_grant_hash: value.root_grant_hash,
            delegation_root_id: value.delegation_root_id,
            root_binding_digest: value.root_binding_digest,
            currency: value.currency,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetCumulativeRequestView {
    pub(crate) operation_id: String,
    pub(crate) account_key: StructuredBudgetCumulativeAccountKeyView,
    pub(crate) authority_threshold: MonetaryAmount,
    pub(crate) effective_threshold: MonetaryAmount,
    pub(crate) requested_authorized: MonetaryAmount,
}

impl From<BudgetCumulativeApprovalRequest> for StructuredBudgetCumulativeRequestView {
    fn from(value: BudgetCumulativeApprovalRequest) -> Self {
        Self {
            operation_id: value.operation_id,
            account_key: value.account_key.into(),
            authority_threshold: value.authority_threshold,
            effective_threshold: value.effective_threshold,
            requested_authorized: value.requested_authorized,
        }
    }
}

impl From<StructuredBudgetCumulativeRequestView> for BudgetCumulativeApprovalRequest {
    fn from(value: StructuredBudgetCumulativeRequestView) -> Self {
        Self {
            operation_id: value.operation_id,
            account_key: value.account_key.into(),
            authority_threshold: value.authority_threshold,
            effective_threshold: value.effective_threshold,
            requested_authorized: value.requested_authorized,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StructuredBudgetCumulativeStateView {
    PendingApproval,
    Authorized,
    Captured,
    ReversedBeforeDispatch,
}

impl From<BudgetCumulativeApprovalState> for StructuredBudgetCumulativeStateView {
    fn from(value: BudgetCumulativeApprovalState) -> Self {
        match value {
            BudgetCumulativeApprovalState::PendingApproval => Self::PendingApproval,
            BudgetCumulativeApprovalState::Authorized => Self::Authorized,
            BudgetCumulativeApprovalState::Captured => Self::Captured,
            BudgetCumulativeApprovalState::ReversedBeforeDispatch => Self::ReversedBeforeDispatch,
        }
    }
}

impl From<StructuredBudgetCumulativeStateView> for BudgetCumulativeApprovalState {
    fn from(value: StructuredBudgetCumulativeStateView) -> Self {
        match value {
            StructuredBudgetCumulativeStateView::PendingApproval => Self::PendingApproval,
            StructuredBudgetCumulativeStateView::Authorized => Self::Authorized,
            StructuredBudgetCumulativeStateView::Captured => Self::Captured,
            StructuredBudgetCumulativeStateView::ReversedBeforeDispatch => {
                Self::ReversedBeforeDispatch
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetCumulativeUsageView {
    pub(crate) operation_id: String,
    pub(crate) account_key: StructuredBudgetCumulativeAccountKeyView,
    pub(crate) authority_threshold: MonetaryAmount,
    pub(crate) effective_threshold: MonetaryAmount,
    pub(crate) requested_authorized: MonetaryAmount,
    pub(crate) reserved_authorized_after: MonetaryAmount,
    pub(crate) captured_authorized_after: MonetaryAmount,
    pub(crate) state: StructuredBudgetCumulativeStateView,
    pub(crate) version: u64,
}

impl From<BudgetCumulativeApprovalUsage> for StructuredBudgetCumulativeUsageView {
    fn from(value: BudgetCumulativeApprovalUsage) -> Self {
        Self {
            operation_id: value.operation_id,
            account_key: value.account_key.into(),
            authority_threshold: value.authority_threshold,
            effective_threshold: value.effective_threshold,
            requested_authorized: value.requested_authorized,
            reserved_authorized_after: value.reserved_authorized_after,
            captured_authorized_after: value.captured_authorized_after,
            state: value.state.into(),
            version: value.version,
        }
    }
}

impl From<StructuredBudgetCumulativeUsageView> for BudgetCumulativeApprovalUsage {
    fn from(value: StructuredBudgetCumulativeUsageView) -> Self {
        Self {
            operation_id: value.operation_id,
            account_key: value.account_key.into(),
            authority_threshold: value.authority_threshold,
            effective_threshold: value.effective_threshold,
            requested_authorized: value.requested_authorized,
            reserved_authorized_after: value.reserved_authorized_after,
            captured_authorized_after: value.captured_authorized_after,
            state: value.state.into(),
            version: value.version,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StructuredBudgetInvocationStateView {
    Absent,
    Authorized,
    Captured,
    Reversed,
    Denied,
}

impl From<BudgetInvocationState> for StructuredBudgetInvocationStateView {
    fn from(value: BudgetInvocationState) -> Self {
        match value {
            BudgetInvocationState::Absent => Self::Absent,
            BudgetInvocationState::Authorized => Self::Authorized,
            BudgetInvocationState::Captured => Self::Captured,
            BudgetInvocationState::Reversed => Self::Reversed,
            BudgetInvocationState::Denied => Self::Denied,
        }
    }
}

impl From<StructuredBudgetInvocationStateView> for BudgetInvocationState {
    fn from(value: StructuredBudgetInvocationStateView) -> Self {
        match value {
            StructuredBudgetInvocationStateView::Absent => Self::Absent,
            StructuredBudgetInvocationStateView::Authorized => Self::Authorized,
            StructuredBudgetInvocationStateView::Captured => Self::Captured,
            StructuredBudgetInvocationStateView::Reversed => Self::Reversed,
            StructuredBudgetInvocationStateView::Denied => Self::Denied,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StructuredBudgetMonetaryStateView {
    None,
    Exposed,
    Released,
    Reconciled,
    Captured,
    Reversed,
}

impl From<BudgetMonetaryState> for StructuredBudgetMonetaryStateView {
    fn from(value: BudgetMonetaryState) -> Self {
        match value {
            BudgetMonetaryState::None => Self::None,
            BudgetMonetaryState::Exposed => Self::Exposed,
            BudgetMonetaryState::Released => Self::Released,
            BudgetMonetaryState::Reconciled => Self::Reconciled,
            BudgetMonetaryState::Captured => Self::Captured,
            BudgetMonetaryState::Reversed => Self::Reversed,
        }
    }
}

impl From<StructuredBudgetMonetaryStateView> for BudgetMonetaryState {
    fn from(value: StructuredBudgetMonetaryStateView) -> Self {
        match value {
            StructuredBudgetMonetaryStateView::None => Self::None,
            StructuredBudgetMonetaryStateView::Exposed => Self::Exposed,
            StructuredBudgetMonetaryStateView::Released => Self::Released,
            StructuredBudgetMonetaryStateView::Reconciled => Self::Reconciled,
            StructuredBudgetMonetaryStateView::Captured => Self::Captured,
            StructuredBudgetMonetaryStateView::Reversed => Self::Reversed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetCommitMetadataView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority: Option<StructuredBudgetEventAuthorityView>,
    pub(crate) guarantee_level: String,
    pub(crate) budget_profile: String,
    pub(crate) metering_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recorded_at_unix_seconds: Option<u64>,
}

impl From<BudgetCommitMetadata> for StructuredBudgetCommitMetadataView {
    fn from(value: BudgetCommitMetadata) -> Self {
        Self {
            authority: value.authority.map(Into::into),
            guarantee_level: value.guarantee_level.as_str().to_string(),
            budget_profile: value.budget_profile.as_str().to_string(),
            metering_profile: value.metering_profile.as_str().to_string(),
            budget_commit_index: value.budget_commit_index,
            event_id: value.event_id,
            recorded_at_unix_seconds: value.recorded_at_unix_seconds,
        }
    }
}

impl TryFrom<StructuredBudgetCommitMetadataView> for BudgetCommitMetadata {
    type Error = String;

    fn try_from(value: StructuredBudgetCommitMetadataView) -> Result<Self, Self::Error> {
        let guarantee_level = parse_structured_guarantee(&value.guarantee_level)?;
        if value.budget_profile != "authoritative_hold_event" {
            return Err("unknown structured budget authority profile".to_string());
        }
        if value.metering_profile != "max_cost_preauthorize_then_reconcile_actual" {
            return Err("unknown structured budget metering profile".to_string());
        }
        Ok(Self {
            authority: value.authority.map(Into::into),
            guarantee_level,
            budget_profile: chio_kernel::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile:
                chio_kernel::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index: value.budget_commit_index,
            event_id: value.event_id,
            recorded_at_unix_seconds: value.recorded_at_unix_seconds,
        })
    }
}

fn parse_structured_guarantee(value: &str) -> Result<BudgetGuaranteeLevel, String> {
    match value {
        "single_node_atomic" => Ok(BudgetGuaranteeLevel::SingleNodeAtomic),
        "ha_linearizable" => Ok(BudgetGuaranteeLevel::HaLinearizable),
        "partition_escrowed" => Ok(BudgetGuaranteeLevel::PartitionEscrowed),
        "advisory_posthoc" => Ok(BudgetGuaranteeLevel::AdvisoryPosthoc),
        other => Err(format!("unknown structured budget guarantee `{other}`")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetUsageView {
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
    pub(crate) invocation_count: u32,
    pub(crate) updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) seq: Option<u64>,
    pub(crate) total_cost_exposed: u64,
    pub(crate) total_cost_realized_spend: u64,
}

impl From<BudgetUsageRecord> for StructuredBudgetUsageView {
    fn from(value: BudgetUsageRecord) -> Self {
        Self {
            capability_id: value.capability_id,
            grant_index: value.grant_index,
            invocation_count: value.invocation_count,
            updated_at: value.updated_at,
            seq: Some(value.seq),
            total_cost_exposed: value.total_cost_exposed,
            total_cost_realized_spend: value.total_cost_realized_spend,
        }
    }
}

impl TryFrom<StructuredBudgetUsageView> for BudgetUsageRecord {
    type Error = String;

    fn try_from(value: StructuredBudgetUsageView) -> Result<Self, Self::Error> {
        Ok(Self {
            capability_id: value.capability_id,
            grant_index: value.grant_index,
            invocation_count: value.invocation_count,
            updated_at: value.updated_at,
            seq: value
                .seq
                .ok_or_else(|| "structured budget usage omitted sequence".to_string())?,
            total_cost_exposed: value.total_cost_exposed,
            total_cost_realized_spend: value.total_cost_realized_spend,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetAuthorizeRequest {
    pub(crate) schema: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_invocations: Option<u32>,
    pub(crate) invocation_quotas: Vec<StructuredBudgetInvocationQuotaView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cumulative_approval: Option<StructuredBudgetCumulativeRequestView>,
    pub(crate) admission_binding: StructuredBudgetAdmissionBindingView,
    pub(crate) requested_exposure_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_cost_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_total_cost_units: Option<u64>,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
}

impl StructuredBudgetAuthorizeRequest {
    pub(crate) fn from_core(request: &BudgetAuthorizeHoldRequest) -> Result<Self, String> {
        let invocation_quotas = if request.invocation_quotas.is_empty() {
            match request.max_invocations {
                Some(max_invocations) => vec![BudgetInvocationQuota {
                    key: BudgetQuotaKey::grant(
                        request.capability_id.clone(),
                        u32::try_from(request.grant_index)
                            .map_err(|_| "grant_index exceeds u32 range".to_string())?,
                    ),
                    max_invocations,
                }],
                None => Vec::new(),
            }
        } else {
            request.invocation_quotas.clone()
        };
        Ok(Self {
            schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: u32::try_from(request.grant_index)
                .map_err(|_| "grant_index exceeds u32 range".to_string())?,
            max_invocations: request.max_invocations,
            invocation_quotas: invocation_quotas.into_iter().map(Into::into).collect(),
            cumulative_approval: request.cumulative_approval.clone().map(Into::into),
            admission_binding: request
                .admission_binding
                .clone()
                .ok_or_else(|| {
                    "structured budget authorization requires admission binding".to_string()
                })?
                .into(),
            requested_exposure_units: request.requested_exposure_units,
            max_cost_per_invocation: request.max_cost_per_invocation,
            max_total_cost_units: request.max_total_cost_units,
            hold_id: request
                .hold_id
                .clone()
                .ok_or_else(|| "structured budget authorization requires hold_id".to_string())?,
            event_id: request
                .event_id
                .clone()
                .ok_or_else(|| "structured budget authorization requires event_id".to_string())?,
        })
    }

    pub(crate) fn into_core(
        self,
        authority: Option<BudgetEventAuthority>,
    ) -> Result<BudgetAuthorizeHoldRequest, String> {
        require_structured_schema(&self.schema)?;
        Ok(BudgetAuthorizeHoldRequest {
            capability_id: self.capability_id,
            grant_index: usize::try_from(self.grant_index)
                .map_err(|_| "grant_index exceeds usize range".to_string())?,
            max_invocations: self.max_invocations,
            invocation_quotas: self
                .invocation_quotas
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            cumulative_approval: self.cumulative_approval.map(Into::into),
            admission_binding: Some(self.admission_binding.try_into()?),
            requested_exposure_units: self.requested_exposure_units,
            max_cost_per_invocation: self.max_cost_per_invocation,
            max_total_cost_units: self.max_total_cost_units,
            hold_id: Some(self.hold_id),
            event_id: Some(self.event_id),
            authority,
        })
    }
}

macro_rules! structured_transition_request {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub(crate) struct $name {
            pub(crate) schema: String,
            pub(crate) capability_id: String,
            pub(crate) grant_index: u32,
            pub(crate) hold_id: String,
            pub(crate) event_id: String,
            $(pub(crate) $field: $ty,)*
        }
    };
}

structured_transition_request!(StructuredBudgetCancelCapturedRequest {});
structured_transition_request!(StructuredBudgetCaptureInvocationRequest {});
structured_transition_request!(StructuredBudgetFencedReverseRequest {
    reversed_exposure_units: u64,
    expected_cumulative_approval_state: Option<StructuredBudgetCumulativeStateView>,
});
structured_transition_request!(StructuredBudgetReleaseRequest {
    released_exposure_units: u64,
});
structured_transition_request!(StructuredBudgetReconcileRequest {
    exposed_cost_units: u64,
    realized_spend_units: u64,
});
structured_transition_request!(StructuredBudgetCaptureSpendRequest {
    exposed_cost_units: u64,
    realized_spend_units: u64,
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetAuthorizeCumulativeRequest {
    pub(crate) schema: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
    pub(crate) operation_id: String,
    pub(crate) hold_id: String,
    pub(crate) admission_binding: StructuredBudgetAdmissionBindingView,
    pub(crate) approval_set_digest: String,
    pub(crate) event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetCumulativeOperationRequest {
    pub(crate) schema: String,
    pub(crate) operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetCumulativeOperationResponse {
    pub(crate) schema: String,
    pub(crate) operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) usage: Option<StructuredBudgetCumulativeUsageView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) approval_set_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metadata: Option<StructuredBudgetCommitMetadataView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StructuredBudgetAuthorizeDecisionView {
    Authorized,
    ApprovalRequired,
    Denied,
    AlreadyCaptured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StructuredBudgetMutationDecisionView {
    Applied,
    AlreadyApplied,
    AppliedOrAlreadyApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetProjectionView {
    pub(crate) hold_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admission_binding: Option<StructuredBudgetAdmissionBindingView>,
    pub(crate) exposure_units: u64,
    pub(crate) realized_spend_units: u64,
    pub(crate) committed_cost_units_after: u64,
    pub(crate) invocation_count_after: u32,
    pub(crate) invocation_quota_usages: Vec<StructuredBudgetInvocationQuotaUsageView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cumulative_approval: Option<StructuredBudgetCumulativeUsageView>,
    pub(crate) invocation_state: StructuredBudgetInvocationStateView,
    pub(crate) monetary_state: StructuredBudgetMonetaryStateView,
    pub(crate) metadata: StructuredBudgetCommitMetadataView,
}

impl StructuredBudgetProjectionView {
    fn from_parts(
        hold_id: Option<String>,
        admission_binding: Option<BudgetAdmissionBinding>,
        exposure_units: u64,
        realized_spend_units: u64,
        committed_cost_units_after: u64,
        invocation_count_after: u32,
        invocation_quota_usages: Vec<BudgetInvocationQuotaUsage>,
        cumulative_approval: Option<BudgetCumulativeApprovalUsage>,
        invocation_state: BudgetInvocationState,
        monetary_state: BudgetMonetaryState,
        metadata: BudgetCommitMetadata,
    ) -> Result<Self, String> {
        Ok(Self {
            hold_id: hold_id.ok_or_else(|| "structured response omitted hold_id".to_string())?,
            admission_binding: admission_binding.map(Into::into),
            exposure_units,
            realized_spend_units,
            committed_cost_units_after,
            invocation_count_after,
            invocation_quota_usages: invocation_quota_usages
                .into_iter()
                .map(Into::into)
                .collect(),
            cumulative_approval: cumulative_approval.map(Into::into),
            invocation_state: invocation_state.into(),
            monetary_state: monetary_state.into(),
            metadata: metadata.into(),
        })
    }

    pub(crate) fn from_mutation(value: BudgetHoldMutationDecision) -> Result<Self, String> {
        Self::from_parts(
            value.hold_id,
            value.admission_binding,
            value.exposure_units,
            value.realized_spend_units,
            value.committed_cost_units_after,
            value.invocation_count_after,
            value.invocation_quota_usages,
            value.cumulative_approval,
            value.invocation_state,
            value.monetary_state,
            value.metadata,
        )
    }

    pub(crate) fn into_mutation(self) -> Result<BudgetHoldMutationDecision, String> {
        Ok(BudgetHoldMutationDecision {
            hold_id: Some(self.hold_id),
            admission_binding: self.admission_binding.map(TryInto::try_into).transpose()?,
            exposure_units: self.exposure_units,
            realized_spend_units: self.realized_spend_units,
            committed_cost_units_after: self.committed_cost_units_after,
            invocation_count_after: self.invocation_count_after,
            invocation_quota_usages: self
                .invocation_quota_usages
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            cumulative_approval: self.cumulative_approval.map(Into::into),
            invocation_state: self.invocation_state.into(),
            monetary_state: self.monetary_state.into(),
            metadata: self.metadata.try_into()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StructuredBudgetProjectionKindView {
    LegacyHold,
    AdmissionOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetProjectionContractView {
    pub(crate) kind: StructuredBudgetProjectionKindView,
    pub(crate) projection_sha256: String,
    pub(crate) invocation_quota_count: u32,
    pub(crate) cumulative_approval_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) usage_seq: Option<u64>,
    pub(crate) usage_updated_at: i64,
}

impl StructuredBudgetProjectionContractView {
    pub(crate) fn from_projection(
        projection: &StructuredBudgetProjectionView,
        usage: &StructuredBudgetUsageView,
    ) -> Result<Self, String> {
        if projection.admission_binding.is_none()
            && (!projection.invocation_quota_usages.is_empty()
                || projection.cumulative_approval.is_some())
        {
            return Err(
                "legacy structured projection cannot carry admission-operation children"
                    .to_string(),
            );
        }
        Ok(Self {
            kind: if projection.admission_binding.is_some() {
                StructuredBudgetProjectionKindView::AdmissionOperation
            } else {
                StructuredBudgetProjectionKindView::LegacyHold
            },
            projection_sha256: sha256_hex(&canonical_json_bytes(projection).map_err(|error| {
                format!("structured projection canonicalization failed: {error}")
            })?),
            invocation_quota_count: u32::try_from(projection.invocation_quota_usages.len())
                .map_err(|_| "structured projection has too many invocation quotas".to_string())?,
            cumulative_approval_present: projection.cumulative_approval.is_some(),
            usage_seq: usage.seq,
            usage_updated_at: usage.updated_at,
        })
    }

    pub(crate) fn validate(
        &self,
        projection: &StructuredBudgetProjectionView,
        usage: &StructuredBudgetUsageView,
    ) -> Result<(), String> {
        let expected = Self::from_projection(projection, usage)?;
        if self != &expected {
            return Err(
                "structured response projection contract did not match its durable projection"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetAuthorizeResponse {
    pub(crate) schema: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
    pub(crate) request_hold_id: String,
    pub(crate) request_event_id: String,
    pub(crate) decision: StructuredBudgetAuthorizeDecisionView,
    pub(crate) projection_contract: StructuredBudgetProjectionContractView,
    pub(crate) projection: StructuredBudgetProjectionView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) usage: Option<StructuredBudgetUsageView>,
}

impl StructuredBudgetAuthorizeResponse {
    pub(crate) fn from_core(
        capability_id: String,
        grant_index: u32,
        request_hold_id: String,
        request_event_id: String,
        decision: BudgetAuthorizeHoldDecision,
        usage: StructuredBudgetUsageView,
    ) -> Result<Self, String> {
        let (decision, projection) = match decision {
            BudgetAuthorizeHoldDecision::Authorized(value) => (
                StructuredBudgetAuthorizeDecisionView::Authorized,
                projection_from_authorized(value)?,
            ),
            BudgetAuthorizeHoldDecision::ApprovalRequired(value) => (
                StructuredBudgetAuthorizeDecisionView::ApprovalRequired,
                projection_from_approval_required(value)?,
            ),
            BudgetAuthorizeHoldDecision::Denied(value) => (
                StructuredBudgetAuthorizeDecisionView::Denied,
                projection_from_denied(value)?,
            ),
            BudgetAuthorizeHoldDecision::AlreadyCaptured(value) => (
                StructuredBudgetAuthorizeDecisionView::AlreadyCaptured,
                StructuredBudgetProjectionView::from_mutation(value)?,
            ),
        };
        let projection_contract =
            StructuredBudgetProjectionContractView::from_projection(&projection, &usage)?;
        Ok(Self {
            schema: STRUCTURED_BUDGET_RESPONSE_SCHEMA.to_string(),
            capability_id,
            grant_index,
            request_hold_id,
            request_event_id,
            decision,
            projection_contract,
            projection,
            usage: Some(usage),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StructuredBudgetMutationResponse {
    pub(crate) schema: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: u32,
    pub(crate) request_hold_id: String,
    pub(crate) request_event_id: String,
    pub(crate) decision: StructuredBudgetMutationDecisionView,
    pub(crate) projection_contract: StructuredBudgetProjectionContractView,
    pub(crate) projection: StructuredBudgetProjectionView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) usage: Option<StructuredBudgetUsageView>,
}

impl StructuredBudgetMutationResponse {
    pub(crate) fn from_core(
        capability_id: String,
        grant_index: u32,
        request_hold_id: String,
        request_event_id: String,
        decision: StructuredBudgetMutationDecisionView,
        projection: BudgetHoldMutationDecision,
        usage: StructuredBudgetUsageView,
    ) -> Result<Self, String> {
        let projection = StructuredBudgetProjectionView::from_mutation(projection)?;
        let projection_contract =
            StructuredBudgetProjectionContractView::from_projection(&projection, &usage)?;
        Ok(Self {
            schema: STRUCTURED_BUDGET_RESPONSE_SCHEMA.to_string(),
            capability_id,
            grant_index,
            request_hold_id,
            request_event_id,
            decision,
            projection_contract,
            projection,
            usage: Some(usage),
        })
    }
}

fn projection_from_authorized(
    value: AuthorizedBudgetHold,
) -> Result<StructuredBudgetProjectionView, String> {
    StructuredBudgetProjectionView::from_parts(
        value.hold_id,
        value.admission_binding,
        value.authorized_exposure_units,
        0,
        value.committed_cost_units_after,
        value.invocation_count_after,
        value.invocation_quota_usages,
        value.cumulative_approval,
        value.invocation_state,
        value.monetary_state,
        value.metadata,
    )
}

fn projection_from_approval_required(
    value: ApprovalRequiredBudgetHold,
) -> Result<StructuredBudgetProjectionView, String> {
    StructuredBudgetProjectionView::from_parts(
        Some(value.hold_id),
        Some(value.admission_binding),
        value.authorized_exposure_units,
        0,
        value.committed_cost_units_after,
        value.invocation_count_after,
        value.invocation_quota_usages,
        Some(value.cumulative_approval),
        value.invocation_state,
        value.monetary_state,
        value.metadata,
    )
}

fn projection_from_denied(
    value: DeniedBudgetHold,
) -> Result<StructuredBudgetProjectionView, String> {
    StructuredBudgetProjectionView::from_parts(
        value.hold_id,
        value.admission_binding,
        value.attempted_exposure_units,
        0,
        value.committed_cost_units_after,
        value.invocation_count_after,
        value.invocation_quota_usages,
        value.cumulative_approval,
        value.invocation_state,
        value.monetary_state,
        value.metadata,
    )
}

pub(crate) fn require_structured_schema(schema: &str) -> Result<(), String> {
    if schema == STRUCTURED_BUDGET_REQUEST_SCHEMA {
        Ok(())
    } else {
        Err(format!(
            "unsupported structured budget request schema `{schema}`"
        ))
    }
}

pub(crate) fn require_structured_response_schema(schema: &str) -> Result<(), String> {
    if schema == STRUCTURED_BUDGET_RESPONSE_SCHEMA {
        Ok(())
    } else {
        Err(format!(
            "unsupported structured budget response schema `{schema}`"
        ))
    }
}
