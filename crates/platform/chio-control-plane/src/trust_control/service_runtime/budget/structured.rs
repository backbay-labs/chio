use super::*;

impl RemoteBudgetStore {
    pub(super) fn get_cumulative_approval_operation_usage_remote(
        &self,
        operation_id: &str,
    ) -> Result<Option<BudgetCumulativeApprovalUsage>, BudgetStoreError> {
        if operation_id.is_empty() {
            return Err(structured_budget_error(
                "cumulative operation_id must not be empty",
            ));
        }
        let response = self
            .client
            .get_structured_cumulative_operation(&StructuredBudgetCumulativeOperationRequest {
                schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
                operation_id: operation_id.to_string(),
            })
            .map_err(into_budget_store_error)?;
        require_structured_response_schema(&response.schema).map_err(structured_budget_error)?;
        if response.operation_id != operation_id {
            return Err(structured_budget_error(
                "structured cumulative lookup changed the operation identity",
            ));
        }
        let (usage, metadata) = match (response.usage, response.metadata) {
            (None, None) if response.approval_set_digest.is_none() => return Ok(None),
            (Some(usage), Some(metadata)) => (usage, metadata),
            _ => {
                return Err(structured_budget_error(
                    "structured cumulative lookup returned a partial durable projection",
                ))
            }
        };
        let usage: BudgetCumulativeApprovalUsage = usage.into();
        validate_cumulative_operation_usage(operation_id, &usage)?;
        if response
            .approval_set_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256_digest(digest))
        {
            return Err(structured_budget_error(
                "structured cumulative lookup returned an invalid approval digest",
            ));
        }
        let metadata: BudgetCommitMetadata =
            metadata.try_into().map_err(structured_budget_error)?;
        let authority = metadata.authority.as_ref().ok_or_else(|| {
            structured_budget_error(
                "structured cumulative lookup omitted its durable authority fence",
            )
        })?;
        if authority.authority_id.is_empty()
            || authority.lease_id.is_empty()
            || authority.lease_epoch == 0
            || metadata.budget_commit_index.is_none_or(|index| index == 0)
            || metadata.event_id.as_deref().is_none_or(str::is_empty)
            || metadata.guarantee_level == BudgetGuaranteeLevel::AdvisoryPosthoc
        {
            return Err(structured_budget_error(
                "structured cumulative lookup returned invalid durable event metadata",
            ));
        }
        Ok(Some(usage))
    }

    pub(super) fn authorize_cumulative_approval_remote(
        &self,
        request: BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<BudgetCumulativeApprovalAuthorizationDecision, BudgetStoreError> {
        request.validate()?;
        Err(structured_budget_error(
            "advisory remote budget authority cannot mutate cumulative family approval without a modeled partition escrow profile",
        ))
    }

    pub(super) fn cancel_captured_before_dispatch_remote(
        &self,
        request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        remote_budget_grant_index(request.grant_index)?;
        request.validate()?;
        let wire = StructuredBudgetCancelCapturedRequest {
            schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: remote_budget_grant_index(request.grant_index)?,
            hold_id: request.hold_id.clone(),
            event_id: request.event_id.clone(),
        };
        let response = self
            .client
            .cancel_structured_captured_invocation(&wire)
            .map_err(into_budget_store_error)?;
        let (decision, mutation, usage) = self.validate_structured_mutation_response(
            &request.capability_id,
            request.grant_index,
            &request.hold_id,
            &request.event_id,
            response,
            StructuredUsageSequenceRelation::AdvancesAtCommit,
        )?;
        if mutation.invocation_state != BudgetInvocationState::Reversed
            || mutation.realized_spend_units != 0
            || mutation.monetary_state
                != if mutation.exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Reversed
                }
            || mutation
                .cumulative_approval
                .as_ref()
                .is_some_and(|cumulative| {
                    cumulative.state != BudgetCumulativeApprovalState::ReversedBeforeDispatch
                })
        {
            return Err(structured_budget_error(
                "remote captured cancellation response returned an invalid reversed state",
            ));
        }
        self.cache_structured_usage(&request.capability_id, request.grant_index, usage)?;
        Ok(match decision {
            StructuredBudgetMutationDecisionView::Applied => {
                BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(mutation)
            }
            StructuredBudgetMutationDecisionView::AlreadyApplied => {
                BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(mutation)
            }
            StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied => {
                return Err(structured_budget_error(
                    "remote captured cancellation omitted exact replay status",
                ));
            }
        })
    }

    pub(super) fn authorize_structured_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let wire = StructuredBudgetAuthorizeRequest::from_core(&request)
            .map_err(structured_budget_error)?;
        let response = self
            .client
            .authorize_structured_budget_hold(&wire)
            .map_err(into_budget_store_error)?;
        self.decode_structured_budget_authorization(
            request,
            wire,
            response,
            BudgetGuaranteeLevel::AdvisoryPosthoc,
        )
    }

    pub(crate) fn decode_structured_budget_authorization(
        &self,
        request: BudgetAuthorizeHoldRequest,
        wire: StructuredBudgetAuthorizeRequest,
        response: StructuredBudgetAuthorizeResponse,
        guarantee_level: BudgetGuaranteeLevel,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let expected_quotas = wire
            .invocation_quotas
            .clone()
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<BudgetInvocationQuota>, String>>()
            .map_err(structured_budget_error)?;
        require_structured_response_schema(&response.schema).map_err(structured_budget_error)?;
        if response.capability_id != wire.capability_id
            || response.grant_index != wire.grant_index
            || response.request_hold_id != wire.hold_id
            || response.request_event_id != wire.event_id
            || response.projection.hold_id != wire.hold_id
            || response.projection.admission_binding.as_ref() != Some(&wire.admission_binding)
        {
            return Err(structured_budget_error(
                "structured remote authorization response changed the request identity or admission binding",
            ));
        }
        let decision = response.decision;
        let usage = response.usage.ok_or_else(|| {
            structured_budget_error(
                "structured remote authorization omitted its event-time usage projection",
            )
        })?;
        response
            .projection_contract
            .validate(&response.projection, &usage)
            .map_err(structured_budget_error)?;
        if response.projection_contract.kind
            != StructuredBudgetProjectionKindView::AdmissionOperation
        {
            return Err(structured_budget_error(
                "structured remote authorization was downgraded to a legacy hold projection",
            ));
        }
        let usage_sequence_relation = match decision {
            StructuredBudgetAuthorizeDecisionView::Authorized
            | StructuredBudgetAuthorizeDecisionView::ApprovalRequired => {
                StructuredUsageSequenceRelation::AdvancesAtCommit
            }
            StructuredBudgetAuthorizeDecisionView::AlreadyCaptured => {
                StructuredUsageSequenceRelation::ExistingProjection
            }
            StructuredBudgetAuthorizeDecisionView::Denied => StructuredUsageSequenceRelation::None,
        };
        let mut mutation = response
            .projection
            .into_mutation()
            .map_err(structured_budget_error)?;
        self.validate_structured_projection(
            &mutation,
            &response.projection_contract,
            &wire.event_id,
            !matches!(
                decision,
                StructuredBudgetAuthorizeDecisionView::AlreadyCaptured
            ),
            true,
        )?;
        self.validate_structured_usage_projection(
            &request.capability_id,
            request.grant_index,
            &mutation,
            &usage,
            &response.projection_contract,
            usage_sequence_relation,
        )?;
        mutation.metadata.guarantee_level = guarantee_level;
        let returned_quotas = mutation
            .invocation_quota_usages
            .iter()
            .map(|usage| usage.quota.clone())
            .collect::<Vec<_>>();
        if returned_quotas != expected_quotas {
            return Err(structured_budget_error(
                "structured remote authorization response changed the quota set",
            ));
        }
        if let Some(expected) = &request.cumulative_approval {
            if matches!(decision, StructuredBudgetAuthorizeDecisionView::Denied) {
                if mutation.cumulative_approval.is_some() {
                    return Err(structured_budget_error(
                        "structured remote denial added cumulative approval state",
                    ));
                }
            } else {
                let Some(actual) = mutation.cumulative_approval.as_ref() else {
                    return Err(structured_budget_error(
                        "structured remote authorization response omitted cumulative approval",
                    ));
                };
                if actual.operation_id != expected.operation_id
                    || actual.account_key != expected.account_key
                    || actual.authority_threshold != expected.authority_threshold
                    || actual.effective_threshold != expected.effective_threshold
                    || actual.requested_authorized != expected.requested_authorized
                {
                    return Err(structured_budget_error(
                        "structured remote authorization response changed cumulative authority",
                    ));
                }
            }
        } else if mutation.cumulative_approval.is_some() {
            return Err(structured_budget_error(
                "structured remote authorization response added cumulative approval",
            ));
        }
        let result = match decision {
            StructuredBudgetAuthorizeDecisionView::Authorized => {
                let expected_monetary_state = if request.requested_exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Exposed
                };
                if mutation.invocation_state != BudgetInvocationState::Authorized
                    || mutation.realized_spend_units != 0
                    || mutation.exposure_units != request.requested_exposure_units
                    || mutation.monetary_state != expected_monetary_state
                    || mutation
                        .cumulative_approval
                        .as_ref()
                        .is_some_and(|cumulative| {
                            cumulative.state != BudgetCumulativeApprovalState::Authorized
                        })
                {
                    return Err(structured_budget_error(
                        "structured remote authorization response returned an invalid authorized state",
                    ));
                }
                BudgetAuthorizeHoldDecision::Authorized(AuthorizedBudgetHold {
                    hold_id: mutation.hold_id.clone(),
                    admission_binding: mutation.admission_binding.clone(),
                    authorized_exposure_units: mutation.exposure_units,
                    committed_cost_units_after: mutation.committed_cost_units_after,
                    invocation_count_after: mutation.invocation_count_after,
                    invocation_quota_usages: mutation.invocation_quota_usages.clone(),
                    cumulative_approval: mutation.cumulative_approval.clone(),
                    invocation_state: mutation.invocation_state,
                    monetary_state: mutation.monetary_state,
                    metadata: mutation.metadata.clone(),
                })
            }
            StructuredBudgetAuthorizeDecisionView::ApprovalRequired => {
                let hold_id = mutation
                    .hold_id
                    .clone()
                    .ok_or_else(|| structured_budget_error("approval response omitted hold_id"))?;
                let admission_binding = mutation.admission_binding.clone().ok_or_else(|| {
                    structured_budget_error("approval response omitted admission binding")
                })?;
                let cumulative_approval =
                    mutation.cumulative_approval.clone().ok_or_else(|| {
                        structured_budget_error("approval response omitted cumulative approval")
                    })?;
                let expected_monetary_state = if request.requested_exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Exposed
                };
                if cumulative_approval.state != BudgetCumulativeApprovalState::PendingApproval
                    || mutation.invocation_state != BudgetInvocationState::Authorized
                    || mutation.exposure_units != request.requested_exposure_units
                    || mutation.realized_spend_units != 0
                    || mutation.monetary_state != expected_monetary_state
                {
                    return Err(structured_budget_error(
                        "structured remote approval response returned an invalid pending state",
                    ));
                }
                BudgetAuthorizeHoldDecision::ApprovalRequired(ApprovalRequiredBudgetHold {
                    hold_id,
                    admission_binding,
                    authorized_exposure_units: mutation.exposure_units,
                    committed_cost_units_after: mutation.committed_cost_units_after,
                    invocation_count_after: mutation.invocation_count_after,
                    invocation_quota_usages: mutation.invocation_quota_usages.clone(),
                    cumulative_approval,
                    invocation_state: mutation.invocation_state,
                    monetary_state: mutation.monetary_state,
                    metadata: mutation.metadata.clone(),
                })
            }
            StructuredBudgetAuthorizeDecisionView::Denied => {
                if mutation.invocation_state != BudgetInvocationState::Denied
                    || mutation.monetary_state != BudgetMonetaryState::None
                    || mutation.exposure_units != request.requested_exposure_units
                    || mutation.realized_spend_units != 0
                {
                    return Err(structured_budget_error(
                        "structured remote authorization response returned an invalid denied state",
                    ));
                }
                BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                    hold_id: mutation.hold_id.clone(),
                    admission_binding: mutation.admission_binding.clone(),
                    attempted_exposure_units: mutation.exposure_units,
                    committed_cost_units_after: mutation.committed_cost_units_after,
                    invocation_count_after: mutation.invocation_count_after,
                    invocation_quota_usages: mutation.invocation_quota_usages.clone(),
                    cumulative_approval: mutation.cumulative_approval.clone(),
                    invocation_state: mutation.invocation_state,
                    monetary_state: mutation.monetary_state,
                    metadata: mutation.metadata.clone(),
                })
            }
            StructuredBudgetAuthorizeDecisionView::AlreadyCaptured => {
                if mutation.invocation_state != BudgetInvocationState::Captured
                    || mutation.exposure_units != request.requested_exposure_units
                    || mutation.exposure_units == 0
                        && mutation.monetary_state != BudgetMonetaryState::None
                    || mutation.exposure_units > 0
                        && mutation.monetary_state == BudgetMonetaryState::None
                    || mutation.monetary_state == BudgetMonetaryState::Exposed
                        && mutation.realized_spend_units != 0
                    || !matches!(
                        mutation.monetary_state,
                        BudgetMonetaryState::None
                            | BudgetMonetaryState::Exposed
                            | BudgetMonetaryState::Reconciled
                            | BudgetMonetaryState::Captured
                    )
                    || mutation
                        .cumulative_approval
                        .as_ref()
                        .is_some_and(|cumulative| {
                            cumulative.state != BudgetCumulativeApprovalState::Captured
                        })
                {
                    return Err(structured_budget_error(
                        "structured remote replay response was not captured",
                    ));
                }
                BudgetAuthorizeHoldDecision::AlreadyCaptured(mutation)
            }
        };
        self.cache_structured_usage(&request.capability_id, request.grant_index, usage)?;
        Ok(result)
    }

    pub(super) fn validate_structured_mutation_response(
        &self,
        capability_id: &str,
        grant_index: usize,
        hold_id: &str,
        event_id: &str,
        response: StructuredBudgetMutationResponse,
        usage_sequence_relation: StructuredUsageSequenceRelation,
    ) -> Result<
        (
            StructuredBudgetMutationDecisionView,
            BudgetHoldMutationDecision,
            StructuredBudgetUsageView,
        ),
        BudgetStoreError,
    > {
        require_structured_response_schema(&response.schema).map_err(structured_budget_error)?;
        let expected_grant_index = remote_budget_grant_index(grant_index)?;
        if response.capability_id != capability_id
            || response.grant_index != expected_grant_index
            || response.request_hold_id != hold_id
            || response.request_event_id != event_id
            || response.projection.hold_id != hold_id
        {
            return Err(structured_budget_error(
                "structured remote mutation response changed the request identity",
            ));
        }
        let decision = response.decision;
        let usage = response.usage.ok_or_else(|| {
            structured_budget_error(
                "structured remote mutation response omitted its event-time usage projection",
            )
        })?;
        response
            .projection_contract
            .validate(&response.projection, &usage)
            .map_err(structured_budget_error)?;
        let mut mutation = response
            .projection
            .into_mutation()
            .map_err(structured_budget_error)?;
        self.validate_structured_projection(
            &mutation,
            &response.projection_contract,
            event_id,
            true,
            false,
        )?;
        self.validate_structured_usage_projection(
            capability_id,
            grant_index,
            &mutation,
            &usage,
            &response.projection_contract,
            usage_sequence_relation,
        )?;
        mutation.metadata.guarantee_level = BudgetGuaranteeLevel::AdvisoryPosthoc;
        Ok((decision, mutation, usage))
    }

    pub(super) fn validate_structured_projection(
        &self,
        mutation: &BudgetHoldMutationDecision,
        contract: &StructuredBudgetProjectionContractView,
        expected_event_id: &str,
        require_exact_event: bool,
        require_admission_binding: bool,
    ) -> Result<(), BudgetStoreError> {
        if mutation.hold_id.as_deref().is_none_or(str::is_empty)
            || require_admission_binding && mutation.admission_binding.is_none()
            || mutation.admission_binding.is_none()
                && (!mutation.invocation_quota_usages.is_empty()
                    || mutation.cumulative_approval.is_some())
            || mutation
                .metadata
                .budget_commit_index
                .is_none_or(|index| index == 0)
            || mutation
                .metadata
                .event_id
                .as_deref()
                .is_none_or(str::is_empty)
            || require_exact_event
                && mutation.metadata.event_id.as_deref() != Some(expected_event_id)
        {
            return Err(structured_budget_error(
                "structured remote response omitted required durable hold, event, admission, or commit identity",
            ));
        }
        let projection_shape_invalid = match contract.kind {
            StructuredBudgetProjectionKindView::LegacyHold => {
                mutation.admission_binding.is_some()
                    || !mutation.invocation_quota_usages.is_empty()
                    || mutation.cumulative_approval.is_some()
            }
            StructuredBudgetProjectionKindView::AdmissionOperation => {
                mutation.admission_binding.is_none()
                    || usize::try_from(contract.invocation_quota_count)
                        != Ok(mutation.invocation_quota_usages.len())
                    || contract.cumulative_approval_present
                        != mutation.cumulative_approval.is_some()
            }
        };
        if projection_shape_invalid {
            return Err(structured_budget_error(
                "structured remote response changed its durable projection shape",
            ));
        }
        if mutation.realized_spend_units > mutation.exposure_units {
            return Err(structured_budget_error(
                "structured remote response realized more spend than authorized exposure",
            ));
        }
        if let Some(binding) = mutation.admission_binding.as_ref() {
            binding.validate()?;
        }
        if let Some(authority) = mutation.metadata.authority.as_ref() {
            if authority.authority_id.is_empty()
                || authority.lease_id.is_empty()
                || authority.lease_epoch == 0
            {
                return Err(structured_budget_error(
                    "structured remote response returned a malformed serving authority identity",
                ));
            }
            if mutation
                .admission_binding
                .as_ref()
                .and_then(|binding| binding.last_observed_revocation.as_ref())
                .is_some_and(|observation| {
                    observation.authority.authority_id != authority.authority_id
                        || observation.authority.lease_epoch > authority.lease_epoch
                        || observation.authority.lease_epoch == authority.lease_epoch
                            && observation.authority.lease_id != authority.lease_id
                })
            {
                return Err(structured_budget_error(
                    "structured remote response mixed budget and revocation authorities",
                ));
            }
        } else if require_admission_binding || mutation.admission_binding.is_some() {
            return Err(structured_budget_error(
                "structured remote response omitted its serving authority identity",
            ));
        }
        let mut previous_key: Option<&BudgetQuotaKey> = None;
        for usage in &mutation.invocation_quota_usages {
            usage.quota.key.validate()?;
            if previous_key.is_some_and(|key| key >= &usage.quota.key)
                || usage
                    .reserved_invocations
                    .checked_add(usage.captured_invocations)
                    .is_none_or(|count| count > usage.quota.max_invocations)
            {
                return Err(structured_budget_error(
                    "structured remote response returned invalid quota usage",
                ));
            }
            previous_key = Some(&usage.quota.key);
        }
        if let Some(cumulative) = &mutation.cumulative_approval {
            cumulative.account_key.validate()?;
            let currency = cumulative.account_key.currency.as_str();
            if cumulative.operation_id.is_empty()
                || cumulative.version == 0
                || cumulative.authority_threshold.currency != currency
                || cumulative.effective_threshold.currency != currency
                || cumulative.requested_authorized.currency != currency
                || cumulative.reserved_authorized_after.currency != currency
                || cumulative.captured_authorized_after.currency != currency
                || cumulative.effective_threshold.units > cumulative.authority_threshold.units
                || cumulative
                    .reserved_authorized_after
                    .units
                    .checked_add(cumulative.captured_authorized_after.units)
                    .is_none()
            {
                return Err(structured_budget_error(
                    "structured remote response returned invalid cumulative approval state",
                ));
            }
        }
        mutation
            .exposure_units
            .checked_add(mutation.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "structured remote response exposure overflowed u64".to_string(),
                )
            })?;
        Ok(())
    }

    pub(super) fn validate_structured_usage_projection(
        &self,
        capability_id: &str,
        grant_index: usize,
        mutation: &BudgetHoldMutationDecision,
        usage: &StructuredBudgetUsageView,
        contract: &StructuredBudgetProjectionContractView,
        usage_sequence_relation: StructuredUsageSequenceRelation,
    ) -> Result<(), BudgetStoreError> {
        let expected_grant_index = remote_budget_grant_index(grant_index)?;
        if let Some(binding) = mutation.admission_binding.as_ref() {
            let has_broker_quota = mutation.invocation_quota_usages.iter().any(|usage| {
                usage.quota.key.profile == BudgetQuotaProfile::SupplementalBrokerCapabilityExecution
            });
            let has_supplemental_binding = binding.supplemental_verifier_id.is_some();
            let grant_quota_mismatch = mutation.invocation_quota_usages.iter().any(|usage| {
                usage.quota.key.profile == BudgetQuotaProfile::GrantInvocation
                    && (usage.quota.key.owner_id != capability_id
                        || usage.quota.key.grant_index != Some(expected_grant_index))
            });
            if !binding
                .revocation_set
                .ids()
                .iter()
                .any(|id| id == capability_id)
                || grant_quota_mismatch
                || has_broker_quota != has_supplemental_binding
                || mutation
                    .cumulative_approval
                    .as_ref()
                    .is_some_and(|cumulative| cumulative.operation_id != binding.operation_id)
            {
                return Err(structured_budget_error(
                    "structured remote projection broke admission, quota, or cumulative coupling",
                ));
            }
        }
        let committed_cost_units = usage
            .total_cost_exposed
            .checked_add(usage.total_cost_realized_spend)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "structured remote usage overflowed committed cost".to_string(),
                )
            })?;
        let commit_index = mutation.metadata.budget_commit_index.ok_or_else(|| {
            structured_budget_error("structured remote usage omitted durable mutation commit")
        })?;
        let invalid_sequence = match usage_sequence_relation {
            StructuredUsageSequenceRelation::None => {
                usage.seq.is_some() || contract.usage_seq.is_some()
            }
            StructuredUsageSequenceRelation::ExistingProjection => {
                usage.seq.is_none_or(|seq| seq == 0 || seq > commit_index)
                    || usage.seq != contract.usage_seq
            }
            StructuredUsageSequenceRelation::AdvancesAtCommit => {
                usage.seq != Some(commit_index) || contract.usage_seq != Some(commit_index)
            }
        };
        if invalid_sequence {
            let reason = match usage_sequence_relation {
                StructuredUsageSequenceRelation::None => {
                    "structured remote denial invented a mutable usage sequence"
                }
                StructuredUsageSequenceRelation::ExistingProjection => {
                    "structured remote existing usage sequence was missing, zero, or ahead of its mutation commit"
                }
                StructuredUsageSequenceRelation::AdvancesAtCommit => {
                    "structured remote advancing usage sequence did not match its mutation commit"
                }
            };
            return Err(structured_budget_error(reason));
        }
        if usage.capability_id != capability_id
            || usage.grant_index != expected_grant_index
            || usage.updated_at != contract.usage_updated_at
            || usage.invocation_count != mutation.invocation_count_after
            || committed_cost_units != mutation.committed_cost_units_after
        {
            return Err(structured_budget_error(
                "structured remote usage changed the request identity or event-time projection",
            ));
        }
        if let Some(grant_usage) = mutation.invocation_quota_usages.iter().find(|quota_usage| {
            quota_usage.quota.key.profile == BudgetQuotaProfile::GrantInvocation
        }) {
            let grant_usage_count = grant_usage
                .reserved_invocations
                .checked_add(grant_usage.captured_invocations)
                .ok_or_else(|| {
                    structured_budget_error(
                        "structured remote grant quota usage overflowed its invocation count",
                    )
                })?;
            if grant_usage_count != usage.invocation_count {
                return Err(structured_budget_error(
                    "structured remote grant quota usage did not match aggregate invocation usage",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn cache_structured_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
        usage: StructuredBudgetUsageView,
    ) -> Result<(), BudgetStoreError> {
        if usage.capability_id != capability_id
            || usage.grant_index != remote_budget_grant_index(grant_index)?
        {
            return Err(structured_budget_error(
                "structured remote response changed the usage identity",
            ));
        }
        usage
            .total_cost_exposed
            .checked_add(usage.total_cost_realized_spend)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "structured remote usage overflowed committed cost".to_string(),
                )
            })?;
        let Some(_seq) = usage.seq else {
            return Ok(());
        };
        let record = BudgetUsageRecord::try_from(usage).map_err(structured_budget_error)?;
        let key = (capability_id.to_string(), grant_index);
        let mut cached_usage = match self.cached_usage.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(existing) = cached_usage.get(&key).map(|entry| &entry.record) {
            if existing.seq > record.seq {
                return Ok(());
            }
            if existing.seq == record.seq {
                if existing != &record {
                    return Err(structured_budget_error(
                        "structured remote replay changed the exact usage projection",
                    ));
                }
                return Ok(());
            }
        }
        record.committed_cost_units()?;
        // Structured usage views carry both monetary totals.
        cached_usage.insert(
            key,
            CachedBudgetUsage {
                record,
                cost_authoritative: true,
            },
        );
        Ok(())
    }
}

fn validate_cumulative_operation_usage(
    operation_id: &str,
    usage: &BudgetCumulativeApprovalUsage,
) -> Result<(), BudgetStoreError> {
    usage.account_key.validate()?;
    let currency = usage.account_key.currency.as_str();
    if usage.operation_id != operation_id
        || usage.version == 0
        || usage.authority_threshold.currency != currency
        || usage.effective_threshold.currency != currency
        || usage.requested_authorized.currency != currency
        || usage.reserved_authorized_after.currency != currency
        || usage.captured_authorized_after.currency != currency
        || usage.effective_threshold.units > usage.authority_threshold.units
    {
        return Err(structured_budget_error(
            "structured cumulative lookup returned an invalid operation projection",
        ));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
