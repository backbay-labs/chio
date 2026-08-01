use super::*;

impl RemoteBudgetStore {
    pub(super) fn capture_invocation_reservations_remote(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        remote_budget_grant_index(request.grant_index)?;
        request.validate()?;
        if request.trusted_time.is_some() {
            return Err(BudgetStoreError::Invariant(
                "remote budget callers cannot supply trusted capture time".to_string(),
            ));
        }
        let wire = StructuredBudgetCaptureInvocationRequest {
            schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: remote_budget_grant_index(request.grant_index)?,
            hold_id: request.hold_id.clone(),
            event_id: request.event_id.clone(),
        };
        let response = self
            .client
            .capture_structured_invocation(&wire)
            .map_err(into_budget_store_error)?;
        self.qualify_invocation_capture_response(&request, response)
    }

    pub(crate) fn qualify_invocation_capture_response(
        &self,
        request: &BudgetCaptureInvocationRequest,
        response: StructuredBudgetMutationResponse,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        let (decision, mutation, usage) = self.validate_structured_mutation_response(
            &request.capability_id,
            request.grant_index,
            &request.hold_id,
            &request.event_id,
            response,
            StructuredUsageSequenceRelation::ExistingProjection,
        )?;
        if mutation.invocation_state != BudgetInvocationState::Captured
            || mutation.monetary_state
                != if mutation.exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Exposed
                }
            || mutation.realized_spend_units != 0
            || mutation.committed_cost_units_after < mutation.exposure_units
            || mutation
                .cumulative_approval
                .as_ref()
                .is_some_and(|cumulative| {
                    cumulative.state != BudgetCumulativeApprovalState::Captured
                })
        {
            return Err(structured_budget_error(
                "remote invocation capture response returned an invalid captured state",
            ));
        }
        self.cache_structured_usage(&request.capability_id, request.grant_index, usage)?;
        Ok(match decision {
            StructuredBudgetMutationDecisionView::Applied => {
                BudgetInvocationCaptureDecision::Captured(mutation)
            }
            StructuredBudgetMutationDecisionView::AlreadyApplied => {
                BudgetInvocationCaptureDecision::AlreadyCaptured(mutation)
            }
            StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied => {
                return Err(structured_budget_error(
                    "remote invocation capture omitted exact replay status",
                ));
            }
        })
    }

    pub(super) fn reverse_budget_hold_remote(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        remote_budget_grant_index(request.grant_index)?;
        request.validate()?;
        let (hold_id, event_id) = required_remote_hold_event(
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            "reversal",
        )?;
        let expected_cumulative_approval_state = request.expected_cumulative_approval_state;
        let wire = StructuredBudgetFencedReverseRequest {
            schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: remote_budget_grant_index(request.grant_index)?,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            reversed_exposure_units: request.reversed_exposure_units,
            expected_cumulative_approval_state: expected_cumulative_approval_state.map(Into::into),
        };
        let response = self
            .client
            .reverse_structured_budget_hold(&wire)
            .map_err(into_budget_store_error)?;
        let (decision, mutation, usage) = self.validate_structured_mutation_response(
            &request.capability_id,
            request.grant_index,
            hold_id,
            event_id,
            response,
            StructuredUsageSequenceRelation::AdvancesAtCommit,
        )?;
        let cumulative_invalid = match expected_cumulative_approval_state {
            Some(_) => mutation
                .cumulative_approval
                .as_ref()
                .is_none_or(|cumulative| {
                    cumulative.state != BudgetCumulativeApprovalState::ReversedBeforeDispatch
                }),
            None => mutation
                .cumulative_approval
                .as_ref()
                .is_some_and(|cumulative| {
                    cumulative.state != BudgetCumulativeApprovalState::ReversedBeforeDispatch
                }),
        };
        if decision != StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied
            || mutation.invocation_state != BudgetInvocationState::Reversed
            || mutation.monetary_state
                != if mutation.exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Reversed
                }
            || mutation.exposure_units != request.reversed_exposure_units
            || mutation.realized_spend_units != 0
            || cumulative_invalid
        {
            return Err(structured_budget_error(
                "remote reversal response returned an invalid reversed state",
            ));
        }
        self.cache_structured_usage(&request.capability_id, request.grant_index, usage)?;
        Ok(mutation)
    }

    pub(super) fn release_budget_hold_remote(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        remote_budget_grant_index(request.grant_index)?;
        request.validate()?;
        let (hold_id, event_id) = required_remote_hold_event(
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            "release",
        )?;
        if request.released_exposure_units == 0 {
            return Err(structured_budget_error(
                "zero-unit remote monetary release is not a state transition",
            ));
        }
        let wire = StructuredBudgetReleaseRequest {
            schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: remote_budget_grant_index(request.grant_index)?,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            released_exposure_units: request.released_exposure_units,
        };
        let response = self
            .client
            .release_structured_budget_hold(&wire)
            .map_err(into_budget_store_error)?;
        let (decision, mutation, usage) = self.validate_structured_mutation_response(
            &request.capability_id,
            request.grant_index,
            hold_id,
            event_id,
            response,
            StructuredUsageSequenceRelation::AdvancesAtCommit,
        )?;
        if decision != StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied
            || mutation.invocation_state != BudgetInvocationState::Authorized
            || mutation.exposure_units != request.released_exposure_units
            || mutation.realized_spend_units != 0
            || !matches!(
                mutation.monetary_state,
                BudgetMonetaryState::Exposed | BudgetMonetaryState::Released
            )
            || mutation
                .cumulative_approval
                .as_ref()
                .is_some_and(|cumulative| {
                    !matches!(
                        cumulative.state,
                        BudgetCumulativeApprovalState::PendingApproval
                            | BudgetCumulativeApprovalState::Authorized
                    )
                })
        {
            return Err(structured_budget_error(
                "remote release response returned an invalid released state",
            ));
        }
        self.cache_structured_usage(&request.capability_id, request.grant_index, usage)?;
        Ok(mutation)
    }

    pub(super) fn reconcile_budget_hold_remote(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        remote_budget_grant_index(request.grant_index)?;
        request.validate()?;
        let (hold_id, event_id) = required_remote_hold_event(
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            "reconciliation",
        )?;
        if request.exposed_cost_units == 0 {
            return Err(structured_budget_error(
                "zero-unit remote budget reconciliation is not a state transition",
            ));
        }
        let wire = StructuredBudgetReconcileRequest {
            schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: remote_budget_grant_index(request.grant_index)?,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            exposed_cost_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
        };
        let response = self
            .client
            .reconcile_structured_budget_hold(&wire)
            .map_err(into_budget_store_error)?;
        self.qualify_reconcile_response(&request, response, false)
            .map(|(mutation, _)| mutation)
    }

    pub(crate) fn qualify_reconcile_response(
        &self,
        request: &BudgetReconcileHoldRequest,
        response: StructuredBudgetMutationResponse,
        require_exact_replay_status: bool,
    ) -> Result<(BudgetHoldMutationDecision, bool), BudgetStoreError> {
        request.validate()?;
        if request.exposed_cost_units == 0 {
            return Err(structured_budget_error(
                "zero-unit remote budget reconciliation is not a state transition",
            ));
        }
        let (hold_id, event_id) = required_remote_hold_event(
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            "reconciliation",
        )?;
        let (decision, mutation, usage) = self.validate_structured_mutation_response(
            &request.capability_id,
            request.grant_index,
            hold_id,
            event_id,
            response,
            StructuredUsageSequenceRelation::AdvancesAtCommit,
        )?;
        let replayed = match (require_exact_replay_status, decision) {
            (false, StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied) => false,
            (true, StructuredBudgetMutationDecisionView::Applied) => false,
            (true, StructuredBudgetMutationDecisionView::AlreadyApplied) => true,
            _ => {
                return Err(structured_budget_error(
                    "remote reconciliation returned an invalid replay status",
                ));
            }
        };
        if mutation.invocation_state != BudgetInvocationState::Captured
            || mutation.exposure_units != request.exposed_cost_units
            || mutation.realized_spend_units != request.realized_spend_units
            || mutation.monetary_state != BudgetMonetaryState::Reconciled
            || mutation
                .cumulative_approval
                .as_ref()
                .is_some_and(|cumulative| {
                    cumulative.state != BudgetCumulativeApprovalState::Captured
                })
        {
            return Err(structured_budget_error(
                "remote reconciliation response returned an invalid reconciled state",
            ));
        }
        self.cache_structured_usage(&request.capability_id, request.grant_index, usage)?;
        Ok((mutation, replayed))
    }

    pub(super) fn capture_budget_hold_remote(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        remote_budget_grant_index(request.grant_index)?;
        request.validate()?;
        let (hold_id, event_id) = required_remote_hold_event(
            request.hold_id.as_deref(),
            request.event_id.as_deref(),
            "monetary capture",
        )?;
        if request.exposed_cost_units == 0 {
            return Err(structured_budget_error(
                "zero-unit remote monetary capture is not a state transition",
            ));
        }
        let wire = StructuredBudgetCaptureSpendRequest {
            schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: remote_budget_grant_index(request.grant_index)?,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            exposed_cost_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
        };
        let response = self
            .client
            .capture_structured_budget_spend(&wire)
            .map_err(into_budget_store_error)?;
        let (decision, mutation, usage) = self.validate_structured_mutation_response(
            &request.capability_id,
            request.grant_index,
            hold_id,
            event_id,
            response,
            StructuredUsageSequenceRelation::AdvancesAtCommit,
        )?;
        if decision != StructuredBudgetMutationDecisionView::AppliedOrAlreadyApplied
            || mutation.invocation_state != BudgetInvocationState::Captured
            || mutation.exposure_units != request.exposed_cost_units
            || mutation.realized_spend_units != request.realized_spend_units
            || mutation.monetary_state != BudgetMonetaryState::Captured
            || mutation
                .cumulative_approval
                .as_ref()
                .is_some_and(|cumulative| {
                    cumulative.state != BudgetCumulativeApprovalState::Captured
                })
        {
            return Err(structured_budget_error(
                "remote monetary capture response returned an invalid captured state",
            ));
        }
        self.cache_structured_usage(&request.capability_id, request.grant_index, usage)?;
        Ok(mutation)
    }
}
