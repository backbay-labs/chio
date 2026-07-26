use super::super::*;

impl TrustControlClient {
    pub fn list_budgets(&self, query: &BudgetQuery) -> Result<BudgetListResponse, CliError> {
        self.get_json_with_query(BUDGETS_PATH, query)
    }

    pub(crate) fn try_increment_budget(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<TryIncrementBudgetResponse, CliError> {
        self.post_json(
            BUDGET_INCREMENT_PATH,
            &TryIncrementBudgetRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
            },
        )
    }

    pub(crate) fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    pub(crate) fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<TryChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_AUTHORIZE_EXPOSURE_PATH,
            &TryChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    #[cfg(test)]
    pub(crate) fn capture_invocation_reservations(
        &self,
        capability_id: &str,
        grant_index: usize,
        hold_id: &str,
        event_id: &str,
    ) -> Result<CaptureInvocationResponse, CliError> {
        self.post_json(
            BUDGET_CAPTURE_INVOCATION_PATH,
            &CaptureInvocationRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                hold_id: hold_id.to_string(),
                event_id: event_id.to_string(),
            },
        )
    }

    pub(crate) fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReverseChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_RELEASE_EXPOSURE_PATH,
            &ReverseChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    pub(crate) fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.post_json(
            BUDGET_RECONCILE_SPEND_PATH,
            &ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units,
                exposure_units: None,
                realized_spend_units: None,
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn reconcile_budget_spend(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        self.reconcile_budget_spend_with_ids(
            capability_id,
            grant_index,
            authorized_exposure_units,
            realized_spend_units,
            None,
            None,
        )
    }

    pub(crate) fn reconcile_budget_spend_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        authorized_exposure_units: u64,
        realized_spend_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<ReduceChargeCostResponse, CliError> {
        let released_exposure_units = authorized_exposure_units
            .checked_sub(realized_spend_units)
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "realized spend cannot exceed authorized exposure during reconciliation"
                        .to_string(),
                )
            })?;
        self.post_json(
            BUDGET_RECONCILE_SPEND_PATH,
            &ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index,
                cost_units: released_exposure_units,
                exposure_units: Some(authorized_exposure_units),
                realized_spend_units: Some(realized_spend_units),
                hold_id: hold_id.map(ToOwned::to_owned),
                event_id: event_id.map(ToOwned::to_owned),
            },
        )
    }

    pub(crate) fn authorize_structured_budget_hold(
        &self,
        request: &StructuredBudgetAuthorizeRequest,
    ) -> Result<StructuredBudgetAuthorizeResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_AUTHORIZE_PATH, request)
    }

    pub(crate) fn get_structured_cumulative_operation(
        &self,
        request: &StructuredBudgetCumulativeOperationRequest,
    ) -> Result<StructuredBudgetCumulativeOperationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_CUMULATIVE_OPERATION_PATH, request)
    }

    pub(crate) fn cancel_structured_captured_invocation(
        &self,
        request: &StructuredBudgetCancelCapturedRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH, request)
    }

    pub(crate) fn capture_structured_invocation(
        &self,
        request: &StructuredBudgetCaptureInvocationRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH, request)
    }

    pub(crate) fn reverse_structured_budget_hold(
        &self,
        request: &StructuredBudgetFencedReverseRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_FENCED_REVERSE_PATH, request)
    }

    pub(crate) fn release_structured_budget_hold(
        &self,
        request: &StructuredBudgetReleaseRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_RELEASE_PATH, request)
    }

    pub(crate) fn reconcile_structured_budget_hold(
        &self,
        request: &StructuredBudgetReconcileRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_RECONCILE_PATH, request)
    }

    pub(crate) fn capture_structured_budget_spend(
        &self,
        request: &StructuredBudgetCaptureSpendRequest,
    ) -> Result<StructuredBudgetMutationResponse, CliError> {
        self.post_json(STRUCTURED_BUDGET_CAPTURE_SPEND_PATH, request)
    }
}
