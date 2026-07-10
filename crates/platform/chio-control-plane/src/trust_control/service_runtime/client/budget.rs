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
}
