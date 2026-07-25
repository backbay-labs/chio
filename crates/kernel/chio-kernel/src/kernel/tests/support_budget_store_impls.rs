macro_rules! delegate_authority_fenced_budget_methods {
    ($field:ident) => {
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
            authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<bool, crate::budget_store::BudgetStoreError> {
            self.$field.try_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id,
                event_id,
                authority,
            )
        }

        fn reverse_charge_cost_with_ids_and_authority(
            &self,
            capability_id: &str,
            grant_index: usize,
            cost_units: u64,
            hold_id: Option<&str>,
            event_id: Option<&str>,
            authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<(), crate::budget_store::BudgetStoreError> {
            self.$field.reverse_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
        }

        fn reduce_charge_cost_with_ids_and_authority(
            &self,
            capability_id: &str,
            grant_index: usize,
            cost_units: u64,
            hold_id: Option<&str>,
            event_id: Option<&str>,
            authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<(), crate::budget_store::BudgetStoreError> {
            self.$field.reduce_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
        }

        fn settle_charge_cost_with_ids_and_authority(
            &self,
            capability_id: &str,
            grant_index: usize,
            exposed_cost_units: u64,
            realized_cost_units: u64,
            hold_id: Option<&str>,
            event_id: Option<&str>,
            authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<(), crate::budget_store::BudgetStoreError> {
            self.$field.settle_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
                hold_id,
                event_id,
                authority,
            )
        }
    };
}

macro_rules! reject_authority_fenced_budget_methods {
    ($reason:literal) => {
        fn try_charge_cost_with_ids_and_authority(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _max_invocations: Option<u32>,
            _cost_units: u64,
            _max_cost_per_invocation: Option<u64>,
            _max_total_cost_units: Option<u64>,
            _hold_id: Option<&str>,
            _event_id: Option<&str>,
            _authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<bool, crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant(
                $reason.to_string(),
            ))
        }

        fn reverse_charge_cost_with_ids_and_authority(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _cost_units: u64,
            _hold_id: Option<&str>,
            _event_id: Option<&str>,
            _authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<(), crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant(
                $reason.to_string(),
            ))
        }

        fn reduce_charge_cost_with_ids_and_authority(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _cost_units: u64,
            _hold_id: Option<&str>,
            _event_id: Option<&str>,
            _authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<(), crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant(
                $reason.to_string(),
            ))
        }

        fn settle_charge_cost_with_ids_and_authority(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _exposed_cost_units: u64,
            _realized_cost_units: u64,
            _hold_id: Option<&str>,
            _event_id: Option<&str>,
            _authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<(), crate::budget_store::BudgetStoreError> {
            Err(crate::budget_store::BudgetStoreError::Invariant(
                $reason.to_string(),
            ))
        }
    };
}
