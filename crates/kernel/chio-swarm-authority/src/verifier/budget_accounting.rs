use std::collections::BTreeSet;

use crate::{
    SwarmAuthorityError, SwarmBudgetAllocation, SwarmBudgetAllocationState, SwarmBudgetPool,
    CHIO_SWARM_BUDGET_POOL_SCHEMA,
};

use super::util::{rejected, require_non_empty};

/// Validate the complete standalone accounting state committed by a pool
/// digest before any authority-signed companion can authenticate it.
pub fn validate_swarm_budget_pool_accounting(
    budget: &SwarmBudgetPool,
) -> Result<(), SwarmAuthorityError> {
    if budget.schema != CHIO_SWARM_BUDGET_POOL_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm budget pool schema: {}",
            budget.schema
        )));
    }
    require_non_empty(&budget.pool_id, "swarm budget pool id")?;
    require_non_empty(&budget.graph_id, "swarm budget graph id")?;
    require_non_empty(&budget.currency, "swarm budget currency")?;
    let mut total = 0_u64;
    let mut allocation_ids = BTreeSet::new();
    for allocation in &budget.allocations {
        require_non_empty(&allocation.allocation_id, "swarm budget allocation id")?;
        require_non_empty(&allocation.task_id, "swarm budget task id")?;
        require_non_empty(
            &allocation.dimension_id,
            "swarm budget allocation dimension",
        )?;
        validate_budget_allocation_units(allocation)?;
        total = total
            .checked_add(allocation.max_units)
            .ok_or_else(|| rejected("swarm budget allocation overflow"))?;
        if !allocation_ids.insert(allocation.allocation_id.as_str()) {
            return Err(rejected(format!(
                "duplicate swarm budget allocation: {}",
                allocation.allocation_id
            )));
        }
    }
    if total > budget.total_units {
        return Err(rejected("swarm budget allocations exceed pool total"));
    }
    Ok(())
}

fn validate_budget_allocation_units(
    allocation: &SwarmBudgetAllocation,
) -> Result<(), SwarmAuthorityError> {
    let units = allocation
        .reserved_units
        .checked_add(allocation.active_units)
        .and_then(|units| units.checked_add(allocation.consumed_units))
        .and_then(|units| units.checked_add(allocation.released_units))
        .and_then(|units| units.checked_add(allocation.reversed_units))
        .ok_or_else(|| rejected("swarm budget allocation unit overflow"))?;
    if units != allocation.max_units {
        return Err(rejected(format!(
            "swarm budget allocation unit rollup mismatch: {}",
            allocation.allocation_id
        )));
    }
    if allocation.state == SwarmBudgetAllocationState::Active && allocation.active_units == 0 {
        return Err(rejected(format!(
            "swarm budget allocation has no active units: {}",
            allocation.allocation_id
        )));
    }
    Ok(())
}
