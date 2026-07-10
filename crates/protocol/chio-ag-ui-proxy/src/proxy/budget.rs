use chio_kernel_core::{BudgetRegistry, BudgetSplitError, InMemoryBudgetRegistry};

use super::config::ParentBudgetSnapshot;
use super::decision::AgUiProxyError;

pub(super) fn build_budget_registry(
    snapshots: &[ParentBudgetSnapshot],
) -> Result<InMemoryBudgetRegistry, AgUiProxyError> {
    let mut budget_registry = InMemoryBudgetRegistry::new();
    seed_budget_registry(&mut budget_registry, snapshots)?;
    Ok(budget_registry)
}

fn seed_budget_registry(
    budgets: &mut InMemoryBudgetRegistry,
    snapshots: &[ParentBudgetSnapshot],
) -> Result<(), AgUiProxyError> {
    for snapshot in snapshots {
        budgets
            .register_parent(snapshot.parent_token_id.clone(), snapshot.parent_share_bps)
            .map_err(|error| budget_seed_error("parent budget snapshot", &error))?;
        for child in &snapshot.admitted_children {
            budgets
                .try_admit_child(
                    snapshot.parent_token_id.as_str(),
                    child.child_token_id.clone(),
                    child.share_bps,
                )
                .map_err(|error| budget_seed_error("admitted child budget snapshot", &error))?;
        }
    }
    Ok(())
}

pub(super) fn budget_seed_error(context: &str, error: &BudgetSplitError) -> AgUiProxyError {
    AgUiProxyError::BudgetRegistry(format!("{context}: {error}"))
}
