use super::{BudgetStore, SqliteBudgetStore};

pub(crate) fn seed_budget_exposure(
    store: &SqliteBudgetStore,
    capability_id: &str,
    total_exposure: u64,
) {
    let per_invocation = total_exposure / 2;
    assert_eq!(per_invocation * 2, total_exposure);
    for index in 0..2 {
        let hold_id = format!("fixture-{capability_id}-{index}");
        assert!(store
            .try_charge_cost_with_ids(
                capability_id,
                0,
                Some(2),
                per_invocation,
                Some(per_invocation),
                Some(total_exposure),
                Some(&hold_id),
                Some(&format!("{hold_id}:authorize")),
            )
            .expect("seed budget exposure"));
    }
}
