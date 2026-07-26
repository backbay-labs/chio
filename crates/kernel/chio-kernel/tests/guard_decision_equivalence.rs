use chio_kernel::Verdict;
use chio_kernel_core::{
    guard_pipeline_allows, guard_projection_allows_continuation, guard_step_admits, GuardStep,
};
use proptest::prelude::*;

fn runtime_allows(core_authorized: bool, verdicts: &[Verdict]) -> bool {
    core_authorized && verdicts.iter().all(|verdict| *verdict == Verdict::Allow)
}

proptest! {
    #[test]
    fn verdict_fold_matches_bounded_pipeline(
        core_authorized in any::<bool>(),
        raw_verdicts in proptest::collection::vec(0_u8..3, 0..16),
    ) {
        let verdicts = raw_verdicts
            .iter()
            .map(|raw| match raw {
                0 => Verdict::Allow,
                1 => Verdict::Deny,
                _ => Verdict::PendingApproval,
            })
            .collect::<Vec<_>>();
        let steps = verdicts
            .iter()
            .copied()
            .map(GuardStep::from)
            .collect::<Vec<_>>();

        prop_assert_eq!(
            guard_pipeline_allows(core_authorized, &steps),
            runtime_allows(core_authorized, &verdicts),
        );
    }
}

#[test]
fn pending_approval_and_error_projections_fail_closed() {
    let pending = GuardStep::from(Verdict::PendingApproval);
    assert_eq!(pending, GuardStep::Error);
    assert!(!guard_step_admits(GuardStep::Deny));
    assert!(!guard_step_admits(pending));
    assert!(!guard_step_admits(GuardStep::Error));
    assert!(!runtime_allows(true, &[Verdict::PendingApproval]));
}

#[test]
fn only_allow_projection_permits_continuation() {
    assert_eq!(GuardStep::from(Verdict::Allow), GuardStep::Allow);
    assert_eq!(GuardStep::from(Verdict::Deny), GuardStep::Deny);
    assert!(guard_step_admits(GuardStep::Allow));
    assert!(!guard_step_admits(GuardStep::Deny));
    assert!(!guard_step_admits(GuardStep::Error));
}

#[test]
fn inconsistent_projection_results_remain_fail_closed() {
    assert!(!guard_projection_allows_continuation(true, GuardStep::Deny));
    assert!(!guard_projection_allows_continuation(
        true,
        GuardStep::Error
    ));
    assert!(!guard_projection_allows_continuation(
        false,
        GuardStep::Allow
    ));
}
