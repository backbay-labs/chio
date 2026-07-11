mod support;

use chio_trace_validate::{
    decode_observations, project_revocation_trace, validate_projection_with, PrefixReachability,
    ReachabilityOracle, TraceError, ValidationStatus,
};

struct CutoffOracle {
    first_unreachable: Option<usize>,
}

impl ReachabilityOracle for CutoffOracle {
    fn checker_name(&self) -> &str {
        "test cutoff oracle"
    }

    fn prefix_reachability(
        &self,
        _projection: &chio_trace_validate::RevocationProjection,
        prefix_len: usize,
    ) -> Result<PrefixReachability, TraceError> {
        Ok(
            if self
                .first_unreachable
                .is_some_and(|cutoff| prefix_len >= cutoff)
            {
                PrefixReachability::Unreachable
            } else {
                PrefixReachability::Reachable
            },
        )
    }
}

#[test]
fn binary_prefix_search_reports_the_first_divergent_step() -> Result<(), TraceError> {
    let fixture = support::bad_trace()?;
    let observations = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let projection = project_revocation_trace(&observations)?;
    let report = validate_projection_with(
        &projection,
        &CutoffOracle {
            first_unreachable: Some(3),
        },
    )?;

    assert_eq!(report.status, ValidationStatus::Failed);
    let divergence = report
        .divergence
        .ok_or_else(|| TraceError::InvalidInput("missing divergence".to_string()))?;
    assert_eq!(divergence.step, 3);
    assert_eq!(divergence.failed_conjunct, "TraceReachability");
    Ok(())
}

#[test]
fn reachable_trace_reports_all_four_safety_invariants() -> Result<(), TraceError> {
    let fixture = support::good_trace()?;
    let observations = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let projection = project_revocation_trace(&observations)?;
    let report = validate_projection_with(
        &projection,
        &CutoffOracle {
            first_unreachable: None,
        },
    )?;

    assert_eq!(report.status, ValidationStatus::Passed);
    assert_eq!(report.checker, "test cutoff oracle");
    assert_eq!(report.invariants.len(), 4);
    assert!(report.divergence.is_none());
    Ok(())
}
