//! Cross-provider equality feed.
//!
//! Consumes verdict-matrix outputs. Each observation reports per-case
//! verdicts across providers and asks: did the providers agree? The
//! delta is the rate of cases where every observed provider produced the
//! same verdict.
//!
//! The cross-provider equality input is a comparability oracle, not a
//! trust oracle by itself; a high delta from this feed only means the
//! publisher's guard verdicts are reproducible across providers, not
//! that the verdicts are correct. Combined with `ArenaSurvivalFeed` and
//! the threshold table in `tier.rs`, reproducible-and-survival makes a
//! publisher eligible for higher tiers.
//!
//! Determinism notes:
//!
//! - The feed reads no global state; the same `VerdictMatrixObservation`
//!   produces the same `ScoreDelta` on every call.
//! - The feed does not depend on `chio-conformance` directly; callers
//!   project the verdict-matrix runs into the local
//!   `VerdictCaseOutcome` shape.

use serde::{Deserialize, Serialize};

use crate::feed::{ReputationFeed, ScoreDelta};

/// Identifier embedded in `ScoreDelta` outputs from this feed.
pub const FEED_ID: &str = "cross_provider_equality";

/// Per-case outcome across providers.
///
/// `providers_observed` is the count of providers reporting on the case;
/// `unique_verdicts` is the count of distinct verdict tokens observed. A
/// case is "in agreement" when `unique_verdicts == 1` and at least two
/// providers reported. Single-provider cases are skipped (they cannot
/// disagree); zero-provider cases are also skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictCaseOutcome {
    pub providers_observed: u32,
    pub unique_verdicts: u32,
}

impl VerdictCaseOutcome {
    /// Whether this case counts toward the agreement-rate denominator.
    /// Cases with fewer than two providers cannot disagree.
    #[must_use]
    pub fn is_eligible(self) -> bool {
        self.providers_observed >= 2
    }

    /// Whether this case shows full agreement across the providers.
    /// Returns false for ineligible cases.
    #[must_use]
    pub fn is_in_agreement(self) -> bool {
        self.is_eligible() && self.unique_verdicts == 1
    }
}

/// Caller-projected view of a verdict-matrix run for a single
/// publisher's guard bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictMatrixObservation {
    pub cases: Vec<VerdictCaseOutcome>,
}

impl VerdictMatrixObservation {
    /// Count of cases that contribute to the denominator.
    #[must_use]
    pub fn eligible_cases(&self) -> u64 {
        self.cases.iter().filter(|case| case.is_eligible()).count() as u64
    }

    /// Count of cases where every observed provider produced the same
    /// verdict.
    #[must_use]
    pub fn cases_in_agreement(&self) -> u64 {
        self.cases
            .iter()
            .filter(|case| case.is_in_agreement())
            .count() as u64
    }
}

/// Cross-provider equality feed.
///
/// Reads `VerdictMatrixObservation` and produces a delta equal to the
/// rate of cases in agreement among eligible cases (cases with at least
/// two providers reporting).
#[derive(Debug, Default, Clone, Copy)]
pub struct CrossProviderEqualityFeed;

impl CrossProviderEqualityFeed {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ReputationFeed for CrossProviderEqualityFeed {
    type Observation = VerdictMatrixObservation;

    fn feed_id(&self) -> &'static str {
        FEED_ID
    }

    fn observe(&self, observation: &Self::Observation) -> ScoreDelta {
        let eligible = observation.eligible_cases();
        if eligible == 0 {
            return ScoreDelta::zero(FEED_ID);
        }
        let agreed = observation.cases_in_agreement();
        let observations_consumed = u32::try_from(observation.cases.len()).unwrap_or(u32::MAX);
        let agreement_rate = (agreed as f64) / (eligible as f64);
        ScoreDelta::from_value(FEED_ID, agreement_rate, observations_consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_observation_yields_zero_delta() {
        let feed = CrossProviderEqualityFeed::new();
        let delta = feed.observe(&VerdictMatrixObservation::default());
        assert_eq!(delta.value, 0.0);
        assert_eq!(delta.observations_consumed, 0);
        assert_eq!(delta.feed_id, FEED_ID);
    }

    #[test]
    fn unanimous_agreement_yields_max_delta() {
        let feed = CrossProviderEqualityFeed::new();
        let observation = VerdictMatrixObservation {
            cases: vec![
                VerdictCaseOutcome {
                    providers_observed: 3,
                    unique_verdicts: 1,
                },
                VerdictCaseOutcome {
                    providers_observed: 4,
                    unique_verdicts: 1,
                },
            ],
        };
        let delta = feed.observe(&observation);
        assert!((delta.value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn partial_agreement_yields_proportional_delta() {
        let feed = CrossProviderEqualityFeed::new();
        let observation = VerdictMatrixObservation {
            cases: vec![
                VerdictCaseOutcome {
                    providers_observed: 3,
                    unique_verdicts: 1,
                },
                VerdictCaseOutcome {
                    providers_observed: 3,
                    unique_verdicts: 2,
                },
                VerdictCaseOutcome {
                    providers_observed: 3,
                    unique_verdicts: 3,
                },
                VerdictCaseOutcome {
                    providers_observed: 3,
                    unique_verdicts: 1,
                },
            ],
        };
        let delta = feed.observe(&observation);
        assert!((delta.value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn single_provider_case_is_skipped() {
        let feed = CrossProviderEqualityFeed::new();
        let observation = VerdictMatrixObservation {
            cases: vec![
                VerdictCaseOutcome {
                    providers_observed: 1,
                    unique_verdicts: 1,
                },
                VerdictCaseOutcome {
                    providers_observed: 2,
                    unique_verdicts: 1,
                },
            ],
        };
        let delta = feed.observe(&observation);
        assert!((delta.value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn no_eligible_cases_yields_zero_delta() {
        let feed = CrossProviderEqualityFeed::new();
        let observation = VerdictMatrixObservation {
            cases: vec![
                VerdictCaseOutcome {
                    providers_observed: 0,
                    unique_verdicts: 0,
                },
                VerdictCaseOutcome {
                    providers_observed: 1,
                    unique_verdicts: 1,
                },
            ],
        };
        let delta = feed.observe(&observation);
        assert_eq!(delta.value, 0.0);
    }

    #[test]
    fn deterministic_under_repeated_calls() {
        let feed = CrossProviderEqualityFeed::new();
        let observation = VerdictMatrixObservation {
            cases: vec![
                VerdictCaseOutcome {
                    providers_observed: 3,
                    unique_verdicts: 1,
                },
                VerdictCaseOutcome {
                    providers_observed: 3,
                    unique_verdicts: 2,
                },
            ],
        };
        let first = feed.observe(&observation);
        let second = feed.observe(&observation);
        assert_eq!(first, second);
    }
}
