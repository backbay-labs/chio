//! Arena-survival feed.
//!
//! Consumes arena round outputs. Each observation reports how many
//! adversarial rounds a publisher's guard bundle entered and how many
//! it survived. The delta is the survival rate clamped to
//! `[0.0, MAX_FEED_DELTA]`. Empty observation vectors produce a zero
//! delta; the empty-input fallback exists for unit-test isolation only.
//!
//! Determinism notes:
//!
//! - The feed reads no global state; the same `ArenaRoundsObservation`
//!   produces the same `ScoreDelta` on every call.
//! - The feed does not depend on `chio-arena` directly; callers (the
//!   marketplace surface, the reputation CLI, audit tooling) project
//!   leaderboard rows or per-round receipts into the
//!   `ArenaRoundOutcome` shape.

use serde::{Deserialize, Serialize};

use crate::feed::{ReputationFeed, ScoreDelta};

/// Identifier embedded in `ScoreDelta` outputs from this feed.
pub const FEED_ID: &str = "arena_survival";

/// Single arena round outcome for a publisher's guard bundle.
///
/// `entered` and `survived` are u32 because the arena round structure caps
/// rounds per epoch well below 2^32. `survived` must be `<= entered`; if
/// callers pass `survived > entered`, the feed clamps to the entered count
/// rather than panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArenaRoundOutcome {
    pub entered: u32,
    pub survived: u32,
}

/// Caller-projected view of arena rounds for a single publisher.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArenaRoundsObservation {
    pub rounds: Vec<ArenaRoundOutcome>,
}

impl ArenaRoundsObservation {
    /// Total rounds entered across all `ArenaRoundOutcome` entries.
    #[must_use]
    pub fn total_entered(&self) -> u64 {
        self.rounds
            .iter()
            .map(|outcome| u64::from(outcome.entered))
            .sum()
    }

    /// Total rounds survived across all `ArenaRoundOutcome` entries, clamped
    /// per-outcome so a malformed input cannot inflate the survival count.
    #[must_use]
    pub fn total_survived(&self) -> u64 {
        self.rounds
            .iter()
            .map(|outcome| u64::from(outcome.survived.min(outcome.entered)))
            .sum()
    }
}

/// Arena-survival feed.
///
/// Reads `ArenaRoundsObservation` and produces a delta equal to the
/// publisher's survival rate. Construction is parameter-free today; future
/// configuration knobs (round-age decay, minimum sample size, per-cluster
/// floors) plug in here without changing the public trait.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArenaSurvivalFeed;

impl ArenaSurvivalFeed {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ReputationFeed for ArenaSurvivalFeed {
    type Observation = ArenaRoundsObservation;

    fn feed_id(&self) -> &'static str {
        FEED_ID
    }

    fn observe(&self, observation: &Self::Observation) -> ScoreDelta {
        let total_entered = observation.total_entered();
        if total_entered == 0 {
            return ScoreDelta::zero(FEED_ID);
        }
        let total_survived = observation.total_survived();
        let observations_consumed = u32::try_from(observation.rounds.len()).unwrap_or(u32::MAX);
        let survival_rate = (total_survived as f64) / (total_entered as f64);
        ScoreDelta::from_value(FEED_ID, survival_rate, observations_consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_observation_yields_zero_delta() {
        let feed = ArenaSurvivalFeed::new();
        let observation = ArenaRoundsObservation::default();
        let delta = feed.observe(&observation);
        assert_eq!(delta.value, 0.0);
        assert_eq!(delta.observations_consumed, 0);
        assert_eq!(delta.feed_id, FEED_ID);
    }

    #[test]
    fn full_survival_yields_max_delta() {
        let feed = ArenaSurvivalFeed::new();
        let observation = ArenaRoundsObservation {
            rounds: vec![
                ArenaRoundOutcome {
                    entered: 10,
                    survived: 10,
                },
                ArenaRoundOutcome {
                    entered: 5,
                    survived: 5,
                },
            ],
        };
        let delta = feed.observe(&observation);
        assert!((delta.value - 1.0).abs() < f64::EPSILON);
        assert_eq!(delta.observations_consumed, 2);
    }

    #[test]
    fn partial_survival_yields_proportional_delta() {
        let feed = ArenaSurvivalFeed::new();
        let observation = ArenaRoundsObservation {
            rounds: vec![ArenaRoundOutcome {
                entered: 4,
                survived: 1,
            }],
        };
        let delta = feed.observe(&observation);
        assert!((delta.value - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn malformed_survived_clamps_to_entered() {
        let feed = ArenaSurvivalFeed::new();
        let observation = ArenaRoundsObservation {
            rounds: vec![ArenaRoundOutcome {
                entered: 3,
                survived: 99,
            }],
        };
        let delta = feed.observe(&observation);
        assert!((delta.value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn zero_entered_in_one_outcome_is_skipped() {
        let feed = ArenaSurvivalFeed::new();
        let observation = ArenaRoundsObservation {
            rounds: vec![
                ArenaRoundOutcome {
                    entered: 0,
                    survived: 0,
                },
                ArenaRoundOutcome {
                    entered: 2,
                    survived: 1,
                },
            ],
        };
        let delta = feed.observe(&observation);
        assert!((delta.value - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn deterministic_under_repeated_calls() {
        let feed = ArenaSurvivalFeed::new();
        let observation = ArenaRoundsObservation {
            rounds: vec![ArenaRoundOutcome {
                entered: 7,
                survived: 4,
            }],
        };
        let first = feed.observe(&observation);
        let second = feed.observe(&observation);
        assert_eq!(first, second);
    }
}
