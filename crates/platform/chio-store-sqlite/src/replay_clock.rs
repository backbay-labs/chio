use std::sync::Mutex;
use std::time::{Duration, Instant};

use chio_kernel::ReplayClockDirection;

const MIN_REBASELINE_CONFIRMATION: Duration = Duration::from_secs(1);
const MAX_REBASELINE_DRIFT_SECS: u64 = 1;

pub(crate) enum ReplayClockValidationError {
    Poisoned,
    Anomaly {
        direction: ReplayClockDirection,
        observed: i64,
        high_water: i64,
    },
}

pub(crate) struct StableReplayClock {
    state: Mutex<StableReplayClockState>,
    max_skew_secs: i64,
}

struct StableReplayClockState {
    anchor_wall: i64,
    anchor_monotonic: Instant,
    pending_rebaseline: Option<PendingReplayClockRebaseline>,
}

#[derive(Clone, Copy)]
struct PendingReplayClockRebaseline {
    observed_wall: i64,
    observed_monotonic: Instant,
    unexplained_gap_secs: i64,
}

enum RebaselineConfirmation {
    Confirmed,
    Waiting,
    Inconsistent,
}

impl StableReplayClock {
    pub(crate) fn new(anchor_wall: i64, max_skew_secs: i64) -> Self {
        Self {
            state: Mutex::new(StableReplayClockState {
                anchor_wall,
                anchor_monotonic: Instant::now(),
                pending_rebaseline: None,
            }),
            max_skew_secs,
        }
    }

    pub(crate) fn validate_persisted(
        &self,
        high_water: i64,
    ) -> Result<(), ReplayClockValidationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReplayClockValidationError::Poisoned)?;
        let expected = expected_wall_now(&state, Instant::now());
        if high_water > expected.saturating_add(self.max_skew_secs) {
            return Err(ReplayClockValidationError::Anomaly {
                direction: ReplayClockDirection::Rollback,
                observed: expected,
                high_water,
            });
        }
        Ok(())
    }

    pub(crate) fn expected_wall_now(&self) -> Result<i64, ReplayClockValidationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReplayClockValidationError::Poisoned)?;
        Ok(expected_wall_now(&state, Instant::now()))
    }

    pub(crate) fn validate_observed(
        &self,
        observed: i64,
        durable_high_water: i64,
    ) -> Result<(), ReplayClockValidationError> {
        self.validate_observed_at(observed, durable_high_water, Instant::now())
    }

    pub(crate) fn validate_observed_at(
        &self,
        observed: i64,
        durable_high_water: i64,
        sample_monotonic: Instant,
    ) -> Result<(), ReplayClockValidationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayClockValidationError::Poisoned)?;
        let expected = expected_wall_now(&state, sample_monotonic);
        if observed > expected.saturating_add(self.max_skew_secs) {
            let unexplained_gap_secs = observed.saturating_sub(expected);
            let confirmation = state.pending_rebaseline.map(|pending| {
                rebaseline_confirmation(pending, observed, sample_monotonic, unexplained_gap_secs)
            });
            match confirmation {
                Some(RebaselineConfirmation::Confirmed) => {
                    state.anchor_wall = observed;
                    state.anchor_monotonic = sample_monotonic;
                    state.pending_rebaseline = None;
                }
                Some(RebaselineConfirmation::Waiting) => {
                    return Err(ReplayClockValidationError::Anomaly {
                        direction: ReplayClockDirection::ForwardJump,
                        observed,
                        high_water: expected,
                    });
                }
                Some(RebaselineConfirmation::Inconsistent) | None => {
                    state.pending_rebaseline = Some(PendingReplayClockRebaseline {
                        observed_wall: observed,
                        observed_monotonic: sample_monotonic,
                        unexplained_gap_secs,
                    });
                    return Err(ReplayClockValidationError::Anomaly {
                        direction: ReplayClockDirection::ForwardJump,
                        observed,
                        high_water: expected,
                    });
                }
            }
        } else if observed < expected.saturating_sub(self.max_skew_secs) {
            state.pending_rebaseline = None;
            return Err(ReplayClockValidationError::Anomaly {
                direction: ReplayClockDirection::Rollback,
                observed,
                high_water: expected,
            });
        } else {
            state.pending_rebaseline = None;
        }

        if observed < durable_high_water.saturating_sub(self.max_skew_secs) {
            return Err(ReplayClockValidationError::Anomaly {
                direction: ReplayClockDirection::Rollback,
                observed,
                high_water: durable_high_water,
            });
        }
        Ok(())
    }
}

fn expected_wall_now(state: &StableReplayClockState, sample_monotonic: Instant) -> i64 {
    let elapsed = i64::try_from(
        sample_monotonic
            .saturating_duration_since(state.anchor_monotonic)
            .as_secs(),
    )
    .unwrap_or(i64::MAX);
    state.anchor_wall.saturating_add(elapsed)
}

fn rebaseline_confirmation(
    pending: PendingReplayClockRebaseline,
    observed_wall: i64,
    observed_monotonic: Instant,
    unexplained_gap_secs: i64,
) -> RebaselineConfirmation {
    let monotonic_progress =
        observed_monotonic.saturating_duration_since(pending.observed_monotonic);
    let Some(wall_progress) = observed_wall
        .checked_sub(pending.observed_wall)
        .and_then(|progress| u64::try_from(progress).ok())
    else {
        return RebaselineConfirmation::Inconsistent;
    };
    let monotonic_progress_secs = i64::try_from(monotonic_progress.as_secs()).unwrap_or(i64::MAX);
    let wall_progress_secs = i64::try_from(wall_progress).unwrap_or(i64::MAX);
    if wall_progress_secs.abs_diff(monotonic_progress_secs) > MAX_REBASELINE_DRIFT_SECS
        || unexplained_gap_secs.abs_diff(pending.unexplained_gap_secs) > MAX_REBASELINE_DRIFT_SECS
    {
        return RebaselineConfirmation::Inconsistent;
    }
    if monotonic_progress < MIN_REBASELINE_CONFIRMATION {
        return RebaselineConfirmation::Waiting;
    }
    RebaselineConfirmation::Confirmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_follow_up_sample_rebaselines_after_suspend_gap(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let anchor_wall = 10_000;
        let clock = StableReplayClock::new(anchor_wall, 300);
        let first_monotonic = {
            let state = clock
                .state
                .lock()
                .map_err(|_| std::io::Error::other("replay clock mutex poisoned"))?;
            state
                .anchor_monotonic
                .checked_add(Duration::from_secs(1))
                .ok_or_else(|| std::io::Error::other("monotonic test instant overflow"))?
        };
        let suspended_wall = anchor_wall + 3_600;
        assert!(matches!(
            clock.validate_observed_at(suspended_wall, anchor_wall, first_monotonic),
            Err(ReplayClockValidationError::Anomaly {
                direction: ReplayClockDirection::ForwardJump,
                ..
            })
        ));
        assert!(clock
            .validate_observed_at(
                suspended_wall + 2,
                anchor_wall,
                first_monotonic
                    .checked_add(Duration::from_secs(2))
                    .ok_or_else(|| std::io::Error::other("monotonic test instant overflow"))?,
            )
            .is_ok());
        Ok(())
    }

    #[test]
    fn inconsistent_follow_up_sample_remains_denied() -> Result<(), Box<dyn std::error::Error>> {
        let anchor_wall = 10_000;
        let clock = StableReplayClock::new(anchor_wall, 300);
        let first_monotonic = {
            let state = clock
                .state
                .lock()
                .map_err(|_| std::io::Error::other("replay clock mutex poisoned"))?;
            state
                .anchor_monotonic
                .checked_add(Duration::from_secs(1))
                .ok_or_else(|| std::io::Error::other("monotonic test instant overflow"))?
        };
        assert!(clock
            .validate_observed_at(anchor_wall + 3_600, anchor_wall, first_monotonic)
            .is_err());
        assert!(clock
            .validate_observed_at(
                anchor_wall + 7_200,
                anchor_wall,
                first_monotonic
                    .checked_add(Duration::from_secs(2))
                    .ok_or_else(|| std::io::Error::other("monotonic test instant overflow"))?,
            )
            .is_err());
        Ok(())
    }
}
