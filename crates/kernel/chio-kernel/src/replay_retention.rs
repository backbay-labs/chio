use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Retention deadline for an in-memory replay marker.
///
/// Signed artifacts use both their absolute validity boundary and a monotonic
/// projection of that boundary. Reclamation requires both clocks to pass the
/// deadline so a wall-clock jump cannot shorten or reopen the replay window.
#[derive(Clone, Copy)]
pub(crate) enum ReplayRetention {
    Local {
        monotonic_deadline: Option<Instant>,
    },
    Signed {
        absolute_deadline: Option<SystemTime>,
        monotonic_deadline: Option<Instant>,
    },
}

impl ReplayRetention {
    pub(crate) fn local(ttl: Duration) -> Self {
        let now = Instant::now();
        Self::Local {
            monotonic_deadline: now.checked_add(ttl),
        }
    }

    /// Retain through an inclusive Unix-second validity horizon.
    pub(crate) fn signed_through_unix_secs(valid_through: u64) -> Self {
        let Some(exclusive_deadline) = valid_through.checked_add(1) else {
            return Self::indefinite_signed();
        };
        Self::signed_until_unix_secs(exclusive_deadline)
    }

    /// Retain until an exclusive Unix-second validity boundary.
    pub(crate) fn signed_until_unix_secs(expires_at: u64) -> Self {
        Self::signed_until_at(
            UNIX_EPOCH.checked_add(Duration::from_secs(expires_at)),
            SystemTime::now(),
            Instant::now(),
        )
    }

    /// Retain until an exclusive signed Unix-second validity boundary.
    pub(crate) fn signed_until_unix_i64(expires_at: i64) -> Self {
        let absolute_deadline = if let Ok(seconds) = u64::try_from(expires_at) {
            UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(expires_at.unsigned_abs()))
        };
        Self::signed_until_at(absolute_deadline, SystemTime::now(), Instant::now())
    }

    pub(crate) fn signed_until_at(
        absolute_deadline: Option<SystemTime>,
        now_wall: SystemTime,
        now_monotonic: Instant,
    ) -> Self {
        let monotonic_deadline = absolute_deadline.and_then(|deadline| {
            let remaining = deadline.duration_since(now_wall).unwrap_or(Duration::ZERO);
            now_monotonic.checked_add(remaining)
        });
        Self::Signed {
            absolute_deadline,
            monotonic_deadline,
        }
    }

    fn indefinite_signed() -> Self {
        Self::Signed {
            absolute_deadline: None,
            monotonic_deadline: None,
        }
    }

    pub(crate) fn signed_horizon_elapsed_at(&self, wall_clock_high_water: SystemTime) -> bool {
        match self {
            Self::Local { .. } => false,
            Self::Signed {
                absolute_deadline, ..
            } => absolute_deadline.is_some_and(|deadline| wall_clock_high_water >= deadline),
        }
    }

    pub(crate) fn is_signed(&self) -> bool {
        matches!(self, Self::Signed { .. })
    }

    pub(crate) fn is_expired_at(
        &self,
        wall_clock_high_water: SystemTime,
        now_monotonic: Instant,
    ) -> bool {
        match self {
            Self::Local { monotonic_deadline } => {
                monotonic_deadline.is_some_and(|deadline| now_monotonic >= deadline)
            }
            Self::Signed {
                absolute_deadline,
                monotonic_deadline,
            } => {
                absolute_deadline.is_some_and(|deadline| wall_clock_high_water >= deadline)
                    && monotonic_deadline.is_some_and(|deadline| now_monotonic >= deadline)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn signed_retention_requires_both_deadlines_to_elapse() {
        let start_wall = UNIX_EPOCH.checked_add(Duration::from_secs(1_000)).unwrap();
        let start_monotonic = Instant::now();
        let retention = ReplayRetention::signed_until_at(
            UNIX_EPOCH.checked_add(Duration::from_secs(1_010)),
            start_wall,
            start_monotonic,
        );

        assert!(!retention.is_expired_at(
            start_wall.checked_add(Duration::from_secs(20)).unwrap(),
            start_monotonic.checked_add(Duration::from_secs(5)).unwrap(),
        ));
        assert!(!retention.is_expired_at(
            start_wall.checked_add(Duration::from_secs(5)).unwrap(),
            start_monotonic
                .checked_add(Duration::from_secs(20))
                .unwrap(),
        ));
        assert!(retention.is_expired_at(
            start_wall.checked_add(Duration::from_secs(10)).unwrap(),
            start_monotonic
                .checked_add(Duration::from_secs(10))
                .unwrap(),
        ));
    }

    #[test]
    fn inclusive_horizon_overflow_is_retained_indefinitely() {
        let retention = ReplayRetention::signed_through_unix_secs(u64::MAX);
        assert!(!retention.is_expired_at(SystemTime::now(), Instant::now()));
    }
}
