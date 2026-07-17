//! Supervisor policy: restart budget, backoff schedule, and the per-iteration
//! outcome the worker body reports back to the loop.

use crate::time::as_millis_u64;
use std::time::Duration;

/// Restart and trip policy for one supervised worker.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Stable identifier used in log lines, thread names, and health reasons.
    pub name: &'static str,
    /// A tripped flag on a TCB-critical surface fails evaluations closed.
    pub tcb_critical: bool,
    /// Consecutive restarts before the flag trips to `Degraded`.
    pub trip_after: u32,
    /// Consecutive restarts before terminal `Failed`, after which the supervisor
    /// stops respawning and leaves the flag set for surfaces to read.
    pub max_restarts: u32,
    /// First backoff delay; subsequent delays double up to `max_backoff`.
    pub base_backoff: Duration,
    /// Ceiling on the exponential backoff delay.
    pub max_backoff: Duration,
}

impl SupervisorConfig {
    /// A conventional policy: trip to degraded after a few consecutive failures,
    /// give up after a larger budget, exponential backoff bounded at a minute.
    #[must_use]
    pub fn new(name: &'static str, tcb_critical: bool) -> Self {
        Self {
            name,
            tcb_critical,
            trip_after: 3,
            max_restarts: 10,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(60),
        }
    }
}

/// Result of one worker-body invocation, reported back to the supervisor loop.
pub enum SupervisedOutcome {
    /// The worker observed the shutdown signal and exited cleanly. Do not restart.
    Shutdown,
    /// One iteration completed successfully (a one-shot tick such as a single cluster
    /// sync round). Loop again without recording a failure and without backing off.
    /// The worker is expected to have already stamped its own healthy heartbeat via
    /// [`crate::HealthFlag::record_ok`], so a healthy tick is never misclassified as a
    /// restart-worthy failure.
    Continue,
    /// The worker returned or failed and should be restarted with backoff.
    Restart,
}

/// Exponential backoff for the `count`-th consecutive restart:
/// `min(max_backoff, base_backoff * 2^(count - 1))`, computed with saturating
/// arithmetic so a large `count` can never overflow or panic.
#[must_use]
pub(crate) fn backoff_delay(config: &SupervisorConfig, count: u32) -> Duration {
    let shift = count.saturating_sub(1);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let base_ms = as_millis_u64(config.base_backoff);
    let uncapped = base_ms.saturating_mul(factor);
    let capped = uncapped.min(as_millis_u64(config.max_backoff));
    Duration::from_millis(capped)
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    fn config() -> SupervisorConfig {
        SupervisorConfig {
            name: "test",
            tcb_critical: false,
            trip_after: 3,
            max_restarts: 5,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
        }
    }

    #[test]
    fn backoff_doubles_from_base() {
        let cfg = config();
        assert_eq!(backoff_delay(&cfg, 1), Duration::from_millis(100));
        assert_eq!(backoff_delay(&cfg, 2), Duration::from_millis(200));
        assert_eq!(backoff_delay(&cfg, 3), Duration::from_millis(400));
    }

    #[test]
    fn backoff_saturates_at_max_and_never_overflows() {
        let cfg = config();
        assert_eq!(backoff_delay(&cfg, 100), cfg.max_backoff);
        // A count large enough to overflow the shift must still saturate cleanly.
        assert_eq!(backoff_delay(&cfg, u32::MAX), cfg.max_backoff);
    }

    #[test]
    fn default_policy_is_sane() {
        let cfg = SupervisorConfig::new("writer", true);
        assert!(cfg.tcb_critical);
        assert!(cfg.trip_after <= cfg.max_restarts);
        assert!(cfg.base_backoff <= cfg.max_backoff);
    }
}
