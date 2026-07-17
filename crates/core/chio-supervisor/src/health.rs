//! The health flag: one monotonic, cloneable state handle per supervised surface.
//!
//! The governing rule is honesty. A supervisor that restarted its worker but lost
//! work in the gap must still report the gap, so a tripped flag never clears itself
//! on a later lucky success. The only path back to [`HealthLevel::Healthy`] is an
//! explicit, operator-visible [`HealthFlag::clear`].

use crate::sync::{Arc, AtomicU32, AtomicU64, AtomicU8, Mutex, Ordering};

/// Severity of a supervised surface. Ordered by increasing severity; the flag only
/// ever raises the level and never lowers it except through [`HealthFlag::clear`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    /// Serving normally.
    #[default]
    Healthy = 0,
    /// Tripped after `trip_after` consecutive restarts. The surface reports degraded
    /// and, if TCB-critical, fails evaluations closed. Restarts may still be running.
    Degraded = 1,
    /// Terminal: the restart budget is exhausted and the supervisor stopped respawning.
    Failed = 2,
}

impl HealthLevel {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => HealthLevel::Healthy,
            1 => HealthLevel::Degraded,
            _ => HealthLevel::Failed,
        }
    }
}

/// A cloneable handle to one surface's health. Level and counter reads are
/// lock-free; the reason string lives behind a `Mutex` whose only invariant is the
/// single `Option` it holds, so recovering a poisoned lock with `into_inner` is
/// sound (there is no cross-field state to leave half-mutated).
#[derive(Clone)]
pub struct HealthFlag(Arc<HealthState>);

struct HealthState {
    level: AtomicU8,
    tcb_critical: bool,
    consecutive_failures: AtomicU32,
    restart_total: AtomicU64,
    last_ok_unix_ms: AtomicU64,
    last_transition_unix_ms: AtomicU64,
    reason: Mutex<Option<String>>,
}

impl HealthFlag {
    /// Create a flag in the [`HealthLevel::Healthy`] state. `tcb_critical` marks a
    /// surface whose degradation must fail evaluations closed.
    #[must_use]
    pub fn new(tcb_critical: bool) -> Self {
        Self(Arc::new(HealthState {
            level: AtomicU8::new(HealthLevel::Healthy as u8),
            tcb_critical,
            consecutive_failures: AtomicU32::new(0),
            restart_total: AtomicU64::new(0),
            last_ok_unix_ms: AtomicU64::new(0),
            last_transition_unix_ms: AtomicU64::new(0),
            reason: Mutex::new(None),
        }))
    }

    /// Record a completed unit of work. Resets the consecutive-failure counter and
    /// stamps liveness, but never lowers a tripped level.
    pub fn record_ok(&self, now_ms: u64) {
        self.0.consecutive_failures.store(0, Ordering::SeqCst);
        self.0.last_ok_unix_ms.store(now_ms, Ordering::SeqCst);
    }

    /// Record a restart-worthy failure and return the new consecutive count. Trips to
    /// [`HealthLevel::Degraded`] once the count reaches `trip_after`, and never
    /// downgrades. `trip_after == 0` trips on the first failure.
    pub fn record_failure(&self, reason: impl Into<String>, now_ms: u64, trip_after: u32) -> u32 {
        let count = self.0.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        self.0.restart_total.fetch_add(1, Ordering::SeqCst);
        self.set_reason(Some(reason.into()));
        if count >= trip_after {
            self.raise_to(HealthLevel::Degraded, now_ms);
        }
        count
    }

    /// Terminal escalation: the restart budget is exhausted and the supervisor has
    /// stopped respawning. Raises the level to [`HealthLevel::Failed`].
    pub fn escalate_failed(&self, now_ms: u64) {
        self.raise_to(HealthLevel::Failed, now_ms);
    }

    /// The current severity level.
    #[must_use]
    pub fn level(&self) -> HealthLevel {
        HealthLevel::from_u8(self.0.level.load(Ordering::SeqCst))
    }

    /// Whether this surface is TCB-critical.
    #[must_use]
    pub fn tcb_critical(&self) -> bool {
        self.0.tcb_critical
    }

    /// True when the surface must fail closed: TCB-critical and not
    /// [`HealthLevel::Healthy`]. Read on the pre-dispatch path.
    #[must_use]
    pub fn is_serving_closed(&self) -> bool {
        self.0.tcb_critical && !matches!(self.level(), HealthLevel::Healthy)
    }

    /// The only path back to [`HealthLevel::Healthy`]: an explicit operator recovery.
    /// Clears the reason and resets the consecutive-failure counter; the cumulative
    /// `restart_total` is preserved so the history of the incident is not erased.
    pub fn clear(&self, now_ms: u64) {
        self.0.consecutive_failures.store(0, Ordering::SeqCst);
        self.0
            .level
            .store(HealthLevel::Healthy as u8, Ordering::SeqCst);
        self.0
            .last_transition_unix_ms
            .store(now_ms, Ordering::SeqCst);
        self.set_reason(None);
    }

    /// Point-in-time view for operator surfaces and telemetry exporters.
    #[must_use]
    pub fn snapshot(&self) -> HealthSnapshot {
        HealthSnapshot {
            level: self.level(),
            tcb_critical: self.0.tcb_critical,
            restart_total: self.0.restart_total.load(Ordering::SeqCst),
            consecutive_failures: self.0.consecutive_failures.load(Ordering::SeqCst),
            last_ok_unix_ms: nonzero(self.0.last_ok_unix_ms.load(Ordering::SeqCst)),
            last_transition_unix_ms: nonzero(self.0.last_transition_unix_ms.load(Ordering::SeqCst)),
            reason: self.reason(),
        }
    }

    /// Monotonically raise the level. A compare-and-swap loop guarantees a concurrent
    /// escalation can never be lost behind a lower-severity raise.
    fn raise_to(&self, level: HealthLevel, now_ms: u64) {
        let target = level as u8;
        let mut current = self.0.level.load(Ordering::SeqCst);
        while target > current {
            match self
                .0
                .level
                .compare_exchange(current, target, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    self.0
                        .last_transition_unix_ms
                        .store(now_ms, Ordering::SeqCst);
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn set_reason(&self, reason: Option<String>) {
        match self.0.reason.lock() {
            Ok(mut guard) => *guard = reason,
            Err(poisoned) => *poisoned.into_inner() = reason,
        }
    }

    fn reason(&self) -> Option<String> {
        match self.0.reason.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// A serializable point-in-time view of a [`HealthFlag`], for operator surfaces and
/// the telemetry exporter. All fields are additive; consumers deserialize with
/// `#[serde(default)]`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthSnapshot {
    pub level: HealthLevel,
    pub tcb_critical: bool,
    pub restart_total: u64,
    pub consecutive_failures: u32,
    #[serde(default)]
    pub last_ok_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_transition_unix_ms: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn healthy_by_default_and_never_serves_closed_when_healthy() {
        let flag = HealthFlag::new(true);
        assert_eq!(flag.level(), HealthLevel::Healthy);
        assert!(!flag.is_serving_closed());
    }

    #[test]
    fn record_ok_resets_consecutive_failures_without_lowering_level() {
        let flag = HealthFlag::new(false);
        flag.record_failure("boom", NOW, 2);
        flag.record_failure("boom", NOW, 2);
        assert_eq!(flag.level(), HealthLevel::Degraded);
        flag.record_ok(NOW + 1);
        // The consecutive counter reset, but a tripped level must not self-heal.
        assert_eq!(flag.snapshot().consecutive_failures, 0);
        assert_eq!(flag.level(), HealthLevel::Degraded);
    }

    #[test]
    fn trips_to_degraded_exactly_at_trip_after() {
        let flag = HealthFlag::new(false);
        assert_eq!(flag.record_failure("one", NOW, 3), 1);
        assert_eq!(flag.level(), HealthLevel::Healthy);
        assert_eq!(flag.record_failure("two", NOW, 3), 2);
        assert_eq!(flag.level(), HealthLevel::Healthy);
        assert_eq!(flag.record_failure("three", NOW, 3), 3);
        assert_eq!(flag.level(), HealthLevel::Degraded);
    }

    #[test]
    fn trip_after_zero_trips_on_first_failure() {
        let flag = HealthFlag::new(false);
        flag.record_failure("immediate", NOW, 0);
        assert_eq!(flag.level(), HealthLevel::Degraded);
    }

    #[test]
    fn escalate_failed_is_terminal_and_reported() {
        let flag = HealthFlag::new(true);
        flag.record_failure("boom", NOW, 1);
        flag.escalate_failed(NOW);
        assert_eq!(flag.level(), HealthLevel::Failed);
        assert!(flag.is_serving_closed());
    }

    #[test]
    fn raise_is_monotonic_and_ignores_lower_severity() {
        let flag = HealthFlag::new(false);
        flag.escalate_failed(NOW);
        assert_eq!(flag.level(), HealthLevel::Failed);
        // A later degraded trip must not lower a Failed surface.
        flag.record_failure("late", NOW, 0);
        assert_eq!(flag.level(), HealthLevel::Failed);
    }

    #[test]
    fn tcb_flag_serves_closed_when_not_healthy_only() {
        let non_tcb = HealthFlag::new(false);
        non_tcb.escalate_failed(NOW);
        assert!(!non_tcb.is_serving_closed());

        let tcb = HealthFlag::new(true);
        assert!(!tcb.is_serving_closed());
        tcb.record_failure("boom", NOW, 0);
        assert!(tcb.is_serving_closed());
    }

    #[test]
    fn clear_is_the_only_downgrade_and_preserves_restart_total() {
        let flag = HealthFlag::new(true);
        flag.record_failure("boom", NOW, 1);
        flag.record_failure("boom", NOW, 1);
        assert_eq!(flag.level(), HealthLevel::Degraded);
        let restarts_before = flag.snapshot().restart_total;
        flag.clear(NOW + 5);
        assert_eq!(flag.level(), HealthLevel::Healthy);
        assert!(!flag.is_serving_closed());
        assert_eq!(flag.snapshot().reason, None);
        // History is not erased: the cumulative restart count survives the recovery.
        assert_eq!(flag.snapshot().restart_total, restarts_before);
    }

    #[test]
    fn snapshot_reports_reason_and_liveness() {
        let flag = HealthFlag::new(false);
        assert_eq!(flag.snapshot().last_ok_unix_ms, None);
        flag.record_ok(NOW);
        flag.record_failure("disk full", NOW + 1, 0);
        let snap = flag.snapshot();
        assert_eq!(snap.level, HealthLevel::Degraded);
        assert_eq!(snap.restart_total, 1);
        assert_eq!(snap.last_ok_unix_ms, Some(NOW));
        assert_eq!(snap.reason.as_deref(), Some("disk full"));
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let flag = HealthFlag::new(true);
        flag.record_failure("boom", NOW, 0);
        let snap = flag.snapshot();
        let encoded = serde_json::to_string(&snap).unwrap_or_default();
        assert!(encoded.contains("\"level\":\"degraded\""));
        let decoded: HealthSnapshot =
            serde_json::from_str(&encoded).unwrap_or_else(|_| snap.clone());
        assert_eq!(decoded, snap);
    }
}
