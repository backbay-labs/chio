//! Budget arithmetic for the TTFRH gate.
//!
//! The gate fails when any template's measured p99 exceeds the
//! configured budget plus a fixed buffer. The default budget is
//! 60 000 ms; the default buffer is 10 %.

#![forbid(unsafe_code)]

use std::time::Duration;

/// Maximum budget the bench accepts before refusing to start. Guards
/// against accidentally widening the gate via CLI flag drift.
pub const MAX_BUDGET_MS: u64 = 600_000;

/// Default p99 budget enforced by the bench gate.
pub const DEFAULT_BUDGET_MS: u64 = 60_000;

/// Default buffer (percentage points) added to the budget before
/// declaring a regression.
pub const DEFAULT_BUFFER_PCT: u8 = 10;

/// Per-template TTFRH budget configuration.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub budget_ms: u64,
    pub buffer_pct: u8,
}

impl Budget {
    /// Construct a budget rejecting values outside the gate's accepted
    /// envelope.
    pub fn new(budget_ms: u64, buffer_pct: u8) -> Result<Self, BudgetError> {
        if budget_ms == 0 {
            return Err(BudgetError::ZeroBudget);
        }
        if budget_ms > MAX_BUDGET_MS {
            return Err(BudgetError::BudgetExceedsMax {
                budget_ms,
                max_ms: MAX_BUDGET_MS,
            });
        }
        if buffer_pct > 100 {
            return Err(BudgetError::BufferExceedsHundred(buffer_pct));
        }
        Ok(Self {
            budget_ms,
            buffer_pct,
        })
    }

    pub fn default_60s() -> Self {
        // Hard-coded constants are within the accepted envelope, so the
        // struct is constructed directly without the fallible validator.
        Self {
            budget_ms: DEFAULT_BUDGET_MS,
            buffer_pct: DEFAULT_BUFFER_PCT,
        }
    }

    pub fn effective_ms(self) -> u64 {
        let buffer = u128::from(self.budget_ms) * u128::from(self.buffer_pct) / 100;
        let total = u128::from(self.budget_ms) + buffer;
        if total > u128::from(u64::MAX) {
            u64::MAX
        } else {
            total as u64
        }
    }

    pub fn breaches(&self, observed: Duration) -> bool {
        let observed_ms = observed.as_millis();
        observed_ms > u128::from(self.effective_ms())
    }
}

/// Errors raised by [`Budget::new`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    #[error("budget must be greater than zero")]
    ZeroBudget,
    #[error("budget {budget_ms}ms exceeds the gate maximum of {max_ms}ms")]
    BudgetExceedsMax { budget_ms: u64, max_ms: u64 },
    #[error("buffer {0}% must be at most 100%")]
    BufferExceedsHundred(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_budget() {
        match Budget::new(0, 10) {
            Err(BudgetError::ZeroBudget) => {}
            other => panic!("expected ZeroBudget, got {other:?}"),
        }
    }

    #[test]
    fn rejects_budget_above_max() {
        match Budget::new(MAX_BUDGET_MS + 1, 10) {
            Err(BudgetError::BudgetExceedsMax { budget_ms, max_ms }) => {
                assert_eq!(budget_ms, MAX_BUDGET_MS + 1);
                assert_eq!(max_ms, MAX_BUDGET_MS);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_buffer_over_hundred() {
        match Budget::new(60_000, 200) {
            Err(BudgetError::BufferExceedsHundred(value)) => assert_eq!(value, 200),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn applies_buffer_to_effective() {
        let budget = match Budget::new(60_000, 10) {
            Ok(b) => b,
            Err(_) => panic!("budget construction should succeed"),
        };
        assert_eq!(budget.effective_ms(), 66_000);
    }

    #[test]
    fn breaches_when_observed_exceeds_effective() {
        let budget = Budget::default_60s();
        assert!(!budget.breaches(Duration::from_millis(60_000)));
        assert!(!budget.breaches(Duration::from_millis(66_000)));
        assert!(budget.breaches(Duration::from_millis(66_001)));
    }
}
