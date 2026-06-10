//! Reputation feed trait.
//!
//! A `ReputationFeed` is a deterministic, pure function from a caller-provided
//! observation to a non-negative score delta. Feeds do NOT call back into the
//! kernel, do NOT touch storage, and do NOT mutate global state. The kernel
//! never invokes a feed; instead, callers (the marketplace surface, the
//! reputation CLI, audit tooling) gather observations from existing
//! ground-truth sources (arena rounds, the verdict matrix) and feed them
//! through the trait to produce score deltas that are summed into a numeric
//! score and then mapped to a `ReputationTier`.
//!
//! Determinism guarantees:
//!
//! - The same observation produces the same delta on every call.
//! - The trait surface is intentionally narrow (no async, no `&mut self`); a
//!   feed is a value type whose configuration is set at construction time.
//! - Deltas are clamped to a closed `[0.0, max_delta]` range. Negative deltas
//!   are rejected at the trait surface so feeds remain monotonic in the
//!   observed signal (more positive evidence never decreases the score).
//!
//! The trait is sealed only by convention, not by Rust's sealed-trait pattern;
//! downstream crates may define their own feeds, but the two feeds bundled in
//! this crate (`feeds::arena_survival`, `feeds::cross_provider_equality`) are
//! the canonical Chio implementations. Each shipped feed names a stable
//! `feed_id` so the audit doc and downstream tooling can attribute the
//! tier-distribution histogram back to the feed that produced it.

use serde::{Deserialize, Serialize};

/// Maximum delta a single feed call may emit. Composition over many calls
/// (one per observation) is allowed; the per-call cap defends against a
/// single oversized observation dominating the composite score.
pub const MAX_FEED_DELTA: f64 = 1.0;

/// Per-feed score delta produced from a single observation.
///
/// `value` is always in `[0.0, MAX_FEED_DELTA]`. The struct also carries the
/// `feed_id` and `observations_consumed` count so the audit doc can report
/// which feed produced which delta on the deterministic corpus.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScoreDelta {
    pub feed_id: &'static str,
    pub value: f64,
    pub observations_consumed: u32,
}

impl ScoreDelta {
    /// Build a `ScoreDelta` from a non-negative finite value, clamping at
    /// `MAX_FEED_DELTA`. Non-finite or negative inputs map to a zero delta;
    /// callers cannot use `ScoreDelta` to subtract from a score.
    #[must_use]
    pub fn from_value(feed_id: &'static str, value: f64, observations_consumed: u32) -> Self {
        let clamped = if value.is_finite() && value > 0.0 {
            value.min(MAX_FEED_DELTA)
        } else {
            0.0
        };
        Self {
            feed_id,
            value: clamped,
            observations_consumed,
        }
    }

    /// Construct a zero delta. Used by feeds that received an empty
    /// observation set; the empty fallback is for unit-test isolation
    /// only, production runs always have non-empty inputs.
    #[must_use]
    pub fn zero(feed_id: &'static str) -> Self {
        Self {
            feed_id,
            value: 0.0,
            observations_consumed: 0,
        }
    }
}

/// Deterministic mapping from an observation to a score delta.
///
/// Implementations must be pure: same observation in, same delta out. The
/// trait surface is intentionally synchronous and `&self`-only because feeds
/// are value types that should be cheap to construct, share, and reproduce in
/// the audit doc.
pub trait ReputationFeed {
    /// Caller-provided observation type. The two shipped feeds use thin
    /// structs (one for arena survival rounds, one for cross-provider
    /// equality outcomes) so the input shapes can evolve independently of
    /// the trait.
    type Observation;

    /// Stable feed identifier. The string is embedded in `ScoreDelta`
    /// outputs so the audit doc can attribute deltas back to the feed.
    fn feed_id(&self) -> &'static str;

    /// Deterministic delta function. Implementations must return a delta in
    /// `[0.0, MAX_FEED_DELTA]`; the trait will not validate this, but the
    /// monotonicity property test in `tests/feed_monotonicity.rs` covers
    /// every shipped feed.
    fn observe(&self, observation: &Self::Observation) -> ScoreDelta;
}

/// Compose feed deltas into a single numeric score in `[0.0, MAX_FEED_DELTA]`.
///
/// Composition is the per-feed maximum, not the sum: a single feed dominating
/// the floor would otherwise let a publisher whose only signal is arena
/// survival reach the highest tier. Capping at the per-feed maximum keeps the
/// `tier_3` requirement (the threshold table) satisfiable only when every
/// feed independently clears its bar.
///
/// Returns `None` when the slice is empty so callers can distinguish
/// "no signal" from "zero signal".
#[must_use]
pub fn compose_deltas(deltas: &[ScoreDelta]) -> Option<f64> {
    if deltas.is_empty() {
        return None;
    }
    let mut max_value = 0.0_f64;
    for delta in deltas {
        if delta.value > max_value {
            max_value = delta.value;
        }
    }
    Some(max_value.min(MAX_FEED_DELTA))
}

/// Composition that requires every feed in the input slice to clear an
/// independent threshold for the corresponding tier. This is the
/// monotonic-AND companion to `compose_deltas` and is used by the tier
/// threshold table in `tier.rs`: `tier_3` requires all feeds present and all
/// above their thresholds.
#[must_use]
pub fn min_delta(deltas: &[ScoreDelta]) -> Option<f64> {
    if deltas.is_empty() {
        return None;
    }
    let mut min_value = MAX_FEED_DELTA;
    for delta in deltas {
        if delta.value < min_value {
            min_value = delta.value;
        }
    }
    Some(min_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_value_clamps_above_max() {
        let delta = ScoreDelta::from_value("test", 2.5, 1);
        assert!((delta.value - MAX_FEED_DELTA).abs() < f64::EPSILON);
    }

    #[test]
    fn from_value_rejects_negative() {
        let delta = ScoreDelta::from_value("test", -0.1, 1);
        assert_eq!(delta.value, 0.0);
    }

    #[test]
    fn from_value_rejects_non_finite() {
        let delta = ScoreDelta::from_value("test", f64::NAN, 1);
        assert_eq!(delta.value, 0.0);
        let delta = ScoreDelta::from_value("test", f64::INFINITY, 1);
        assert_eq!(delta.value, 0.0);
    }

    #[test]
    fn compose_deltas_empty_is_none() {
        assert_eq!(compose_deltas(&[]), None);
    }

    #[test]
    fn compose_deltas_returns_max() {
        let deltas = [
            ScoreDelta::from_value("a", 0.1, 1),
            ScoreDelta::from_value("b", 0.7, 1),
            ScoreDelta::from_value("c", 0.3, 1),
        ];
        let composed = compose_deltas(&deltas);
        assert!(composed.is_some());
        let value = composed.unwrap_or(0.0);
        assert!((value - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn min_delta_empty_is_none() {
        assert_eq!(min_delta(&[]), None);
    }

    #[test]
    fn min_delta_returns_min() {
        let deltas = [
            ScoreDelta::from_value("a", 0.4, 1),
            ScoreDelta::from_value("b", 0.7, 1),
        ];
        let value = min_delta(&deltas).unwrap_or(MAX_FEED_DELTA);
        assert!((value - 0.4).abs() < f64::EPSILON);
    }
}
