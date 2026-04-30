//! Reputation tier mapping.
//!
//! `ReputationTier` is the discrete output the marketplace consumes. The
//! threshold table in this module maps composed feed deltas to one of four
//! tiers (`tier_0` through `tier_3`). Tiers gate marketplace discovery
//! visibility; cosign verify (trajectory-1 M06) gates publication. A
//! publisher whose tier is below a guard's `reputation_floor` does not see
//! the guard in `arc guard market list` outputs but is not blocked from
//! installing a guard whose floor is `tier_0` (the default for manifests
//! without an explicit floor).
//!
//! Threshold table (per ticket M09.P3.T4):
//!
//! - `tier_0`: any composed score (the default tier; no positive evidence
//!   required).
//! - `tier_1`: composed score >= `TIER_1_THRESHOLD` (0.50).
//! - `tier_2`: composed score >= `TIER_2_THRESHOLD` (0.75).
//! - `tier_3`: composed score >= `TIER_3_THRESHOLD` (0.90) AND every
//!   shipped feed independently clears `TIER_3_PER_FEED_THRESHOLD`
//!   (0.80). The per-feed floor is the AND-companion to the composed
//!   score: a publisher whose only signal is one feed (per the M09
//!   narrative's Sybil mitigation in "Risks and mitigations") cannot
//!   reach `tier_3` without independent evidence from the other feed.
//!
//! Thresholds are policy-loaded only by way of the `ReputationConfig`
//! values in `model.rs`. For now the constants are hard-coded so the
//! audit doc can record a stable tier distribution on the M04 corpus
//! (M09.P3.T6).

use serde::{Deserialize, Serialize};

use crate::feed::{compose_deltas, min_delta, ScoreDelta, MAX_FEED_DELTA};

/// Composed-score floor for `tier_1`.
pub const TIER_1_THRESHOLD: f64 = 0.50;

/// Composed-score floor for `tier_2`.
pub const TIER_2_THRESHOLD: f64 = 0.75;

/// Composed-score floor for `tier_3`.
pub const TIER_3_THRESHOLD: f64 = 0.90;

/// Per-feed minimum delta required for `tier_3`. Every shipped feed
/// MUST clear this value independently for the publisher to reach the
/// highest tier; this is the M09 narrative's Sybil-resistance
/// mitigation: a flood of arena rounds alone cannot promote a
/// publisher past `tier_2`.
pub const TIER_3_PER_FEED_THRESHOLD: f64 = 0.80;

/// Discrete reputation tier surfaced to the marketplace.
///
/// Tiers are intentionally coarse so the marketplace UI and the audit
/// doc can render a stable distribution histogram. `tier_3` is the only
/// tier with an AND-style composition: composed score AND per-feed
/// floors. Lower tiers use only the composed score.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ReputationTier {
    /// Default tier. No positive evidence required. Applied to manifests
    /// without an explicit `reputation_floor` field.
    #[default]
    Tier0,
    /// Composed score >= `TIER_1_THRESHOLD`.
    Tier1,
    /// Composed score >= `TIER_2_THRESHOLD`.
    Tier2,
    /// Composed score >= `TIER_3_THRESHOLD` and every shipped feed
    /// independently clears `TIER_3_PER_FEED_THRESHOLD`.
    Tier3,
}

impl ReputationTier {
    /// Stable string identifier matching the serde rename. The grep
    /// gate on M09.P3.T4 looks for `tier_3` in this module's source;
    /// keep these strings byte-stable.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tier0 => "tier_0",
            Self::Tier1 => "tier_1",
            Self::Tier2 => "tier_2",
            Self::Tier3 => "tier_3",
        }
    }
}

/// Map a slice of feed deltas to a `ReputationTier`.
///
/// The mapping is monotonic in the input deltas (P3.T5 property test):
/// raising any single delta never lowers the tier. Empty input returns
/// `tier_0` (no signal -> default tier).
#[must_use]
pub fn tier_from_deltas(deltas: &[ScoreDelta]) -> ReputationTier {
    let composed = match compose_deltas(deltas) {
        Some(value) => value,
        None => return ReputationTier::Tier0,
    };
    let per_feed_min = match min_delta(deltas) {
        Some(value) => value,
        None => return ReputationTier::Tier0,
    };

    if composed >= TIER_3_THRESHOLD
        && per_feed_min >= TIER_3_PER_FEED_THRESHOLD
        && deltas.len() >= 2
    {
        ReputationTier::Tier3
    } else if composed >= TIER_2_THRESHOLD {
        ReputationTier::Tier2
    } else if composed >= TIER_1_THRESHOLD {
        ReputationTier::Tier1
    } else {
        ReputationTier::Tier0
    }
}

/// Composed-score floor for a tier. Returns `MAX_FEED_DELTA + 1.0` for
/// unreachable above-tier_3 cases so callers comparing inclusive
/// thresholds always behave correctly.
#[must_use]
pub fn tier_threshold(tier: ReputationTier) -> f64 {
    match tier {
        ReputationTier::Tier0 => 0.0,
        ReputationTier::Tier1 => TIER_1_THRESHOLD,
        ReputationTier::Tier2 => TIER_2_THRESHOLD,
        ReputationTier::Tier3 => TIER_3_THRESHOLD,
    }
}

/// Whether `tier` satisfies the floor `required`. Used by the
/// marketplace discovery path to filter guards by tenant reputation
/// tier without leaking thresholds to the manifest schema.
#[must_use]
pub fn satisfies_floor(tier: ReputationTier, required: ReputationTier) -> bool {
    tier >= required
}

/// Sentinel constant used to remind readers that
/// `MAX_FEED_DELTA` is the saturation cap on the composed score.
pub const MAX_COMPOSED_SCORE: f64 = MAX_FEED_DELTA;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_strings_are_stable() {
        assert_eq!(ReputationTier::Tier0.as_str(), "tier_0");
        assert_eq!(ReputationTier::Tier1.as_str(), "tier_1");
        assert_eq!(ReputationTier::Tier2.as_str(), "tier_2");
        assert_eq!(ReputationTier::Tier3.as_str(), "tier_3");
    }

    #[test]
    fn empty_deltas_default_to_tier_0() {
        assert_eq!(tier_from_deltas(&[]), ReputationTier::Tier0);
    }

    #[test]
    fn below_tier_1_is_tier_0() {
        let deltas = [
            ScoreDelta::from_value("a", 0.4, 1),
            ScoreDelta::from_value("b", 0.49, 1),
        ];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier0);
    }

    #[test]
    fn at_tier_1_threshold() {
        let deltas = [
            ScoreDelta::from_value("a", TIER_1_THRESHOLD, 1),
            ScoreDelta::from_value("b", 0.0, 1),
        ];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier1);
    }

    #[test]
    fn at_tier_2_threshold() {
        let deltas = [
            ScoreDelta::from_value("a", TIER_2_THRESHOLD, 1),
            ScoreDelta::from_value("b", 0.0, 1),
        ];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier2);
    }

    #[test]
    fn one_strong_feed_alone_cannot_reach_tier_3() {
        // composed score reaches tier_3 because compose_deltas returns
        // the max, but min_delta is below per-feed threshold so the AND
        // condition fails. Tier collapses back to tier_2.
        let deltas = [
            ScoreDelta::from_value("a", 0.95, 1),
            ScoreDelta::from_value("b", 0.10, 1),
        ];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier2);
    }

    #[test]
    fn two_strong_feeds_reach_tier_3() {
        let deltas = [
            ScoreDelta::from_value("a", 0.92, 1),
            ScoreDelta::from_value("b", 0.85, 1),
        ];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier3);
    }

    #[test]
    fn single_feed_input_cannot_reach_tier_3() {
        // tier_3 requires deltas.len() >= 2 because the per-feed AND
        // condition is meaningful only across multiple feeds.
        let deltas = [ScoreDelta::from_value("a", 0.99, 1)];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier2);
    }

    #[test]
    fn satisfies_floor_is_transitive() {
        assert!(satisfies_floor(
            ReputationTier::Tier3,
            ReputationTier::Tier1
        ));
        assert!(satisfies_floor(
            ReputationTier::Tier1,
            ReputationTier::Tier1
        ));
        assert!(!satisfies_floor(
            ReputationTier::Tier1,
            ReputationTier::Tier2
        ));
    }

    #[test]
    fn tier_threshold_table_round_trip() {
        assert_eq!(tier_threshold(ReputationTier::Tier0), 0.0);
        assert_eq!(tier_threshold(ReputationTier::Tier1), TIER_1_THRESHOLD);
        assert_eq!(tier_threshold(ReputationTier::Tier2), TIER_2_THRESHOLD);
        assert_eq!(tier_threshold(ReputationTier::Tier3), TIER_3_THRESHOLD);
    }
}
