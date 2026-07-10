//! Reputation tier mapping.
//!
//! `ReputationTier` is the discrete output the marketplace consumes. The
//! threshold table in this module maps composed feed deltas to one of four
//! tiers (`tier_0` through `tier_3`). Tiers gate marketplace discovery
//! visibility; cosign verify gates publication. A publisher whose tier is
//! below a guard's `reputation_floor` does not see the guard in
//! `chio guard market list` outputs but is not blocked from installing a
//! guard whose floor is `tier_0` (the default for manifests without an
//! explicit floor).
//!
//! Threshold table:
//!
//! - `tier_0`: any composed score (the default tier; no positive evidence
//!   required).
//! - `tier_1`: composed score >= `TIER_1_THRESHOLD` (0.50).
//! - `tier_2`: composed score >= `TIER_2_THRESHOLD` (0.75).
//! - `tier_3`: composed score >= `TIER_3_THRESHOLD` (0.90) AND every
//!   shipped feed independently clears `TIER_3_PER_FEED_THRESHOLD`
//!   (0.80). The per-feed floor is the AND-companion to the composed
//!   score: a publisher whose only signal is one feed cannot reach
//!   `tier_3` without independent evidence from the other feed (Sybil
//!   resistance).
//!
//! Thresholds are policy-loaded only by way of the `ReputationConfig`
//! values in `model.rs`. The constants are hard-coded so the audit doc
//! can record a stable tier distribution.

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
/// highest tier; this is the Sybil-resistance mitigation: a flood of
/// arena rounds alone cannot promote a publisher past `tier_2`.
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
    /// Stable string identifier matching the serde rename. Keep these
    /// strings byte-stable.
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
/// The mapping is monotonic in the input deltas (verified by a property test):
/// raising any single delta never lowers the tier. Empty input returns
/// `tier_0` (no signal -> default tier).
///
/// `tier_3` requires composed score AND independent evidence from at
/// least two distinct feeds (counted by `feed_id`, not slice length).
/// Submitting multiple deltas from the same feed cannot satisfy the
/// Sybil-resistance gate: a flood of arena rounds alone stays at
/// `tier_2` even when each individual delta clears the per-feed floor.
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

    if qualifies_for_tier_3(deltas, composed, per_feed_min) {
        ReputationTier::Tier3
    } else if composed >= TIER_2_THRESHOLD {
        ReputationTier::Tier2
    } else if composed >= TIER_1_THRESHOLD {
        ReputationTier::Tier1
    } else {
        ReputationTier::Tier0
    }
}

/// Count the number of distinct `feed_id` values in `deltas`.
///
/// O(n^2) in the worst case but bounded by the small feed catalog, so
/// a linear scan over a `Vec` is preferable to allocating a hash set
/// for the typical 1-3 element input.
fn distinct_feed_count(deltas: &[ScoreDelta]) -> usize {
    let mut seen: Vec<&'static str> = Vec::with_capacity(deltas.len());
    for delta in deltas {
        let id = delta.feed_id;
        if !seen.contains(&id) {
            seen.push(id);
        }
    }
    seen.len()
}

fn qualifies_for_tier_3(deltas: &[ScoreDelta], composed: f64, per_feed_min: f64) -> bool {
    composed >= TIER_3_THRESHOLD
        && per_feed_min >= TIER_3_PER_FEED_THRESHOLD
        && distinct_feed_count(deltas) >= 2
}

#[cfg(test)]
mod tier3_gate_tests {
    use super::*;

    #[test]
    fn tier3_helper_requires_score_floor_per_feed_floor_and_two_feeds() {
        let two_strong = [
            ScoreDelta::from_value("feed_a", 0.91, 1),
            ScoreDelta::from_value("feed_b", 0.82, 1),
        ];
        assert!(qualifies_for_tier_3(&two_strong, 0.91, 0.82));

        assert!(!qualifies_for_tier_3(&two_strong, 0.89, 0.82));
        assert!(!qualifies_for_tier_3(&two_strong, 0.91, 0.79));

        let one_feed = [
            ScoreDelta::from_value("feed_a", 0.95, 1),
            ScoreDelta::from_value("feed_a", 0.94, 1),
        ];
        assert!(!qualifies_for_tier_3(&one_feed, 0.95, 0.94));
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

/// Saturation cap on the composed score; equal to `MAX_FEED_DELTA`.
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
        // tier_3 requires evidence from >= 2 distinct feeds because
        // the per-feed AND condition is meaningful only across multiple
        // feeds.
        let deltas = [ScoreDelta::from_value("a", 0.99, 1)];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier2);
    }

    #[test]
    fn multiple_deltas_same_feed_cannot_reach_tier_3() {
        // Two strong deltas from the same feed_id must NOT promote a
        // publisher to tier_3; the gate counts distinct feeds, not
        // slice length.
        let deltas = [
            ScoreDelta::from_value("arena_survival", 0.95, 1),
            ScoreDelta::from_value("arena_survival", 0.92, 1),
        ];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier2);
    }

    #[test]
    fn three_deltas_two_feeds_reach_tier_3() {
        // Two arena_survival deltas plus one cross_provider_equality
        // delta: distinct count is 2, composed >= 0.90, per-feed min
        // >= 0.80, so tier_3 is reached. This documents that adding
        // extra observations from the same feed neither helps nor
        // hurts the distinct-feed gate.
        let deltas = [
            ScoreDelta::from_value("arena_survival", 0.92, 1),
            ScoreDelta::from_value("arena_survival", 0.90, 1),
            ScoreDelta::from_value("cross_provider_equality", 0.85, 1),
        ];
        assert_eq!(tier_from_deltas(&deltas), ReputationTier::Tier3);
    }

    #[test]
    fn distinct_feed_count_dedupes_repeated_feed_ids() {
        let deltas = [
            ScoreDelta::from_value("a", 0.5, 1),
            ScoreDelta::from_value("a", 0.6, 1),
            ScoreDelta::from_value("b", 0.7, 1),
            ScoreDelta::from_value("a", 0.8, 1),
        ];
        assert_eq!(distinct_feed_count(&deltas), 2);
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
