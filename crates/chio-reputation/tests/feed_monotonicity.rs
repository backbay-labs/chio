//! Monotonicity property test for the bundled `ReputationFeed`
//! implementations.
//!
//! Asserts feed composition is monotonic in observed signal: more arena
//! survival never decreases score; more equality never decreases score.
//!
//! These tests assert the strict invariant for each shipped feed and
//! the aggregated invariant on `tier_from_deltas`. The proptest cases
//! are deterministic (`ProptestConfig::with_cases`) so the audit doc
//! records a stable count.

use chio_reputation::feeds::arena_survival::{
    ArenaRoundOutcome, ArenaRoundsObservation, ArenaSurvivalFeed,
};
use chio_reputation::feeds::cross_provider_equality::{
    CrossProviderEqualityFeed, VerdictCaseOutcome, VerdictMatrixObservation,
};
use chio_reputation::{tier_from_deltas, ReputationFeed, ReputationTier, ScoreDelta};
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 256;

fn arena_outcome_strategy() -> impl Strategy<Value = ArenaRoundOutcome> {
    (0u32..1024u32).prop_flat_map(|entered| {
        (Just(entered), 0u32..=entered)
            .prop_map(|(entered, survived)| ArenaRoundOutcome { entered, survived })
    })
}

fn arena_observation_strategy() -> impl Strategy<Value = ArenaRoundsObservation> {
    prop::collection::vec(arena_outcome_strategy(), 0..16)
        .prop_map(|rounds| ArenaRoundsObservation { rounds })
}

fn verdict_outcome_strategy() -> impl Strategy<Value = VerdictCaseOutcome> {
    (0u32..16u32).prop_flat_map(|providers| {
        (Just(providers), 0u32..=providers.max(1)).prop_map(|(providers, unique)| {
            VerdictCaseOutcome {
                providers_observed: providers,
                unique_verdicts: unique,
            }
        })
    })
}

fn verdict_observation_strategy() -> impl Strategy<Value = VerdictMatrixObservation> {
    prop::collection::vec(verdict_outcome_strategy(), 0..16)
        .prop_map(|cases| VerdictMatrixObservation { cases })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Adding any number of additional fully-survived rounds (entered ==
    /// survived > 0) to an arena observation never decreases the
    /// resulting score delta. This is the canonical statement of "more
    /// arena survival never decreases score."
    #[test]
    fn arena_survival_added_full_rounds_are_monotonic(
        base in arena_observation_strategy(),
        additions in 0u32..32u32,
    ) {
        let feed = ArenaSurvivalFeed::new();
        let baseline = feed.observe(&base);

        let mut extended = base.clone();
        for _ in 0..additions {
            extended.rounds.push(ArenaRoundOutcome { entered: 4, survived: 4 });
        }
        let after = feed.observe(&extended);

        prop_assert!(
            after.value + 1e-12 >= baseline.value,
            "arena survival decreased after adding fully-survived rounds: baseline={} after={}",
            baseline.value,
            after.value,
        );
    }

    /// Per-outcome: raising the survived count on a single existing
    /// outcome never decreases the score delta.
    #[test]
    fn arena_survival_raising_survived_is_monotonic(
        base in arena_observation_strategy(),
        index in 0usize..16usize,
    ) {
        if base.rounds.is_empty() {
            return Ok(());
        }
        let feed = ArenaSurvivalFeed::new();
        let baseline = feed.observe(&base);

        let mut raised = base.clone();
        let target_index = index % raised.rounds.len();
        let outcome = raised.rounds[target_index];
        let new_survived = outcome.entered;
        raised.rounds[target_index] = ArenaRoundOutcome {
            entered: outcome.entered,
            survived: new_survived,
        };
        let after = feed.observe(&raised);

        prop_assert!(
            after.value + 1e-12 >= baseline.value,
            "raising survived count decreased the score: baseline={} after={}",
            baseline.value,
            after.value,
        );
    }

    /// Adding any number of additional unanimous-agreement cases (with
    /// at least two providers reporting and unique_verdicts == 1) to a
    /// verdict-matrix observation never decreases the resulting score
    /// delta. This is the canonical statement of "more equality never
    /// decreases score."
    #[test]
    fn cross_provider_equality_added_agreement_cases_are_monotonic(
        base in verdict_observation_strategy(),
        additions in 0u32..32u32,
    ) {
        let feed = CrossProviderEqualityFeed::new();
        let baseline = feed.observe(&base);

        let mut extended = base.clone();
        for _ in 0..additions {
            extended.cases.push(VerdictCaseOutcome {
                providers_observed: 3,
                unique_verdicts: 1,
            });
        }
        let after = feed.observe(&extended);

        prop_assert!(
            after.value + 1e-12 >= baseline.value,
            "cross-provider equality decreased after adding agreement cases: baseline={} after={}",
            baseline.value,
            after.value,
        );
    }

    /// Per-case: replacing a disagreement (unique_verdicts > 1) with a
    /// unanimous-agreement case never decreases the score delta.
    #[test]
    fn cross_provider_equality_replacing_disagreement_is_monotonic(
        base in verdict_observation_strategy(),
        index in 0usize..16usize,
    ) {
        if base.cases.is_empty() {
            return Ok(());
        }
        let feed = CrossProviderEqualityFeed::new();
        let baseline = feed.observe(&base);

        let mut replaced = base.clone();
        let target = index % replaced.cases.len();
        let case = replaced.cases[target];
        if case.providers_observed >= 2 && case.unique_verdicts > 1 {
            replaced.cases[target] = VerdictCaseOutcome {
                providers_observed: case.providers_observed,
                unique_verdicts: 1,
            };
        }
        let after = feed.observe(&replaced);

        prop_assert!(
            after.value + 1e-12 >= baseline.value,
            "replacing disagreement with agreement decreased the score: baseline={} after={}",
            baseline.value,
            after.value,
        );
    }

    /// Aggregate invariant: tier_from_deltas is monotonic when any
    /// single delta is raised. Raising one feed's delta cannot lower
    /// the resulting tier.
    #[test]
    fn tier_is_monotonic_when_a_single_delta_is_raised(
        a in 0.0_f64..=1.0_f64,
        b in 0.0_f64..=1.0_f64,
        raise_index in 0u8..2u8,
        delta_increase in 0.0_f64..=0.5_f64,
    ) {
        let baseline_deltas = [
            ScoreDelta::from_value("a", a, 1),
            ScoreDelta::from_value("b", b, 1),
        ];
        let baseline_tier = tier_from_deltas(&baseline_deltas);

        let raised_a = (a + if raise_index == 0 { delta_increase } else { 0.0 }).min(1.0);
        let raised_b = (b + if raise_index == 1 { delta_increase } else { 0.0 }).min(1.0);
        let raised_deltas = [
            ScoreDelta::from_value("a", raised_a, 1),
            ScoreDelta::from_value("b", raised_b, 1),
        ];
        let raised_tier = tier_from_deltas(&raised_deltas);

        prop_assert!(
            raised_tier >= baseline_tier,
            "raising a single delta lowered the tier: baseline={:?} raised={:?}",
            baseline_tier,
            raised_tier,
        );
    }

    /// tier_3 must require distinct feed evidence. Repeating the same
    /// `feed_id` with strong values must NEVER reach tier_3, regardless
    /// of how many copies are submitted. This is the Sybil-resistance
    /// gate the audit doc promises.
    #[test]
    fn same_feed_id_repeated_never_reaches_tier_3(
        first_value in 0.80_f64..=1.0_f64,
        second_value in 0.80_f64..=1.0_f64,
        third_value in 0.80_f64..=1.0_f64,
    ) {
        let deltas = [
            ScoreDelta::from_value("arena_survival", first_value, 1),
            ScoreDelta::from_value("arena_survival", second_value, 1),
            ScoreDelta::from_value("arena_survival", third_value, 1),
        ];
        let tier = tier_from_deltas(&deltas);
        prop_assert!(
            tier < ReputationTier::Tier3,
            "tier_3 reached with one feed_id only: tier={:?}",
            tier,
        );
    }
}

/// Empty inputs MUST yield tier_0; a zero-delta fallback MUST NOT produce a positive default tier.
#[test]
fn empty_inputs_always_tier_0() {
    let arena_feed = ArenaSurvivalFeed::new();
    let cross_feed = CrossProviderEqualityFeed::new();
    let arena_delta = arena_feed.observe(&ArenaRoundsObservation::default());
    let cross_delta = cross_feed.observe(&VerdictMatrixObservation::default());
    let tier = tier_from_deltas(&[arena_delta, cross_delta]);
    assert_eq!(tier, ReputationTier::Tier0);
}
