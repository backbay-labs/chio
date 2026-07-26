#[path = "dst/support.rs"]
mod support;

use std::collections::HashSet;

use serde::Deserialize;
use support::{
    assert_wrapped_budget_hold_sweep, assert_wrapped_budget_replay_outcome,
    run_child_flush_mutation, run_crash_reopen, run_episode, CrashBoundary, EpisodeClass,
};

const FIXED_SEEDS: &str = include_str!("dst/seeds.toml");
const REGRESSIONS: &str = include_str!("dst/dst-regressions.toml");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedCorpus {
    schema: String,
    seeds: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegressionCorpus {
    schema: String,
    child_receipt_flush_seed: u64,
}

fn fixed_seeds() -> Result<Vec<u64>, String> {
    let corpus: SeedCorpus =
        toml::from_str(FIXED_SEEDS).map_err(|error| format!("parse fixed seeds: {error}"))?;
    if corpus.schema != "chio.dst.seeds.v1" {
        return Err(format!("unexpected seed schema {}", corpus.schema));
    }
    if corpus.seeds.len() != 64 {
        return Err(format!(
            "fixed DST corpus must contain exactly 64 seeds, found {}",
            corpus.seeds.len()
        ));
    }
    let unique = corpus.seeds.iter().copied().collect::<HashSet<_>>();
    if unique.len() != corpus.seeds.len() {
        return Err("fixed DST corpus contains duplicate seeds".to_string());
    }
    Ok(corpus.seeds)
}

fn run_or_panic(seed: u64) -> EpisodeClass {
    match run_episode(seed) {
        Ok(summary) => summary.plan.class,
        Err(error) => {
            let plan = support::FaultPlan::from_seed(seed);
            panic!(
                "DST episode failed; replay with `bash scripts/run-dst.sh --lane replay --seed {seed}`; seed={seed}; plan={plan:?}; error={error}"
            );
        }
    }
}

#[test]
fn dst_fixed_seed_corpus() {
    let seeds = match fixed_seeds() {
        Ok(seeds) => seeds,
        Err(error) => panic!("{error}"),
    };
    let classes = seeds.into_iter().map(run_or_panic).collect::<HashSet<_>>();
    let expected = HashSet::from([
        EpisodeClass::PreDispatchClean,
        EpisodeClass::PreDispatchAdmissionReleaseFault,
        EpisodeClass::PreDispatchBudgetReversalFault,
        EpisodeClass::PostDispatchClean,
        EpisodeClass::PostDispatchLongServerWait,
        EpisodeClass::CompleteAllow,
        EpisodeClass::CompleteReceiptFault,
        EpisodeClass::BudgetAdmissionFault,
    ]);
    assert_eq!(classes, expected, "fixed corpus lost an episode class");
}

#[test]
fn dst_sqlite_crash_reopen_boundaries() {
    for boundary in [
        CrashBoundary::BeforeReceiptPersist,
        CrashBoundary::AfterReceiptPersist,
    ] {
        if let Err(error) = run_crash_reopen(boundary) {
            panic!("DST crash/reopen failed at {boundary:?}: {error}");
        }
    }
}

#[test]
fn dst_child_receipt_flush_regression_is_killed() {
    let regression: RegressionCorpus = match toml::from_str(REGRESSIONS) {
        Ok(regression) => regression,
        Err(error) => panic!("parse DST regressions: {error}"),
    };
    assert_eq!(regression.schema, "chio.dst.regressions.v1");
    let seed = regression.child_receipt_flush_seed;
    if let Err(error) = run_child_flush_mutation(seed, false) {
        panic!("unmodified child receipt flush failed: {error}");
    }
    let mutation = run_child_flush_mutation(seed, true);
    assert!(
        mutation
            .as_ref()
            .is_err_and(|error| error.contains("ChildReceiptsFlushed violated")),
        "deliberate child-receipt flush omission survived the oracle: {mutation:?}"
    );
}

#[test]
fn dst_budget_wrapper_preserves_replay_outcome() {
    if let Err(error) = assert_wrapped_budget_replay_outcome() {
        panic!("DST budget wrapper replay check failed: {error}");
    }
    if let Err(error) = assert_wrapped_budget_hold_sweep() {
        panic!("DST budget wrapper hold-sweep check failed: {error}");
    }
}

#[test]
#[ignore = "10,000-episode nightly deterministic sweep"]
fn dst_wide_sweep() {
    let episodes = std::env::var("CHIO_DST_EPISODES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10_000);
    assert_eq!(
        episodes, 10_000,
        "wide lane is closed to exactly 10,000 episodes"
    );
    for seed in 0..episodes {
        let _ = run_or_panic(0xd57_0000 + seed);
    }
}

#[test]
#[ignore = "requires CHIO_DST_SEED and the replay runner"]
fn dst_replay_seed() {
    let seed = match std::env::var("CHIO_DST_SEED") {
        Ok(value) => match value.parse::<u64>() {
            Ok(seed) => seed,
            Err(error) => panic!("CHIO_DST_SEED is not a u64: {error}"),
        },
        Err(error) => panic!("CHIO_DST_SEED is required: {error}"),
    };
    let plan = support::FaultPlan::from_seed(seed);
    println!("DST replay seed={seed} plan={plan:?}");
    let _ = run_or_panic(seed);
}
