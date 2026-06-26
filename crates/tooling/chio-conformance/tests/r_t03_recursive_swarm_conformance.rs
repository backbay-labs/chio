#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::error::Error;

use chio_core::crypto::PublicKey;
use chio_swarm_authority::{
    verify_swarm_authority_bundle, SwarmAuthorityBundle, SwarmBudgetPool, SwarmContinuationToken,
    SwarmDelegationWitnessChain, SwarmJoinReceipt, SwarmRevocationEpoch, SwarmRoutePlanReceipt,
    SwarmTaskGraph, SwarmTerminalGraphReceipt,
};
use proptest::prelude::*;

const NOW_UNIX_MS: u64 = 1_800_000_001_000;

fn fixture_artifact<T>(bytes: &str) -> Result<T, serde_json::Error>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(bytes)
}

fn recursive_swarm_bundle() -> Result<SwarmAuthorityBundle, Box<dyn Error>> {
    Ok(SwarmAuthorityBundle {
        task_graph: fixture_artifact::<SwarmTaskGraph>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/task-graph.json"
        ))?,
        continuation_tokens: vec![
            fixture_artifact::<SwarmContinuationToken>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/continuation-child-a.json"
            ))?,
            fixture_artifact::<SwarmContinuationToken>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/continuation-child-b.json"
            ))?,
            fixture_artifact::<SwarmContinuationToken>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/continuation-child-c.json"
            ))?,
        ],
        witness_chains: vec![
            fixture_artifact::<SwarmDelegationWitnessChain>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/witness-child-a.json"
            ))?,
            fixture_artifact::<SwarmDelegationWitnessChain>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/witness-child-b.json"
            ))?,
            fixture_artifact::<SwarmDelegationWitnessChain>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/witness-child-c.json"
            ))?,
        ],
        join_receipts: vec![fixture_artifact::<SwarmJoinReceipt>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/join-receipt.json"
        ))?],
        route_plan_receipts: vec![
            fixture_artifact::<SwarmRoutePlanReceipt>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/route-child-a.json"
            ))?,
            fixture_artifact::<SwarmRoutePlanReceipt>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/route-child-b.json"
            ))?,
            fixture_artifact::<SwarmRoutePlanReceipt>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/route-child-c.json"
            ))?,
        ],
        budget_pool: fixture_artifact::<SwarmBudgetPool>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/budget-pool.json"
        ))?,
        revocation_epoch: fixture_artifact::<SwarmRevocationEpoch>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/revocation-epoch.json"
        ))?,
        terminal_receipts: vec![fixture_artifact::<SwarmTerminalGraphReceipt>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/terminal-graph-receipt.json"
        ))?],
        now_unix_ms: NOW_UNIX_MS,
    })
}

fn trusted_witness_keys(bundle: &SwarmAuthorityBundle) -> Result<Vec<PublicKey>, Box<dyn Error>> {
    let issuer = bundle
        .witness_chains
        .first()
        .and_then(|chain| chain.hops.first())
        .map(|hop| hop.issuer.as_str())
        .ok_or("fixture witness issuer missing")?;
    let key_hex = issuer
        .strip_prefix("did:chio:")
        .ok_or("fixture witness issuer is not did:chio")?;
    Ok(vec![PublicKey::from_hex(key_hex)?])
}

#[test]
fn r_t03_recursive_swarm_conformance_accepts_signed_fixture() -> Result<(), Box<dyn Error>> {
    let bundle = recursive_swarm_bundle()?;
    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys(&bundle)?)?;

    assert_eq!(report.verdict, "verified");
    assert_eq!(report.graph_id, "swarm-graph-proof-valid");
    Ok(())
}

fn mutate_recursive_bundle(bundle: &mut SwarmAuthorityBundle, case: u8) -> &'static str {
    match case {
        0 => {
            bundle.task_graph.max_fanout = 0;
            "max_fanout"
        }
        1 => {
            bundle.budget_pool.total_units = 1;
            "budget allocations exceed pool total"
        }
        2 => {
            bundle.revocation_epoch.valid_until_unix_ms = bundle.now_unix_ms;
            "revocation epoch is stale"
        }
        3 => {
            bundle.route_plan_receipts[0].bridge_id = "a2a".to_string();
            "route-plan selected route bridge mismatch"
        }
        4 => {
            bundle.budget_pool.allocations[0].max_units += 1;
            bundle.budget_pool.allocations[0].active_units += 1;
            "terminal budget rollup mismatch"
        }
        _ => {
            bundle.task_graph.nodes[1].parent_task_id = Some("task-child-b".to_string());
            "task parent edge missing"
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn r_t03_recursive_swarm_conformance_rejects_generated_malformed_cases(case in 0_u8..6) {
        let mut bundle = recursive_swarm_bundle()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let trusted_keys = trusted_witness_keys(&bundle)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let expected = mutate_recursive_bundle(&mut bundle, case);

        let error = match verify_swarm_authority_bundle(&bundle, &trusted_keys) {
            Ok(report) => {
                return Err(TestCaseError::fail(format!(
                    "malformed recursive swarm bundle verified unexpectedly: {report:#?}"
                )));
            }
            Err(error) => error,
        };
        prop_assert!(
            error.to_string().contains(expected),
            "expected generated case {case} to reject with {expected}, got {error}"
        );
    }
}
