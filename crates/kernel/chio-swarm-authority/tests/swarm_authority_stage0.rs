use std::collections::BTreeMap;
use std::error::Error;

use chio_core_types::capability::attenuation::{compute_attenuation_witness, scope_hash};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_swarm_authority::{
    mint_swarm_continuation_token, mint_swarm_join_receipt, release_swarm_budget_fanin,
    reserve_swarm_budget_fanout, sign_swarm_continuation_token, sign_swarm_delegation_witness_hop,
    sign_swarm_join_receipt, sign_swarm_revocation_epoch, sign_swarm_route_plan_receipt,
    sign_swarm_task_graph, sign_swarm_terminal_graph_receipt, verify_swarm_authority_bundle,
    SwarmAuthorityBundle, SwarmBudgetAllocation, SwarmBudgetAllocationState,
    SwarmBudgetFanInReleaseRequest, SwarmBudgetFanoutAllocationRequest,
    SwarmBudgetFanoutReservationRequest, SwarmBudgetPool, SwarmContinuationMode,
    SwarmContinuationToken, SwarmContinuationTokenMintRequest, SwarmDelegationWitnessChain,
    SwarmDelegationWitnessHop, SwarmGraphEdge, SwarmGraphJoin, SwarmGraphNode,
    SwarmJoinParentReceipt, SwarmJoinReceipt, SwarmJoinReceiptMintRequest, SwarmRevocationEpoch,
    SwarmRoutePlanReceipt, SwarmTaskGraph, SwarmTerminalBudgetRollup, SwarmTerminalGraphReceipt,
    CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_SCHEMA, CHIO_SWARM_BUDGET_POOL_SCHEMA,
    CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA, CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA,
    CHIO_SWARM_JOIN_RECEIPT_SCHEMA, CHIO_SWARM_REVOCATION_EPOCH_SCHEMA,
    CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA, CHIO_SWARM_TASK_GRAPH_SCHEMA,
    CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA, CLAIM_SWARM_ATTENUATION_WITNESS_CHAIN_BOUND,
    CLAIM_SWARM_BUDGET_POOL_BOUND, CLAIM_SWARM_CONTINUATION_FRESH, CLAIM_SWARM_JOIN_RECEIPT_BOUND,
    CLAIM_SWARM_REVOCATION_EPOCH_BOUND, CLAIM_SWARM_ROUTE_PLAN_BOUND, CLAIM_SWARM_TASK_GRAPH_BOUND,
    CLAIM_SWARM_TERMINAL_GRAPH_RECEIPT_BOUND,
};
use proptest::prelude::*;

const NOW_UNIX_MS: u64 = 1_800_000_001_000;

#[test]
fn swarm_authority_stage0_verifies_valid_bundle() -> Result<(), Box<dyn Error>> {
    let bundle = sample_swarm_bundle()?;
    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;

    assert_eq!(report.schema, CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_SCHEMA);
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.graph_id, "swarm-graph-proof-valid");
    assert_eq!(report.task_count, 3);
    assert_eq!(report.continuation_count, 2);
    assert_eq!(report.join_count, 1);
    assert_eq!(report.route_count, 2);
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_TASK_GRAPH_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_CONTINUATION_FRESH.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_ATTENUATION_WITNESS_CHAIN_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_ROUTE_PLAN_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_JOIN_RECEIPT_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_BUDGET_POOL_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_REVOCATION_EPOCH_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_TERMINAL_GRAPH_RECEIPT_BOUND.to_string()));
    assert_eq!(report.hop_reports.len(), 2);
    for child_task_id in ["task-child-a", "task-child-b"] {
        let hop = report
            .hop_reports
            .iter()
            .find(|hop| hop.child_task_id == child_task_id)
            .ok_or("missing per-hop verifier report")?;
        assert!(hop.authority_verified);
        assert!(hop.attenuation_verified);
        assert!(hop.lineage_verified);
        assert!(hop.route_verified);
        assert!(hop.budget_verified);
        assert_eq!(hop.parent_task_id.as_deref(), Some("task-root"));
        assert_eq!(
            hop.continuation_token_id,
            format!("continuation-{}", child_task_id.trim_start_matches("task-"))
        );
        assert_eq!(
            hop.witness_chain_id.as_deref(),
            Some(format!("witness-{}", child_task_id.trim_start_matches("task-")).as_str())
        );
    }
    Ok(())
}

#[test]
fn swarm_authority_mints_signed_continuation_token() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    let graph_sha256 = sha256_hex(&canonical_json_bytes(&bundle.task_graph)?);
    let minted = mint_swarm_continuation_token(
        SwarmContinuationTokenMintRequest {
            token_id: "continuation-child-a".to_string(),
            graph_id: "swarm-graph-proof-valid".to_string(),
            child_task_id: "task-child-a".to_string(),
            parent_task_id: Some("task-root".to_string()),
            join_receipt_id: None,
            parent_receipt_ids: vec!["receipt-root".to_string()],
            graph_sha256,
            route_plan_receipt_id: "route-child-a".to_string(),
            budget_allocation_id: "budget-child-a".to_string(),
            witness_chain_ref: Some(bundle.witness_chains[0].chain_id.clone()),
            witness_chain_sha256: Some(canonical_hash(&bundle.witness_chains[0])?),
            revocation_epoch_ref: "revocation-epoch-swarm-valid".to_string(),
            revocation_epoch_root_hash: bundle.revocation_epoch.root_hash.clone(),
            session_anchor_ref: "session-anchor-swarm-valid".to_string(),
            nonce: "nonce-task-child-a".to_string(),
            mode: SwarmContinuationMode::SingleUse,
            issued_at_unix_ms: NOW_UNIX_MS - 1_000,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        },
        &witness_keypair(),
    )?;
    assert_eq!(minted.issuer, witness_issuer());
    assert!(!minted.signature.is_empty());

    bundle.continuation_tokens[0] = minted;
    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;

    assert_eq!(report.verdict, "verified");
    Ok(())
}

#[test]
fn swarm_authority_mints_signed_join_receipt() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    let minted = mint_swarm_join_receipt(
        SwarmJoinReceiptMintRequest {
            join_id: "join-child-results".to_string(),
            graph_id: "swarm-graph-proof-valid".to_string(),
            chain_id: "swarm-chain-proof-valid".to_string(),
            dag_ordinal: 2,
            hlc_unix_ms: NOW_UNIX_MS - 500,
            parent_task_receipts: vec![
                SwarmJoinParentReceipt {
                    task_id: "task-child-a".to_string(),
                    receipt_id: "receipt-child-a".to_string(),
                },
                SwarmJoinParentReceipt {
                    task_id: "task-child-b".to_string(),
                    receipt_id: "receipt-child-b".to_string(),
                },
            ],
            expected_parent_receipt_ids: vec![
                "receipt-child-a".to_string(),
                "receipt-child-b".to_string(),
            ],
            actual_parent_receipt_ids: vec![
                "receipt-child-a".to_string(),
                "receipt-child-b".to_string(),
            ],
            join_predicate: "all_success".to_string(),
            result_digest: sha256_hex(b"joined-child-results"),
            next_task_id: "task-root".to_string(),
        },
        &witness_keypair(),
    )?;
    assert_eq!(minted.issuer, witness_issuer());
    assert!(!minted.signature.is_empty());
    assert_eq!(
        minted.parent_set_hash,
        join_parent_set_hash(
            "swarm-chain-proof-valid",
            &["receipt-child-a", "receipt-child-b"]
        )?
    );

    bundle.join_receipts[0] = minted;
    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;

    assert_eq!(report.verdict, "verified");
    Ok(())
}

#[test]
fn swarm_authority_reserves_budget_fanout() -> Result<(), Box<dyn Error>> {
    let pool = reserve_swarm_budget_fanout(SwarmBudgetFanoutReservationRequest {
        pool_id: "budget-pool-swarm-valid".to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        currency: "USD".to_string(),
        total_units: 10_000,
        allocations: vec![
            SwarmBudgetFanoutAllocationRequest {
                allocation_id: "budget-child-a".to_string(),
                task_id: "task-child-a".to_string(),
                dimension_id: "usd_minor".to_string(),
                reserved_units: 2_500,
            },
            SwarmBudgetFanoutAllocationRequest {
                allocation_id: "budget-child-b".to_string(),
                task_id: "task-child-b".to_string(),
                dimension_id: "usd_minor".to_string(),
                reserved_units: 2_500,
            },
        ],
    })?;

    assert_eq!(pool.allocations.len(), 2);
    assert_eq!(
        pool.allocations[0].state,
        SwarmBudgetAllocationState::Reserved
    );
    assert_eq!(pool.allocations[0].reserved_units, 2_500);
    assert_eq!(pool.allocations[0].active_units, 0);
    Ok(())
}

#[test]
fn swarm_authority_rejects_oversubscribed_budget_fanout() {
    let error = match reserve_swarm_budget_fanout(SwarmBudgetFanoutReservationRequest {
        pool_id: "budget-pool-swarm-valid".to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        currency: "USD".to_string(),
        total_units: 10_000,
        allocations: vec![
            SwarmBudgetFanoutAllocationRequest {
                allocation_id: "budget-child-a".to_string(),
                task_id: "task-child-a".to_string(),
                dimension_id: "usd_minor".to_string(),
                reserved_units: 8_000,
            },
            SwarmBudgetFanoutAllocationRequest {
                allocation_id: "budget-child-b".to_string(),
                task_id: "task-child-b".to_string(),
                dimension_id: "usd_minor".to_string(),
                reserved_units: 8_000,
            },
        ],
    }) {
        Ok(pool) => panic!("oversubscribed fanout reserved unexpectedly: {pool:#?}"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("swarm budget fanout exceeds pool total"));
}

#[test]
fn swarm_authority_releases_budget_on_fanin() -> Result<(), Box<dyn Error>> {
    let mut pool = sample_swarm_bundle()?.budget_pool;
    pool.allocations[0].active_units = 1_000;
    pool.allocations[0].consumed_units = 400;
    pool.allocations[0].max_units = 2_500;
    pool.allocations[1].active_units = 2_500;
    let released = release_swarm_budget_fanin(SwarmBudgetFanInReleaseRequest {
        pool,
        completed_task_ids: vec!["task-child-a".to_string()],
    })?;

    assert_eq!(
        released.allocations[0].state,
        SwarmBudgetAllocationState::Released
    );
    assert_eq!(released.allocations[0].reserved_units, 0);
    assert_eq!(released.allocations[0].active_units, 0);
    assert_eq!(released.allocations[0].consumed_units, 400);
    assert_eq!(released.allocations[0].released_units, 2_100);
    assert_eq!(
        released.allocations[1].state,
        SwarmBudgetAllocationState::Active
    );
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_unpinned_witness_issuer() -> Result<(), Box<dyn Error>> {
    let bundle = sample_swarm_bundle()?;
    let error = match verify_swarm_authority_bundle(&bundle, &[]) {
        Ok(report) => panic!("unpinned swarm witness verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("trusted swarm witness keys missing"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_root_only_bundle_without_trusted_witness_keys(
) -> Result<(), Box<dyn Error>> {
    let bundle = root_only_swarm_bundle()?;
    let error = match verify_swarm_authority_bundle(&bundle, &[]) {
        Ok(report) => panic!("root-only swarm verified without trusted keys: {report:#?}"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("trusted swarm witness keys missing"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_root_only_bundle_without_signed_swarm_evidence(
) -> Result<(), Box<dyn Error>> {
    let bundle = root_only_swarm_bundle()?;
    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("root-only swarm verified without signed evidence: {report:#?}"),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("signed swarm delegation evidence missing"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_graph_cycle() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.edges.push(SwarmGraphEdge {
        from_task_id: "task-child-a".to_string(),
        to_task_id: "task-root".to_string(),
        edge_type: "delegates".to_string(),
    });

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("cyclic swarm task graph verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("swarm task graph cycle"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_edge_depth_bypass() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    let child_scope = scope_for("commerce", "reserve_budget", 1);
    let child_scope_hash = scope_hash(&child_scope)?;

    bundle.task_graph.max_depth = 1;
    bundle.task_graph.nodes[2].parent_task_id = Some("task-child-a".to_string());
    bundle.task_graph.nodes[2].depth = 1;
    bundle.task_graph.edges[1].from_task_id = "task-child-a".to_string();
    bundle.continuation_tokens[1].parent_task_id = Some("task-child-a".to_string());
    bundle.witness_chains[1] = witness_chain(
        "witness-child-b",
        "task-child-a",
        "task-child-b",
        &child_scope_hash,
        &child_scope_hash,
        compute_attenuation_witness(&child_scope, &child_scope)?,
    )?;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("understated swarm graph depth verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("swarm task depth mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_non_root_task_without_parent() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.nodes[1].parent_task_id = None;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("non-root task without parent verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm non-root task missing parent"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_stale_continuation() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.continuation_tokens[0].expires_at_unix_ms = NOW_UNIX_MS - 1;
    sign_continuation_token(&mut bundle.continuation_tokens[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("stale continuation verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation token is stale"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_future_task_graph() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.created_at_unix_ms = NOW_UNIX_MS + 1;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("future swarm task graph verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm task graph is from the future"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_unsigned_continuation_token_json() {
    let unsigned_token = serde_json::json!({
        "schema": CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
        "tokenId": "continuation-child-a",
        "graphId": "swarm-graph-proof-valid",
        "childTaskId": "task-child-a",
        "parentTaskId": "task-root",
        "parentReceiptIds": ["receipt-root"],
        "graphSha256": "a7576259e58daae8002cb0daf8234199b5e004d122f652ef6a36aa5678efec9a",
        "routePlanReceiptId": "route-child-a",
        "budgetAllocationId": "budget-child-a",
        "revocationEpochRef": "revocation-epoch-swarm-valid",
        "revocationEpochRootHash": sha256_hex(b"revocation-root"),
        "sessionAnchorRef": "session-anchor-swarm-valid",
        "nonce": "nonce-task-child-a",
        "mode": "single_use",
        "issuedAtUnixMs": NOW_UNIX_MS - 1_000,
        "expiresAtUnixMs": NOW_UNIX_MS + 60_000
    });

    let error = match serde_json::from_value::<SwarmContinuationToken>(unsigned_token) {
        Ok(token) => panic!("unsigned continuation token parsed unexpectedly: {token:#?}"),
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("missing field `issuer`")
            || error.to_string().contains("missing field `signature`")
    );
}

#[test]
fn swarm_authority_stage0_rejects_future_continuation() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.continuation_tokens[0].issued_at_unix_ms = NOW_UNIX_MS + 1_000;
    sign_continuation_token(&mut bundle.continuation_tokens[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("future continuation verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation token is from the future"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_replayed_continuation_nonce() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.continuation_tokens[1].nonce = bundle.continuation_tokens[0].nonce.clone();
    sign_continuation_token(&mut bundle.continuation_tokens[1])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("replayed continuation nonce verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation nonce replay"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_tampered_continuation_signature() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.continuation_tokens[0].signature = "00".repeat(64);

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("tampered continuation signature verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation signature invalid"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_join_continuation_parent_receipt_mismatch(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.nodes[0].route_plan_ref = Some("route-join-root".to_string());
    bundle.task_graph.nodes[0].continuation_token_ref = Some("continuation-join-root".to_string());
    bundle.task_graph.nodes[0].budget_allocation_ref = Some("budget-root".to_string());
    bundle
        .task_graph
        .route_plan_refs
        .push("route-join-root".to_string());
    let graph_sha256 = canonical_hash(&bundle.task_graph)?;
    let mut continuation = continuation_token(
        "continuation-join-root",
        "task-root",
        "route-join-root",
        &graph_sha256,
        &bundle.revocation_epoch.root_hash,
        None,
    )?;
    continuation.parent_task_id = None;
    continuation.join_receipt_id = Some("join-child-results".to_string());
    continuation.parent_receipt_ids = vec!["receipt-unrelated".to_string()];
    sign_continuation_token(&mut continuation)?;
    bundle.continuation_tokens.push(continuation);
    bundle.route_plan_receipts.push(route_plan_receipt(
        "route-join-root",
        "task-root",
        "mcp",
        "mcp://provider-root",
    )?);
    bundle.budget_pool.allocations.push(SwarmBudgetAllocation {
        allocation_id: "budget-root".to_string(),
        task_id: "task-root".to_string(),
        dimension_id: "usd_minor".to_string(),
        state: SwarmBudgetAllocationState::Active,
        max_units: 2_500,
        reserved_units: 0,
        active_units: 2_500,
        consumed_units: 0,
        released_units: 0,
        reversed_units: 0,
    });
    bundle.terminal_receipts[0]
        .route_plan_receipt_ids
        .push("route-join-root".to_string());
    bundle.terminal_receipts[0].budget_rollups[0].active_units += 2_500;
    bundle.terminal_receipts[0].budget_rollups[0].total_units += 2_500;
    sign_terminal_graph_receipt(&mut bundle.terminal_receipts[0])?;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("join continuation parent receipt mismatch verified: {report:#?}"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("swarm continuation join parent receipts mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_tampered_join_receipt_signature() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.join_receipts[0].signature = "00".repeat(64);

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("tampered join receipt signature verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join receipt signature invalid"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_accepts_any_success_join_subset() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    keep_first_join_parent_receipt(&mut bundle.join_receipts[0])?;
    bundle.join_receipts[0].join_predicate = "any_success".to_string();
    sign_join_receipt(&mut bundle.join_receipts[0])?;

    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;

    assert_eq!(report.verdict, "verified");
    assert!(report
        .verified_claims
        .contains(&CLAIM_SWARM_JOIN_RECEIPT_BOUND.to_string()));
    Ok(())
}

#[test]
fn swarm_authority_stage0_accepts_quorum_join_subset() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    keep_first_join_parent_receipt(&mut bundle.join_receipts[0])?;
    bundle.join_receipts[0].join_predicate = "quorum:1".to_string();
    sign_join_receipt(&mut bundle.join_receipts[0])?;

    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;

    assert_eq!(report.verdict, "verified");
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_unmet_quorum_join_subset() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    keep_first_join_parent_receipt(&mut bundle.join_receipts[0])?;
    bundle.join_receipts[0].join_predicate = "quorum:2".to_string();
    sign_join_receipt(&mut bundle.join_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("unmet quorum join verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join receipt parent set mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_tampered_route_plan_signature() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.route_plan_receipts[0].signature = "00".repeat(64);

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("tampered route-plan signature verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm route-plan signature invalid"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_continuation_route_ref_mismatch() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.nodes[1].route_plan_ref = Some("route-child-b".to_string());
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("route ref mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation route-plan ref mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_continuation_parent_not_declared_on_child(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    let child_scope = scope_for("commerce", "reserve_budget", 1);
    let child_scope_hash = scope_hash(&child_scope)?;

    bundle.task_graph.nodes.push(SwarmGraphNode {
        task_id: "task-grandchild".to_string(),
        parent_task_id: Some("task-child-a".to_string()),
        route_plan_ref: Some("route-grandchild".to_string()),
        continuation_token_ref: Some("continuation-grandchild".to_string()),
        budget_allocation_ref: Some("budget-grandchild".to_string()),
        scope_hash: child_scope_hash.clone(),
        depth: 2,
    });
    bundle.task_graph.edges.push(SwarmGraphEdge {
        from_task_id: "task-child-a".to_string(),
        to_task_id: "task-grandchild".to_string(),
        edge_type: "delegates".to_string(),
    });
    bundle.task_graph.edges.push(SwarmGraphEdge {
        from_task_id: "task-child-b".to_string(),
        to_task_id: "task-grandchild".to_string(),
        edge_type: "delegates".to_string(),
    });
    bundle
        .task_graph
        .route_plan_refs
        .push("route-grandchild".to_string());

    let graph_sha256 = canonical_hash(&bundle.task_graph)?;
    let mut continuation = continuation_token(
        "continuation-grandchild",
        "task-grandchild",
        "route-grandchild",
        &graph_sha256,
        &bundle.revocation_epoch.root_hash,
        None,
    )?;
    continuation.parent_task_id = Some("task-child-b".to_string());
    continuation.parent_receipt_ids = vec!["receipt-child-b".to_string()];
    sign_continuation_token(&mut continuation)?;
    bundle.continuation_tokens.push(continuation);
    bundle.route_plan_receipts.push(route_plan_receipt(
        "route-grandchild",
        "task-grandchild",
        "mcp",
        "mcp://provider-grandchild",
    )?);
    bundle.budget_pool.allocations.push(SwarmBudgetAllocation {
        allocation_id: "budget-grandchild".to_string(),
        task_id: "task-grandchild".to_string(),
        dimension_id: "usd_minor".to_string(),
        state: SwarmBudgetAllocationState::Active,
        max_units: 2_500,
        reserved_units: 0,
        active_units: 2_500,
        consumed_units: 0,
        released_units: 0,
        reversed_units: 0,
    });
    bundle.witness_chains.push(witness_chain(
        "witness-grandchild-from-a",
        "task-child-a",
        "task-grandchild",
        &child_scope_hash,
        &child_scope_hash,
        compute_attenuation_witness(&child_scope, &child_scope)?,
    )?);
    bundle.witness_chains.push(witness_chain(
        "witness-grandchild-from-b",
        "task-child-b",
        "task-grandchild",
        &child_scope_hash,
        &child_scope_hash,
        compute_attenuation_witness(&child_scope, &child_scope)?,
    )?);
    bundle.terminal_receipts[0]
        .completed_task_ids
        .push("task-grandchild".to_string());
    bundle.terminal_receipts[0]
        .route_plan_receipt_ids
        .push("route-grandchild".to_string());
    bundle.terminal_receipts[0].budget_rollups[0].active_units += 2_500;
    bundle.terminal_receipts[0].budget_rollups[0].total_units += 2_500;
    sign_terminal_graph_receipt(&mut bundle.terminal_receipts[0])?;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("mismatched continuation parent verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("swarm continuation parent task mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_child_without_continuation_ref() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.nodes[1].continuation_token_ref = None;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("child without continuation ref verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm task continuation token ref missing"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_continuation_budget_ref_mismatch() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.nodes[1].budget_allocation_ref = Some("budget-child-b".to_string());
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("budget ref mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation budget ref mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_witness_child_scope_mismatch() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.witness_chains[0].hops[0].child_scope_hash = sha256_hex(b"wrong-child-scope");
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("witness mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm witness child scope mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_continuation_witness_chain_binding_mismatch(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.witness_chains[0].chain_id = "witness-child-a-rebound".to_string();
    sign_witness_chain(&mut bundle.witness_chains[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("continuation witness binding mismatch verified: {report:#?}"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("swarm continuation witness chain mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_multi_hop_without_feature_gate() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    set_child_a_multi_hop_witness(&mut bundle)?;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("ungated multi-hop witness verified: {report:#?}"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("swarm multi-hop witness chain feature gate missing"),
        "{error}"
    );
    Ok(())
}

#[test]
fn swarm_authority_stage0_accepts_multi_hop_with_feature_gate() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.multi_hop_witness_chains = true;
    set_child_a_multi_hop_witness(&mut bundle)?;
    refresh_continuation_graph_digests(&mut bundle)?;

    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;
    let hop = report
        .hop_reports
        .iter()
        .find(|hop| hop.child_task_id == "task-child-a")
        .ok_or("missing task-child-a hop report")?;

    assert_eq!(hop.witness_hop_count, 2);
    assert!(hop.multi_hop_witness_enabled);
    assert!(hop.attenuation_verified);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn swarm_authority_stage0_rejects_generated_recursive_scope_widening(
        parent_limit in 1_u32..32,
        extra_invocations in 1_u32..32,
    ) {
        let mut bundle = sample_swarm_bundle()
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let child_limit = parent_limit + extra_invocations;
        let parent_scope = scope_for("commerce", "reserve_budget", parent_limit);
        let permitted_child_scope = scope_for("commerce", "reserve_budget", parent_limit);
        let widened_child_scope = scope_for("commerce", "reserve_budget", child_limit);
        let parent_scope_hash = scope_hash(&parent_scope)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let widened_child_scope_hash = scope_hash(&widened_child_scope)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        bundle.task_graph.nodes[0].scope_hash = parent_scope_hash.clone();
        bundle.task_graph.nodes[1].scope_hash = widened_child_scope_hash.clone();
        bundle.witness_chains[0].hops[0].parent_scope_hash = parent_scope_hash;
        bundle.witness_chains[0].hops[0].child_scope_hash = widened_child_scope_hash;
        bundle.witness_chains[0].hops[0].scope_subset_proof =
            compute_attenuation_witness(&parent_scope, &permitted_child_scope)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        sign_witness_chain(&mut bundle.witness_chains[0])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        refresh_continuation_graph_digests(&mut bundle)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
            Ok(report) => {
                return Err(TestCaseError::fail(format!(
                    "generated widening verified unexpectedly: {report:#?}"
                )));
            }
            Err(error) => error,
        };
        prop_assert!(
            error.to_string().contains("swarm attenuation witness invalid"),
            "{}",
            error
        );
    }
}

#[test]
fn swarm_authority_stage0_rejects_tampered_witness_signature() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.witness_chains[0].hops[0].witness_signature = "sig-tampered-witness-child-a".to_string();
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("tampered witness signature verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm witness signature invalid"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_disconnected_witness_hops() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.multi_hop_witness_chains = true;
    let parent_scope = scope_for("commerce", "reserve_budget", 3);
    let intermediate_scope = scope_for("commerce", "reserve_budget", 2);
    let child_scope = scope_for("commerce", "reserve_budget", 1);
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let intermediate_scope_hash = scope_hash(&intermediate_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;

    bundle.witness_chains[0].hops = vec![
        SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"parent-capability"),
            child_capability_digest: sha256_hex(b"intermediate-capability"),
            parent_scope_hash: parent_scope_hash.clone(),
            child_scope_hash: intermediate_scope_hash,
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof: compute_attenuation_witness(&parent_scope, &intermediate_scope)?,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        },
        SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"disconnected-parent-capability"),
            child_capability_digest: sha256_hex(b"task-child-a"),
            parent_scope_hash,
            child_scope_hash,
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof: compute_attenuation_witness(&parent_scope, &child_scope)?,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        },
    ];
    sign_witness_chain(&mut bundle.witness_chains[0])?;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("disconnected witness hops verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm witness hop scope discontinuity"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_stale_route_plan() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.route_plan_receipts[0].expires_at_unix_ms = NOW_UNIX_MS - 1;
    sign_route_plan_receipt(&mut bundle.route_plan_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("stale route plan verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm route-plan receipt is stale"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_rejected_route_plan() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.route_plan_receipts[0].attenuation_decision = "rejected".to_string();
    sign_route_plan_receipt(&mut bundle.route_plan_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("rejected route plan verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm route-plan attenuation was not accepted"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_empty_route_plan_egress_constraints() -> Result<(), Box<dyn Error>>
{
    let mut bundle = sample_swarm_bundle()?;
    bundle.route_plan_receipts[0].egress_constraints.clear();
    sign_route_plan_receipt(&mut bundle.route_plan_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("empty egress constraints verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm route-plan egress constraints missing"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_unsupported_route_plan_egress_constraint(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.route_plan_receipts[0].egress_constraints = vec!["allow-private-network".to_string()];
    sign_route_plan_receipt(&mut bundle.route_plan_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("unsupported egress constraint verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("unsupported swarm route-plan egress constraint"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_route_plan_selected_route_bridge_mismatch(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.route_plan_receipts[0].selected_route = "a2a:task-child-a".to_string();
    sign_route_plan_receipt(&mut bundle.route_plan_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("route bridge mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm route-plan selected route bridge mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_route_plan_protocol_target_bridge_mismatch(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.route_plan_receipts[0].protocol_target = "a2a://provider-a".to_string();
    sign_route_plan_receipt(&mut bundle.route_plan_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("route target mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm route-plan protocol target bridge mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_join_parent_set_mismatch() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.join_receipts[0].actual_parent_receipt_ids.pop();
    refresh_join_receipt_parent_set_hash(&mut bundle.join_receipts[0])?;
    sign_join_receipt(&mut bundle.join_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("join mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join receipt parent set mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_join_parent_task_receipt_mapping_mismatch(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.join_receipts[0].parent_task_receipts[0].receipt_id = "receipt-unrelated".to_string();
    sign_join_receipt(&mut bundle.join_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("join parent task receipt mismatch verified: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join receipt parent task receipts mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_accepts_reordered_join_parent_task_receipts() -> Result<(), Box<dyn Error>>
{
    let mut bundle = sample_swarm_bundle()?;
    bundle.join_receipts[0].parent_task_receipts.swap(0, 1);
    sign_join_receipt(&mut bundle.join_receipts[0])?;

    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;
    assert_eq!(report.verdict, "verified");
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_single_parent_join() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.joins[0].parent_task_ids.pop();
    bundle.join_receipts[0].expected_parent_receipt_ids.pop();
    bundle.join_receipts[0].actual_parent_receipt_ids.pop();
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("single-parent join verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join requires at least two parents"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_join_receipt_parent_count_mismatch() -> Result<(), Box<dyn Error>>
{
    let mut bundle = sample_swarm_bundle()?;
    bundle.join_receipts[0]
        .expected_parent_receipt_ids
        .push("receipt-extra".to_string());
    bundle.join_receipts[0]
        .actual_parent_receipt_ids
        .push("receipt-extra".to_string());
    refresh_join_receipt_parent_set_hash(&mut bundle.join_receipts[0])?;
    sign_join_receipt(&mut bundle.join_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("extra join parent receipt verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join receipt parent count mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_join_next_task_that_is_parent() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.joins[0].next_task_id = "task-child-a".to_string();
    bundle.join_receipts[0].next_task_id = "task-child-a".to_string();
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("self-referential join verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join next task is a parent"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_unsupported_join_predicate() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.join_receipts[0].join_predicate = "first_success".to_string();
    sign_join_receipt(&mut bundle.join_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("unsupported join predicate verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join receipt predicate unsupported"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_budget_allocations_exceeding_pool() -> Result<(), Box<dyn Error>>
{
    let mut bundle = sample_swarm_bundle()?;
    bundle.budget_pool.total_units = 100;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("overspent budget verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm budget allocations exceed pool total"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_terminal_budget_rollup_mismatch() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.terminal_receipts[0].budget_rollups[0].active_units += 1;
    bundle.terminal_receipts[0].budget_rollups[0].total_units += 1;
    sign_terminal_graph_receipt(&mut bundle.terminal_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("terminal budget rollup mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("swarm terminal budget rollup mismatch"),
        "{error}"
    );
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_released_budget_allocation() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.budget_pool.allocations[0].state = SwarmBudgetAllocationState::Released;
    bundle.budget_pool.allocations[0].active_units = 0;
    bundle.budget_pool.allocations[0].released_units = 2_500;
    bundle.terminal_receipts[0].budget_rollups[0].active_units = 2_500;
    bundle.terminal_receipts[0].budget_rollups[0].released_units = 2_500;
    sign_terminal_graph_receipt(&mut bundle.terminal_receipts[0])?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("released budget allocation verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("swarm budget allocation is not active"),
        "{message}"
    );
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_revoked_task() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle
        .revocation_epoch
        .revoked_task_ids
        .push("task-child-a".to_string());
    refresh_revocation_epoch_root(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("revoked task verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("swarm task is revoked"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_future_revocation_epoch() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.revocation_epoch.issued_at_unix_ms = NOW_UNIX_MS + 1_000;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("future revocation epoch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm revocation epoch is from the future"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_revocation_epoch_root_mismatch() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.revocation_epoch.root_hash = sha256_hex(b"different-revocation-root");

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("revocation epoch root mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm revocation epoch root mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_revocation_epoch_list_root_mismatch() -> Result<(), Box<dyn Error>>
{
    let mut bundle = sample_swarm_bundle()?;
    bundle
        .revocation_epoch
        .revoked_subjects
        .push("did:chio:unrelated-subject".to_string());

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => {
            panic!("revocation epoch list root mismatch verified unexpectedly: {report:#?}")
        }
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm revocation epoch root mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_unsigned_revocation_epoch_list_reseal(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle
        .revocation_epoch
        .revoked_subjects
        .push("did:chio:unrelated-subject".to_string());
    refresh_revocation_epoch_root(&mut bundle)?;
    bundle.revocation_epoch.signature = "0".repeat(128);

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("unsigned revocation epoch reseal verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm revocation epoch signature invalid"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_revoked_authority_subject() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle
        .revocation_epoch
        .revoked_subjects
        .push(witness_issuer());
    refresh_revocation_epoch_root(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("revoked authority subject verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm authority subject is revoked"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_task_graph_tampering_after_continuations_are_resealed(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.max_fanout += 1;
    let graph_sha256 = canonical_hash(&bundle.task_graph)?;
    for token in &mut bundle.continuation_tokens {
        token.graph_sha256 = graph_sha256.clone();
        sign_continuation_token(token)?;
    }

    let error = match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => panic!("tampered swarm task graph verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm task graph signature invalid"));
    Ok(())
}

fn sample_swarm_bundle() -> Result<SwarmAuthorityBundle, Box<dyn Error>> {
    let parent_scope = scope_for("commerce", "reserve_budget", 3);
    let child_scope = scope_for("commerce", "reserve_budget", 1);
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;
    let witness = compute_attenuation_witness(&parent_scope, &child_scope)?;

    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        root_transaction_ref: "passport-swarm-valid".to_string(),
        planner_subject: "did:chio:planner".to_string(),
        issuer: witness_issuer(),
        signature: String::new(),
        created_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        max_depth: 2,
        max_fanout: 2,
        multi_hop_witness_chains: false,
        nodes: vec![
            SwarmGraphNode {
                task_id: "task-root".to_string(),
                parent_task_id: None,
                route_plan_ref: None,
                continuation_token_ref: None,
                budget_allocation_ref: None,
                scope_hash: parent_scope_hash.clone(),
                depth: 0,
            },
            SwarmGraphNode {
                task_id: "task-child-a".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-a".to_string()),
                continuation_token_ref: Some("continuation-child-a".to_string()),
                budget_allocation_ref: Some("budget-child-a".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
            SwarmGraphNode {
                task_id: "task-child-b".to_string(),
                parent_task_id: Some("task-root".to_string()),
                route_plan_ref: Some("route-child-b".to_string()),
                continuation_token_ref: Some("continuation-child-b".to_string()),
                budget_allocation_ref: Some("budget-child-b".to_string()),
                scope_hash: child_scope_hash.clone(),
                depth: 1,
            },
        ],
        edges: vec![
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-a".to_string(),
                edge_type: "delegates".to_string(),
            },
            SwarmGraphEdge {
                from_task_id: "task-root".to_string(),
                to_task_id: "task-child-b".to_string(),
                edge_type: "delegates".to_string(),
            },
        ],
        joins: vec![SwarmGraphJoin {
            join_id: "join-child-results".to_string(),
            parent_task_ids: vec!["task-child-a".to_string(), "task-child-b".to_string()],
            next_task_id: "task-root".to_string(),
        }],
        budget_pool_ref: "budget-pool-swarm-valid".to_string(),
        revocation_epoch_ref: "revocation-epoch-swarm-valid".to_string(),
        route_plan_refs: vec!["route-child-a".to_string(), "route-child-b".to_string()],
    };
    sign_task_graph(&mut task_graph)?;
    let graph_sha256 = canonical_hash(&task_graph)?;
    let empty_revoked_subjects = Vec::<String>::new();
    let empty_revoked_task_ids = Vec::<String>::new();
    let revocation_epoch_root_hash =
        revocation_epoch_root_hash(&empty_revoked_subjects, &empty_revoked_task_ids)?;

    let witness_chains = vec![
        witness_chain(
            "witness-child-a",
            "task-root",
            "task-child-a",
            &parent_scope_hash,
            &child_scope_hash,
            witness.clone(),
        )?,
        witness_chain(
            "witness-child-b",
            "task-root",
            "task-child-b",
            &parent_scope_hash,
            &child_scope_hash,
            witness,
        )?,
    ];
    let continuation_tokens = vec![
        continuation_token(
            "continuation-child-a",
            "task-child-a",
            "route-child-a",
            &graph_sha256,
            &revocation_epoch_root_hash,
            Some(&witness_chains[0]),
        )?,
        continuation_token(
            "continuation-child-b",
            "task-child-b",
            "route-child-b",
            &graph_sha256,
            &revocation_epoch_root_hash,
            Some(&witness_chains[1]),
        )?,
    ];
    task_graph.nodes[1].continuation_token_ref = Some(continuation_tokens[0].token_id.clone());
    task_graph.nodes[2].continuation_token_ref = Some(continuation_tokens[1].token_id.clone());

    let mut join_receipts = vec![SwarmJoinReceipt {
        schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
        join_id: "join-child-results".to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        chain_id: "swarm-chain-proof-valid".to_string(),
        parent_set_hash: join_parent_set_hash(
            "swarm-chain-proof-valid",
            &["receipt-child-a", "receipt-child-b"],
        )?,
        dag_ordinal: 2,
        hlc_unix_ms: NOW_UNIX_MS - 500,
        parent_task_receipts: vec![
            SwarmJoinParentReceipt {
                task_id: "task-child-a".to_string(),
                receipt_id: "receipt-child-a".to_string(),
            },
            SwarmJoinParentReceipt {
                task_id: "task-child-b".to_string(),
                receipt_id: "receipt-child-b".to_string(),
            },
        ],
        expected_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        actual_parent_receipt_ids: vec![
            "receipt-child-a".to_string(),
            "receipt-child-b".to_string(),
        ],
        join_predicate: "all_success".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        next_task_id: "task-root".to_string(),
        issuer: witness_issuer(),
        signature: String::new(),
    }];
    sign_join_receipt(&mut join_receipts[0])?;

    let mut bundle = SwarmAuthorityBundle {
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts,
        route_plan_receipts: vec![
            route_plan_receipt("route-child-a", "task-child-a", "mcp", "mcp://provider-a")?,
            route_plan_receipt("route-child-b", "task-child-b", "a2a", "a2a://provider-b")?,
        ],
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: "budget-pool-swarm-valid".to_string(),
            graph_id: "swarm-graph-proof-valid".to_string(),
            currency: "USD".to_string(),
            total_units: 10_000,
            allocations: vec![
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-a".to_string(),
                    task_id: "task-child-a".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 2_500,
                    reserved_units: 0,
                    active_units: 2_500,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-b".to_string(),
                    task_id: "task-child-b".to_string(),
                    dimension_id: "usd_minor".to_string(),
                    state: SwarmBudgetAllocationState::Active,
                    max_units: 2_500,
                    reserved_units: 0,
                    active_units: 2_500,
                    consumed_units: 0,
                    released_units: 0,
                    reversed_units: 0,
                },
            ],
        },
        revocation_epoch: SwarmRevocationEpoch {
            schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
            epoch_id: "revocation-epoch-swarm-valid".to_string(),
            root_hash: revocation_epoch_root_hash,
            issued_at_unix_ms: NOW_UNIX_MS - 1_000,
            valid_until_unix_ms: NOW_UNIX_MS + 60_000,
            revoked_subjects: empty_revoked_subjects,
            revoked_task_ids: empty_revoked_task_ids,
            issuer: witness_issuer(),
            signature: String::new(),
        },
        terminal_receipts: vec![terminal_graph_receipt()?],
        now_unix_ms: NOW_UNIX_MS,
    };
    sign_revocation_epoch(&mut bundle.revocation_epoch)?;
    Ok(bundle)
}

fn root_only_swarm_bundle() -> Result<SwarmAuthorityBundle, Box<dyn Error>> {
    let root_scope_hash = scope_hash(&scope_for("commerce", "reserve_budget", 1))?;
    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: "swarm-graph-root-only".to_string(),
        root_transaction_ref: "passport-swarm-root-only".to_string(),
        planner_subject: "did:chio:planner".to_string(),
        issuer: witness_issuer(),
        signature: String::new(),
        created_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        max_depth: 1,
        max_fanout: 1,
        multi_hop_witness_chains: false,
        nodes: vec![SwarmGraphNode {
            task_id: "task-root".to_string(),
            parent_task_id: None,
            route_plan_ref: None,
            continuation_token_ref: None,
            budget_allocation_ref: None,
            scope_hash: root_scope_hash,
            depth: 0,
        }],
        edges: Vec::new(),
        joins: Vec::new(),
        budget_pool_ref: "budget-pool-swarm-root-only".to_string(),
        revocation_epoch_ref: "revocation-epoch-swarm-root-only".to_string(),
        route_plan_refs: Vec::new(),
    };
    sign_task_graph(&mut task_graph)?;
    let empty_revoked_subjects = Vec::<String>::new();
    let empty_revoked_task_ids = Vec::<String>::new();
    let revocation_epoch_root_hash =
        revocation_epoch_root_hash(&empty_revoked_subjects, &empty_revoked_task_ids)?;
    let mut bundle = SwarmAuthorityBundle {
        task_graph,
        continuation_tokens: Vec::new(),
        witness_chains: Vec::new(),
        join_receipts: Vec::new(),
        route_plan_receipts: Vec::new(),
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: "budget-pool-swarm-root-only".to_string(),
            graph_id: "swarm-graph-root-only".to_string(),
            currency: "USD".to_string(),
            total_units: 0,
            allocations: Vec::new(),
        },
        revocation_epoch: SwarmRevocationEpoch {
            schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
            epoch_id: "revocation-epoch-swarm-root-only".to_string(),
            root_hash: revocation_epoch_root_hash,
            issued_at_unix_ms: NOW_UNIX_MS - 1_000,
            valid_until_unix_ms: NOW_UNIX_MS + 60_000,
            revoked_subjects: empty_revoked_subjects,
            revoked_task_ids: empty_revoked_task_ids,
            issuer: witness_issuer(),
            signature: String::new(),
        },
        terminal_receipts: Vec::new(),
        now_unix_ms: NOW_UNIX_MS,
    };
    sign_revocation_epoch(&mut bundle.revocation_epoch)?;
    Ok(bundle)
}

fn continuation_token(
    token_id: &str,
    child_task_id: &str,
    route_plan_receipt_id: &str,
    graph_sha256: &str,
    revocation_epoch_root_hash: &str,
    witness_chain: Option<&SwarmDelegationWitnessChain>,
) -> Result<SwarmContinuationToken, Box<dyn Error>> {
    let witness_chain_ref = witness_chain.map(|chain| chain.chain_id.clone());
    let witness_chain_sha256 = witness_chain.map(canonical_hash).transpose()?;
    let mut token = SwarmContinuationToken {
        schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.to_string(),
        token_id: token_id.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        child_task_id: child_task_id.to_string(),
        parent_task_id: Some("task-root".to_string()),
        join_receipt_id: None,
        parent_receipt_ids: vec!["receipt-root".to_string()],
        graph_sha256: graph_sha256.to_string(),
        route_plan_receipt_id: route_plan_receipt_id.to_string(),
        budget_allocation_id: format!("budget-{}", child_task_id.trim_start_matches("task-")),
        witness_chain_ref,
        witness_chain_sha256,
        revocation_epoch_ref: "revocation-epoch-swarm-valid".to_string(),
        revocation_epoch_root_hash: revocation_epoch_root_hash.to_string(),
        session_anchor_ref: "session-anchor-swarm-valid".to_string(),
        nonce: format!("nonce-{child_task_id}"),
        mode: SwarmContinuationMode::SingleUse,
        issued_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        issuer: witness_issuer(),
        signature: String::new(),
    };
    sign_continuation_token(&mut token)?;
    Ok(token)
}

fn sign_continuation_token(token: &mut SwarmContinuationToken) -> Result<(), Box<dyn Error>> {
    token.signature = sign_swarm_continuation_token(token, &witness_keypair())?;
    Ok(())
}

fn sign_task_graph(graph: &mut SwarmTaskGraph) -> Result<(), Box<dyn Error>> {
    graph.signature = sign_swarm_task_graph(graph, &witness_keypair())?;
    Ok(())
}

fn sign_join_receipt(receipt: &mut SwarmJoinReceipt) -> Result<(), Box<dyn Error>> {
    receipt.signature = sign_swarm_join_receipt(receipt, &witness_keypair())?;
    Ok(())
}

fn sign_route_plan_receipt(receipt: &mut SwarmRoutePlanReceipt) -> Result<(), Box<dyn Error>> {
    receipt.signature = sign_swarm_route_plan_receipt(receipt, &witness_keypair())?;
    Ok(())
}

fn sign_terminal_graph_receipt(
    receipt: &mut SwarmTerminalGraphReceipt,
) -> Result<(), Box<dyn Error>> {
    receipt.signature = sign_swarm_terminal_graph_receipt(receipt, &witness_keypair())?;
    Ok(())
}

fn sign_revocation_epoch(epoch: &mut SwarmRevocationEpoch) -> Result<(), Box<dyn Error>> {
    epoch.signature = sign_swarm_revocation_epoch(epoch, &witness_keypair())?;
    Ok(())
}

fn refresh_join_receipt_parent_set_hash(
    receipt: &mut SwarmJoinReceipt,
) -> Result<(), Box<dyn Error>> {
    let receipt_ids = receipt
        .actual_parent_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    receipt.parent_set_hash = join_parent_set_hash(&receipt.chain_id, &receipt_ids)?;
    Ok(())
}

fn keep_first_join_parent_receipt(receipt: &mut SwarmJoinReceipt) -> Result<(), Box<dyn Error>> {
    receipt.actual_parent_receipt_ids.truncate(1);
    receipt.parent_task_receipts.truncate(1);
    refresh_join_receipt_parent_set_hash(receipt)
}

fn join_parent_set_hash(chain_id: &str, receipt_ids: &[&str]) -> Result<String, Box<dyn Error>> {
    let mut sorted_receipt_ids = receipt_ids.to_vec();
    sorted_receipt_ids.sort();
    let body = serde_json::json!({
        "chainId": chain_id,
        "parentReceiptIds": sorted_receipt_ids,
    });
    Ok(sha256_hex(&canonical_json_bytes(&body)?))
}

fn witness_chain(
    chain_id: &str,
    parent_task_id: &str,
    child_task_id: &str,
    parent_scope_hash: &str,
    child_scope_hash: &str,
    scope_subset_proof: chio_core_types::capability::attenuation::AttenuationWitness,
) -> Result<SwarmDelegationWitnessChain, Box<dyn Error>> {
    let mut chain = SwarmDelegationWitnessChain {
        schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.to_string(),
        chain_id: chain_id.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        parent_task_id: parent_task_id.to_string(),
        child_task_id: child_task_id.to_string(),
        hops: vec![SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"parent-capability"),
            child_capability_digest: sha256_hex(child_task_id.as_bytes()),
            parent_scope_hash: parent_scope_hash.to_string(),
            child_scope_hash: child_scope_hash.to_string(),
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        }],
    };
    sign_witness_chain(&mut chain)?;
    Ok(chain)
}

fn set_child_a_multi_hop_witness(bundle: &mut SwarmAuthorityBundle) -> Result<(), Box<dyn Error>> {
    let parent_scope = scope_for("commerce", "reserve_budget", 3);
    let intermediate_scope = scope_for("commerce", "reserve_budget", 2);
    let child_scope = scope_for("commerce", "reserve_budget", 1);
    let parent_scope_hash = scope_hash(&parent_scope)?;
    let intermediate_scope_hash = scope_hash(&intermediate_scope)?;
    let child_scope_hash = scope_hash(&child_scope)?;

    bundle.witness_chains[0].hops = vec![
        SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"parent-capability"),
            child_capability_digest: sha256_hex(b"intermediate-capability"),
            parent_scope_hash: parent_scope_hash.clone(),
            child_scope_hash: intermediate_scope_hash.clone(),
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof: compute_attenuation_witness(&parent_scope, &intermediate_scope)?,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        },
        SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"intermediate-capability"),
            child_capability_digest: sha256_hex(b"task-child-a"),
            parent_scope_hash: intermediate_scope_hash,
            child_scope_hash,
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof: compute_attenuation_witness(&intermediate_scope, &child_scope)?,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: witness_issuer(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: String::new(),
        },
    ];
    sign_witness_chain(&mut bundle.witness_chains[0])?;
    Ok(())
}

fn sign_witness_chain(chain: &mut SwarmDelegationWitnessChain) -> Result<(), Box<dyn Error>> {
    let keypair = witness_keypair();
    for index in 0..chain.hops.len() {
        let signature = sign_swarm_delegation_witness_hop(chain, &chain.hops[index], &keypair)?;
        chain.hops[index].witness_signature = signature;
    }
    Ok(())
}

fn witness_keypair() -> Keypair {
    Keypair::from_seed(&[31u8; 32])
}

fn trusted_witness_keys() -> Vec<PublicKey> {
    vec![witness_keypair().public_key()]
}

fn witness_issuer() -> String {
    format!("did:chio:{}", witness_keypair().public_key().to_hex())
}

fn route_plan_receipt(
    route_plan_id: &str,
    task_id: &str,
    bridge_id: &str,
    protocol_target: &str,
) -> Result<SwarmRoutePlanReceipt, Box<dyn Error>> {
    let mut receipt = SwarmRoutePlanReceipt {
        schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.to_string(),
        route_plan_id: route_plan_id.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        task_id: task_id.to_string(),
        selected_route: format!("{bridge_id}:{task_id}"),
        candidate_set_digest: sha256_hex(format!("candidates-{task_id}").as_bytes()),
        registry_snapshot_hash: sha256_hex(b"registry-snapshot"),
        bridge_id: bridge_id.to_string(),
        protocol_target: protocol_target.to_string(),
        egress_contract_id: format!("{bridge_id}:egress-contract-{task_id}"),
        egress_constraints: vec!["deny-private-network".to_string()],
        attenuation_decision: "accepted".to_string(),
        policy_digest: sha256_hex(b"swarm-route-policy"),
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        issuer: witness_issuer(),
        signature: String::new(),
    };
    sign_route_plan_receipt(&mut receipt)?;
    Ok(receipt)
}

fn terminal_graph_receipt() -> Result<SwarmTerminalGraphReceipt, Box<dyn Error>> {
    let mut receipt = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.to_string(),
        receipt_id: "terminal-swarm-proof-valid".to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        chain_id: "swarm-chain-proof-valid".to_string(),
        terminal_task_ids: vec!["task-root".to_string()],
        completed_task_ids: vec![
            "task-root".to_string(),
            "task-child-a".to_string(),
            "task-child-b".to_string(),
        ],
        join_receipt_ids: vec!["join-child-results".to_string()],
        route_plan_receipt_ids: vec!["route-child-a".to_string(), "route-child-b".to_string()],
        budget_pool_id: "budget-pool-swarm-valid".to_string(),
        budget_rollups: vec![SwarmTerminalBudgetRollup {
            dimension_id: "usd_minor".to_string(),
            reserved_units: 0,
            active_units: 5_000,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
            total_units: 5_000,
        }],
        revocation_epoch_ref: "revocation-epoch-swarm-valid".to_string(),
        result_digest: sha256_hex(b"joined-child-results"),
        completed_at_unix_ms: NOW_UNIX_MS,
        issuer: witness_issuer(),
        signature: String::new(),
    };
    sign_terminal_graph_receipt(&mut receipt)?;
    Ok(receipt)
}

fn scope_for(server_id: &str, tool_name: &str, max_invocations: u32) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: server_id.to_string(),
            tool_name: tool_name.to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(max_invocations),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<String, Box<dyn Error>> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn revocation_epoch_root_hash(
    revoked_subjects: &[String],
    revoked_task_ids: &[String],
) -> Result<String, Box<dyn Error>> {
    let mut subjects = revoked_subjects
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    subjects.sort_unstable();
    let mut task_ids = revoked_task_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    task_ids.sort_unstable();
    canonical_hash(&serde_json::json!({
        "revokedSubjects": subjects,
        "revokedTaskIds": task_ids,
    }))
}

fn refresh_revocation_epoch_root(bundle: &mut SwarmAuthorityBundle) -> Result<(), Box<dyn Error>> {
    let root_hash = revocation_epoch_root_hash(
        &bundle.revocation_epoch.revoked_subjects,
        &bundle.revocation_epoch.revoked_task_ids,
    )?;
    bundle.revocation_epoch.root_hash = root_hash.clone();
    sign_revocation_epoch(&mut bundle.revocation_epoch)?;
    for token in &mut bundle.continuation_tokens {
        token.revocation_epoch_root_hash = root_hash.clone();
        sign_continuation_token(token)?;
    }
    Ok(())
}

fn refresh_continuation_graph_digests(
    bundle: &mut SwarmAuthorityBundle,
) -> Result<(), Box<dyn Error>> {
    sign_task_graph(&mut bundle.task_graph)?;
    let graph_sha256 = canonical_hash(&bundle.task_graph)?;
    let mut witness_bindings = BTreeMap::new();
    for chain in &bundle.witness_chains {
        witness_bindings.insert(
            (chain.parent_task_id.as_str(), chain.child_task_id.as_str()),
            (chain.chain_id.clone(), canonical_hash(chain)?),
        );
    }
    for token in &mut bundle.continuation_tokens {
        token.graph_sha256 = graph_sha256.clone();
        if let Some(parent_task_id) = token.parent_task_id.as_deref() {
            if let Some((chain_id, chain_sha256)) =
                witness_bindings.get(&(parent_task_id, token.child_task_id.as_str()))
            {
                token.witness_chain_ref = Some(chain_id.clone());
                token.witness_chain_sha256 = Some(chain_sha256.clone());
            }
        }
        sign_continuation_token(token)?;
    }
    Ok(())
}
