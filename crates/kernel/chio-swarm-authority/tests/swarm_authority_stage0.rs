use std::error::Error;

use chio_core_types::capability::attenuation::{compute_attenuation_witness, scope_hash};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_swarm_authority::{
    verify_swarm_authority_bundle, SwarmAuthorityBundle, SwarmBudgetAllocation, SwarmBudgetPool,
    SwarmContinuationMode, SwarmContinuationToken, SwarmDelegationWitnessChain,
    SwarmDelegationWitnessHop, SwarmGraphEdge, SwarmGraphJoin, SwarmGraphNode, SwarmJoinReceipt,
    SwarmRevocationEpoch, SwarmRoutePlanReceipt, SwarmTaskGraph,
    CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_SCHEMA, CHIO_SWARM_BUDGET_POOL_SCHEMA,
    CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA, CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA,
    CHIO_SWARM_JOIN_RECEIPT_SCHEMA, CHIO_SWARM_REVOCATION_EPOCH_SCHEMA,
    CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA, CHIO_SWARM_TASK_GRAPH_SCHEMA,
    CLAIM_SWARM_ATTENUATION_WITNESS_CHAIN_BOUND, CLAIM_SWARM_BUDGET_POOL_BOUND,
    CLAIM_SWARM_CONTINUATION_FRESH, CLAIM_SWARM_JOIN_RECEIPT_BOUND,
    CLAIM_SWARM_REVOCATION_EPOCH_BOUND, CLAIM_SWARM_ROUTE_PLAN_BOUND, CLAIM_SWARM_TASK_GRAPH_BOUND,
};

const NOW_UNIX_MS: u64 = 1_800_000_001_000;

#[test]
fn swarm_authority_stage0_verifies_valid_bundle() -> Result<(), Box<dyn Error>> {
    let bundle = sample_swarm_bundle()?;
    let report = verify_swarm_authority_bundle(&bundle)?;

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

    let error = match verify_swarm_authority_bundle(&bundle) {
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
    );
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("stale continuation verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation token is stale"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_replayed_continuation_nonce() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.continuation_tokens[1].nonce = bundle.continuation_tokens[0].nonce.clone();

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("replayed continuation nonce verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation nonce replay"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_continuation_route_ref_mismatch() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.nodes[1].route_plan_ref = Some("route-child-b".to_string());
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("route ref mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm continuation route-plan ref mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_child_without_continuation_ref() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.nodes[1].continuation_token_ref = None;
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("witness mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm witness child scope mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_disconnected_witness_hops() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
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
            issuer: "did:chio:authority".to_string(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: "sig-witness-child-a-hop-1".to_string(),
        },
        SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(b"disconnected-parent-capability"),
            child_capability_digest: sha256_hex(b"task-child-a"),
            parent_scope_hash,
            child_scope_hash,
            attenuation_rule_id: "rule-subset-tool-invocation".to_string(),
            scope_subset_proof: compute_attenuation_witness(&parent_scope, &child_scope)?,
            expires_at_unix_ms: NOW_UNIX_MS + 60_000,
            issuer: "did:chio:authority".to_string(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: "sig-witness-child-a-hop-2".to_string(),
        },
    ];

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("rejected route plan verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm route-plan attenuation was not accepted"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_route_plan_selected_route_bridge_mismatch(
) -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.route_plan_receipts[0].selected_route = "a2a:task-child-a".to_string();

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("join mismatch verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm join receipt parent set mismatch"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_single_parent_join() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.task_graph.joins[0].parent_task_ids.pop();
    bundle.join_receipts[0].expected_parent_receipt_ids.pop();
    bundle.join_receipts[0].actual_parent_receipt_ids.pop();
    refresh_continuation_graph_digests(&mut bundle)?;

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
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

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("overspent budget verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm budget allocations exceed pool total"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_revoked_task() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle
        .revocation_epoch
        .revoked_task_ids
        .push("task-child-a".to_string());

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("revoked task verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("swarm task is revoked"));
    Ok(())
}

#[test]
fn swarm_authority_stage0_rejects_revoked_authority_subject() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle
        .revocation_epoch
        .revoked_subjects
        .push("did:chio:authority".to_string());

    let error = match verify_swarm_authority_bundle(&bundle) {
        Ok(report) => panic!("revoked authority subject verified unexpectedly: {report:#?}"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("swarm authority subject is revoked"));
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
        issuer: "did:chio:authority".to_string(),
        created_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        max_depth: 2,
        max_fanout: 2,
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
    let graph_sha256 = canonical_hash(&task_graph)?;

    let continuation_tokens = vec![
        continuation_token(
            "continuation-child-a",
            "task-child-a",
            "route-child-a",
            &graph_sha256,
        ),
        continuation_token(
            "continuation-child-b",
            "task-child-b",
            "route-child-b",
            &graph_sha256,
        ),
    ];
    task_graph.nodes[1].continuation_token_ref = Some(continuation_tokens[0].token_id.clone());
    task_graph.nodes[2].continuation_token_ref = Some(continuation_tokens[1].token_id.clone());

    let witness_chains = vec![
        witness_chain(
            "witness-child-a",
            "task-root",
            "task-child-a",
            &parent_scope_hash,
            &child_scope_hash,
            witness.clone(),
        ),
        witness_chain(
            "witness-child-b",
            "task-root",
            "task-child-b",
            &parent_scope_hash,
            &child_scope_hash,
            witness,
        ),
    ];

    Ok(SwarmAuthorityBundle {
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts: vec![SwarmJoinReceipt {
            schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
            join_id: "join-child-results".to_string(),
            graph_id: "swarm-graph-proof-valid".to_string(),
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
        }],
        route_plan_receipts: vec![
            route_plan_receipt("route-child-a", "task-child-a", "mcp", "mcp://provider-a"),
            route_plan_receipt("route-child-b", "task-child-b", "a2a", "a2a://provider-b"),
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
                    max_units: 2_500,
                },
                SwarmBudgetAllocation {
                    allocation_id: "budget-child-b".to_string(),
                    task_id: "task-child-b".to_string(),
                    max_units: 2_500,
                },
            ],
        },
        revocation_epoch: SwarmRevocationEpoch {
            schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
            epoch_id: "revocation-epoch-swarm-valid".to_string(),
            root_hash: sha256_hex(b"revocation-root"),
            issued_at_unix_ms: NOW_UNIX_MS - 1_000,
            valid_until_unix_ms: NOW_UNIX_MS + 60_000,
            revoked_subjects: Vec::new(),
            revoked_task_ids: Vec::new(),
        },
        now_unix_ms: NOW_UNIX_MS,
    })
}

fn continuation_token(
    token_id: &str,
    child_task_id: &str,
    route_plan_receipt_id: &str,
    graph_sha256: &str,
) -> SwarmContinuationToken {
    SwarmContinuationToken {
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
        revocation_epoch_ref: "revocation-epoch-swarm-valid".to_string(),
        session_anchor_ref: "session-anchor-swarm-valid".to_string(),
        nonce: format!("nonce-{child_task_id}"),
        mode: SwarmContinuationMode::SingleUse,
        issued_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
    }
}

fn witness_chain(
    chain_id: &str,
    parent_task_id: &str,
    child_task_id: &str,
    parent_scope_hash: &str,
    child_scope_hash: &str,
    scope_subset_proof: chio_core_types::capability::attenuation::AttenuationWitness,
) -> SwarmDelegationWitnessChain {
    SwarmDelegationWitnessChain {
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
            issuer: "did:chio:authority".to_string(),
            policy_digest: sha256_hex(b"swarm-policy"),
            witness_signature: format!("sig-{chain_id}"),
        }],
    }
}

fn route_plan_receipt(
    route_plan_id: &str,
    task_id: &str,
    bridge_id: &str,
    protocol_target: &str,
) -> SwarmRoutePlanReceipt {
    SwarmRoutePlanReceipt {
        schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.to_string(),
        route_plan_id: route_plan_id.to_string(),
        graph_id: "swarm-graph-proof-valid".to_string(),
        task_id: task_id.to_string(),
        selected_route: format!("{bridge_id}:{task_id}"),
        candidate_set_digest: sha256_hex(format!("candidates-{task_id}").as_bytes()),
        registry_snapshot_hash: sha256_hex(b"registry-snapshot"),
        bridge_id: bridge_id.to_string(),
        protocol_target: protocol_target.to_string(),
        egress_constraints: vec!["deny-private-network".to_string()],
        attenuation_decision: "accepted".to_string(),
        policy_digest: sha256_hex(b"swarm-route-policy"),
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
    }
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

fn refresh_continuation_graph_digests(
    bundle: &mut SwarmAuthorityBundle,
) -> Result<(), Box<dyn Error>> {
    let graph_sha256 = canonical_hash(&bundle.task_graph)?;
    for token in &mut bundle.continuation_tokens {
        token.graph_sha256 = graph_sha256.clone();
    }
    Ok(())
}
