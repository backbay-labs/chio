//! One swarm, verified before any child task runs.
//!
//! An orchestrator fans out to a researcher and a writer, each holding a
//! narrower scope, a route plan, a budget allocation, and a continuation
//! token bound to the signed task graph. The swarm authority verifies the
//! whole bundle, then rejects four tampered versions of it.
//!
//! Run with `cargo run -p chio-swarm-authority --example agent_os`.

use std::collections::BTreeMap;
use std::error::Error;

use chio_core_types::capability::attenuation::{
    compute_attenuation_witness, scope_hash, AttenuationWitness,
};
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_swarm_authority::{
    sign_swarm_continuation_token, sign_swarm_delegation_witness_hop, sign_swarm_join_receipt,
    sign_swarm_revocation_epoch, sign_swarm_route_plan_receipt, sign_swarm_task_graph,
    sign_swarm_terminal_graph_receipt, verify_swarm_authority_bundle, SwarmAuthorityBundle,
    SwarmBudgetAllocation, SwarmBudgetAllocationState, SwarmBudgetPool, SwarmContinuationMode,
    SwarmContinuationToken, SwarmDelegationWitnessChain, SwarmDelegationWitnessHop, SwarmGraphEdge,
    SwarmGraphJoin, SwarmGraphNode, SwarmJoinParentReceipt, SwarmJoinReceipt, SwarmRevocationEpoch,
    SwarmRoutePlanReceipt, SwarmTaskGraph, SwarmTerminalBudgetRollup, SwarmTerminalGraphReceipt,
    CHIO_SWARM_BUDGET_POOL_SCHEMA, CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
    CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA, CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
    CHIO_SWARM_REVOCATION_EPOCH_SCHEMA, CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
    CHIO_SWARM_TASK_GRAPH_SCHEMA, CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA,
};

type Fallible<T> = Result<T, Box<dyn Error>>;

const NOW_UNIX_MS: u64 = 1_800_000_001_000;
const GRAPH_ID: &str = "swarm-incident-42";
const CHAIN_ID: &str = "swarm-chain-incident-42";
const POOL_ID: &str = "budget-pool-incident-42";
const EPOCH_ID: &str = "revocation-epoch-incident-42";
const ROOT: &str = "task-orchestrator";
const CHILD_A: &str = "task-researcher";
const CHILD_B: &str = "task-writer";
const POOL_UNITS: u64 = 10_000;
const CHILD_UNITS: u64 = 2_500;

fn main() -> Fallible<()> {
    let bundle = swarm_bundle()?;

    println!("chio swarm authority  ·  one task graph, verified before any child runs");
    println!();
    println!("task graph  {GRAPH_ID}");
    for node in &bundle.task_graph.nodes {
        let route = node.route_plan_ref.as_deref().unwrap_or("-");
        let budget = bundle
            .budget_pool
            .allocations
            .iter()
            .find(|a| a.task_id == node.task_id)
            .map(|a| {
                format!(
                    "{} of {} units",
                    a.max_units, bundle.budget_pool.total_units
                )
            })
            .unwrap_or_else(|| "holds the pool".to_string());
        println!(
            "  {:<17} depth {}  scope {}  route {:<16} budget {}",
            node.task_id.trim_start_matches("task-"),
            node.depth,
            &node.scope_hash[..12],
            route,
            budget
        );
    }
    for join in &bundle.task_graph.joins {
        println!(
            "  join {} -> {}  ({})",
            join.parent_task_ids
                .iter()
                .map(|t| t.trim_start_matches("task-"))
                .collect::<Vec<_>>()
                .join(" + "),
            join.next_task_id.trim_start_matches("task-"),
            bundle.join_receipts[0].join_predicate
        );
    }
    println!();

    let report = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;
    println!(
        "verdict  {}  ({} tasks, {} continuations, {} joins, {} routes)",
        report.verdict,
        report.task_count,
        report.continuation_count,
        report.join_count,
        report.route_count
    );
    for hop in &report.hop_reports {
        println!(
            "  {:<12} continuation {:<26} witness {} ({} hop)",
            hop.child_task_id.trim_start_matches("task-"),
            hop.continuation_token_id,
            hop.witness_chain_id.as_deref().unwrap_or("-"),
            hop.witness_hop_count
        );
    }
    println!("claims   {}", report.verified_claims.join(", "));
    println!();

    println!("then someone tries to");
    reject("add an edge from the writer back to the orchestrator", {
        let mut b = swarm_bundle()?;
        b.task_graph.edges.push(SwarmGraphEdge {
            from_task_id: CHILD_B.to_string(),
            to_task_id: ROOT.to_string(),
            edge_type: "delegates".to_string(),
        });
        b
    });
    reject("hide a hop by understating the writer's depth", {
        let mut b = swarm_bundle()?;
        let child_scope = scope_for("tools", "fetch_report", 1);
        let child_hash = scope_hash(&child_scope)?;
        b.task_graph.max_depth = 1;
        b.task_graph.nodes[2].parent_task_id = Some(CHILD_A.to_string());
        b.task_graph.nodes[2].depth = 1;
        b.task_graph.edges[1].from_task_id = CHILD_A.to_string();
        b.continuation_tokens[1].parent_task_id = Some(CHILD_A.to_string());
        b.witness_chains[1] = witness_chain(
            "witness-writer",
            CHILD_A,
            CHILD_B,
            &child_hash,
            &child_hash,
            compute_attenuation_witness(&child_scope, &child_scope)?,
        )?;
        refresh_continuation_graph_digests(&mut b)?;
        b
    });
    reject("allocate 5,000 units out of a 100 unit pool", {
        let mut b = swarm_bundle()?;
        b.budget_pool.total_units = 100;
        b
    });
    reject("run the researcher after its task was revoked", {
        let mut b = swarm_bundle()?;
        b.revocation_epoch
            .revoked_task_ids
            .push(CHILD_A.to_string());
        refresh_revocation_epoch_root(&mut b)?;
        b
    });
    Ok(())
}

fn reject(attempt: &str, bundle: SwarmAuthorityBundle) {
    match verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()) {
        Ok(report) => println!("  {attempt:<52} verified unexpectedly ({})", report.verdict),
        Err(error) => println!("  {attempt:<52} rejected: {error}"),
    }
}

fn swarm_bundle() -> Fallible<SwarmAuthorityBundle> {
    let parent_scope = scope_for("tools", "fetch_report", 3);
    let child_scope = scope_for("tools", "fetch_report", 1);
    let parent_hash = scope_hash(&parent_scope)?;
    let child_hash = scope_hash(&child_scope)?;
    let witness = compute_attenuation_witness(&parent_scope, &child_scope)?;

    let mut task_graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.to_string(),
        graph_id: GRAPH_ID.to_string(),
        root_transaction_ref: "passport-incident-42".to_string(),
        planner_subject: "did:chio:orchestrator".to_string(),
        issuer: witness_issuer(),
        signature: String::new(),
        created_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        max_depth: 2,
        max_fanout: 2,
        multi_hop_witness_chains: false,
        nodes: vec![
            node(ROOT, None, &parent_hash, 0),
            node(CHILD_A, Some(ROOT), &child_hash, 1),
            node(CHILD_B, Some(ROOT), &child_hash, 1),
        ],
        edges: vec![edge(ROOT, CHILD_A), edge(ROOT, CHILD_B)],
        joins: vec![SwarmGraphJoin {
            join_id: "join-drafts".to_string(),
            parent_task_ids: vec![CHILD_A.to_string(), CHILD_B.to_string()],
            next_task_id: ROOT.to_string(),
        }],
        budget_pool_ref: POOL_ID.to_string(),
        revocation_epoch_ref: EPOCH_ID.to_string(),
        route_plan_refs: vec!["route-researcher".to_string(), "route-writer".to_string()],
    };
    task_graph.signature = sign_swarm_task_graph(&task_graph, &witness_keypair())?;
    let graph_sha256 = canonical_hash(&task_graph)?;
    let epoch_root = revocation_epoch_root_hash(&[], &[])?;

    let witness_chains = vec![
        witness_chain(
            "witness-researcher",
            ROOT,
            CHILD_A,
            &parent_hash,
            &child_hash,
            witness.clone(),
        )?,
        witness_chain(
            "witness-writer",
            ROOT,
            CHILD_B,
            &parent_hash,
            &child_hash,
            witness,
        )?,
    ];
    let continuation_tokens = vec![
        continuation_token(
            "continuation-researcher",
            CHILD_A,
            "route-researcher",
            &graph_sha256,
            &epoch_root,
            &witness_chains[0],
        )?,
        continuation_token(
            "continuation-writer",
            CHILD_B,
            "route-writer",
            &graph_sha256,
            &epoch_root,
            &witness_chains[1],
        )?,
    ];

    let mut join = SwarmJoinReceipt {
        schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
        join_id: "join-drafts".to_string(),
        graph_id: GRAPH_ID.to_string(),
        chain_id: CHAIN_ID.to_string(),
        parent_set_hash: join_parent_set_hash(CHAIN_ID, &["receipt-researcher", "receipt-writer"])?,
        dag_ordinal: 2,
        hlc_unix_ms: NOW_UNIX_MS - 500,
        parent_task_receipts: vec![
            SwarmJoinParentReceipt {
                task_id: CHILD_A.to_string(),
                receipt_id: "receipt-researcher".to_string(),
            },
            SwarmJoinParentReceipt {
                task_id: CHILD_B.to_string(),
                receipt_id: "receipt-writer".to_string(),
            },
        ],
        expected_parent_receipt_ids: vec![
            "receipt-researcher".to_string(),
            "receipt-writer".to_string(),
        ],
        actual_parent_receipt_ids: vec![
            "receipt-researcher".to_string(),
            "receipt-writer".to_string(),
        ],
        join_predicate: "all_success".to_string(),
        result_digest: sha256_hex(b"joined-drafts"),
        next_task_id: ROOT.to_string(),
        issuer: witness_issuer(),
        signature: String::new(),
    };
    join.signature = sign_swarm_join_receipt(&join, &witness_keypair())?;

    let mut epoch = SwarmRevocationEpoch {
        schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.to_string(),
        epoch_id: EPOCH_ID.to_string(),
        root_hash: epoch_root,
        issued_at_unix_ms: NOW_UNIX_MS - 1_000,
        valid_until_unix_ms: NOW_UNIX_MS + 60_000,
        revoked_subjects: vec![],
        revoked_task_ids: vec![],
        issuer: witness_issuer(),
        signature: String::new(),
    };
    epoch.signature = sign_swarm_revocation_epoch(&epoch, &witness_keypair())?;

    Ok(SwarmAuthorityBundle {
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts: vec![join],
        route_plan_receipts: vec![
            route_plan_receipt("route-researcher", CHILD_A, "mcp", "mcp://provider-a")?,
            route_plan_receipt("route-writer", CHILD_B, "a2a", "a2a://provider-b")?,
        ],
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
            pool_id: POOL_ID.to_string(),
            graph_id: GRAPH_ID.to_string(),
            currency: "USD".to_string(),
            total_units: POOL_UNITS,
            allocations: vec![
                allocation("budget-researcher", CHILD_A),
                allocation("budget-writer", CHILD_B),
            ],
        },
        revocation_epoch: epoch,
        terminal_receipts: vec![terminal_graph_receipt()?],
        now_unix_ms: NOW_UNIX_MS,
    })
}

fn node(task_id: &str, parent: Option<&str>, scope: &str, depth: u32) -> SwarmGraphNode {
    let short = task_id.trim_start_matches("task-");
    SwarmGraphNode {
        task_id: task_id.to_string(),
        parent_task_id: parent.map(str::to_string),
        route_plan_ref: parent.map(|_| format!("route-{short}")),
        continuation_token_ref: parent.map(|_| format!("continuation-{short}")),
        budget_allocation_ref: parent.map(|_| format!("budget-{short}")),
        scope_hash: scope.to_string(),
        depth,
    }
}

fn edge(from: &str, to: &str) -> SwarmGraphEdge {
    SwarmGraphEdge {
        from_task_id: from.to_string(),
        to_task_id: to.to_string(),
        edge_type: "delegates".to_string(),
    }
}

fn allocation(id: &str, task_id: &str) -> SwarmBudgetAllocation {
    SwarmBudgetAllocation {
        allocation_id: id.to_string(),
        task_id: task_id.to_string(),
        dimension_id: "usd_minor".to_string(),
        state: SwarmBudgetAllocationState::Active,
        max_units: CHILD_UNITS,
        reserved_units: 0,
        active_units: CHILD_UNITS,
        consumed_units: 0,
        released_units: 0,
        reversed_units: 0,
    }
}

fn continuation_token(
    token_id: &str,
    child_task_id: &str,
    route_plan_receipt_id: &str,
    graph_sha256: &str,
    epoch_root: &str,
    chain: &SwarmDelegationWitnessChain,
) -> Fallible<SwarmContinuationToken> {
    let mut token = SwarmContinuationToken {
        schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.to_string(),
        token_id: token_id.to_string(),
        graph_id: GRAPH_ID.to_string(),
        child_task_id: child_task_id.to_string(),
        parent_task_id: Some(ROOT.to_string()),
        join_receipt_id: None,
        parent_receipt_ids: vec!["receipt-orchestrator".to_string()],
        graph_sha256: graph_sha256.to_string(),
        route_plan_receipt_id: route_plan_receipt_id.to_string(),
        budget_allocation_id: format!("budget-{}", child_task_id.trim_start_matches("task-")),
        witness_chain_ref: Some(chain.chain_id.clone()),
        witness_chain_sha256: Some(canonical_hash(chain)?),
        revocation_epoch_ref: EPOCH_ID.to_string(),
        revocation_epoch_root_hash: epoch_root.to_string(),
        session_anchor_ref: "session-anchor-incident-42".to_string(),
        nonce: format!("nonce-{child_task_id}"),
        mode: SwarmContinuationMode::SingleUse,
        issued_at_unix_ms: NOW_UNIX_MS - 1_000,
        expires_at_unix_ms: NOW_UNIX_MS + 60_000,
        issuer: witness_issuer(),
        signature: String::new(),
    };
    token.signature = sign_swarm_continuation_token(&token, &witness_keypair())?;
    Ok(token)
}

fn witness_chain(
    chain_id: &str,
    parent_task_id: &str,
    child_task_id: &str,
    parent_scope_hash: &str,
    child_scope_hash: &str,
    scope_subset_proof: AttenuationWitness,
) -> Fallible<SwarmDelegationWitnessChain> {
    let mut chain = SwarmDelegationWitnessChain {
        schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.to_string(),
        chain_id: chain_id.to_string(),
        graph_id: GRAPH_ID.to_string(),
        parent_task_id: parent_task_id.to_string(),
        child_task_id: child_task_id.to_string(),
        hops: vec![SwarmDelegationWitnessHop {
            parent_capability_digest: sha256_hex(parent_task_id.as_bytes()),
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
    let keypair = witness_keypair();
    for index in 0..chain.hops.len() {
        let signature = sign_swarm_delegation_witness_hop(&chain, &chain.hops[index], &keypair)?;
        chain.hops[index].witness_signature = signature;
    }
    Ok(chain)
}

fn route_plan_receipt(
    route_plan_id: &str,
    task_id: &str,
    bridge_id: &str,
    protocol_target: &str,
) -> Fallible<SwarmRoutePlanReceipt> {
    let mut receipt = SwarmRoutePlanReceipt {
        schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.to_string(),
        route_plan_id: route_plan_id.to_string(),
        graph_id: GRAPH_ID.to_string(),
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
    receipt.signature = sign_swarm_route_plan_receipt(&receipt, &witness_keypair())?;
    Ok(receipt)
}

fn terminal_graph_receipt() -> Fallible<SwarmTerminalGraphReceipt> {
    let mut receipt = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.to_string(),
        receipt_id: "terminal-incident-42".to_string(),
        graph_id: GRAPH_ID.to_string(),
        chain_id: CHAIN_ID.to_string(),
        terminal_task_ids: vec![ROOT.to_string()],
        completed_task_ids: vec![ROOT.to_string(), CHILD_A.to_string(), CHILD_B.to_string()],
        join_receipt_ids: vec!["join-drafts".to_string()],
        route_plan_receipt_ids: vec!["route-researcher".to_string(), "route-writer".to_string()],
        budget_pool_id: POOL_ID.to_string(),
        budget_rollups: vec![SwarmTerminalBudgetRollup {
            dimension_id: "usd_minor".to_string(),
            reserved_units: 0,
            active_units: CHILD_UNITS * 2,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
            total_units: CHILD_UNITS * 2,
        }],
        revocation_epoch_ref: EPOCH_ID.to_string(),
        result_digest: sha256_hex(b"joined-drafts"),
        completed_at_unix_ms: NOW_UNIX_MS,
        issuer: witness_issuer(),
        signature: String::new(),
    };
    receipt.signature = sign_swarm_terminal_graph_receipt(&receipt, &witness_keypair())?;
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

fn canonical_hash<T: serde::Serialize>(value: &T) -> Fallible<String> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn join_parent_set_hash(chain_id: &str, receipt_ids: &[&str]) -> Fallible<String> {
    let mut sorted = receipt_ids.to_vec();
    sorted.sort_unstable();
    canonical_hash(&serde_json::json!({ "chainId": chain_id, "parentReceiptIds": sorted }))
}

fn revocation_epoch_root_hash(
    revoked_subjects: &[String],
    revoked_task_ids: &[String],
) -> Fallible<String> {
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
    canonical_hash(&serde_json::json!({ "revokedSubjects": subjects, "revokedTaskIds": task_ids }))
}

fn refresh_revocation_epoch_root(bundle: &mut SwarmAuthorityBundle) -> Fallible<()> {
    let root_hash = revocation_epoch_root_hash(
        &bundle.revocation_epoch.revoked_subjects,
        &bundle.revocation_epoch.revoked_task_ids,
    )?;
    bundle.revocation_epoch.root_hash = root_hash.clone();
    bundle.revocation_epoch.signature =
        sign_swarm_revocation_epoch(&bundle.revocation_epoch, &witness_keypair())?;
    for token in &mut bundle.continuation_tokens {
        token.revocation_epoch_root_hash = root_hash.clone();
        token.signature = sign_swarm_continuation_token(token, &witness_keypair())?;
    }
    Ok(())
}

fn refresh_continuation_graph_digests(bundle: &mut SwarmAuthorityBundle) -> Fallible<()> {
    bundle.task_graph.signature = sign_swarm_task_graph(&bundle.task_graph, &witness_keypair())?;
    let graph_sha256 = canonical_hash(&bundle.task_graph)?;
    let mut bindings = BTreeMap::new();
    for chain in &bundle.witness_chains {
        bindings.insert(
            (chain.parent_task_id.clone(), chain.child_task_id.clone()),
            (chain.chain_id.clone(), canonical_hash(chain)?),
        );
    }
    for token in &mut bundle.continuation_tokens {
        token.graph_sha256 = graph_sha256.clone();
        if let Some(parent) = token.parent_task_id.clone() {
            if let Some((chain_id, chain_sha256)) =
                bindings.get(&(parent, token.child_task_id.clone()))
            {
                token.witness_chain_ref = Some(chain_id.clone());
                token.witness_chain_sha256 = Some(chain_sha256.clone());
            }
        }
        token.signature = sign_swarm_continuation_token(token, &witness_keypair())?;
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
