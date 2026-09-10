//! Construct a signed execution graph from real issued capabilities. Completion
//! receipts are added only after the corresponding work has returned.
use crate::*;
use chio_core_types::{
    capability::{
        attenuation::{compute_attenuation_witness, scope_hash},
        token::CapabilityToken,
    },
    crypto::{canonical_json_bytes, sha256_hex, Keypair},
};
use serde::Serialize;

pub struct SwarmFanoutTask {
    pub task_id: String,
    pub capability: CapabilityToken,
    pub protocol_target: String,
    pub reserved_units: u64,
}
pub struct SwarmFanoutRequest {
    pub graph_id: String,
    pub root_transaction_ref: String,
    pub parent_receipt_id: String,
    pub session_anchor: String,
    pub parent: CapabilityToken,
    pub tasks: Vec<SwarmFanoutTask>,
    pub policy_digest: String,
    pub now_unix_ms: u64,
    pub lifetime_ms: u64,
}
fn reject(message: &str) -> SwarmAuthorityError {
    SwarmAuthorityError::Rejected(message.into())
}
fn digest(value: &impl Serialize) -> Result<String, SwarmAuthorityError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|e| SwarmAuthorityError::Canonical(e.to_string()))
}

/// Create a one-level fanout with single-use child continuations and an
/// all-success join back to the coordinator. Keys remain with the issuer.
pub fn mint_swarm_fanout(
    request: SwarmFanoutRequest,
    issuer: &Keypair,
) -> Result<SwarmAuthorityBundle, SwarmAuthorityError> {
    if request.tasks.len() < 2 || request.tasks.len() > 32 {
        return Err(reject("fanout requires 2 to 32 tasks"));
    }
    if request.parent_receipt_id.is_empty()
        || request.session_anchor.is_empty()
        || request.lifetime_ms == 0
        || request.lifetime_ms > 900_000
    {
        return Err(reject(
            "fanout requires a parent receipt, session anchor, and lifetime of at most 15 minutes",
        ));
    }
    if request.parent.issuer != issuer.public_key()
        || !request
            .parent
            .verify_signature()
            .map_err(|e| SwarmAuthorityError::Canonical(e.to_string()))?
    {
        return Err(reject(
            "fanout parent must be issued by the selected signer",
        ));
    }
    let expires = request
        .now_unix_ms
        .checked_add(request.lifetime_ms)
        .ok_or_else(|| reject("fanout expiry overflow"))?
        .min(request.parent.expires_at.saturating_mul(1000));
    if expires <= request.now_unix_ms {
        return Err(reject("fanout parent expired"));
    }
    let did = format!("did:chio:{}", issuer.public_key().to_hex());
    let root = format!("{}:root", request.graph_id);
    let pool_id = format!("{}:budget", request.graph_id);
    let epoch_id = format!("{}:epoch", request.graph_id);
    let parent_scope = scope_hash(&request.parent.scope)
        .map_err(|e| SwarmAuthorityError::Canonical(e.to_string()))?;
    let mut nodes = vec![SwarmGraphNode {
        task_id: root.clone(),
        parent_task_id: None,
        route_plan_ref: None,
        continuation_token_ref: None,
        budget_allocation_ref: None,
        scope_hash: parent_scope.clone(),
        depth: 0,
    }];
    let mut edges = Vec::new();
    let mut routes = Vec::new();
    let mut chains = Vec::new();
    let mut allocations = Vec::new();
    let mut child_ids = Vec::new();
    let mut total = 0u64;
    let registry = digest(
        &request
            .tasks
            .iter()
            .map(|task| (&task.task_id, &task.protocol_target))
            .collect::<Vec<_>>(),
    )?;
    for task in &request.tasks {
        if task.task_id == root || child_ids.contains(&task.task_id) || task.reserved_units == 0 {
            return Err(reject(
                "fanout task IDs must be distinct and allocations nonzero",
            ));
        }
        if task.capability.issuer != issuer.public_key()
            || !task
                .capability
                .verify_signature()
                .map_err(|e| SwarmAuthorityError::Canonical(e.to_string()))?
        {
            return Err(reject(
                "fanout child must carry a valid capability from the selected issuer",
            ));
        }
        if task.capability.expires_at.saturating_mul(1000) < expires {
            return Err(reject("fanout cannot outlive a child capability"));
        }
        let proof = compute_attenuation_witness(&request.parent.scope, &task.capability.scope)
            .map_err(|e| SwarmAuthorityError::Canonical(e.to_string()))?;
        let child_scope = scope_hash(&task.capability.scope)
            .map_err(|e| SwarmAuthorityError::Canonical(e.to_string()))?;
        let route_id = format!("{}:route", task.task_id);
        let continuation_id = format!("{}:continuation", task.task_id);
        let allocation_id = format!("{}:allocation", task.task_id);
        let bridge = task
            .protocol_target
            .split_once("://")
            .map(|(bridge, _)| bridge)
            .ok_or_else(|| reject("route target requires a protocol scheme"))?;
        nodes.push(SwarmGraphNode {
            task_id: task.task_id.clone(),
            parent_task_id: Some(root.clone()),
            route_plan_ref: Some(route_id.clone()),
            continuation_token_ref: Some(continuation_id),
            budget_allocation_ref: Some(allocation_id.clone()),
            scope_hash: child_scope.clone(),
            depth: 1,
        });
        edges.push(SwarmGraphEdge {
            from_task_id: root.clone(),
            to_task_id: task.task_id.clone(),
            edge_type: "delegates".into(),
        });
        let mut route = SwarmRoutePlanReceipt {
            schema: CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA.into(),
            route_plan_id: route_id,
            graph_id: request.graph_id.clone(),
            task_id: task.task_id.clone(),
            selected_route: format!("{bridge}:{}", task.task_id),
            candidate_set_digest: digest(&vec![&task.protocol_target])?,
            registry_snapshot_hash: registry.clone(),
            bridge_id: bridge.into(),
            protocol_target: task.protocol_target.clone(),
            egress_contract_id: format!("{bridge}:{}:egress", task.task_id),
            egress_constraints: vec!["deny-private-network".into()],
            attenuation_decision: "accepted".into(),
            policy_digest: request.policy_digest.clone(),
            expires_at_unix_ms: expires,
            issuer: did.clone(),
            signature: String::new(),
        };
        route.signature = sign_swarm_route_plan_receipt(&route, issuer)?;
        routes.push(route);
        let mut chain = SwarmDelegationWitnessChain {
            schema: CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA.into(),
            chain_id: format!("{}:witness", task.task_id),
            graph_id: request.graph_id.clone(),
            parent_task_id: root.clone(),
            child_task_id: task.task_id.clone(),
            hops: vec![SwarmDelegationWitnessHop {
                parent_capability_digest: digest(&request.parent)?,
                child_capability_digest: digest(&task.capability)?,
                parent_scope_hash: parent_scope.clone(),
                child_scope_hash: child_scope,
                attenuation_rule_id: "scope-subset".into(),
                scope_subset_proof: proof,
                expires_at_unix_ms: expires,
                issuer: did.clone(),
                policy_digest: request.policy_digest.clone(),
                witness_signature: String::new(),
            }],
        };
        chain.hops[0].witness_signature =
            sign_swarm_delegation_witness_hop(&chain, &chain.hops[0], issuer)?;
        chains.push(chain);
        allocations.push(SwarmBudgetAllocation {
            allocation_id,
            task_id: task.task_id.clone(),
            dimension_id: "work_units".into(),
            state: SwarmBudgetAllocationState::Active,
            max_units: task.reserved_units,
            reserved_units: 0,
            active_units: task.reserved_units,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
        });
        total = total
            .checked_add(task.reserved_units)
            .ok_or_else(|| reject("fanout budget overflow"))?;
        child_ids.push(task.task_id.clone());
    }
    let mut graph = SwarmTaskGraph {
        schema: CHIO_SWARM_TASK_GRAPH_SCHEMA.into(),
        graph_id: request.graph_id.clone(),
        root_transaction_ref: request.root_transaction_ref,
        planner_subject: format!("did:chio:{}", request.parent.subject.to_hex()),
        issuer: did.clone(),
        signature: String::new(),
        created_at_unix_ms: request.now_unix_ms,
        expires_at_unix_ms: expires,
        max_depth: 1,
        max_fanout: request.tasks.len() as u32,
        multi_hop_witness_chains: false,
        nodes,
        edges,
        joins: vec![SwarmGraphJoin {
            join_id: format!("{}:join", request.graph_id),
            parent_task_ids: child_ids,
            next_task_id: root.clone(),
        }],
        budget_pool_ref: pool_id.clone(),
        revocation_epoch_ref: epoch_id.clone(),
        route_plan_refs: routes.iter().map(|r| r.route_plan_id.clone()).collect(),
    };
    graph.signature = sign_swarm_task_graph(&graph, issuer)?;
    let mut epoch = SwarmRevocationEpoch {
        schema: CHIO_SWARM_REVOCATION_EPOCH_SCHEMA.into(),
        epoch_id: epoch_id.clone(),
        root_hash: digest(&serde_json::json!({"revokedSubjects":[],"revokedTaskIds":[]}))?,
        issued_at_unix_ms: request.now_unix_ms,
        valid_until_unix_ms: expires,
        revoked_subjects: Vec::new(),
        revoked_task_ids: Vec::new(),
        issuer: did,
        signature: String::new(),
    };
    epoch.signature = sign_swarm_revocation_epoch(&epoch, issuer)?;
    let mut tokens = Vec::new();
    for (task, chain) in request.tasks.iter().zip(&chains) {
        tokens.push(mint_swarm_continuation_token(
            SwarmContinuationTokenMintRequest {
                token_id: format!("{}:continuation", task.task_id),
                graph_id: request.graph_id.clone(),
                child_task_id: task.task_id.clone(),
                parent_task_id: Some(root.clone()),
                join_receipt_id: None,
                parent_receipt_ids: vec![request.parent_receipt_id.clone()],
                graph_sha256: digest(&graph)?,
                route_plan_receipt_id: format!("{}:route", task.task_id),
                budget_allocation_id: format!("{}:allocation", task.task_id),
                witness_chain_ref: Some(chain.chain_id.clone()),
                witness_chain_sha256: Some(digest(chain)?),
                revocation_epoch_ref: epoch_id.clone(),
                revocation_epoch_root_hash: epoch.root_hash.clone(),
                session_anchor_ref: request.session_anchor.clone(),
                nonce: digest(&(&request.graph_id, &task.task_id, request.now_unix_ms))?,
                mode: SwarmContinuationMode::SingleUse,
                issued_at_unix_ms: request.now_unix_ms,
                expires_at_unix_ms: expires,
            },
            issuer,
        )?);
    }
    let bundle = SwarmAuthorityBundle {
        task_graph: graph,
        continuation_tokens: tokens,
        witness_chains: chains,
        join_receipts: Vec::new(),
        route_plan_receipts: routes,
        budget_pool: SwarmBudgetPool {
            schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.into(),
            pool_id,
            graph_id: request.graph_id,
            currency: "WORK".into(),
            total_units: total,
            allocations,
        },
        revocation_epoch: epoch,
        terminal_receipts: Vec::new(),
        now_unix_ms: request.now_unix_ms,
    };
    for (token, task) in bundle.continuation_tokens.iter().zip(&request.tasks) {
        verify_swarm_admission_bundle(&bundle, &token.token_id, &[issuer.public_key()])?;
        verify_swarm_admission_capability(&bundle, &token.token_id, &task.capability)?;
    }
    Ok(bundle)
}

pub struct SwarmTaskCompletion {
    pub task_id: String,
    pub receipt_id: String,
    pub consumed_units: u64,
}
/// Close the fanout after the caller has verified each worker's actual result.
/// Work units describe this graph's allocation, not external currency settlement.
pub fn complete_swarm_fanout(
    mut bundle: SwarmAuthorityBundle,
    completed: Vec<SwarmTaskCompletion>,
    result_digest: String,
    now_unix_ms: u64,
    issuer: &Keypair,
) -> Result<SwarmAuthorityBundle, SwarmAuthorityError> {
    if bundle.task_graph.joins.len() != 1
        || !bundle.join_receipts.is_empty()
        || !bundle.terminal_receipts.is_empty()
    {
        return Err(reject("complete fanout requires one unfinished join"));
    }
    let join = &bundle.task_graph.joins[0];
    let mut expected = join.parent_task_ids.clone();
    expected.sort();
    let mut actual = completed
        .iter()
        .map(|c| c.task_id.clone())
        .collect::<Vec<_>>();
    actual.sort();
    if expected != actual {
        return Err(reject(
            "fanout completion requires exactly the declared child tasks",
        ));
    }
    let receipt_ids = completed
        .iter()
        .map(|c| c.receipt_id.clone())
        .collect::<Vec<_>>();
    let chain_id = format!("swarm-chain-{}", bundle.task_graph.graph_id);
    let joined = mint_swarm_join_receipt(
        SwarmJoinReceiptMintRequest {
            join_id: join.join_id.clone(),
            graph_id: bundle.task_graph.graph_id.clone(),
            chain_id: chain_id.clone(),
            dag_ordinal: 2,
            hlc_unix_ms: now_unix_ms,
            parent_task_receipts: completed
                .iter()
                .map(|c| SwarmJoinParentReceipt {
                    task_id: c.task_id.clone(),
                    receipt_id: c.receipt_id.clone(),
                })
                .collect(),
            expected_parent_receipt_ids: receipt_ids.clone(),
            actual_parent_receipt_ids: receipt_ids,
            join_predicate: "all_success".into(),
            result_digest: result_digest.clone(),
            next_task_id: join.next_task_id.clone(),
        },
        issuer,
    )?;
    let mut consumed = 0u64;
    let mut released = 0u64;
    for allocation in &mut bundle.budget_pool.allocations {
        let completion = completed
            .iter()
            .find(|c| c.task_id == allocation.task_id)
            .ok_or_else(|| reject("completion has no budget allocation"))?;
        if completion.consumed_units > allocation.max_units {
            return Err(reject("completion exceeds its work allocation"));
        }
        allocation.consumed_units = completion.consumed_units;
        allocation.released_units = allocation.max_units - completion.consumed_units;
        allocation.active_units = 0;
        allocation.reserved_units = 0;
        allocation.state = SwarmBudgetAllocationState::Released;
        consumed = consumed
            .checked_add(allocation.consumed_units)
            .ok_or_else(|| reject("consumption overflow"))?;
        released = released
            .checked_add(allocation.released_units)
            .ok_or_else(|| reject("release overflow"))?;
    }
    let mut terminal = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.into(),
        receipt_id: format!("{}:terminal", bundle.task_graph.graph_id),
        graph_id: bundle.task_graph.graph_id.clone(),
        chain_id,
        terminal_task_ids: vec![join.next_task_id.clone()],
        completed_task_ids: bundle
            .task_graph
            .nodes
            .iter()
            .map(|n| n.task_id.clone())
            .collect(),
        join_receipt_ids: vec![joined.join_id.clone()],
        route_plan_receipt_ids: bundle
            .route_plan_receipts
            .iter()
            .map(|r| r.route_plan_id.clone())
            .collect(),
        budget_pool_id: bundle.budget_pool.pool_id.clone(),
        budget_rollups: vec![SwarmTerminalBudgetRollup {
            dimension_id: "work_units".into(),
            reserved_units: 0,
            active_units: 0,
            consumed_units: consumed,
            released_units: released,
            reversed_units: 0,
            total_units: bundle.budget_pool.total_units,
        }],
        revocation_epoch_ref: bundle.revocation_epoch.epoch_id.clone(),
        result_digest,
        completed_at_unix_ms: now_unix_ms,
        issuer: format!("did:chio:{}", issuer.public_key().to_hex()),
        signature: String::new(),
    };
    terminal.signature = sign_swarm_terminal_graph_receipt(&terminal, issuer)?;
    bundle.join_receipts.push(joined);
    bundle.terminal_receipts.push(terminal);
    bundle.now_unix_ms = now_unix_ms;
    verify_swarm_authority_bundle(&bundle, &[issuer.public_key()])?;
    Ok(bundle)
}
