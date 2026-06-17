use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::capability::attenuation::{validate_attenuation_proof, AttenuationWitness};

use crate::error::SwarmAuthorityError;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};
use serde::Serialize;

use super::types::{
    SwarmAuthorityBundle, SwarmAuthorityVerifierReport, SwarmBudgetAllocation,
    SwarmContinuationToken, SwarmDelegationWitnessChain, SwarmGraphEdge, SwarmGraphJoin,
    SwarmGraphNode, SwarmJoinReceipt, SwarmRoutePlanReceipt, SwarmTaskGraph,
    CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_SCHEMA, CHIO_SWARM_BUDGET_POOL_SCHEMA,
    CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA, CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA,
    CHIO_SWARM_JOIN_RECEIPT_SCHEMA, CHIO_SWARM_REVOCATION_EPOCH_SCHEMA,
    CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA, CHIO_SWARM_TASK_GRAPH_SCHEMA,
    CLAIM_SWARM_ATTENUATION_WITNESS_CHAIN_BOUND, CLAIM_SWARM_BUDGET_POOL_BOUND,
    CLAIM_SWARM_CONTINUATION_FRESH, CLAIM_SWARM_JOIN_RECEIPT_BOUND,
    CLAIM_SWARM_REVOCATION_EPOCH_BOUND, CLAIM_SWARM_ROUTE_PLAN_BOUND, CLAIM_SWARM_TASK_GRAPH_BOUND,
};

const CHIO_SWARM_DELEGATION_WITNESS_HOP_SIGNATURE_SCHEMA: &str =
    "chio.swarm.delegation-witness-hop-signature.v1";
const DID_CHIO_PREFIX: &str = "did:chio:";

pub fn verify_swarm_authority_bundle(
    bundle: &SwarmAuthorityBundle,
) -> Result<SwarmAuthorityVerifierReport, SwarmAuthorityError> {
    validate_task_graph(&bundle.task_graph, bundle.now_unix_ms)?;
    let graph_sha256 = canonical_sha256(&bundle.task_graph)?;
    let task_by_id = task_index(&bundle.task_graph)?;
    let edge_set = edge_set(&bundle.task_graph.edges);
    let route_by_id = validate_route_plan_receipts(bundle, &task_by_id)?;
    let join_by_id = validate_join_receipts(bundle, &task_by_id)?;
    let allocation_by_id = validate_budget_pool(bundle, &task_by_id)?;
    validate_revocation_epoch(bundle, &task_by_id)?;
    validate_continuation_tokens(
        bundle,
        &graph_sha256,
        &task_by_id,
        &edge_set,
        &route_by_id,
        &join_by_id,
        &allocation_by_id,
    )?;
    validate_witness_chains(bundle, &task_by_id, &edge_set)?;

    let mut verified_claims = vec![CLAIM_SWARM_TASK_GRAPH_BOUND.to_string()];
    if !bundle.continuation_tokens.is_empty() {
        verified_claims.push(CLAIM_SWARM_CONTINUATION_FRESH.to_string());
    }
    if !bundle.witness_chains.is_empty() {
        verified_claims.push(CLAIM_SWARM_ATTENUATION_WITNESS_CHAIN_BOUND.to_string());
    }
    if !bundle.route_plan_receipts.is_empty() {
        verified_claims.push(CLAIM_SWARM_ROUTE_PLAN_BOUND.to_string());
    }
    if !bundle.join_receipts.is_empty() {
        verified_claims.push(CLAIM_SWARM_JOIN_RECEIPT_BOUND.to_string());
    }
    verified_claims.push(CLAIM_SWARM_BUDGET_POOL_BOUND.to_string());
    verified_claims.push(CLAIM_SWARM_REVOCATION_EPOCH_BOUND.to_string());

    Ok(SwarmAuthorityVerifierReport {
        schema: CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_SCHEMA.to_string(),
        id: format!(
            "swarm-authority-verifier-report-{}",
            bundle.task_graph.graph_id
        ),
        verdict: "verified".to_string(),
        graph_id: bundle.task_graph.graph_id.clone(),
        task_count: bundle.task_graph.nodes.len(),
        continuation_count: bundle.continuation_tokens.len(),
        join_count: bundle.join_receipts.len(),
        route_count: bundle.route_plan_receipts.len(),
        verified_claims,
    })
}

pub fn sign_swarm_delegation_witness_hop(
    chain: &SwarmDelegationWitnessChain,
    hop: &super::types::SwarmDelegationWitnessHop,
    keypair: &Keypair,
) -> Result<String, SwarmAuthorityError> {
    let issuer_public_key = witness_issuer_public_key(&hop.issuer).map_err(|error| {
        rejected(format!(
            "swarm witness issuer public key invalid: {}",
            error.runtime_detail()
        ))
    })?;
    if issuer_public_key != keypair.public_key() {
        return Err(rejected(format!(
            "swarm witness signer does not match issuer: {}",
            chain.chain_id
        )));
    }
    let body = witness_signature_body(chain, hop);
    let (signature, _canonical) = keypair
        .sign_canonical(&body)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(signature.to_hex())
}

fn validate_task_graph(
    graph: &SwarmTaskGraph,
    now_unix_ms: u64,
) -> Result<(), SwarmAuthorityError> {
    if graph.schema != CHIO_SWARM_TASK_GRAPH_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm task graph schema: {}",
            graph.schema
        )));
    }
    require_non_empty(&graph.graph_id, "swarm graph id")?;
    require_non_empty(&graph.root_transaction_ref, "swarm root transaction ref")?;
    require_non_empty(&graph.planner_subject, "swarm planner subject")?;
    require_non_empty(&graph.issuer, "swarm issuer")?;
    require_non_empty(&graph.budget_pool_ref, "swarm budget pool ref")?;
    require_non_empty(&graph.revocation_epoch_ref, "swarm revocation epoch ref")?;
    if graph.expires_at_unix_ms <= now_unix_ms {
        return Err(rejected("swarm task graph is expired"));
    }
    if graph.nodes.is_empty() {
        return Err(rejected("swarm task graph requires at least one task"));
    }
    if graph.max_fanout == 0 {
        return Err(rejected("swarm task graph max_fanout must be positive"));
    }

    let task_by_id = task_index(graph)?;
    let edge_set = edge_set(&graph.edges);
    validate_roots(graph)?;
    validate_edges(graph, &task_by_id, &edge_set)?;
    validate_joins(graph, &task_by_id)?;
    validate_route_refs(graph)?;
    validate_acyclic(graph, &task_by_id)?;
    validate_edge_depths(graph, &task_by_id)?;
    validate_graph_limits(graph)?;
    Ok(())
}

fn task_index(
    graph: &SwarmTaskGraph,
) -> Result<BTreeMap<&str, &SwarmGraphNode>, SwarmAuthorityError> {
    let mut tasks = BTreeMap::new();
    for node in &graph.nodes {
        require_non_empty(&node.task_id, "swarm task id")?;
        require_non_empty(&node.scope_hash, "swarm task scope hash")?;
        require_sha256(&node.scope_hash, "swarm task scope hash")?;
        if tasks.insert(node.task_id.as_str(), node).is_some() {
            return Err(rejected(format!(
                "duplicate swarm task id: {}",
                node.task_id
            )));
        }
    }
    Ok(tasks)
}

fn edge_set(edges: &[SwarmGraphEdge]) -> BTreeSet<(&str, &str)> {
    edges
        .iter()
        .map(|edge| (edge.from_task_id.as_str(), edge.to_task_id.as_str()))
        .collect()
}

fn validate_roots(graph: &SwarmTaskGraph) -> Result<(), SwarmAuthorityError> {
    let root_count = graph
        .nodes
        .iter()
        .filter(|node| node.parent_task_id.is_none() && node.depth == 0)
        .count();
    if root_count != 1 {
        return Err(rejected("swarm task graph requires exactly one root task"));
    }
    for node in &graph.nodes {
        if node.depth == 0 && node.parent_task_id.is_some() {
            return Err(rejected(format!(
                "swarm root-depth task has parent: {}",
                node.task_id
            )));
        }
        if node.depth > 0 && node.parent_task_id.is_none() {
            return Err(rejected(format!(
                "swarm non-root task missing parent: {}",
                node.task_id
            )));
        }
    }
    Ok(())
}

fn validate_edges(
    graph: &SwarmTaskGraph,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    edge_set: &BTreeSet<(&str, &str)>,
) -> Result<(), SwarmAuthorityError> {
    for edge in &graph.edges {
        require_non_empty(&edge.from_task_id, "swarm edge source")?;
        require_non_empty(&edge.to_task_id, "swarm edge target")?;
        require_non_empty(&edge.edge_type, "swarm edge type")?;
        if !task_by_id.contains_key(edge.from_task_id.as_str()) {
            return Err(rejected(format!(
                "unknown swarm edge source: {}",
                edge.from_task_id
            )));
        }
        if !task_by_id.contains_key(edge.to_task_id.as_str()) {
            return Err(rejected(format!(
                "unknown swarm edge target: {}",
                edge.to_task_id
            )));
        }
    }
    if edge_set.len() != graph.edges.len() {
        return Err(rejected("duplicate swarm task graph edge"));
    }
    for node in &graph.nodes {
        if let Some(parent_task_id) = &node.parent_task_id {
            if !edge_set.contains(&(parent_task_id.as_str(), node.task_id.as_str())) {
                return Err(rejected(format!(
                    "swarm task parent edge missing: {} -> {}",
                    parent_task_id, node.task_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_edge_depths(
    graph: &SwarmTaskGraph,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<(), SwarmAuthorityError> {
    for edge in &graph.edges {
        let Some(parent) = task_by_id.get(edge.from_task_id.as_str()) else {
            return Err(rejected(format!(
                "unknown swarm edge source: {}",
                edge.from_task_id
            )));
        };
        let Some(child) = task_by_id.get(edge.to_task_id.as_str()) else {
            return Err(rejected(format!(
                "unknown swarm edge target: {}",
                edge.to_task_id
            )));
        };
        let expected_child_depth = parent
            .depth
            .checked_add(1)
            .ok_or_else(|| rejected("swarm task depth overflow"))?;
        if child.depth != expected_child_depth {
            return Err(rejected(format!(
                "swarm task depth mismatch: {} -> {}",
                edge.from_task_id, edge.to_task_id
            )));
        }
    }
    Ok(())
}

fn validate_graph_limits(graph: &SwarmTaskGraph) -> Result<(), SwarmAuthorityError> {
    let mut fanout: BTreeMap<&str, u32> = BTreeMap::new();
    for node in &graph.nodes {
        if node.depth > graph.max_depth {
            return Err(rejected(format!(
                "swarm task exceeds max depth: {}",
                node.task_id
            )));
        }
    }
    for edge in &graph.edges {
        let count = fanout.entry(edge.from_task_id.as_str()).or_default();
        *count += 1;
        if *count > graph.max_fanout {
            return Err(rejected(format!(
                "swarm task exceeds max fanout: {}",
                edge.from_task_id
            )));
        }
    }
    Ok(())
}

fn validate_joins(
    graph: &SwarmTaskGraph,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<(), SwarmAuthorityError> {
    let mut join_ids = BTreeSet::new();
    for join in &graph.joins {
        require_non_empty(&join.join_id, "swarm join id")?;
        require_non_empty(&join.next_task_id, "swarm join next task id")?;
        if !join_ids.insert(join.join_id.as_str()) {
            return Err(rejected(format!(
                "duplicate swarm join id: {}",
                join.join_id
            )));
        }
        if join.parent_task_ids.is_empty() {
            return Err(rejected(format!(
                "swarm join requires parents: {}",
                join.join_id
            )));
        }
        if join.parent_task_ids.len() < 2 {
            return Err(rejected(format!(
                "swarm join requires at least two parents: {}",
                join.join_id
            )));
        }
        if !task_by_id.contains_key(join.next_task_id.as_str()) {
            return Err(rejected(format!(
                "swarm join next task is unknown: {}",
                join.next_task_id
            )));
        }
        require_unique_strings(&join.parent_task_ids, "swarm join parent task")?;
        for parent_task_id in &join.parent_task_ids {
            if parent_task_id == &join.next_task_id {
                return Err(rejected(format!(
                    "swarm join next task is a parent: {}",
                    join.join_id
                )));
            }
            if !task_by_id.contains_key(parent_task_id.as_str()) {
                return Err(rejected(format!(
                    "swarm join parent task is unknown: {parent_task_id}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_route_refs(graph: &SwarmTaskGraph) -> Result<(), SwarmAuthorityError> {
    require_unique_strings(&graph.route_plan_refs, "swarm route plan ref")?;
    for route_plan_ref in &graph.route_plan_refs {
        require_non_empty(route_plan_ref, "swarm route plan ref")?;
    }
    Ok(())
}

fn validate_acyclic(
    graph: &SwarmTaskGraph,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<(), SwarmAuthorityError> {
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &graph.edges {
        adjacency
            .entry(edge.from_task_id.as_str())
            .or_default()
            .push(edge.to_task_id.as_str());
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for task_id in task_by_id.keys() {
        visit_task(task_id, &adjacency, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit_task<'a>(
    task_id: &'a str,
    adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
    visiting: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), SwarmAuthorityError> {
    if visited.contains(task_id) {
        return Ok(());
    }
    if !visiting.insert(task_id) {
        return Err(rejected(format!("swarm task graph cycle at {task_id}")));
    }
    if let Some(children) = adjacency.get(task_id) {
        for child in children {
            visit_task(child, adjacency, visiting, visited)?;
        }
    }
    visiting.remove(task_id);
    visited.insert(task_id);
    Ok(())
}

fn validate_route_plan_receipts<'a>(
    bundle: &'a SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<BTreeMap<&'a str, &'a SwarmRoutePlanReceipt>, SwarmAuthorityError> {
    let mut route_plan_refs = BTreeSet::new();
    for route_plan_ref in &bundle.task_graph.route_plan_refs {
        route_plan_refs.insert(route_plan_ref.as_str());
    }

    let mut routes = BTreeMap::new();
    for route in &bundle.route_plan_receipts {
        if route.schema != CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA {
            return Err(rejected(format!(
                "unsupported swarm route-plan receipt schema: {}",
                route.schema
            )));
        }
        require_non_empty(&route.route_plan_id, "swarm route plan id")?;
        require_same_graph(&route.graph_id, &bundle.task_graph.graph_id, "route plan")?;
        require_non_empty(&route.task_id, "swarm route task id")?;
        require_non_empty(&route.selected_route, "swarm selected route")?;
        require_sha256(&route.candidate_set_digest, "swarm candidate set digest")?;
        require_sha256(
            &route.registry_snapshot_hash,
            "swarm registry snapshot hash",
        )?;
        require_non_empty(&route.bridge_id, "swarm route bridge id")?;
        require_non_empty(&route.protocol_target, "swarm route protocol target")?;
        validate_route_plan_target(route)?;
        require_non_empty(
            &route.attenuation_decision,
            "swarm route attenuation decision",
        )?;
        if route.attenuation_decision != "accepted" {
            return Err(rejected("swarm route-plan attenuation was not accepted"));
        }
        require_sha256(&route.policy_digest, "swarm route policy digest")?;
        if route.expires_at_unix_ms <= bundle.now_unix_ms {
            return Err(rejected(format!(
                "swarm route-plan receipt is stale: {}",
                route.route_plan_id
            )));
        }
        if !task_by_id.contains_key(route.task_id.as_str()) {
            return Err(rejected(format!(
                "swarm route-plan task is unknown: {}",
                route.task_id
            )));
        }
        if !route_plan_refs.contains(route.route_plan_id.as_str()) {
            return Err(rejected(format!(
                "unknown swarm route-plan ref: {}",
                route.route_plan_id
            )));
        }
        if routes.insert(route.route_plan_id.as_str(), route).is_some() {
            return Err(rejected(format!(
                "duplicate swarm route-plan receipt: {}",
                route.route_plan_id
            )));
        }
    }
    for route_plan_ref in route_plan_refs {
        if !routes.contains_key(route_plan_ref) {
            return Err(rejected(format!(
                "missing swarm route-plan receipt: {route_plan_ref}"
            )));
        }
    }
    Ok(routes)
}

fn validate_route_plan_target(route: &SwarmRoutePlanReceipt) -> Result<(), SwarmAuthorityError> {
    let selected_bridge = route
        .selected_route
        .split_once(':')
        .map(|(bridge, _)| bridge)
        .ok_or_else(|| {
            rejected(format!(
                "swarm route-plan selected route bridge mismatch: {}",
                route.route_plan_id
            ))
        })?;
    if selected_bridge != route.bridge_id {
        return Err(rejected(format!(
            "swarm route-plan selected route bridge mismatch: {}",
            route.route_plan_id
        )));
    }

    let target_bridge = route
        .protocol_target
        .split_once("://")
        .map(|(bridge, _)| bridge)
        .ok_or_else(|| {
            rejected(format!(
                "swarm route-plan protocol target bridge mismatch: {}",
                route.route_plan_id
            ))
        })?;
    if target_bridge != route.bridge_id {
        return Err(rejected(format!(
            "swarm route-plan protocol target bridge mismatch: {}",
            route.route_plan_id
        )));
    }
    Ok(())
}

fn validate_join_receipts<'a>(
    bundle: &'a SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<BTreeMap<&'a str, &'a SwarmJoinReceipt>, SwarmAuthorityError> {
    let mut graph_joins = BTreeMap::new();
    for join in &bundle.task_graph.joins {
        graph_joins.insert(join.join_id.as_str(), join);
    }

    let mut receipts = BTreeMap::new();
    for receipt in &bundle.join_receipts {
        validate_join_receipt_schema(receipt, &bundle.task_graph.graph_id)?;
        let graph_join = graph_joins
            .get(receipt.join_id.as_str())
            .ok_or_else(|| rejected(format!("unknown swarm join receipt: {}", receipt.join_id)))?;
        if receipt.next_task_id != graph_join.next_task_id {
            return Err(rejected(format!(
                "swarm join receipt next task mismatch: {}",
                receipt.join_id
            )));
        }
        if !task_by_id.contains_key(receipt.next_task_id.as_str()) {
            return Err(rejected(format!(
                "swarm join receipt next task is unknown: {}",
                receipt.next_task_id
            )));
        }
        require_unique_strings(
            &receipt.expected_parent_receipt_ids,
            "swarm expected parent receipt",
        )?;
        require_unique_strings(
            &receipt.actual_parent_receipt_ids,
            "swarm actual parent receipt",
        )?;
        if sorted_strings(&receipt.expected_parent_receipt_ids)
            != sorted_strings(&receipt.actual_parent_receipt_ids)
        {
            return Err(rejected(format!(
                "swarm join receipt parent set mismatch: {}",
                receipt.join_id
            )));
        }
        if receipt.expected_parent_receipt_ids.len() != graph_join.parent_task_ids.len() {
            return Err(rejected(format!(
                "swarm join receipt parent count mismatch: {}",
                receipt.join_id
            )));
        }
        validate_join_parent_task_receipts(receipt, graph_join)?;
        if receipts.insert(receipt.join_id.as_str(), receipt).is_some() {
            return Err(rejected(format!(
                "duplicate swarm join receipt: {}",
                receipt.join_id
            )));
        }
    }
    for join_id in graph_joins.keys() {
        if !receipts.contains_key(join_id) {
            return Err(rejected(format!("missing swarm join receipt: {join_id}")));
        }
    }
    Ok(receipts)
}

fn validate_join_parent_task_receipts(
    receipt: &SwarmJoinReceipt,
    graph_join: &SwarmGraphJoin,
) -> Result<(), SwarmAuthorityError> {
    if receipt.parent_task_receipts.len() != graph_join.parent_task_ids.len() {
        return Err(rejected(format!(
            "swarm join receipt parent task receipts mismatch: {}",
            receipt.join_id
        )));
    }

    let mut task_ids = Vec::with_capacity(receipt.parent_task_receipts.len());
    let mut receipt_ids = Vec::with_capacity(receipt.parent_task_receipts.len());
    for (index, parent) in receipt.parent_task_receipts.iter().enumerate() {
        require_non_empty(&parent.task_id, "swarm join parent task receipt task")?;
        require_non_empty(&parent.receipt_id, "swarm join parent task receipt receipt")?;
        if parent.task_id != graph_join.parent_task_ids[index]
            || parent.receipt_id != receipt.expected_parent_receipt_ids[index]
            || parent.receipt_id != receipt.actual_parent_receipt_ids[index]
        {
            return Err(rejected(format!(
                "swarm join receipt parent task receipts mismatch: {}",
                receipt.join_id
            )));
        }
        task_ids.push(parent.task_id.clone());
        receipt_ids.push(parent.receipt_id.clone());
    }
    require_unique_strings(&task_ids, "swarm join parent task receipt task")?;
    require_unique_strings(&receipt_ids, "swarm join parent task receipt receipt")?;
    if sorted_strings(&task_ids) != sorted_strings(&graph_join.parent_task_ids)
        || sorted_strings(&receipt_ids) != sorted_strings(&receipt.actual_parent_receipt_ids)
    {
        return Err(rejected(format!(
            "swarm join receipt parent task receipts mismatch: {}",
            receipt.join_id
        )));
    }
    Ok(())
}

fn validate_join_receipt_schema(
    receipt: &SwarmJoinReceipt,
    graph_id: &str,
) -> Result<(), SwarmAuthorityError> {
    if receipt.schema != CHIO_SWARM_JOIN_RECEIPT_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm join receipt schema: {}",
            receipt.schema
        )));
    }
    require_non_empty(&receipt.join_id, "swarm join receipt id")?;
    require_same_graph(&receipt.graph_id, graph_id, "join receipt")?;
    require_non_empty(&receipt.join_predicate, "swarm join predicate")?;
    if receipt.join_predicate != "all_success" {
        return Err(rejected(format!(
            "swarm join receipt predicate unsupported: {}",
            receipt.join_predicate
        )));
    }
    require_sha256(&receipt.result_digest, "swarm join result digest")?;
    Ok(())
}

fn validate_budget_pool<'a>(
    bundle: &'a SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<BTreeMap<&'a str, &'a SwarmBudgetAllocation>, SwarmAuthorityError> {
    let budget = &bundle.budget_pool;
    if budget.schema != CHIO_SWARM_BUDGET_POOL_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm budget pool schema: {}",
            budget.schema
        )));
    }
    require_non_empty(&budget.pool_id, "swarm budget pool id")?;
    require_same_graph(&budget.graph_id, &bundle.task_graph.graph_id, "budget pool")?;
    if budget.pool_id != bundle.task_graph.budget_pool_ref {
        return Err(rejected("swarm budget pool ref mismatch"));
    }
    require_non_empty(&budget.currency, "swarm budget currency")?;
    let mut total = 0_u64;
    let mut allocations = BTreeMap::new();
    for allocation in &budget.allocations {
        require_non_empty(&allocation.allocation_id, "swarm budget allocation id")?;
        require_non_empty(&allocation.task_id, "swarm budget task id")?;
        if !task_by_id.contains_key(allocation.task_id.as_str()) {
            return Err(rejected(format!(
                "swarm budget allocation task is unknown: {}",
                allocation.task_id
            )));
        }
        total = total
            .checked_add(allocation.max_units)
            .ok_or_else(|| rejected("swarm budget allocation overflow"))?;
        if allocations
            .insert(allocation.allocation_id.as_str(), allocation)
            .is_some()
        {
            return Err(rejected(format!(
                "duplicate swarm budget allocation: {}",
                allocation.allocation_id
            )));
        }
    }
    if total > budget.total_units {
        return Err(rejected("swarm budget allocations exceed pool total"));
    }
    Ok(allocations)
}

fn validate_revocation_epoch(
    bundle: &SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<(), SwarmAuthorityError> {
    let epoch = &bundle.revocation_epoch;
    if epoch.schema != CHIO_SWARM_REVOCATION_EPOCH_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm revocation epoch schema: {}",
            epoch.schema
        )));
    }
    require_non_empty(&epoch.epoch_id, "swarm revocation epoch id")?;
    if epoch.epoch_id != bundle.task_graph.revocation_epoch_ref {
        return Err(rejected("swarm revocation epoch ref mismatch"));
    }
    require_sha256(&epoch.root_hash, "swarm revocation epoch root")?;
    if epoch.issued_at_unix_ms > bundle.now_unix_ms {
        return Err(rejected("swarm revocation epoch is from the future"));
    }
    if epoch.valid_until_unix_ms <= epoch.issued_at_unix_ms {
        return Err(rejected("swarm revocation epoch window is empty"));
    }
    if epoch.valid_until_unix_ms <= bundle.now_unix_ms {
        return Err(rejected("swarm revocation epoch is stale"));
    }
    let mut revoked_subjects = BTreeSet::new();
    for subject in &epoch.revoked_subjects {
        require_non_empty(subject, "swarm revoked subject")?;
        revoked_subjects.insert(subject.as_str());
    }
    if revoked_subjects.contains(bundle.task_graph.issuer.as_str()) {
        return Err(rejected(format!(
            "swarm authority subject is revoked: {}",
            bundle.task_graph.issuer
        )));
    }
    if revoked_subjects.contains(bundle.task_graph.planner_subject.as_str()) {
        return Err(rejected(format!(
            "swarm authority subject is revoked: {}",
            bundle.task_graph.planner_subject
        )));
    }
    for chain in &bundle.witness_chains {
        for hop in &chain.hops {
            if revoked_subjects.contains(hop.issuer.as_str()) {
                return Err(rejected(format!(
                    "swarm authority subject is revoked: {}",
                    hop.issuer
                )));
            }
        }
    }
    for task_id in &epoch.revoked_task_ids {
        if task_by_id.contains_key(task_id.as_str()) {
            return Err(rejected(format!("swarm task is revoked: {task_id}")));
        }
    }
    Ok(())
}

struct ContinuationValidationContext<'a, 'b> {
    bundle: &'a SwarmAuthorityBundle,
    graph_sha256: &'a str,
    task_by_id: &'a BTreeMap<&'b str, &'b SwarmGraphNode>,
    edge_set: &'a BTreeSet<(&'b str, &'b str)>,
    route_by_id: &'a BTreeMap<&'b str, &'b SwarmRoutePlanReceipt>,
    join_by_id: &'a BTreeMap<&'b str, &'b SwarmJoinReceipt>,
    allocation_by_id: &'a BTreeMap<&'b str, &'b SwarmBudgetAllocation>,
}

fn validate_continuation_tokens(
    bundle: &SwarmAuthorityBundle,
    graph_sha256: &str,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    edge_set: &BTreeSet<(&str, &str)>,
    route_by_id: &BTreeMap<&str, &SwarmRoutePlanReceipt>,
    join_by_id: &BTreeMap<&str, &SwarmJoinReceipt>,
    allocation_by_id: &BTreeMap<&str, &SwarmBudgetAllocation>,
) -> Result<(), SwarmAuthorityError> {
    let context = ContinuationValidationContext {
        bundle,
        graph_sha256,
        task_by_id,
        edge_set,
        route_by_id,
        join_by_id,
        allocation_by_id,
    };
    let mut continuations = BTreeMap::new();
    let mut continuation_nonces = BTreeSet::new();
    for token in &bundle.continuation_tokens {
        validate_continuation_token(&context, token)?;
        if !continuation_nonces.insert(token.nonce.as_str()) {
            return Err(rejected(format!(
                "swarm continuation nonce replay: {}",
                token.token_id
            )));
        }
        if continuations
            .insert(token.token_id.as_str(), token)
            .is_some()
        {
            return Err(rejected(format!(
                "duplicate swarm continuation token: {}",
                token.token_id
            )));
        }
    }
    for node in &bundle.task_graph.nodes {
        if node.parent_task_id.is_some() && node.continuation_token_ref.is_none() {
            return Err(rejected(format!(
                "swarm task continuation token ref missing: {}",
                node.task_id
            )));
        }
        if let Some(token_ref) = &node.continuation_token_ref {
            match continuations.get(token_ref.as_str()) {
                Some(token) if token.child_task_id == node.task_id => {}
                Some(_) => {
                    return Err(rejected(format!(
                        "swarm continuation token task mismatch: {token_ref}"
                    )));
                }
                None => {
                    return Err(rejected(format!(
                        "missing swarm continuation token: {token_ref}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_continuation_token(
    context: &ContinuationValidationContext<'_, '_>,
    token: &SwarmContinuationToken,
) -> Result<(), SwarmAuthorityError> {
    let bundle = context.bundle;
    if token.schema != CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm continuation token schema: {}",
            token.schema
        )));
    }
    require_non_empty(&token.token_id, "swarm continuation token id")?;
    require_same_graph(
        &token.graph_id,
        &bundle.task_graph.graph_id,
        "continuation token",
    )?;
    require_non_empty(&token.child_task_id, "swarm continuation child task id")?;
    let child_task = context
        .task_by_id
        .get(token.child_task_id.as_str())
        .copied()
        .ok_or_else(|| {
            rejected(format!(
                "swarm continuation child task is unknown: {}",
                token.child_task_id
            ))
        })?;
    if token.issued_at_unix_ms > bundle.now_unix_ms {
        return Err(rejected(format!(
            "swarm continuation token is from the future: {}",
            token.token_id
        )));
    }
    if token.expires_at_unix_ms <= bundle.now_unix_ms {
        return Err(rejected(format!(
            "swarm continuation token is stale: {}",
            token.token_id
        )));
    }
    if token.graph_sha256 != context.graph_sha256 {
        return Err(rejected(format!(
            "swarm continuation graph digest mismatch: {}",
            token.token_id
        )));
    }
    require_non_empty(
        &token.session_anchor_ref,
        "swarm continuation session anchor",
    )?;
    require_non_empty(&token.nonce, "swarm continuation nonce")?;
    require_unique_strings(
        &token.parent_receipt_ids,
        "swarm continuation parent receipt",
    )?;
    validate_continuation_parent(token, context.edge_set, context.join_by_id)?;
    validate_continuation_route(token, child_task, context.route_by_id)?;
    validate_continuation_budget(token, child_task, context.allocation_by_id)?;
    if token.revocation_epoch_ref != bundle.revocation_epoch.epoch_id {
        return Err(rejected(format!(
            "swarm continuation revocation epoch mismatch: {}",
            token.token_id
        )));
    }
    Ok(())
}

fn validate_continuation_parent(
    token: &SwarmContinuationToken,
    edge_set: &BTreeSet<(&str, &str)>,
    join_by_id: &BTreeMap<&str, &SwarmJoinReceipt>,
) -> Result<(), SwarmAuthorityError> {
    match (&token.parent_task_id, &token.join_receipt_id) {
        (Some(parent_task_id), None) => {
            if token.parent_receipt_ids.is_empty() {
                return Err(rejected(format!(
                    "swarm continuation lacks parent receipt: {}",
                    token.token_id
                )));
            }
            if !edge_set.contains(&(parent_task_id.as_str(), token.child_task_id.as_str())) {
                return Err(rejected(format!(
                    "swarm continuation parent edge mismatch: {}",
                    token.token_id
                )));
            }
        }
        (None, Some(join_receipt_id)) => {
            let join = join_by_id.get(join_receipt_id.as_str()).ok_or_else(|| {
                rejected(format!(
                    "swarm continuation join receipt is unknown: {join_receipt_id}"
                ))
            })?;
            if join.next_task_id != token.child_task_id {
                return Err(rejected(format!(
                    "swarm continuation join target mismatch: {}",
                    token.token_id
                )));
            }
            if sorted_strings(&token.parent_receipt_ids)
                != sorted_strings(&join.actual_parent_receipt_ids)
            {
                return Err(rejected(format!(
                    "swarm continuation join parent receipts mismatch: {}",
                    token.token_id
                )));
            }
        }
        (Some(_), Some(_)) => {
            return Err(rejected(format!(
                "swarm continuation must choose parent task or join receipt: {}",
                token.token_id
            )));
        }
        (None, None) => {
            return Err(rejected(format!(
                "swarm continuation missing parent context: {}",
                token.token_id
            )));
        }
    }
    Ok(())
}

fn validate_continuation_route(
    token: &SwarmContinuationToken,
    child_task: &SwarmGraphNode,
    route_by_id: &BTreeMap<&str, &SwarmRoutePlanReceipt>,
) -> Result<(), SwarmAuthorityError> {
    match child_task.route_plan_ref.as_deref() {
        Some(route_plan_ref) if route_plan_ref == token.route_plan_receipt_id => {}
        Some(_) => {
            return Err(rejected(format!(
                "swarm continuation route-plan ref mismatch: {}",
                token.token_id
            )));
        }
        None => {
            return Err(rejected(format!(
                "swarm continuation route-plan ref missing: {}",
                token.token_id
            )));
        }
    }
    let route = route_by_id
        .get(token.route_plan_receipt_id.as_str())
        .ok_or_else(|| {
            rejected(format!(
                "swarm continuation route-plan receipt is unknown: {}",
                token.route_plan_receipt_id
            ))
        })?;
    if route.task_id != token.child_task_id {
        return Err(rejected(format!(
            "swarm continuation route-plan task mismatch: {}",
            token.token_id
        )));
    }
    Ok(())
}

fn validate_continuation_budget(
    token: &SwarmContinuationToken,
    child_task: &SwarmGraphNode,
    allocation_by_id: &BTreeMap<&str, &SwarmBudgetAllocation>,
) -> Result<(), SwarmAuthorityError> {
    match child_task.budget_allocation_ref.as_deref() {
        Some(allocation_ref) if allocation_ref == token.budget_allocation_id => {}
        Some(_) => {
            return Err(rejected(format!(
                "swarm continuation budget ref mismatch: {}",
                token.token_id
            )));
        }
        None => {
            return Err(rejected(format!(
                "swarm continuation budget ref missing: {}",
                token.token_id
            )));
        }
    }
    let allocation = allocation_by_id
        .get(token.budget_allocation_id.as_str())
        .ok_or_else(|| {
            rejected(format!(
                "swarm continuation budget allocation is unknown: {}",
                token.budget_allocation_id
            ))
        })?;
    if allocation.task_id != token.child_task_id {
        return Err(rejected(format!(
            "swarm continuation budget task mismatch: {}",
            token.token_id
        )));
    }
    Ok(())
}

fn validate_witness_chains(
    bundle: &SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    edge_set: &BTreeSet<(&str, &str)>,
) -> Result<(), SwarmAuthorityError> {
    let mut witnessed_edges = BTreeSet::new();
    for chain in &bundle.witness_chains {
        validate_witness_chain(bundle, chain, task_by_id, edge_set)?;
        if !witnessed_edges.insert((chain.parent_task_id.as_str(), chain.child_task_id.as_str())) {
            return Err(rejected(format!(
                "duplicate swarm delegation witness chain: {} -> {}",
                chain.parent_task_id, chain.child_task_id
            )));
        }
    }
    for edge in edge_set {
        if !witnessed_edges.contains(edge) {
            return Err(rejected(format!(
                "missing swarm delegation witness chain: {} -> {}",
                edge.0, edge.1
            )));
        }
    }
    Ok(())
}

fn validate_witness_chain(
    bundle: &SwarmAuthorityBundle,
    chain: &SwarmDelegationWitnessChain,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    edge_set: &BTreeSet<(&str, &str)>,
) -> Result<(), SwarmAuthorityError> {
    if chain.schema != CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm delegation witness chain schema: {}",
            chain.schema
        )));
    }
    require_non_empty(&chain.chain_id, "swarm witness chain id")?;
    require_same_graph(
        &chain.graph_id,
        &bundle.task_graph.graph_id,
        "witness chain",
    )?;
    if !edge_set.contains(&(chain.parent_task_id.as_str(), chain.child_task_id.as_str())) {
        return Err(rejected(format!(
            "swarm witness chain edge mismatch: {}",
            chain.chain_id
        )));
    }
    let parent = task_by_id
        .get(chain.parent_task_id.as_str())
        .ok_or_else(|| {
            rejected(format!(
                "swarm witness chain parent task is unknown: {}",
                chain.parent_task_id
            ))
        })?;
    let child = task_by_id
        .get(chain.child_task_id.as_str())
        .ok_or_else(|| {
            rejected(format!(
                "swarm witness chain child task is unknown: {}",
                chain.child_task_id
            ))
        })?;
    if chain.hops.is_empty() {
        return Err(rejected(format!(
            "swarm witness chain has no hops: {}",
            chain.chain_id
        )));
    }
    let Some(first_hop) = chain.hops.first() else {
        return Err(rejected(format!(
            "swarm witness chain has no hops: {}",
            chain.chain_id
        )));
    };
    let Some(last_hop) = chain.hops.last() else {
        return Err(rejected(format!(
            "swarm witness chain has no hops: {}",
            chain.chain_id
        )));
    };
    if first_hop.parent_scope_hash != parent.scope_hash {
        return Err(rejected(format!(
            "swarm witness parent scope mismatch: {}",
            chain.chain_id
        )));
    }
    if last_hop.child_scope_hash != child.scope_hash {
        return Err(rejected(format!(
            "swarm witness child scope mismatch: {}",
            chain.chain_id
        )));
    }
    let mut previous_hop: Option<&super::types::SwarmDelegationWitnessHop> = None;
    for hop in &chain.hops {
        validate_witness_hop(bundle, chain, hop)?;
        if let Some(previous) = previous_hop {
            if previous.child_scope_hash != hop.parent_scope_hash {
                return Err(rejected(format!(
                    "swarm witness hop scope discontinuity: {}",
                    chain.chain_id
                )));
            }
            if previous.child_capability_digest != hop.parent_capability_digest {
                return Err(rejected(format!(
                    "swarm witness hop capability discontinuity: {}",
                    chain.chain_id
                )));
            }
        }
        previous_hop = Some(hop);
    }
    Ok(())
}

fn validate_witness_hop(
    bundle: &SwarmAuthorityBundle,
    chain: &SwarmDelegationWitnessChain,
    hop: &super::types::SwarmDelegationWitnessHop,
) -> Result<(), SwarmAuthorityError> {
    require_sha256(
        &hop.parent_capability_digest,
        "swarm witness parent capability digest",
    )?;
    require_sha256(
        &hop.child_capability_digest,
        "swarm witness child capability digest",
    )?;
    require_sha256(&hop.parent_scope_hash, "swarm witness parent scope hash")?;
    require_sha256(&hop.child_scope_hash, "swarm witness child scope hash")?;
    require_non_empty(&hop.attenuation_rule_id, "swarm witness attenuation rule")?;
    require_non_empty(&hop.issuer, "swarm witness issuer")?;
    require_sha256(&hop.policy_digest, "swarm witness policy digest")?;
    require_non_empty(&hop.witness_signature, "swarm witness signature")?;
    if hop.expires_at_unix_ms <= bundle.now_unix_ms {
        return Err(rejected(format!(
            "swarm witness hop is stale: {}",
            chain.chain_id
        )));
    }
    validate_attenuation_proof(
        &hop.parent_scope_hash,
        &hop.child_scope_hash,
        &hop.scope_subset_proof,
    )
    .map_err(|error| rejected(format!("swarm attenuation witness invalid: {error}")))?;
    verify_witness_signature(chain, hop)?;
    Ok(())
}

fn verify_witness_signature(
    chain: &SwarmDelegationWitnessChain,
    hop: &super::types::SwarmDelegationWitnessHop,
) -> Result<(), SwarmAuthorityError> {
    let public_key = witness_issuer_public_key(&hop.issuer)?;
    let signature = Signature::from_hex(&hop.witness_signature).map_err(|error| {
        rejected(format!(
            "swarm witness signature invalid: {}: {error}",
            chain.chain_id
        ))
    })?;
    let body = witness_signature_body(chain, hop);
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm witness signature invalid: {}",
            chain.chain_id
        )))
    }
}

fn witness_issuer_public_key(issuer: &str) -> Result<PublicKey, SwarmAuthorityError> {
    let public_key_hex = if let Some(public_key_hex) = issuer.strip_prefix(DID_CHIO_PREFIX) {
        if public_key_hex.len() != 64 || !public_key_hex.bytes().all(is_lower_hex_byte) {
            return Err(rejected(
                "swarm witness issuer did:chio is not self-certifying",
            ));
        }
        public_key_hex
    } else {
        issuer
    };
    PublicKey::from_hex(public_key_hex)
        .map_err(|error| rejected(format!("swarm witness issuer public key invalid: {error}")))
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SwarmWitnessHopSignatureBody<'a> {
    schema: &'static str,
    graph_id: &'a str,
    chain_id: &'a str,
    parent_task_id: &'a str,
    child_task_id: &'a str,
    parent_capability_digest: &'a str,
    child_capability_digest: &'a str,
    parent_scope_hash: &'a str,
    child_scope_hash: &'a str,
    attenuation_rule_id: &'a str,
    scope_subset_proof: &'a AttenuationWitness,
    expires_at_unix_ms: u64,
    issuer: &'a str,
    policy_digest: &'a str,
}

fn witness_signature_body<'a>(
    chain: &'a SwarmDelegationWitnessChain,
    hop: &'a super::types::SwarmDelegationWitnessHop,
) -> SwarmWitnessHopSignatureBody<'a> {
    SwarmWitnessHopSignatureBody {
        schema: CHIO_SWARM_DELEGATION_WITNESS_HOP_SIGNATURE_SCHEMA,
        graph_id: &chain.graph_id,
        chain_id: &chain.chain_id,
        parent_task_id: &chain.parent_task_id,
        child_task_id: &chain.child_task_id,
        parent_capability_digest: &hop.parent_capability_digest,
        child_capability_digest: &hop.child_capability_digest,
        parent_scope_hash: &hop.parent_scope_hash,
        child_scope_hash: &hop.child_scope_hash,
        attenuation_rule_id: &hop.attenuation_rule_id,
        scope_subset_proof: &hop.scope_subset_proof,
        expires_at_unix_ms: hop.expires_at_unix_ms,
        issuer: &hop.issuer,
        policy_digest: &hop.policy_digest,
    }
}

fn require_same_graph(
    actual: &str,
    expected: &str,
    label: &str,
) -> Result<(), SwarmAuthorityError> {
    if actual == expected {
        Ok(())
    } else {
        Err(rejected(format!("swarm {label} graph id mismatch")))
    }
}

fn require_non_empty(value: &str, label: &str) -> Result<(), SwarmAuthorityError> {
    if value.is_empty() {
        Err(rejected(format!("{label} must not be empty")))
    } else {
        Ok(())
    }
}

fn require_sha256(value: &str, label: &str) -> Result<(), SwarmAuthorityError> {
    if is_sha256_hex(value) {
        Ok(())
    } else {
        Err(rejected(format!(
            "{label} must be a lowercase sha256 digest"
        )))
    }
}

fn require_unique_strings(values: &[String], label: &str) -> Result<(), SwarmAuthorityError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(value, label)?;
        if !seen.insert(value.as_str()) {
            return Err(rejected(format!("duplicate {label}: {value}")));
        }
    }
    Ok(())
}

fn sorted_strings(values: &[String]) -> Vec<&str> {
    let mut sorted = values.iter().map(String::as_str).collect::<Vec<_>>();
    sorted.sort_unstable();
    sorted
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, SwarmAuthorityError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn rejected(message: impl Into<String>) -> SwarmAuthorityError {
    SwarmAuthorityError::Rejected(message.into())
}
