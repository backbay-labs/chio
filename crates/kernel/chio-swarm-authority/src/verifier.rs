use std::collections::{BTreeMap, BTreeSet};

use crate::error::SwarmAuthorityError;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};

mod budget_accounting;
mod util;
mod witness;
pub use budget_accounting::validate_swarm_budget_pool_accounting;
use util::{
    canonical_sha256, continuation_token_signature_body, join_receipt_signature_body, rejected,
    require_non_empty, require_same_graph, require_sha256, require_unique_strings,
    revocation_epoch_signature_body, route_plan_signature_body, sorted_strings,
    task_graph_signature_body, terminal_graph_receipt_signature_body,
};
use witness::{
    validate_witness_chains, witness_issuer_public_key, witness_signature_body, DID_CHIO_PREFIX,
};

use super::types::{
    SwarmAuthorityBundle, SwarmAuthorityHopReport, SwarmAuthorityVerifierReport,
    SwarmBudgetAllocation, SwarmBudgetAllocationState, SwarmBudgetFanInReleaseRequest,
    SwarmBudgetFanoutReservationRequest, SwarmBudgetPool, SwarmContinuationToken,
    SwarmContinuationTokenMintRequest, SwarmDelegationWitnessChain, SwarmGraphEdge, SwarmGraphJoin,
    SwarmGraphNode, SwarmJoinReceipt, SwarmJoinReceiptMintRequest, SwarmRevocationEpoch,
    SwarmRoutePlanReceipt, SwarmTaskGraph, SwarmTerminalBudgetRollup, SwarmTerminalGraphReceipt,
    CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_SCHEMA, CHIO_SWARM_BUDGET_POOL_SCHEMA,
    CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA, CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
    CHIO_SWARM_REVOCATION_EPOCH_SCHEMA, CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
    CHIO_SWARM_TASK_GRAPH_SCHEMA, CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA,
    CLAIM_SWARM_ATTENUATION_WITNESS_CHAIN_BOUND, CLAIM_SWARM_BUDGET_POOL_BOUND,
    CLAIM_SWARM_CONTINUATION_FRESH, CLAIM_SWARM_JOIN_RECEIPT_BOUND,
    CLAIM_SWARM_REVOCATION_EPOCH_BOUND, CLAIM_SWARM_ROUTE_PLAN_BOUND, CLAIM_SWARM_TASK_GRAPH_BOUND,
    CLAIM_SWARM_TERMINAL_GRAPH_RECEIPT_BOUND,
};

pub fn verify_swarm_authority_bundle(
    bundle: &SwarmAuthorityBundle,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<SwarmAuthorityVerifierReport, SwarmAuthorityError> {
    require_trusted_witness_issuer_keys(trusted_witness_issuer_keys)?;
    validate_task_graph(&bundle.task_graph, bundle.now_unix_ms)?;
    verify_task_graph_signature(&bundle.task_graph, trusted_witness_issuer_keys)?;
    require_signed_swarm_delegation_evidence(bundle)?;
    let graph_sha256 = canonical_sha256(&bundle.task_graph)?;
    let task_by_id = task_index(&bundle.task_graph)?;
    let edge_set = edge_set(&bundle.task_graph.edges);
    let route_by_id =
        validate_route_plan_receipts(bundle, &task_by_id, trusted_witness_issuer_keys)?;
    let join_by_id = validate_join_receipts(bundle, &task_by_id, trusted_witness_issuer_keys)?;
    let allocation_by_id = validate_budget_pool(bundle, &task_by_id)?;
    validate_revocation_epoch(bundle, &task_by_id, trusted_witness_issuer_keys)?;
    validate_terminal_graph_receipts(
        bundle,
        &task_by_id,
        &route_by_id,
        &join_by_id,
        &allocation_by_id,
        trusted_witness_issuer_keys,
    )?;
    validate_continuation_tokens(&ContinuationValidationContext {
        bundle,
        graph_sha256: &graph_sha256,
        task_by_id: &task_by_id,
        edge_set: &edge_set,
        route_by_id: &route_by_id,
        join_by_id: &join_by_id,
        allocation_by_id: &allocation_by_id,
        trusted_witness_issuer_keys,
    })?;
    validate_witness_chains(bundle, &task_by_id, &edge_set, trusted_witness_issuer_keys)?;

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
    verified_claims.push(CLAIM_SWARM_TERMINAL_GRAPH_RECEIPT_BOUND.to_string());
    let hop_reports = swarm_authority_hop_reports(bundle)?;

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
        hop_reports,
        verified_claims,
    })
}

fn swarm_authority_hop_reports(
    bundle: &SwarmAuthorityBundle,
) -> Result<Vec<SwarmAuthorityHopReport>, SwarmAuthorityError> {
    let mut continuation_by_id = BTreeMap::new();
    for token in &bundle.continuation_tokens {
        continuation_by_id.insert(token.token_id.as_str(), token);
    }
    let mut witness_chain_by_id = BTreeMap::new();
    for chain in &bundle.witness_chains {
        witness_chain_by_id.insert(chain.chain_id.as_str(), chain);
    }
    let mut reports = Vec::new();
    for node in &bundle.task_graph.nodes {
        let Some(continuation_token_ref) = node.continuation_token_ref.as_deref() else {
            continue;
        };
        let token = continuation_by_id
            .get(continuation_token_ref)
            .copied()
            .ok_or_else(|| {
                rejected(format!(
                    "missing swarm continuation token: {continuation_token_ref}"
                ))
            })?;
        let witness_hop_count = token
            .witness_chain_ref
            .as_deref()
            .and_then(|chain_id| witness_chain_by_id.get(chain_id))
            .map(|chain| chain.hops.len())
            .unwrap_or(0);
        reports.push(SwarmAuthorityHopReport {
            child_task_id: node.task_id.clone(),
            parent_task_id: token.parent_task_id.clone(),
            join_receipt_id: token.join_receipt_id.clone(),
            continuation_token_id: token.token_id.clone(),
            witness_chain_id: token.witness_chain_ref.clone(),
            witness_hop_count,
            multi_hop_witness_enabled: bundle.task_graph.multi_hop_witness_chains,
            route_plan_receipt_id: token.route_plan_receipt_id.clone(),
            budget_allocation_id: token.budget_allocation_id.clone(),
            authority_verified: true,
            attenuation_verified: true,
            lineage_verified: true,
            route_verified: true,
            budget_verified: true,
        });
    }
    Ok(reports)
}

fn require_signed_swarm_delegation_evidence(
    bundle: &SwarmAuthorityBundle,
) -> Result<(), SwarmAuthorityError> {
    if bundle.continuation_tokens.is_empty() || bundle.witness_chains.is_empty() {
        return Err(rejected(
            "signed swarm delegation evidence missing: continuation tokens and witness chains are required",
        ));
    }
    Ok(())
}

fn require_trusted_witness_issuer_keys(
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if trusted_witness_issuer_keys.is_empty() {
        return Err(rejected(
            "trusted swarm witness keys missing: CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys",
        ));
    }
    Ok(())
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

pub fn sign_swarm_task_graph(
    graph: &SwarmTaskGraph,
    keypair: &Keypair,
) -> Result<String, SwarmAuthorityError> {
    let issuer_public_key = witness_issuer_public_key(&graph.issuer).map_err(|error| {
        rejected(format!(
            "swarm task graph issuer public key invalid: {}",
            error.runtime_detail()
        ))
    })?;
    if issuer_public_key != keypair.public_key() {
        return Err(rejected(format!(
            "swarm task graph signer does not match issuer: {}",
            graph.graph_id
        )));
    }
    let body = task_graph_signature_body(graph)?;
    let (signature, _canonical) = keypair
        .sign_canonical(&body)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(signature.to_hex())
}

pub fn sign_swarm_continuation_token(
    token: &SwarmContinuationToken,
    keypair: &Keypair,
) -> Result<String, SwarmAuthorityError> {
    let issuer_public_key = witness_issuer_public_key(&token.issuer).map_err(|error| {
        rejected(format!(
            "swarm continuation issuer public key invalid: {}",
            error.runtime_detail()
        ))
    })?;
    if issuer_public_key != keypair.public_key() {
        return Err(rejected(format!(
            "swarm continuation signer does not match issuer: {}",
            token.token_id
        )));
    }
    let body = continuation_token_signature_body(token)?;
    let (signature, _canonical) = keypair
        .sign_canonical(&body)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(signature.to_hex())
}

pub fn mint_swarm_continuation_token(
    request: SwarmContinuationTokenMintRequest,
    keypair: &Keypair,
) -> Result<SwarmContinuationToken, SwarmAuthorityError> {
    if request.expires_at_unix_ms <= request.issued_at_unix_ms {
        return Err(rejected(format!(
            "swarm continuation expiry must be after issue time: {}",
            request.token_id
        )));
    }
    if request.parent_task_id.is_some() {
        match (&request.witness_chain_ref, &request.witness_chain_sha256) {
            (Some(witness_chain_ref), Some(witness_chain_sha256)) => {
                require_non_empty(witness_chain_ref, "swarm continuation witness chain ref")?;
                require_sha256(
                    witness_chain_sha256,
                    "swarm continuation witness chain digest",
                )?;
            }
            _ => {
                return Err(rejected(format!(
                    "swarm continuation witness chain binding missing: {}",
                    request.token_id
                )));
            }
        }
    }
    let issuer = format!("{DID_CHIO_PREFIX}{}", keypair.public_key().to_hex());
    let mut token = SwarmContinuationToken {
        schema: CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA.to_string(),
        token_id: request.token_id,
        graph_id: request.graph_id,
        child_task_id: request.child_task_id,
        parent_task_id: request.parent_task_id,
        join_receipt_id: request.join_receipt_id,
        parent_receipt_ids: request.parent_receipt_ids,
        graph_sha256: request.graph_sha256,
        route_plan_receipt_id: request.route_plan_receipt_id,
        budget_allocation_id: request.budget_allocation_id,
        witness_chain_ref: request.witness_chain_ref,
        witness_chain_sha256: request.witness_chain_sha256,
        revocation_epoch_ref: request.revocation_epoch_ref,
        revocation_epoch_root_hash: request.revocation_epoch_root_hash,
        session_anchor_ref: request.session_anchor_ref,
        nonce: request.nonce,
        mode: request.mode,
        issued_at_unix_ms: request.issued_at_unix_ms,
        expires_at_unix_ms: request.expires_at_unix_ms,
        issuer,
        signature: String::new(),
    };
    token.signature = sign_swarm_continuation_token(&token, keypair)?;
    Ok(token)
}

pub fn sign_swarm_join_receipt(
    receipt: &SwarmJoinReceipt,
    keypair: &Keypair,
) -> Result<String, SwarmAuthorityError> {
    let issuer_public_key = witness_issuer_public_key(&receipt.issuer).map_err(|error| {
        rejected(format!(
            "swarm join receipt issuer public key invalid: {}",
            error.runtime_detail()
        ))
    })?;
    if issuer_public_key != keypair.public_key() {
        return Err(rejected(format!(
            "swarm join receipt signer does not match issuer: {}",
            receipt.join_id
        )));
    }
    let body = join_receipt_signature_body(receipt)?;
    let (signature, _canonical) = keypair
        .sign_canonical(&body)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(signature.to_hex())
}

pub fn mint_swarm_join_receipt(
    request: SwarmJoinReceiptMintRequest,
    keypair: &Keypair,
) -> Result<SwarmJoinReceipt, SwarmAuthorityError> {
    if request.parent_task_receipts.is_empty() {
        return Err(rejected(format!(
            "swarm join receipt parent task receipts missing: {}",
            request.join_id
        )));
    }
    if request.actual_parent_receipt_ids.is_empty() {
        return Err(rejected(format!(
            "swarm join receipt actual parent receipts missing: {}",
            request.join_id
        )));
    }
    if request.dag_ordinal == 0 {
        return Err(rejected(format!(
            "swarm join receipt dag ordinal must be positive: {}",
            request.join_id
        )));
    }
    let parent_set_hash =
        join_parent_set_hash_from_parts(&request.chain_id, &request.actual_parent_receipt_ids)?;
    let issuer = format!("{DID_CHIO_PREFIX}{}", keypair.public_key().to_hex());
    let mut receipt = SwarmJoinReceipt {
        schema: CHIO_SWARM_JOIN_RECEIPT_SCHEMA.to_string(),
        join_id: request.join_id,
        graph_id: request.graph_id,
        chain_id: request.chain_id,
        parent_set_hash,
        dag_ordinal: request.dag_ordinal,
        hlc_unix_ms: request.hlc_unix_ms,
        parent_task_receipts: request.parent_task_receipts,
        expected_parent_receipt_ids: request.expected_parent_receipt_ids,
        actual_parent_receipt_ids: request.actual_parent_receipt_ids,
        join_predicate: request.join_predicate,
        result_digest: request.result_digest,
        next_task_id: request.next_task_id,
        issuer,
        signature: String::new(),
    };
    receipt.signature = sign_swarm_join_receipt(&receipt, keypair)?;
    Ok(receipt)
}

pub fn reserve_swarm_budget_fanout(
    request: SwarmBudgetFanoutReservationRequest,
) -> Result<SwarmBudgetPool, SwarmAuthorityError> {
    require_non_empty(&request.pool_id, "swarm budget pool id")?;
    require_non_empty(&request.graph_id, "swarm budget pool graph")?;
    require_non_empty(&request.currency, "swarm budget currency")?;
    if request.allocations.is_empty() {
        return Err(rejected("swarm budget fanout allocations missing"));
    }

    let mut allocation_ids = Vec::with_capacity(request.allocations.len());
    let mut task_ids = Vec::with_capacity(request.allocations.len());
    let mut total_reserved = 0_u64;
    let mut allocations = Vec::with_capacity(request.allocations.len());
    for allocation in request.allocations {
        require_non_empty(&allocation.allocation_id, "swarm budget allocation id")?;
        require_non_empty(&allocation.task_id, "swarm budget task id")?;
        require_non_empty(
            &allocation.dimension_id,
            "swarm budget allocation dimension",
        )?;
        if allocation.reserved_units == 0 {
            return Err(rejected(format!(
                "swarm budget fanout allocation units missing: {}",
                allocation.allocation_id
            )));
        }
        total_reserved = total_reserved
            .checked_add(allocation.reserved_units)
            .ok_or_else(|| rejected("swarm budget fanout overflow"))?;
        allocation_ids.push(allocation.allocation_id.clone());
        task_ids.push(allocation.task_id.clone());
        allocations.push(SwarmBudgetAllocation {
            allocation_id: allocation.allocation_id,
            task_id: allocation.task_id,
            dimension_id: allocation.dimension_id,
            state: SwarmBudgetAllocationState::Reserved,
            max_units: allocation.reserved_units,
            reserved_units: allocation.reserved_units,
            active_units: 0,
            consumed_units: 0,
            released_units: 0,
            reversed_units: 0,
        });
    }
    require_unique_strings(&allocation_ids, "swarm budget allocation")?;
    require_unique_strings(&task_ids, "swarm budget task")?;
    if total_reserved > request.total_units {
        return Err(rejected("swarm budget fanout exceeds pool total"));
    }

    Ok(SwarmBudgetPool {
        schema: CHIO_SWARM_BUDGET_POOL_SCHEMA.to_string(),
        pool_id: request.pool_id,
        graph_id: request.graph_id,
        currency: request.currency,
        total_units: request.total_units,
        allocations,
    })
}

pub fn release_swarm_budget_fanin(
    request: SwarmBudgetFanInReleaseRequest,
) -> Result<SwarmBudgetPool, SwarmAuthorityError> {
    if request.completed_task_ids.is_empty() {
        return Err(rejected("swarm budget fanin completed tasks missing"));
    }
    require_unique_strings(&request.completed_task_ids, "swarm budget fanin task")?;
    let completed_task_ids = request
        .completed_task_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut pool = request.pool;
    let mut released_task_ids = BTreeSet::new();

    for allocation in &mut pool.allocations {
        if !completed_task_ids.contains(allocation.task_id.as_str()) {
            continue;
        }
        let already_final = allocation
            .consumed_units
            .checked_add(allocation.released_units)
            .and_then(|units| units.checked_add(allocation.reversed_units))
            .ok_or_else(|| rejected("swarm budget fanin release overflow"))?;
        let releasable = allocation
            .max_units
            .checked_sub(already_final)
            .ok_or_else(|| {
                rejected(format!(
                    "swarm budget fanin release exceeds allocation: {}",
                    allocation.allocation_id
                ))
            })?;
        allocation.reserved_units = 0;
        allocation.active_units = 0;
        allocation.released_units = allocation
            .released_units
            .checked_add(releasable)
            .ok_or_else(|| rejected("swarm budget fanin release overflow"))?;
        allocation.state = SwarmBudgetAllocationState::Released;
        released_task_ids.insert(allocation.task_id.as_str());
    }

    if released_task_ids != completed_task_ids {
        return Err(rejected("swarm budget fanin task has no allocation"));
    }
    Ok(pool)
}

pub fn sign_swarm_route_plan_receipt(
    receipt: &SwarmRoutePlanReceipt,
    keypair: &Keypair,
) -> Result<String, SwarmAuthorityError> {
    let issuer_public_key = witness_issuer_public_key(&receipt.issuer).map_err(|error| {
        rejected(format!(
            "swarm route-plan issuer public key invalid: {}",
            error.runtime_detail()
        ))
    })?;
    if issuer_public_key != keypair.public_key() {
        return Err(rejected(format!(
            "swarm route-plan signer does not match issuer: {}",
            receipt.route_plan_id
        )));
    }
    let body = route_plan_signature_body(receipt)?;
    let (signature, _canonical) = keypair
        .sign_canonical(&body)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(signature.to_hex())
}

pub fn sign_swarm_revocation_epoch(
    epoch: &SwarmRevocationEpoch,
    keypair: &Keypair,
) -> Result<String, SwarmAuthorityError> {
    let issuer_public_key = witness_issuer_public_key(&epoch.issuer).map_err(|error| {
        rejected(format!(
            "swarm revocation epoch issuer public key invalid: {}",
            error.runtime_detail()
        ))
    })?;
    if issuer_public_key != keypair.public_key() {
        return Err(rejected(format!(
            "swarm revocation epoch signer does not match issuer: {}",
            epoch.epoch_id
        )));
    }
    let body = revocation_epoch_signature_body(epoch)?;
    let (signature, _canonical) = keypair
        .sign_canonical(&body)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(signature.to_hex())
}

pub fn sign_swarm_terminal_graph_receipt(
    receipt: &SwarmTerminalGraphReceipt,
    keypair: &Keypair,
) -> Result<String, SwarmAuthorityError> {
    let issuer_public_key = witness_issuer_public_key(&receipt.issuer).map_err(|error| {
        rejected(format!(
            "swarm terminal receipt issuer public key invalid: {}",
            error.runtime_detail()
        ))
    })?;
    if issuer_public_key != keypair.public_key() {
        return Err(rejected(format!(
            "swarm terminal receipt signer does not match issuer: {}",
            receipt.receipt_id
        )));
    }
    let body = terminal_graph_receipt_signature_body(receipt)?;
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
    require_non_empty(&graph.signature, "swarm task graph signature")?;
    require_non_empty(&graph.budget_pool_ref, "swarm budget pool ref")?;
    require_non_empty(&graph.revocation_epoch_ref, "swarm revocation epoch ref")?;
    if graph.created_at_unix_ms > now_unix_ms {
        return Err(rejected("swarm task graph is from the future"));
    }
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

fn verify_task_graph_signature(
    graph: &SwarmTaskGraph,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    let public_key = witness_issuer_public_key(&graph.issuer)?;
    ensure_task_graph_issuer_is_pinned(graph, &public_key, trusted_witness_issuer_keys)?;
    let signature = Signature::from_hex(&graph.signature).map_err(|error| {
        rejected(format!(
            "swarm task graph signature invalid: {}: {error}",
            graph.graph_id
        ))
    })?;
    let body = task_graph_signature_body(graph)?;
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm task graph signature invalid: {}",
            graph.graph_id
        )))
    }
}

fn ensure_task_graph_issuer_is_pinned(
    graph: &SwarmTaskGraph,
    public_key: &PublicKey,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if trusted_witness_issuer_keys.is_empty() {
        return Err(rejected(
            "trusted swarm witness keys missing: CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys",
        ));
    }
    if trusted_witness_issuer_keys
        .iter()
        .any(|trusted_key| trusted_key == public_key)
    {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm task graph issuer is not trusted: {}",
            graph.graph_id
        )))
    }
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
    trusted_witness_issuer_keys: &[PublicKey],
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
        require_non_empty(&route.egress_contract_id, "swarm route egress contract id")?;
        validate_route_plan_egress_constraints(route)?;
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
        require_non_empty(&route.issuer, "swarm route-plan issuer")?;
        require_non_empty(&route.signature, "swarm route-plan signature")?;
        verify_route_plan_signature(route, trusted_witness_issuer_keys)?;
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

fn validate_route_plan_egress_constraints(
    route: &SwarmRoutePlanReceipt,
) -> Result<(), SwarmAuthorityError> {
    if route.egress_constraints.is_empty() {
        return Err(rejected(format!(
            "swarm route-plan egress constraints missing: {}",
            route.route_plan_id
        )));
    }
    require_unique_strings(
        &route.egress_constraints,
        "swarm route-plan egress constraint",
    )?;
    for constraint in &route.egress_constraints {
        require_non_empty(constraint, "swarm route-plan egress constraint")?;
        if constraint != "deny-private-network" {
            return Err(rejected(format!(
                "unsupported swarm route-plan egress constraint: {}",
                constraint
            )));
        }
    }
    Ok(())
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

    let Some((egress_bridge, _egress_contract)) = route.egress_contract_id.split_once(':') else {
        return Err(rejected(format!(
            "swarm route-plan egress contract bridge mismatch: {}",
            route.route_plan_id
        )));
    };
    if egress_bridge != route.bridge_id {
        return Err(rejected(format!(
            "swarm route-plan egress contract bridge mismatch: {}",
            route.route_plan_id
        )));
    }
    Ok(())
}

fn verify_route_plan_signature(
    receipt: &SwarmRoutePlanReceipt,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    let public_key = witness_issuer_public_key(&receipt.issuer)?;
    ensure_route_plan_issuer_is_pinned(receipt, &public_key, trusted_witness_issuer_keys)?;
    let signature = Signature::from_hex(&receipt.signature).map_err(|error| {
        rejected(format!(
            "swarm route-plan signature invalid: {}: {error}",
            receipt.route_plan_id
        ))
    })?;
    let body = route_plan_signature_body(receipt)?;
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm route-plan signature invalid: {}",
            receipt.route_plan_id
        )))
    }
}

fn ensure_route_plan_issuer_is_pinned(
    receipt: &SwarmRoutePlanReceipt,
    public_key: &PublicKey,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if trusted_witness_issuer_keys.is_empty() {
        return Err(rejected(
            "trusted swarm witness keys missing: CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys",
        ));
    }
    if trusted_witness_issuer_keys
        .iter()
        .any(|trusted_key| trusted_key == public_key)
    {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm route-plan issuer is not trusted: {}",
            receipt.route_plan_id
        )))
    }
}

fn validate_join_receipts<'a>(
    bundle: &'a SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<BTreeMap<&'a str, &'a SwarmJoinReceipt>, SwarmAuthorityError> {
    let mut graph_joins = BTreeMap::new();
    for join in &bundle.task_graph.joins {
        graph_joins.insert(join.join_id.as_str(), join);
    }

    let mut receipts = BTreeMap::new();
    for receipt in &bundle.join_receipts {
        validate_join_receipt_schema(receipt, &bundle.task_graph.graph_id, bundle.now_unix_ms)?;
        verify_join_receipt_signature(receipt, trusted_witness_issuer_keys)?;
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
        if receipt.expected_parent_receipt_ids.len() != graph_join.parent_task_ids.len() {
            return Err(rejected(format!(
                "swarm join receipt parent count mismatch: {}",
                receipt.join_id
            )));
        }
        validate_join_predicate(receipt)?;
        validate_actual_parent_receipt_subset(receipt)?;
        let parent_set_hash = join_parent_set_hash(receipt)?;
        if receipt.parent_set_hash != parent_set_hash {
            return Err(rejected(format!(
                "swarm join receipt parent set hash mismatch: {}",
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
    if receipt.parent_task_receipts.len() != receipt.actual_parent_receipt_ids.len() {
        return Err(rejected(format!(
            "swarm join receipt parent task receipts mismatch: {}",
            receipt.join_id
        )));
    }

    let mut task_ids = Vec::with_capacity(receipt.parent_task_receipts.len());
    let mut receipt_ids = Vec::with_capacity(receipt.parent_task_receipts.len());
    let expected_actual_pairs = expected_actual_parent_receipt_pairs(receipt, graph_join);
    let expected_actual_pair_set = expected_actual_pairs
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for parent in &receipt.parent_task_receipts {
        require_non_empty(&parent.task_id, "swarm join parent task receipt task")?;
        require_non_empty(&parent.receipt_id, "swarm join parent task receipt receipt")?;
        if !expected_actual_pair_set
            .contains(&(parent.task_id.as_str(), parent.receipt_id.as_str()))
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
    let expected_actual_task_ids = expected_actual_pairs
        .iter()
        .map(|(task_id, _receipt_id)| (*task_id).to_string())
        .collect::<Vec<_>>();
    let expected_actual_receipt_ids = expected_actual_pairs
        .iter()
        .map(|(_task_id, receipt_id)| (*receipt_id).to_string())
        .collect::<Vec<_>>();
    if sorted_strings(&task_ids) != sorted_strings(&expected_actual_task_ids)
        || sorted_strings(&receipt_ids) != sorted_strings(&receipt.actual_parent_receipt_ids)
        || sorted_strings(&receipt_ids) != sorted_strings(&expected_actual_receipt_ids)
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
    now_unix_ms: u64,
) -> Result<(), SwarmAuthorityError> {
    if receipt.schema != CHIO_SWARM_JOIN_RECEIPT_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm join receipt schema: {}",
            receipt.schema
        )));
    }
    require_non_empty(&receipt.join_id, "swarm join receipt id")?;
    require_same_graph(&receipt.graph_id, graph_id, "join receipt")?;
    require_non_empty(&receipt.chain_id, "swarm join receipt chain id")?;
    require_sha256(&receipt.parent_set_hash, "swarm join parent set hash")?;
    if receipt.dag_ordinal == 0 {
        return Err(rejected(format!(
            "swarm join receipt dag ordinal must be positive: {}",
            receipt.join_id
        )));
    }
    if receipt.hlc_unix_ms > now_unix_ms {
        return Err(rejected(format!(
            "swarm join receipt is from the future: {}",
            receipt.join_id
        )));
    }
    require_non_empty(&receipt.join_predicate, "swarm join predicate")?;
    require_sha256(&receipt.result_digest, "swarm join result digest")?;
    require_non_empty(&receipt.issuer, "swarm join receipt issuer")?;
    require_non_empty(&receipt.signature, "swarm join receipt signature")?;
    Ok(())
}

fn validate_join_predicate(receipt: &SwarmJoinReceipt) -> Result<(), SwarmAuthorityError> {
    let expected_len = receipt.expected_parent_receipt_ids.len();
    let actual_len = receipt.actual_parent_receipt_ids.len();
    match receipt.join_predicate.as_str() {
        "all_success" => {
            if sorted_strings(&receipt.expected_parent_receipt_ids)
                != sorted_strings(&receipt.actual_parent_receipt_ids)
            {
                return Err(rejected(format!(
                    "swarm join receipt parent set mismatch: {}",
                    receipt.join_id
                )));
            }
            Ok(())
        }
        "any_success" => {
            if actual_len == 0 {
                return Err(rejected(format!(
                    "swarm join receipt parent set mismatch: {}",
                    receipt.join_id
                )));
            }
            Ok(())
        }
        predicate if predicate.starts_with("quorum:") => {
            let quorum = predicate
                .strip_prefix("quorum:")
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| {
                    rejected(format!(
                        "swarm join receipt predicate unsupported: {}",
                        receipt.join_predicate
                    ))
                })?;
            if quorum == 0 || quorum > expected_len {
                return Err(rejected(format!(
                    "swarm join receipt predicate unsupported: {}",
                    receipt.join_predicate
                )));
            }
            if actual_len < quorum {
                return Err(rejected(format!(
                    "swarm join receipt parent set mismatch: {}",
                    receipt.join_id
                )));
            }
            Ok(())
        }
        _ => Err(rejected(format!(
            "swarm join receipt predicate unsupported: {}",
            receipt.join_predicate
        ))),
    }
}

fn validate_actual_parent_receipt_subset(
    receipt: &SwarmJoinReceipt,
) -> Result<(), SwarmAuthorityError> {
    let expected = receipt
        .expected_parent_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if receipt
        .actual_parent_receipt_ids
        .iter()
        .any(|receipt_id| !expected.contains(receipt_id.as_str()))
    {
        return Err(rejected(format!(
            "swarm join receipt parent set mismatch: {}",
            receipt.join_id
        )));
    }
    Ok(())
}

fn expected_actual_parent_receipt_pairs<'a>(
    receipt: &'a SwarmJoinReceipt,
    graph_join: &'a SwarmGraphJoin,
) -> Vec<(&'a str, &'a str)> {
    let actual_receipts = receipt
        .actual_parent_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    graph_join
        .parent_task_ids
        .iter()
        .zip(receipt.expected_parent_receipt_ids.iter())
        .filter_map(|(task_id, receipt_id)| {
            if actual_receipts.contains(receipt_id.as_str()) {
                Some((task_id.as_str(), receipt_id.as_str()))
            } else {
                None
            }
        })
        .collect()
}

fn verify_join_receipt_signature(
    receipt: &SwarmJoinReceipt,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    let public_key = witness_issuer_public_key(&receipt.issuer)?;
    ensure_join_issuer_is_pinned(receipt, &public_key, trusted_witness_issuer_keys)?;
    let signature = Signature::from_hex(&receipt.signature).map_err(|error| {
        rejected(format!(
            "swarm join receipt signature invalid: {}: {error}",
            receipt.join_id
        ))
    })?;
    let body = join_receipt_signature_body(receipt)?;
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm join receipt signature invalid: {}",
            receipt.join_id
        )))
    }
}

fn ensure_join_issuer_is_pinned(
    receipt: &SwarmJoinReceipt,
    public_key: &PublicKey,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if trusted_witness_issuer_keys.is_empty() {
        return Err(rejected(
            "trusted swarm witness keys missing: CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys",
        ));
    }
    if trusted_witness_issuer_keys
        .iter()
        .any(|trusted_key| trusted_key == public_key)
    {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm join receipt issuer is not trusted: {}",
            receipt.join_id
        )))
    }
}

fn join_parent_set_hash(receipt: &SwarmJoinReceipt) -> Result<String, SwarmAuthorityError> {
    join_parent_set_hash_from_parts(&receipt.chain_id, &receipt.actual_parent_receipt_ids)
}

fn join_parent_set_hash_from_parts(
    chain_id: &str,
    receipt_ids: &[String],
) -> Result<String, SwarmAuthorityError> {
    let mut receipt_ids = receipt_ids.to_vec();
    receipt_ids.sort();
    let body = serde_json::json!({
        "chainId": chain_id,
        "parentReceiptIds": receipt_ids,
    });
    let canonical = canonical_json_bytes(&body)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&canonical))
}

fn validate_budget_pool<'a>(
    bundle: &'a SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
) -> Result<BTreeMap<&'a str, &'a SwarmBudgetAllocation>, SwarmAuthorityError> {
    let budget = &bundle.budget_pool;
    validate_swarm_budget_pool_accounting(budget)?;
    require_same_graph(&budget.graph_id, &bundle.task_graph.graph_id, "budget pool")?;
    if budget.pool_id != bundle.task_graph.budget_pool_ref {
        return Err(rejected("swarm budget pool ref mismatch"));
    }
    let mut allocations = BTreeMap::new();
    for allocation in &budget.allocations {
        if !task_by_id.contains_key(allocation.task_id.as_str()) {
            return Err(rejected(format!(
                "swarm budget allocation task is unknown: {}",
                allocation.task_id
            )));
        }
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
    Ok(allocations)
}

fn validate_revocation_epoch(
    bundle: &SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    trusted_witness_issuer_keys: &[PublicKey],
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
    let computed_root_hash = revocation_epoch_list_root_hash(epoch)?;
    if computed_root_hash != epoch.root_hash {
        return Err(rejected("swarm revocation epoch root mismatch"));
    }
    verify_revocation_epoch_signature(epoch, trusted_witness_issuer_keys)?;
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

fn verify_revocation_epoch_signature(
    epoch: &SwarmRevocationEpoch,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    require_non_empty(&epoch.issuer, "swarm revocation epoch issuer")?;
    require_non_empty(&epoch.signature, "swarm revocation epoch signature")?;
    let public_key = witness_issuer_public_key(&epoch.issuer)?;
    if trusted_witness_issuer_keys
        .iter()
        .all(|trusted| trusted != &public_key)
    {
        return Err(rejected(format!(
            "swarm revocation epoch issuer is not pinned: {}",
            epoch.epoch_id
        )));
    }
    let signature = Signature::from_hex(&epoch.signature).map_err(|error| {
        rejected(format!(
            "swarm revocation epoch signature invalid: {}: {error}",
            epoch.epoch_id
        ))
    })?;
    let body = revocation_epoch_signature_body(epoch)?;
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm revocation epoch signature invalid: {}",
            epoch.epoch_id
        )))
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RevocationEpochListRoot<'a> {
    revoked_subjects: Vec<&'a str>,
    revoked_task_ids: Vec<&'a str>,
}

fn revocation_epoch_list_root_hash(
    epoch: &SwarmRevocationEpoch,
) -> Result<String, SwarmAuthorityError> {
    canonical_sha256(&RevocationEpochListRoot {
        revoked_subjects: sorted_strings(&epoch.revoked_subjects),
        revoked_task_ids: sorted_strings(&epoch.revoked_task_ids),
    })
}

fn validate_terminal_graph_receipts(
    bundle: &SwarmAuthorityBundle,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    route_by_id: &BTreeMap<&str, &SwarmRoutePlanReceipt>,
    join_by_id: &BTreeMap<&str, &SwarmJoinReceipt>,
    allocation_by_id: &BTreeMap<&str, &SwarmBudgetAllocation>,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if bundle.terminal_receipts.is_empty() {
        return Err(rejected("missing swarm terminal graph receipt"));
    }

    let mut receipt_ids = BTreeSet::new();
    for receipt in &bundle.terminal_receipts {
        validate_terminal_graph_receipt_schema(receipt, bundle)?;
        verify_terminal_graph_receipt_signature(receipt, trusted_witness_issuer_keys)?;
        if !receipt_ids.insert(receipt.receipt_id.as_str()) {
            return Err(rejected(format!(
                "duplicate swarm terminal receipt: {}",
                receipt.receipt_id
            )));
        }
        validate_terminal_graph_receipt_refs(receipt, task_by_id, route_by_id, join_by_id)?;
        validate_terminal_budget_rollups(receipt, bundle, allocation_by_id)?;
    }
    Ok(())
}

fn validate_terminal_graph_receipt_schema(
    receipt: &SwarmTerminalGraphReceipt,
    bundle: &SwarmAuthorityBundle,
) -> Result<(), SwarmAuthorityError> {
    if receipt.schema != CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA {
        return Err(rejected(format!(
            "unsupported swarm terminal receipt schema: {}",
            receipt.schema
        )));
    }
    require_non_empty(&receipt.receipt_id, "swarm terminal receipt id")?;
    require_same_graph(
        &receipt.graph_id,
        &bundle.task_graph.graph_id,
        "terminal receipt",
    )?;
    require_non_empty(&receipt.chain_id, "swarm terminal receipt chain id")?;
    require_unique_strings(&receipt.terminal_task_ids, "swarm terminal task")?;
    require_unique_strings(&receipt.completed_task_ids, "swarm completed task")?;
    require_unique_strings(&receipt.join_receipt_ids, "swarm terminal join receipt")?;
    require_unique_strings(
        &receipt.route_plan_receipt_ids,
        "swarm terminal route-plan receipt",
    )?;
    if receipt.budget_pool_id != bundle.budget_pool.pool_id {
        return Err(rejected(format!(
            "swarm terminal budget pool mismatch: {}",
            receipt.receipt_id
        )));
    }
    if receipt.revocation_epoch_ref != bundle.revocation_epoch.epoch_id {
        return Err(rejected(format!(
            "swarm terminal revocation epoch mismatch: {}",
            receipt.receipt_id
        )));
    }
    require_sha256(&receipt.result_digest, "swarm terminal result digest")?;
    if receipt.completed_at_unix_ms > bundle.now_unix_ms {
        return Err(rejected(format!(
            "swarm terminal receipt is from the future: {}",
            receipt.receipt_id
        )));
    }
    require_non_empty(&receipt.issuer, "swarm terminal receipt issuer")?;
    require_non_empty(&receipt.signature, "swarm terminal receipt signature")?;
    Ok(())
}

fn validate_terminal_graph_receipt_refs(
    receipt: &SwarmTerminalGraphReceipt,
    task_by_id: &BTreeMap<&str, &SwarmGraphNode>,
    route_by_id: &BTreeMap<&str, &SwarmRoutePlanReceipt>,
    join_by_id: &BTreeMap<&str, &SwarmJoinReceipt>,
) -> Result<(), SwarmAuthorityError> {
    for terminal_task_id in &receipt.terminal_task_ids {
        if !task_by_id.contains_key(terminal_task_id.as_str()) {
            return Err(rejected(format!(
                "swarm terminal task is unknown: {terminal_task_id}"
            )));
        }
    }
    let expected_task_ids = task_by_id
        .keys()
        .map(|task_id| (*task_id).to_string())
        .collect::<Vec<_>>();
    if sorted_strings(&receipt.completed_task_ids) != sorted_strings(&expected_task_ids) {
        return Err(rejected(format!(
            "swarm terminal completed task set mismatch: {}",
            receipt.receipt_id
        )));
    }

    let expected_join_ids = join_by_id
        .keys()
        .map(|join_id| (*join_id).to_string())
        .collect::<Vec<_>>();
    if sorted_strings(&receipt.join_receipt_ids) != sorted_strings(&expected_join_ids) {
        return Err(rejected(format!(
            "swarm terminal join receipt set mismatch: {}",
            receipt.receipt_id
        )));
    }

    let expected_route_ids = route_by_id
        .keys()
        .map(|route_id| (*route_id).to_string())
        .collect::<Vec<_>>();
    if sorted_strings(&receipt.route_plan_receipt_ids) != sorted_strings(&expected_route_ids) {
        return Err(rejected(format!(
            "swarm terminal route-plan set mismatch: {}",
            receipt.receipt_id
        )));
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct BudgetRollupTotals {
    reserved_units: u64,
    active_units: u64,
    consumed_units: u64,
    released_units: u64,
    reversed_units: u64,
}

impl BudgetRollupTotals {
    fn add_allocation(
        &mut self,
        allocation: &SwarmBudgetAllocation,
    ) -> Result<(), SwarmAuthorityError> {
        self.reserved_units = self
            .reserved_units
            .checked_add(allocation.reserved_units)
            .ok_or_else(|| rejected("swarm terminal budget rollup overflow"))?;
        self.active_units = self
            .active_units
            .checked_add(allocation.active_units)
            .ok_or_else(|| rejected("swarm terminal budget rollup overflow"))?;
        self.consumed_units = self
            .consumed_units
            .checked_add(allocation.consumed_units)
            .ok_or_else(|| rejected("swarm terminal budget rollup overflow"))?;
        self.released_units = self
            .released_units
            .checked_add(allocation.released_units)
            .ok_or_else(|| rejected("swarm terminal budget rollup overflow"))?;
        self.reversed_units = self
            .reversed_units
            .checked_add(allocation.reversed_units)
            .ok_or_else(|| rejected("swarm terminal budget rollup overflow"))?;
        Ok(())
    }

    fn total_units(&self) -> Result<u64, SwarmAuthorityError> {
        self.reserved_units
            .checked_add(self.active_units)
            .and_then(|units| units.checked_add(self.consumed_units))
            .and_then(|units| units.checked_add(self.released_units))
            .and_then(|units| units.checked_add(self.reversed_units))
            .ok_or_else(|| rejected("swarm terminal budget rollup overflow"))
    }
}

fn validate_terminal_budget_rollups(
    receipt: &SwarmTerminalGraphReceipt,
    bundle: &SwarmAuthorityBundle,
    allocation_by_id: &BTreeMap<&str, &SwarmBudgetAllocation>,
) -> Result<(), SwarmAuthorityError> {
    let mut expected = BTreeMap::<&str, BudgetRollupTotals>::new();
    for allocation in allocation_by_id.values() {
        expected
            .entry(allocation.dimension_id.as_str())
            .or_default()
            .add_allocation(allocation)?;
    }

    let mut actual = BTreeMap::<&str, BudgetRollupTotals>::new();
    for rollup in &receipt.budget_rollups {
        require_non_empty(&rollup.dimension_id, "swarm terminal budget dimension")?;
        if actual
            .insert(rollup.dimension_id.as_str(), totals_from_rollup(rollup)?)
            .is_some()
        {
            return Err(rejected(format!(
                "duplicate swarm terminal budget rollup: {}",
                rollup.dimension_id
            )));
        }
    }

    if actual != expected {
        return Err(rejected(format!(
            "swarm terminal budget rollup mismatch: {}",
            receipt.receipt_id
        )));
    }

    let total_units = actual.values().try_fold(0_u64, |total, rollup| {
        total
            .checked_add(rollup.total_units()?)
            .ok_or_else(|| rejected("swarm terminal budget rollup overflow"))
    })?;
    if total_units > bundle.budget_pool.total_units {
        return Err(rejected(format!(
            "swarm terminal budget exceeds pool total: {}",
            receipt.receipt_id
        )));
    }
    Ok(())
}

fn totals_from_rollup(
    rollup: &SwarmTerminalBudgetRollup,
) -> Result<BudgetRollupTotals, SwarmAuthorityError> {
    let totals = BudgetRollupTotals {
        reserved_units: rollup.reserved_units,
        active_units: rollup.active_units,
        consumed_units: rollup.consumed_units,
        released_units: rollup.released_units,
        reversed_units: rollup.reversed_units,
    };
    if totals.total_units()? != rollup.total_units {
        return Err(rejected(format!(
            "swarm terminal budget rollup total mismatch: {}",
            rollup.dimension_id
        )));
    }
    Ok(totals)
}

fn verify_terminal_graph_receipt_signature(
    receipt: &SwarmTerminalGraphReceipt,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    let public_key = witness_issuer_public_key(&receipt.issuer)?;
    ensure_terminal_receipt_issuer_is_pinned(receipt, &public_key, trusted_witness_issuer_keys)?;
    let signature = Signature::from_hex(&receipt.signature).map_err(|error| {
        rejected(format!(
            "swarm terminal receipt signature invalid: {}: {error}",
            receipt.receipt_id
        ))
    })?;
    let body = terminal_graph_receipt_signature_body(receipt)?;
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm terminal receipt signature invalid: {}",
            receipt.receipt_id
        )))
    }
}

fn ensure_terminal_receipt_issuer_is_pinned(
    receipt: &SwarmTerminalGraphReceipt,
    public_key: &PublicKey,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if trusted_witness_issuer_keys.is_empty() {
        return Err(rejected(
            "trusted swarm witness keys missing: CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys",
        ));
    }
    if trusted_witness_issuer_keys
        .iter()
        .any(|trusted_key| trusted_key == public_key)
    {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm terminal receipt issuer is not trusted: {}",
            receipt.receipt_id
        )))
    }
}

struct ContinuationValidationContext<'a, 'b> {
    bundle: &'a SwarmAuthorityBundle,
    graph_sha256: &'a str,
    task_by_id: &'a BTreeMap<&'b str, &'b SwarmGraphNode>,
    edge_set: &'a BTreeSet<(&'b str, &'b str)>,
    route_by_id: &'a BTreeMap<&'b str, &'b SwarmRoutePlanReceipt>,
    join_by_id: &'a BTreeMap<&'b str, &'b SwarmJoinReceipt>,
    allocation_by_id: &'a BTreeMap<&'b str, &'b SwarmBudgetAllocation>,
    trusted_witness_issuer_keys: &'a [PublicKey],
}

fn validate_continuation_tokens(
    context: &ContinuationValidationContext<'_, '_>,
) -> Result<(), SwarmAuthorityError> {
    let mut continuations = BTreeMap::new();
    let mut continuation_nonces = BTreeSet::new();
    for token in &context.bundle.continuation_tokens {
        validate_continuation_token(context, token)?;
        verify_continuation_token_signature(token, context.trusted_witness_issuer_keys)?;
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
    for node in &context.bundle.task_graph.nodes {
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
    require_non_empty(&token.issuer, "swarm continuation issuer")?;
    require_non_empty(&token.signature, "swarm continuation signature")?;
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
    validate_continuation_parent(token, child_task, context.edge_set, context.join_by_id)?;
    validate_continuation_witness_chain(token, bundle)?;
    validate_continuation_route(token, child_task, context.route_by_id)?;
    validate_continuation_budget(token, child_task, context.allocation_by_id)?;
    if token.revocation_epoch_ref != bundle.revocation_epoch.epoch_id {
        return Err(rejected(format!(
            "swarm continuation revocation epoch mismatch: {}",
            token.token_id
        )));
    }
    require_sha256(
        &token.revocation_epoch_root_hash,
        "swarm continuation revocation epoch root",
    )?;
    if token.revocation_epoch_root_hash != bundle.revocation_epoch.root_hash {
        return Err(rejected(format!(
            "swarm continuation revocation epoch root mismatch: {}",
            token.token_id
        )));
    }
    Ok(())
}

fn validate_continuation_witness_chain(
    token: &SwarmContinuationToken,
    bundle: &SwarmAuthorityBundle,
) -> Result<(), SwarmAuthorityError> {
    let Some(parent_task_id) = token.parent_task_id.as_deref() else {
        if token.witness_chain_ref.is_some() || token.witness_chain_sha256.is_some() {
            return Err(rejected(format!(
                "swarm continuation witness chain binding without parent task: {}",
                token.token_id
            )));
        }
        return Ok(());
    };
    let witness_chain_ref = token.witness_chain_ref.as_deref().ok_or_else(|| {
        rejected(format!(
            "swarm continuation witness chain binding missing: {}",
            token.token_id
        ))
    })?;
    require_non_empty(witness_chain_ref, "swarm continuation witness chain ref")?;
    let witness_chain_sha256 = token.witness_chain_sha256.as_deref().ok_or_else(|| {
        rejected(format!(
            "swarm continuation witness chain digest missing: {}",
            token.token_id
        ))
    })?;
    require_sha256(
        witness_chain_sha256,
        "swarm continuation witness chain digest",
    )?;
    let chain = bundle
        .witness_chains
        .iter()
        .find(|chain| chain.chain_id == witness_chain_ref)
        .ok_or_else(|| {
            rejected(format!(
                "swarm continuation witness chain mismatch: {}",
                token.token_id
            ))
        })?;
    if chain.parent_task_id != parent_task_id || chain.child_task_id != token.child_task_id {
        return Err(rejected(format!(
            "swarm continuation witness chain mismatch: {}",
            token.token_id
        )));
    }
    let actual_sha256 = canonical_sha256(chain)?;
    if actual_sha256 != witness_chain_sha256 {
        return Err(rejected(format!(
            "swarm continuation witness chain digest mismatch: {}",
            token.token_id
        )));
    }
    Ok(())
}

fn verify_continuation_token_signature(
    token: &SwarmContinuationToken,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    let public_key = witness_issuer_public_key(&token.issuer)?;
    ensure_continuation_issuer_is_pinned(token, &public_key, trusted_witness_issuer_keys)?;
    let signature = Signature::from_hex(&token.signature).map_err(|error| {
        rejected(format!(
            "swarm continuation signature invalid: {}: {error}",
            token.token_id
        ))
    })?;
    let body = continuation_token_signature_body(token)?;
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| SwarmAuthorityError::Canonical(error.to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm continuation signature invalid: {}",
            token.token_id
        )))
    }
}

fn ensure_continuation_issuer_is_pinned(
    token: &SwarmContinuationToken,
    public_key: &PublicKey,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if trusted_witness_issuer_keys.is_empty() {
        return Err(rejected(
            "trusted swarm witness keys missing: CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys",
        ));
    }
    if trusted_witness_issuer_keys
        .iter()
        .any(|trusted_key| trusted_key == public_key)
    {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm continuation issuer is not trusted: {}",
            token.token_id
        )))
    }
}

fn validate_continuation_parent(
    token: &SwarmContinuationToken,
    child_task: &SwarmGraphNode,
    edge_set: &BTreeSet<(&str, &str)>,
    join_by_id: &BTreeMap<&str, &SwarmJoinReceipt>,
) -> Result<(), SwarmAuthorityError> {
    match (&token.parent_task_id, &token.join_receipt_id) {
        (Some(parent_task_id), None) => {
            if child_task.parent_task_id.as_deref() != Some(parent_task_id.as_str()) {
                return Err(rejected(format!(
                    "swarm continuation parent task mismatch: {}",
                    token.token_id
                )));
            }
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
    if allocation.state != SwarmBudgetAllocationState::Active {
        return Err(rejected(format!(
            "swarm budget allocation is not active: {}",
            allocation.allocation_id
        )));
    }
    Ok(())
}
