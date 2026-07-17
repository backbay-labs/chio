use std::collections::BTreeSet;

use chio_core_types::crypto::{PublicKey, Signature};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::super::error::TransactionPassportError;
use super::super::ids::{
    POLICY_ACTIVATION_RECEIPT_SCHEMA_ID, RUNTIME_ATTACK_SIMULATION_REPORT_SCHEMA_ID,
    RUNTIME_CHAOS_RUN_REPORT_SCHEMA_ID, RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID,
    RUNTIME_TRUSTED_TIME_PROOF_SCHEMA_ID, SWARM_BUDGET_POOL_SCHEMA_ID,
    SWARM_JOIN_RECEIPT_SCHEMA_ID, SWARM_ROUTE_PLAN_RECEIPT_SCHEMA_ID, SWARM_TASK_GRAPH_SCHEMA_ID,
};
use super::super::validation::validate_bundle_relative_path;
use super::super::validation::validate_sha256_hex;
use super::evidence::{parse_artifact, RuntimeEvidenceGraph, RuntimeEvidenceRole};
use super::RuntimeSecurityBundle;

const DID_CHIO_PREFIX: &str = "did:chio:";
const RUNTIME_EXECUTION_LEASE_SIGNATURE_SCHEMA: &str = "chio.runtime.execution-lease-signature.v1";
const RUNTIME_REVOCATION_FRESHNESS_PROOF_SIGNATURE_SCHEMA: &str =
    "chio.runtime.revocation-freshness-proof-signature.v1";
const RUNTIME_SANDBOX_ATTESTATION_SIGNATURE_SCHEMA: &str =
    "chio.runtime.sandbox-attestation-signature.v1";
const RUNTIME_TERMINAL_RECEIPT_SIGNATURE_SCHEMA: &str =
    "chio.runtime.terminal-receipt-signature.v1";
const RUNTIME_TOOL_SERVER_ACK_SIGNATURE_SCHEMA: &str = "chio.runtime.tool-server-ack-signature.v1";
const RUNTIME_TRUSTED_TIME_PROOF_SIGNATURE_SCHEMA: &str =
    "chio.runtime.trusted-time-proof-signature.v1";
const POLICY_ACTIVATION_RECEIPT_SIGNATURE_SCHEMA: &str =
    "chio.policy.activation-receipt-signature.v1";
const RUNTIME_ATTACK_SIMULATION_REPORT_SIGNATURE_SCHEMA: &str =
    "chio.runtime.attack-simulation-report-signature.v1";
const RUNTIME_CHAOS_RUN_REPORT_SIGNATURE_SCHEMA: &str =
    "chio.runtime.chaos-run-report-signature.v1";
const SWARM_ROUTE_PLAN_RECEIPT_SIGNATURE_SCHEMA: &str =
    "chio.swarm.route-plan-receipt-signature.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeExecutionLease {
    schema: String,
    pub(super) lease_id: String,
    subject_agent: String,
    tool_server_id: String,
    tool_instance_id: String,
    tool_manifest_digest: String,
    pub(super) sandbox_attestation_ref: String,
    capability_digest: String,
    request_digest: String,
    response_policy_digest: String,
    task_graph_digest: String,
    child_task_id: String,
    parent_receipt_ref: String,
    join_receipt_ref: String,
    budget_pool_ref: String,
    budget_allocation_ref: String,
    subject_capability_digest: String,
    ancestor_capability_digest: String,
    revocation_epoch_ref: Option<String>,
    pub(super) route_plan_receipt_ref: Option<String>,
    pub(super) revocation_freshness_ref: String,
    policy_digest: String,
    pub(super) nonce: String,
    side_effect_class: String,
    max_invocations: Option<u64>,
    issued_at: String,
    expires_at: String,
    issuer: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeRequestDigest {
    schema: String,
    id: String,
    method: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimePolicyActivationReceipt {
    schema: String,
    policy_digest: String,
    previous_policy_digest: String,
    activation_epoch: String,
    activated_at: String,
    activation_mode: String,
    narrowing_or_widening: String,
    migration_rule: String,
    issuer: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeAttackSimulationReport {
    schema: String,
    scenario_id: String,
    attack_class: String,
    fixture_path: String,
    expected_denial_claim: String,
    actual_verifier_report_digest: String,
    runtime_receipt_refs: Vec<String>,
    #[serde(default)]
    chaos_knobs: Vec<String>,
    status: String,
    simulator_version_digest: String,
    issuer: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeChaosRunReport {
    schema: String,
    case_id: String,
    failure_injected: String,
    expected_result: String,
    actual_verifier_report_digest: String,
    runtime_receipt_refs: Vec<String>,
    deterministic_seed_digest: String,
    status: String,
    runner_version_digest: String,
    issuer: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RuntimeRoutePlanReceipt {
    schema: String,
    route_plan_id: String,
    graph_id: String,
    task_id: String,
    selected_route: String,
    candidate_set_digest: String,
    registry_snapshot_hash: String,
    bridge_id: String,
    protocol_target: String,
    egress_contract_id: String,
    egress_constraints: Vec<String>,
    attenuation_decision: String,
    policy_digest: String,
    expires_at_unix_ms: u64,
    issuer: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RuntimeTaskGraph {
    schema: String,
    graph_id: String,
    root_transaction_ref: String,
    planner_subject: String,
    issuer: String,
    signature: String,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    max_depth: u64,
    max_fanout: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    multi_hop_witness_chains: Option<bool>,
    nodes: Vec<RuntimeTaskGraphNode>,
    edges: Vec<RuntimeTaskGraphEdge>,
    joins: Vec<RuntimeTaskGraphJoin>,
    budget_pool_ref: String,
    revocation_epoch_ref: String,
    route_plan_refs: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeTaskGraphNode {
    task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_plan_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation_token_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    budget_allocation_ref: Option<String>,
    scope_hash: String,
    depth: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeTaskGraphEdge {
    from_task_id: String,
    to_task_id: String,
    edge_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeTaskGraphJoin {
    join_id: String,
    parent_task_ids: Vec<String>,
    next_task_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RuntimeBudgetPool {
    schema: String,
    pool_id: String,
    graph_id: String,
    currency: String,
    total_units: u64,
    allocations: Vec<RuntimeBudgetAllocation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeBudgetAllocation {
    allocation_id: String,
    task_id: String,
    dimension_id: String,
    state: String,
    max_units: u64,
    reserved_units: u64,
    active_units: u64,
    consumed_units: u64,
    released_units: u64,
    reversed_units: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RuntimeJoinReceipt {
    schema: String,
    join_id: String,
    graph_id: String,
    chain_id: String,
    parent_set_hash: String,
    dag_ordinal: u64,
    hlc_unix_ms: u64,
    parent_task_receipts: Vec<RuntimeParentTaskReceipt>,
    expected_parent_receipt_ids: Vec<String>,
    actual_parent_receipt_ids: Vec<String>,
    join_predicate: String,
    result_digest: String,
    next_task_id: String,
    issuer: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeParentTaskReceipt {
    task_id: String,
    receipt_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeTrustRoot {
    schema: String,
    id: String,
    #[serde(default)]
    authority: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roots: Vec<RuntimeTrustRootEntry>,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTrustRootEntry {
    subject: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeRevocationFreshnessProof {
    schema: String,
    pub(super) proof_id: String,
    oracle_id: String,
    epoch_id: String,
    epoch_root: String,
    sequence: u64,
    fetched_at: String,
    max_staleness_ms: u64,
    subject_capability_digest: String,
    ancestor_capability_digest: String,
    revoked_leaf_result: bool,
    revoked_ancestor_result: bool,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeSandboxAttestation {
    schema: String,
    pub(super) attestation_id: String,
    tool_server_id: String,
    tool_instance_id: String,
    tool_manifest_digest: String,
    sandbox_profile_digest: String,
    egress_policy_digest: String,
    started_at: String,
    expires_at: String,
    attester: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeToolServerAck {
    schema: String,
    ack_id: String,
    pub(super) lease_id: String,
    tool_server_id: String,
    tool_instance_id: String,
    sandbox_attestation_ref: String,
    nonce: String,
    terminal_status: String,
    issued_at: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeTrustedTimeProof {
    schema: String,
    proof_id: String,
    lease_id: String,
    ack_id: String,
    observed_at: String,
    max_clock_skew_ms: u64,
    time_source_id: String,
    issuer: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeTerminalReceipt {
    schema: String,
    receipt_id: String,
    pub(super) terminal_status: String,
    policy_digest: String,
    #[serde(default)]
    pub(super) execution_lease_ref: Option<String>,
    #[serde(default)]
    incident_ref: Option<String>,
    kernel_key: String,
    signature: String,
}

pub(super) fn validate_execution_lease(
    lease: &RuntimeExecutionLease,
    policy_digest: &str,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &lease.schema),
        ("lease_id", &lease.lease_id),
        ("subject_agent", &lease.subject_agent),
        ("tool_server_id", &lease.tool_server_id),
        ("tool_instance_id", &lease.tool_instance_id),
        ("sandbox_attestation_ref", &lease.sandbox_attestation_ref),
        ("revocation_freshness_ref", &lease.revocation_freshness_ref),
        ("child_task_id", &lease.child_task_id),
        ("parent_receipt_ref", &lease.parent_receipt_ref),
        ("join_receipt_ref", &lease.join_receipt_ref),
        ("budget_pool_ref", &lease.budget_pool_ref),
        ("budget_allocation_ref", &lease.budget_allocation_ref),
        ("nonce", &lease.nonce),
        ("side_effect_class", &lease.side_effect_class),
        ("issued_at", &lease.issued_at),
        ("expires_at", &lease.expires_at),
        ("issuer", &lease.issuer),
        ("signature", &lease.signature),
    ] {
        require_non_empty(value, field)?;
    }
    for (field, digest) in [
        ("tool_manifest_digest", &lease.tool_manifest_digest),
        ("capability_digest", &lease.capability_digest),
        ("request_digest", &lease.request_digest),
        ("response_policy_digest", &lease.response_policy_digest),
        ("task_graph_digest", &lease.task_graph_digest),
        (
            "subject_capability_digest",
            &lease.subject_capability_digest,
        ),
        (
            "ancestor_capability_digest",
            &lease.ancestor_capability_digest,
        ),
        ("policy_digest", &lease.policy_digest),
    ] {
        validate_digest_field(field, digest)?;
    }
    if lease.policy_digest != policy_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "policy digest mismatch".to_string(),
        ));
    }
    if !is_governed_side_effect_class(&lease.side_effect_class) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease side effect class is not governed".to_string(),
        ));
    }
    if let Some(revocation_epoch_ref) = lease.revocation_epoch_ref.as_deref() {
        require_non_empty(revocation_epoch_ref, "revocation_epoch_ref")?;
    }
    let route_plan_receipt_ref = lease.route_plan_receipt_ref.as_deref().ok_or_else(|| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease route plan receipt missing".to_string(),
        )
    })?;
    require_non_empty(route_plan_receipt_ref, "route_plan_receipt_ref")?;
    if let Some(max_invocations) = lease.max_invocations {
        if max_invocations != 1 {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "execution lease max_invocations must be 1".to_string(),
            ));
        }
    }
    let issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    if expires_at <= issued_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease expired before issuance".to_string(),
        ));
    }
    validate_execution_lease_trust_root(lease, trusted_roots, trusted_root_signer_keys)?;
    verify_execution_lease_signature(lease)?;
    Ok(())
}

pub(super) struct ExecutionLeaseContext<'a> {
    pub(super) task_graph_sha256: &'a str,
    pub(super) task_graph: &'a RuntimeTaskGraph,
    pub(super) route_plan: &'a RuntimeRoutePlanReceipt,
    pub(super) budget_pool: &'a RuntimeBudgetPool,
    pub(super) join_receipt: &'a RuntimeJoinReceipt,
    pub(super) trusted_roots: &'a [&'a RuntimeTrustRoot],
    pub(super) trusted_root_signer_keys: &'a [PublicKey],
}

pub(super) fn validate_execution_lease_context(
    lease: &RuntimeExecutionLease,
    context: ExecutionLeaseContext<'_>,
) -> Result<(), TransactionPassportError> {
    let ExecutionLeaseContext {
        task_graph_sha256,
        task_graph,
        route_plan,
        budget_pool,
        join_receipt,
        trusted_roots,
        trusted_root_signer_keys,
    } = context;
    if task_graph.schema != SWARM_TASK_GRAPH_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "task graph schema mismatch".to_string(),
        ));
    }
    for (field, value) in [
        ("task graph id", &task_graph.graph_id),
        (
            "task graph root transaction",
            &task_graph.root_transaction_ref,
        ),
        ("task graph planner subject", &task_graph.planner_subject),
        ("task graph issuer", &task_graph.issuer),
        ("task graph signature", &task_graph.signature),
        ("task graph budget pool ref", &task_graph.budget_pool_ref),
        (
            "task graph revocation epoch ref",
            &task_graph.revocation_epoch_ref,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    if task_graph.expires_at_unix_ms <= task_graph.created_at_unix_ms {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "task graph expired before creation".to_string(),
        ));
    }
    if task_graph.max_fanout == 0 {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "task graph max fanout must be positive".to_string(),
        ));
    }
    if task_graph.max_depth == 0 && task_graph.nodes.iter().any(|node| node.depth > 0) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "task graph max depth does not cover child tasks".to_string(),
        ));
    }
    if task_graph.multi_hop_witness_chains == Some(true) && task_graph.max_depth < 2 {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "task graph multi-hop setting requires depth".to_string(),
        ));
    }
    for route_plan_ref in &task_graph.route_plan_refs {
        require_non_empty(route_plan_ref, "task graph route plan ref")?;
    }
    for edge in &task_graph.edges {
        require_non_empty(&edge.from_task_id, "task graph edge from")?;
        require_non_empty(&edge.to_task_id, "task graph edge to")?;
        require_non_empty(&edge.edge_type, "task graph edge type")?;
    }
    for join in &task_graph.joins {
        require_non_empty(&join.join_id, "task graph join id")?;
        require_non_empty(&join.next_task_id, "task graph join next task")?;
        if join.parent_task_ids.is_empty() {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "task graph join parent tasks missing".to_string(),
            ));
        }
        for parent_task_id in &join.parent_task_ids {
            require_non_empty(parent_task_id, "task graph join parent task")?;
        }
    }
    if task_graph_sha256 != lease.task_graph_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease task graph digest mismatch".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "task graph issuer",
        &task_graph.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_task_graph_signature(task_graph)?;
    if !task_graph
        .route_plan_refs
        .iter()
        .any(|route_plan_ref| route_plan_ref == &route_plan.route_plan_id)
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease route plan not listed in task graph".to_string(),
        ));
    }
    if route_plan.graph_id != task_graph.graph_id {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease route plan graph mismatch".to_string(),
        ));
    }
    if route_plan.task_id != lease.child_task_id {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease child task mismatch".to_string(),
        ));
    }
    let task = task_graph
        .nodes
        .iter()
        .find(|node| node.task_id == lease.child_task_id)
        .ok_or_else(|| {
            TransactionPassportError::RuntimeSecurityClaimFailed(
                "execution lease child task missing from task graph".to_string(),
            )
        })?;
    require_non_empty(&task.scope_hash, "task graph child scope hash")?;
    validate_digest_field("task graph child scope hash", &task.scope_hash)?;
    if task.depth == 0 || task.parent_task_id.as_deref().is_none() {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease child task missing parent".to_string(),
        ));
    }
    if task.depth > task_graph.max_depth {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease child task exceeds graph depth".to_string(),
        ));
    }
    if let Some(continuation_token_ref) = task.continuation_token_ref.as_deref() {
        require_non_empty(continuation_token_ref, "task graph continuation token ref")?;
    }
    if task.route_plan_ref.as_deref() != Some(route_plan.route_plan_id.as_str()) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease child task route plan mismatch".to_string(),
        ));
    }
    if task.budget_allocation_ref.as_deref() != Some(lease.budget_allocation_ref.as_str()) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease child task budget allocation mismatch".to_string(),
        ));
    }
    if budget_pool.schema != SWARM_BUDGET_POOL_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "budget pool schema mismatch".to_string(),
        ));
    }
    require_non_empty(&budget_pool.currency, "budget pool currency")?;
    if budget_pool.total_units == 0 {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "budget pool total units missing".to_string(),
        ));
    }
    if budget_pool.pool_id != lease.budget_pool_ref {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease budget pool mismatch".to_string(),
        ));
    }
    if budget_pool.pool_id != task_graph.budget_pool_ref
        || budget_pool.graph_id != task_graph.graph_id
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease budget pool task graph mismatch".to_string(),
        ));
    }
    let allocation = budget_pool
        .allocations
        .iter()
        .find(|allocation| allocation.allocation_id == lease.budget_allocation_ref)
        .ok_or_else(|| {
            TransactionPassportError::RuntimeSecurityClaimFailed(
                "execution lease budget allocation missing".to_string(),
            )
        })?;
    if allocation.task_id != lease.child_task_id {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease budget allocation task mismatch".to_string(),
        ));
    }
    require_non_empty(&allocation.dimension_id, "budget allocation dimension")?;
    if allocation.max_units == 0 {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease budget allocation max units missing".to_string(),
        ));
    }
    let allocation_total = [
        allocation.reserved_units,
        allocation.active_units,
        allocation.consumed_units,
        allocation.released_units,
        allocation.reversed_units,
    ]
    .into_iter()
    .try_fold(0_u64, |total, units| total.checked_add(units))
    .ok_or_else(|| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease budget allocation exceeds max units".to_string(),
        )
    })?;
    if allocation_total > allocation.max_units {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease budget allocation exceeds max units".to_string(),
        ));
    }
    if !matches!(allocation.state.as_str(), "reserved" | "active") {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease budget allocation is not active".to_string(),
        ));
    }
    if join_receipt.schema != SWARM_JOIN_RECEIPT_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "join receipt schema mismatch".to_string(),
        ));
    }
    for (field, value) in [
        ("join receipt chain id", &join_receipt.chain_id),
        (
            "join receipt parent set hash",
            &join_receipt.parent_set_hash,
        ),
        ("join receipt predicate", &join_receipt.join_predicate),
        ("join receipt result digest", &join_receipt.result_digest),
        ("join receipt issuer", &join_receipt.issuer),
        ("join receipt signature", &join_receipt.signature),
    ] {
        require_non_empty(value, field)?;
    }
    validate_digest_field(
        "join receipt parent set hash",
        &join_receipt.parent_set_hash,
    )?;
    validate_digest_field("join receipt result digest", &join_receipt.result_digest)?;
    ensure_runtime_identity_is_trusted(
        "join receipt issuer",
        &join_receipt.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_join_receipt_signature(join_receipt)?;
    if join_receipt.dag_ordinal == 0 || join_receipt.hlc_unix_ms == 0 {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "join receipt ordering fields missing".to_string(),
        ));
    }
    if join_receipt.join_id != lease.join_receipt_ref {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease join receipt mismatch".to_string(),
        ));
    }
    if join_receipt.graph_id != task_graph.graph_id {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease join receipt graph mismatch".to_string(),
        ));
    }
    if join_receipt.next_task_id != lease.child_task_id {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease join receipt child task mismatch".to_string(),
        ));
    }
    if join_receipt.expected_parent_receipt_ids != join_receipt.actual_parent_receipt_ids
        || !join_receipt
            .actual_parent_receipt_ids
            .iter()
            .any(|receipt_id| receipt_id == &lease.parent_receipt_ref)
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease parent receipt mismatch".to_string(),
        ));
    }
    if !join_receipt.parent_task_receipts.iter().any(|receipt| {
        receipt.receipt_id == lease.parent_receipt_ref
            && receipt.task_id == task.parent_task_id.as_deref().unwrap_or_default()
    }) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease parent task receipt missing".to_string(),
        ));
    }
    Ok(())
}

fn verify_join_receipt_signature(
    receipt: &RuntimeJoinReceipt,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&receipt.issuer, "join receipt issuer")?;
    let signature = Signature::from_hex(&receipt.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "join receipt signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&join_receipt_signature_body(receipt)?, &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "join receipt signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "join receipt signature invalid".to_string(),
        ))
    }
}

fn join_receipt_signature_body(
    receipt: &RuntimeJoinReceipt,
) -> Result<serde_json::Value, TransactionPassportError> {
    let mut body = serde_json::to_value(receipt).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "join receipt signature body invalid: {error}"
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "join receipt signature body invalid".to_string(),
        )
    })?;
    object.remove("signature");
    Ok(body)
}

pub(super) fn validate_request_digest_binding(
    lease: &RuntimeExecutionLease,
    request: &RuntimeRequestDigest,
) -> Result<(), TransactionPassportError> {
    if request.schema != super::super::ids::REQUEST_DIGEST_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "request digest schema mismatch".to_string(),
        ));
    }
    require_non_empty(&request.id, "request digest id")?;
    require_non_empty(&request.method, "request digest method")?;
    validate_digest_field("request digest sha256", &request.sha256)?;
    if request.sha256 != lease.request_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease request digest mismatch".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_policy_activation_receipt(
    receipt: &RuntimePolicyActivationReceipt,
    policy_digest: &str,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if receipt.schema != POLICY_ACTIVATION_RECEIPT_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "policy activation receipt schema mismatch".to_string(),
        ));
    }
    for (field, value) in [
        ("policy_digest", &receipt.policy_digest),
        ("previous_policy_digest", &receipt.previous_policy_digest),
        ("activation_epoch", &receipt.activation_epoch),
        ("activated_at", &receipt.activated_at),
        ("activation_mode", &receipt.activation_mode),
        ("narrowing_or_widening", &receipt.narrowing_or_widening),
        ("migration_rule", &receipt.migration_rule),
        ("issuer", &receipt.issuer),
        ("signature", &receipt.signature),
    ] {
        require_non_empty(value, field)?;
    }
    validate_digest_field("policy_digest", &receipt.policy_digest)?;
    validate_digest_field("previous_policy_digest", &receipt.previous_policy_digest)?;
    if receipt.policy_digest != policy_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "policy activation digest mismatch".to_string(),
        ));
    }
    parse_rfc3339_utc(&receipt.activated_at, "policy activation activated_at")?;
    if !matches!(
        receipt.activation_mode.as_str(),
        "initial_load" | "hot_reload"
    ) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "unsupported policy activation mode".to_string(),
        ));
    }
    match receipt.narrowing_or_widening.as_str() {
        "narrowing" | "same" => {}
        "widening" => {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "policy activation cannot widen in-flight authority".to_string(),
            ));
        }
        _ => {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "unsupported policy activation direction".to_string(),
            ));
        }
    }
    ensure_runtime_identity_is_trusted(
        "policy activation issuer",
        &receipt.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_policy_activation_receipt_signature(receipt)?;
    Ok(())
}

pub(super) fn validate_attack_simulation_report(
    report: &RuntimeAttackSimulationReport,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if report.schema != RUNTIME_ATTACK_SIMULATION_REPORT_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "attack simulation report schema mismatch".to_string(),
        ));
    }
    for (field, value) in [
        ("scenario_id", &report.scenario_id),
        ("attack_class", &report.attack_class),
        ("fixture_path", &report.fixture_path),
        ("expected_denial_claim", &report.expected_denial_claim),
        (
            "actual_verifier_report_digest",
            &report.actual_verifier_report_digest,
        ),
        ("status", &report.status),
        ("simulator_version_digest", &report.simulator_version_digest),
        ("issuer", &report.issuer),
        ("signature", &report.signature),
    ] {
        require_non_empty(value, field)?;
    }
    validate_bundle_relative_path(&report.fixture_path).map_err(|_| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "attack simulation fixture path is unsafe".to_string(),
        )
    })?;
    validate_digest_field(
        "actual_verifier_report_digest",
        &report.actual_verifier_report_digest,
    )?;
    validate_digest_field("simulator_version_digest", &report.simulator_version_digest)?;
    if !report.expected_denial_claim.starts_with("claim.runtime.") {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "attack simulation expected denial claim must be runtime-scoped".to_string(),
        ));
    }
    if report.runtime_receipt_refs.is_empty() {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "attack simulation runtime receipt refs missing".to_string(),
        ));
    }
    for receipt_ref in &report.runtime_receipt_refs {
        require_non_empty(receipt_ref, "runtime receipt ref")?;
    }
    for knob in &report.chaos_knobs {
        require_non_empty(knob, "chaos knob")?;
    }
    if !is_supported_attack_class(&report.attack_class) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "unsupported attack simulation class".to_string(),
        ));
    }
    if report.status != "passed" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "attack simulation did not pass".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "attack simulation issuer",
        &report.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_attack_simulation_report_signature(report)?;
    Ok(())
}

pub(super) fn validate_chaos_run_report(
    report: &RuntimeChaosRunReport,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if report.schema != RUNTIME_CHAOS_RUN_REPORT_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "chaos run report schema mismatch".to_string(),
        ));
    }
    for (field, value) in [
        ("case_id", &report.case_id),
        ("failure_injected", &report.failure_injected),
        ("expected_result", &report.expected_result),
        (
            "actual_verifier_report_digest",
            &report.actual_verifier_report_digest,
        ),
        (
            "deterministic_seed_digest",
            &report.deterministic_seed_digest,
        ),
        ("status", &report.status),
        ("runner_version_digest", &report.runner_version_digest),
        ("issuer", &report.issuer),
        ("signature", &report.signature),
    ] {
        require_non_empty(value, field)?;
    }
    validate_digest_field(
        "actual_verifier_report_digest",
        &report.actual_verifier_report_digest,
    )?;
    validate_digest_field(
        "deterministic_seed_digest",
        &report.deterministic_seed_digest,
    )?;
    validate_digest_field("runner_version_digest", &report.runner_version_digest)?;
    if report.runtime_receipt_refs.is_empty() {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "chaos run runtime receipt refs missing".to_string(),
        ));
    }
    for receipt_ref in &report.runtime_receipt_refs {
        require_non_empty(receipt_ref, "runtime receipt ref")?;
    }
    if !is_supported_chaos_case(&report.case_id) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "unsupported chaos run case".to_string(),
        ));
    }
    if report.status != "passed" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "chaos run did not pass".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "chaos run issuer",
        &report.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_chaos_run_report_signature(report)?;
    Ok(())
}

pub(super) fn validate_route_plan_receipt(
    lease: &RuntimeExecutionLease,
    route_plan: &RuntimeRoutePlanReceipt,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if route_plan.schema != SWARM_ROUTE_PLAN_RECEIPT_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "route plan receipt schema mismatch".to_string(),
        ));
    }
    let Some(route_plan_receipt_ref) = lease.route_plan_receipt_ref.as_deref() else {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease route plan receipt missing".to_string(),
        ));
    };
    if route_plan.route_plan_id != route_plan_receipt_ref {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease route plan receipt mismatch".to_string(),
        ));
    }
    if route_plan.policy_digest != lease.policy_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "route plan receipt policy digest mismatch".to_string(),
        ));
    }
    for (field, value) in [
        ("routePlanId", &route_plan.route_plan_id),
        ("graphId", &route_plan.graph_id),
        ("taskId", &route_plan.task_id),
        ("selectedRoute", &route_plan.selected_route),
        ("bridgeId", &route_plan.bridge_id),
        ("protocolTarget", &route_plan.protocol_target),
        ("egressContractId", &route_plan.egress_contract_id),
        ("attenuationDecision", &route_plan.attenuation_decision),
        ("issuer", &route_plan.issuer),
        ("signature", &route_plan.signature),
    ] {
        require_non_empty(value, field)?;
    }
    for constraint in &route_plan.egress_constraints {
        require_non_empty(constraint, "egress constraint")?;
    }
    for (field, digest) in [
        ("candidateSetDigest", &route_plan.candidate_set_digest),
        ("registrySnapshotHash", &route_plan.registry_snapshot_hash),
        ("policyDigest", &route_plan.policy_digest),
    ] {
        validate_digest_field(field, digest)?;
    }
    if route_plan.attenuation_decision != "accepted" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "route plan receipt was not accepted".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "route plan issuer",
        &route_plan.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_route_plan_receipt_signature(route_plan)?;
    Ok(())
}

fn validate_execution_lease_trust_root(
    lease: &RuntimeExecutionLease,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    ensure_runtime_identity_is_trusted(
        "execution lease issuer",
        &lease.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )
}

fn ensure_runtime_identity_is_trusted(
    label: &'static str,
    identity: &str,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    for trust_root in trusted_roots {
        validate_trust_root(trust_root, trusted_root_signer_keys)?;
        if trust_root.authority.as_deref() == Some(identity)
            || trust_root
                .roots
                .iter()
                .any(|entry| entry.subject == identity)
        {
            return Ok(());
        }
    }
    Err(TransactionPassportError::RuntimeSecurityClaimFailed(
        format!("{label} is not trusted"),
    ))
}

fn validate_trust_root(
    trust_root: &RuntimeTrustRoot,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if trust_root.schema != "chio.trust.root.v1" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "runtime trust root schema mismatch".to_string(),
        ));
    }
    require_non_empty(&trust_root.id, "runtime trust root id")?;
    require_non_empty(&trust_root.signature, "runtime trust root signature")?;
    if let Some(authority) = trust_root.authority.as_deref() {
        require_non_empty(authority, "runtime trust root authority")?;
    } else {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "runtime trust root authority missing".to_string(),
        ));
    }
    for root in &trust_root.roots {
        require_non_empty(&root.subject, "runtime trust root subject")?;
    }
    let signer = trust_root.authority.as_deref().ok_or_else(|| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "runtime trust root authority missing".to_string(),
        )
    })?;
    ensure_runtime_trust_root_signer_is_pinned(signer, trusted_root_signer_keys)?;
    verify_runtime_trust_root_signature(trust_root, signer)?;
    Ok(())
}

fn ensure_runtime_trust_root_signer_is_pinned(
    signer_identity: &str,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if trusted_root_signer_keys.is_empty() {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted runtime root keys missing".to_string(),
        ));
    }
    let signer_key = self_certifying_public_key(signer_identity, "runtime trust root")?;
    if trusted_root_signer_keys
        .iter()
        .any(|trusted_key| trusted_key == &signer_key)
    {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "runtime trust root signer is not trusted".to_string(),
        ))
    }
}

fn verify_runtime_trust_root_signature(
    trust_root: &RuntimeTrustRoot,
    signer_identity: &str,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(signer_identity, "runtime trust root")?;
    let signature = Signature::from_hex(&trust_root.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "runtime trust root signature invalid: {error}"
        ))
    })?;
    let mut body = serde_json::to_value(trust_root).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "runtime trust root signature invalid: {error}"
        ))
    })?;
    body.as_object_mut()
        .ok_or_else(|| {
            TransactionPassportError::RuntimeSecurityClaimFailed(
                "runtime trust root signature body invalid".to_string(),
            )
        })?
        .remove("signature");
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "runtime trust root signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "runtime trust root signature invalid".to_string(),
        ))
    }
}

fn verify_execution_lease_signature(
    lease: &RuntimeExecutionLease,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&lease.issuer, "execution lease issuer")?;
    let signature = Signature::from_hex(&lease.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "execution lease signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&execution_lease_signature_body(lease), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "execution lease signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease signature invalid".to_string(),
        ))
    }
}

fn verify_task_graph_signature(
    task_graph: &RuntimeTaskGraph,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&task_graph.issuer, "task graph issuer")?;
    let signature = Signature::from_hex(&task_graph.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "task graph signature invalid: {error}"
        ))
    })?;
    let mut body = serde_json::to_value(task_graph).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "task graph signature body invalid: {error}"
        ))
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "task graph signature body invalid".to_string(),
        )
    })?;
    object.remove("signature");
    let verified = public_key
        .verify_canonical(&body, &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "task graph signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "task graph signature invalid".to_string(),
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeExecutionLeaseSignatureBody<'a> {
    schema: &'static str,
    lease_id: &'a str,
    subject_agent: &'a str,
    tool_server_id: &'a str,
    tool_instance_id: &'a str,
    tool_manifest_digest: &'a str,
    sandbox_attestation_ref: &'a str,
    capability_digest: &'a str,
    request_digest: &'a str,
    response_policy_digest: &'a str,
    task_graph_digest: &'a str,
    child_task_id: &'a str,
    parent_receipt_ref: &'a str,
    join_receipt_ref: &'a str,
    budget_pool_ref: &'a str,
    budget_allocation_ref: &'a str,
    subject_capability_digest: &'a str,
    ancestor_capability_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_epoch_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_plan_receipt_ref: Option<&'a str>,
    revocation_freshness_ref: &'a str,
    policy_digest: &'a str,
    nonce: &'a str,
    side_effect_class: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_invocations: Option<u64>,
    issued_at: &'a str,
    expires_at: &'a str,
    issuer: &'a str,
}

fn execution_lease_signature_body(
    lease: &RuntimeExecutionLease,
) -> RuntimeExecutionLeaseSignatureBody<'_> {
    RuntimeExecutionLeaseSignatureBody {
        schema: RUNTIME_EXECUTION_LEASE_SIGNATURE_SCHEMA,
        lease_id: &lease.lease_id,
        subject_agent: &lease.subject_agent,
        tool_server_id: &lease.tool_server_id,
        tool_instance_id: &lease.tool_instance_id,
        tool_manifest_digest: &lease.tool_manifest_digest,
        sandbox_attestation_ref: &lease.sandbox_attestation_ref,
        capability_digest: &lease.capability_digest,
        request_digest: &lease.request_digest,
        response_policy_digest: &lease.response_policy_digest,
        task_graph_digest: &lease.task_graph_digest,
        child_task_id: &lease.child_task_id,
        parent_receipt_ref: &lease.parent_receipt_ref,
        join_receipt_ref: &lease.join_receipt_ref,
        budget_pool_ref: &lease.budget_pool_ref,
        budget_allocation_ref: &lease.budget_allocation_ref,
        subject_capability_digest: &lease.subject_capability_digest,
        ancestor_capability_digest: &lease.ancestor_capability_digest,
        revocation_epoch_ref: lease.revocation_epoch_ref.as_deref(),
        route_plan_receipt_ref: lease.route_plan_receipt_ref.as_deref(),
        revocation_freshness_ref: &lease.revocation_freshness_ref,
        policy_digest: &lease.policy_digest,
        nonce: &lease.nonce,
        side_effect_class: &lease.side_effect_class,
        max_invocations: lease.max_invocations,
        issued_at: &lease.issued_at,
        expires_at: &lease.expires_at,
        issuer: &lease.issuer,
    }
}

fn verify_route_plan_receipt_signature(
    route_plan: &RuntimeRoutePlanReceipt,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&route_plan.issuer, "route plan issuer")?;
    let signature = Signature::from_hex(&route_plan.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "route plan receipt signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&route_plan_receipt_signature_body(route_plan), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "route plan receipt signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "route plan receipt signature invalid".to_string(),
        ))
    }
}

fn verify_policy_activation_receipt_signature(
    receipt: &RuntimePolicyActivationReceipt,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&receipt.issuer, "policy activation issuer")?;
    let signature = Signature::from_hex(&receipt.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "policy activation receipt signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(
            &policy_activation_receipt_signature_body(receipt),
            &signature,
        )
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "policy activation receipt signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "policy activation receipt signature invalid".to_string(),
        ))
    }
}

fn verify_attack_simulation_report_signature(
    report: &RuntimeAttackSimulationReport,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&report.issuer, "attack simulation issuer")?;
    let signature = Signature::from_hex(&report.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "attack simulation report signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&attack_simulation_report_signature_body(report), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "attack simulation report signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "attack simulation report signature invalid".to_string(),
        ))
    }
}

fn verify_chaos_run_report_signature(
    report: &RuntimeChaosRunReport,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&report.issuer, "chaos run issuer")?;
    let signature = Signature::from_hex(&report.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "chaos run report signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&chaos_run_report_signature_body(report), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "chaos run report signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "chaos run report signature invalid".to_string(),
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeChaosRunReportSignatureBody<'a> {
    schema: &'static str,
    case_id: &'a str,
    failure_injected: &'a str,
    expected_result: &'a str,
    actual_verifier_report_digest: &'a str,
    runtime_receipt_refs: &'a [String],
    deterministic_seed_digest: &'a str,
    status: &'a str,
    runner_version_digest: &'a str,
    issuer: &'a str,
}

fn chaos_run_report_signature_body(
    report: &RuntimeChaosRunReport,
) -> RuntimeChaosRunReportSignatureBody<'_> {
    RuntimeChaosRunReportSignatureBody {
        schema: RUNTIME_CHAOS_RUN_REPORT_SIGNATURE_SCHEMA,
        case_id: &report.case_id,
        failure_injected: &report.failure_injected,
        expected_result: &report.expected_result,
        actual_verifier_report_digest: &report.actual_verifier_report_digest,
        runtime_receipt_refs: &report.runtime_receipt_refs,
        deterministic_seed_digest: &report.deterministic_seed_digest,
        status: &report.status,
        runner_version_digest: &report.runner_version_digest,
        issuer: &report.issuer,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeAttackSimulationReportSignatureBody<'a> {
    schema: &'static str,
    scenario_id: &'a str,
    attack_class: &'a str,
    fixture_path: &'a str,
    expected_denial_claim: &'a str,
    actual_verifier_report_digest: &'a str,
    runtime_receipt_refs: &'a [String],
    chaos_knobs: &'a [String],
    status: &'a str,
    simulator_version_digest: &'a str,
    issuer: &'a str,
}

fn attack_simulation_report_signature_body(
    report: &RuntimeAttackSimulationReport,
) -> RuntimeAttackSimulationReportSignatureBody<'_> {
    RuntimeAttackSimulationReportSignatureBody {
        schema: RUNTIME_ATTACK_SIMULATION_REPORT_SIGNATURE_SCHEMA,
        scenario_id: &report.scenario_id,
        attack_class: &report.attack_class,
        fixture_path: &report.fixture_path,
        expected_denial_claim: &report.expected_denial_claim,
        actual_verifier_report_digest: &report.actual_verifier_report_digest,
        runtime_receipt_refs: &report.runtime_receipt_refs,
        chaos_knobs: &report.chaos_knobs,
        status: &report.status,
        simulator_version_digest: &report.simulator_version_digest,
        issuer: &report.issuer,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimePolicyActivationReceiptSignatureBody<'a> {
    schema: &'static str,
    policy_digest: &'a str,
    previous_policy_digest: &'a str,
    activation_epoch: &'a str,
    activated_at: &'a str,
    activation_mode: &'a str,
    narrowing_or_widening: &'a str,
    migration_rule: &'a str,
    issuer: &'a str,
}

fn policy_activation_receipt_signature_body(
    receipt: &RuntimePolicyActivationReceipt,
) -> RuntimePolicyActivationReceiptSignatureBody<'_> {
    RuntimePolicyActivationReceiptSignatureBody {
        schema: POLICY_ACTIVATION_RECEIPT_SIGNATURE_SCHEMA,
        policy_digest: &receipt.policy_digest,
        previous_policy_digest: &receipt.previous_policy_digest,
        activation_epoch: &receipt.activation_epoch,
        activated_at: &receipt.activated_at,
        activation_mode: &receipt.activation_mode,
        narrowing_or_widening: &receipt.narrowing_or_widening,
        migration_rule: &receipt.migration_rule,
        issuer: &receipt.issuer,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeRoutePlanReceiptSignatureBody<'a> {
    schema: &'static str,
    route_plan_id: &'a str,
    graph_id: &'a str,
    task_id: &'a str,
    selected_route: &'a str,
    candidate_set_digest: &'a str,
    registry_snapshot_hash: &'a str,
    bridge_id: &'a str,
    protocol_target: &'a str,
    egress_contract_id: &'a str,
    egress_constraints: &'a [String],
    attenuation_decision: &'a str,
    policy_digest: &'a str,
    expires_at_unix_ms: u64,
    issuer: &'a str,
}

fn route_plan_receipt_signature_body(
    route_plan: &RuntimeRoutePlanReceipt,
) -> RuntimeRoutePlanReceiptSignatureBody<'_> {
    RuntimeRoutePlanReceiptSignatureBody {
        schema: SWARM_ROUTE_PLAN_RECEIPT_SIGNATURE_SCHEMA,
        route_plan_id: &route_plan.route_plan_id,
        graph_id: &route_plan.graph_id,
        task_id: &route_plan.task_id,
        selected_route: &route_plan.selected_route,
        candidate_set_digest: &route_plan.candidate_set_digest,
        registry_snapshot_hash: &route_plan.registry_snapshot_hash,
        bridge_id: &route_plan.bridge_id,
        protocol_target: &route_plan.protocol_target,
        egress_contract_id: &route_plan.egress_contract_id,
        egress_constraints: &route_plan.egress_constraints,
        attenuation_decision: &route_plan.attenuation_decision,
        policy_digest: &route_plan.policy_digest,
        expires_at_unix_ms: route_plan.expires_at_unix_ms,
        issuer: &route_plan.issuer,
    }
}

pub(super) fn validate_revocation_freshness(
    lease: &RuntimeExecutionLease,
    proof: &RuntimeRevocationFreshnessProof,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if proof.proof_id != lease.revocation_freshness_ref {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness proof mismatch".to_string(),
        ));
    }
    if let Some(revocation_epoch_ref) = lease.revocation_epoch_ref.as_deref() {
        if revocation_epoch_ref != proof.epoch_id {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "execution lease revocation epoch mismatch".to_string(),
            ));
        }
    }
    require_non_empty(&proof.schema, "revocation freshness proof schema")?;
    require_non_empty(&proof.oracle_id, "oracle_id")?;
    require_non_empty(&proof.epoch_id, "epoch_id")?;
    require_non_empty(&proof.fetched_at, "fetched_at")?;
    require_non_empty(&proof.signature, "signature")?;
    validate_digest_field("epoch_root", &proof.epoch_root)?;
    validate_digest_field(
        "revocation freshness subject_capability_digest",
        &proof.subject_capability_digest,
    )?;
    validate_digest_field(
        "revocation freshness ancestor_capability_digest",
        &proof.ancestor_capability_digest,
    )?;
    if proof.subject_capability_digest != lease.subject_capability_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness subject capability mismatch".to_string(),
        ));
    }
    if proof.ancestor_capability_digest != lease.ancestor_capability_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness ancestor capability mismatch".to_string(),
        ));
    }
    if proof.sequence == 0
        || proof.max_staleness_ms == 0
        || proof.revoked_leaf_result
        || proof.revoked_ancestor_result
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness failed".to_string(),
        ));
    }
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let fetched_at = parse_rfc3339_utc(&proof.fetched_at, "revocation fetched_at")?;
    if fetched_at > lease_issued_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness fetched after lease issuance".to_string(),
        ));
    }
    let freshness_age_ms = lease_issued_at
        .signed_duration_since(fetched_at)
        .num_milliseconds();
    let freshness_age_ms = u64::try_from(freshness_age_ms).map_err(|_| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness age overflow".to_string(),
        )
    })?;
    if freshness_age_ms > proof.max_staleness_ms {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness stale".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "revocation freshness oracle",
        &proof.oracle_id,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_revocation_freshness_signature(proof)?;
    Ok(())
}

pub(super) fn validate_revocation_freshness_at_ack(
    proof: &RuntimeRevocationFreshnessProof,
    ack: &RuntimeToolServerAck,
) -> Result<(), TransactionPassportError> {
    let fetched_at = parse_rfc3339_utc(&proof.fetched_at, "revocation fetched_at")?;
    let ack_issued_at = parse_rfc3339_utc(&ack.issued_at, "tool-server acknowledgement issued_at")?;
    if fetched_at > ack_issued_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness fetched after acknowledgement".to_string(),
        ));
    }
    let freshness_age_ms = ack_issued_at
        .signed_duration_since(fetched_at)
        .num_milliseconds();
    let freshness_age_ms = u64::try_from(freshness_age_ms).map_err(|_| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation acknowledgement freshness age overflow".to_string(),
        )
    })?;
    if freshness_age_ms > proof.max_staleness_ms {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness stale at acknowledgement".to_string(),
        ));
    }
    Ok(())
}

fn verify_revocation_freshness_signature(
    proof: &RuntimeRevocationFreshnessProof,
) -> Result<(), TransactionPassportError> {
    let public_key =
        self_certifying_public_key(&proof.oracle_id, "revocation freshness oracle id")?;
    let signature = Signature::from_hex(&proof.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "revocation freshness signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&revocation_freshness_signature_body(proof), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "revocation freshness signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness signature invalid".to_string(),
        ))
    }
}

fn self_certifying_public_key(
    identity: &str,
    label: &'static str,
) -> Result<PublicKey, TransactionPassportError> {
    let public_key_hex = if let Some(public_key_hex) = identity.strip_prefix(DID_CHIO_PREFIX) {
        if public_key_hex.len() != 64 || !public_key_hex.bytes().all(is_lower_hex_byte) {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                format!("{label} is not self-certifying"),
            ));
        }
        public_key_hex
    } else {
        identity
    };
    PublicKey::from_hex(public_key_hex).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "{label} public key invalid: {error}"
        ))
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeRevocationFreshnessSignatureBody<'a> {
    schema: &'static str,
    proof_id: &'a str,
    oracle_id: &'a str,
    epoch_id: &'a str,
    epoch_root: &'a str,
    sequence: u64,
    fetched_at: &'a str,
    max_staleness_ms: u64,
    subject_capability_digest: &'a str,
    ancestor_capability_digest: &'a str,
    revoked_leaf_result: bool,
    revoked_ancestor_result: bool,
}

fn revocation_freshness_signature_body(
    proof: &RuntimeRevocationFreshnessProof,
) -> RuntimeRevocationFreshnessSignatureBody<'_> {
    RuntimeRevocationFreshnessSignatureBody {
        schema: RUNTIME_REVOCATION_FRESHNESS_PROOF_SIGNATURE_SCHEMA,
        proof_id: &proof.proof_id,
        oracle_id: &proof.oracle_id,
        epoch_id: &proof.epoch_id,
        epoch_root: &proof.epoch_root,
        sequence: proof.sequence,
        fetched_at: &proof.fetched_at,
        max_staleness_ms: proof.max_staleness_ms,
        subject_capability_digest: &proof.subject_capability_digest,
        ancestor_capability_digest: &proof.ancestor_capability_digest,
        revoked_leaf_result: proof.revoked_leaf_result,
        revoked_ancestor_result: proof.revoked_ancestor_result,
    }
}

fn verify_sandbox_attestation_signature(
    sandbox: &RuntimeSandboxAttestation,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&sandbox.attester, "sandbox attester")?;
    let signature = Signature::from_hex(&sandbox.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "sandbox attestation signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&sandbox_attestation_signature_body(sandbox), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "sandbox attestation signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox attestation signature invalid".to_string(),
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeSandboxAttestationSignatureBody<'a> {
    schema: &'static str,
    attestation_id: &'a str,
    tool_server_id: &'a str,
    tool_instance_id: &'a str,
    tool_manifest_digest: &'a str,
    sandbox_profile_digest: &'a str,
    egress_policy_digest: &'a str,
    started_at: &'a str,
    expires_at: &'a str,
    attester: &'a str,
}

fn sandbox_attestation_signature_body(
    sandbox: &RuntimeSandboxAttestation,
) -> RuntimeSandboxAttestationSignatureBody<'_> {
    RuntimeSandboxAttestationSignatureBody {
        schema: RUNTIME_SANDBOX_ATTESTATION_SIGNATURE_SCHEMA,
        attestation_id: &sandbox.attestation_id,
        tool_server_id: &sandbox.tool_server_id,
        tool_instance_id: &sandbox.tool_instance_id,
        tool_manifest_digest: &sandbox.tool_manifest_digest,
        sandbox_profile_digest: &sandbox.sandbox_profile_digest,
        egress_policy_digest: &sandbox.egress_policy_digest,
        started_at: &sandbox.started_at,
        expires_at: &sandbox.expires_at,
        attester: &sandbox.attester,
    }
}

pub(super) fn validate_sandbox_attestation(
    lease: &RuntimeExecutionLease,
    sandbox: &RuntimeSandboxAttestation,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if sandbox.attestation_id != lease.sandbox_attestation_ref {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox attestation mismatch".to_string(),
        ));
    }
    if sandbox.tool_server_id != lease.tool_server_id
        || sandbox.tool_instance_id != lease.tool_instance_id
        || sandbox.tool_manifest_digest != lease.tool_manifest_digest
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox tool binding mismatch".to_string(),
        ));
    }
    require_non_empty(&sandbox.schema, "sandbox attestation schema")?;
    for (field, value) in [
        ("sandbox_profile_digest", &sandbox.sandbox_profile_digest),
        ("egress_policy_digest", &sandbox.egress_policy_digest),
    ] {
        validate_digest_field(field, value)?;
    }
    for (field, value) in [
        ("started_at", &sandbox.started_at),
        ("expires_at", &sandbox.expires_at),
        ("attester", &sandbox.attester),
        ("signature", &sandbox.signature),
    ] {
        require_non_empty(value, field)?;
    }
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let lease_expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    let sandbox_started_at = parse_rfc3339_utc(&sandbox.started_at, "sandbox started_at")?;
    let sandbox_expires_at = parse_rfc3339_utc(&sandbox.expires_at, "sandbox expires_at")?;
    if sandbox_expires_at <= sandbox_started_at
        || sandbox_started_at > lease_issued_at
        || sandbox_expires_at < lease_expires_at
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox attestation not valid for execution lease".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "sandbox attester",
        &sandbox.attester,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_sandbox_attestation_signature(sandbox)?;
    Ok(())
}

pub(super) fn validate_tool_server_ack(
    lease: &RuntimeExecutionLease,
    sandbox: &RuntimeSandboxAttestation,
    ack: &RuntimeToolServerAck,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if ack.lease_id != lease.lease_id
        || ack.tool_server_id != lease.tool_server_id
        || ack.tool_instance_id != lease.tool_instance_id
        || ack.sandbox_attestation_ref != sandbox.attestation_id
        || ack.nonce != lease.nonce
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "tool-server acknowledgement mismatch".to_string(),
        ));
    }
    if ack.terminal_status != "allowed_executed" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "tool-server acknowledgement did not execute".to_string(),
        ));
    }
    require_non_empty(&ack.schema, "tool-server acknowledgement schema")?;
    require_non_empty(&ack.ack_id, "ack_id")?;
    require_non_empty(&ack.issued_at, "issued_at")?;
    require_non_empty(&ack.signature, "signature")?;
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let lease_expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    let ack_issued_at = parse_rfc3339_utc(&ack.issued_at, "tool-server acknowledgement issued_at")?;
    if ack_issued_at < lease_issued_at || ack_issued_at > lease_expires_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "acknowledgement outside execution lease".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "tool-server",
        &ack.tool_server_id,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_tool_server_ack_signature(ack)?;
    Ok(())
}

pub(super) fn validate_trusted_time_proof(
    lease: &RuntimeExecutionLease,
    ack: &RuntimeToolServerAck,
    proof: &RuntimeTrustedTimeProof,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if proof.schema != RUNTIME_TRUSTED_TIME_PROOF_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof schema mismatch".to_string(),
        ));
    }
    for (field, value) in [
        ("proof_id", &proof.proof_id),
        ("lease_id", &proof.lease_id),
        ("ack_id", &proof.ack_id),
        ("observed_at", &proof.observed_at),
        ("time_source_id", &proof.time_source_id),
        ("issuer", &proof.issuer),
        ("signature", &proof.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if proof.lease_id != lease.lease_id || proof.ack_id != ack.ack_id {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof acknowledgement mismatch".to_string(),
        ));
    }
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let lease_expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    let observed_at = parse_rfc3339_utc(&proof.observed_at, "trusted time observed_at")?;
    if proof.max_clock_skew_ms > 30_000 {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof clock skew bound too wide".to_string(),
        ));
    }
    if observed_at < lease_issued_at || observed_at > lease_expires_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof outside execution lease".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "trusted time issuer",
        &proof.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_trusted_time_proof_signature(proof)?;
    Ok(())
}

fn verify_tool_server_ack_signature(
    ack: &RuntimeToolServerAck,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&ack.tool_server_id, "tool-server id")?;
    let signature = Signature::from_hex(&ack.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "tool-server acknowledgement signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&tool_server_ack_signature_body(ack), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "tool-server acknowledgement signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "tool-server acknowledgement signature invalid".to_string(),
        ))
    }
}

fn verify_trusted_time_proof_signature(
    proof: &RuntimeTrustedTimeProof,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&proof.issuer, "trusted time issuer")?;
    let signature = Signature::from_hex(&proof.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "trusted time proof signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&trusted_time_proof_signature_body(proof), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "trusted time proof signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof signature invalid".to_string(),
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeToolServerAckSignatureBody<'a> {
    schema: &'static str,
    ack_id: &'a str,
    lease_id: &'a str,
    tool_server_id: &'a str,
    tool_instance_id: &'a str,
    sandbox_attestation_ref: &'a str,
    nonce: &'a str,
    terminal_status: &'a str,
    issued_at: &'a str,
}

fn tool_server_ack_signature_body(
    ack: &RuntimeToolServerAck,
) -> RuntimeToolServerAckSignatureBody<'_> {
    RuntimeToolServerAckSignatureBody {
        schema: RUNTIME_TOOL_SERVER_ACK_SIGNATURE_SCHEMA,
        ack_id: &ack.ack_id,
        lease_id: &ack.lease_id,
        tool_server_id: &ack.tool_server_id,
        tool_instance_id: &ack.tool_instance_id,
        sandbox_attestation_ref: &ack.sandbox_attestation_ref,
        nonce: &ack.nonce,
        terminal_status: &ack.terminal_status,
        issued_at: &ack.issued_at,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeTrustedTimeProofSignatureBody<'a> {
    schema: &'static str,
    proof_id: &'a str,
    lease_id: &'a str,
    ack_id: &'a str,
    observed_at: &'a str,
    max_clock_skew_ms: u64,
    time_source_id: &'a str,
    issuer: &'a str,
}

fn trusted_time_proof_signature_body(
    proof: &RuntimeTrustedTimeProof,
) -> RuntimeTrustedTimeProofSignatureBody<'_> {
    RuntimeTrustedTimeProofSignatureBody {
        schema: RUNTIME_TRUSTED_TIME_PROOF_SIGNATURE_SCHEMA,
        proof_id: &proof.proof_id,
        lease_id: &proof.lease_id,
        ack_id: &proof.ack_id,
        observed_at: &proof.observed_at,
        max_clock_skew_ms: proof.max_clock_skew_ms,
        time_source_id: &proof.time_source_id,
        issuer: &proof.issuer,
    }
}

pub(super) fn validate_nonce_uniqueness(
    bundle: &RuntimeSecurityBundle,
    graph: &RuntimeEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    let mut consumed_nonces = BTreeSet::new();
    for ack_node in graph
        .nodes
        .iter()
        .filter(|node| node.role == RuntimeEvidenceRole::ToolServerAck)
    {
        let ack: RuntimeToolServerAck =
            parse_artifact(bundle, ack_node, RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID)?;
        let nonce_key = (ack.lease_id, ack.nonce);
        if !consumed_nonces.insert(nonce_key) {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "reused nonce".to_string(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_allow_receipt(
    lease: &RuntimeExecutionLease,
    receipt: &RuntimeTerminalReceipt,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    validate_terminal_receipt(
        receipt,
        &lease.policy_digest,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    if receipt.terminal_status != "allowed_executed" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "receipt totality failed".to_string(),
        ));
    }
    if receipt.execution_lease_ref.as_deref() != Some(lease.lease_id.as_str()) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "receipt totality failed".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_terminal_receipt(
    receipt: &RuntimeTerminalReceipt,
    policy_digest: &str,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    require_non_empty(&receipt.schema, "receipt schema")?;
    require_non_empty(&receipt.receipt_id, "receipt_id")?;
    require_non_empty(&receipt.terminal_status, "terminal_status")?;
    require_non_empty(&receipt.kernel_key, "terminal receipt kernel_key")?;
    require_non_empty(&receipt.signature, "terminal receipt signature")?;
    validate_digest_field("policy_digest", &receipt.policy_digest)?;
    if receipt.policy_digest != policy_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "terminal receipt policy digest mismatch".to_string(),
        ));
    }
    if !is_terminal_receipt_status(&receipt.terminal_status) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            format!(
                "unsupported terminal receipt status: {}",
                receipt.terminal_status
            ),
        ));
    }
    if receipt.terminal_status == "allowed_executed" {
        let Some(execution_lease_ref) = receipt.execution_lease_ref.as_deref() else {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "allowed terminal receipt missing execution lease".to_string(),
            ));
        };
        require_non_empty(execution_lease_ref, "execution_lease_ref")?;
    }
    if receipt.terminal_status.starts_with("failed_") {
        let Some(incident_ref) = receipt.incident_ref.as_deref() else {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "failed terminal receipt missing incident".to_string(),
            ));
        };
        require_non_empty(incident_ref, "incident_ref")?;
    }
    ensure_runtime_public_key_is_trusted(
        "terminal receipt kernel",
        &receipt.kernel_key,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_terminal_receipt_signature(receipt)?;
    Ok(())
}

fn ensure_runtime_public_key_is_trusted(
    label: &'static str,
    public_key_hex: &str,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    let public_key = PublicKey::from_hex(public_key_hex).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "{label} key invalid: {error}"
        ))
    })?;
    let identity = format!("{DID_CHIO_PREFIX}{}", public_key.to_hex());
    ensure_runtime_identity_is_trusted(label, &identity, trusted_roots, trusted_root_signer_keys)
}

fn verify_terminal_receipt_signature(
    receipt: &RuntimeTerminalReceipt,
) -> Result<(), TransactionPassportError> {
    let public_key = PublicKey::from_hex(&receipt.kernel_key).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "terminal receipt signature invalid: {error}"
        ))
    })?;
    let signature = Signature::from_hex(&receipt.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "terminal receipt signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&terminal_receipt_signature_body(receipt), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "terminal receipt signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "terminal receipt signature invalid".to_string(),
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeTerminalReceiptSignatureBody<'a> {
    schema: &'static str,
    receipt_id: &'a str,
    terminal_status: &'a str,
    policy_digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_lease_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    incident_ref: Option<&'a str>,
    kernel_key: &'a str,
}

fn terminal_receipt_signature_body(
    receipt: &RuntimeTerminalReceipt,
) -> RuntimeTerminalReceiptSignatureBody<'_> {
    RuntimeTerminalReceiptSignatureBody {
        schema: RUNTIME_TERMINAL_RECEIPT_SIGNATURE_SCHEMA,
        receipt_id: &receipt.receipt_id,
        terminal_status: &receipt.terminal_status,
        policy_digest: &receipt.policy_digest,
        execution_lease_ref: receipt.execution_lease_ref.as_deref(),
        incident_ref: receipt.incident_ref.as_deref(),
        kernel_key: &receipt.kernel_key,
    }
}

fn is_terminal_receipt_status(status: &str) -> bool {
    matches!(
        status,
        "allowed_executed"
            | "allowed_tool_rejected"
            | "denied_pre_dispatch"
            | "denied_guard_request"
            | "denied_guard_response"
            | "denied_revocation_stale"
            | "denied_policy_reload_conflict"
            | "denied_missing_execution_lease"
            | "denied_sandbox_attestation_mismatch"
            | "failed_receipt_log_unavailable"
            | "failed_tool_unreachable"
            | "failed_timeout_before_tool_entry"
            | "failed_timeout_after_tool_entry"
    )
}

fn is_supported_attack_class(attack_class: &str) -> bool {
    matches!(
        attack_class,
        "confused-deputy-route-metadata"
            | "replayed-continuation-token"
            | "stale-revocation-epoch"
            | "policy-hot-reload-widening"
            | "advisory-evidence-laundering"
            | "external-payment-success-laundering"
            | "route-plan-registry-downgrade"
            | "tool-server-bypass-without-kernel-allow"
            | "missing-denial-receipt"
            | "sandbox-profile-mismatch"
    )
}

fn is_supported_chaos_case(case_id: &str) -> bool {
    matches!(
        case_id,
        "revocation-oracle-unavailable"
            | "receipt-log-unavailable"
            | "policy-reload-during-dispatch"
            | "duplicate-nonce-race"
            | "tool-restart-lost-lease-cache"
            | "registry-split-brain"
            | "clock-skew-expiry-bypass"
            | "sandbox-profile-drift"
    )
}

fn is_governed_side_effect_class(side_effect_class: &str) -> bool {
    matches!(
        side_effect_class,
        "network-write" | "filesystem-write" | "process-spawn" | "state-write"
    )
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn parse_rfc3339_utc(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, TransactionPassportError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "invalid {field}: {error}"
            ))
        })
}

fn validate_digest_field(
    field: &'static str,
    digest: &str,
) -> Result<(), TransactionPassportError> {
    validate_sha256_hex(digest).map_err(|_| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!("invalid {field}: {digest}"))
    })
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            format!("{field} must not be empty"),
        ))
    } else {
        Ok(())
    }
}
