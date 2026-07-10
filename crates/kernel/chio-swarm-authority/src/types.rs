use chio_core_types::capability::attenuation::AttenuationWitness;
use serde::{Deserialize, Serialize};

pub const CHIO_SWARM_TASK_GRAPH_SCHEMA: &str = "chio.swarm.task-graph.v1";
pub const CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA: &str = "chio.swarm.continuation-token.v1";
pub const CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA: &str =
    "chio.swarm.delegation-witness-chain.v1";
pub const CHIO_SWARM_JOIN_RECEIPT_SCHEMA: &str = "chio.swarm.join-receipt.v1";
pub const CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA: &str = "chio.swarm.route-plan-receipt.v1";
pub const CHIO_SWARM_BUDGET_POOL_SCHEMA: &str = "chio.swarm.budget-pool.v1";
pub const CHIO_SWARM_REVOCATION_EPOCH_SCHEMA: &str = "chio.swarm.revocation-epoch.v1";
pub const CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA: &str = "chio.swarm.terminal-graph-receipt.v1";
pub const CHIO_SWARM_AUTHORITY_VERIFIER_REPORT_SCHEMA: &str =
    "chio.swarm.authority-verifier-report.v1";

pub const CLAIM_SWARM_TASK_GRAPH_BOUND: &str = "claim.swarm.task_graph_bound";
pub const CLAIM_SWARM_CONTINUATION_FRESH: &str = "claim.swarm.continuation_fresh";
pub const CLAIM_SWARM_ATTENUATION_WITNESS_CHAIN_BOUND: &str =
    "claim.swarm.attenuation_witness_chain_bound";
pub const CLAIM_SWARM_ROUTE_PLAN_BOUND: &str = "claim.swarm.route_plan_bound";
pub const CLAIM_SWARM_JOIN_RECEIPT_BOUND: &str = "claim.swarm.join_receipt_bound";
pub const CLAIM_SWARM_BUDGET_POOL_BOUND: &str = "claim.swarm.budget_pool_bound";
pub const CLAIM_SWARM_REVOCATION_EPOCH_BOUND: &str = "claim.swarm.revocation_epoch_bound";
pub const CLAIM_SWARM_TERMINAL_GRAPH_RECEIPT_BOUND: &str =
    "claim.swarm.terminal_graph_receipt_bound";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmAuthorityBundle {
    pub task_graph: SwarmTaskGraph,
    pub continuation_tokens: Vec<SwarmContinuationToken>,
    pub witness_chains: Vec<SwarmDelegationWitnessChain>,
    pub join_receipts: Vec<SwarmJoinReceipt>,
    pub route_plan_receipts: Vec<SwarmRoutePlanReceipt>,
    pub budget_pool: SwarmBudgetPool,
    pub revocation_epoch: SwarmRevocationEpoch,
    #[serde(default)]
    pub terminal_receipts: Vec<SwarmTerminalGraphReceipt>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmTaskGraph {
    pub schema: String,
    pub graph_id: String,
    pub root_transaction_ref: String,
    pub planner_subject: String,
    pub issuer: String,
    pub signature: String,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_depth: u32,
    pub max_fanout: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub multi_hop_witness_chains: bool,
    pub nodes: Vec<SwarmGraphNode>,
    pub edges: Vec<SwarmGraphEdge>,
    pub joins: Vec<SwarmGraphJoin>,
    pub budget_pool_ref: String,
    pub revocation_epoch_ref: String,
    pub route_plan_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmGraphNode {
    pub task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_plan_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_allocation_ref: Option<String>,
    pub scope_hash: String,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmGraphEdge {
    pub from_task_id: String,
    pub to_task_id: String,
    pub edge_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmGraphJoin {
    pub join_id: String,
    pub parent_task_ids: Vec<String>,
    pub next_task_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmContinuationToken {
    pub schema: String,
    pub token_id: String,
    pub graph_id: String,
    pub child_task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_receipt_id: Option<String>,
    pub parent_receipt_ids: Vec<String>,
    pub graph_sha256: String,
    pub route_plan_receipt_id: String,
    pub budget_allocation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_chain_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_chain_sha256: Option<String>,
    pub revocation_epoch_ref: String,
    pub revocation_epoch_root_hash: String,
    pub session_anchor_ref: String,
    pub nonce: String,
    pub mode: SwarmContinuationMode,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub issuer: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmContinuationTokenMintRequest {
    pub token_id: String,
    pub graph_id: String,
    pub child_task_id: String,
    pub parent_task_id: Option<String>,
    pub join_receipt_id: Option<String>,
    pub parent_receipt_ids: Vec<String>,
    pub graph_sha256: String,
    pub route_plan_receipt_id: String,
    pub budget_allocation_id: String,
    pub witness_chain_ref: Option<String>,
    pub witness_chain_sha256: Option<String>,
    pub revocation_epoch_ref: String,
    pub revocation_epoch_root_hash: String,
    pub session_anchor_ref: String,
    pub nonce: String,
    pub mode: SwarmContinuationMode,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwarmContinuationMode {
    SingleUse,
    Resumable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmDelegationWitnessChain {
    pub schema: String,
    pub chain_id: String,
    pub graph_id: String,
    pub parent_task_id: String,
    pub child_task_id: String,
    pub hops: Vec<SwarmDelegationWitnessHop>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmDelegationWitnessHop {
    pub parent_capability_digest: String,
    pub child_capability_digest: String,
    pub parent_scope_hash: String,
    pub child_scope_hash: String,
    pub attenuation_rule_id: String,
    pub scope_subset_proof: AttenuationWitness,
    pub expires_at_unix_ms: u64,
    pub issuer: String,
    pub policy_digest: String,
    pub witness_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmJoinReceipt {
    pub schema: String,
    pub join_id: String,
    pub graph_id: String,
    pub chain_id: String,
    pub parent_set_hash: String,
    pub dag_ordinal: u64,
    pub hlc_unix_ms: u64,
    pub parent_task_receipts: Vec<SwarmJoinParentReceipt>,
    pub expected_parent_receipt_ids: Vec<String>,
    pub actual_parent_receipt_ids: Vec<String>,
    pub join_predicate: String,
    pub result_digest: String,
    pub next_task_id: String,
    pub issuer: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmJoinReceiptMintRequest {
    pub join_id: String,
    pub graph_id: String,
    pub chain_id: String,
    pub dag_ordinal: u64,
    pub hlc_unix_ms: u64,
    pub parent_task_receipts: Vec<SwarmJoinParentReceipt>,
    pub expected_parent_receipt_ids: Vec<String>,
    pub actual_parent_receipt_ids: Vec<String>,
    pub join_predicate: String,
    pub result_digest: String,
    pub next_task_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmJoinParentReceipt {
    pub task_id: String,
    pub receipt_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmRoutePlanReceipt {
    pub schema: String,
    pub route_plan_id: String,
    pub graph_id: String,
    pub task_id: String,
    pub selected_route: String,
    pub candidate_set_digest: String,
    pub registry_snapshot_hash: String,
    pub bridge_id: String,
    pub protocol_target: String,
    pub egress_contract_id: String,
    pub egress_constraints: Vec<String>,
    pub attenuation_decision: String,
    pub policy_digest: String,
    pub expires_at_unix_ms: u64,
    pub issuer: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmBudgetPool {
    pub schema: String,
    pub pool_id: String,
    pub graph_id: String,
    pub currency: String,
    pub total_units: u64,
    pub allocations: Vec<SwarmBudgetAllocation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmBudgetFanoutReservationRequest {
    pub pool_id: String,
    pub graph_id: String,
    pub currency: String,
    pub total_units: u64,
    pub allocations: Vec<SwarmBudgetFanoutAllocationRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmBudgetFanoutAllocationRequest {
    pub allocation_id: String,
    pub task_id: String,
    pub dimension_id: String,
    pub reserved_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmBudgetFanInReleaseRequest {
    pub pool: SwarmBudgetPool,
    pub completed_task_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmBudgetAllocation {
    pub allocation_id: String,
    pub task_id: String,
    pub dimension_id: String,
    pub state: SwarmBudgetAllocationState,
    pub max_units: u64,
    pub reserved_units: u64,
    pub active_units: u64,
    pub consumed_units: u64,
    pub released_units: u64,
    pub reversed_units: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwarmBudgetAllocationState {
    Reserved,
    Active,
    Consumed,
    Released,
    Reversed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmRevocationEpoch {
    pub schema: String,
    pub epoch_id: String,
    pub root_hash: String,
    pub issued_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub revoked_subjects: Vec<String>,
    pub revoked_task_ids: Vec<String>,
    pub issuer: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmTerminalGraphReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub graph_id: String,
    pub chain_id: String,
    pub terminal_task_ids: Vec<String>,
    pub completed_task_ids: Vec<String>,
    pub join_receipt_ids: Vec<String>,
    pub route_plan_receipt_ids: Vec<String>,
    pub budget_pool_id: String,
    pub budget_rollups: Vec<SwarmTerminalBudgetRollup>,
    pub revocation_epoch_ref: String,
    pub result_digest: String,
    pub completed_at_unix_ms: u64,
    pub issuer: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmTerminalBudgetRollup {
    pub dimension_id: String,
    pub reserved_units: u64,
    pub active_units: u64,
    pub consumed_units: u64,
    pub released_units: u64,
    pub reversed_units: u64,
    pub total_units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmAuthorityVerifierReport {
    pub schema: String,
    pub id: String,
    pub verdict: String,
    pub graph_id: String,
    pub task_count: usize,
    pub continuation_count: usize,
    pub join_count: usize,
    pub route_count: usize,
    pub hop_reports: Vec<SwarmAuthorityHopReport>,
    pub verified_claims: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmAuthorityHopReport {
    pub child_task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_receipt_id: Option<String>,
    pub continuation_token_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_chain_id: Option<String>,
    pub witness_hop_count: usize,
    pub multi_hop_witness_enabled: bool,
    pub route_plan_receipt_id: String,
    pub budget_allocation_id: String,
    pub authority_verified: bool,
    pub attenuation_verified: bool,
    pub lineage_verified: bool,
    pub route_verified: bool,
    pub budget_verified: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}
