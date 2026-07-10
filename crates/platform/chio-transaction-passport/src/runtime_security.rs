use std::collections::BTreeMap;

use chio_core_types::crypto::PublicKey;
use serde::{Deserialize, Serialize};

use super::error::TransactionPassportError;
use super::ids::{
    POLICY_ACTIVATION_RECEIPT_SCHEMA_ID, REQUEST_DIGEST_SCHEMA_ID,
    RUNTIME_ATTACK_SIMULATION_REPORT_SCHEMA_ID, RUNTIME_CHAOS_RUN_REPORT_SCHEMA_ID,
    RUNTIME_EXECUTION_LEASE_SCHEMA_ID, RUNTIME_REVOCATION_FRESHNESS_PROOF_SCHEMA_ID,
    RUNTIME_SANDBOX_ATTESTATION_SCHEMA_ID, RUNTIME_TERMINAL_RECEIPT_SCHEMA_ID,
    RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID, RUNTIME_TRUSTED_TIME_PROOF_SCHEMA_ID,
    SWARM_BUDGET_POOL_SCHEMA_ID, SWARM_JOIN_RECEIPT_SCHEMA_ID, SWARM_ROUTE_PLAN_RECEIPT_SCHEMA_ID,
    SWARM_TASK_GRAPH_SCHEMA_ID, TRANSACTION_RUNTIME_SECURITY_REPORT_SCHEMA_ID,
};
use super::minimal::verify_passport_root_and_claim_set_artifacts;
use super::types::TransactionPassport;

mod artifacts;
mod claims;
mod evidence;
mod policy;

use artifacts::{
    validate_allow_receipt, validate_attack_simulation_report, validate_chaos_run_report,
    validate_execution_lease, validate_execution_lease_context, validate_nonce_uniqueness,
    validate_policy_activation_receipt, validate_request_digest_binding,
    validate_revocation_freshness, validate_revocation_freshness_at_ack,
    validate_route_plan_receipt, validate_sandbox_attestation, validate_terminal_receipt,
    validate_tool_server_ack, validate_trusted_time_proof, ExecutionLeaseContext,
    RuntimeAttackSimulationReport, RuntimeBudgetPool, RuntimeChaosRunReport, RuntimeExecutionLease,
    RuntimeJoinReceipt, RuntimePolicyActivationReceipt, RuntimeRequestDigest,
    RuntimeRevocationFreshnessProof, RuntimeRoutePlanReceipt, RuntimeSandboxAttestation,
    RuntimeTaskGraph, RuntimeTerminalReceipt, RuntimeToolServerAck, RuntimeTrustRoot,
    RuntimeTrustedTimeProof,
};
use claims::{
    push_claim_once, CLAIM_ADVISORY_NOT_AUTHORIZATION, CLAIM_EXECUTION_LEASE_VALID,
    CLAIM_NONCE_FRESH, CLAIM_RECEIPT_TOTALITY, CLAIM_REVOCATION_FRESH, CLAIM_SANDBOX_MATCHED,
    CLAIM_TOOL_ACK_BOUND,
};
use evidence::{
    bound_budget_pool_nodes, bound_join_receipt_nodes, bound_request_nodes, bound_route_plan_nodes,
    bound_task_graph_nodes, bound_trusted_time_nodes, ensure_no_advisory_authorization,
    leased_receipt_nodes, node_sha256, nodes_by_role, parse_artifact, parse_graph,
    trust_root_authorizes_lease, RuntimeEvidenceGraph, RuntimeEvidenceRole,
};
use policy::parse_policy;

#[derive(Debug, Clone)]
pub struct RuntimeSecurityBundle {
    pub passport: TransactionPassport,
    pub evidence_graph_bytes: Vec<u8>,
    pub root_evidence_graph_bytes: Option<Vec<u8>>,
    pub verifier_policy_bytes: Vec<u8>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeSecurityTrust {
    pub trusted_passport_signer_keys: Vec<PublicKey>,
    pub trusted_root_signer_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSecurityReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub passport_id: String,
    pub verified_claims: Vec<String>,
}

pub fn verify_runtime_security_claims(
    bundle: &RuntimeSecurityBundle,
) -> Result<RuntimeSecurityReport, TransactionPassportError> {
    verify_runtime_security_claims_with_trust(bundle, &RuntimeSecurityTrust::default())
}

pub fn verify_runtime_security_claims_with_trust(
    bundle: &RuntimeSecurityBundle,
    trust: &RuntimeSecurityTrust,
) -> Result<RuntimeSecurityReport, TransactionPassportError> {
    let graph_artifacts = runtime_graph_artifacts(bundle);
    let root_evidence_graph_bytes = bundle
        .root_evidence_graph_bytes
        .as_deref()
        .unwrap_or(&bundle.evidence_graph_bytes);
    verify_passport_root_and_claim_set_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        root_evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
        &graph_artifacts,
        &trust.trusted_passport_signer_keys,
    )?;
    let graph = parse_graph(&bundle.evidence_graph_bytes)?;
    let policy = parse_policy(&bundle.verifier_policy_bytes)?;
    ensure_no_advisory_authorization(&graph)?;

    let mut verified_claims = Vec::new();
    if requires_online_runtime_evidence(&policy.required_claims) {
        verify_online_runtime_evidence(bundle, trust, &graph, &mut verified_claims)?;
    }
    if policy
        .required_claims
        .iter()
        .any(|claim| claim == CLAIM_RECEIPT_TOTALITY)
        && !verified_claims
            .iter()
            .any(|claim| claim == CLAIM_RECEIPT_TOTALITY)
    {
        verify_terminal_receipt_totality(bundle, trust, &graph, &mut verified_claims)?;
    }
    if policy
        .required_claims
        .iter()
        .any(|claim| claim == CLAIM_ADVISORY_NOT_AUTHORIZATION)
    {
        push_claim_once(&mut verified_claims, CLAIM_ADVISORY_NOT_AUTHORIZATION);
    }
    ensure_required_claims_verified(&policy.required_claims, &verified_claims)?;

    Ok(RuntimeSecurityReport {
        schema: TRANSACTION_RUNTIME_SECURITY_REPORT_SCHEMA_ID.to_string(),
        id: format!("runtime-security-report-{}", bundle.passport.id),
        issued_at: bundle.passport.issued_at.clone(),
        verdict: "verified".to_string(),
        passport_id: bundle.passport.id.clone(),
        verified_claims,
    })
}

fn runtime_graph_artifacts(bundle: &RuntimeSecurityBundle) -> BTreeMap<String, Vec<u8>> {
    let mut artifacts = bundle.artifacts.clone();
    artifacts.insert(
        bundle.passport.verifier_policy_path.clone(),
        bundle.verifier_policy_bytes.clone(),
    );
    artifacts
}

fn verify_online_runtime_evidence(
    bundle: &RuntimeSecurityBundle,
    trust: &RuntimeSecurityTrust,
    graph: &RuntimeEvidenceGraph,
    verified_claims: &mut Vec<String>,
) -> Result<(), TransactionPassportError> {
    verify_allowed_execution_attempts(bundle, trust, graph)?;

    push_claim_once(verified_claims, CLAIM_EXECUTION_LEASE_VALID);
    push_claim_once(verified_claims, CLAIM_NONCE_FRESH);
    push_claim_once(verified_claims, CLAIM_REVOCATION_FRESH);
    push_claim_once(verified_claims, CLAIM_SANDBOX_MATCHED);
    push_claim_once(verified_claims, CLAIM_TOOL_ACK_BOUND);
    push_claim_once(verified_claims, CLAIM_RECEIPT_TOTALITY);
    Ok(())
}

fn requires_online_runtime_evidence(required_claims: &[String]) -> bool {
    required_claims.iter().any(|claim| {
        matches!(
            claim.as_str(),
            CLAIM_EXECUTION_LEASE_VALID
                | CLAIM_NONCE_FRESH
                | CLAIM_REVOCATION_FRESH
                | CLAIM_SANDBOX_MATCHED
                | CLAIM_TOOL_ACK_BOUND
        )
    })
}

fn ensure_required_claims_verified(
    required_claims: &[String],
    verified_claims: &[String],
) -> Result<(), TransactionPassportError> {
    for required_claim in required_claims
        .iter()
        .filter(|claim| claim.starts_with("claim.runtime."))
    {
        if !verified_claims
            .iter()
            .any(|verified_claim| verified_claim == required_claim)
        {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                format!("required claim not verified: {required_claim}"),
            ));
        }
    }
    Ok(())
}

fn verify_terminal_receipt_totality(
    bundle: &RuntimeSecurityBundle,
    trust: &RuntimeSecurityTrust,
    graph: &RuntimeEvidenceGraph,
    verified_claims: &mut Vec<String>,
) -> Result<(), TransactionPassportError> {
    let receipts: Vec<RuntimeTerminalReceipt> = parse_artifacts_by_role(
        bundle,
        graph,
        RuntimeEvidenceRole::Receipt,
        RUNTIME_TERMINAL_RECEIPT_SCHEMA_ID,
    )?;
    if receipts.is_empty() {
        let message = if nodes_by_role(graph, RuntimeEvidenceRole::ExecutionLease)
            .next()
            .is_some()
        {
            "missing terminal receipt for execution lease"
        } else {
            "missing terminal receipt"
        };
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            message.to_string(),
        ));
    }
    let trust_roots = parse_runtime_trust_roots(bundle, graph)?;
    let trusted_roots: Vec<_> = trust_roots.iter().collect();
    for receipt in &receipts {
        validate_terminal_receipt(
            receipt,
            &bundle.passport.verifier_policy_sha256,
            &trusted_roots,
            &trust.trusted_root_signer_keys,
        )?;
    }
    ensure_terminal_receipts_cover_execution_leases(bundle, graph)?;
    if receipts
        .iter()
        .any(|receipt| receipt.terminal_status == "allowed_executed")
    {
        verify_allowed_execution_attempts(bundle, trust, graph)?;
    }
    push_claim_once(verified_claims, CLAIM_RECEIPT_TOTALITY);
    Ok(())
}

fn verify_allowed_execution_attempts(
    bundle: &RuntimeSecurityBundle,
    trust: &RuntimeSecurityTrust,
    graph: &RuntimeEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    let leases: Vec<_> = nodes_by_role(graph, RuntimeEvidenceRole::ExecutionLease)
        .map(|node| {
            parse_artifact(bundle, node, RUNTIME_EXECUTION_LEASE_SCHEMA_ID)
                .map(|lease: RuntimeExecutionLease| (node, lease))
        })
        .collect::<Result<_, _>>()?;
    if leases.is_empty() {
        return Err(TransactionPassportError::MissingExecutionLease);
    }

    let revocations: Vec<RuntimeRevocationFreshnessProof> = parse_artifacts_by_role(
        bundle,
        graph,
        RuntimeEvidenceRole::RevocationFreshnessProof,
        RUNTIME_REVOCATION_FRESHNESS_PROOF_SCHEMA_ID,
    )?;
    let sandboxes: Vec<RuntimeSandboxAttestation> = parse_artifacts_by_role(
        bundle,
        graph,
        RuntimeEvidenceRole::SandboxAttestation,
        RUNTIME_SANDBOX_ATTESTATION_SCHEMA_ID,
    )?;
    let acks: Vec<_> = nodes_by_role(graph, RuntimeEvidenceRole::ToolServerAck)
        .map(|node| {
            parse_artifact(bundle, node, RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID)
                .map(|ack: RuntimeToolServerAck| (node, ack))
        })
        .collect::<Result<_, _>>()?;
    let trust_roots: Vec<_> = nodes_by_role(graph, RuntimeEvidenceRole::TrustRoot)
        .map(|node| parse_artifact(bundle, node, "chio.trust.root.v1").map(|root| (node, root)))
        .collect::<Result<Vec<_>, _>>()?;
    let activation_receipts: Vec<RuntimePolicyActivationReceipt> = parse_artifacts_by_role(
        bundle,
        graph,
        RuntimeEvidenceRole::PolicyActivationReceipt,
        POLICY_ACTIVATION_RECEIPT_SCHEMA_ID,
    )?;
    let trusted_roots: Vec<_> = trust_roots
        .iter()
        .map(|(_, trust_root)| trust_root)
        .collect();
    for receipt in &activation_receipts {
        validate_policy_activation_receipt(
            receipt,
            &bundle.passport.verifier_policy_sha256,
            &trusted_roots,
            &trust.trusted_root_signer_keys,
        )?;
    }
    let attack_reports: Vec<RuntimeAttackSimulationReport> = parse_artifacts_by_role(
        bundle,
        graph,
        RuntimeEvidenceRole::RuntimeAttackSimulationReport,
        RUNTIME_ATTACK_SIMULATION_REPORT_SCHEMA_ID,
    )?;
    for report in &attack_reports {
        validate_attack_simulation_report(report, &trusted_roots, &trust.trusted_root_signer_keys)?;
    }
    let chaos_reports: Vec<RuntimeChaosRunReport> = parse_artifacts_by_role(
        bundle,
        graph,
        RuntimeEvidenceRole::RuntimeChaosRunReport,
        RUNTIME_CHAOS_RUN_REPORT_SCHEMA_ID,
    )?;
    for report in &chaos_reports {
        validate_chaos_run_report(report, &trusted_roots, &trust.trusted_root_signer_keys)?;
    }
    validate_nonce_uniqueness(bundle, graph)?;

    for (lease_node, lease) in &leases {
        let authorizing_trust_roots: Vec<_> = trust_roots
            .iter()
            .filter(|(trust_root_node, _)| {
                trust_root_authorizes_lease(graph, trust_root_node, lease_node)
            })
            .map(|(_, trust_root)| trust_root)
            .collect();
        validate_execution_lease(
            lease,
            &bundle.passport.verifier_policy_sha256,
            &authorizing_trust_roots,
            &trust.trusted_root_signer_keys,
        )?;
        let requests: Vec<RuntimeRequestDigest> = bound_request_nodes(graph, lease_node)
            .map(|node| parse_artifact(bundle, node, REQUEST_DIGEST_SCHEMA_ID))
            .collect::<Result<_, _>>()?;
        let request = match requests.as_slice() {
            [request] => request,
            [] => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing request digest for execution lease".to_string(),
                ));
            }
            _ => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "multiple request digests for execution lease".to_string(),
                ));
            }
        };
        validate_request_digest_binding(lease, request)?;
        let route_plans: Vec<RuntimeRoutePlanReceipt> = bound_route_plan_nodes(graph, lease_node)
            .map(|node| parse_artifact(bundle, node, SWARM_ROUTE_PLAN_RECEIPT_SCHEMA_ID))
            .collect::<Result<_, _>>()?;
        let route_plan = match route_plans.as_slice() {
            [route_plan] => route_plan,
            [] => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing route plan receipt for execution lease".to_string(),
                ));
            }
            _ => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "multiple route plan receipts for execution lease".to_string(),
                ));
            }
        };
        validate_route_plan_receipt(
            lease,
            route_plan,
            &authorizing_trust_roots,
            &trust.trusted_root_signer_keys,
        )?;
        let task_graph_nodes: Vec<_> = bound_task_graph_nodes(graph, lease_node).collect();
        let task_graph_node = match task_graph_nodes.as_slice() {
            [task_graph_node] => *task_graph_node,
            [] => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing task graph for execution lease".to_string(),
                ));
            }
            _ => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "multiple task graphs for execution lease".to_string(),
                ));
            }
        };
        let task_graph: RuntimeTaskGraph =
            parse_artifact(bundle, task_graph_node, SWARM_TASK_GRAPH_SCHEMA_ID)?;
        let budget_pools: Vec<RuntimeBudgetPool> = bound_budget_pool_nodes(graph, lease_node)
            .map(|node| parse_artifact(bundle, node, SWARM_BUDGET_POOL_SCHEMA_ID))
            .collect::<Result<_, _>>()?;
        let budget_pool = match budget_pools.as_slice() {
            [budget_pool] => budget_pool,
            [] => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing budget pool for execution lease".to_string(),
                ));
            }
            _ => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "multiple budget pools for execution lease".to_string(),
                ));
            }
        };
        let join_receipts: Vec<RuntimeJoinReceipt> = bound_join_receipt_nodes(graph, lease_node)
            .map(|node| parse_artifact(bundle, node, SWARM_JOIN_RECEIPT_SCHEMA_ID))
            .collect::<Result<_, _>>()?;
        let join_receipt = match join_receipts.as_slice() {
            [join_receipt] => join_receipt,
            [] => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing join receipt for execution lease".to_string(),
                ));
            }
            _ => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "multiple join receipts for execution lease".to_string(),
                ));
            }
        };
        validate_execution_lease_context(
            lease,
            ExecutionLeaseContext {
                task_graph_sha256: node_sha256(task_graph_node),
                task_graph: &task_graph,
                route_plan,
                budget_pool,
                join_receipt,
                trusted_roots: &authorizing_trust_roots,
                trusted_root_signer_keys: &trust.trusted_root_signer_keys,
            },
        )?;

        let revocation = revocations
            .iter()
            .find(|proof| proof.proof_id == lease.revocation_freshness_ref)
            .ok_or_else(|| {
                TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing revocation freshness proof for execution lease".to_string(),
                )
            })?;
        validate_revocation_freshness(
            lease,
            revocation,
            &authorizing_trust_roots,
            &trust.trusted_root_signer_keys,
        )?;

        let sandbox = sandboxes
            .iter()
            .find(|sandbox| sandbox.attestation_id == lease.sandbox_attestation_ref)
            .ok_or_else(|| {
                TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing sandbox attestation for execution lease".to_string(),
                )
            })?;
        validate_sandbox_attestation(
            lease,
            sandbox,
            &authorizing_trust_roots,
            &trust.trusted_root_signer_keys,
        )?;

        let (ack_node, ack) = acks
            .iter()
            .find(|(_, ack)| ack.lease_id == lease.lease_id)
            .ok_or_else(|| {
                TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing tool-server acknowledgement for execution lease".to_string(),
                )
            })?;
        let trusted_time_proofs: Vec<RuntimeTrustedTimeProof> =
            bound_trusted_time_nodes(graph, ack_node)
                .map(|node| parse_artifact(bundle, node, RUNTIME_TRUSTED_TIME_PROOF_SCHEMA_ID))
                .collect::<Result<_, _>>()?;
        let trusted_time_proof = match trusted_time_proofs.as_slice() {
            [trusted_time_proof] => trusted_time_proof,
            [] => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing trusted time proof for tool acknowledgement".to_string(),
                ));
            }
            _ => {
                return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                    "multiple trusted time proofs for tool acknowledgement".to_string(),
                ));
            }
        };
        validate_tool_server_ack(
            lease,
            sandbox,
            ack,
            &authorizing_trust_roots,
            &trust.trusted_root_signer_keys,
        )?;
        validate_trusted_time_proof(
            lease,
            ack,
            trusted_time_proof,
            &authorizing_trust_roots,
            &trust.trusted_root_signer_keys,
        )?;
        validate_revocation_freshness_at_ack(revocation, ack)?;

        let receipts: Vec<RuntimeTerminalReceipt> = leased_receipt_nodes(graph, lease_node)
            .map(|node| parse_artifact(bundle, node, RUNTIME_TERMINAL_RECEIPT_SCHEMA_ID))
            .collect::<Result<_, _>>()?;
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.execution_lease_ref.as_deref() == Some(lease.lease_id.as_str()))
            .ok_or_else(|| {
                TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing terminal receipt for execution lease".to_string(),
                )
            })?;
        validate_allow_receipt(
            lease,
            receipt,
            &authorizing_trust_roots,
            &trust.trusted_root_signer_keys,
        )?;
    }

    Ok(())
}

fn ensure_terminal_receipts_cover_execution_leases(
    bundle: &RuntimeSecurityBundle,
    graph: &RuntimeEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    for lease_node in nodes_by_role(graph, RuntimeEvidenceRole::ExecutionLease) {
        let lease: RuntimeExecutionLease =
            parse_artifact(bundle, lease_node, RUNTIME_EXECUTION_LEASE_SCHEMA_ID)?;
        let receipts: Vec<RuntimeTerminalReceipt> = leased_receipt_nodes(graph, lease_node)
            .map(|node| parse_artifact(bundle, node, RUNTIME_TERMINAL_RECEIPT_SCHEMA_ID))
            .collect::<Result<_, _>>()?;
        if !receipts
            .iter()
            .any(|receipt| receipt.execution_lease_ref.as_deref() == Some(lease.lease_id.as_str()))
        {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "missing terminal receipt for execution lease".to_string(),
            ));
        }
    }
    Ok(())
}

fn parse_runtime_trust_roots(
    bundle: &RuntimeSecurityBundle,
    graph: &RuntimeEvidenceGraph,
) -> Result<Vec<RuntimeTrustRoot>, TransactionPassportError> {
    nodes_by_role(graph, RuntimeEvidenceRole::TrustRoot)
        .map(|node| parse_artifact(bundle, node, "chio.trust.root.v1"))
        .collect()
}

fn parse_artifacts_by_role<T: for<'de> Deserialize<'de>>(
    bundle: &RuntimeSecurityBundle,
    graph: &RuntimeEvidenceGraph,
    role: RuntimeEvidenceRole,
    schema: &str,
) -> Result<Vec<T>, TransactionPassportError> {
    nodes_by_role(graph, role)
        .map(|node| parse_artifact(bundle, node, schema))
        .collect()
}
