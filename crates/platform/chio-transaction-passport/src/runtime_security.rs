use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::TransactionPassportError;
use super::ids::{
    RUNTIME_EXECUTION_LEASE_SCHEMA_ID, RUNTIME_REVOCATION_FRESHNESS_PROOF_SCHEMA_ID,
    RUNTIME_SANDBOX_ATTESTATION_SCHEMA_ID, RUNTIME_TERMINAL_RECEIPT_SCHEMA_ID,
    RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID, TRANSACTION_RUNTIME_SECURITY_REPORT_SCHEMA_ID,
};
use super::minimal::verify_minimal_passport_artifacts;
use super::types::TransactionPassport;

mod artifacts;
mod claims;
mod evidence;
mod policy;

use artifacts::{
    validate_allow_receipt, validate_execution_lease, validate_nonce_uniqueness,
    validate_revocation_freshness, validate_sandbox_attestation, validate_terminal_receipt,
    validate_tool_server_ack, RuntimeExecutionLease, RuntimeRevocationFreshnessProof,
    RuntimeSandboxAttestation, RuntimeTerminalReceipt, RuntimeToolServerAck,
};
use claims::{
    push_claim_once, CLAIM_ADVISORY_NOT_AUTHORIZATION, CLAIM_EXECUTION_LEASE_VALID,
    CLAIM_NONCE_FRESH, CLAIM_RECEIPT_TOTALITY, CLAIM_REVOCATION_FRESH, CLAIM_SANDBOX_MATCHED,
    CLAIM_TOOL_ACK_BOUND,
};
use evidence::{
    ensure_no_advisory_authorization, leased_receipt_nodes, nodes_by_role, parse_artifact,
    parse_graph, RuntimeEvidenceGraph, RuntimeEvidenceRole,
};
use policy::parse_policy;

#[derive(Debug, Clone)]
pub struct RuntimeSecurityBundle {
    pub passport: TransactionPassport,
    pub evidence_graph_bytes: Vec<u8>,
    pub verifier_policy_bytes: Vec<u8>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
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
    verify_minimal_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
    )?;

    let graph = parse_graph(&bundle.evidence_graph_bytes)?;
    let policy = parse_policy(&bundle.verifier_policy_bytes)?;
    ensure_no_advisory_authorization(&graph)?;

    let mut verified_claims = Vec::new();
    if policy
        .required_claims
        .iter()
        .any(|claim| claim == CLAIM_EXECUTION_LEASE_VALID)
    {
        verify_online_runtime_evidence(bundle, &graph, &mut verified_claims)?;
    }
    if policy
        .required_claims
        .iter()
        .any(|claim| claim == CLAIM_RECEIPT_TOTALITY)
        && !verified_claims
            .iter()
            .any(|claim| claim == CLAIM_RECEIPT_TOTALITY)
    {
        verify_terminal_receipt_totality(bundle, &graph, &mut verified_claims)?;
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

fn verify_online_runtime_evidence(
    bundle: &RuntimeSecurityBundle,
    graph: &RuntimeEvidenceGraph,
    verified_claims: &mut Vec<String>,
) -> Result<(), TransactionPassportError> {
    verify_allowed_execution_attempts(bundle, graph)?;

    push_claim_once(verified_claims, CLAIM_EXECUTION_LEASE_VALID);
    push_claim_once(verified_claims, CLAIM_NONCE_FRESH);
    push_claim_once(verified_claims, CLAIM_REVOCATION_FRESH);
    push_claim_once(verified_claims, CLAIM_SANDBOX_MATCHED);
    push_claim_once(verified_claims, CLAIM_TOOL_ACK_BOUND);
    push_claim_once(verified_claims, CLAIM_RECEIPT_TOTALITY);
    Ok(())
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
    for receipt in &receipts {
        validate_terminal_receipt(receipt, &bundle.passport.verifier_policy_sha256)?;
    }
    if receipts
        .iter()
        .any(|receipt| receipt.terminal_status == "allowed_executed")
    {
        verify_allowed_execution_attempts(bundle, graph)?;
    }
    push_claim_once(verified_claims, CLAIM_RECEIPT_TOTALITY);
    Ok(())
}

fn verify_allowed_execution_attempts(
    bundle: &RuntimeSecurityBundle,
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
    let acks: Vec<RuntimeToolServerAck> = parse_artifacts_by_role(
        bundle,
        graph,
        RuntimeEvidenceRole::ToolServerAck,
        RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID,
    )?;
    validate_nonce_uniqueness(bundle, graph)?;

    for (lease_node, lease) in &leases {
        validate_execution_lease(lease, &bundle.passport.verifier_policy_sha256)?;

        let revocation = revocations
            .iter()
            .find(|proof| proof.proof_id == lease.revocation_freshness_ref)
            .ok_or_else(|| {
                TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing revocation freshness proof for execution lease".to_string(),
                )
            })?;
        validate_revocation_freshness(lease, revocation)?;

        let sandbox = sandboxes
            .iter()
            .find(|sandbox| sandbox.attestation_id == lease.sandbox_attestation_ref)
            .ok_or_else(|| {
                TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing sandbox attestation for execution lease".to_string(),
                )
            })?;
        validate_sandbox_attestation(lease, sandbox)?;

        let ack = acks
            .iter()
            .find(|ack| ack.lease_id == lease.lease_id)
            .ok_or_else(|| {
                TransactionPassportError::RuntimeSecurityClaimFailed(
                    "missing tool-server acknowledgement for execution lease".to_string(),
                )
            })?;
        validate_tool_server_ack(lease, sandbox, ack)?;

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
        validate_allow_receipt(lease, receipt)?;
    }

    Ok(())
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
