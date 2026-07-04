use chio_kernel::ToolCallRequest;

use crate::*;

#[derive(Debug, Clone)]
pub(super) struct SwarmAuthorityReference {
    pub task_graph: SwarmEvidenceReference,
    pub continuation_token: SwarmEvidenceReference,
    pub route_plan_receipt: SwarmEvidenceReference,
    pub delegation_witness: SwarmEvidenceReference,
    pub join_receipt: SwarmEvidenceReference,
    pub revocation_epoch: SwarmEvidenceReference,
    pub budget_pool: SwarmEvidenceReference,
}

#[derive(Debug, Clone)]
pub(super) struct SwarmEvidenceReference {
    pub evidence_id: String,
    pub artifact_sha256: String,
}

pub(super) fn swarm_ref_from_request(
    request: &ToolCallRequest,
) -> Result<Option<SwarmAuthorityReference>, &'static str> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Ok(None);
    };
    let Some(context) = intent.context.as_ref() else {
        return Ok(None);
    };
    let Some(swarm) = context.get("chioSwarm") else {
        return Ok(None);
    };
    let Some(object) = swarm.as_object() else {
        return Err("invalid_chio_swarm_context");
    };
    for forbidden in [
        "trustRoot",
        "trustRoots",
        "trustBundle",
        "authorityBundle",
        "signingKey",
        "witnessKeys",
    ] {
        if object.contains_key(forbidden) {
            return Err("request_smuggled_trust_root");
        }
    }
    for forbidden in ["dynamicTrust", "dynamicTrustBundle", "peerDiscovery"] {
        if object.contains_key(forbidden) {
            return Err("request_smuggled_dynamic_trust");
        }
    }
    let task_graph = required_swarm_evidence_ref(
        object,
        &["taskGraph"],
        &["taskGraphId"],
        &["taskGraphSha256"],
    )?;
    let continuation_token = required_swarm_evidence_ref(
        object,
        &["continuationToken", "continuation"],
        &["continuationTokenId"],
        &["continuationTokenSha256"],
    )?;
    let route_plan_receipt = required_swarm_evidence_ref(
        object,
        &["routePlanReceipt", "routePlan"],
        &["routePlanReceiptId", "routePlanId"],
        &["routePlanReceiptSha256", "routePlanSha256"],
    )?;
    let delegation_witness = required_swarm_evidence_ref(
        object,
        &["delegationWitness", "witnessChain", "witness"],
        &["delegationWitnessId", "witnessChainId", "witnessId"],
        &[
            "delegationWitnessSha256",
            "witnessChainSha256",
            "witnessSha256",
        ],
    )?;
    let join_receipt = required_swarm_evidence_ref(
        object,
        &["joinReceipt"],
        &["joinReceiptId"],
        &["joinReceiptSha256"],
    )?;
    let revocation_epoch = required_swarm_evidence_ref(
        object,
        &["revocationEpoch"],
        &["revocationEpochId"],
        &["revocationEpochSha256"],
    )?;
    let budget_pool = required_swarm_evidence_ref(
        object,
        &["budgetPool", "budgetLease"],
        &["budgetPoolId", "budgetLeaseId"],
        &["budgetPoolSha256", "budgetLeaseSha256"],
    )?;
    Ok(Some(SwarmAuthorityReference {
        task_graph,
        continuation_token,
        route_plan_receipt,
        delegation_witness,
        join_receipt,
        revocation_epoch,
        budget_pool,
    }))
}

fn required_swarm_evidence_ref(
    object: &serde_json::Map<String, serde_json::Value>,
    object_fields: &[&str],
    id_fields: &[&str],
    hash_fields: &[&str],
) -> Result<SwarmEvidenceReference, &'static str> {
    for field in object_fields {
        if let Some(value) = object.get(*field) {
            let Some(ref_object) = value.as_object() else {
                return Err("invalid_chio_swarm_evidence_ref");
            };
            let evidence_id = ref_object
                .get("id")
                .or_else(|| ref_object.get("evidenceId"))
                .or_else(|| ref_object.get("artifactId"))
                .and_then(|value| value.as_str())
                .ok_or("missing_chio_swarm_evidence_ref")?;
            let artifact_sha256 = ref_object
                .get("sha256")
                .or_else(|| ref_object.get("artifactSha256"))
                .and_then(|value| value.as_str())
                .ok_or("missing_chio_swarm_evidence_ref")?;
            return swarm_evidence_ref(evidence_id, artifact_sha256);
        }
    }

    let evidence_id = id_fields
        .iter()
        .find_map(|field| object.get(*field).and_then(|value| value.as_str()));
    let artifact_sha256 = hash_fields
        .iter()
        .find_map(|field| object.get(*field).and_then(|value| value.as_str()));
    match (evidence_id, artifact_sha256) {
        (Some(evidence_id), Some(artifact_sha256)) => {
            swarm_evidence_ref(evidence_id, artifact_sha256)
        }
        _ => Err("missing_chio_swarm_evidence_ref"),
    }
}

fn swarm_evidence_ref(
    evidence_id: &str,
    artifact_sha256: &str,
) -> Result<SwarmEvidenceReference, &'static str> {
    if evidence_id.trim().is_empty() || !is_sha256_hex(artifact_sha256) {
        return Err("invalid_chio_swarm_evidence_ref");
    }
    Ok(SwarmEvidenceReference {
        evidence_id: evidence_id.to_string(),
        artifact_sha256: artifact_sha256.to_string(),
    })
}
