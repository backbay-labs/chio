use chio_kernel::ToolCallRequest;

use crate::*;

pub(super) struct TreatyReference {
    pub(super) treaty_scope_id: String,
    pub(super) treaty_scope_sha256: String,
    pub(super) ladder_intersection_id: String,
    pub(super) ladder_intersection_sha256: String,
    pub(super) action_class_id: String,
    pub(super) continuation: Option<TreatyEvidenceReference>,
    pub(super) lineage_bundle: Option<TreatyEvidenceReference>,
    pub(super) bilateral_dsse: Option<TreatyEvidenceReference>,
    pub(super) bilateral_invocation: Option<TreatyEvidenceReference>,
}

#[derive(Debug, Clone)]
pub(super) struct TreatyEvidenceReference {
    pub(super) evidence_id: String,
    pub(super) artifact_sha256: String,
}

pub(super) fn treaty_ref_from_request(
    request: &ToolCallRequest,
) -> Result<Option<TreatyReference>, &'static str> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Ok(None);
    };
    let Some(context) = intent.context.as_ref() else {
        return Ok(None);
    };
    let Some(treaty) = context.get("chioTreaty") else {
        return Ok(None);
    };
    let Some(object) = treaty.as_object() else {
        return Err("invalid_chio_treaty_context");
    };
    for forbidden in [
        "trustRoot",
        "trustRoots",
        "trustBundle",
        "treatyScope",
        "ladderManifest",
        "signingKey",
        "peerDirectory",
    ] {
        if object.contains_key(forbidden) {
            return Err("request_smuggled_trust_root");
        }
    }
    for forbidden in [
        "dynamicTrust",
        "dynamicTrustBundle",
        "runtimeTrustInput",
        "peerDiscovery",
    ] {
        if object.contains_key(forbidden) {
            return Err("request_smuggled_dynamic_trust");
        }
    }
    let Some(treaty_scope_id) = object.get("treatyScopeId").and_then(|value| value.as_str()) else {
        return Err("missing_treaty_scope_id");
    };
    let Some(treaty_scope_sha256) = object
        .get("treatyScopeSha256")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_treaty_scope_hash");
    };
    let Some(ladder_intersection_id) = object
        .get("ladderIntersectionId")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_ladder_intersection_id");
    };
    let Some(ladder_intersection_sha256) = object
        .get("ladderIntersectionSha256")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_ladder_intersection_hash");
    };
    let Some(action_class_id) = object.get("actionClassId").and_then(|value| value.as_str()) else {
        return Err("missing_action_class_id");
    };
    if treaty_scope_id.trim().is_empty()
        || ladder_intersection_id.trim().is_empty()
        || action_class_id.trim().is_empty()
    {
        return Err("invalid_chio_treaty_context");
    }
    if !is_sha256_hex(treaty_scope_sha256) || !is_sha256_hex(ladder_intersection_sha256) {
        return Err("invalid_chio_treaty_hash");
    }
    let continuation = treaty_evidence_ref_from_context(
        object,
        &["crossKernelContinuation", "continuation"],
        &["continuationId"],
        &["continuationSha256"],
    )?;
    let lineage_bundle = treaty_evidence_ref_from_context(
        object,
        &["receiptLineageBundle", "lineageBundle"],
        &["receiptLineageBundleId", "lineageBundleId"],
        &["receiptLineageBundleSha256", "lineageBundleSha256"],
    )?;
    let bilateral_dsse = treaty_evidence_ref_from_context(
        object,
        &["bilateralDsse", "bilateralDsseEnvelope"],
        &["bilateralDsseId", "bilateralDsseEnvelopeId"],
        &["bilateralDsseSha256", "bilateralDsseEnvelopeSha256"],
    )?;
    let bilateral_invocation = treaty_evidence_ref_from_context(
        object,
        &["bilateralInvocation"],
        &["bilateralInvocationId"],
        &["bilateralInvocationSha256"],
    )?;
    Ok(Some(TreatyReference {
        treaty_scope_id: treaty_scope_id.to_string(),
        treaty_scope_sha256: treaty_scope_sha256.to_string(),
        ladder_intersection_id: ladder_intersection_id.to_string(),
        ladder_intersection_sha256: ladder_intersection_sha256.to_string(),
        action_class_id: action_class_id.to_string(),
        continuation,
        lineage_bundle,
        bilateral_dsse,
        bilateral_invocation,
    }))
}

fn treaty_evidence_ref_from_context(
    object: &serde_json::Map<String, serde_json::Value>,
    object_fields: &[&str],
    id_fields: &[&str],
    hash_fields: &[&str],
) -> Result<Option<TreatyEvidenceReference>, &'static str> {
    for field in object_fields {
        if let Some(value) = object.get(*field) {
            let Some(ref_object) = value.as_object() else {
                return Err("invalid_chio_treaty_evidence_ref");
            };
            let evidence_id = ref_object
                .get("id")
                .or_else(|| ref_object.get("evidenceId"))
                .or_else(|| ref_object.get("artifactId"))
                .and_then(|value| value.as_str())
                .ok_or("missing_chio_treaty_evidence_ref")?;
            let artifact_sha256 = ref_object
                .get("sha256")
                .or_else(|| ref_object.get("artifactSha256"))
                .and_then(|value| value.as_str())
                .ok_or("missing_chio_treaty_evidence_ref")?;
            return treaty_evidence_ref(evidence_id, artifact_sha256);
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
            treaty_evidence_ref(evidence_id, artifact_sha256)
        }
        (None, None) => Ok(None),
        _ => Err("missing_chio_treaty_evidence_ref"),
    }
}

fn treaty_evidence_ref(
    evidence_id: &str,
    artifact_sha256: &str,
) -> Result<Option<TreatyEvidenceReference>, &'static str> {
    if evidence_id.trim().is_empty() || !is_sha256_hex(artifact_sha256) {
        return Err("invalid_chio_treaty_evidence_ref");
    }
    Ok(Some(TreatyEvidenceReference {
        evidence_id: evidence_id.to_string(),
        artifact_sha256: artifact_sha256.to_string(),
    }))
}
