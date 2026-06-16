use chio_transaction_passport::TransactionPassportError;

use super::{
    claim_failed, required_json_bool, required_json_str, validate_sha256_hex,
    AgentWebProofEnvelope, ProjectionManifest,
};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("SCIM source version mismatch"));
    }
    if manifest.source_version != "rfc7644" {
        return Err(claim_failed("unsupported SCIM source version"));
    }
    required_json_str(value, "provider_id", "missing SCIM provider id")?;
    let resource_type = required_json_str(value, "resource_type", "missing SCIM resource type")?;
    if !matches!(resource_type, "User" | "Group") {
        return Err(claim_failed("unsupported SCIM resource type"));
    }
    let operation = required_json_str(value, "operation", "missing SCIM operation")?;
    if !matches!(operation, "create" | "update" | "patch" | "delete") {
        return Err(claim_failed("unsupported SCIM operation"));
    }
    let active_state = required_json_str(value, "active_state", "missing SCIM active state")?;
    if !matches!(active_state, "active" | "inactive") {
        return Err(claim_failed("unsupported SCIM active state"));
    }
    for (field, message) in [
        ("resource_id_digest", "missing SCIM resource id digest"),
        ("subject_digest", "missing SCIM subject digest"),
        (
            "resource_version_digest",
            "missing SCIM resource version digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid SCIM digest: {field}")))?;
    }
    if let Some(group_digest) = value
        .get("group_digest")
        .and_then(serde_json::Value::as_str)
    {
        validate_sha256_hex(group_digest)
            .map_err(|_| claim_failed("invalid SCIM digest: group_digest"))?;
    }
    if operation == "delete" || active_state == "inactive" {
        let deprovisioning_receipt_ref = required_json_str(
            value,
            "deprovisioning_receipt_ref",
            "missing SCIM deprovisioning receipt ref",
        )?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|receipt_ref| receipt_ref == deprovisioning_receipt_ref)
        {
            return Err(claim_failed("SCIM deprovisioning receipt is not bound"));
        }
        let revocation_refs = value
            .get("capability_revocation_refs")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| claim_failed("missing SCIM capability revocation refs"))?;
        if revocation_refs.is_empty()
            || revocation_refs
                .iter()
                .any(|revocation_ref| match revocation_ref.as_str() {
                    Some(value) => value.is_empty(),
                    None => true,
                })
        {
            return Err(claim_failed("invalid SCIM capability revocation refs"));
        }
    } else {
        let lifecycle_receipt_ref = required_json_str(
            value,
            "chio_lifecycle_receipt_ref",
            "missing SCIM lifecycle receipt ref",
        )?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|receipt_ref| receipt_ref == lifecycle_receipt_ref)
        {
            return Err(claim_failed("SCIM lifecycle receipt is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing SCIM Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "SCIM lifecycle event was not mediated by Chio receipt",
        ));
    }
    Ok(())
}
