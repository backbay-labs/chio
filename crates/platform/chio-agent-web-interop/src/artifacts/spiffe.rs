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
        return Err(claim_failed("SPIFFE source version mismatch"));
    }
    if manifest.source_version != "workload-api-v1" {
        return Err(claim_failed("unsupported SPIFFE source version"));
    }
    let trust_domain = required_json_str(value, "trust_domain", "missing SPIFFE trust domain")?;
    if trust_domain.contains('/') {
        return Err(claim_failed("SPIFFE trust domain must not contain path"));
    }
    let spiffe_id = required_json_str(value, "spiffe_id", "missing SPIFFE ID")?;
    let expected_prefix = format!("spiffe://{trust_domain}/");
    if !spiffe_id.starts_with(&expected_prefix) {
        return Err(claim_failed("SPIFFE ID does not match trust domain"));
    }
    let svid_type = required_json_str(value, "svid_type", "missing SPIFFE SVID type")?;
    if !matches!(svid_type, "x509_svid" | "jwt_svid") {
        return Err(claim_failed("unsupported SPIFFE SVID type"));
    }
    let bundle_digest = required_json_str(value, "bundle_digest", "missing SPIFFE bundle digest")?;
    validate_sha256_hex(bundle_digest)
        .map_err(|_| claim_failed("invalid SPIFFE digest: bundle_digest"))?;
    required_json_str(
        value,
        "workload_attestation_ref",
        "missing SPIFFE workload attestation ref",
    )?;
    required_json_str(value, "expiry", "missing SPIFFE expiry")?;
    required_json_str(
        value,
        "chio_workload_identity_mapping_ref",
        "missing SPIFFE Chio workload identity mapping ref",
    )?;
    let workload_receipt_ref = required_json_str(
        value,
        "chio_workload_receipt_ref",
        "missing SPIFFE workload receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == workload_receipt_ref)
    {
        return Err(claim_failed("SPIFFE workload receipt ref is not bound"));
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing SPIFFE Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "SPIFFE workload identity was not mediated by Chio receipt",
        ));
    }
    Ok(())
}
