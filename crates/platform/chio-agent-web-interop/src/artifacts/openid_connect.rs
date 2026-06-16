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
        return Err(claim_failed("OpenID Connect source version mismatch"));
    }
    if manifest.source_version != "core-1.0" {
        return Err(claim_failed("unsupported OpenID Connect source version"));
    }
    let issuer = required_json_str(value, "issuer", "missing OpenID Connect issuer")?;
    if !issuer.starts_with("https://") {
        return Err(claim_failed("OpenID Connect issuer must be https"));
    }
    required_json_str(
        value,
        "authentication_time",
        "missing OpenID Connect authentication time",
    )?;
    required_json_str(value, "acr", "missing OpenID Connect acr")?;
    let token_status =
        required_json_str(value, "token_status", "missing OpenID Connect token status")?;
    if token_status != "verified" {
        return Err(claim_failed("OpenID Connect token is not verified"));
    }
    for (field, message) in [
        ("subject_digest", "missing OpenID Connect subject digest"),
        ("audience_digest", "missing OpenID Connect audience digest"),
        ("nonce_digest", "missing OpenID Connect nonce digest"),
        ("amr_digest", "missing OpenID Connect amr digest"),
        (
            "id_token_verification_report_digest",
            "missing OpenID Connect ID token verification report digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid OpenID Connect digest: {field}")))?;
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing OpenID Connect Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "OpenID Connect identity was not mediated by Chio receipt",
        ));
    }
    let identity_receipt_ref = required_json_str(
        value,
        "chio_identity_receipt_ref",
        "missing OpenID Connect identity receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == identity_receipt_ref)
    {
        return Err(claim_failed(
            "OpenID Connect identity receipt ref is not bound",
        ));
    }
    Ok(())
}
