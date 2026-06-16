use chio_transaction_passport::TransactionPassportError;

use super::{
    claim_failed, required_json_bool, required_json_str, validate_object_kind, validate_sha256_hex,
    AgentWebProofEnvelope, ProjectionManifest,
};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    validate_object_kind(
        value,
        "oauth2_authorization",
        "OAuth2 external subject kind mismatch",
    )?;
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("OAuth2 source version mismatch"));
    }
    if manifest.source_version != "rfc6749" {
        return Err(claim_failed("unsupported OAuth2 source version"));
    }
    let issuer = required_json_str(value, "issuer", "missing OAuth2 issuer")?;
    if !issuer.starts_with("https://") {
        return Err(claim_failed("OAuth2 issuer must be https"));
    }
    let resource = required_json_str(value, "resource", "missing OAuth2 resource")?;
    if !resource.starts_with("https://") {
        return Err(claim_failed("OAuth2 resource must be https"));
    }
    let grant_type = required_json_str(value, "grant_type", "missing OAuth2 grant type")?;
    if !matches!(
        grant_type,
        "authorization_code"
            | "client_credentials"
            | "token_exchange"
            | "refresh_token"
            | "device_code"
    ) {
        return Err(claim_failed("unsupported OAuth2 grant type"));
    }
    let sender_constraint = required_json_str(
        value,
        "sender_constraint",
        "missing OAuth2 sender constraint",
    )?;
    if !matches!(sender_constraint, "dpop" | "mtls" | "bound-session") {
        return Err(claim_failed("unsupported OAuth2 sender constraint"));
    }
    let token_status = required_json_str(value, "token_status", "missing OAuth2 token status")?;
    if token_status != "active" {
        return Err(claim_failed("OAuth2 token is not active"));
    }
    let authorized_scope_subset = required_json_bool(
        value,
        "authorized_scope_subset",
        "missing OAuth2 authorized scope subset result",
    )?;
    if !authorized_scope_subset {
        return Err(claim_failed(
            "OAuth2 scope set is broader than the projection authorization",
        ));
    }
    for (field, message) in [
        ("subject_digest", "missing OAuth2 subject digest"),
        ("audience_digest", "missing OAuth2 audience digest"),
        ("client_id_digest", "missing OAuth2 client id digest"),
        ("scope_set_digest", "missing OAuth2 scope set digest"),
        (
            "authorization_details_digest",
            "missing OAuth2 authorization details digest",
        ),
        (
            "sender_constraint_digest",
            "missing OAuth2 sender constraint digest",
        ),
        (
            "token_verification_report_digest",
            "missing OAuth2 token verification report digest",
        ),
        (
            "chio_caller_identity_digest",
            "missing OAuth2 Chio caller identity digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid OAuth2 digest: {field}")))?;
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing OAuth2 Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "OAuth2 authorization was not mediated by Chio receipt",
        ));
    }
    let authorization_receipt_ref = required_json_str(
        value,
        "chio_authorization_receipt_ref",
        "missing OAuth2 authorization receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == authorization_receipt_ref)
    {
        return Err(claim_failed(
            "OAuth2 authorization receipt ref is not bound",
        ));
    }
    Ok(())
}
