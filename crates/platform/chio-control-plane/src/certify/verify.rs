use chio_core::{canonical_json_bytes, sha256_hex};

use crate::CliError;

use super::types::{
    CertificationRegistryEntry, CertificationRegistryState, SignedCertificationCheck,
};
use super::validators::validate_certification_artifact_body;

pub(crate) fn verify_signed_certification_check(
    artifact: &SignedCertificationCheck,
) -> Result<(), CliError> {
    validate_certification_artifact_body(&artifact.body)?;
    let body_bytes = canonical_json_bytes(&artifact.body)?;
    if !artifact
        .signer_public_key
        .verify(&body_bytes, &artifact.signature)
    {
        return Err(CliError::attest_error(
            "certification artifact signature is invalid".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn certification_artifact_id(
    artifact: &SignedCertificationCheck,
) -> Result<String, CliError> {
    Ok(sha256_hex(&canonical_json_bytes(artifact)?))
}

pub(crate) fn verify_certification_registry_entry(
    entry: &CertificationRegistryEntry,
) -> Result<(), CliError> {
    verify_signed_certification_check(&entry.artifact)?;
    let expected_artifact_id = certification_artifact_id(&entry.artifact)?;
    if entry.artifact_id != expected_artifact_id {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched artifact_id",
            entry.artifact_id
        )));
    }
    if entry.artifact_sha256 != expected_artifact_id {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched artifact digest",
            entry.artifact_id
        )));
    }
    if entry.tool_server_id != entry.artifact.body.target.tool_server_id {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched tool_server_id",
            entry.artifact_id
        )));
    }
    if entry.tool_server_name != entry.artifact.body.target.tool_server_name {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched tool_server_name",
            entry.artifact_id
        )));
    }
    if entry.checked_at != entry.artifact.body.checked_at {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched checked_at",
            entry.artifact_id
        )));
    }
    if entry.verdict != entry.artifact.body.verdict {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` has mismatched verdict",
            entry.artifact_id
        )));
    }
    if entry.status == CertificationRegistryState::Superseded && entry.superseded_by.is_none() {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` is superseded without superseded_by",
            entry.artifact_id
        )));
    }
    if entry.status == CertificationRegistryState::Superseded && entry.superseded_at.is_none() {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` is superseded without superseded_at",
            entry.artifact_id
        )));
    }
    if entry.status == CertificationRegistryState::Revoked && entry.revoked_at.is_none() {
        return Err(CliError::attest_error(format!(
            "certification registry entry `{}` is revoked without revoked_at",
            entry.artifact_id
        )));
    }
    if let Some(dispute) = entry.dispute.as_ref() {
        if dispute.updated_at == 0 {
            return Err(CliError::attest_error(format!(
                "certification registry entry `{}` has invalid dispute timestamp",
                entry.artifact_id
            )));
        }
    }
    Ok(())
}
