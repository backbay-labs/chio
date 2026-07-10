use crate::CliError;

use super::helpers::normalize_registry_url;
use super::schema::{
    is_supported_certification_schema, is_supported_evidence_profile,
    CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER, CERTIFICATION_PUBLIC_METADATA_SCHEMA,
    CERTIFICATION_SCHEMA, CRITERIA_PROFILE_ALL_PASS_V1, GENERATED_REPORT_MEDIA_TYPE_MARKDOWN,
};
use super::types::{CertificationCheckBody, CertificationEvidence, CertificationPublicMetadata};

fn require_non_empty_field(value: &str, field: &str) -> Result<(), CliError> {
    if value.trim().is_empty() {
        return Err(CliError::attest_error(format!(
            "certification field `{field}` must not be empty"
        )));
    }
    Ok(())
}

fn validate_certification_evidence(evidence: &CertificationEvidence) -> Result<(), CliError> {
    if !is_supported_evidence_profile(&evidence.evidence_profile) {
        return Err(CliError::attest_error(format!(
            "unsupported certification evidence profile: {}",
            evidence.evidence_profile
        )));
    }
    require_non_empty_field(&evidence.scenarios_dir, "evidence.scenariosDir")?;
    require_non_empty_field(&evidence.results_dir, "evidence.resultsDir")?;
    require_non_empty_field(
        &evidence.normalized_scenarios_sha256,
        "evidence.normalizedScenariosSha256",
    )?;
    require_non_empty_field(
        &evidence.normalized_results_sha256,
        "evidence.normalizedResultsSha256",
    )?;
    require_non_empty_field(
        &evidence.generated_report_sha256,
        "evidence.generatedReportSha256",
    )?;
    if evidence.generated_report_bytes == 0 {
        return Err(CliError::attest_error(
            "certification evidence must include a non-empty generated report".to_string(),
        ));
    }
    if evidence.generated_report_media_type != GENERATED_REPORT_MEDIA_TYPE_MARKDOWN {
        return Err(CliError::attest_error(format!(
            "unsupported generated report media type: {}",
            evidence.generated_report_media_type
        )));
    }
    if evidence.provenance_mode != CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER {
        return Err(CliError::attest_error(format!(
            "unsupported certification provenance mode: {}",
            evidence.provenance_mode
        )));
    }
    Ok(())
}

pub(crate) fn validate_public_certification_metadata(
    metadata: &CertificationPublicMetadata,
    expected_registry_url: Option<&str>,
    now: u64,
) -> Result<(), CliError> {
    if metadata.schema != CERTIFICATION_PUBLIC_METADATA_SCHEMA {
        return Err(CliError::attest_error(format!(
            "unsupported certification public metadata schema: {}",
            metadata.schema
        )));
    }
    let publisher_id = normalize_registry_url(&metadata.publisher.publisher_id);
    let registry_url = normalize_registry_url(&metadata.publisher.registry_url);
    if publisher_id.is_empty() {
        return Err(CliError::attest_error(
            "certification public metadata is missing publisher.publisherId".to_string(),
        ));
    }
    if registry_url.is_empty() {
        return Err(CliError::attest_error(
            "certification public metadata is missing publisher.registryUrl".to_string(),
        ));
    }
    if publisher_id != registry_url {
        return Err(CliError::attest_error(format!(
            "certification public metadata publisher id `{publisher_id}` does not match registry url `{registry_url}`"
        )));
    }
    if let Some(expected_registry_url) = expected_registry_url {
        let expected = normalize_registry_url(expected_registry_url);
        if registry_url != expected {
            return Err(CliError::attest_error(format!(
                "certification public metadata registry url `{registry_url}` does not match expected `{expected}`"
            )));
        }
    }
    if metadata.generated_at == 0 {
        return Err(CliError::attest_error(
            "certification public metadata must include generatedAt".to_string(),
        ));
    }
    if metadata.expires_at <= metadata.generated_at {
        return Err(CliError::attest_error(
            "certification public metadata has expired or invalid expiry".to_string(),
        ));
    }
    if now >= metadata.expires_at {
        return Err(CliError::attest_error(
            "certification public metadata is stale".to_string(),
        ));
    }
    if !metadata.discovery_informational_only {
        return Err(CliError::attest_error(
            "certification public metadata must declare discovery as informational-only"
                .to_string(),
        ));
    }
    if metadata.supported_profiles.is_empty() {
        return Err(CliError::attest_error(
            "certification public metadata must advertise at least one supported profile"
                .to_string(),
        ));
    }
    for profile in &metadata.supported_profiles {
        if profile.criteria_profile.trim().is_empty() {
            return Err(CliError::attest_error(
                "certification public metadata contains an empty criteria profile".to_string(),
            ));
        }
        if !is_supported_evidence_profile(&profile.evidence_profile) {
            return Err(CliError::attest_error(format!(
                "certification public metadata contains unsupported evidence profile `{}`",
                profile.evidence_profile
            )));
        }
    }
    for path in [
        metadata.public_resolve_path_template.as_str(),
        metadata.public_search_path.as_str(),
        metadata.public_transparency_path.as_str(),
    ] {
        if !normalize_registry_url(path).starts_with(&registry_url) {
            return Err(CliError::attest_error(format!(
                "certification public metadata path `{path}` falls outside publisher registry url `{registry_url}`"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_certification_artifact_body(
    body: &CertificationCheckBody,
) -> Result<(), CliError> {
    if !is_supported_certification_schema(&body.schema) {
        return Err(CliError::attest_error(format!(
            "unsupported certification schema: expected {}, got {}",
            CERTIFICATION_SCHEMA, body.schema
        )));
    }
    if body.criteria_profile != CRITERIA_PROFILE_ALL_PASS_V1 {
        return Err(CliError::attest_error(format!(
            "unsupported certification criteria profile: {}",
            body.criteria_profile
        )));
    }
    require_non_empty_field(&body.target.tool_server_id, "target.toolServerId")?;
    validate_certification_evidence(&body.evidence)?;
    Ok(())
}
