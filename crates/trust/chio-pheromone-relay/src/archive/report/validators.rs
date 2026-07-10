use super::*;

pub(crate) fn validate_archive_restore_profile(
    profile: &RelayAlertAssuranceArchiveRestoreProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_archive_package_identity(&profile.profile_id, "restore profile id")?;
    if profile.max_package_count == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile max package count must be positive".to_string(),
        ));
    }
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile validity window is invalid".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_physical_archive_evidence(
    evidence: &RelayAlertAssurancePhysicalArchiveEvidence,
) -> Result<(), PheromoneRelayError> {
    if evidence.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    validate_archive_package_identity(&evidence.evidence_id, "evidence id")?;
    validate_archive_package_identity(&evidence.package_id, "package id")?;
    validate_archive_package_identity(&evidence.media_alias, "media alias")?;
    if !is_sha256_hex(&evidence.package_report_sha256)
        || !is_sha256_hex(&evidence.package_manifest_sha256)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence hashes are invalid".to_string(),
        ));
    }
    if evidence.sampled_member_count == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence must sample at least one member".to_string(),
        ));
    }
    for claim in &evidence.claims {
        validate_archive_safety_claim(claim)?;
    }
    Ok(())
}
pub(crate) fn validate_retention_handoff_profile(
    profile: &RelayAlertAssuranceRetentionHandoffProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff profile is not fresh".to_string(),
        ));
    }
    if profile.allowed_system_aliases.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff profile has no allowed aliases".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for alias in &profile.allowed_system_aliases {
        validate_archive_package_identity(alias, "retention system alias")?;
        if !seen.insert(alias) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate retention system alias".to_string(),
            ));
        }
    }
    Ok(())
}
pub(crate) fn validate_retention_handoff_evidence(
    evidence: &RelayAlertAssuranceRetentionHandoffEvidence,
) -> Result<(), PheromoneRelayError> {
    if evidence.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    validate_archive_package_identity(&evidence.evidence_id, "evidence id")?;
    validate_archive_package_identity(&evidence.package_id, "package id")?;
    validate_archive_package_identity(&evidence.target_system_alias, "target system alias")?;
    if !is_sha256_hex(&evidence.package_report_sha256) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff evidence package report hash is invalid".to_string(),
        ));
    }
    for claim in &evidence.claims {
        validate_archive_safety_claim(claim)?;
    }
    Ok(())
}
pub(crate) fn validate_external_retention_profile(
    profile: &RelayAlertAssuranceExternalRetentionProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile is not fresh".to_string(),
        ));
    }
    if profile.max_package_count == 0 || profile.max_evidence_age_ms == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile limits must be positive".to_string(),
        ));
    }
    if profile.min_sampled_members == 0 || profile.min_sample_coverage_basis_points == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention sample requirements must be positive".to_string(),
        ));
    }
    if profile.min_sample_coverage_basis_points > 10_000 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention sample coverage exceeds 100 percent".to_string(),
        ));
    }
    if profile.allowed_retention_system_aliases.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile has no allowed aliases".to_string(),
        ));
    }
    let mut seen_aliases = BTreeSet::new();
    for alias in &profile.allowed_retention_system_aliases {
        validate_external_retention_schema_token(alias, "external retention alias")?;
        if !seen_aliases.insert(alias) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate external retention alias".to_string(),
            ));
        }
    }
    let mut seen_recommendations = BTreeSet::new();
    for code in &profile.recommendation_codes {
        validate_external_retention_schema_token(code, "external retention recommendation")?;
        if !seen_recommendations.insert(code) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate external retention recommendation".to_string(),
            ));
        }
    }
    Ok(())
}
pub(crate) fn validate_external_retention_schema_token(
    value: &str,
    field: &str,
) -> Result<(), PheromoneRelayError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "{field} is invalid"
        )));
    }
    Ok(())
}

pub(crate) fn validate_archive_profile(
    profile: &RelayAlertAssuranceArchiveProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_local_kernel_id(profile.local_kernel_id.as_str())?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_closeout_profile(
    profile: &RelayAlertAssuranceCloseoutProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_local_kernel_id(profile.local_kernel_id.as_str())?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "closeout profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_archive_input_roots(
    profile_kernel_id: &str,
    trusted_kernel_id: &str,
    retention_kernel_id: &str,
) -> Result<(), PheromoneRelayError> {
    if profile_kernel_id != trusted_kernel_id || profile_kernel_id != retention_kernel_id {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive closeout inputs use mixed local kernel ids".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_local_kernel_id(value: &str) -> Result<(), PheromoneRelayError> {
    if value.trim().is_empty() || contains_secret_marker(value) || value.contains("://") {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "local kernel id is empty or unsafe".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_archive_candidates(
    candidates: &[RelayAlertAssuranceArchiveBundleCandidate],
) -> Result<(), PheromoneRelayError> {
    if candidates.is_empty() {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive review requires at least one bundle candidate".to_string(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut bundle_ids = BTreeSet::new();
    for candidate in candidates {
        validate_export_path(&candidate.bundle_path)?;
        if !paths.insert(candidate.bundle_path.as_str()) {
            return Err(PheromoneRelayError::AlertAssuranceInvalid(format!(
                "duplicate bundle path {}",
                candidate.bundle_path
            )));
        }
        if let Some(bundle) = &candidate.bundle {
            let bundle_id = bundle.manifest.body.bundle_id.as_str();
            if !bundle_ids.insert(bundle_id) {
                return Err(PheromoneRelayError::AlertAssuranceInvalid(format!(
                    "duplicate bundle id {bundle_id}"
                )));
            }
        }
    }
    Ok(())
}
