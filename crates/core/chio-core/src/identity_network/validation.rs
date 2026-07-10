use std::collections::HashSet;

use super::error::IdentityNetworkContractError;
use super::types::{
    IdentityArtifactKind, IdentityCredentialFamily, IdentityDidMethod,
    IdentityInteropQualificationMatrix, PublicIdentityProfileArtifact,
    PublicWalletDirectoryEntryArtifact, PublicWalletRoutingManifestArtifact,
    CHIO_IDENTITY_INTEROP_QUALIFICATION_MATRIX_SCHEMA, CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
    CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA, CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA,
};
use super::validators::{
    contains_non_chio_method, ensure_non_empty, ensure_refs_present, ensure_required_transports,
    ensure_unique_copy_values, ensure_unique_strings, validate_https_url,
    validate_identity_artifact_reference, validate_identity_binding_policy,
    validate_wallet_directory_lookup_guardrails, validate_wallet_routing_guardrails,
};

const IDENTITY_NETWORK_REQUIRED_REQUIREMENTS: [&str; 5] =
    ["IDMAX-01", "IDMAX-02", "IDMAX-03", "IDMAX-04", "IDMAX-05"];

pub fn validate_public_identity_profile(
    profile: &PublicIdentityProfileArtifact,
) -> Result<(), IdentityNetworkContractError> {
    if profile.schema != CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA {
        return Err(IdentityNetworkContractError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    ensure_non_empty(&profile.profile_id, "profile_id")?;
    ensure_unique_copy_values(
        &profile.supported_subject_methods,
        "supported_subject_methods",
    )?;
    ensure_unique_copy_values(
        &profile.supported_issuer_methods,
        "supported_issuer_methods",
    )?;
    ensure_unique_copy_values(
        &profile.supported_credential_families,
        "supported_credential_families",
    )?;
    ensure_unique_copy_values(
        &profile.supported_proof_families,
        "supported_proof_families",
    )?;
    ensure_unique_copy_values(&profile.supported_transports, "supported_transports")?;
    ensure_refs_present(&profile.basis_refs, "basis_refs")?;
    validate_identity_binding_policy(&profile.binding_policy)?;

    if !profile
        .supported_subject_methods
        .contains(&IdentityDidMethod::DidChio)
        || !profile
            .supported_issuer_methods
            .contains(&IdentityDidMethod::DidChio)
    {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must retain did:chio provenance in both subject and issuer support".to_string(),
        ));
    }
    if !contains_non_chio_method(&profile.supported_subject_methods)
        && !contains_non_chio_method(&profile.supported_issuer_methods)
    {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must support at least one non-did:chio method".to_string(),
        ));
    }
    if !profile
        .supported_credential_families
        .contains(&IdentityCredentialFamily::ChioAgentPassportJson)
    {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must retain chio-agent-passport+json compatibility"
                .to_string(),
        ));
    }
    if !profile.supported_credential_families.iter().any(|family| {
        matches!(
            family,
            IdentityCredentialFamily::DcSdJwt | IdentityCredentialFamily::JwtVcJson
        )
    }) {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must advertise at least one portable VC family".to_string(),
        ));
    }
    ensure_required_transports(&profile.supported_transports, "supported_transports")?;

    let mut required_kinds = HashSet::from([
        IdentityArtifactKind::PortableTrustProfile,
        IdentityArtifactKind::Oid4vciIssuerMetadata,
        IdentityArtifactKind::Oid4vpVerifierMetadata,
    ]);
    for reference in &profile.basis_refs {
        validate_identity_artifact_reference(reference)?;
        required_kinds.remove(&reference.kind);
    }
    if !required_kinds.is_empty() {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must reference portable trust, OID4VCI, and OID4VP basis artifacts".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_public_wallet_directory_entry(
    entry: &PublicWalletDirectoryEntryArtifact,
) -> Result<(), IdentityNetworkContractError> {
    if entry.schema != CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA {
        return Err(IdentityNetworkContractError::UnsupportedSchema(
            entry.schema.clone(),
        ));
    }
    ensure_non_empty(&entry.entry_id, "entry_id")?;
    ensure_non_empty(&entry.directory_operator_id, "directory_operator_id")?;
    ensure_non_empty(&entry.wallet_id, "wallet_id")?;
    ensure_unique_copy_values(
        &entry.supported_subject_methods,
        "supported_subject_methods",
    )?;
    ensure_unique_copy_values(&entry.supported_issuer_methods, "supported_issuer_methods")?;
    ensure_unique_copy_values(
        &entry.supported_credential_families,
        "supported_credential_families",
    )?;
    ensure_unique_copy_values(&entry.supported_proof_families, "supported_proof_families")?;
    validate_identity_artifact_reference(&entry.discovery_ref)?;
    validate_identity_artifact_reference(&entry.profile_ref)?;
    validate_wallet_directory_lookup_guardrails(&entry.lookup_guardrails)?;
    validate_https_url(&entry.metadata_url, "metadata_url")?;
    validate_https_url(&entry.request_uri_prefix, "request_uri_prefix")?;

    if entry.discovery_ref.kind != IdentityArtifactKind::PublicVerifierDiscovery {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory discovery_ref must point to public verifier discovery".to_string(),
        ));
    }
    if entry.profile_ref.kind != IdentityArtifactKind::PublicIdentityProfile {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory profile_ref must point to a public identity profile".to_string(),
        ));
    }
    if !contains_non_chio_method(&entry.supported_subject_methods)
        || !contains_non_chio_method(&entry.supported_issuer_methods)
    {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must advertise at least one broader subject and issuer method".to_string(),
        ));
    }
    if !entry.supported_credential_families.iter().any(|family| {
        matches!(
            family,
            IdentityCredentialFamily::DcSdJwt | IdentityCredentialFamily::JwtVcJson
        )
    }) {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must advertise at least one portable credential family"
                .to_string(),
        ));
    }

    Ok(())
}

pub fn validate_public_wallet_routing_manifest(
    manifest: &PublicWalletRoutingManifestArtifact,
) -> Result<(), IdentityNetworkContractError> {
    if manifest.schema != CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA {
        return Err(IdentityNetworkContractError::UnsupportedSchema(
            manifest.schema.clone(),
        ));
    }
    ensure_non_empty(&manifest.route_id, "route_id")?;
    ensure_non_empty(&manifest.verifier_id, "verifier_id")?;
    validate_identity_artifact_reference(&manifest.directory_entry_ref)?;
    validate_https_url(&manifest.verifier_id, "verifier_id")?;
    validate_https_url(&manifest.response_uri_prefix, "response_uri_prefix")?;
    validate_https_url(&manifest.relay_url, "relay_url")?;
    ensure_required_transports(&manifest.transport_modes, "transport_modes")?;
    validate_wallet_routing_guardrails(&manifest.routing_guardrails)?;

    if manifest.directory_entry_ref.kind != IdentityArtifactKind::PublicWalletDirectoryEntry {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifest directory_entry_ref must point to a wallet directory entry"
                .to_string(),
        ));
    }
    if !manifest.requires_signed_request_object {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must require signed request objects".to_string(),
        ));
    }
    if !manifest.requires_replay_anchors {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must require replay anchors".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_identity_interop_qualification_matrix(
    matrix: &IdentityInteropQualificationMatrix,
) -> Result<(), IdentityNetworkContractError> {
    if matrix.schema != CHIO_IDENTITY_INTEROP_QUALIFICATION_MATRIX_SCHEMA {
        return Err(IdentityNetworkContractError::UnsupportedSchema(
            matrix.schema.clone(),
        ));
    }
    validate_identity_artifact_reference(&matrix.profile_ref)?;
    validate_identity_artifact_reference(&matrix.directory_entry_ref)?;
    validate_identity_artifact_reference(&matrix.routing_manifest_ref)?;
    if matrix.profile_ref.kind != IdentityArtifactKind::PublicIdentityProfile {
        return Err(IdentityNetworkContractError::InvalidQualificationCase(
            "qualification matrix profile_ref must point to a public identity profile".to_string(),
        ));
    }
    if matrix.directory_entry_ref.kind != IdentityArtifactKind::PublicWalletDirectoryEntry {
        return Err(IdentityNetworkContractError::InvalidQualificationCase(
            "qualification matrix directory_entry_ref must point to a wallet directory entry"
                .to_string(),
        ));
    }
    if matrix.routing_manifest_ref.kind != IdentityArtifactKind::PublicWalletRoutingManifest {
        return Err(IdentityNetworkContractError::InvalidQualificationCase(
            "qualification matrix routing_manifest_ref must point to a wallet routing manifest"
                .to_string(),
        ));
    }
    if matrix.cases.is_empty() {
        return Err(IdentityNetworkContractError::MissingField("cases"));
    }

    let mut case_ids = HashSet::new();
    let mut covered_requirements = HashSet::new();
    for case in &matrix.cases {
        ensure_non_empty(&case.id, "case.id")?;
        ensure_non_empty(&case.name, "case.name")?;
        if !case_ids.insert(case.id.as_str()) {
            return Err(IdentityNetworkContractError::DuplicateValue(format!(
                "case.id:{}",
                case.id
            )));
        }
        if case.expected_outcome != case.observed_outcome {
            return Err(IdentityNetworkContractError::InvalidQualificationCase(
                format!(
                    "case `{}` expected and observed outcomes must match",
                    case.id
                ),
            ));
        }
        ensure_unique_strings(&case.requirement_ids, "case.requirement_ids")?;
        for requirement_id in &case.requirement_ids {
            covered_requirements.insert(requirement_id.as_str());
        }
        for note in &case.notes {
            ensure_non_empty(note, "case.notes")?;
        }
    }

    for requirement_id in IDENTITY_NETWORK_REQUIRED_REQUIREMENTS {
        if !covered_requirements.contains(requirement_id) {
            return Err(IdentityNetworkContractError::InvalidQualificationCase(
                format!("qualification matrix must cover `{requirement_id}`"),
            ));
        }
    }

    Ok(())
}
