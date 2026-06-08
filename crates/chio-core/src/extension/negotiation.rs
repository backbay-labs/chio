use std::collections::{HashMap, HashSet};

use super::*;

pub fn negotiate_extension(
    inventory: &ChioExtensionInventory,
    package: &OfficialStackPackage,
    manifest: &ChioExtensionManifest,
) -> ExtensionNegotiationReport {
    let mut reasons = Vec::new();

    if let Err(error) = validate_extension_inventory(inventory) {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::MalformedInventory,
            error.to_string(),
        ));
    }
    if let Err(error) = validate_official_stack_package(inventory, package) {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::MalformedOfficialStack,
            error.to_string(),
        ));
    }
    if let Err(error) = validate_extension_manifest(manifest) {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::MalformedManifest,
            error.to_string(),
        ));
    }
    if !reasons.is_empty() {
        return ExtensionNegotiationReport {
            schema: CHIO_EXTENSION_NEGOTIATION_SCHEMA.to_string(),
            official_stack_package_id: package.package_id.clone(),
            extension_id: manifest.extension_id.clone(),
            extension_point_id: manifest.extension_point_id.clone(),
            outcome: ExtensionNegotiationOutcome::Rejected,
            reasons,
        };
    }

    let points_by_id: HashMap<_, _> = inventory
        .extension_points
        .iter()
        .map(|point| (point.id.as_str(), point))
        .collect();
    let profiles: HashSet<_> = package
        .profiles
        .iter()
        .map(|profile| profile.id.as_str())
        .collect();
    let components: HashSet<_> = package
        .components
        .iter()
        .map(|component| component.id.as_str())
        .collect();

    if package.package_id != manifest.compatibility.official_stack_package_id {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::UnsupportedOfficialStack,
            format!(
                "manifest targets {}, expected {}",
                manifest.compatibility.official_stack_package_id, package.package_id
            ),
        ));
    }
    if package.chio_contract_version != manifest.compatibility.chio_contract_version {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::UnsupportedChioContract,
            format!(
                "manifest targets Chio {}, expected {}",
                manifest.compatibility.chio_contract_version, package.chio_contract_version
            ),
        ));
    }

    let Some(point) = points_by_id.get(manifest.extension_point_id.as_str()) else {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::UnknownExtensionPoint,
            format!(
                "extension point {} is not registered",
                manifest.extension_point_id
            ),
        ));
        return ExtensionNegotiationReport {
            schema: CHIO_EXTENSION_NEGOTIATION_SCHEMA.to_string(),
            official_stack_package_id: package.package_id.clone(),
            extension_id: manifest.extension_id.clone(),
            extension_point_id: manifest.extension_point_id.clone(),
            outcome: ExtensionNegotiationOutcome::Rejected,
            reasons,
        };
    };

    if manifest.distribution != ExtensionDistribution::OfficialFirstParty
        && !point.custom_implementations_allowed
    {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::OfficialOnlyPoint,
            format!(
                "extension point {} is reserved for official components",
                point.id
            ),
        ));
    }
    if manifest.distribution != ExtensionDistribution::OfficialFirstParty
        && point.stability == ExtensionStability::Internal
    {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::InternalOnlyPoint,
            format!("extension point {} is internal-only", point.id),
        ));
    }

    for profile_id in &manifest.supported_profiles {
        if !profiles.contains(profile_id.as_str()) {
            reasons.push(negotiation_rejection(
                ExtensionNegotiationRejectionCode::UnsupportedProfile,
                format!(
                    "profile {} is not part of {}",
                    profile_id, package.package_id
                ),
            ));
        }
    }
    for component_id in &manifest.compatibility.supported_component_ids {
        if !components.contains(component_id.as_str()) {
            reasons.push(negotiation_rejection(
                ExtensionNegotiationRejectionCode::UnsupportedComponent,
                format!(
                    "component {} is not part of {}",
                    component_id, package.package_id
                ),
            ));
        }
    }
    if !manifest
        .compatibility
        .supported_component_ids
        .iter()
        .any(|component_id| {
            point
                .official_component_ids
                .iter()
                .any(|official| official == component_id)
        })
    {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::UnsupportedComponent,
            format!(
                "extension {} does not target an official component for point {}",
                manifest.extension_id, point.id
            ),
        ));
    }

    if !point
        .allowed_isolations
        .contains(&manifest.runtime.isolation)
    {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::UnsupportedIsolation,
            format!(
                "extension point {} does not allow {:?} isolation",
                point.id, manifest.runtime.isolation
            ),
        ));
    }
    if !point
        .allowed_evidence_modes
        .contains(&manifest.runtime.evidence_mode)
    {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::UnsupportedEvidenceMode,
            format!(
                "extension point {} does not allow {:?} evidence mode",
                point.id, manifest.runtime.evidence_mode
            ),
        ));
    }
    for privilege in &manifest.runtime.allowed_privileges {
        if !point.allowed_privileges.contains(privilege) {
            reasons.push(negotiation_rejection(
                ExtensionNegotiationRejectionCode::UnsupportedPrivilege,
                format!(
                    "extension point {} does not allow {:?}",
                    point.id, privilege
                ),
            ));
        }
    }

    if point.policy_activation_required && !manifest.runtime.requires_local_policy_activation {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::LocalPolicyActivationRequired,
            format!(
                "extension point {} requires local policy activation",
                point.id
            ),
        ));
    }
    if manifest.runtime.evidence_mode != ExtensionEvidenceMode::None
        && !manifest.runtime.requires_subject_binding
    {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::MissingSubjectBinding,
            format!(
                "extension {} omitted subject binding",
                manifest.extension_id
            ),
        ));
    }
    if manifest.runtime.evidence_mode != ExtensionEvidenceMode::None
        && !manifest.runtime.requires_signer_verification
    {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::MissingSignerVerification,
            format!(
                "extension {} omitted signer verification",
                manifest.extension_id
            ),
        ));
    }
    if manifest.runtime.evidence_mode != ExtensionEvidenceMode::None
        && !manifest.runtime.requires_freshness_check
    {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::MissingFreshnessCheck,
            format!(
                "extension {} omitted freshness checks",
                manifest.extension_id
            ),
        ));
    }
    if manifest.runtime.allows_truth_mutation {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::TruthMutationNotAllowed,
            format!("extension {} claims truth mutation", manifest.extension_id),
        ));
    }
    if manifest.runtime.allows_trust_widening {
        reasons.push(negotiation_rejection(
            ExtensionNegotiationRejectionCode::TrustWideningNotAllowed,
            format!("extension {} claims trust widening", manifest.extension_id),
        ));
    }

    ExtensionNegotiationReport {
        schema: CHIO_EXTENSION_NEGOTIATION_SCHEMA.to_string(),
        official_stack_package_id: package.package_id.clone(),
        extension_id: manifest.extension_id.clone(),
        extension_point_id: manifest.extension_point_id.clone(),
        outcome: if reasons.is_empty() {
            ExtensionNegotiationOutcome::Accepted
        } else {
            ExtensionNegotiationOutcome::Rejected
        },
        reasons,
    }
}

fn negotiation_rejection(
    code: ExtensionNegotiationRejectionCode,
    detail: impl Into<String>,
) -> ExtensionNegotiationRejection {
    ExtensionNegotiationRejection {
        code,
        detail: detail.into(),
    }
}
