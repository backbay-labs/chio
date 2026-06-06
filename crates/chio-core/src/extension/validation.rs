use std::collections::{HashMap, HashSet};

use super::*;

pub fn validate_extension_inventory(
    inventory: &ChioExtensionInventory,
) -> Result<(), ExtensionContractError> {
    if inventory.schema != CHIO_EXTENSION_INVENTORY_SCHEMA {
        return Err(ExtensionContractError::UnsupportedSchema(
            inventory.schema.clone(),
        ));
    }
    ensure_non_empty(&inventory.chio_contract_version, "chio_contract_version")?;
    if inventory.canonical_truth.is_empty() {
        return Err(ExtensionContractError::MissingField("canonical_truth"));
    }
    if inventory.extension_points.is_empty() {
        return Err(ExtensionContractError::MissingField("extension_points"));
    }

    let mut ids = HashSet::new();
    for surface in &inventory.canonical_truth {
        ensure_non_empty(&surface.id, "canonical_truth.id")?;
        ensure_non_empty(&surface.name, "canonical_truth.name")?;
        ensure_non_empty(&surface.crate_path, "canonical_truth.crate_path")?;
        ensure_non_empty(&surface.notes, "canonical_truth.notes")?;
        if surface.artifact_schemas.is_empty() {
            return Err(ExtensionContractError::MissingField(
                "canonical_truth.artifact_schemas",
            ));
        }
        if surface.extensions_may_write {
            return Err(ExtensionContractError::InvalidGuardrail(format!(
                "canonical truth surface {} must not be writable by extensions",
                surface.id
            )));
        }
        if !ids.insert(surface.id.as_str()) {
            return Err(ExtensionContractError::DuplicateValue(surface.id.clone()));
        }
        ensure_unique_strings(
            &surface.artifact_schemas,
            "canonical_truth.artifact_schemas",
        )?;
    }

    for point in &inventory.extension_points {
        ensure_non_empty(&point.id, "extension_points.id")?;
        ensure_non_empty(&point.name, "extension_points.name")?;
        ensure_non_empty(&point.owner, "extension_points.owner")?;
        ensure_non_empty(&point.contract_path, "extension_points.contract_path")?;
        if !ids.insert(point.id.as_str()) {
            return Err(ExtensionContractError::DuplicateValue(point.id.clone()));
        }
        if point.allowed_isolations.is_empty() {
            return Err(ExtensionContractError::MissingField(
                "extension_points.allowed_isolations",
            ));
        }
        if point.allowed_evidence_modes.is_empty() {
            return Err(ExtensionContractError::MissingField(
                "extension_points.allowed_evidence_modes",
            ));
        }
        if point.allowed_privileges.is_empty() {
            return Err(ExtensionContractError::MissingField(
                "extension_points.allowed_privileges",
            ));
        }
        if point.official_component_ids.is_empty() {
            return Err(ExtensionContractError::MissingField(
                "extension_points.official_component_ids",
            ));
        }
        ensure_unique_copy_values(
            &point.allowed_isolations,
            "extension_points.allowed_isolations",
        )?;
        ensure_unique_copy_values(
            &point.allowed_evidence_modes,
            "extension_points.allowed_evidence_modes",
        )?;
        ensure_unique_copy_values(
            &point.allowed_privileges,
            "extension_points.allowed_privileges",
        )?;
        ensure_unique_strings(
            &point.official_component_ids,
            "extension_points.official_component_ids",
        )?;
        let admits_evidence = admits_evidence_capable_mode(&point.allowed_evidence_modes);
        if admits_evidence && !point.policy_activation_required {
            return Err(ExtensionContractError::InvalidGuardrail(format!(
                "extension point {} admits evidence-capable modes without local policy activation",
                point.id
            )));
        }
        if point.policy_activation_required && !admits_evidence {
            return Err(ExtensionContractError::InvalidGuardrail(format!(
                "extension point {} requires policy activation but admits no evidence-capable mode",
                point.id
            )));
        }
    }

    Ok(())
}

pub fn validate_official_stack_package(
    inventory: &ChioExtensionInventory,
    package: &OfficialStackPackage,
) -> Result<(), ExtensionContractError> {
    validate_extension_inventory(inventory)?;
    if package.schema != CHIO_OFFICIAL_STACK_SCHEMA {
        return Err(ExtensionContractError::UnsupportedSchema(
            package.schema.clone(),
        ));
    }
    ensure_non_empty(&package.package_id, "official_stack.package_id")?;
    ensure_non_empty(&package.version, "official_stack.version")?;
    ensure_non_empty(
        &package.chio_contract_version,
        "official_stack.chio_contract_version",
    )?;
    if package.components.is_empty() {
        return Err(ExtensionContractError::MissingField(
            "official_stack.components",
        ));
    }
    if package.profiles.is_empty() {
        return Err(ExtensionContractError::MissingField(
            "official_stack.profiles",
        ));
    }

    let points_by_id: HashMap<_, _> = inventory
        .extension_points
        .iter()
        .map(|point| (point.id.as_str(), point))
        .collect();

    let mut component_ids = HashSet::new();
    for component in &package.components {
        ensure_non_empty(&component.id, "official_stack.components.id")?;
        ensure_non_empty(&component.name, "official_stack.components.name")?;
        ensure_non_empty(
            &component.crate_path,
            "official_stack.components.crate_path",
        )?;
        if !component_ids.insert(component.id.as_str()) {
            return Err(ExtensionContractError::DuplicateValue(component.id.clone()));
        }
        if component.extension_point_ids.is_empty() {
            return Err(ExtensionContractError::MissingField(
                "official_stack.components.extension_point_ids",
            ));
        }
        ensure_unique_strings(
            &component.extension_point_ids,
            "official_stack.components.extension_point_ids",
        )?;
        for point_id in &component.extension_point_ids {
            if !points_by_id.contains_key(point_id.as_str()) {
                return Err(ExtensionContractError::UnknownReference(point_id.clone()));
            }
        }
    }

    let components_by_id: HashMap<_, _> = package
        .components
        .iter()
        .map(|component| (component.id.as_str(), component))
        .collect();
    for component in &package.components {
        for point_id in &component.extension_point_ids {
            let point = points_by_id
                .get(point_id.as_str())
                .ok_or_else(|| ExtensionContractError::UnknownReference(point_id.clone()))?;
            if !point
                .official_component_ids
                .iter()
                .any(|component_id| component_id == &component.id)
            {
                return Err(ExtensionContractError::UnknownReference(format!(
                    "{} -> {}",
                    component.id, point_id
                )));
            }
        }
    }
    let mut profile_ids = HashSet::new();
    for profile in &package.profiles {
        ensure_non_empty(&profile.id, "official_stack.profiles.id")?;
        ensure_non_empty(&profile.name, "official_stack.profiles.name")?;
        ensure_non_empty(&profile.description, "official_stack.profiles.description")?;
        if !profile_ids.insert(profile.id.as_str()) {
            return Err(ExtensionContractError::DuplicateValue(profile.id.clone()));
        }
        if profile.component_ids.is_empty() {
            return Err(ExtensionContractError::MissingField(
                "official_stack.profiles.component_ids",
            ));
        }
        ensure_unique_strings(
            &profile.component_ids,
            "official_stack.profiles.component_ids",
        )?;

        let mut covered_points = HashSet::new();
        for component_id in &profile.component_ids {
            let component = components_by_id
                .get(component_id.as_str())
                .ok_or_else(|| ExtensionContractError::UnknownReference(component_id.clone()))?;
            for point_id in &component.extension_point_ids {
                if !covered_points.insert(point_id.as_str()) {
                    return Err(ExtensionContractError::InvalidProfile(format!(
                        "profile {} selects multiple components for extension point {}",
                        profile.id, point_id
                    )));
                }
            }
        }
    }

    for point in &inventory.extension_points {
        for component_id in &point.official_component_ids {
            let component = components_by_id
                .get(component_id.as_str())
                .ok_or_else(|| ExtensionContractError::UnknownReference(component_id.clone()))?;
            if !component
                .extension_point_ids
                .iter()
                .any(|point_id| point_id == &point.id)
            {
                return Err(ExtensionContractError::UnknownReference(format!(
                    "{} -> {}",
                    point.id, component_id
                )));
            }
        }
    }

    Ok(())
}

pub fn validate_extension_manifest(
    manifest: &ChioExtensionManifest,
) -> Result<(), ExtensionContractError> {
    if manifest.schema != CHIO_EXTENSION_MANIFEST_SCHEMA {
        return Err(ExtensionContractError::UnsupportedSchema(
            manifest.schema.clone(),
        ));
    }
    ensure_non_empty(&manifest.extension_id, "extension_manifest.extension_id")?;
    ensure_non_empty(&manifest.display_name, "extension_manifest.display_name")?;
    ensure_non_empty(&manifest.version, "extension_manifest.version")?;
    ensure_non_empty(
        &manifest.extension_point_id,
        "extension_manifest.extension_point_id",
    )?;
    if manifest.capabilities.is_empty() {
        return Err(ExtensionContractError::MissingField(
            "extension_manifest.capabilities",
        ));
    }
    if manifest.supported_profiles.is_empty() {
        return Err(ExtensionContractError::MissingField(
            "extension_manifest.supported_profiles",
        ));
    }
    ensure_unique_strings(&manifest.capabilities, "extension_manifest.capabilities")?;
    ensure_unique_strings(
        &manifest.supported_profiles,
        "extension_manifest.supported_profiles",
    )?;

    ensure_non_empty(
        &manifest.compatibility.chio_contract_version,
        "extension_manifest.compatibility.chio_contract_version",
    )?;
    ensure_non_empty(
        &manifest.compatibility.official_stack_package_id,
        "extension_manifest.compatibility.official_stack_package_id",
    )?;
    if manifest.compatibility.supported_component_ids.is_empty() {
        return Err(ExtensionContractError::MissingField(
            "extension_manifest.compatibility.supported_component_ids",
        ));
    }
    if manifest.compatibility.supported_contract_schemas.is_empty() {
        return Err(ExtensionContractError::MissingField(
            "extension_manifest.compatibility.supported_contract_schemas",
        ));
    }
    ensure_unique_strings(
        &manifest.compatibility.supported_component_ids,
        "extension_manifest.compatibility.supported_component_ids",
    )?;
    ensure_unique_strings(
        &manifest.compatibility.supported_contract_schemas,
        "extension_manifest.compatibility.supported_contract_schemas",
    )?;
    if !manifest
        .compatibility
        .supported_contract_schemas
        .iter()
        .any(|schema| schema == CHIO_EXTENSION_MANIFEST_SCHEMA)
    {
        return Err(ExtensionContractError::InvalidGuardrail(
            "extension manifest compatibility must list chio.extension-manifest.v1".to_string(),
        ));
    }

    ensure_unique_copy_values(
        &manifest.runtime.allowed_privileges,
        "extension_manifest.runtime.allowed_privileges",
    )?;
    if manifest.runtime.allows_truth_mutation {
        return Err(ExtensionContractError::InvalidGuardrail(
            "extensions must not claim truth mutation".to_string(),
        ));
    }
    if manifest.runtime.allows_trust_widening {
        return Err(ExtensionContractError::InvalidGuardrail(
            "extensions must not claim trust widening".to_string(),
        ));
    }
    validate_evidence_runtime_guardrails(&manifest.runtime)?;

    Ok(())
}

pub fn validate_qualification_matrix(
    matrix: &ExtensionQualificationMatrix,
) -> Result<(), ExtensionContractError> {
    if matrix.schema != CHIO_EXTENSION_QUALIFICATION_MATRIX_SCHEMA {
        return Err(ExtensionContractError::UnsupportedSchema(
            matrix.schema.clone(),
        ));
    }
    ensure_non_empty(
        &matrix.official_stack_package_id,
        "qualification_matrix.official_stack_package_id",
    )?;
    ensure_non_empty(
        &matrix.chio_contract_version,
        "qualification_matrix.chio_contract_version",
    )?;
    if matrix.cases.is_empty() {
        return Err(ExtensionContractError::MissingField(
            "qualification_matrix.cases",
        ));
    }

    let mut case_ids = HashSet::new();
    for case in &matrix.cases {
        ensure_non_empty(&case.id, "qualification_matrix.case.id")?;
        ensure_non_empty(&case.name, "qualification_matrix.case.name")?;
        ensure_non_empty(
            &case.extension_point_id,
            "qualification_matrix.case.extension_point_id",
        )?;
        ensure_non_empty(
            &case.supported_component_id,
            "qualification_matrix.case.supported_component_id",
        )?;
        ensure_non_empty(
            &case.candidate_extension_id,
            "qualification_matrix.case.candidate_extension_id",
        )?;
        if !case_ids.insert(case.id.as_str()) {
            return Err(ExtensionContractError::DuplicateValue(case.id.clone()));
        }
        if case.invariants.is_empty() {
            return Err(ExtensionContractError::InvalidQualificationCase(format!(
                "case {} must record at least one invariant",
                case.id
            )));
        }
        ensure_unique_copy_values(&case.invariants, "qualification_matrix.case.invariants")?;
        ensure_unique_copy_values(
            &case.rejection_codes,
            "qualification_matrix.case.rejection_codes",
        )?;
        let must_have_rejections = case.expected_outcome == QualificationOutcome::FailClosed
            || case.observed_outcome == QualificationOutcome::FailClosed;
        if must_have_rejections && case.rejection_codes.is_empty() {
            return Err(ExtensionContractError::InvalidQualificationCase(format!(
                "case {} must record rejection codes for fail-closed outcomes",
                case.id
            )));
        }
        if !must_have_rejections && !case.rejection_codes.is_empty() {
            return Err(ExtensionContractError::InvalidQualificationCase(format!(
                "case {} recorded rejection codes for a passing outcome",
                case.id
            )));
        }
    }

    Ok(())
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), ExtensionContractError> {
    if value.trim().is_empty() {
        Err(ExtensionContractError::MissingField(field))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), ExtensionContractError> {
    let mut seen = HashSet::new();
    for value in values {
        ensure_non_empty(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(ExtensionContractError::DuplicateValue(value.clone()));
        }
    }
    Ok(())
}

fn ensure_unique_copy_values<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), ExtensionContractError>
where
    T: Eq + std::hash::Hash + Copy + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(ExtensionContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_evidence_runtime_guardrails(
    runtime: &ExtensionRuntimeEnvelope,
) -> Result<(), ExtensionContractError> {
    if runtime.evidence_mode == ExtensionEvidenceMode::None {
        return Ok(());
    }
    if !runtime.requires_subject_binding {
        return Err(ExtensionContractError::InvalidGuardrail(
            "evidence-capable extensions must require subject binding".to_string(),
        ));
    }
    if !runtime.requires_signer_verification {
        return Err(ExtensionContractError::InvalidGuardrail(
            "evidence-capable extensions must require signer verification".to_string(),
        ));
    }
    if !runtime.requires_freshness_check {
        return Err(ExtensionContractError::InvalidGuardrail(
            "evidence-capable extensions must require freshness checks".to_string(),
        ));
    }
    if !runtime.requires_local_policy_activation {
        return Err(ExtensionContractError::InvalidGuardrail(
            "evidence-capable extensions must require local policy activation".to_string(),
        ));
    }
    Ok(())
}

fn admits_evidence_capable_mode(modes: &[ExtensionEvidenceMode]) -> bool {
    modes
        .iter()
        .any(|mode| *mode != ExtensionEvidenceMode::None)
}
