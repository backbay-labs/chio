//! Chio extension and official-stack contract types.
//!
//! These types freeze which Chio surfaces are canonical truth, which seams are
//! replaceable, how custom implementations negotiate against the official
//! stack, and which fail-closed conditions must be preserved.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

pub const CHIO_EXTENSION_INVENTORY_SCHEMA: &str = "chio.extension-inventory.v1";
pub const CHIO_EXTENSION_MANIFEST_SCHEMA: &str = "chio.extension-manifest.v1";
pub const CHIO_EXTENSION_NEGOTIATION_SCHEMA: &str = "chio.extension-negotiation.v1";
pub const CHIO_OFFICIAL_STACK_SCHEMA: &str = "chio.official-stack.v1";
pub const CHIO_EXTENSION_QUALIFICATION_MATRIX_SCHEMA: &str =
    "chio.extension-qualification-matrix.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalContractKind {
    Capability,
    Receipt,
    Policy,
    ArtifactFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionPointKind {
    Authority,
    Store,
    ToolServerConnection,
    ResourceProvider,
    PromptProvider,
    Adapter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionStability {
    Supported,
    Experimental,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionIsolation {
    InProcess,
    Subprocess,
    RemoteService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionEvidenceMode {
    None,
    ImportOnly,
    DispatchOnly,
    ImportAndDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionPrivilege {
    FilesystemRead,
    FilesystemWrite,
    NetworkEgress,
    ProcessExecution,
    OperatorSecrets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionDistribution {
    OfficialFirstParty,
    CustomFirstParty,
    ThirdPartyCustom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficialImplementationSource {
    FirstParty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionNegotiationOutcome {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationMode {
    OfficialToOfficial,
    OfficialToCustom,
    CustomToOfficial,
    CustomToCustom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationOutcome {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationInvariant {
    PreservesCanonicalTruth,
    RequiresLocalPolicyActivation,
    RejectsVersionMismatch,
    RejectsPrivilegeEscalation,
    RejectsTruthMutation,
    RejectsUnsignedEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionNegotiationRejectionCode {
    MalformedInventory,
    MalformedOfficialStack,
    MalformedManifest,
    UnknownExtensionPoint,
    UnsupportedOfficialStack,
    UnsupportedChioContract,
    UnsupportedProfile,
    UnsupportedComponent,
    UnsupportedIsolation,
    UnsupportedEvidenceMode,
    UnsupportedPrivilege,
    OfficialOnlyPoint,
    InternalOnlyPoint,
    LocalPolicyActivationRequired,
    MissingSubjectBinding,
    MissingSignerVerification,
    MissingFreshnessCheck,
    TruthMutationNotAllowed,
    TrustWideningNotAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTruthSurface {
    pub id: String,
    pub name: String,
    pub crate_path: String,
    pub contract_kind: CanonicalContractKind,
    pub artifact_schemas: Vec<String>,
    pub notes: String,
    pub extensions_may_write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioExtensionPoint {
    pub id: String,
    pub name: String,
    pub point_kind: ExtensionPointKind,
    pub owner: String,
    pub contract_path: String,
    pub stability: ExtensionStability,
    pub allowed_isolations: Vec<ExtensionIsolation>,
    pub allowed_evidence_modes: Vec<ExtensionEvidenceMode>,
    pub allowed_privileges: Vec<ExtensionPrivilege>,
    pub custom_implementations_allowed: bool,
    pub policy_activation_required: bool,
    pub official_component_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioExtensionInventory {
    pub schema: String,
    pub chio_contract_version: String,
    pub canonical_truth: Vec<CanonicalTruthSurface>,
    pub extension_points: Vec<ChioExtensionPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialStackComponent {
    pub id: String,
    pub name: String,
    pub extension_point_ids: Vec<String>,
    pub crate_path: String,
    pub implementation_source: OfficialImplementationSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialStackProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub component_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialStackPackage {
    pub schema: String,
    pub package_id: String,
    pub version: String,
    pub chio_contract_version: String,
    pub components: Vec<OfficialStackComponent>,
    pub profiles: Vec<OfficialStackProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionCompatibility {
    pub chio_contract_version: String,
    pub official_stack_package_id: String,
    pub supported_component_ids: Vec<String>,
    pub supported_contract_schemas: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionRuntimeEnvelope {
    pub isolation: ExtensionIsolation,
    pub allowed_privileges: Vec<ExtensionPrivilege>,
    pub evidence_mode: ExtensionEvidenceMode,
    pub requires_subject_binding: bool,
    pub requires_signer_verification: bool,
    pub requires_freshness_check: bool,
    pub requires_local_policy_activation: bool,
    pub allows_truth_mutation: bool,
    pub allows_trust_widening: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioExtensionManifest {
    pub schema: String,
    pub extension_id: String,
    pub display_name: String,
    pub version: String,
    pub distribution: ExtensionDistribution,
    pub extension_point_id: String,
    pub capabilities: Vec<String>,
    pub supported_profiles: Vec<String>,
    pub compatibility: ExtensionCompatibility,
    pub runtime: ExtensionRuntimeEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionNegotiationRejection {
    pub code: ExtensionNegotiationRejectionCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionNegotiationReport {
    pub schema: String,
    pub official_stack_package_id: String,
    pub extension_id: String,
    pub extension_point_id: String,
    pub outcome: ExtensionNegotiationOutcome,
    pub reasons: Vec<ExtensionNegotiationRejection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionQualificationCase {
    pub id: String,
    pub name: String,
    pub extension_point_id: String,
    pub supported_component_id: String,
    pub candidate_extension_id: String,
    pub mode: QualificationMode,
    pub expected_outcome: QualificationOutcome,
    pub observed_outcome: QualificationOutcome,
    pub rejection_codes: Vec<ExtensionNegotiationRejectionCode>,
    pub invariants: Vec<QualificationInvariant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionQualificationMatrix {
    pub schema: String,
    pub official_stack_package_id: String,
    pub chio_contract_version: String,
    pub cases: Vec<ExtensionQualificationCase>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtensionContractError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("duplicate id or value: {0}")]
    DuplicateValue(String),

    #[error("unknown reference: {0}")]
    UnknownReference(String),

    #[error("invalid guardrail: {0}")]
    InvalidGuardrail(String),

    #[error("invalid profile: {0}")]
    InvalidProfile(String),

    #[error("invalid qualification case: {0}")]
    InvalidQualificationCase(String),
}

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
        if point.policy_activation_required
            && point.allowed_evidence_modes == [ExtensionEvidenceMode::None]
        {
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
            if !components_by_id.contains_key(component_id.as_str()) {
                return Err(ExtensionContractError::UnknownReference(
                    component_id.clone(),
                ));
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
    if manifest.runtime.evidence_mode != ExtensionEvidenceMode::None {
        if !manifest.runtime.requires_subject_binding {
            return Err(ExtensionContractError::InvalidGuardrail(
                "evidence-capable extensions must require subject binding".to_string(),
            ));
        }
        if !manifest.runtime.requires_signer_verification {
            return Err(ExtensionContractError::InvalidGuardrail(
                "evidence-capable extensions must require signer verification".to_string(),
            ));
        }
        if !manifest.runtime.requires_freshness_check {
            return Err(ExtensionContractError::InvalidGuardrail(
                "evidence-capable extensions must require freshness checks".to_string(),
            ));
        }
        if !manifest.runtime.requires_local_policy_activation {
            return Err(ExtensionContractError::InvalidGuardrail(
                "evidence-capable extensions must require local policy activation".to_string(),
            ));
        }
    }

    Ok(())
}

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

fn negotiation_rejection(
    code: ExtensionNegotiationRejectionCode,
    detail: impl Into<String>,
) -> ExtensionNegotiationRejection {
    ExtensionNegotiationRejection {
        code,
        detail: detail.into(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_inventory() -> ChioExtensionInventory {
        ChioExtensionInventory {
            schema: CHIO_EXTENSION_INVENTORY_SCHEMA.to_string(),
            chio_contract_version: "2.0".to_string(),
            canonical_truth: vec![CanonicalTruthSurface {
                id: "chio.canonical.receipt".to_string(),
                name: "Signed receipts and checkpoints".to_string(),
                crate_path: "crates/chio-core/src/receipt.rs".to_string(),
                contract_kind: CanonicalContractKind::Receipt,
                artifact_schemas: vec!["chio.receipt.v1".to_string(), "chio.checkpoint.v1".to_string()],
                notes: "Extensions may project evidence around receipts, but they must not mutate signed receipt or checkpoint truth."
                    .to_string(),
                extensions_may_write: false,
            }],
            extension_points: vec![
                ChioExtensionPoint {
                    id: "chio.kernel.receipt_store".to_string(),
                    name: "Receipt store backend".to_string(),
                    point_kind: ExtensionPointKind::Store,
                    owner: "kernel".to_string(),
                    contract_path: "crates/chio-kernel/src/receipt_store.rs::ReceiptStore".to_string(),
                    stability: ExtensionStability::Supported,
                    allowed_isolations: vec![
                        ExtensionIsolation::InProcess,
                        ExtensionIsolation::RemoteService,
                    ],
                    allowed_evidence_modes: vec![ExtensionEvidenceMode::None],
                    allowed_privileges: vec![
                        ExtensionPrivilege::FilesystemRead,
                        ExtensionPrivilege::FilesystemWrite,
                        ExtensionPrivilege::NetworkEgress,
                    ],
                    custom_implementations_allowed: true,
                    policy_activation_required: false,
                    official_component_ids: vec![
                        "chio.sqlite-receipt-store".to_string(),
                        "chio.remote-receipt-store".to_string(),
                    ],
                },
                ChioExtensionPoint {
                    id: "chio.kernel.tool_server_connection".to_string(),
                    name: "Tool server connection".to_string(),
                    point_kind: ExtensionPointKind::ToolServerConnection,
                    owner: "kernel".to_string(),
                    contract_path: "crates/chio-kernel/src/runtime.rs::ToolServerConnection".to_string(),
                    stability: ExtensionStability::Supported,
                    allowed_isolations: vec![
                        ExtensionIsolation::InProcess,
                        ExtensionIsolation::Subprocess,
                        ExtensionIsolation::RemoteService,
                    ],
                    allowed_evidence_modes: vec![
                        ExtensionEvidenceMode::None,
                        ExtensionEvidenceMode::ImportOnly,
                        ExtensionEvidenceMode::DispatchOnly,
                        ExtensionEvidenceMode::ImportAndDispatch,
                    ],
                    allowed_privileges: vec![
                        ExtensionPrivilege::FilesystemRead,
                        ExtensionPrivilege::NetworkEgress,
                        ExtensionPrivilege::ProcessExecution,
                        ExtensionPrivilege::OperatorSecrets,
                    ],
                    custom_implementations_allowed: true,
                    policy_activation_required: true,
                    official_component_ids: vec!["chio.native-chio-service".to_string()],
                },
            ],
        }
    }

    fn sample_official_stack() -> OfficialStackPackage {
        OfficialStackPackage {
            schema: CHIO_OFFICIAL_STACK_SCHEMA.to_string(),
            package_id: "chio.official-stack".to_string(),
            version: "0.1.0".to_string(),
            chio_contract_version: "2.0".to_string(),
            components: vec![
                OfficialStackComponent {
                    id: "chio.sqlite-receipt-store".to_string(),
                    name: "SQLite receipt store".to_string(),
                    extension_point_ids: vec!["chio.kernel.receipt_store".to_string()],
                    crate_path: "crates/chio-store-sqlite/src/receipt_store.rs::SqliteReceiptStore"
                        .to_string(),
                    implementation_source: OfficialImplementationSource::FirstParty,
                },
                OfficialStackComponent {
                    id: "chio.remote-receipt-store".to_string(),
                    name: "Remote receipt store".to_string(),
                    extension_point_ids: vec!["chio.kernel.receipt_store".to_string()],
                    crate_path:
                        "crates/chio-control-plane/src/trust_control.rs::RemoteReceiptStore"
                            .to_string(),
                    implementation_source: OfficialImplementationSource::FirstParty,
                },
                OfficialStackComponent {
                    id: "chio.native-chio-service".to_string(),
                    name: "Native Chio service".to_string(),
                    extension_point_ids: vec!["chio.kernel.tool_server_connection".to_string()],
                    crate_path: "crates/chio-mcp-adapter/src/native.rs::NativeChioService"
                        .to_string(),
                    implementation_source: OfficialImplementationSource::FirstParty,
                },
            ],
            profiles: vec![
                OfficialStackProfile {
                    id: "local_default".to_string(),
                    name: "Local default".to_string(),
                    description: "Local stores with native Chio service".to_string(),
                    component_ids: vec![
                        "chio.sqlite-receipt-store".to_string(),
                        "chio.native-chio-service".to_string(),
                    ],
                },
                OfficialStackProfile {
                    id: "shared_control_plane".to_string(),
                    name: "Shared control plane".to_string(),
                    description: "Remote store components with first-party service adapters"
                        .to_string(),
                    component_ids: vec![
                        "chio.remote-receipt-store".to_string(),
                        "chio.native-chio-service".to_string(),
                    ],
                },
            ],
        }
    }

    fn sample_manifest() -> ChioExtensionManifest {
        ChioExtensionManifest {
            schema: CHIO_EXTENSION_MANIFEST_SCHEMA.to_string(),
            extension_id: "sample.pg-receipt-store".to_string(),
            display_name: "Sample Postgres Receipt Store".to_string(),
            version: "1.0.0".to_string(),
            distribution: ExtensionDistribution::ThirdPartyCustom,
            extension_point_id: "chio.kernel.receipt_store".to_string(),
            capabilities: vec![
                "receipt_append".to_string(),
                "receipt_query".to_string(),
                "checkpoint_replay_safe".to_string(),
            ],
            supported_profiles: vec!["shared_control_plane".to_string()],
            compatibility: ExtensionCompatibility {
                chio_contract_version: "2.0".to_string(),
                official_stack_package_id: "chio.official-stack".to_string(),
                supported_component_ids: vec!["chio.remote-receipt-store".to_string()],
                supported_contract_schemas: vec![
                    CHIO_EXTENSION_MANIFEST_SCHEMA.to_string(),
                    "chio.receipt.v1".to_string(),
                    "chio.checkpoint.v1".to_string(),
                ],
            },
            runtime: ExtensionRuntimeEnvelope {
                isolation: ExtensionIsolation::RemoteService,
                allowed_privileges: vec![
                    ExtensionPrivilege::NetworkEgress,
                    ExtensionPrivilege::FilesystemRead,
                ],
                evidence_mode: ExtensionEvidenceMode::None,
                requires_subject_binding: false,
                requires_signer_verification: false,
                requires_freshness_check: false,
                requires_local_policy_activation: false,
                allows_truth_mutation: false,
                allows_trust_widening: false,
            },
        }
    }

    fn sample_qualification_matrix() -> ExtensionQualificationMatrix {
        ExtensionQualificationMatrix {
            schema: CHIO_EXTENSION_QUALIFICATION_MATRIX_SCHEMA.to_string(),
            official_stack_package_id: "chio.official-stack".to_string(),
            chio_contract_version: "2.0".to_string(),
            cases: vec![ExtensionQualificationCase {
                id: "tool-server-pass".to_string(),
                name: "Supported tool-server extension remains bounded".to_string(),
                extension_point_id: "chio.kernel.tool_server_connection".to_string(),
                supported_component_id: "chio.native-chio-service".to_string(),
                candidate_extension_id: "sample.tool-server".to_string(),
                mode: QualificationMode::OfficialToCustom,
                expected_outcome: QualificationOutcome::Pass,
                observed_outcome: QualificationOutcome::Pass,
                rejection_codes: vec![],
                invariants: vec![
                    QualificationInvariant::PreservesCanonicalTruth,
                    QualificationInvariant::RequiresLocalPolicyActivation,
                ],
            }],
        }
    }

    fn rejection_codes(
        report: &ExtensionNegotiationReport,
    ) -> HashSet<ExtensionNegotiationRejectionCode> {
        report.reasons.iter().map(|reason| reason.code).collect()
    }

    #[test]
    fn rejects_duplicate_inventory_ids() {
        let mut inventory = sample_inventory();
        inventory
            .extension_points
            .push(inventory.extension_points[0].clone());
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::DuplicateValue(_))
        ));
    }

    #[test]
    fn inventory_validation_rejects_remaining_shape_and_guardrail_errors() {
        let mut inventory = sample_inventory();
        inventory.schema = "chio.extension-inventory.v9".to_string();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::UnsupportedSchema(_))
        ));

        let mut inventory = sample_inventory();
        inventory.chio_contract_version.clear();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::MissingField(
                "chio_contract_version"
            ))
        ));

        let mut inventory = sample_inventory();
        inventory.canonical_truth.clear();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::MissingField("canonical_truth"))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points.clear();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::MissingField("extension_points"))
        ));

        let mut inventory = sample_inventory();
        inventory.canonical_truth[0].artifact_schemas.clear();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::MissingField(
                "canonical_truth.artifact_schemas"
            ))
        ));

        let mut inventory = sample_inventory();
        inventory.canonical_truth[0].extensions_may_write = true;
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));

        let mut inventory = sample_inventory();
        inventory.canonical_truth[0]
            .artifact_schemas
            .push("chio.receipt.v1".to_string());
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0].allowed_isolations.clear();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::MissingField(
                "extension_points.allowed_isolations"
            ))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0].allowed_evidence_modes.clear();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::MissingField(
                "extension_points.allowed_evidence_modes"
            ))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0].allowed_privileges.clear();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::MissingField(
                "extension_points.allowed_privileges"
            ))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0].official_component_ids.clear();
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::MissingField(
                "extension_points.official_component_ids"
            ))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0]
            .allowed_isolations
            .push(ExtensionIsolation::InProcess);
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0]
            .allowed_evidence_modes
            .push(ExtensionEvidenceMode::None);
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0]
            .allowed_privileges
            .push(ExtensionPrivilege::FilesystemRead);
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0]
            .official_component_ids
            .push("chio.sqlite-receipt-store".to_string());
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[1].allowed_evidence_modes = vec![ExtensionEvidenceMode::None];
        assert!(matches!(
            validate_extension_inventory(&inventory),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));
    }

    #[test]
    fn accepts_supported_custom_store_extension() {
        let report = negotiate_extension(
            &sample_inventory(),
            &sample_official_stack(),
            &sample_manifest(),
        );
        assert_eq!(report.outcome, ExtensionNegotiationOutcome::Accepted);
        assert!(report.reasons.is_empty());
    }

    #[test]
    fn official_stack_validation_rejects_remaining_reference_and_profile_errors() {
        let inventory = sample_inventory();

        let mut package = sample_official_stack();
        package.schema = "chio.official-stack.v9".to_string();
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::UnsupportedSchema(_))
        ));

        let mut package = sample_official_stack();
        package.package_id.clear();
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::MissingField(
                "official_stack.package_id"
            ))
        ));

        let mut package = sample_official_stack();
        package.components.clear();
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::MissingField(
                "official_stack.components"
            ))
        ));

        let mut package = sample_official_stack();
        package.profiles.clear();
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::MissingField(
                "official_stack.profiles"
            ))
        ));

        let mut package = sample_official_stack();
        package.components[0].extension_point_ids.clear();
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::MissingField(
                "official_stack.components.extension_point_ids"
            ))
        ));

        let mut package = sample_official_stack();
        package.components[0]
            .extension_point_ids
            .push("chio.kernel.receipt_store".to_string());
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut package = sample_official_stack();
        package.components[0].extension_point_ids = vec!["chio.kernel.unknown".to_string()];
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::UnknownReference(_))
        ));

        let mut package = sample_official_stack();
        package.components[1].id = package.components[0].id.clone();
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut package = sample_official_stack();
        package.profiles[0].component_ids.clear();
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::MissingField(
                "official_stack.profiles.component_ids"
            ))
        ));

        let mut package = sample_official_stack();
        package.profiles[1].id = package.profiles[0].id.clone();
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut package = sample_official_stack();
        package.profiles[0]
            .component_ids
            .push("chio.sqlite-receipt-store".to_string());
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut package = sample_official_stack();
        package.profiles[0].component_ids = vec!["chio.unknown-component".to_string()];
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::UnknownReference(_))
        ));

        let mut package = sample_official_stack();
        package.profiles[0]
            .component_ids
            .push("chio.remote-receipt-store".to_string());
        assert!(matches!(
            validate_official_stack_package(&inventory, &package),
            Err(ExtensionContractError::InvalidProfile(_))
        ));

        let mut inventory = sample_inventory();
        inventory.extension_points[0]
            .official_component_ids
            .push("chio.unknown-component".to_string());
        assert!(matches!(
            validate_official_stack_package(&inventory, &sample_official_stack()),
            Err(ExtensionContractError::UnknownReference(_))
        ));
    }

    #[test]
    fn manifest_validation_rejects_remaining_shape_and_runtime_guardrails() {
        let mut manifest = sample_manifest();
        manifest.schema = "chio.extension-manifest.v9".to_string();
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::UnsupportedSchema(_))
        ));

        let mut manifest = sample_manifest();
        manifest.extension_id.clear();
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::MissingField(
                "extension_manifest.extension_id"
            ))
        ));

        let mut manifest = sample_manifest();
        manifest.capabilities.clear();
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::MissingField(
                "extension_manifest.capabilities"
            ))
        ));

        let mut manifest = sample_manifest();
        manifest.supported_profiles.clear();
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::MissingField(
                "extension_manifest.supported_profiles"
            ))
        ));

        let mut manifest = sample_manifest();
        manifest.capabilities.push("receipt_append".to_string());
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut manifest = sample_manifest();
        manifest
            .supported_profiles
            .push("shared_control_plane".to_string());
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut manifest = sample_manifest();
        manifest.compatibility.supported_component_ids.clear();
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::MissingField(
                "extension_manifest.compatibility.supported_component_ids"
            ))
        ));

        let mut manifest = sample_manifest();
        manifest.compatibility.supported_contract_schemas.clear();
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::MissingField(
                "extension_manifest.compatibility.supported_contract_schemas"
            ))
        ));

        let mut manifest = sample_manifest();
        manifest
            .compatibility
            .supported_component_ids
            .push("chio.remote-receipt-store".to_string());
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut manifest = sample_manifest();
        manifest
            .compatibility
            .supported_contract_schemas
            .push("chio.receipt.v1".to_string());
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut manifest = sample_manifest();
        manifest.compatibility.supported_contract_schemas = vec![
            "chio.receipt.v1".to_string(),
            "chio.checkpoint.v1".to_string(),
        ];
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));

        let mut manifest = sample_manifest();
        manifest
            .runtime
            .allowed_privileges
            .push(ExtensionPrivilege::FilesystemRead);
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut manifest = sample_manifest();
        manifest.runtime.allows_truth_mutation = true;
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));

        let mut manifest = sample_manifest();
        manifest.runtime.allows_trust_widening = true;
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));

        let mut manifest = sample_manifest();
        manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
        manifest.runtime.requires_signer_verification = true;
        manifest.runtime.requires_freshness_check = true;
        manifest.runtime.requires_local_policy_activation = true;
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));

        let mut manifest = sample_manifest();
        manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
        manifest.runtime.requires_subject_binding = true;
        manifest.runtime.requires_freshness_check = true;
        manifest.runtime.requires_local_policy_activation = true;
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));

        let mut manifest = sample_manifest();
        manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
        manifest.runtime.requires_subject_binding = true;
        manifest.runtime.requires_signer_verification = true;
        manifest.runtime.requires_local_policy_activation = true;
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));

        let mut manifest = sample_manifest();
        manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
        manifest.runtime.requires_subject_binding = true;
        manifest.runtime.requires_signer_verification = true;
        manifest.runtime.requires_freshness_check = true;
        assert!(matches!(
            validate_extension_manifest(&manifest),
            Err(ExtensionContractError::InvalidGuardrail(_))
        ));
    }

    #[test]
    fn rejects_policy_bypass_for_evidence_capable_extension() {
        let mut manifest = sample_manifest();
        manifest.extension_id = "sample.web3-oracle".to_string();
        manifest.extension_point_id = "chio.kernel.tool_server_connection".to_string();
        manifest.compatibility.supported_component_ids =
            vec!["chio.native-chio-service".to_string()];
        manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportAndDispatch;
        manifest.runtime.requires_subject_binding = true;
        manifest.runtime.requires_signer_verification = false;
        manifest.runtime.requires_freshness_check = true;
        manifest.runtime.requires_local_policy_activation = false;
        manifest.runtime.allowed_privileges = vec![
            ExtensionPrivilege::NetworkEgress,
            ExtensionPrivilege::OperatorSecrets,
        ];

        let report = negotiate_extension(&sample_inventory(), &sample_official_stack(), &manifest);
        assert_eq!(report.outcome, ExtensionNegotiationOutcome::Rejected);
        assert!(report.reasons.iter().any(|reason| {
            reason.code == ExtensionNegotiationRejectionCode::MalformedManifest
                || reason.code == ExtensionNegotiationRejectionCode::LocalPolicyActivationRequired
        }));
    }

    #[test]
    fn negotiation_rejects_malformed_and_mismatched_inputs() {
        let mut inventory = sample_inventory();
        inventory.canonical_truth.clear();
        let mut package = sample_official_stack();
        package.components.clear();
        let mut manifest = sample_manifest();
        manifest.capabilities.clear();

        let report = negotiate_extension(&inventory, &package, &manifest);
        let codes = rejection_codes(&report);
        assert_eq!(report.outcome, ExtensionNegotiationOutcome::Rejected);
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::MalformedInventory));
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::MalformedOfficialStack));
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::MalformedManifest));

        let mut manifest = sample_manifest();
        manifest.compatibility.official_stack_package_id = "chio.other-stack".to_string();
        manifest.compatibility.chio_contract_version = "9.9".to_string();
        let report = negotiate_extension(&sample_inventory(), &sample_official_stack(), &manifest);
        let codes = rejection_codes(&report);
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedOfficialStack));
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedChioContract));

        let mut manifest = sample_manifest();
        manifest.extension_point_id = "chio.kernel.unknown".to_string();
        let report = negotiate_extension(&sample_inventory(), &sample_official_stack(), &manifest);
        let codes = rejection_codes(&report);
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnknownExtensionPoint));
    }

    #[test]
    fn negotiation_rejects_reserved_and_incompatible_extension_claims() {
        let mut inventory = sample_inventory();
        inventory.extension_points[0].custom_implementations_allowed = false;
        inventory.extension_points[0].stability = ExtensionStability::Internal;
        let report = negotiate_extension(&inventory, &sample_official_stack(), &sample_manifest());
        let codes = rejection_codes(&report);
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::OfficialOnlyPoint));
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::InternalOnlyPoint));

        let mut manifest = sample_manifest();
        manifest.supported_profiles = vec!["missing-profile".to_string()];
        manifest.compatibility.supported_component_ids = vec![
            "chio.native-chio-service".to_string(),
            "chio.unknown-component".to_string(),
        ];
        manifest.runtime.isolation = ExtensionIsolation::Subprocess;
        manifest.runtime.evidence_mode = ExtensionEvidenceMode::ImportOnly;
        manifest
            .runtime
            .allowed_privileges
            .push(ExtensionPrivilege::OperatorSecrets);
        manifest.runtime.requires_subject_binding = true;
        manifest.runtime.requires_signer_verification = true;
        manifest.runtime.requires_freshness_check = true;
        manifest.runtime.requires_local_policy_activation = true;

        let report = negotiate_extension(&sample_inventory(), &sample_official_stack(), &manifest);
        let codes = rejection_codes(&report);
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedProfile));
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedComponent));
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedIsolation));
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedEvidenceMode));
        assert!(codes.contains(&ExtensionNegotiationRejectionCode::UnsupportedPrivilege));
    }

    #[test]
    fn qualification_matrix_requires_rejection_codes_for_fail_closed_cases() {
        let matrix = ExtensionQualificationMatrix {
            schema: CHIO_EXTENSION_QUALIFICATION_MATRIX_SCHEMA.to_string(),
            official_stack_package_id: "chio.official-stack".to_string(),
            chio_contract_version: "2.0".to_string(),
            cases: vec![ExtensionQualificationCase {
                id: "missing-reasons".to_string(),
                name: "Broken case".to_string(),
                extension_point_id: "chio.kernel.receipt_store".to_string(),
                supported_component_id: "chio.sqlite-receipt-store".to_string(),
                candidate_extension_id: "sample.bad".to_string(),
                mode: QualificationMode::OfficialToCustom,
                expected_outcome: QualificationOutcome::FailClosed,
                observed_outcome: QualificationOutcome::FailClosed,
                rejection_codes: vec![],
                invariants: vec![QualificationInvariant::RejectsVersionMismatch],
            }],
        };
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::InvalidQualificationCase(_))
        ));
    }

    #[test]
    fn qualification_matrix_rejects_remaining_shape_and_outcome_errors() {
        let mut matrix = sample_qualification_matrix();
        matrix.schema = "chio.extension-qualification-matrix.v9".to_string();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::UnsupportedSchema(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.official_stack_package_id.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::MissingField(
                "qualification_matrix.official_stack_package_id"
            ))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.chio_contract_version.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::MissingField(
                "qualification_matrix.chio_contract_version"
            ))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::MissingField(
                "qualification_matrix.cases"
            ))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].id.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::MissingField(
                "qualification_matrix.case.id"
            ))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].name.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::MissingField(
                "qualification_matrix.case.name"
            ))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].extension_point_id.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::MissingField(
                "qualification_matrix.case.extension_point_id"
            ))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].supported_component_id.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::MissingField(
                "qualification_matrix.case.supported_component_id"
            ))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].candidate_extension_id.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::MissingField(
                "qualification_matrix.case.candidate_extension_id"
            ))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases.push(matrix.cases[0].clone());
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].invariants.clear();
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::InvalidQualificationCase(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0]
            .invariants
            .push(QualificationInvariant::PreservesCanonicalTruth);
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].expected_outcome = QualificationOutcome::FailClosed;
        matrix.cases[0].observed_outcome = QualificationOutcome::FailClosed;
        matrix.cases[0].rejection_codes = vec![
            ExtensionNegotiationRejectionCode::UnsupportedProfile,
            ExtensionNegotiationRejectionCode::UnsupportedProfile,
        ];
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::DuplicateValue(_))
        ));

        let mut matrix = sample_qualification_matrix();
        matrix.cases[0].rejection_codes =
            vec![ExtensionNegotiationRejectionCode::UnsupportedProfile];
        assert!(matches!(
            validate_qualification_matrix(&matrix),
            Err(ExtensionContractError::InvalidQualificationCase(_))
        ));
    }

    #[test]
    fn reference_artifacts_parse_and_validate() {
        let inventory: ChioExtensionInventory = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_EXTENSION_INVENTORY.json"
        ))
        .unwrap();
        let official_stack: OfficialStackPackage = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_OFFICIAL_STACK.json"
        ))
        .unwrap();
        let manifest: ChioExtensionManifest = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_EXTENSION_MANIFEST_EXAMPLE.json"
        ))
        .unwrap();
        let matrix: ExtensionQualificationMatrix = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_EXTENSION_QUALIFICATION_MATRIX.json"
        ))
        .unwrap();

        validate_extension_inventory(&inventory).unwrap();
        validate_official_stack_package(&inventory, &official_stack).unwrap();
        validate_extension_manifest(&manifest).unwrap();
        validate_qualification_matrix(&matrix).unwrap();

        let report = negotiate_extension(&inventory, &official_stack, &manifest);
        assert_eq!(report.outcome, ExtensionNegotiationOutcome::Accepted);
    }
}
