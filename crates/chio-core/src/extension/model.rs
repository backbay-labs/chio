use serde::{Deserialize, Serialize};

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
