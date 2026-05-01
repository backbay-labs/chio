//! Chio public identity and wallet network contracts.
//!
//! These contracts widen Chio's outward-facing identity claim without replacing
//! Chio's native `did:chio` provenance anchor. Broader DID methods, credential
//! families, wallet directory entries, and routing manifests remain explicit
//! and fail closed.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::receipt::SignedExportEnvelope;

pub const CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA: &str = "chio.public-identity-profile.v1";
pub const CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA: &str = "chio.public-wallet-directory-entry.v1";
pub const CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA: &str =
    "chio.public-wallet-routing-manifest.v1";
pub const CHIO_IDENTITY_INTEROP_QUALIFICATION_MATRIX_SCHEMA: &str =
    "chio.identity-interop-qualification-matrix.v1";

const IDENTITY_NETWORK_REQUIRED_REQUIREMENTS: [&str; 5] =
    ["IDMAX-01", "IDMAX-02", "IDMAX-03", "IDMAX-04", "IDMAX-05"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityArtifactKind {
    PortableTrustProfile,
    Oid4vciIssuerMetadata,
    Oid4vpVerifierMetadata,
    PublicIssuerDiscovery,
    PublicVerifierDiscovery,
    WalletExchangeDescriptor,
    PublicIdentityProfile,
    PublicWalletDirectoryEntry,
    PublicWalletRoutingManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityArtifactReference {
    pub kind: IdentityArtifactKind,
    pub schema: String,
    pub artifact_id: String,
    pub operator_id: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityDidMethod {
    #[serde(rename = "did:chio")]
    DidChio,
    #[serde(rename = "did:web")]
    DidWeb,
    #[serde(rename = "did:key")]
    DidKey,
    #[serde(rename = "did:jwk")]
    DidJwk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityCredentialFamily {
    #[serde(rename = "chio-agent-passport+json")]
    ChioAgentPassportJson,
    #[serde(rename = "application/dc+sd-jwt")]
    DcSdJwt,
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityProofFamily {
    #[serde(rename = "ed25519-signature-2020")]
    Ed25519Signature2020,
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WalletTransportMode {
    #[serde(rename = "openid4vp-same-device")]
    Oid4vpSameDevice,
    #[serde(rename = "openid4vp-cross-device")]
    Oid4vpCrossDevice,
    #[serde(rename = "openid4vp-relay")]
    Oid4vpRelay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBindingPolicy {
    pub requires_chio_subject_provenance: bool,
    pub requires_chio_issuer_provenance: bool,
    pub requires_same_subject_across_credentials: bool,
    pub manual_subject_rebinding_required: bool,
    pub unsupported_mappings_fail_closed: bool,
}

impl Default for IdentityBindingPolicy {
    fn default() -> Self {
        Self {
            requires_chio_subject_provenance: true,
            requires_chio_issuer_provenance: true,
            requires_same_subject_across_credentials: true,
            manual_subject_rebinding_required: true,
            unsupported_mappings_fail_closed: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicIdentityProfileArtifact {
    pub schema: String,
    pub profile_id: String,
    pub issued_at: u64,
    pub supported_subject_methods: Vec<IdentityDidMethod>,
    pub supported_issuer_methods: Vec<IdentityDidMethod>,
    pub supported_credential_families: Vec<IdentityCredentialFamily>,
    pub supported_proof_families: Vec<IdentityProofFamily>,
    pub supported_transports: Vec<WalletTransportMode>,
    pub basis_refs: Vec<IdentityArtifactReference>,
    #[serde(default)]
    pub binding_policy: IdentityBindingPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedPublicIdentityProfile = SignedExportEnvelope<PublicIdentityProfileArtifact>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletDirectoryLookupGuardrails {
    pub requires_explicit_verifier_binding: bool,
    pub requires_manual_subject_binding_review: bool,
    pub reject_ambient_directory_trust: bool,
    pub fail_closed_on_unknown_wallet_family: bool,
}

impl Default for WalletDirectoryLookupGuardrails {
    fn default() -> Self {
        Self {
            requires_explicit_verifier_binding: true,
            requires_manual_subject_binding_review: true,
            reject_ambient_directory_trust: true,
            fail_closed_on_unknown_wallet_family: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicWalletDirectoryEntryArtifact {
    pub schema: String,
    pub entry_id: String,
    pub issued_at: u64,
    pub directory_operator_id: String,
    pub wallet_id: String,
    pub supported_subject_methods: Vec<IdentityDidMethod>,
    pub supported_issuer_methods: Vec<IdentityDidMethod>,
    pub supported_credential_families: Vec<IdentityCredentialFamily>,
    pub supported_proof_families: Vec<IdentityProofFamily>,
    pub discovery_ref: IdentityArtifactReference,
    pub profile_ref: IdentityArtifactReference,
    pub metadata_url: String,
    pub request_uri_prefix: String,
    #[serde(default)]
    pub lookup_guardrails: WalletDirectoryLookupGuardrails,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedPublicWalletDirectoryEntry =
    SignedExportEnvelope<PublicWalletDirectoryEntryArtifact>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletRoutingGuardrails {
    pub requires_explicit_verifier_binding: bool,
    pub requires_replay_safe_exchange: bool,
    pub fail_closed_on_subject_mismatch: bool,
    pub fail_closed_on_cross_operator_issuer_mismatch: bool,
}

impl Default for WalletRoutingGuardrails {
    fn default() -> Self {
        Self {
            requires_explicit_verifier_binding: true,
            requires_replay_safe_exchange: true,
            fail_closed_on_subject_mismatch: true,
            fail_closed_on_cross_operator_issuer_mismatch: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicWalletRoutingManifestArtifact {
    pub schema: String,
    pub route_id: String,
    pub issued_at: u64,
    pub directory_entry_ref: IdentityArtifactReference,
    pub verifier_id: String,
    pub response_uri_prefix: String,
    pub relay_url: String,
    pub transport_modes: Vec<WalletTransportMode>,
    pub requires_signed_request_object: bool,
    pub requires_replay_anchors: bool,
    #[serde(default)]
    pub routing_guardrails: WalletRoutingGuardrails,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedPublicWalletRoutingManifest =
    SignedExportEnvelope<PublicWalletRoutingManifestArtifact>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityInteropScenarioKind {
    UnsupportedDidMethod,
    UnsupportedCredentialFamily,
    DirectoryPoisoning,
    RouteReplay,
    MultiWalletSelection,
    CrossOperatorIssuerMismatch,
    ReleaseBoundaryClosure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityQualificationOutcome {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityInteropQualificationCase {
    pub id: String,
    pub name: String,
    pub requirement_ids: Vec<String>,
    pub scenario: IdentityInteropScenarioKind,
    pub expected_outcome: IdentityQualificationOutcome,
    pub observed_outcome: IdentityQualificationOutcome,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityInteropQualificationMatrix {
    pub schema: String,
    pub profile_ref: IdentityArtifactReference,
    pub directory_entry_ref: IdentityArtifactReference,
    pub routing_manifest_ref: IdentityArtifactReference,
    pub cases: Vec<IdentityInteropQualificationCase>,
}

pub type SignedIdentityInteropQualificationMatrix =
    SignedExportEnvelope<IdentityInteropQualificationMatrix>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityNetworkContractError {
    #[error("unsupported schema `{0}`")]
    UnsupportedSchema(String),
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("duplicate value `{0}`")]
    DuplicateValue(String),
    #[error("invalid reference `{0}`")]
    InvalidReference(String),
    #[error("invalid identity profile `{0}`")]
    InvalidProfile(String),
    #[error("invalid wallet directory entry `{0}`")]
    InvalidDirectoryEntry(String),
    #[error("invalid wallet routing manifest `{0}`")]
    InvalidRouting(String),
    #[error("invalid qualification case `{0}`")]
    InvalidQualificationCase(String),
}

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

fn validate_identity_artifact_reference(
    reference: &IdentityArtifactReference,
) -> Result<(), IdentityNetworkContractError> {
    ensure_non_empty(&reference.schema, "reference.schema")?;
    ensure_non_empty(&reference.artifact_id, "reference.artifact_id")?;
    ensure_non_empty(&reference.operator_id, "reference.operator_id")?;
    validate_hex_digest(&reference.sha256, "reference.sha256")?;
    if let Some(uri) = reference.uri.as_ref() {
        validate_https_url(uri, "reference.uri")?;
    }
    Ok(())
}

fn validate_identity_binding_policy(
    policy: &IdentityBindingPolicy,
) -> Result<(), IdentityNetworkContractError> {
    if !policy.requires_chio_subject_provenance {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must require Chio subject provenance".to_string(),
        ));
    }
    if !policy.requires_chio_issuer_provenance {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must require Chio issuer provenance".to_string(),
        ));
    }
    if !policy.requires_same_subject_across_credentials {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must require the same subject across credentials".to_string(),
        ));
    }
    if !policy.manual_subject_rebinding_required {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must require manual subject rebinding review".to_string(),
        ));
    }
    if !policy.unsupported_mappings_fail_closed {
        return Err(IdentityNetworkContractError::InvalidProfile(
            "public identity profiles must fail closed on unsupported mappings".to_string(),
        ));
    }
    Ok(())
}

fn validate_wallet_directory_lookup_guardrails(
    guardrails: &WalletDirectoryLookupGuardrails,
) -> Result<(), IdentityNetworkContractError> {
    if !guardrails.requires_explicit_verifier_binding {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must require explicit verifier binding".to_string(),
        ));
    }
    if !guardrails.requires_manual_subject_binding_review {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must require manual subject binding review".to_string(),
        ));
    }
    if !guardrails.reject_ambient_directory_trust {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must reject ambient directory trust".to_string(),
        ));
    }
    if !guardrails.fail_closed_on_unknown_wallet_family {
        return Err(IdentityNetworkContractError::InvalidDirectoryEntry(
            "wallet directory entries must fail closed on unknown wallet families".to_string(),
        ));
    }
    Ok(())
}

fn validate_wallet_routing_guardrails(
    guardrails: &WalletRoutingGuardrails,
) -> Result<(), IdentityNetworkContractError> {
    if !guardrails.requires_explicit_verifier_binding {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must require explicit verifier binding".to_string(),
        ));
    }
    if !guardrails.requires_replay_safe_exchange {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must require replay-safe exchange".to_string(),
        ));
    }
    if !guardrails.fail_closed_on_subject_mismatch {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must fail closed on subject mismatch".to_string(),
        ));
    }
    if !guardrails.fail_closed_on_cross_operator_issuer_mismatch {
        return Err(IdentityNetworkContractError::InvalidRouting(
            "wallet routing manifests must fail closed on cross-operator issuer mismatch"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_https_url(
    value: &str,
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    ensure_non_empty(value, field)?;
    let parsed = Url::parse(value).map_err(|error| {
        IdentityNetworkContractError::InvalidReference(format!("{field}: {error}"))
    })?;
    if parsed.scheme() != "https" {
        return Err(IdentityNetworkContractError::InvalidReference(format!(
            "{field}: expected https URL"
        )));
    }
    Ok(())
}

fn validate_hex_digest(
    value: &str,
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(IdentityNetworkContractError::InvalidReference(format!(
            "{field}: expected 64 hex characters"
        )));
    }
    Ok(())
}

fn contains_non_chio_method(methods: &[IdentityDidMethod]) -> bool {
    methods
        .iter()
        .any(|method| *method != IdentityDidMethod::DidChio)
}

fn ensure_required_transports(
    transports: &[WalletTransportMode],
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    ensure_unique_copy_values(transports, field)?;
    let transport_set: HashSet<_> = transports.iter().copied().collect();
    let required = HashSet::from([
        WalletTransportMode::Oid4vpSameDevice,
        WalletTransportMode::Oid4vpCrossDevice,
        WalletTransportMode::Oid4vpRelay,
    ]);
    if transport_set != required {
        return Err(IdentityNetworkContractError::DuplicateValue(format!(
            "{field}:must include same-device, cross-device, and relay"
        )));
    }
    Ok(())
}

fn ensure_refs_present(
    references: &[IdentityArtifactReference],
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    if references.is_empty() {
        return Err(IdentityNetworkContractError::MissingField(field));
    }
    let composite_ids = references
        .iter()
        .map(|reference| format!("{}:{}", reference.operator_id, reference.artifact_id))
        .collect::<Vec<_>>();
    ensure_unique_strings(&composite_ids, field)?;
    Ok(())
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), IdentityNetworkContractError> {
    if value.trim().is_empty() {
        return Err(IdentityNetworkContractError::MissingField(field));
    }
    Ok(())
}

fn ensure_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), IdentityNetworkContractError> {
    let mut seen = HashSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(IdentityNetworkContractError::MissingField(field));
        }
        if !seen.insert(value.as_str()) {
            return Err(IdentityNetworkContractError::DuplicateValue(format!(
                "{field}:{value}"
            )));
        }
    }
    Ok(())
}

fn ensure_unique_copy_values<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), IdentityNetworkContractError>
where
    T: Copy + Eq + std::hash::Hash + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(IdentityNetworkContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_contract_err<T>(
        result: Result<T, IdentityNetworkContractError>,
        context: &str,
    ) -> IdentityNetworkContractError {
        match result {
            Ok(_) => panic!("{context}: unexpected success"),
            Err(error) => error,
        }
    }

    fn hex(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    fn sample_reference(
        kind: IdentityArtifactKind,
        schema: &str,
        artifact_id: &str,
        operator_id: &str,
        seed: char,
    ) -> IdentityArtifactReference {
        IdentityArtifactReference {
            kind,
            schema: schema.to_string(),
            artifact_id: artifact_id.to_string(),
            operator_id: operator_id.to_string(),
            sha256: hex(seed),
            uri: Some(format!("https://example.com/{artifact_id}")),
        }
    }

    fn sample_profile() -> PublicIdentityProfileArtifact {
        PublicIdentityProfileArtifact {
            schema: CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA.to_string(),
            profile_id: "pip-1".to_string(),
            issued_at: 1_710_000_000,
            supported_subject_methods: vec![
                IdentityDidMethod::DidChio,
                IdentityDidMethod::DidWeb,
                IdentityDidMethod::DidKey,
            ],
            supported_issuer_methods: vec![
                IdentityDidMethod::DidChio,
                IdentityDidMethod::DidWeb,
                IdentityDidMethod::DidJwk,
            ],
            supported_credential_families: vec![
                IdentityCredentialFamily::ChioAgentPassportJson,
                IdentityCredentialFamily::DcSdJwt,
                IdentityCredentialFamily::JwtVcJson,
            ],
            supported_proof_families: vec![
                IdentityProofFamily::Ed25519Signature2020,
                IdentityProofFamily::DcSdJwt,
                IdentityProofFamily::JwtVcJson,
            ],
            supported_transports: vec![
                WalletTransportMode::Oid4vpSameDevice,
                WalletTransportMode::Oid4vpCrossDevice,
                WalletTransportMode::Oid4vpRelay,
            ],
            basis_refs: vec![
                sample_reference(
                    IdentityArtifactKind::PortableTrustProfile,
                    "chio.portable-trust-profile.v1",
                    "ptp-1",
                    "chio",
                    'a',
                ),
                sample_reference(
                    IdentityArtifactKind::Oid4vciIssuerMetadata,
                    "openid-credential-issuer-metadata",
                    "oid4vci-1",
                    "issuer-operator-1",
                    'b',
                ),
                sample_reference(
                    IdentityArtifactKind::Oid4vpVerifierMetadata,
                    "chio.oid4vp-verifier-metadata.v1",
                    "oid4vp-1",
                    "verifier-operator-1",
                    'c',
                ),
            ],
            binding_policy: IdentityBindingPolicy::default(),
            note: Some("bounded broader identity support".to_string()),
        }
    }

    fn sample_directory_entry() -> PublicWalletDirectoryEntryArtifact {
        PublicWalletDirectoryEntryArtifact {
            schema: CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA.to_string(),
            entry_id: "wde-1".to_string(),
            issued_at: 1_710_000_010,
            directory_operator_id: "wallet-operator-1".to_string(),
            wallet_id: "wallet.example".to_string(),
            supported_subject_methods: vec![
                IdentityDidMethod::DidChio,
                IdentityDidMethod::DidWeb,
                IdentityDidMethod::DidKey,
            ],
            supported_issuer_methods: vec![
                IdentityDidMethod::DidChio,
                IdentityDidMethod::DidWeb,
                IdentityDidMethod::DidJwk,
            ],
            supported_credential_families: vec![
                IdentityCredentialFamily::DcSdJwt,
                IdentityCredentialFamily::JwtVcJson,
            ],
            supported_proof_families: vec![
                IdentityProofFamily::DcSdJwt,
                IdentityProofFamily::JwtVcJson,
            ],
            discovery_ref: sample_reference(
                IdentityArtifactKind::PublicVerifierDiscovery,
                "chio.public-verifier-discovery.v1",
                "pvd-1",
                "verifier-operator-1",
                'd',
            ),
            profile_ref: sample_reference(
                IdentityArtifactKind::PublicIdentityProfile,
                CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
                "pip-1",
                "chio",
                'e',
            ),
            metadata_url: "https://wallet.example/.well-known/openid-credential-wallet".to_string(),
            request_uri_prefix: "https://wallet.example/wallet-exchanges/".to_string(),
            lookup_guardrails: WalletDirectoryLookupGuardrails::default(),
            note: Some("verifier-scoped public wallet routing".to_string()),
        }
    }

    fn sample_routing_manifest() -> PublicWalletRoutingManifestArtifact {
        PublicWalletRoutingManifestArtifact {
            schema: CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA.to_string(),
            route_id: "wrm-1".to_string(),
            issued_at: 1_710_000_020,
            directory_entry_ref: sample_reference(
                IdentityArtifactKind::PublicWalletDirectoryEntry,
                CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA,
                "wde-1",
                "wallet-operator-1",
                'f',
            ),
            verifier_id: "https://verifier.example.com".to_string(),
            response_uri_prefix:
                "https://verifier.example.com/v1/public/passport/wallet-exchanges/".to_string(),
            relay_url: "https://wallet.example/relay".to_string(),
            transport_modes: vec![
                WalletTransportMode::Oid4vpSameDevice,
                WalletTransportMode::Oid4vpCrossDevice,
                WalletTransportMode::Oid4vpRelay,
            ],
            requires_signed_request_object: true,
            requires_replay_anchors: true,
            routing_guardrails: WalletRoutingGuardrails::default(),
            note: Some("bounded public wallet routing".to_string()),
        }
    }

    fn sample_matrix() -> IdentityInteropQualificationMatrix {
        IdentityInteropQualificationMatrix {
            schema: CHIO_IDENTITY_INTEROP_QUALIFICATION_MATRIX_SCHEMA.to_string(),
            profile_ref: sample_reference(
                IdentityArtifactKind::PublicIdentityProfile,
                CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
                "pip-1",
                "chio",
                'a',
            ),
            directory_entry_ref: sample_reference(
                IdentityArtifactKind::PublicWalletDirectoryEntry,
                CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA,
                "wde-1",
                "wallet-operator-1",
                'b',
            ),
            routing_manifest_ref: sample_reference(
                IdentityArtifactKind::PublicWalletRoutingManifest,
                CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA,
                "wrm-1",
                "wallet-operator-1",
                'c',
            ),
            cases: vec![
                IdentityInteropQualificationCase {
                    id: "method-support".to_string(),
                    name: "Unsupported DID methods fail closed".to_string(),
                    requirement_ids: vec!["IDMAX-01".to_string()],
                    scenario: IdentityInteropScenarioKind::UnsupportedDidMethod,
                    expected_outcome: IdentityQualificationOutcome::FailClosed,
                    observed_outcome: IdentityQualificationOutcome::FailClosed,
                    notes: vec!["Unsupported method families are rejected explicitly".to_string()],
                },
                IdentityInteropQualificationCase {
                    id: "directory-poisoning".to_string(),
                    name: "Directory poisoning fails closed".to_string(),
                    requirement_ids: vec!["IDMAX-02".to_string()],
                    scenario: IdentityInteropScenarioKind::DirectoryPoisoning,
                    expected_outcome: IdentityQualificationOutcome::FailClosed,
                    observed_outcome: IdentityQualificationOutcome::FailClosed,
                    notes: vec!["Directory entries stay verifier-bound and non-ambient".to_string()],
                },
                IdentityInteropQualificationCase {
                    id: "multi-wallet".to_string(),
                    name: "Multi-wallet selection remains replay safe".to_string(),
                    requirement_ids: vec!["IDMAX-03".to_string()],
                    scenario: IdentityInteropScenarioKind::MultiWalletSelection,
                    expected_outcome: IdentityQualificationOutcome::Pass,
                    observed_outcome: IdentityQualificationOutcome::Pass,
                    notes: vec![
                        "Supported multi-wallet routing completes inside explicit guardrails"
                            .to_string(),
                    ],
                },
                IdentityInteropQualificationCase {
                    id: "cross-operator-boundary".to_string(),
                    name: "Cross-operator issuer mismatch fails closed".to_string(),
                    requirement_ids: vec!["IDMAX-04".to_string()],
                    scenario: IdentityInteropScenarioKind::CrossOperatorIssuerMismatch,
                    expected_outcome: IdentityQualificationOutcome::FailClosed,
                    observed_outcome: IdentityQualificationOutcome::FailClosed,
                    notes: vec!["Issuer and admission boundaries remain explicit".to_string()],
                },
                IdentityInteropQualificationCase {
                    id: "release-closure".to_string(),
                    name: "Release boundary stays honest".to_string(),
                    requirement_ids: vec!["IDMAX-05".to_string()],
                    scenario: IdentityInteropScenarioKind::ReleaseBoundaryClosure,
                    expected_outcome: IdentityQualificationOutcome::Pass,
                    observed_outcome: IdentityQualificationOutcome::Pass,
                    notes: vec!["Final public claim remains bounded and specific".to_string()],
                },
            ],
        }
    }

    #[test]
    fn profile_validation_rejects_remaining_schema_reference_and_policy_errors() {
        let mut profile = sample_profile();
        profile.schema = "chio.public-identity-profile.v9".to_string();
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::UnsupportedSchema(_))
        ));

        let mut profile = sample_profile();
        profile.profile_id.clear();
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::MissingField("profile_id"))
        ));

        let mut profile = sample_profile();
        profile
            .supported_subject_methods
            .push(IdentityDidMethod::DidChio);
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));

        let mut profile = sample_profile();
        profile
            .supported_credential_families
            .push(IdentityCredentialFamily::DcSdJwt);
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));

        let mut profile = sample_profile();
        profile
            .supported_proof_families
            .push(IdentityProofFamily::DcSdJwt);
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));

        let mut profile = sample_profile();
        profile
            .supported_transports
            .push(WalletTransportMode::Oid4vpRelay);
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));

        let mut profile = sample_profile();
        profile.basis_refs.clear();
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::MissingField("basis_refs"))
        ));

        let mut profile = sample_profile();
        profile.binding_policy.requires_chio_issuer_provenance = false;
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidProfile(_))
        ));

        let mut profile = sample_profile();
        profile
            .binding_policy
            .requires_same_subject_across_credentials = false;
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidProfile(_))
        ));

        let mut profile = sample_profile();
        profile.binding_policy.manual_subject_rebinding_required = false;
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidProfile(_))
        ));

        let mut profile = sample_profile();
        profile.binding_policy.unsupported_mappings_fail_closed = false;
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidProfile(_))
        ));

        let mut profile = sample_profile();
        profile.supported_subject_methods = vec![IdentityDidMethod::DidWeb];
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidProfile(_))
        ));

        let mut profile = sample_profile();
        profile.supported_credential_families = vec![IdentityCredentialFamily::DcSdJwt];
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidProfile(_))
        ));

        let mut profile = sample_profile();
        profile.supported_credential_families =
            vec![IdentityCredentialFamily::ChioAgentPassportJson];
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidProfile(_))
        ));

        let mut profile = sample_profile();
        profile.basis_refs.remove(0);
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidProfile(_))
        ));

        let mut profile = sample_profile();
        profile.basis_refs[0].sha256 = "abcd".to_string();
        assert!(matches!(
            validate_public_identity_profile(&profile),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));
    }

    #[test]
    fn profile_requires_chio_anchor_and_broader_support() {
        let mut profile = sample_profile();
        profile.binding_policy.requires_chio_subject_provenance = false;
        let error = expect_contract_err(
            validate_public_identity_profile(&profile),
            "missing chio subject provenance",
        );
        assert!(matches!(
            error,
            IdentityNetworkContractError::InvalidProfile(_)
        ));

        let mut profile = sample_profile();
        profile.supported_subject_methods = vec![IdentityDidMethod::DidChio];
        profile.supported_issuer_methods = vec![IdentityDidMethod::DidChio];
        let error = expect_contract_err(
            validate_public_identity_profile(&profile),
            "missing broader method",
        );
        assert!(matches!(
            error,
            IdentityNetworkContractError::InvalidProfile(_)
        ));
    }

    #[test]
    fn wallet_directory_requires_verifier_guardrails() {
        let mut entry = sample_directory_entry();
        entry.lookup_guardrails.requires_explicit_verifier_binding = false;
        let error = expect_contract_err(
            validate_public_wallet_directory_entry(&entry),
            "missing verifier binding guardrail",
        );
        assert!(matches!(
            error,
            IdentityNetworkContractError::InvalidDirectoryEntry(_)
        ));
    }

    #[test]
    fn wallet_directory_validation_rejects_remaining_reference_url_and_guardrail_errors() {
        let mut entry = sample_directory_entry();
        entry.schema = "chio.public-wallet-directory-entry.v9".to_string();
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::UnsupportedSchema(_))
        ));

        let mut entry = sample_directory_entry();
        entry.entry_id.clear();
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::MissingField("entry_id"))
        ));

        let mut entry = sample_directory_entry();
        entry
            .supported_subject_methods
            .push(IdentityDidMethod::DidChio);
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));

        let mut entry = sample_directory_entry();
        entry.discovery_ref.kind = IdentityArtifactKind::PublicIdentityProfile;
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
        ));

        let mut entry = sample_directory_entry();
        entry.profile_ref.kind = IdentityArtifactKind::PortableTrustProfile;
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
        ));

        let mut entry = sample_directory_entry();
        entry.metadata_url = "http://wallet.example/metadata".to_string();
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));

        let mut entry = sample_directory_entry();
        entry.request_uri_prefix = "https://".to_string();
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));

        let mut entry = sample_directory_entry();
        entry
            .lookup_guardrails
            .requires_manual_subject_binding_review = false;
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
        ));

        let mut entry = sample_directory_entry();
        entry.lookup_guardrails.reject_ambient_directory_trust = false;
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
        ));

        let mut entry = sample_directory_entry();
        entry.lookup_guardrails.fail_closed_on_unknown_wallet_family = false;
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
        ));

        let mut entry = sample_directory_entry();
        entry.supported_subject_methods = vec![IdentityDidMethod::DidChio];
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
        ));

        let mut entry = sample_directory_entry();
        entry.supported_credential_families = vec![IdentityCredentialFamily::ChioAgentPassportJson];
        assert!(matches!(
            validate_public_wallet_directory_entry(&entry),
            Err(IdentityNetworkContractError::InvalidDirectoryEntry(_))
        ));
    }

    #[test]
    fn routing_manifest_requires_all_transports() {
        let mut manifest = sample_routing_manifest();
        manifest.transport_modes = vec![
            WalletTransportMode::Oid4vpSameDevice,
            WalletTransportMode::Oid4vpCrossDevice,
        ];
        let error = expect_contract_err(
            validate_public_wallet_routing_manifest(&manifest),
            "missing relay transport",
        );
        assert!(matches!(
            error,
            IdentityNetworkContractError::DuplicateValue(_)
        ));
    }

    #[test]
    fn routing_manifest_validation_rejects_remaining_guardrails_and_reference_errors() {
        let mut manifest = sample_routing_manifest();
        manifest.schema = "chio.public-wallet-routing-manifest.v9".to_string();
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::UnsupportedSchema(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.route_id.clear();
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::MissingField("route_id"))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.directory_entry_ref.kind = IdentityArtifactKind::PublicIdentityProfile;
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidRouting(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.verifier_id = "not-a-url".to_string();
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.response_uri_prefix = "http://verifier.example.com/response".to_string();
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.relay_url = "https://".to_string();
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.routing_guardrails.requires_replay_safe_exchange = false;
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidRouting(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.routing_guardrails.fail_closed_on_subject_mismatch = false;
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidRouting(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest
            .routing_guardrails
            .fail_closed_on_cross_operator_issuer_mismatch = false;
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidRouting(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.requires_signed_request_object = false;
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidRouting(_))
        ));

        let mut manifest = sample_routing_manifest();
        manifest.requires_replay_anchors = false;
        assert!(matches!(
            validate_public_wallet_routing_manifest(&manifest),
            Err(IdentityNetworkContractError::InvalidRouting(_))
        ));
    }

    #[test]
    fn qualification_matrix_requires_requirement_coverage() {
        let mut matrix = sample_matrix();
        matrix.cases.pop();
        let _ = expect_contract_err(
            validate_identity_interop_qualification_matrix(&matrix),
            "missing requirement coverage",
        );
    }

    #[test]
    fn qualification_matrix_rejects_remaining_reference_and_case_errors() {
        let mut matrix = sample_matrix();
        matrix.schema = "chio.identity-interop-qualification-matrix.v9".to_string();
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::UnsupportedSchema(_))
        ));

        let mut matrix = sample_matrix();
        matrix.profile_ref.kind = IdentityArtifactKind::PublicWalletDirectoryEntry;
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::InvalidQualificationCase(_))
        ));

        let mut matrix = sample_matrix();
        matrix.directory_entry_ref.kind = IdentityArtifactKind::PortableTrustProfile;
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::InvalidQualificationCase(_))
        ));

        let mut matrix = sample_matrix();
        matrix.routing_manifest_ref.kind = IdentityArtifactKind::PublicIdentityProfile;
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::InvalidQualificationCase(_))
        ));

        let mut matrix = sample_matrix();
        matrix.cases.clear();
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::MissingField("cases"))
        ));

        let mut matrix = sample_matrix();
        matrix.cases[0].id.clear();
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::MissingField("case.id"))
        ));

        let mut matrix = sample_matrix();
        matrix.cases[0].name.clear();
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::MissingField("case.name"))
        ));

        let mut matrix = sample_matrix();
        matrix.cases[0].observed_outcome = IdentityQualificationOutcome::Pass;
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::InvalidQualificationCase(_))
        ));

        let mut matrix = sample_matrix();
        matrix.cases[0].requirement_ids.push("IDMAX-01".to_string());
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));

        let mut matrix = sample_matrix();
        matrix.cases[0].notes.push(" ".to_string());
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::MissingField("case.notes"))
        ));

        let mut matrix = sample_matrix();
        matrix.cases.push(matrix.cases[0].clone());
        assert!(matches!(
            validate_identity_interop_qualification_matrix(&matrix),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));
    }

    #[test]
    fn identity_helper_validators_cover_remaining_reference_edges() {
        let mut reference = sample_reference(
            IdentityArtifactKind::PublicIdentityProfile,
            CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
            "pip-1",
            "chio",
            'j',
        );
        reference.schema.clear();
        assert!(matches!(
            validate_identity_artifact_reference(&reference),
            Err(IdentityNetworkContractError::MissingField(
                "reference.schema"
            ))
        ));

        let mut reference = sample_reference(
            IdentityArtifactKind::PublicIdentityProfile,
            CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
            "pip-1",
            "chio",
            'k',
        );
        reference.artifact_id.clear();
        assert!(matches!(
            validate_identity_artifact_reference(&reference),
            Err(IdentityNetworkContractError::MissingField(
                "reference.artifact_id"
            ))
        ));

        let mut reference = sample_reference(
            IdentityArtifactKind::PublicIdentityProfile,
            CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
            "pip-1",
            "chio",
            'l',
        );
        reference.operator_id.clear();
        assert!(matches!(
            validate_identity_artifact_reference(&reference),
            Err(IdentityNetworkContractError::MissingField(
                "reference.operator_id"
            ))
        ));

        assert!(matches!(
            validate_https_url("mailto:test@example.com", "reference.uri"),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));
        assert!(matches!(
            validate_https_url("https://", "reference.uri"),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));
        assert!(matches!(
            validate_hex_digest("zzzz", "reference.sha256"),
            Err(IdentityNetworkContractError::InvalidReference(_))
        ));
        assert!(!contains_non_chio_method(&[IdentityDidMethod::DidChio]));
        assert!(contains_non_chio_method(&[
            IdentityDidMethod::DidChio,
            IdentityDidMethod::DidWeb,
        ]));

        assert!(matches!(
            ensure_required_transports(
                &[
                    WalletTransportMode::Oid4vpSameDevice,
                    WalletTransportMode::Oid4vpSameDevice,
                    WalletTransportMode::Oid4vpRelay,
                ],
                "transport_modes",
            ),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));
        assert!(matches!(
            ensure_refs_present(&[], "basis_refs"),
            Err(IdentityNetworkContractError::MissingField("basis_refs"))
        ));

        let duplicate_refs = vec![
            sample_reference(
                IdentityArtifactKind::PublicIdentityProfile,
                CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA,
                "pip-1",
                "chio",
                'm',
            ),
            sample_reference(
                IdentityArtifactKind::PublicWalletDirectoryEntry,
                CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA,
                "pip-1",
                "chio",
                'n',
            ),
        ];
        assert!(matches!(
            ensure_refs_present(&duplicate_refs, "basis_refs"),
            Err(IdentityNetworkContractError::DuplicateValue(_))
        ));
    }

    #[test]
    fn reference_artifacts_parse_and_validate() {
        let profile: PublicIdentityProfileArtifact = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_PUBLIC_IDENTITY_PROFILE.json"
        ))
        .unwrap_or_else(|error| panic!("parse public identity profile fixture: {error}"));
        validate_public_identity_profile(&profile)
            .unwrap_or_else(|error| panic!("validate public identity profile fixture: {error:?}"));

        let entry: PublicWalletDirectoryEntryArtifact = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_EXAMPLE.json"
        ))
        .unwrap_or_else(|error| panic!("parse wallet directory entry fixture: {error}"));
        validate_public_wallet_directory_entry(&entry)
            .unwrap_or_else(|error| panic!("validate wallet directory entry fixture: {error:?}"));

        let routing: PublicWalletRoutingManifestArtifact = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_PUBLIC_WALLET_ROUTING_EXAMPLE.json"
        ))
        .unwrap_or_else(|error| panic!("parse wallet routing manifest fixture: {error}"));
        validate_public_wallet_routing_manifest(&routing)
            .unwrap_or_else(|error| panic!("validate wallet routing manifest fixture: {error:?}"));

        let matrix: IdentityInteropQualificationMatrix = serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_PUBLIC_IDENTITY_QUALIFICATION_MATRIX.json"
        ))
        .unwrap_or_else(|error| panic!("parse identity qualification matrix fixture: {error}"));
        validate_identity_interop_qualification_matrix(&matrix).unwrap_or_else(|error| {
            panic!("validate identity qualification matrix fixture: {error:?}")
        });
    }
}
