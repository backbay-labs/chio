use serde::{Deserialize, Serialize};

use crate::receipt::lineage::SignedExportEnvelope;

pub const CHIO_PUBLIC_IDENTITY_PROFILE_SCHEMA: &str = "chio.public-identity-profile.v1";
pub const CHIO_PUBLIC_WALLET_DIRECTORY_ENTRY_SCHEMA: &str = "chio.public-wallet-directory-entry.v1";
pub const CHIO_PUBLIC_WALLET_ROUTING_MANIFEST_SCHEMA: &str =
    "chio.public-wallet-routing-manifest.v1";
pub const CHIO_IDENTITY_INTEROP_QUALIFICATION_MATRIX_SCHEMA: &str =
    "chio.identity-interop-qualification-matrix.v1";

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
