//! Runtime Chio federation authority artifact issuance.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use chio_attest_buyer_core::{
    ChioAuthorityStatus, ChioDisclosurePolicy, ChioPackageError, ChioRevocationCheckpoint,
    ChioRevocationMaterial, ChioTrustedActionClass, ChioTrustedGovernanceAuthority,
    ChioTrustedLeaseAuthority, ChioTrustedWorkflowIntersection, ChioVerificationContext,
    ChioVerifierTrustBundle, ChioVerifierTrustBundleDocument, LeaseScopeBindingArtifact,
    PeerLadderBinding, SignedChioRevocationCheckpoint, TrustedBbsIssuer, VendorKeyBinding,
    WorkflowIntersectionArtifact, CHIO_FEDERATION_REVOCATION_CHECKPOINT_SCHEMA_V1,
    CHIO_FEDERATION_VERIFIER_TRUST_BUNDLE_SCHEMA, LEASE_SCOPE_BINDING_SCHEMA,
    WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID, WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID,
};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::SignedExportEnvelope;
use chio_federation::Keyid;
use chio_governance::{
    CapabilityLeaseActionClass, CapabilityLeaseArtifact, GovernanceReceiptArtifact,
    GovernanceReceiptCaseKind, SignedCapabilityLease, SignedGovernanceReceipt,
    CAPABILITY_LEASE_SCHEMA_V1, GOVERNANCE_RECEIPT_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};

pub const AUTHORITY_PROFILE_SCHEMA: &str = "chio.federation.authority-profile.v1";
pub const ISSUANCE_REQUEST_SCHEMA: &str = "chio.federation.issuance-request.v1";
pub const ISSUANCE_BUNDLE_SCHEMA: &str = "chio.federation.issuance-bundle.v1";
pub const REVOCATION_PUBLICATION_REQUEST_SCHEMA: &str =
    "chio.federation.revocation-publication-request.v1";
pub const PEER_PINS_SCHEMA: &str = "chio.federation.peer-pins.v1";
pub const LOCAL_SIGNING_KEYS_SCHEMA: &str = "chio.federation.local-signing-keys.v1";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ChioAuthorityError {
    #[error("authority profile failed: {0}")]
    Profile(String),
    #[error("issuance request failed: {0}")]
    Request(String),
    #[error("local signing keys failed: {0}")]
    SigningKeys(String),
    #[error("authority issuance failed: {0}")]
    Issuance(String),
    #[error("revocation checkpoint publication failed: {0}")]
    Revocation(String),
    #[error("trust bundle assembly failed: {0}")]
    TrustBundle(String),
    #[error("json failed: {0}")]
    Json(String),
    #[error("canonical json failed: {0}")]
    Canonical(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioRevocationAuthority {
    pub authority_id: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub status: ChioAuthorityStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityProfileDocument {
    pub schema: String,
    pub trusted_bbs_issuers: Vec<TrustedBbsIssuer>,
    pub lease_authorities: Vec<ChioTrustedLeaseAuthority>,
    pub governance_authorities: Vec<ChioTrustedGovernanceAuthority>,
    pub runtime_policy_issuer_public_keys: Vec<PublicKey>,
    pub revocation_authority: ChioRevocationAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamedSeedHex {
    pub id: String,
    pub seed_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAuthoritySigningKeysDocument {
    pub schema: String,
    pub lease_authority_seeds: Vec<NamedSeedHex>,
    pub governance_authority_seeds: Vec<NamedSeedHex>,
    pub revocation_authority_seed_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioIssuanceStepRequest {
    pub lease_id: String,
    pub step_index: usize,
    pub tool_name: String,
    pub peer_kernel_id: String,
    pub action_class_id: String,
    pub subject: String,
    pub action_class: CapabilityLeaseActionClass,
    pub tool_args_hash: String,
    pub destructive: bool,
    pub lease_issued_at_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_issued_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_expires_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioIssuanceRequest {
    pub schema: String,
    pub workflow_id: String,
    pub workflow_grant_id: String,
    pub lease_authority_issuer: String,
    pub governance_authority_kernel: String,
    pub verification_context: ChioVerificationContext,
    pub steps: Vec<ChioIssuanceStepRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioIssuanceBundle {
    pub schema: String,
    pub capability_leases: Vec<SignedCapabilityLease>,
    pub lease_scope_bindings: Vec<LeaseScopeBindingArtifact>,
    pub governance_receipts: Vec<SignedGovernanceReceipt>,
    pub verification_context: ChioVerificationContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationPublicationRequest {
    pub schema: String,
    pub checkpoint_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub epoch_height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_epoch_height: Option<u64>,
    pub revoked_key_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerPinsDocument {
    pub schema: String,
    pub peers: Vec<PeerLadderBinding>,
    pub vendors: Vec<VendorKeyBinding>,
    pub action_classes: Vec<ChioTrustedActionClass>,
}

impl AuthorityProfileDocument {
    pub fn validate(&self) -> Result<(), ChioAuthorityError> {
        if self.schema != AUTHORITY_PROFILE_SCHEMA {
            return Err(ChioAuthorityError::Profile(format!(
                "authority profile schema {} is unsupported",
                self.schema
            )));
        }
        if self.trusted_bbs_issuers.is_empty()
            || self.lease_authorities.is_empty()
            || self.governance_authorities.is_empty()
            || self.runtime_policy_issuer_public_keys.is_empty()
        {
            return Err(ChioAuthorityError::Profile(
                "authority profile must contain BBS issuers, lease authorities, governance authorities, and runtime policy issuers".to_string(),
            ));
        }
        let mut issuers = BTreeSet::new();
        for issuer in &self.trusted_bbs_issuers {
            validate_sha256(
                &issuer.issuer_fingerprint,
                "trustedBbsIssuers.issuerFingerprint",
            )
            .map_err(ChioAuthorityError::Profile)?;
            validate_hex(&issuer.public_key_hex, "trustedBbsIssuers.publicKeyHex")
                .map_err(ChioAuthorityError::Profile)?;
            if !issuers.insert(&issuer.issuer_fingerprint) {
                return Err(ChioAuthorityError::Profile(format!(
                    "duplicate BBS issuer {}",
                    issuer.issuer_fingerprint
                )));
            }
        }

        let mut lease_issuers = BTreeSet::new();
        for authority in &self.lease_authorities {
            validate_non_empty(&authority.issuer, "leaseAuthorities.issuer")
                .map_err(ChioAuthorityError::Profile)?;
            validate_key_id_matches_public_key(
                authority.key_id.as_deref(),
                &authority.public_key,
                "leaseAuthorities.keyId",
            )
            .map_err(ChioAuthorityError::Profile)?;
            let (valid_from, valid_until) = required_window(
                authority.valid_from_unix_ms,
                authority.valid_until_unix_ms,
                "leaseAuthorities",
            )
            .map_err(ChioAuthorityError::Profile)?;
            if valid_until <= valid_from {
                return Err(ChioAuthorityError::Profile(
                    "lease authority validity window is empty".to_string(),
                ));
            }
            if authority.status.is_none() {
                return Err(ChioAuthorityError::Profile(
                    "lease authority status is required".to_string(),
                ));
            }
            if authority.allowed_action_classes.is_empty() {
                return Err(ChioAuthorityError::Profile(
                    "lease authority allowed action classes are required".to_string(),
                ));
            }
            if !lease_issuers.insert(&authority.issuer) {
                return Err(ChioAuthorityError::Profile(format!(
                    "duplicate lease authority {}",
                    authority.issuer
                )));
            }
        }

        let mut governance_kernels = BTreeSet::new();
        for authority in &self.governance_authorities {
            validate_non_empty(
                &authority.authorizing_kernel,
                "governanceAuthorities.authorizingKernel",
            )
            .map_err(ChioAuthorityError::Profile)?;
            validate_key_id_matches_public_key(
                authority.key_id.as_deref(),
                &authority.public_key,
                "governanceAuthorities.keyId",
            )
            .map_err(ChioAuthorityError::Profile)?;
            let (valid_from, valid_until) = required_window(
                authority.valid_from_unix_ms,
                authority.valid_until_unix_ms,
                "governanceAuthorities",
            )
            .map_err(ChioAuthorityError::Profile)?;
            if valid_until <= valid_from {
                return Err(ChioAuthorityError::Profile(
                    "governance authority validity window is empty".to_string(),
                ));
            }
            if authority.status.is_none() {
                return Err(ChioAuthorityError::Profile(
                    "governance authority status is required".to_string(),
                ));
            }
            if authority.allowed_case_kinds.is_empty() {
                return Err(ChioAuthorityError::Profile(
                    "governance authority allowed case kinds are required".to_string(),
                ));
            }
            if !governance_kernels.insert(&authority.authorizing_kernel) {
                return Err(ChioAuthorityError::Profile(format!(
                    "duplicate governance authority {}",
                    authority.authorizing_kernel
                )));
            }
        }

        let mut runtime_policy_issuer_keys = BTreeSet::new();
        let mut reserved_authority_keys = BTreeSet::new();
        for authority in &self.lease_authorities {
            reserved_authority_keys.insert(authority.public_key.to_hex());
        }
        for authority in &self.governance_authorities {
            reserved_authority_keys.insert(authority.public_key.to_hex());
        }
        reserved_authority_keys.insert(self.revocation_authority.public_key.to_hex());
        for public_key in &self.runtime_policy_issuer_public_keys {
            let public_key_hex = public_key.to_hex();
            if !runtime_policy_issuer_keys.insert(public_key_hex.clone()) {
                return Err(ChioAuthorityError::Profile(format!(
                    "duplicate runtime policy issuer public key {public_key_hex}"
                )));
            }
            if reserved_authority_keys.contains(&public_key_hex) {
                return Err(ChioAuthorityError::Profile(
                    "runtime policy issuer key must be distinct from lease, governance, and revocation authority keys".to_string(),
                ));
            }
        }

        self.revocation_authority.validate()?;
        Ok(())
    }

    fn lease_authority(
        &self,
        issuer: &str,
    ) -> Result<&ChioTrustedLeaseAuthority, ChioAuthorityError> {
        self.lease_authorities
            .iter()
            .find(|authority| authority.issuer == issuer)
            .ok_or_else(|| {
                ChioAuthorityError::Issuance(format!(
                    "lease authority {issuer} is not in the authority profile"
                ))
            })
    }

    fn governance_authority(
        &self,
        authorizing_kernel: &str,
    ) -> Result<&ChioTrustedGovernanceAuthority, ChioAuthorityError> {
        self.governance_authorities
            .iter()
            .find(|authority| authority.authorizing_kernel == authorizing_kernel)
            .ok_or_else(|| {
                ChioAuthorityError::Issuance(format!(
                    "governance authority {authorizing_kernel} is not in the authority profile"
                ))
            })
    }
}

impl ChioRevocationAuthority {
    fn validate(&self) -> Result<(), ChioAuthorityError> {
        validate_non_empty(&self.authority_id, "revocationAuthority.authorityId")
            .map_err(ChioAuthorityError::Profile)?;
        validate_key_id_matches_public_key(
            Some(&self.key_id),
            &self.public_key,
            "revocationAuthority.keyId",
        )
        .map_err(ChioAuthorityError::Profile)?;
        if self.valid_until_unix_ms <= self.valid_from_unix_ms {
            return Err(ChioAuthorityError::Profile(
                "revocation authority validity window is empty".to_string(),
            ));
        }
        Ok(())
    }
}

impl LocalAuthoritySigningKeysDocument {
    pub fn validate(&self) -> Result<(), ChioAuthorityError> {
        if self.schema != LOCAL_SIGNING_KEYS_SCHEMA {
            return Err(ChioAuthorityError::SigningKeys(format!(
                "local signing keys schema {} is unsupported",
                self.schema
            )));
        }
        validate_seed_entries(&self.lease_authority_seeds, "leaseAuthoritySeeds")?;
        validate_seed_entries(&self.governance_authority_seeds, "governanceAuthoritySeeds")?;
        keypair_from_seed_hex(&self.revocation_authority_seed_hex)
            .map_err(ChioAuthorityError::SigningKeys)?;
        Ok(())
    }
}

impl ChioIssuanceRequest {
    pub fn validate(&self) -> Result<(), ChioAuthorityError> {
        if self.schema != ISSUANCE_REQUEST_SCHEMA {
            return Err(ChioAuthorityError::Request(format!(
                "issuance request schema {} is unsupported",
                self.schema
            )));
        }
        validate_non_empty(&self.workflow_id, "workflowId").map_err(ChioAuthorityError::Request)?;
        validate_non_empty(&self.workflow_grant_id, "workflowGrantId")
            .map_err(ChioAuthorityError::Request)?;
        validate_non_empty(&self.lease_authority_issuer, "leaseAuthorityIssuer")
            .map_err(ChioAuthorityError::Request)?;
        validate_non_empty(
            &self.governance_authority_kernel,
            "governanceAuthorityKernel",
        )
        .map_err(ChioAuthorityError::Request)?;
        self.verification_context
            .validate()
            .map_err(|error| ChioAuthorityError::Request(error.to_string()))?;
        if self.steps.is_empty() {
            return Err(ChioAuthorityError::Request(
                "issuance request must contain at least one step".to_string(),
            ));
        }
        let mut lease_ids = BTreeSet::new();
        let mut step_indices = BTreeSet::new();
        for step in &self.steps {
            step.validate()?;
            if !lease_ids.insert(&step.lease_id) {
                return Err(ChioAuthorityError::Request(format!(
                    "duplicate lease id {}",
                    step.lease_id
                )));
            }
            if !step_indices.insert(step.step_index) {
                return Err(ChioAuthorityError::Request(format!(
                    "duplicate step index {}",
                    step.step_index
                )));
            }
        }
        Ok(())
    }
}

impl ChioIssuanceStepRequest {
    fn validate(&self) -> Result<(), ChioAuthorityError> {
        validate_non_empty(&self.lease_id, "steps.leaseId").map_err(ChioAuthorityError::Request)?;
        validate_non_empty(&self.tool_name, "steps.toolName")
            .map_err(ChioAuthorityError::Request)?;
        validate_non_empty(&self.peer_kernel_id, "steps.peerKernelId")
            .map_err(ChioAuthorityError::Request)?;
        validate_non_empty(&self.action_class_id, "steps.actionClassId")
            .map_err(ChioAuthorityError::Request)?;
        validate_non_empty(&self.subject, "steps.subject").map_err(ChioAuthorityError::Request)?;
        validate_sha256(&self.tool_args_hash, "steps.toolArgsHash")
            .map_err(ChioAuthorityError::Request)?;
        if self.lease_expires_at_unix_ms <= self.lease_issued_at_unix_ms {
            return Err(ChioAuthorityError::Request(format!(
                "lease {} expiry must be greater than issue time",
                self.lease_id
            )));
        }
        if self.destructive {
            if self.action_class != CapabilityLeaseActionClass::NarrowDestructive {
                return Err(ChioAuthorityError::Request(format!(
                    "destructive lease {} must use narrow_destructive action class",
                    self.lease_id
                )));
            }
            validate_non_empty(
                self.governance_receipt_id.as_deref().unwrap_or_default(),
                "steps.governanceReceiptId",
            )
            .map_err(ChioAuthorityError::Request)?;
            let issued = self.governance_issued_at_unix_ms.ok_or_else(|| {
                ChioAuthorityError::Request(format!(
                    "destructive lease {} is missing governance issue time",
                    self.lease_id
                ))
            })?;
            let expires = self.governance_expires_at_unix_ms.ok_or_else(|| {
                ChioAuthorityError::Request(format!(
                    "destructive lease {} is missing governance expiry time",
                    self.lease_id
                ))
            })?;
            if expires <= issued {
                return Err(ChioAuthorityError::Request(format!(
                    "governance receipt for lease {} has an empty validity window",
                    self.lease_id
                )));
            }
            validate_sha256(
                self.step_sha256.as_deref().unwrap_or_default(),
                "steps.stepSha256",
            )
            .map_err(ChioAuthorityError::Request)?;
        } else if self.governance_receipt_id.is_some()
            || self.governance_issued_at_unix_ms.is_some()
            || self.governance_expires_at_unix_ms.is_some()
            || self.step_sha256.is_some()
        {
            return Err(ChioAuthorityError::Request(format!(
                "non-destructive lease {} must not carry governance receipt fields",
                self.lease_id
            )));
        }
        Ok(())
    }
}

impl RevocationPublicationRequest {
    pub fn validate(&self) -> Result<(), ChioAuthorityError> {
        if self.schema != REVOCATION_PUBLICATION_REQUEST_SCHEMA {
            return Err(ChioAuthorityError::Revocation(format!(
                "revocation publication schema {} is unsupported",
                self.schema
            )));
        }
        validate_non_empty(&self.checkpoint_id, "checkpointId")
            .map_err(ChioAuthorityError::Revocation)?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ChioAuthorityError::Revocation(
                "revocation checkpoint expiry must be greater than issue time".to_string(),
            ));
        }
        if let Some(previous) = self.previous_epoch_height {
            if self.epoch_height <= previous {
                return Err(ChioAuthorityError::Revocation(
                    "revocation checkpoint epoch must be monotonic".to_string(),
                ));
            }
        }
        let mut fingerprints = BTreeSet::new();
        for fingerprint in &self.revoked_key_fingerprints {
            validate_sha256(fingerprint, "revokedKeyFingerprints")
                .map_err(ChioAuthorityError::Revocation)?;
            if !fingerprints.insert(fingerprint) {
                return Err(ChioAuthorityError::Revocation(format!(
                    "duplicate revoked key fingerprint {fingerprint}"
                )));
            }
        }
        Ok(())
    }
}

impl PeerPinsDocument {
    pub fn validate(&self) -> Result<(), ChioAuthorityError> {
        if self.schema != PEER_PINS_SCHEMA {
            return Err(ChioAuthorityError::TrustBundle(format!(
                "peer pins schema {} is unsupported",
                self.schema
            )));
        }
        if self.peers.is_empty() || self.vendors.is_empty() || self.action_classes.is_empty() {
            return Err(ChioAuthorityError::TrustBundle(
                "peer pins must include peers, vendors, and action classes".to_string(),
            ));
        }
        let mut peer_kernel_ids = BTreeSet::new();
        for peer in &self.peers {
            validate_non_empty(&peer.kernel_id, "peer.kernelId")
                .map_err(ChioAuthorityError::TrustBundle)?;
            peer.ladder_manifest_ref
                .validate()
                .map_err(|error| ChioAuthorityError::TrustBundle(error.to_string()))?;
            if !peer_kernel_ids.insert(peer.kernel_id.as_str()) {
                return Err(ChioAuthorityError::TrustBundle(
                    "duplicate peer kernel id".to_string(),
                ));
            }
        }

        let mut vendor_ids = BTreeSet::new();
        for vendor in &self.vendors {
            validate_non_empty(&vendor.vendor_id, "vendor.vendorId")
                .map_err(ChioAuthorityError::TrustBundle)?;
            if !vendor_ids.insert(vendor.vendor_id.as_str()) {
                return Err(ChioAuthorityError::TrustBundle(
                    "duplicate vendor id".to_string(),
                ));
            }
        }

        let mut action_class_ids = BTreeSet::new();
        let mut action_tool_names = BTreeSet::new();
        for action_class in &self.action_classes {
            validate_non_empty(&action_class.action_class_id, "actionClass.actionClassId")
                .map_err(ChioAuthorityError::TrustBundle)?;
            validate_non_empty(&action_class.tool_name, "actionClass.toolName")
                .map_err(ChioAuthorityError::TrustBundle)?;
            if !action_class_ids.insert(action_class.action_class_id.as_str()) {
                return Err(ChioAuthorityError::TrustBundle(
                    "duplicate action class id".to_string(),
                ));
            }
            if !action_tool_names.insert(action_class.tool_name.as_str()) {
                return Err(ChioAuthorityError::TrustBundle(
                    "duplicate action class tool name".to_string(),
                ));
            }
        }
        ensure_reference_workflow_classes(&self.action_classes)?;
        Ok(())
    }
}

pub fn authority_profile_from_json(
    json: &str,
) -> Result<AuthorityProfileDocument, ChioAuthorityError> {
    let document: AuthorityProfileDocument =
        serde_json::from_str(json).map_err(|error| ChioAuthorityError::Json(error.to_string()))?;
    document.validate()?;
    Ok(document)
}

pub fn issuance_request_from_json(json: &str) -> Result<ChioIssuanceRequest, ChioAuthorityError> {
    let document: ChioIssuanceRequest =
        serde_json::from_str(json).map_err(|error| ChioAuthorityError::Json(error.to_string()))?;
    document.validate()?;
    Ok(document)
}

pub fn signing_keys_from_json(
    json: &str,
) -> Result<LocalAuthoritySigningKeysDocument, ChioAuthorityError> {
    let document: LocalAuthoritySigningKeysDocument =
        serde_json::from_str(json).map_err(|error| ChioAuthorityError::Json(error.to_string()))?;
    document.validate()?;
    Ok(document)
}

pub fn revocation_publication_request_from_json(
    json: &str,
) -> Result<RevocationPublicationRequest, ChioAuthorityError> {
    let document: RevocationPublicationRequest =
        serde_json::from_str(json).map_err(|error| ChioAuthorityError::Json(error.to_string()))?;
    document.validate()?;
    Ok(document)
}

pub fn peer_pins_from_json(json: &str) -> Result<PeerPinsDocument, ChioAuthorityError> {
    let document: PeerPinsDocument =
        serde_json::from_str(json).map_err(|error| ChioAuthorityError::Json(error.to_string()))?;
    document.validate()?;
    Ok(document)
}

pub fn authority_profile_json(
    profile: &AuthorityProfileDocument,
) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(profile)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn issuance_request_json(request: &ChioIssuanceRequest) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(request)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn signing_keys_json(
    keys: &LocalAuthoritySigningKeysDocument,
) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(keys).map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn issuance_bundle_json(bundle: &ChioIssuanceBundle) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(bundle)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn revocation_publication_request_json(
    request: &RevocationPublicationRequest,
) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(request)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn peer_pins_json(document: &PeerPinsDocument) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(document)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn signed_revocation_checkpoint_json(
    checkpoint: &SignedChioRevocationCheckpoint,
) -> Result<String, ChioAuthorityError> {
    serde_json::to_string_pretty(checkpoint)
        .map_err(|error| ChioAuthorityError::Json(error.to_string()))
}

pub fn issue_authority_bundle(
    profile: &AuthorityProfileDocument,
    request: &ChioIssuanceRequest,
    signing_keys: &LocalAuthoritySigningKeysDocument,
) -> Result<ChioIssuanceBundle, ChioAuthorityError> {
    profile.validate()?;
    request.validate()?;
    signing_keys.validate()?;

    let lease_authority = profile.lease_authority(&request.lease_authority_issuer)?;
    let lease_key = signing_keys.lease_keypair(&lease_authority.issuer)?;
    ensure_key_matches_authority(
        &lease_key,
        &lease_authority.public_key,
        "lease authority",
        &lease_authority.issuer,
    )?;
    let (lease_valid_from, lease_valid_until) = authority_window(
        lease_authority.valid_from_unix_ms,
        lease_authority.valid_until_unix_ms,
        "lease authority",
    )?;
    ensure_status_active(
        lease_authority.status,
        "lease authority",
        &lease_authority.issuer,
    )?;

    let governance_authority =
        profile.governance_authority(&request.governance_authority_kernel)?;
    let governance_key =
        signing_keys.governance_keypair(&governance_authority.authorizing_kernel)?;
    ensure_key_matches_authority(
        &governance_key,
        &governance_authority.public_key,
        "governance authority",
        &governance_authority.authorizing_kernel,
    )?;
    let (governance_valid_from, governance_valid_until) = authority_window(
        governance_authority.valid_from_unix_ms,
        governance_authority.valid_until_unix_ms,
        "governance authority",
    )?;
    ensure_status_active(
        governance_authority.status,
        "governance authority",
        &governance_authority.authorizing_kernel,
    )?;
    if !governance_authority
        .allowed_case_kinds
        .contains(&GovernanceReceiptCaseKind::DestructiveAuthorization)
    {
        return Err(ChioAuthorityError::Issuance(format!(
            "governance authority {} is not allowed to sign destructive authorization receipts",
            governance_authority.authorizing_kernel
        )));
    }

    let mut leases = Vec::new();
    let mut scope_bindings = Vec::new();
    let mut governance_receipts = Vec::new();
    for step in &request.steps {
        if !lease_authority
            .allowed_action_classes
            .contains(&step.action_class)
        {
            return Err(ChioAuthorityError::Issuance(format!(
                "lease authority {} is not allowed to sign {:?} leases",
                lease_authority.issuer, step.action_class
            )));
        }
        ensure_interval_inside(
            step.lease_issued_at_unix_ms,
            step.lease_expires_at_unix_ms,
            lease_valid_from,
            lease_valid_until,
            "lease",
            &step.lease_id,
        )?;
        let scope_binding = LeaseScopeBindingArtifact {
            schema: LEASE_SCOPE_BINDING_SCHEMA.to_string(),
            lease_id: step.lease_id.clone(),
            workflow_id: request.workflow_id.clone(),
            workflow_grant_id: request.workflow_grant_id.clone(),
            step_index: step.step_index,
            tool_name: step.tool_name.clone(),
            peer_kernel_id: step.peer_kernel_id.clone(),
            action_class_id: step.action_class_id.clone(),
            subject: step.subject.clone(),
            action_class: step.action_class,
            tool_args_hash: step.tool_args_hash.clone(),
            destructive: step.destructive,
            issued_at_unix_ms: step.lease_issued_at_unix_ms,
            expires_at_unix_ms: step.lease_expires_at_unix_ms,
        };
        let scope_digest = scope_binding
            .scope_digest()
            .map_err(|error| ChioAuthorityError::Issuance(error.to_string()))?;
        let lease_body = CapabilityLeaseArtifact {
            schema: CAPABILITY_LEASE_SCHEMA_V1.to_string(),
            lease_id: step.lease_id.clone(),
            issuer: lease_authority.issuer.clone(),
            subject: step.subject.clone(),
            scope_digest,
            action_class: step.action_class,
            issued_at_unix_ms: step.lease_issued_at_unix_ms,
            expires_at_unix_ms: step.lease_expires_at_unix_ms,
        };
        lease_body
            .validate()
            .map_err(|error| ChioAuthorityError::Issuance(error.to_string()))?;
        let lease = SignedExportEnvelope::sign(lease_body, &lease_key)
            .map_err(|error| ChioAuthorityError::Issuance(error.to_string()))?;
        if step.destructive {
            let receipt_id = step.governance_receipt_id.clone().ok_or_else(|| {
                ChioAuthorityError::Issuance(format!(
                    "destructive lease {} is missing governance receipt id",
                    step.lease_id
                ))
            })?;
            let governance_issued = step.governance_issued_at_unix_ms.ok_or_else(|| {
                ChioAuthorityError::Issuance(format!(
                    "destructive lease {} is missing governance issue time",
                    step.lease_id
                ))
            })?;
            let governance_expires = step.governance_expires_at_unix_ms.ok_or_else(|| {
                ChioAuthorityError::Issuance(format!(
                    "destructive lease {} is missing governance expiry time",
                    step.lease_id
                ))
            })?;
            ensure_interval_inside(
                governance_issued,
                governance_expires,
                governance_valid_from,
                governance_valid_until,
                "governance receipt",
                &receipt_id,
            )?;
            ensure_interval_inside(
                governance_issued,
                governance_expires,
                step.lease_issued_at_unix_ms,
                step.lease_expires_at_unix_ms,
                "governance receipt",
                &receipt_id,
            )?;
            let step_sha256 = step.step_sha256.clone().ok_or_else(|| {
                ChioAuthorityError::Issuance(format!(
                    "destructive lease {} is missing step hash",
                    step.lease_id
                ))
            })?;
            let receipt_body = GovernanceReceiptArtifact {
                schema: GOVERNANCE_RECEIPT_SCHEMA_V1.to_string(),
                receipt_id,
                authorizing_kernel: governance_authority.authorizing_kernel.clone(),
                case_kind: GovernanceReceiptCaseKind::DestructiveAuthorization,
                authorized_lease_id: step.lease_id.clone(),
                workflow_id: request.workflow_id.clone(),
                step_sha256,
                issued_at_unix_ms: governance_issued,
                expires_at_unix_ms: governance_expires,
            };
            receipt_body
                .validate()
                .map_err(|error| ChioAuthorityError::Issuance(error.to_string()))?;
            governance_receipts.push(
                SignedExportEnvelope::sign(receipt_body, &governance_key)
                    .map_err(|error| ChioAuthorityError::Issuance(error.to_string()))?,
            );
        }
        leases.push(lease);
        scope_bindings.push(scope_binding);
    }

    Ok(ChioIssuanceBundle {
        schema: ISSUANCE_BUNDLE_SCHEMA.to_string(),
        capability_leases: leases,
        lease_scope_bindings: scope_bindings,
        governance_receipts,
        verification_context: request.verification_context.clone(),
    })
}

pub fn publish_revocation_checkpoint(
    profile: &AuthorityProfileDocument,
    request: &RevocationPublicationRequest,
    signing_keys: &LocalAuthoritySigningKeysDocument,
) -> Result<SignedChioRevocationCheckpoint, ChioAuthorityError> {
    profile.validate()?;
    request.validate()?;
    signing_keys.validate()?;
    if profile.revocation_authority.status != ChioAuthorityStatus::Active {
        return Err(ChioAuthorityError::Revocation(format!(
            "revocation authority {} is not active",
            profile.revocation_authority.authority_id
        )));
    }
    ensure_interval_inside(
        request.issued_at_unix_ms,
        request.expires_at_unix_ms,
        profile.revocation_authority.valid_from_unix_ms,
        profile.revocation_authority.valid_until_unix_ms,
        "revocation checkpoint",
        &request.checkpoint_id,
    )?;
    let revocation_key = keypair_from_seed_hex(&signing_keys.revocation_authority_seed_hex)
        .map_err(ChioAuthorityError::SigningKeys)?;
    ensure_key_matches_authority(
        &revocation_key,
        &profile.revocation_authority.public_key,
        "revocation authority",
        &profile.revocation_authority.authority_id,
    )?;
    let body = ChioRevocationCheckpoint {
        schema: CHIO_FEDERATION_REVOCATION_CHECKPOINT_SCHEMA_V1.to_string(),
        checkpoint_id: request.checkpoint_id.clone(),
        issued_at_unix_ms: request.issued_at_unix_ms,
        expires_at_unix_ms: request.expires_at_unix_ms,
        epoch_height: request.epoch_height,
        revoked_key_fingerprints: request.revoked_key_fingerprints.clone(),
    };
    SignedExportEnvelope::sign(body, &revocation_key)
        .map_err(|error| ChioAuthorityError::Revocation(error.to_string()))
}

pub fn assemble_verifier_trust_bundle(
    profile: &AuthorityProfileDocument,
    peer_pins: &PeerPinsDocument,
    workflow_intersection: &WorkflowIntersectionArtifact,
    disclosure_policy: ChioDisclosurePolicy,
    checkpoint: SignedChioRevocationCheckpoint,
) -> Result<ChioVerifierTrustBundleDocument, ChioAuthorityError> {
    profile.validate()?;
    peer_pins.validate()?;
    let workflow_intersection_sha256 = canonical_sha256(workflow_intersection)?;
    let trusted_workflow_intersection = ChioTrustedWorkflowIntersection {
        intersection_id: workflow_intersection.intersection_id.clone(),
        sha256: workflow_intersection_sha256,
    };
    let document = ChioVerifierTrustBundleDocument {
        schema: CHIO_FEDERATION_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
        trusted_bbs_issuers: profile.trusted_bbs_issuers.clone(),
        peers: peer_pins.peers.clone(),
        vendors: peer_pins.vendors.clone(),
        action_classes: peer_pins.action_classes.clone(),
        workflow_intersections: vec![trusted_workflow_intersection],
        runtime_policy_issuer_public_keys: profile.runtime_policy_issuer_public_keys.clone(),
        lease_authorities: profile.lease_authorities.clone(),
        governance_authorities: profile.governance_authorities.clone(),
        disclosure_policy: Some(disclosure_policy),
        revocation: ChioRevocationMaterial::Checkpoint(Box::new(checkpoint)),
    };
    ChioVerifierTrustBundle::from_document(document.clone())
        .map_err(|error| ChioAuthorityError::TrustBundle(error.to_string()))?;
    Ok(document)
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChioAuthorityError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChioAuthorityError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn required_window(
    valid_from: Option<u64>,
    valid_until: Option<u64>,
    label: &str,
) -> Result<(u64, u64), String> {
    let from = valid_from.ok_or_else(|| format!("{label} validFromUnixMs is required"))?;
    let until = valid_until.ok_or_else(|| format!("{label} validUntilUnixMs is required"))?;
    Ok((from, until))
}

fn authority_window(
    valid_from: Option<u64>,
    valid_until: Option<u64>,
    label: &str,
) -> Result<(u64, u64), ChioAuthorityError> {
    let (from, until) =
        required_window(valid_from, valid_until, label).map_err(ChioAuthorityError::Issuance)?;
    if until <= from {
        return Err(ChioAuthorityError::Issuance(format!(
            "{label} validity window is empty"
        )));
    }
    Ok((from, until))
}

fn ensure_status_active(
    status: Option<ChioAuthorityStatus>,
    label: &str,
    id: &str,
) -> Result<(), ChioAuthorityError> {
    if status != Some(ChioAuthorityStatus::Active) {
        return Err(ChioAuthorityError::Issuance(format!(
            "{label} {id} is not active"
        )));
    }
    Ok(())
}

fn ensure_interval_inside(
    issued_at: u64,
    expires_at: u64,
    valid_from: u64,
    valid_until: u64,
    label: &str,
    id: &str,
) -> Result<(), ChioAuthorityError> {
    if expires_at <= issued_at {
        return Err(ChioAuthorityError::Issuance(format!(
            "{label} {id} expiry must be greater than issue time"
        )));
    }
    if issued_at < valid_from || expires_at > valid_until {
        return Err(ChioAuthorityError::Issuance(format!(
            "{label} {id} is outside the authority validity window"
        )));
    }
    Ok(())
}

fn ensure_key_matches_authority(
    keypair: &Keypair,
    public_key: &PublicKey,
    label: &str,
    id: &str,
) -> Result<(), ChioAuthorityError> {
    if &keypair.public_key() != public_key {
        return Err(ChioAuthorityError::SigningKeys(format!(
            "{label} {id} signing seed does not match authority public key"
        )));
    }
    Ok(())
}

fn validate_seed_entries(entries: &[NamedSeedHex], label: &str) -> Result<(), ChioAuthorityError> {
    let mut ids = BTreeSet::new();
    for entry in entries {
        validate_non_empty(&entry.id, label).map_err(ChioAuthorityError::SigningKeys)?;
        keypair_from_seed_hex(&entry.seed_hex).map_err(ChioAuthorityError::SigningKeys)?;
        if !ids.insert(&entry.id) {
            return Err(ChioAuthorityError::SigningKeys(format!(
                "duplicate signing seed id {}",
                entry.id
            )));
        }
    }
    Ok(())
}

impl LocalAuthoritySigningKeysDocument {
    fn lease_keypair(&self, issuer: &str) -> Result<Keypair, ChioAuthorityError> {
        keypair_for_named_seed(&self.lease_authority_seeds, issuer, "lease authority")
    }

    fn governance_keypair(&self, kernel: &str) -> Result<Keypair, ChioAuthorityError> {
        keypair_for_named_seed(
            &self.governance_authority_seeds,
            kernel,
            "governance authority",
        )
    }
}

fn keypair_for_named_seed(
    entries: &[NamedSeedHex],
    id: &str,
    label: &str,
) -> Result<Keypair, ChioAuthorityError> {
    let entry = entries.iter().find(|entry| entry.id == id).ok_or_else(|| {
        ChioAuthorityError::SigningKeys(format!("{label} {id} has no local signing seed"))
    })?;
    keypair_from_seed_hex(&entry.seed_hex).map_err(ChioAuthorityError::SigningKeys)
}

fn keypair_from_seed_hex(seed_hex: &str) -> Result<Keypair, String> {
    Keypair::from_seed_hex(seed_hex).map_err(|error| error.to_string())
}

fn ensure_reference_workflow_classes(
    action_classes: &[ChioTrustedActionClass],
) -> Result<(), ChioAuthorityError> {
    let ids: BTreeSet<&str> = action_classes
        .iter()
        .map(|class| class.action_class_id.as_str())
        .collect();
    for required in [
        WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID,
        WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID,
    ] {
        if !ids.contains(required) {
            return Err(ChioAuthorityError::TrustBundle(format!(
                "trust bundle action classes must include {required}"
            )));
        }
    }
    Ok(())
}

fn validate_key_id_matches_public_key(
    value: Option<&str>,
    public_key: &PublicKey,
    field: &str,
) -> Result<(), String> {
    let key_id = value.ok_or_else(|| format!("{field} is required"))?;
    validate_non_empty(key_id, field)?;
    let expected = Keyid::from_public_key(public_key).0;
    if key_id != expected {
        return Err(format!("{field} does not match public key"));
    }
    Ok(())
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), String> {
    if !is_sha256_hex_shape(value) {
        return Err(format!("{field} must be a SHA-256 lowercase hex digest"));
    }
    validate_lowercase_hex(value, field)
}

fn is_sha256_hex_shape(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_hex(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(format!(
            "{field} must be non-empty even-length lowercase hex"
        ));
    }
    validate_lowercase_hex(value, field)
}

fn validate_lowercase_hex(value: &str, field: &str) -> Result<(), String> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must be lowercase hex"));
    }
    Ok(())
}

impl From<ChioAuthorityError> for ChioPackageError {
    fn from(value: ChioAuthorityError) -> Self {
        ChioPackageError::Json(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use chio_attest_buyer_core::{
        ChioAuthorityStatus, ChioDisclosurePolicy, ChioTrustedActionClass,
        ChioTrustedGovernanceAuthority, ChioTrustedLeaseAuthority, ChioVerifierTrustBundle,
        ChioVerifierTrustBundleDocument, TrustedBbsIssuer, VendorKeyBinding,
        WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID, WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID,
    };
    use chio_core_types::crypto::{Keypair, PublicKey};
    use chio_federation::{Keyid, LadderManifestRef};
    use chio_governance::{CapabilityLeaseActionClass, GovernanceReceiptCaseKind};

    use crate::{
        assemble_verifier_trust_bundle, issue_authority_bundle, publish_revocation_checkpoint,
        AuthorityProfileDocument, ChioIssuanceRequest, ChioIssuanceStepRequest,
        LocalAuthoritySigningKeysDocument, PeerPinsDocument, RevocationPublicationRequest,
        AUTHORITY_PROFILE_SCHEMA, ISSUANCE_BUNDLE_SCHEMA, ISSUANCE_REQUEST_SCHEMA,
        LOCAL_SIGNING_KEYS_SCHEMA, PEER_PINS_SCHEMA, REVOCATION_PUBLICATION_REQUEST_SCHEMA,
    };

    const NOW: u64 = 1_766_000_000_000;

    fn key(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }

    fn key_id(public_key: &PublicKey) -> String {
        Keyid::from_public_key(public_key).0
    }

    fn different_key_id(public_key: &PublicKey) -> String {
        let current = key_id(public_key);
        let replacement = if current.starts_with('f') { '0' } else { 'f' };
        format!("{replacement}{}", &current[1..])
    }

    #[test]
    fn sha256_hex_shape_helper_accepts_exact_hex_before_lowercase_validation() {
        assert!(crate::is_sha256_hex_shape(&"a".repeat(64)));
        assert!(crate::is_sha256_hex_shape(&"A".repeat(64)));
        assert!(!crate::is_sha256_hex_shape(&"a".repeat(63)));
        assert!(!crate::is_sha256_hex_shape(&format!("{}g", "a".repeat(63))));
    }

    fn profile() -> AuthorityProfileDocument {
        let lease_key = key(11);
        let governance_key = key(12);
        let revocation_key = key(13);
        let runtime_policy_issuer_key = key(42);
        AuthorityProfileDocument {
            schema: AUTHORITY_PROFILE_SCHEMA.to_string(),
            trusted_bbs_issuers: vec![TrustedBbsIssuer {
                issuer_fingerprint: "a".repeat(64),
                public_key_hex: "b".repeat(96),
            }],
            lease_authorities: vec![ChioTrustedLeaseAuthority {
                issuer: "did:chio:buyer-kernel".to_string(),
                key_id: Some(key_id(&lease_key.public_key())),
                public_key: lease_key.public_key(),
                valid_from_unix_ms: Some(NOW - 60_000),
                valid_until_unix_ms: Some(NOW + 60_000),
                status: Some(ChioAuthorityStatus::Active),
                allowed_action_classes: vec![
                    CapabilityLeaseActionClass::DelegatedAction,
                    CapabilityLeaseActionClass::NarrowDestructive,
                ],
            }],
            governance_authorities: vec![ChioTrustedGovernanceAuthority {
                authorizing_kernel: "did:chio:buyer-governance".to_string(),
                key_id: Some(key_id(&governance_key.public_key())),
                public_key: governance_key.public_key(),
                valid_from_unix_ms: Some(NOW - 60_000),
                valid_until_unix_ms: Some(NOW + 60_000),
                status: Some(ChioAuthorityStatus::Active),
                allowed_case_kinds: vec![GovernanceReceiptCaseKind::DestructiveAuthorization],
            }],
            runtime_policy_issuer_public_keys: vec![runtime_policy_issuer_key.public_key()],
            revocation_authority: crate::ChioRevocationAuthority {
                authority_id: "did:chio:buyer-kernel".to_string(),
                key_id: key_id(&revocation_key.public_key()),
                public_key: revocation_key.public_key(),
                valid_from_unix_ms: NOW - 60_000,
                valid_until_unix_ms: NOW + 60_000,
                status: ChioAuthorityStatus::Active,
            },
        }
    }

    fn signing_keys() -> LocalAuthoritySigningKeysDocument {
        LocalAuthoritySigningKeysDocument {
            schema: LOCAL_SIGNING_KEYS_SCHEMA.to_string(),
            lease_authority_seeds: vec![crate::NamedSeedHex {
                id: "did:chio:buyer-kernel".to_string(),
                seed_hex: hex::encode([11u8; 32]),
            }],
            governance_authority_seeds: vec![crate::NamedSeedHex {
                id: "did:chio:buyer-governance".to_string(),
                seed_hex: hex::encode([12u8; 32]),
            }],
            revocation_authority_seed_hex: hex::encode([13u8; 32]),
        }
    }

    fn request() -> ChioIssuanceRequest {
        ChioIssuanceRequest {
            schema: ISSUANCE_REQUEST_SCHEMA.to_string(),
            workflow_id: "wf-001".to_string(),
            workflow_grant_id: "cap-workflow".to_string(),
            lease_authority_issuer: "did:chio:buyer-kernel".to_string(),
            governance_authority_kernel: "did:chio:buyer-governance".to_string(),
            verification_context: chio_attest_buyer_core::ChioVerificationContext {
                schema: chio_attest_buyer_core::VERIFICATION_CONTEXT_SCHEMA.to_string(),
                audience: "buyer-auditor".to_string(),
                challenge: "challenge-001".to_string(),
                proof_purpose: "workflow-disclosure".to_string(),
                issued_at_unix_ms: NOW - 1_000,
                expires_at_unix_ms: NOW + 30_000,
            },
            steps: vec![
                ChioIssuanceStepRequest {
                    lease_id: "lease-read".to_string(),
                    step_index: 0,
                    tool_name: "read_refund_case".to_string(),
                    peer_kernel_id: "did:chio:vendor-a".to_string(),
                    action_class_id: "read_refund_case".to_string(),
                    subject: "did:chio:vendor-a".to_string(),
                    action_class: CapabilityLeaseActionClass::DelegatedAction,
                    tool_args_hash: "c".repeat(64),
                    destructive: false,
                    lease_issued_at_unix_ms: NOW - 5_000,
                    lease_expires_at_unix_ms: NOW + 20_000,
                    governance_receipt_id: None,
                    governance_issued_at_unix_ms: None,
                    governance_expires_at_unix_ms: None,
                    step_sha256: None,
                },
                ChioIssuanceStepRequest {
                    lease_id: "lease-stage-refund".to_string(),
                    step_index: 1,
                    tool_name: "stage_refund".to_string(),
                    peer_kernel_id: "did:chio:vendor-b".to_string(),
                    action_class_id: "stage_refund".to_string(),
                    subject: "did:chio:vendor-b".to_string(),
                    action_class: CapabilityLeaseActionClass::NarrowDestructive,
                    tool_args_hash: "d".repeat(64),
                    destructive: true,
                    lease_issued_at_unix_ms: NOW - 5_000,
                    lease_expires_at_unix_ms: NOW + 20_000,
                    governance_receipt_id: Some("gov-stage-refund".to_string()),
                    governance_issued_at_unix_ms: Some(NOW - 4_000),
                    governance_expires_at_unix_ms: Some(NOW + 10_000),
                    step_sha256: Some("e".repeat(64)),
                },
            ],
        }
    }

    fn peer_pins() -> PeerPinsDocument {
        PeerPinsDocument {
            schema: PEER_PINS_SCHEMA.to_string(),
            peers: vec![chio_attest_buyer_core::PeerLadderBinding {
                kernel_id: "did:chio:vendor-a".to_string(),
                public_key: key(21).public_key(),
                ladder_manifest_ref: LadderManifestRef {
                    manifest_id: "ladder:vendor-a".to_string(),
                    sha256: "f".repeat(64),
                    issued_at_unix_ms: NOW - 1_000,
                    expires_at_unix_ms: NOW + 60_000,
                },
            }],
            vendors: vec![VendorKeyBinding {
                vendor_id: "vendor-a".to_string(),
                public_key: key(21).public_key(),
            }],
            action_classes: vec![
                ChioTrustedActionClass {
                    action_class_id: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                    tool_name: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                    kind: chio_attest_buyer_core::ChioActionClassKind::Routine,
                },
                ChioTrustedActionClass {
                    action_class_id: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                    tool_name: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                    kind: chio_attest_buyer_core::ChioActionClassKind::Routine,
                },
            ],
        }
    }

    #[test]
    fn authority_profile_requires_runtime_policy_issuer_roots() {
        let mut document = profile();
        document.runtime_policy_issuer_public_keys.clear();
        let error = document.validate().unwrap_err();
        assert!(error.to_string().contains("runtime policy issuers"));
    }

    #[test]
    fn authority_profile_rejects_duplicate_runtime_policy_issuer_keys() {
        let mut document = profile();
        let duplicate = document.runtime_policy_issuer_public_keys[0].clone();
        document.runtime_policy_issuer_public_keys.push(duplicate);
        let error = document.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("duplicate runtime policy issuer public key"));
    }

    #[test]
    fn authority_profile_rejects_runtime_policy_issuer_overlapping_authority_keys() {
        let mut document = profile();
        document.runtime_policy_issuer_public_keys =
            vec![document.lease_authorities[0].public_key.clone()];
        let error = document.validate().unwrap_err();
        assert!(error.to_string().contains(
            "runtime policy issuer key must be distinct from lease, governance, and revocation authority keys"
        ));
    }

    #[test]
    fn issuer_outputs_verifier_compatible_lease_and_governance_artifacts() {
        let bundle =
            issue_authority_bundle(&profile(), &request(), &signing_keys()).expect("issue bundle");
        assert_eq!(bundle.schema, ISSUANCE_BUNDLE_SCHEMA);
        assert_eq!(bundle.capability_leases.len(), 2);
        assert_eq!(bundle.lease_scope_bindings.len(), 2);
        assert_eq!(bundle.governance_receipts.len(), 1);
        assert_eq!(
            bundle.capability_leases[0].body.scope_digest,
            bundle.lease_scope_bindings[0].scope_digest().unwrap()
        );
        assert_eq!(
            bundle.governance_receipts[0].body.authorized_lease_id,
            "lease-stage-refund"
        );
        assert_eq!(bundle.verification_context.challenge, "challenge-001");
    }

    #[test]
    fn chio_federation_authority_outputs_chio_native_wrapper_schemas() {
        let profile = profile();
        assert_eq!(profile.schema, "chio.federation.authority-profile.v1");

        let request = request();
        assert_eq!(request.schema, "chio.federation.issuance-request.v1");
        assert_eq!(
            request.verification_context.schema,
            "chio.federation.verification-context.v1"
        );

        let keys = signing_keys();
        assert_eq!(keys.schema, "chio.federation.local-signing-keys.v1");

        let bundle = issue_authority_bundle(&profile, &request, &keys).expect("issue bundle");
        assert_eq!(bundle.schema, "chio.federation.issuance-bundle.v1");
        assert_eq!(
            bundle.verification_context.schema,
            "chio.federation.verification-context.v1"
        );
        assert!(bundle
            .lease_scope_bindings
            .iter()
            .all(|binding| binding.schema == "chio.federation.lease-scope-binding.v1"));
        assert!(bundle
            .capability_leases
            .iter()
            .all(|lease| lease.body.schema == "chio.capability-lease.v1"));
        assert!(bundle
            .governance_receipts
            .iter()
            .all(|receipt| receipt.body.schema == "chio.governance-receipt.v1"));

        let checkpoint_request = RevocationPublicationRequest {
            schema: "chio.federation.revocation-publication-request.v1".to_string(),
            checkpoint_id: "checkpoint-001".to_string(),
            issued_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 60_000,
            epoch_height: 11,
            previous_epoch_height: Some(10),
            revoked_key_fingerprints: Vec::new(),
        };
        let checkpoint = publish_revocation_checkpoint(&profile, &checkpoint_request, &keys)
            .expect("checkpoint");
        assert_eq!(
            checkpoint.body.schema,
            "chio.federation.revocation-checkpoint.v1"
        );

        let peer_pins = PeerPinsDocument {
            schema: "chio.federation.peer-pins.v1".to_string(),
            peers: vec![chio_attest_buyer_core::PeerLadderBinding {
                kernel_id: "did:chio:vendor-a".to_string(),
                public_key: key(21).public_key(),
                ladder_manifest_ref: LadderManifestRef {
                    manifest_id: "ladder:vendor-a".to_string(),
                    sha256: "f".repeat(64),
                    issued_at_unix_ms: NOW - 1_000,
                    expires_at_unix_ms: NOW + 60_000,
                },
            }],
            vendors: vec![VendorKeyBinding {
                vendor_id: "vendor-a".to_string(),
                public_key: key(21).public_key(),
            }],
            action_classes: vec![
                ChioTrustedActionClass {
                    action_class_id: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                    tool_name: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                    kind: chio_attest_buyer_core::ChioActionClassKind::Routine,
                },
                ChioTrustedActionClass {
                    action_class_id: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                    tool_name: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                    kind: chio_attest_buyer_core::ChioActionClassKind::Routine,
                },
            ],
        };
        let workflow_intersection = chio_attest_buyer_core::WorkflowIntersectionArtifact {
            schema: chio_attest_buyer_core::WORKFLOW_INTERSECTION_SCHEMA.to_string(),
            intersection_id: "workflow-intersection:001".to_string(),
            workflow_id: "wf-001".to_string(),
            workflow_grant_id: "cap-workflow".to_string(),
            pairwise_intersection_refs: Vec::new(),
            step_class_bindings: Vec::new(),
            required_vendor_signers: Vec::new(),
            aggregate_workflow_receipt_sha256: "a".repeat(64),
        };
        let trust_bundle = assemble_verifier_trust_bundle(
            &profile,
            &peer_pins,
            &workflow_intersection,
            ChioDisclosurePolicy {
                projection_version: "chio.bbs-projection.workflow.v1".to_string(),
                ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
                message_count: 14,
                required_disclosed_indices: vec![4, 8, 9, 10],
                required_disclosed_fields: vec![
                    "id".to_string(),
                    "session_id".to_string(),
                    "skill_id".to_string(),
                    "skill_version".to_string(),
                ],
            },
            checkpoint,
        )
        .expect("trust bundle assembles");
        assert_eq!(
            trust_bundle.schema,
            "chio.federation.verifier-trust-bundle.v1"
        );
        ChioVerifierTrustBundle::from_document(trust_bundle)
            .expect("Chio-native trust bundle remains verifier compatible");
    }

    #[test]
    fn peer_pins_reject_duplicate_peer_kernel_ids_before_bundle_assembly() {
        let mut peer_pins = peer_pins();
        peer_pins.peers.push(peer_pins.peers[0].clone());

        let error = peer_pins.validate().unwrap_err();

        assert!(error.to_string().contains("duplicate peer kernel id"));
    }

    #[test]
    fn inactive_authority_fails_before_signing() {
        let mut profile = profile();
        profile.lease_authorities[0].status = Some(ChioAuthorityStatus::Inactive);
        let error = issue_authority_bundle(&profile, &request(), &signing_keys()).unwrap_err();
        assert!(error.to_string().contains("not active"));
    }

    #[test]
    fn profile_requires_authority_key_ids() {
        let mut lease_profile = profile();
        lease_profile.lease_authorities[0].key_id = None;
        let error = lease_profile.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("leaseAuthorities.keyId is required"));

        let mut governance_profile = profile();
        governance_profile.governance_authorities[0].key_id = None;
        let error = governance_profile.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("governanceAuthorities.keyId is required"));
    }

    #[test]
    fn profile_rejects_authority_key_ids_that_do_not_match_public_keys() {
        let mut lease_profile = profile();
        lease_profile.lease_authorities[0].key_id = Some(different_key_id(
            &lease_profile.lease_authorities[0].public_key,
        ));
        let error = lease_profile.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("leaseAuthorities.keyId does not match public key"));

        let mut governance_profile = profile();
        governance_profile.governance_authorities[0].key_id = Some(different_key_id(
            &governance_profile.governance_authorities[0].public_key,
        ));
        let error = governance_profile.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("governanceAuthorities.keyId does not match public key"));

        let mut revocation_profile = profile();
        revocation_profile.revocation_authority.key_id =
            different_key_id(&revocation_profile.revocation_authority.public_key);
        let error = revocation_profile.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("revocationAuthority.keyId does not match public key"));
    }

    #[test]
    fn checkpoint_rejects_non_monotonic_epoch() {
        let request = RevocationPublicationRequest {
            schema: REVOCATION_PUBLICATION_REQUEST_SCHEMA.to_string(),
            checkpoint_id: "checkpoint-001".to_string(),
            issued_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 60_000,
            epoch_height: 10,
            previous_epoch_height: Some(10),
            revoked_key_fingerprints: Vec::new(),
        };
        let error =
            publish_revocation_checkpoint(&profile(), &request, &signing_keys()).unwrap_err();
        assert!(error.to_string().contains("monotonic"));
    }

    #[test]
    fn trust_bundle_assembly_requires_reference_workflow_classes() {
        let checkpoint_request = RevocationPublicationRequest {
            schema: REVOCATION_PUBLICATION_REQUEST_SCHEMA.to_string(),
            checkpoint_id: "checkpoint-001".to_string(),
            issued_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 60_000,
            epoch_height: 11,
            previous_epoch_height: Some(10),
            revoked_key_fingerprints: Vec::new(),
        };
        let checkpoint =
            publish_revocation_checkpoint(&profile(), &checkpoint_request, &signing_keys())
                .expect("checkpoint");
        let peer_pins = PeerPinsDocument {
            schema: PEER_PINS_SCHEMA.to_string(),
            peers: vec![chio_attest_buyer_core::PeerLadderBinding {
                kernel_id: "did:chio:vendor-a".to_string(),
                public_key: key(21).public_key(),
                ladder_manifest_ref: LadderManifestRef {
                    manifest_id: "ladder:vendor-a".to_string(),
                    sha256: "f".repeat(64),
                    issued_at_unix_ms: NOW - 1_000,
                    expires_at_unix_ms: NOW + 60_000,
                },
            }],
            vendors: vec![VendorKeyBinding {
                vendor_id: "vendor-a".to_string(),
                public_key: key(21).public_key(),
            }],
            action_classes: vec![
                ChioTrustedActionClass {
                    action_class_id: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                    tool_name: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
                    kind: chio_attest_buyer_core::ChioActionClassKind::Routine,
                },
                ChioTrustedActionClass {
                    action_class_id: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                    tool_name: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
                    kind: chio_attest_buyer_core::ChioActionClassKind::Routine,
                },
            ],
        };
        let workflow_intersection = chio_attest_buyer_core::WorkflowIntersectionArtifact {
            schema: chio_attest_buyer_core::WORKFLOW_INTERSECTION_SCHEMA.to_string(),
            intersection_id: "workflow-intersection:001".to_string(),
            workflow_id: "wf-001".to_string(),
            workflow_grant_id: "cap-workflow".to_string(),
            pairwise_intersection_refs: Vec::new(),
            step_class_bindings: Vec::new(),
            required_vendor_signers: Vec::new(),
            aggregate_workflow_receipt_sha256: "a".repeat(64),
        };
        let disclosure_policy = ChioDisclosurePolicy {
            projection_version: "chio.bbs-projection.workflow.v1".to_string(),
            ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
            message_count: 14,
            required_disclosed_indices: vec![4, 8, 9, 10],
            required_disclosed_fields: vec![
                "id".to_string(),
                "session_id".to_string(),
                "skill_id".to_string(),
                "skill_version".to_string(),
            ],
        };
        let document: ChioVerifierTrustBundleDocument = assemble_verifier_trust_bundle(
            &profile(),
            &peer_pins,
            &workflow_intersection,
            disclosure_policy,
            checkpoint,
        )
        .expect("trust bundle assembles");
        ChioVerifierTrustBundle::from_document(document).expect("strict trust bundle parses");

        let mut missing_class = peer_pins;
        missing_class
            .action_classes
            .retain(|class| class.action_class_id != WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID);
        let error = assemble_verifier_trust_bundle(
            &profile(),
            &missing_class,
            &workflow_intersection,
            ChioDisclosurePolicy {
                projection_version: "chio.bbs-projection.workflow.v1".to_string(),
                ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
                message_count: 14,
                required_disclosed_indices: vec![4, 8, 9, 10],
                required_disclosed_fields: vec![
                    "id".to_string(),
                    "session_id".to_string(),
                    "skill_id".to_string(),
                    "skill_version".to_string(),
                ],
            },
            publish_revocation_checkpoint(&profile(), &checkpoint_request, &signing_keys())
                .expect("checkpoint"),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains(WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID));
    }
}
