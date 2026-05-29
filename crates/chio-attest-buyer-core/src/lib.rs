//! Offline Chio buyer and auditor proof package verification.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chio_core_types::canonical::{canonical_json_bytes, canonical_json_string};
use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_core_types::receipt::{ChioReceipt, SignedExportEnvelope};
use chio_federation::{
    verify_chio_bilateral_invocation, ActionClassKind, ChioBilateralVerifierConfig, DsseEnvelope,
    InMemoryGovernanceReceiptStore, InMemoryLeaseRegistry, InMemoryReceiptStore, Keyid,
    LadderManifestRef, PeerPinSet, PinnedEpoch, PinnedPeer, ResolvedGovernanceReceipt,
    ResolvedLease, RevocationOracle, UnknownActionClassPolicy, VerifierConfig,
};
use chio_governance::{
    verify_capability_lease, verify_destructive_authorization, verify_step_governance_boundary,
    CapabilityLeaseActionClass, GovernanceReceiptCaseKind, SignedCapabilityLease,
    SignedGovernanceReceipt,
};
use chio_selective_disclosure::{
    project_workflow_receipt_body, verify_selective_disclosure_proof, InMemoryIssuerRegistry,
    Projection, SelectiveDisclosureProof, BBS_CIPHERSUITE_SHA256, PROJECTION_VERSION_WORKFLOW_V1,
};
use chio_workflow::receipt::{VendorSignatureRequirement, WorkflowReceipt};
use serde::{Deserialize, Serialize};

pub const PROOF_PACKAGE_SCHEMA: &str = "chio.attest.proof-package.v1";
pub const VERIFIER_REPORT_SCHEMA: &str = "chio.attest.verifier-report.v1";
pub const TRUSTED_ISSUER_REGISTRY_SCHEMA: &str = "chio.attest.trusted-issuer-registry.v1";
pub const VERIFIER_TRUST_BUNDLE_SCHEMA: &str = "chio.federation.verifier-trust-bundle.v1";
pub const REVOCATION_CHECKPOINT_SCHEMA: &str = "chio.federation.revocation-checkpoint.v1";
pub const VERIFICATION_CONTEXT_SCHEMA: &str = "chio.federation.verification-context.v1";
pub const WORKFLOW_INTERSECTION_SCHEMA: &str = "chio.attest.workflow-intersection.v1";
pub const LEASE_SCOPE_BINDING_SCHEMA: &str = "chio.federation.lease-scope-binding.v1";
pub const CHIO_FEDERATION_VERIFIER_TRUST_BUNDLE_SCHEMA: &str = VERIFIER_TRUST_BUNDLE_SCHEMA;
pub const CHIO_FEDERATION_REVOCATION_CHECKPOINT_SCHEMA_V1: &str = REVOCATION_CHECKPOINT_SCHEMA;
pub const WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID: &str = "workflow.grant_issue";
pub const WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID: &str = "workflow.aggregate_publish";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedBbsIssuer {
    pub issuer_fingerprint: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedIssuerRegistryDocument {
    pub schema: String,
    pub issuers: Vec<TrustedBbsIssuer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuerRegistry {
    public_keys: BTreeMap<String, String>,
}

impl TrustedIssuerRegistry {
    pub fn from_document(
        document: TrustedIssuerRegistryDocument,
    ) -> Result<Self, ChioPackageError> {
        if document.schema != TRUSTED_ISSUER_REGISTRY_SCHEMA {
            return Err(ChioPackageError::TrustedIssuer(format!(
                "trusted issuer registry schema {} is unsupported",
                document.schema
            )));
        }
        if document.issuers.is_empty() {
            return Err(ChioPackageError::TrustedIssuer(
                "trusted issuer registry is empty".to_string(),
            ));
        }

        let mut public_keys = BTreeMap::new();
        for issuer in document.issuers {
            validate_non_empty(&issuer.issuer_fingerprint, "issuerFingerprint")?;
            validate_non_empty(&issuer.public_key_hex, "publicKeyHex")?;
            if !is_lower_hex(&issuer.issuer_fingerprint) {
                return Err(ChioPackageError::TrustedIssuer(format!(
                    "issuerFingerprint {} is not lowercase hex",
                    issuer.issuer_fingerprint
                )));
            }
            if !is_lower_hex(&issuer.public_key_hex) || issuer.public_key_hex.len() % 2 != 0 {
                return Err(ChioPackageError::TrustedIssuer(format!(
                    "publicKeyHex for issuer {} is not lowercase even-length hex",
                    issuer.issuer_fingerprint
                )));
            }
            if public_keys
                .insert(issuer.issuer_fingerprint.clone(), issuer.public_key_hex)
                .is_some()
            {
                return Err(ChioPackageError::TrustedIssuer(format!(
                    "duplicate issuer fingerprint {}",
                    issuer.issuer_fingerprint
                )));
            }
        }

        Ok(Self { public_keys })
    }

    fn public_key_hex(&self, issuer_fingerprint: &str) -> Option<&str> {
        self.public_keys
            .get(issuer_fingerprint)
            .map(std::string::String::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChioActionClassKind {
    Routine,
    ReceiptBacked,
}

impl From<ChioActionClassKind> for ActionClassKind {
    fn from(value: ChioActionClassKind) -> Self {
        match value {
            ChioActionClassKind::Routine => ActionClassKind::Routine,
            ChioActionClassKind::ReceiptBacked => ActionClassKind::ReceiptBacked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioTrustedActionClass {
    pub action_class_id: String,
    pub tool_name: String,
    pub kind: ChioActionClassKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioTrustedWorkflowIntersection {
    pub intersection_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChioAuthorityStatus {
    Active,
    Inactive,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioTrustedLeaseAuthority {
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub public_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ChioAuthorityStatus>,
    pub allowed_action_classes: Vec<CapabilityLeaseActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioTrustedGovernanceAuthority {
    pub authorizing_kernel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub public_key: PublicKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ChioAuthorityStatus>,
    pub allowed_case_kinds: Vec<GovernanceReceiptCaseKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioPinnedRevocationEpoch {
    pub now_unix_ms: u64,
    pub epoch_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioRevocationCheckpoint {
    pub schema: String,
    pub checkpoint_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub epoch_height: u64,
    pub revoked_key_fingerprints: Vec<String>,
}

pub type SignedChioRevocationCheckpoint = SignedExportEnvelope<ChioRevocationCheckpoint>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChioRevocationMaterial {
    Historical(ChioPinnedRevocationEpoch),
    Checkpoint(Box<SignedChioRevocationCheckpoint>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioDisclosurePolicy {
    pub projection_version: String,
    pub ciphersuite: String,
    pub message_count: usize,
    pub required_disclosed_indices: Vec<u16>,
    pub required_disclosed_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioVerificationContext {
    pub schema: String,
    pub audience: String,
    pub challenge: String,
    pub proof_purpose: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationContextNoncePreimage<'a> {
    schema: &'a str,
    audience: &'a str,
    challenge: &'a str,
    proof_purpose: &'a str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl ChioVerificationContext {
    pub fn validate(&self) -> Result<(), ChioPackageError> {
        if self.schema != VERIFICATION_CONTEXT_SCHEMA {
            return Err(ChioPackageError::VerificationContext(format!(
                "verification context schema {} is unsupported",
                self.schema
            )));
        }
        validate_context_field(&self.audience, "verificationContext.audience")?;
        validate_context_field(&self.challenge, "verificationContext.challenge")?;
        validate_context_field(&self.proof_purpose, "verificationContext.proofPurpose")?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ChioPackageError::VerificationContext(
                "verification context expiry must be greater than issue time".to_string(),
            ));
        }
        Ok(())
    }

    fn nonce_preimage(&self) -> VerificationContextNoncePreimage<'_> {
        VerificationContextNoncePreimage {
            schema: &self.schema,
            audience: &self.audience,
            challenge: &self.challenge,
            proof_purpose: &self.proof_purpose,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        }
    }

    pub fn expected_bbs_proof_nonce(&self) -> Result<Vec<u8>, ChioPackageError> {
        self.validate()?;
        let bytes = canonical_json_bytes(&self.nonce_preimage())
            .map_err(|error| ChioPackageError::Canonical(error.to_string()))?;
        Ok(sha256_hex(&bytes).into_bytes())
    }

    pub fn expected_bbs_proof_nonce_hex(&self) -> Result<String, ChioPackageError> {
        Ok(lowercase_hex(&self.expected_bbs_proof_nonce()?))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioVerifierTrustBundleDocument {
    pub schema: String,
    pub trusted_bbs_issuers: Vec<TrustedBbsIssuer>,
    pub peers: Vec<PeerLadderBinding>,
    pub vendors: Vec<VendorKeyBinding>,
    pub action_classes: Vec<ChioTrustedActionClass>,
    pub workflow_intersections: Vec<ChioTrustedWorkflowIntersection>,
    #[serde(default)]
    pub runtime_policy_issuer_public_keys: Vec<PublicKey>,
    #[serde(default)]
    pub lease_authorities: Vec<ChioTrustedLeaseAuthority>,
    #[serde(default)]
    pub governance_authorities: Vec<ChioTrustedGovernanceAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_policy: Option<ChioDisclosurePolicy>,
    pub revocation: ChioRevocationMaterial,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChioVerifierTrustBundle {
    document_sha256: String,
    issuer_registry: TrustedIssuerRegistry,
    peers: BTreeMap<String, PeerLadderBinding>,
    vendors: BTreeMap<String, VendorKeyBinding>,
    action_classes: BTreeMap<String, ChioTrustedActionClass>,
    workflow_intersections: BTreeMap<String, String>,
    lease_authorities: BTreeMap<String, ChioTrustedLeaseAuthority>,
    governance_authorities: BTreeMap<String, ChioTrustedGovernanceAuthority>,
    runtime_policy_issuer_public_keys: Vec<PublicKey>,
    disclosure_policy: ChioDisclosurePolicy,
    revocation: SignedChioRevocationCheckpoint,
    revoked_key_fingerprints: BTreeSet<String>,
}

impl ChioVerifierTrustBundle {
    #[must_use]
    pub fn document_sha256(&self) -> &str {
        &self.document_sha256
    }

    #[must_use]
    pub fn runtime_policy_issuer_public_keys(&self) -> &[PublicKey] {
        &self.runtime_policy_issuer_public_keys
    }

    pub fn from_document(
        document: ChioVerifierTrustBundleDocument,
    ) -> Result<Self, ChioPackageError> {
        let document_sha256 = canonical_sha256(&document)?;
        if document.schema != VERIFIER_TRUST_BUNDLE_SCHEMA {
            return Err(ChioPackageError::TrustBundle(format!(
                "verifier trust bundle schema {} is unsupported",
                document.schema
            )));
        }
        if document.trusted_bbs_issuers.is_empty()
            || document.peers.is_empty()
            || document.vendors.is_empty()
            || document.action_classes.is_empty()
            || document.workflow_intersections.is_empty()
            || document.runtime_policy_issuer_public_keys.is_empty()
            || document.lease_authorities.is_empty()
            || document.governance_authorities.is_empty()
        {
            return Err(ChioPackageError::TrustBundle(
                "verifier trust bundle must contain issuers, peers, vendors, action classes, workflow intersections, runtime policy issuers, lease authorities, and governance authorities"
                    .to_string(),
            ));
        }
        let Some(disclosure_policy) = document.disclosure_policy else {
            return Err(ChioPackageError::TrustBundle(
                "verifier trust bundle v3 requires a disclosure policy".to_string(),
            ));
        };
        validate_disclosure_policy(&disclosure_policy)?;
        let ChioRevocationMaterial::Checkpoint(revocation) = document.revocation else {
            return Err(ChioPackageError::TrustBundle(
                "verifier trust bundle v3 requires a signed revocation checkpoint".to_string(),
            ));
        };
        validate_revocation_checkpoint(&revocation)?;
        let revoked_key_fingerprints =
            revoked_key_fingerprints(&revocation.body.revoked_key_fingerprints)?;

        let issuer_registry = TrustedIssuerRegistry::from_document(TrustedIssuerRegistryDocument {
            schema: TRUSTED_ISSUER_REGISTRY_SCHEMA.to_string(),
            issuers: document.trusted_bbs_issuers,
        })
        .map_err(|error| ChioPackageError::TrustBundle(error.to_string()))?;

        let mut peers = BTreeMap::new();
        for peer in document.peers {
            validate_trust_field(&peer.kernel_id, "peer.kernelId")?;
            peer.ladder_manifest_ref
                .validate()
                .map_err(|error| ChioPackageError::TrustBundle(error.to_string()))?;
            if peers.insert(peer.kernel_id.clone(), peer).is_some() {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted peer kernel id".to_string(),
                ));
            }
        }

        let mut vendors = BTreeMap::new();
        for vendor in document.vendors {
            validate_trust_field(&vendor.vendor_id, "vendor.vendorId")?;
            if vendors.insert(vendor.vendor_id.clone(), vendor).is_some() {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted vendor id".to_string(),
                ));
            }
        }

        let mut action_classes = BTreeMap::new();
        let mut action_class_ids = BTreeSet::new();
        for action_class in document.action_classes {
            validate_trust_field(&action_class.action_class_id, "actionClass.actionClassId")?;
            validate_trust_field(&action_class.tool_name, "actionClass.toolName")?;
            if !action_class_ids.insert(action_class.action_class_id.clone()) {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted action class id".to_string(),
                ));
            }
            if action_classes
                .insert(action_class.tool_name.clone(), action_class)
                .is_some()
            {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted action class tool name".to_string(),
                ));
            }
        }
        for required in [
            WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID,
            WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID,
        ] {
            if !action_class_ids.contains(required) {
                return Err(ChioPackageError::TrustBundle(format!(
                    "verifier trust bundle action classes must include {required}"
                )));
            }
        }

        let mut workflow_intersections = BTreeMap::new();
        for intersection in document.workflow_intersections {
            validate_trust_field(
                &intersection.intersection_id,
                "workflowIntersection.intersectionId",
            )?;
            validate_sha256_hex(&intersection.sha256, "workflowIntersection.sha256")?;
            if workflow_intersections
                .insert(intersection.intersection_id.clone(), intersection.sha256)
                .is_some()
            {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted workflow intersection id".to_string(),
                ));
            }
        }

        let mut lease_authorities = BTreeMap::new();
        for authority in document.lease_authorities {
            validate_trust_field(&authority.issuer, "leaseAuthority.issuer")?;
            validate_authority_lifecycle(
                authority.key_id.as_deref(),
                &authority.public_key,
                authority.valid_from_unix_ms,
                authority.valid_until_unix_ms,
                authority.status,
                "leaseAuthority",
            )?;
            validate_unique_action_classes(
                &authority.allowed_action_classes,
                "leaseAuthority.allowedActionClasses",
            )?;
            if lease_authorities
                .insert(authority.issuer.clone(), authority)
                .is_some()
            {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted lease authority issuer".to_string(),
                ));
            }
        }

        let mut governance_authorities = BTreeMap::new();
        for authority in document.governance_authorities {
            validate_trust_field(
                &authority.authorizing_kernel,
                "governanceAuthority.authorizingKernel",
            )?;
            validate_authority_lifecycle(
                authority.key_id.as_deref(),
                &authority.public_key,
                authority.valid_from_unix_ms,
                authority.valid_until_unix_ms,
                authority.status,
                "governanceAuthority",
            )?;
            validate_unique_case_kinds(
                &authority.allowed_case_kinds,
                "governanceAuthority.allowedCaseKinds",
            )?;
            if governance_authorities
                .insert(authority.authorizing_kernel.clone(), authority)
                .is_some()
            {
                return Err(ChioPackageError::TrustBundle(
                    "duplicate trusted governance authority kernel".to_string(),
                ));
            }
        }

        Ok(Self {
            document_sha256,
            issuer_registry,
            peers,
            vendors,
            action_classes,
            workflow_intersections,
            lease_authorities,
            governance_authorities,
            runtime_policy_issuer_public_keys: document.runtime_policy_issuer_public_keys,
            disclosure_policy,
            revocation: *revocation,
            revoked_key_fingerprints,
        })
    }

    fn issuer_public_key_hex(&self, issuer_fingerprint: &str) -> Option<&str> {
        self.issuer_registry.public_key_hex(issuer_fingerprint)
    }

    fn peer(&self, kernel_id: &str) -> Option<&PeerLadderBinding> {
        self.peers.get(kernel_id)
    }

    fn action_class_map(&self) -> BTreeMap<String, ActionClassKind> {
        self.action_classes
            .iter()
            .map(|(tool_name, class)| (tool_name.clone(), class.kind.into()))
            .collect()
    }

    fn workflow_intersection_hash(&self, intersection_id: &str) -> Option<&str> {
        self.workflow_intersections
            .get(intersection_id)
            .map(std::string::String::as_str)
    }

    fn lease_authority(&self, issuer: &str) -> Option<&ChioTrustedLeaseAuthority> {
        self.lease_authorities.get(issuer)
    }

    fn governance_authority(
        &self,
        authorizing_kernel: &str,
    ) -> Option<&ChioTrustedGovernanceAuthority> {
        self.governance_authorities.get(authorizing_kernel)
    }

    fn pinned_epoch(&self) -> PinnedEpoch {
        PinnedEpoch {
            now_unix_ms: self.revocation.body.issued_at_unix_ms,
            epoch_height: self.revocation.body.epoch_height,
        }
    }

    fn revocation_epoch_height(&self) -> u64 {
        self.revocation.body.epoch_height
    }

    fn verification_time_unix_ms(&self) -> u64 {
        self.revocation.body.issued_at_unix_ms
    }

    fn ensure_not_revoked(&self, fingerprint: &str, label: &str) -> Result<(), ChioPackageError> {
        if self.revoked_key_fingerprints.contains(fingerprint) {
            return Err(ChioPackageError::TrustBundle(format!(
                "{label} is revoked by checkpoint {}",
                self.revocation.body.checkpoint_id
            )));
        }
        Ok(())
    }

    fn ensure_public_key_not_revoked(
        &self,
        public_key: &PublicKey,
        label: &str,
    ) -> Result<(), ChioPackageError> {
        self.ensure_not_revoked(&key_fingerprint(public_key), label)
    }

    fn ensure_checkpoint_active_at(&self, now_unix_ms: u64) -> Result<(), ChioPackageError> {
        if now_unix_ms < self.revocation.body.issued_at_unix_ms {
            return Err(ChioPackageError::TrustBundle(format!(
                "revocation checkpoint {} is issued in the future",
                self.revocation.body.checkpoint_id
            )));
        }
        if now_unix_ms >= self.revocation.body.expires_at_unix_ms {
            return Err(ChioPackageError::TrustBundle(format!(
                "revocation checkpoint {} is stale",
                self.revocation.body.checkpoint_id
            )));
        }
        Ok(())
    }

    fn ensure_checkpoint_covers_context(
        &self,
        context: &ChioVerificationContext,
    ) -> Result<(), ChioPackageError> {
        self.ensure_checkpoint_active_at(context.expires_at_unix_ms.saturating_sub(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioProofClaims {
    pub bbs_reveal_set: bool,
    pub hidden_range_predicates: bool,
    pub vc_data_integrity_bbs: bool,
    pub zkvm: bool,
}

impl ChioProofClaims {
    #[must_use]
    pub fn supported() -> Self {
        Self {
            bbs_reveal_set: true,
            hidden_range_predicates: false,
            vc_data_integrity_bbs: false,
            zkvm: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerLadderBinding {
    pub kernel_id: String,
    pub public_key: PublicKey,
    pub ladder_manifest_ref: LadderManifestRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VendorKeyBinding {
    pub vendor_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowPairwiseIntersectionRef {
    pub peer_kernel_id: String,
    pub intersection_id: String,
    pub ladder_manifest_ref: LadderManifestRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowStepClassBinding {
    pub step_index: usize,
    pub tool_name: String,
    pub action_class_id: String,
    pub peer_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRequiredVendorSigner {
    pub vendor_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowIntersectionArtifact {
    pub schema: String,
    pub intersection_id: String,
    pub workflow_id: String,
    pub workflow_grant_id: String,
    pub pairwise_intersection_refs: Vec<WorkflowPairwiseIntersectionRef>,
    pub step_class_bindings: Vec<WorkflowStepClassBinding>,
    pub required_vendor_signers: Vec<WorkflowRequiredVendorSigner>,
    pub aggregate_workflow_receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseScopeBindingArtifact {
    pub schema: String,
    pub lease_id: String,
    pub workflow_id: String,
    pub workflow_grant_id: String,
    pub step_index: usize,
    pub tool_name: String,
    pub peer_kernel_id: String,
    pub action_class_id: String,
    pub subject: String,
    pub action_class: CapabilityLeaseActionClass,
    pub tool_args_hash: String,
    pub destructive: bool,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LeaseScopeBindingPreimage<'a> {
    lease_id: &'a str,
    workflow_id: &'a str,
    workflow_grant_id: &'a str,
    step_index: usize,
    tool_name: &'a str,
    peer_kernel_id: &'a str,
    action_class_id: &'a str,
    subject: &'a str,
    action_class: CapabilityLeaseActionClass,
    tool_args_hash: &'a str,
    destructive: bool,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl LeaseScopeBindingArtifact {
    fn validate(&self) -> Result<(), ChioPackageError> {
        if self.schema != LEASE_SCOPE_BINDING_SCHEMA {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding schema {} is unsupported",
                self.schema
            )));
        }
        validate_scope_field(&self.lease_id, "leaseScopeBinding.leaseId")?;
        validate_scope_field(&self.workflow_id, "leaseScopeBinding.workflowId")?;
        validate_scope_field(&self.workflow_grant_id, "leaseScopeBinding.workflowGrantId")?;
        validate_scope_field(&self.tool_name, "leaseScopeBinding.toolName")?;
        validate_scope_field(&self.peer_kernel_id, "leaseScopeBinding.peerKernelId")?;
        validate_scope_field(&self.action_class_id, "leaseScopeBinding.actionClassId")?;
        validate_scope_field(&self.subject, "leaseScopeBinding.subject")?;
        validate_sha256_hex_for_scope(&self.tool_args_hash, "leaseScopeBinding.toolArgsHash")?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ChioPackageError::LeaseScopeBinding(
                "lease scope binding expiry must be greater than issue time".to_string(),
            ));
        }
        Ok(())
    }

    fn preimage(&self) -> LeaseScopeBindingPreimage<'_> {
        LeaseScopeBindingPreimage {
            lease_id: &self.lease_id,
            workflow_id: &self.workflow_id,
            workflow_grant_id: &self.workflow_grant_id,
            step_index: self.step_index,
            tool_name: &self.tool_name,
            peer_kernel_id: &self.peer_kernel_id,
            action_class_id: &self.action_class_id,
            subject: &self.subject,
            action_class: self.action_class,
            tool_args_hash: &self.tool_args_hash,
            destructive: self.destructive,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        }
    }

    pub fn scope_digest(&self) -> Result<String, ChioPackageError> {
        self.validate()?;
        canonical_sha256(&self.preimage())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioProofPackage {
    pub schema: String,
    pub generated_at_unix_ms: u64,
    pub workflow_id: String,
    pub claims: ChioProofClaims,
    pub peer_ladder_bindings: Vec<PeerLadderBinding>,
    pub vendor_keys: Vec<VendorKeyBinding>,
    pub tool_receipts: Vec<ChioReceipt>,
    pub workflow_receipt: WorkflowReceipt,
    pub bilateral_envelopes: Vec<DsseEnvelope>,
    pub capability_leases: Vec<SignedCapabilityLease>,
    pub lease_scope_bindings: Vec<LeaseScopeBindingArtifact>,
    pub governance_receipts: Vec<SignedGovernanceReceipt>,
    pub workflow_intersection: WorkflowIntersectionArtifact,
    pub selective_disclosure_proof: SelectiveDisclosureProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierCheck {
    pub code: String,
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierFailure {
    pub code: String,
    pub phase: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierReport {
    pub schema: String,
    pub package_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_bundle_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_epoch_height: Option<u64>,
    pub accepted: bool,
    pub checks: Vec<VerifierCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<VerifierFailure>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChioPackageError {
    #[error("canonical JSON failed: {0}")]
    Canonical(String),
    #[error("package schema is unsupported: {0}")]
    UnsupportedSchema(String),
    #[error("unsupported proof claim: {0}")]
    UnsupportedClaim(String),
    #[error("workflow verification failed: {0}")]
    Workflow(String),
    #[error("governance verification failed: {0}")]
    Governance(String),
    #[error("federation verification failed: {0}")]
    Federation(String),
    #[error("selective disclosure verification failed: {0}")]
    SelectiveDisclosure(String),
    #[error("trusted issuer registry failed: {0}")]
    TrustedIssuer(String),
    #[error("verifier trust bundle failed: {0}")]
    TrustBundle(String),
    #[error("workflow intersection failed: {0}")]
    WorkflowIntersection(String),
    #[error("lease scope binding failed: {0}")]
    LeaseScopeBinding(String),
    #[error("verification context failed: {0}")]
    VerificationContext(String),
    #[error("package data is inconsistent: {0}")]
    Inconsistent(String),
    #[error("JSON operation failed: {0}")]
    Json(String),
}

fn validate_trust_field(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.is_empty() {
        return Err(ChioPackageError::TrustBundle(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_sha256_hex(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.len() != 64 || !is_lower_hex(value) {
        return Err(ChioPackageError::TrustBundle(format!(
            "{field} must be a lowercase 64-character SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.is_empty() {
        return Err(ChioPackageError::TrustedIssuer(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_scope_field(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.is_empty() {
        return Err(ChioPackageError::LeaseScopeBinding(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_context_field(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.is_empty() {
        return Err(ChioPackageError::VerificationContext(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_sha256_hex_for_scope(value: &str, field: &str) -> Result<(), ChioPackageError> {
    if value.len() != 64 || !is_lower_hex(value) {
        return Err(ChioPackageError::LeaseScopeBinding(format!(
            "{field} must be a lowercase 64-character SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn validate_unique_action_classes(
    values: &[CapabilityLeaseActionClass],
    field: &str,
) -> Result<(), ChioPackageError> {
    if values.is_empty() {
        return Err(ChioPackageError::TrustBundle(format!(
            "{field} must be non-empty"
        )));
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ChioPackageError::TrustBundle(format!(
                "{field} contains duplicate action class {value:?}"
            )));
        }
    }
    Ok(())
}

fn validate_unique_case_kinds(
    values: &[GovernanceReceiptCaseKind],
    field: &str,
) -> Result<(), ChioPackageError> {
    if values.is_empty() {
        return Err(ChioPackageError::TrustBundle(format!(
            "{field} must be non-empty"
        )));
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ChioPackageError::TrustBundle(format!(
                "{field} contains duplicate case kind {value:?}"
            )));
        }
    }
    Ok(())
}

fn key_fingerprint(public_key: &PublicKey) -> String {
    Keyid::from_public_key(public_key).0
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_disclosure_policy(policy: &ChioDisclosurePolicy) -> Result<(), ChioPackageError> {
    if policy.projection_version != PROJECTION_VERSION_WORKFLOW_V1 {
        return Err(ChioPackageError::TrustBundle(format!(
            "disclosure policy projection version {} is unsupported",
            policy.projection_version
        )));
    }
    if policy.ciphersuite != BBS_CIPHERSUITE_SHA256 {
        return Err(ChioPackageError::TrustBundle(
            "disclosure policy ciphersuite is unsupported".to_string(),
        ));
    }
    if policy.message_count == 0 {
        return Err(ChioPackageError::TrustBundle(
            "disclosure policy message count must be non-zero".to_string(),
        ));
    }
    let mut seen_indices = BTreeSet::new();
    for index in &policy.required_disclosed_indices {
        if usize::from(*index) >= policy.message_count {
            return Err(ChioPackageError::TrustBundle(format!(
                "disclosure policy required index {index} is out of range"
            )));
        }
        if !seen_indices.insert(*index) {
            return Err(ChioPackageError::TrustBundle(format!(
                "disclosure policy has duplicate required index {index}"
            )));
        }
    }
    let mut seen_fields = BTreeSet::new();
    for field in &policy.required_disclosed_fields {
        validate_trust_field(field, "disclosurePolicy.requiredDisclosedFields")?;
        if !seen_fields.insert(field) {
            return Err(ChioPackageError::TrustBundle(format!(
                "disclosure policy has duplicate required field {field}"
            )));
        }
    }
    if seen_indices.is_empty() || seen_fields.is_empty() {
        return Err(ChioPackageError::TrustBundle(
            "disclosure policy must require at least one index and field".to_string(),
        ));
    }
    Ok(())
}

fn validate_revocation_checkpoint(
    checkpoint: &SignedChioRevocationCheckpoint,
) -> Result<(), ChioPackageError> {
    if checkpoint.body.schema != REVOCATION_CHECKPOINT_SCHEMA {
        return Err(ChioPackageError::TrustBundle(format!(
            "revocation checkpoint schema {} is unsupported",
            checkpoint.body.schema
        )));
    }
    validate_trust_field(
        &checkpoint.body.checkpoint_id,
        "revocationCheckpoint.checkpointId",
    )?;
    if checkpoint.body.expires_at_unix_ms <= checkpoint.body.issued_at_unix_ms {
        return Err(ChioPackageError::TrustBundle(
            "revocation checkpoint expiry must be greater than issue time".to_string(),
        ));
    }
    revoked_key_fingerprints(&checkpoint.body.revoked_key_fingerprints)?;
    if !checkpoint
        .verify_signature()
        .map_err(|error| ChioPackageError::TrustBundle(error.to_string()))?
    {
        return Err(ChioPackageError::TrustBundle(
            "revocation checkpoint signature is invalid".to_string(),
        ));
    }
    Ok(())
}

fn revoked_key_fingerprints(values: &[String]) -> Result<BTreeSet<String>, ChioPackageError> {
    let mut fingerprints = BTreeSet::new();
    for fingerprint in values {
        validate_sha256_hex(fingerprint, "revocationCheckpoint.revokedKeyFingerprints")?;
        if !fingerprints.insert(fingerprint.clone()) {
            return Err(ChioPackageError::TrustBundle(format!(
                "duplicate revoked key fingerprint {fingerprint}"
            )));
        }
    }
    Ok(fingerprints)
}

fn validate_authority_lifecycle(
    declared_key_id: Option<&str>,
    public_key: &PublicKey,
    valid_from_unix_ms: Option<u64>,
    valid_until_unix_ms: Option<u64>,
    status: Option<ChioAuthorityStatus>,
    label: &str,
) -> Result<(), ChioPackageError> {
    let Some(key_id) = declared_key_id else {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.keyId is required"
        )));
    };
    let expected = key_fingerprint(public_key);
    if key_id != expected {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.keyId does not match public key fingerprint"
        )));
    }
    let Some(valid_from) = valid_from_unix_ms else {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.validFromUnixMs is required"
        )));
    };
    let Some(valid_until) = valid_until_unix_ms else {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.validUntilUnixMs is required"
        )));
    };
    if valid_until <= valid_from {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label} validity window is invalid"
        )));
    }
    let Some(status) = status else {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label}.status is required"
        )));
    };
    if status != ChioAuthorityStatus::Active {
        return Err(ChioPackageError::TrustBundle(format!(
            "{label} status is not active"
        )));
    }
    Ok(())
}

fn authority_window(
    valid_from_unix_ms: Option<u64>,
    valid_until_unix_ms: Option<u64>,
    label: &str,
) -> Result<(u64, u64), ChioPackageError> {
    let valid_from = valid_from_unix_ms.ok_or_else(|| {
        ChioPackageError::Governance(format!("{label} validFromUnixMs is missing"))
    })?;
    let valid_until = valid_until_unix_ms.ok_or_else(|| {
        ChioPackageError::Governance(format!("{label} validUntilUnixMs is missing"))
    })?;
    if valid_until <= valid_from {
        return Err(ChioPackageError::Governance(format!(
            "{label} validity window is invalid"
        )));
    }
    Ok((valid_from, valid_until))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChioPackageError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChioPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn canonical_string<T: Serialize>(value: &T) -> Result<String, ChioPackageError> {
    canonical_json_string(value).map_err(|error| ChioPackageError::Canonical(error.to_string()))
}

fn verify_claims(claims: &ChioProofClaims) -> Result<(), ChioPackageError> {
    if !claims.bbs_reveal_set {
        return Err(ChioPackageError::UnsupportedClaim(
            "bbs reveal-set support must be claimed for this package".to_string(),
        ));
    }
    if claims.hidden_range_predicates {
        return Err(ChioPackageError::UnsupportedClaim(
            "hidden range predicates are not supported by this package".to_string(),
        ));
    }
    if claims.vc_data_integrity_bbs {
        return Err(ChioPackageError::UnsupportedClaim(
            "VC Data Integrity BBS interop is not supported by this package".to_string(),
        ));
    }
    if claims.zkvm {
        return Err(ChioPackageError::UnsupportedClaim(
            "zkVM support is not supported by this package".to_string(),
        ));
    }
    Ok(())
}

pub fn proof_package_from_json(json: &str) -> Result<ChioProofPackage, ChioPackageError> {
    serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn verifier_report_from_json(json: &str) -> Result<VerifierReport, ChioPackageError> {
    serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn verification_context_from_json(
    json: &str,
) -> Result<ChioVerificationContext, ChioPackageError> {
    let context: ChioVerificationContext =
        serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    context.validate()?;
    Ok(context)
}

pub fn trusted_issuer_registry_from_json(
    json: &str,
) -> Result<TrustedIssuerRegistry, ChioPackageError> {
    let document: TrustedIssuerRegistryDocument =
        serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    TrustedIssuerRegistry::from_document(document)
}

pub fn verifier_trust_bundle_from_json(
    json: &str,
) -> Result<ChioVerifierTrustBundle, ChioPackageError> {
    let document: ChioVerifierTrustBundleDocument =
        serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    ChioVerifierTrustBundle::from_document(document)
}

pub fn package_json(package: &ChioProofPackage) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(package).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn report_json(report: &VerifierReport) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(report).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn trusted_issuer_registry_json(
    registry: &TrustedIssuerRegistryDocument,
) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(registry)
        .map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn verifier_trust_bundle_json(
    trust_bundle: &ChioVerifierTrustBundleDocument,
) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(trust_bundle)
        .map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn verification_context_json(
    context: &ChioVerificationContext,
) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(context).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn package_sha256(package: &ChioProofPackage) -> Result<String, ChioPackageError> {
    let bytes = canonical_json_bytes(package)
        .map_err(|error| ChioPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn verifier_trust_bundle_document_sha256(
    document: &ChioVerifierTrustBundleDocument,
) -> Result<String, ChioPackageError> {
    canonical_sha256(document)
}

pub fn verification_context_sha256(
    context: &ChioVerificationContext,
) -> Result<String, ChioPackageError> {
    canonical_sha256(context)
}

pub fn verify_package(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
) -> Result<VerifierReport, ChioPackageError> {
    let mut checks = Vec::new();
    match verify_package_inner(package, trust_bundle, context, &mut checks) {
        Ok(()) => accepted_report(package, trust_bundle, context, checks),
        Err(error) => Err(error),
    }
}

pub fn verify_package_report(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
) -> VerifierReport {
    let mut checks = Vec::new();
    match verify_package_inner(package, trust_bundle, context, &mut checks) {
        Ok(()) => {
            let accepted_checks = checks.clone();
            accepted_report(package, trust_bundle, context, checks).unwrap_or_else(|error| {
                rejected_report(
                    package,
                    trust_bundle,
                    Some(context),
                    accepted_checks,
                    &error,
                )
            })
        }
        Err(error) => rejected_report(package, trust_bundle, Some(context), checks, &error),
    }
}

fn verify_package_inner(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
    checks: &mut Vec<VerifierCheck>,
) -> Result<(), ChioPackageError> {
    if package.schema != PROOF_PACKAGE_SCHEMA {
        return Err(ChioPackageError::UnsupportedSchema(package.schema.clone()));
    }
    verify_claims(&package.claims)?;
    context.validate()?;
    if context.issued_at_unix_ms > trust_bundle.verification_time_unix_ms() {
        return Err(ChioPackageError::VerificationContext(
            "verification context is issued after the pinned revocation epoch".to_string(),
        ));
    }
    if context.expires_at_unix_ms <= trust_bundle.verification_time_unix_ms() {
        return Err(ChioPackageError::VerificationContext(
            "verification context is expired".to_string(),
        ));
    }
    trust_bundle.ensure_checkpoint_covers_context(context)?;

    let add_check = |checks: &mut Vec<VerifierCheck>, code: &str, name: &str| {
        checks.push(VerifierCheck {
            code: code.to_string(),
            name: name.to_string(),
            passed: true,
            detail: None,
        });
    };

    if !package
        .workflow_receipt
        .verify()
        .map_err(|error| ChioPackageError::Workflow(error.to_string()))?
    {
        return Err(ChioPackageError::Workflow(
            "workflow signature is invalid".to_string(),
        ));
    }
    add_check(
        checks,
        "workflow.kernel_signature",
        "workflow-kernel-signature",
    );

    verify_package_hints_match_trust(package, trust_bundle)?;
    add_check(checks, "trust.package_hints", "package-trust-hints");

    verify_workflow_intersection(package, trust_bundle)?;
    add_check(checks, "workflow.intersection", "workflow-intersection");

    let vendor_requirements = package
        .workflow_intersection
        .required_vendor_signers
        .iter()
        .map(|binding| VendorSignatureRequirement {
            vendor_id: binding.vendor_id.clone(),
            public_key: binding.public_key.clone(),
        })
        .collect::<Vec<_>>();
    package
        .workflow_receipt
        .verify_vendor_signatures(&vendor_requirements)
        .map_err(|error| ChioPackageError::Workflow(error.to_string()))?;
    add_check(
        checks,
        "workflow.vendor_cosignatures",
        "workflow-vendor-cosignatures",
    );

    verify_step_links(package)?;
    add_check(checks, "workflow.step_links", "workflow-step-links");

    let mut receipt_store = InMemoryReceiptStore::new();
    for receipt in &package.tool_receipts {
        receipt_store.insert(receipt.clone());
    }
    let lease_scope_digests = verify_lease_scope_bindings(package)?;
    add_check(
        checks,
        "governance.lease_scope_bindings",
        "lease-scope-bindings",
    );

    let mut lease_registry = InMemoryLeaseRegistry::new();
    let mut seen_lease_ids = BTreeSet::new();
    for lease in &package.capability_leases {
        if !seen_lease_ids.insert(lease.body.lease_id.clone()) {
            return Err(ChioPackageError::Governance(format!(
                "duplicate capability lease {}",
                lease.body.lease_id
            )));
        }
        let scope_digest = lease_scope_digests
            .get(&lease.body.lease_id)
            .ok_or_else(|| {
                ChioPackageError::LeaseScopeBinding(format!(
                    "lease {} has no scope binding",
                    lease.body.lease_id
                ))
            })?
            .clone();
        verify_trusted_capability_lease(lease, trust_bundle, &scope_digest)?;
        lease_registry.insert(ResolvedLease {
            lease_id: lease.body.lease_id.clone(),
            issuer: lease.body.issuer.clone(),
            expires_at_unix_ms: lease.body.expires_at_unix_ms,
            scope_digest_hex: Some(scope_digest),
        });
    }
    add_check(checks, "governance.capability_leases", "capability-leases");

    let mut governance_store = InMemoryGovernanceReceiptStore::new();
    let mut seen_governance_ids = BTreeSet::new();
    for receipt in &package.governance_receipts {
        if !seen_governance_ids.insert(receipt.body.receipt_id.clone()) {
            return Err(ChioPackageError::Governance(format!(
                "duplicate governance receipt {}",
                receipt.body.receipt_id
            )));
        }
        verify_trusted_governance_receipt(receipt, trust_bundle)?;
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: receipt.body.receipt_id.clone(),
            kernel_id: receipt.body.authorizing_kernel.clone(),
            canonical_json: canonical_string(receipt)?,
        });
    }
    verify_destructive_steps(package, trust_bundle, &lease_scope_digests)?;
    add_check(checks, "governance.receipts", "governance-receipts");

    let mut peer_pin_set = PeerPinSet::new();
    for peer in trust_bundle.peers.values() {
        peer_pin_set.insert(PinnedPeer {
            kernel_id: peer.kernel_id.clone(),
            public_key: peer.public_key.clone(),
            ladder_manifest_ref: Some(peer.ladder_manifest_ref.clone()),
        });
    }
    let revocation_oracle = OfflineRevocationOracle {
        revoked_key_fingerprints: trust_bundle.revoked_key_fingerprints.clone(),
    };
    let verifier_config = VerifierConfig {
        peer_pin_set: &peer_pin_set,
        receipt_store: &receipt_store,
        lease_registry: &lease_registry,
        governance_receipt_store: &governance_store,
        revocation_oracle: &revocation_oracle,
        pinned_epoch: trust_bundle.pinned_epoch(),
        action_classes: trust_bundle.action_class_map(),
        unknown_action_class_policy: UnknownActionClassPolicy::Reject,
    };
    for envelope in &package.bilateral_envelopes {
        let verified = verify_chio_bilateral_invocation(
            envelope,
            &ChioBilateralVerifierConfig {
                base: &verifier_config,
            },
        )
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
        if verified.joint_verdict != "allow" {
            return Err(ChioPackageError::Federation(format!(
                "bilateral envelope policy verdict {:?} is not allow",
                verified.joint_verdict
            )));
        }
    }
    add_check(
        checks,
        "federation.strict_bilateral_invocations",
        "strict-bilateral-invocations",
    );

    let workflow_projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    if package.selective_disclosure_proof.subject_sha256_hex
        != workflow_projection.subject_sha256_hex
    {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof subject does not match workflow receipt body".to_string(),
        ));
    }
    let trusted_issuer_key = trust_bundle
        .issuer_public_key_hex(&package.selective_disclosure_proof.issuer_fingerprint)
        .ok_or_else(|| {
            ChioPackageError::TrustedIssuer(format!(
                "issuer {} is not trusted",
                package.selective_disclosure_proof.issuer_fingerprint
            ))
        })?;
    trust_bundle.ensure_not_revoked(
        &package.selective_disclosure_proof.issuer_fingerprint,
        "BBS issuer",
    )?;
    if trusted_issuer_key != package.selective_disclosure_proof.issuer_public_key_hex {
        return Err(ChioPackageError::TrustedIssuer(format!(
            "issuer public key for {} does not match trusted registry",
            package.selective_disclosure_proof.issuer_fingerprint
        )));
    }
    add_check(checks, "trust.bbs_issuer", "trusted-bbs-issuer");

    verify_disclosure_contract(
        &package.selective_disclosure_proof,
        &workflow_projection,
        trust_bundle,
        context,
    )?;

    let mut issuer_registry = InMemoryIssuerRegistry::default();
    issuer_registry.insert(
        package
            .selective_disclosure_proof
            .issuer_fingerprint
            .clone(),
        trusted_issuer_key.to_string(),
    );
    verify_selective_disclosure_proof(&package.selective_disclosure_proof, &issuer_registry)
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    add_check(
        checks,
        "bbs.selective_disclosure",
        "bbs-selective-disclosure",
    );

    Ok(())
}

fn accepted_report(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
    checks: Vec<VerifierCheck>,
) -> Result<VerifierReport, ChioPackageError> {
    Ok(VerifierReport {
        schema: VERIFIER_REPORT_SCHEMA.to_string(),
        package_sha256: package_sha256(package)?,
        trust_bundle_sha256: Some(trust_bundle.document_sha256.clone()),
        context_sha256: Some(verification_context_sha256(context)?),
        revocation_epoch_height: Some(trust_bundle.revocation_epoch_height()),
        accepted: true,
        checks,
        failure: None,
    })
}

fn rejected_report(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: Option<&ChioVerificationContext>,
    checks: Vec<VerifierCheck>,
    error: &ChioPackageError,
) -> VerifierReport {
    VerifierReport {
        schema: VERIFIER_REPORT_SCHEMA.to_string(),
        package_sha256: package_sha256(package).unwrap_or_else(|_| "unavailable".to_string()),
        trust_bundle_sha256: Some(trust_bundle.document_sha256.clone()),
        context_sha256: context.and_then(|context| verification_context_sha256(context).ok()),
        revocation_epoch_height: Some(trust_bundle.revocation_epoch_height()),
        accepted: false,
        checks,
        failure: Some(VerifierFailure {
            code: failure_code(error).to_string(),
            phase: failure_phase(error).to_string(),
            detail: error.to_string(),
        }),
    }
}

fn failure_code(error: &ChioPackageError) -> &'static str {
    match error {
        ChioPackageError::Canonical(_) => "canonical_json",
        ChioPackageError::UnsupportedSchema(_) => "package.schema",
        ChioPackageError::UnsupportedClaim(_) => "package.claim",
        ChioPackageError::Workflow(_) => "workflow",
        ChioPackageError::Governance(_) => "governance",
        ChioPackageError::Federation(_) => "federation",
        ChioPackageError::SelectiveDisclosure(message) if message.contains("proof nonce") => {
            "bbs.context_nonce"
        }
        ChioPackageError::SelectiveDisclosure(_) => "bbs",
        ChioPackageError::TrustedIssuer(_) => "trust.bbs_issuer",
        ChioPackageError::TrustBundle(_) => "trust.bundle",
        ChioPackageError::WorkflowIntersection(_) => "workflow.intersection",
        ChioPackageError::LeaseScopeBinding(_) => "lease.scope_binding",
        ChioPackageError::VerificationContext(_) => "verification.context",
        ChioPackageError::Inconsistent(_) => "package.inconsistent",
        ChioPackageError::Json(_) => "json",
    }
}

fn failure_phase(error: &ChioPackageError) -> &'static str {
    match error {
        ChioPackageError::Canonical(_) | ChioPackageError::Json(_) => "parse",
        ChioPackageError::UnsupportedSchema(_)
        | ChioPackageError::UnsupportedClaim(_)
        | ChioPackageError::Inconsistent(_) => "package",
        ChioPackageError::TrustBundle(_)
        | ChioPackageError::TrustedIssuer(_)
        | ChioPackageError::VerificationContext(_) => "trust",
        ChioPackageError::Workflow(_)
        | ChioPackageError::WorkflowIntersection(_)
        | ChioPackageError::LeaseScopeBinding(_) => "workflow",
        ChioPackageError::Governance(_) => "governance",
        ChioPackageError::Federation(_) => "federation",
        ChioPackageError::SelectiveDisclosure(_) => "bbs",
    }
}

#[derive(Debug, Clone)]
struct OfflineRevocationOracle {
    revoked_key_fingerprints: BTreeSet<String>,
}

impl RevocationOracle for OfflineRevocationOracle {
    fn is_active_at_epoch(&self, fingerprint: &Keyid, _epoch_height: u64) -> bool {
        !self.revoked_key_fingerprints.contains(&fingerprint.0)
    }
}

fn verify_disclosure_contract(
    proof: &SelectiveDisclosureProof,
    projection: &Projection,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
) -> Result<(), ChioPackageError> {
    let policy = &trust_bundle.disclosure_policy;
    if proof.projection_version != policy.projection_version {
        return Err(ChioPackageError::SelectiveDisclosure(format!(
            "projection version {} is not verifier-approved",
            proof.projection_version
        )));
    }
    if projection.version != policy.projection_version {
        return Err(ChioPackageError::SelectiveDisclosure(
            "workflow projection does not match disclosure policy".to_string(),
        ));
    }
    if proof.ciphersuite != policy.ciphersuite {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof ciphersuite does not match disclosure policy".to_string(),
        ));
    }
    if proof.message_count != policy.message_count
        || projection.messages.len() != policy.message_count
    {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof message count does not match disclosure policy".to_string(),
        ));
    }
    let expected_nonce = context.expected_bbs_proof_nonce_hex()?;
    if proof.proof_nonce_hex != expected_nonce {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof nonce does not match verifier context".to_string(),
        ));
    }
    let disclosed_indices = proof
        .disclosed_indices
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if disclosed_indices.len() != proof.disclosed_indices.len() {
        return Err(ChioPackageError::SelectiveDisclosure(
            "BBS proof carries duplicate disclosed index".to_string(),
        ));
    }
    for index in &policy.required_disclosed_indices {
        if !disclosed_indices.contains(index) {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof does not disclose required index {index}"
            )));
        }
    }
    let disclosed_fields = proof
        .disclosed
        .iter()
        .map(|message| message.field.as_str())
        .collect::<BTreeSet<_>>();
    for field in &policy.required_disclosed_fields {
        if !disclosed_fields.contains(field.as_str()) {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof does not disclose required field {field}"
            )));
        }
    }
    for disclosed in &proof.disclosed {
        let Some(projected) = projection
            .messages
            .iter()
            .find(|message| message.index == disclosed.index)
        else {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof discloses out-of-range index {}",
                disclosed.index
            )));
        };
        if disclosed.field != projected.field
            || disclosed.encoding != projected.encoding
            || disclosed.bytes_hex != projected.bytes_hex
        {
            return Err(ChioPackageError::SelectiveDisclosure(format!(
                "BBS proof disclosed message {} does not match projection",
                disclosed.index
            )));
        }
    }
    Ok(())
}

fn verify_package_hints_match_trust(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
) -> Result<(), ChioPackageError> {
    if package.peer_ladder_bindings.is_empty() {
        return Err(ChioPackageError::TrustBundle(
            "package carries no peer ladder hints".to_string(),
        ));
    }
    let mut package_peer_ids = BTreeSet::new();
    for peer in &package.peer_ladder_bindings {
        if !package_peer_ids.insert(peer.kernel_id.clone()) {
            return Err(ChioPackageError::TrustBundle(format!(
                "package carries duplicate peer hint {}",
                peer.kernel_id
            )));
        }
        let trusted = trust_bundle.peer(&peer.kernel_id).ok_or_else(|| {
            ChioPackageError::TrustBundle(format!(
                "package peer {} is not trusted by verifier trust bundle",
                peer.kernel_id
            ))
        })?;
        trust_bundle.ensure_public_key_not_revoked(&trusted.public_key, "peer key")?;
        if trusted.public_key != peer.public_key {
            return Err(ChioPackageError::TrustBundle(format!(
                "package peer {} public key does not match verifier trust bundle",
                peer.kernel_id
            )));
        }
        if trusted.ladder_manifest_ref != peer.ladder_manifest_ref {
            return Err(ChioPackageError::TrustBundle(format!(
                "package peer {} ladder ref does not match verifier trust bundle",
                peer.kernel_id
            )));
        }
        if !trusted
            .ladder_manifest_ref
            .is_fresh(trust_bundle.verification_time_unix_ms())
        {
            return Err(ChioPackageError::TrustBundle(format!(
                "trusted ladder ref for {} is stale",
                peer.kernel_id
            )));
        }
    }

    if package.vendor_keys.is_empty() {
        return Err(ChioPackageError::TrustBundle(
            "package carries no vendor key hints".to_string(),
        ));
    }
    let mut package_vendor_ids = BTreeSet::new();
    for vendor in &package.vendor_keys {
        if !package_vendor_ids.insert(vendor.vendor_id.clone()) {
            return Err(ChioPackageError::TrustBundle(format!(
                "package carries duplicate vendor hint {}",
                vendor.vendor_id
            )));
        }
        let trusted = trust_bundle.vendors.get(&vendor.vendor_id).ok_or_else(|| {
            ChioPackageError::TrustBundle(format!(
                "package vendor {} is not trusted by verifier trust bundle",
                vendor.vendor_id
            ))
        })?;
        trust_bundle.ensure_public_key_not_revoked(&trusted.public_key, "vendor key")?;
        if trusted.public_key != vendor.public_key {
            return Err(ChioPackageError::TrustBundle(format!(
                "package vendor {} public key does not match verifier trust bundle",
                vendor.vendor_id
            )));
        }
    }
    Ok(())
}

fn verify_workflow_intersection(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
) -> Result<(), ChioPackageError> {
    let intersection = &package.workflow_intersection;
    if intersection.schema != WORKFLOW_INTERSECTION_SCHEMA {
        return Err(ChioPackageError::WorkflowIntersection(format!(
            "workflow intersection schema {} is unsupported",
            intersection.schema
        )));
    }
    if intersection.workflow_id != package.workflow_id {
        return Err(ChioPackageError::WorkflowIntersection(
            "workflow intersection workflow id does not match package".to_string(),
        ));
    }
    if intersection.workflow_grant_id != package.workflow_receipt.capability_id {
        return Err(ChioPackageError::WorkflowIntersection(
            "workflow intersection grant id does not match workflow receipt".to_string(),
        ));
    }

    let aggregate_hash = canonical_sha256(&package.workflow_receipt.body())?;
    if intersection.aggregate_workflow_receipt_sha256 != aggregate_hash {
        return Err(ChioPackageError::WorkflowIntersection(
            "workflow intersection aggregate workflow receipt hash mismatch".to_string(),
        ));
    }

    let artifact_hash = canonical_sha256(intersection)?;
    let trusted_hash = trust_bundle
        .workflow_intersection_hash(&intersection.intersection_id)
        .ok_or_else(|| {
            ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection {} is not trusted",
                intersection.intersection_id
            ))
        })?;
    if trusted_hash != artifact_hash {
        return Err(ChioPackageError::WorkflowIntersection(format!(
            "workflow intersection {} hash does not match verifier trust bundle",
            intersection.intersection_id
        )));
    }

    let mut seen_vendor_ids = BTreeSet::new();
    for signer in &intersection.required_vendor_signers {
        let trusted = trust_bundle.vendors.get(&signer.vendor_id).ok_or_else(|| {
            ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection signer {} is not trusted",
                signer.vendor_id
            ))
        })?;
        if !seen_vendor_ids.insert(signer.vendor_id.clone()) {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate signer {}",
                signer.vendor_id
            )));
        }
        if trusted.public_key != signer.public_key {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection signer {} key mismatch",
                signer.vendor_id
            )));
        }
    }

    let mut pairwise_by_peer = BTreeMap::new();
    for pairwise in &intersection.pairwise_intersection_refs {
        let trusted = trust_bundle.peer(&pairwise.peer_kernel_id).ok_or_else(|| {
            ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection peer {} is not trusted",
                pairwise.peer_kernel_id
            ))
        })?;
        if trusted.ladder_manifest_ref != pairwise.ladder_manifest_ref {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection peer {} ladder ref mismatch",
                pairwise.peer_kernel_id
            )));
        }
        if pairwise_by_peer
            .insert(pairwise.peer_kernel_id.clone(), pairwise)
            .is_some()
        {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate peer {}",
                pairwise.peer_kernel_id
            )));
        }
    }

    if intersection.step_class_bindings.len() != package.workflow_receipt.steps.len() {
        return Err(ChioPackageError::WorkflowIntersection(
            "workflow intersection step binding count does not match workflow receipt".to_string(),
        ));
    }
    let mut seen_steps = BTreeSet::new();
    for binding in &intersection.step_class_bindings {
        if !seen_steps.insert(binding.step_index) {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate step {}",
                binding.step_index
            )));
        }
        let step = package
            .workflow_receipt
            .steps
            .get(binding.step_index)
            .ok_or_else(|| {
                ChioPackageError::WorkflowIntersection(format!(
                    "workflow intersection references missing step {}",
                    binding.step_index
                ))
            })?;
        if step.tool_name != binding.tool_name {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection step {} tool mismatch",
                binding.step_index
            )));
        }
        if !pairwise_by_peer.contains_key(&binding.peer_kernel_id) {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection step {} references peer {} without pairwise ref",
                binding.step_index, binding.peer_kernel_id
            )));
        }
        let trusted_class = trust_bundle
            .action_classes
            .get(&binding.tool_name)
            .ok_or_else(|| {
                ChioPackageError::WorkflowIntersection(format!(
                    "workflow intersection tool {} has no trusted action class",
                    binding.tool_name
                ))
            })?;
        if trusted_class.action_class_id != binding.action_class_id {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection tool {} action class mismatch",
                binding.tool_name
            )));
        }
    }
    Ok(())
}

fn verify_step_links(package: &ChioProofPackage) -> Result<(), ChioPackageError> {
    if package.workflow_receipt.steps.len() != package.bilateral_envelopes.len() {
        return Err(ChioPackageError::Workflow(
            "step count does not match bilateral envelope count".to_string(),
        ));
    }
    let mut receipts_by_id = HashMap::new();
    for receipt in &package.tool_receipts {
        if receipts_by_id.insert(receipt.id.clone(), receipt).is_some() {
            return Err(ChioPackageError::Workflow(format!(
                "duplicate tool receipt {}",
                receipt.id
            )));
        }
    }
    let mut leases_by_id = HashMap::new();
    for lease in &package.capability_leases {
        if leases_by_id
            .insert(lease.body.lease_id.clone(), lease)
            .is_some()
        {
            return Err(ChioPackageError::Workflow(format!(
                "duplicate capability lease {}",
                lease.body.lease_id
            )));
        }
    }
    let mut step_classes = HashMap::new();
    for binding in &package.workflow_intersection.step_class_bindings {
        if step_classes.insert(binding.step_index, binding).is_some() {
            return Err(ChioPackageError::Workflow(format!(
                "duplicate workflow step class binding {}",
                binding.step_index
            )));
        }
    }
    let mut previous_step_sha256: Option<String> = None;
    for (expected_index, (step, envelope)) in package
        .workflow_receipt
        .steps
        .iter()
        .zip(package.bilateral_envelopes.iter())
        .enumerate()
    {
        if step.step_index != expected_index {
            return Err(ChioPackageError::Workflow(format!(
                "step index {} does not match position {}",
                step.step_index, expected_index
            )));
        }
        let envelope_sha256 = canonical_sha256(envelope)?;
        if step.bilateral_dsse_sha256.as_deref() != Some(envelope_sha256.as_str()) {
            return Err(ChioPackageError::Workflow(format!(
                "step {} DSSE hash does not match envelope",
                step.step_index
            )));
        }
        if step.parent_receipt_sha256 != previous_step_sha256 {
            return Err(ChioPackageError::Workflow(format!(
                "step {} parent hash does not match previous step",
                step.step_index
            )));
        }
        let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
            ChioPackageError::Workflow(format!("step {} has no tool receipt id", step.step_index))
        })?;
        let tool_receipt = receipts_by_id.get(tool_receipt_id).ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "step {} tool receipt {} is not present in package",
                step.step_index, tool_receipt_id
            ))
        })?;
        let (statement, _) = envelope.decode_statement().map_err(|error| {
            ChioPackageError::Federation(format!("step {} DSSE payload: {error}", step.step_index))
        })?;
        let predicate = &statement.predicate;
        if predicate.invocation_id != *tool_receipt_id {
            return Err(ChioPackageError::Workflow(format!(
                "step {} tool receipt id {} does not match DSSE invocation {}",
                step.step_index, tool_receipt_id, predicate.invocation_id
            )));
        }
        if step.tool_name != tool_receipt.tool_name {
            return Err(ChioPackageError::Workflow(format!(
                "step {} tool name {} does not match tool receipt {}",
                step.step_index, step.tool_name, tool_receipt.tool_name
            )));
        }
        if step.tool_name != predicate.tool_name {
            return Err(ChioPackageError::Workflow(format!(
                "step {} tool name {} does not match DSSE predicate {}",
                step.step_index, step.tool_name, predicate.tool_name
            )));
        }
        if step.server_id != tool_receipt.tool_server {
            return Err(ChioPackageError::Workflow(format!(
                "step {} server id {} does not match tool receipt server {}",
                step.step_index, step.server_id, tool_receipt.tool_server
            )));
        }
        if step.output_hash.as_deref() != Some(tool_receipt.content_hash.as_str()) {
            return Err(ChioPackageError::Workflow(format!(
                "step {} output hash does not match tool receipt content hash",
                step.step_index
            )));
        }
        let expected_anchor = format!(
            "chio:consistency:{}:{}",
            package.workflow_id, step.step_index
        );
        if step.consistency_anchor.as_deref() != Some(expected_anchor.as_str()) {
            return Err(ChioPackageError::Workflow(format!(
                "step {} consistency anchor must be {}",
                step.step_index, expected_anchor
            )));
        }
        if predicate.consistency_anchor.as_deref() != step.consistency_anchor.as_deref() {
            return Err(ChioPackageError::Workflow(format!(
                "step {} consistency anchor does not match DSSE predicate",
                step.step_index
            )));
        }
        let class_binding = step_classes.get(&step.step_index).ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "step {} has no workflow class binding",
                step.step_index
            ))
        })?;
        if class_binding.tool_name != step.tool_name {
            return Err(ChioPackageError::Workflow(format!(
                "step {} class binding tool does not match step",
                step.step_index
            )));
        }
        if class_binding.peer_kernel_id != predicate.tool_server_b.kernel_id {
            return Err(ChioPackageError::Workflow(format!(
                "step {} peer kernel does not match DSSE tool_server_b",
                step.step_index
            )));
        }
        let lease_ref = predicate.capability_lease_ref.as_ref().ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "step {} DSSE predicate has no capability lease ref",
                step.step_index
            ))
        })?;
        let lease = leases_by_id.get(&lease_ref.lease_id).ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "step {} lease {} is not present in package",
                step.step_index, lease_ref.lease_id
            ))
        })?;
        if lease.body.subject != class_binding.peer_kernel_id {
            return Err(ChioPackageError::Workflow(format!(
                "step {} lease subject does not match workflow peer binding",
                step.step_index
            )));
        }
        let destructive = step.destructive.unwrap_or(false);
        let lease_destructive =
            lease.body.action_class == CapabilityLeaseActionClass::NarrowDestructive;
        if destructive != lease_destructive {
            return Err(ChioPackageError::Workflow(format!(
                "step {} destructive flag does not match lease action class",
                step.step_index
            )));
        }
        match (
            destructive,
            step.governance_receipt_id.as_ref(),
            predicate.governance_receipt_ref.as_ref(),
        ) {
            (true, Some(step_receipt_id), Some(predicate_receipt)) => {
                if step_receipt_id != &predicate_receipt.receipt_id {
                    return Err(ChioPackageError::Workflow(format!(
                        "step {} governance receipt id does not match DSSE predicate",
                        step.step_index
                    )));
                }
            }
            (true, None, _) => {
                return Err(ChioPackageError::Workflow(format!(
                    "step {} destructive action has no governance receipt id",
                    step.step_index
                )));
            }
            (true, _, None) => {
                return Err(ChioPackageError::Workflow(format!(
                    "step {} destructive action has no DSSE governance receipt ref",
                    step.step_index
                )));
            }
            (false, Some(_), _) | (false, _, Some(_)) => {
                return Err(ChioPackageError::Workflow(format!(
                    "step {} non-destructive action carries governance receipt material",
                    step.step_index
                )));
            }
            (false, None, None) => {}
        }
        previous_step_sha256 = Some(canonical_sha256(step)?);
    }
    Ok(())
}

fn verify_lease_scope_bindings(
    package: &ChioProofPackage,
) -> Result<BTreeMap<String, String>, ChioPackageError> {
    if package.lease_scope_bindings.len() != package.capability_leases.len() {
        return Err(ChioPackageError::LeaseScopeBinding(
            "lease scope binding count does not match capability lease count".to_string(),
        ));
    }
    let leases_by_id = package
        .capability_leases
        .iter()
        .map(|lease| (lease.body.lease_id.clone(), lease))
        .collect::<HashMap<_, _>>();
    let step_classes = package
        .workflow_intersection
        .step_class_bindings
        .iter()
        .map(|binding| (binding.step_index, binding))
        .collect::<HashMap<_, _>>();
    let receipts_by_step = package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| {
            let receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
                ChioPackageError::LeaseScopeBinding(format!(
                    "step {} has no tool receipt id",
                    step.step_index
                ))
            })?;
            let receipt = package
                .tool_receipts
                .iter()
                .find(|receipt| &receipt.id == receipt_id)
                .ok_or_else(|| {
                    ChioPackageError::LeaseScopeBinding(format!(
                        "step {} tool receipt {} is not present",
                        step.step_index, receipt_id
                    ))
                })?;
            Ok((step.step_index, (step, receipt)))
        })
        .collect::<Result<HashMap<_, _>, ChioPackageError>>()?;

    let mut scope_digests = BTreeMap::new();
    for binding in &package.lease_scope_bindings {
        binding.validate()?;
        if scope_digests.contains_key(&binding.lease_id) {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "duplicate lease scope binding {}",
                binding.lease_id
            )));
        }
        let lease = leases_by_id.get(&binding.lease_id).ok_or_else(|| {
            ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} has no matching lease",
                binding.lease_id
            ))
        })?;
        let (step, receipt) = receipts_by_step.get(&binding.step_index).ok_or_else(|| {
            ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} references missing step {}",
                binding.lease_id, binding.step_index
            ))
        })?;
        let class_binding = step_classes.get(&binding.step_index).ok_or_else(|| {
            ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} references step without class binding",
                binding.lease_id
            ))
        })?;
        if binding.workflow_id != package.workflow_id {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} workflow id mismatch",
                binding.lease_id
            )));
        }
        if binding.workflow_grant_id != package.workflow_receipt.capability_id {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} workflow grant mismatch",
                binding.lease_id
            )));
        }
        if binding.tool_name != step.tool_name || binding.tool_name != receipt.tool_name {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} tool mismatch",
                binding.lease_id
            )));
        }
        if binding.peer_kernel_id != class_binding.peer_kernel_id {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} peer mismatch",
                binding.lease_id
            )));
        }
        if binding.action_class_id != class_binding.action_class_id {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} action class id mismatch",
                binding.lease_id
            )));
        }
        if binding.subject != lease.body.subject {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} subject mismatch",
                binding.lease_id
            )));
        }
        if binding.action_class != lease.body.action_class {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} action class mismatch",
                binding.lease_id
            )));
        }
        if binding.tool_args_hash != receipt.action.parameter_hash {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} tool args hash mismatch",
                binding.lease_id
            )));
        }
        if binding.destructive != step.destructive.unwrap_or(false) {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} destructive flag mismatch",
                binding.lease_id
            )));
        }
        if binding.issued_at_unix_ms != lease.body.issued_at_unix_ms
            || binding.expires_at_unix_ms != lease.body.expires_at_unix_ms
        {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} time window mismatch",
                binding.lease_id
            )));
        }
        let scope_digest = binding.scope_digest()?;
        if lease.body.scope_digest != scope_digest {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} digest mismatch",
                binding.lease_id
            )));
        }
        scope_digests.insert(binding.lease_id.clone(), scope_digest);
    }
    Ok(scope_digests)
}

fn verify_trusted_capability_lease(
    lease: &SignedCapabilityLease,
    trust_bundle: &ChioVerifierTrustBundle,
    scope_digest: &str,
) -> Result<(), ChioPackageError> {
    let authority = trust_bundle
        .lease_authority(&lease.body.issuer)
        .ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "lease authority {} is not trusted",
                lease.body.issuer
            ))
        })?;
    trust_bundle.ensure_public_key_not_revoked(&authority.public_key, "lease authority")?;
    let (valid_from, valid_until) = authority_window(
        authority.valid_from_unix_ms,
        authority.valid_until_unix_ms,
        "lease authority",
    )?;
    let now_unix_ms = trust_bundle.verification_time_unix_ms();
    if now_unix_ms < valid_from || now_unix_ms >= valid_until {
        return Err(ChioPackageError::Governance(format!(
            "lease authority {} is not active at the verifier epoch",
            lease.body.issuer
        )));
    }
    if lease.body.issued_at_unix_ms > now_unix_ms {
        return Err(ChioPackageError::Governance(format!(
            "lease {} is issued in the future",
            lease.body.lease_id
        )));
    }
    if lease.body.issued_at_unix_ms < valid_from || lease.body.issued_at_unix_ms >= valid_until {
        return Err(ChioPackageError::Governance(format!(
            "lease {} is outside the lease authority validity window",
            lease.body.lease_id
        )));
    }
    if lease.signer_key != authority.public_key {
        return Err(ChioPackageError::Governance(format!(
            "lease authority {} signer key mismatch",
            lease.body.issuer
        )));
    }
    if !authority
        .allowed_action_classes
        .contains(&lease.body.action_class)
    {
        return Err(ChioPackageError::Governance(format!(
            "lease authority {} is not trusted for action class {:?}",
            lease.body.issuer, lease.body.action_class
        )));
    }
    verify_capability_lease(lease, now_unix_ms, Some(scope_digest.to_string()))
        .map_err(|error| ChioPackageError::Governance(error.to_string()))
}

fn verify_trusted_governance_receipt(
    receipt: &SignedGovernanceReceipt,
    trust_bundle: &ChioVerifierTrustBundle,
) -> Result<(), ChioPackageError> {
    let authority = trust_bundle
        .governance_authority(&receipt.body.authorizing_kernel)
        .ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "governance authority {} is not trusted",
                receipt.body.authorizing_kernel
            ))
        })?;
    trust_bundle.ensure_public_key_not_revoked(&authority.public_key, "governance authority")?;
    let (valid_from, valid_until) = authority_window(
        authority.valid_from_unix_ms,
        authority.valid_until_unix_ms,
        "governance authority",
    )?;
    let now_unix_ms = trust_bundle.verification_time_unix_ms();
    if now_unix_ms < valid_from || now_unix_ms >= valid_until {
        return Err(ChioPackageError::Governance(format!(
            "governance authority {} is not active at the verifier epoch",
            receipt.body.authorizing_kernel
        )));
    }
    if receipt.body.issued_at_unix_ms > now_unix_ms {
        return Err(ChioPackageError::Governance(format!(
            "governance receipt {} is issued in the future",
            receipt.body.receipt_id
        )));
    }
    if receipt.body.issued_at_unix_ms < valid_from || receipt.body.issued_at_unix_ms >= valid_until
    {
        return Err(ChioPackageError::Governance(format!(
            "governance receipt {} is outside the governance authority validity window",
            receipt.body.receipt_id
        )));
    }
    if receipt.signer_key != authority.public_key {
        return Err(ChioPackageError::Governance(format!(
            "governance authority {} signer key mismatch",
            receipt.body.authorizing_kernel
        )));
    }
    if !authority
        .allowed_case_kinds
        .contains(&receipt.body.case_kind)
    {
        return Err(ChioPackageError::Governance(format!(
            "governance authority {} is not trusted for case kind {:?}",
            receipt.body.authorizing_kernel, receipt.body.case_kind
        )));
    }
    verify_step_governance_boundary(true, Some(receipt), now_unix_ms)
        .map_err(|error| ChioPackageError::Governance(error.to_string()))
}

fn verify_destructive_steps(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    lease_scope_digests: &BTreeMap<String, String>,
) -> Result<(), ChioPackageError> {
    let leases_by_id = package
        .capability_leases
        .iter()
        .map(|lease| (lease.body.lease_id.clone(), lease))
        .collect::<HashMap<_, _>>();
    let governance_by_id = package
        .governance_receipts
        .iter()
        .map(|receipt| (receipt.body.receipt_id.clone(), receipt))
        .collect::<HashMap<_, _>>();
    let receipts_by_id = package
        .tool_receipts
        .iter()
        .map(|receipt| (receipt.id.clone(), receipt))
        .collect::<HashMap<_, _>>();
    for step in &package.workflow_receipt.steps {
        if !step.destructive.unwrap_or(false) {
            continue;
        }
        let governance_id = step.governance_receipt_id.as_ref().ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "destructive step {} has no governance receipt id",
                step.step_index
            ))
        })?;
        let governance_receipt = governance_by_id.get(governance_id).ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "governance receipt {governance_id} is not present in package"
            ))
        })?;
        let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "destructive step {} has no tool receipt id",
                step.step_index
            ))
        })?;
        let tool_receipt = receipts_by_id.get(tool_receipt_id).ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "tool receipt {tool_receipt_id} is not present in package"
            ))
        })?;
        let step_sha256 = canonical_sha256(&tool_receipt.body())?;
        let lease = leases_by_id
            .get(&governance_receipt.body.authorized_lease_id)
            .ok_or_else(|| {
                ChioPackageError::Governance(format!(
                    "lease {} is not present in package",
                    governance_receipt.body.authorized_lease_id
                ))
            })?;
        let scope_digest = lease_scope_digests
            .get(&lease.body.lease_id)
            .ok_or_else(|| {
                ChioPackageError::LeaseScopeBinding(format!(
                    "lease {} has no scope binding",
                    lease.body.lease_id
                ))
            })?;
        verify_capability_lease(
            lease,
            trust_bundle.verification_time_unix_ms(),
            Some(scope_digest.clone()),
        )
        .map_err(|error| ChioPackageError::Governance(error.to_string()))?;
        if governance_receipt.body.issued_at_unix_ms < lease.body.issued_at_unix_ms
            || governance_receipt.body.expires_at_unix_ms > lease.body.expires_at_unix_ms
        {
            return Err(ChioPackageError::Governance(format!(
                "governance receipt {} is outside lease {} validity window",
                governance_receipt.body.receipt_id, lease.body.lease_id
            )));
        }
        verify_destructive_authorization(
            governance_receipt,
            &lease.body.lease_id,
            &package.workflow_id,
            &step_sha256,
            trust_bundle.verification_time_unix_ms(),
        )
        .map_err(|error| ChioPackageError::Governance(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use chio_core_types::crypto::Keypair;
    use chio_core_types::receipt::SignedExportEnvelope;

    fn trust_bundle_document_from_fixture() -> ChioVerifierTrustBundleDocument {
        serde_json::from_str(include_str!(
            "../../../examples/chio-3vendor/fixtures/verifier-trust-bundle.json"
        ))
        .expect("trust bundle fixture parses")
    }

    fn trust_bundle_from_fixture() -> Result<ChioVerifierTrustBundle, ChioPackageError> {
        ChioVerifierTrustBundle::from_document(trust_bundle_document_from_fixture())
    }

    fn verification_context_from_fixture() -> ChioVerificationContext {
        verification_context_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/verification-context.json"
        ))
        .expect("verification context fixture parses")
    }

    fn trust_bundle_with_revocations(
        revoked_key_fingerprints: Vec<String>,
    ) -> ChioVerifierTrustBundle {
        let mut document = trust_bundle_document_from_fixture();
        let ChioRevocationMaterial::Checkpoint(checkpoint) = document.revocation else {
            panic!("fixture carries signed revocation checkpoint");
        };
        let checkpoint = *checkpoint;
        let mut body = checkpoint.body;
        body.revoked_key_fingerprints = revoked_key_fingerprints;
        document.revocation = ChioRevocationMaterial::Checkpoint(Box::new(
            SignedExportEnvelope::sign(body, &Keypair::from_seed(&[11; 32]))
                .expect("revocation checkpoint re-signs"),
        ));
        ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses")
    }

    fn resign_lease(lease: &mut SignedCapabilityLease) {
        *lease = SignedExportEnvelope::sign(lease.body.clone(), &Keypair::from_seed(&[11; 32]))
            .expect("lease re-signs");
    }

    fn resign_governance_receipt(receipt: &mut SignedGovernanceReceipt) {
        *receipt = SignedExportEnvelope::sign(receipt.body.clone(), &Keypair::from_seed(&[12; 32]))
            .expect("governance receipt re-signs");
    }

    #[test]
    fn committed_fixture_verifies_through_production_crate() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
        let context = verification_context_from_fixture();
        let report =
            verify_package(&package, &trust_bundle, &context).expect("package fixture verifies");
        assert!(report.accepted);
        assert_eq!(report.schema, VERIFIER_REPORT_SCHEMA);
        assert!(report
            .checks
            .iter()
            .any(|check| check.code == "workflow.intersection"));
        let context_sha256 = verification_context_sha256(&context).expect("context hash computes");
        assert_eq!(
            report.context_sha256.as_deref(),
            Some(context_sha256.as_str())
        );
    }

    #[test]
    fn proof_package_parser_rejects_treaty_bilateral_side_channel() {
        let mut package: serde_json::Value = serde_json::from_str(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses as JSON");
        package["treatyBilateralEnvelopes"] = serde_json::json!([]);
        let err = proof_package_from_json(&package.to_string())
            .expect_err("canonical proof package parser must reject unknown side-channel fields");
        assert!(err.to_string().contains("treatyBilateralEnvelopes"));
    }

    #[test]
    fn verifier_report_parses_through_production_api() {
        let report = verifier_report_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/verifier-report.json"
        ))
        .expect("report fixture parses");
        assert!(report.accepted);
        assert_eq!(report.schema, VERIFIER_REPORT_SCHEMA);
        assert!(report.context_sha256.is_some());
        assert!(report.revocation_epoch_height.is_some());
    }

    #[test]
    fn verifier_trust_bundle_may_contain_unrelated_trust_roots() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let mut document = trust_bundle_document_from_fixture();

        let mut extra_peer = document.peers[0].clone();
        extra_peer.kernel_id = "did:chio:unrelated-peer".to_string();
        extra_peer.ladder_manifest_ref.manifest_id = "ladder:unrelated:v1".to_string();
        document.peers.push(extra_peer);

        let mut extra_vendor = document.vendors[0].clone();
        extra_vendor.vendor_id = "vendor-unrelated".to_string();
        document.vendors.push(extra_vendor);

        let trust_bundle =
            ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses");
        let context = verification_context_from_fixture();
        let report =
            verify_package(&package, &trust_bundle, &context).expect("package fixture verifies");

        assert!(report.accepted);
    }

    #[test]
    fn verifier_trust_bundle_requires_signed_fresh_revocation_checkpoint() {
        let mut document = serde_json::to_value(trust_bundle_document_from_fixture())
            .expect("trust bundle serializes");
        assert_eq!(
            document["schema"],
            serde_json::Value::String(VERIFIER_TRUST_BUNDLE_SCHEMA.to_string())
        );

        document["revocation"]["body"]["expiresAtUnixMs"] =
            serde_json::Value::Number(serde_json::Number::from(1_u64));
        let error = verifier_trust_bundle_from_json(
            &serde_json::to_string(&document).expect("trust bundle json serializes"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("revocation"));

        let mut unsigned = serde_json::to_value(trust_bundle_document_from_fixture())
            .expect("trust bundle serializes");
        unsigned["revocation"]["signature"] = serde_json::Value::String("00".to_string());
        let error = verifier_trust_bundle_from_json(
            &serde_json::to_string(&unsigned).expect("trust bundle json serializes"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("revocation") || error.to_string().contains("JSON"));
    }

    #[test]
    fn revocation_checkpoint_must_cover_verifier_context() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let context = verification_context_from_fixture();
        let mut document = trust_bundle_document_from_fixture();
        let ChioRevocationMaterial::Checkpoint(checkpoint) = document.revocation else {
            panic!("fixture carries signed revocation checkpoint");
        };
        let checkpoint = *checkpoint;
        let mut body = checkpoint.body;
        body.expires_at_unix_ms = context.expires_at_unix_ms - 1;
        document.revocation = ChioRevocationMaterial::Checkpoint(Box::new(
            SignedExportEnvelope::sign(body, &Keypair::from_seed(&[11; 32]))
                .expect("revocation checkpoint re-signs"),
        ));
        let trust_bundle = ChioVerifierTrustBundle::from_document(document)
            .expect("trust bundle remains structurally valid");

        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("revocation checkpoint"));
        assert!(error.to_string().contains("stale"));
    }

    #[test]
    fn revoked_trust_roots_fail_closed() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let context = verification_context_from_fixture();

        let revoked_peer = key_fingerprint(&package.peer_ladder_bindings[1].public_key);
        let trust_bundle = trust_bundle_with_revocations(vec![revoked_peer]);
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("revoked"));

        let revoked_vendor = key_fingerprint(&package.vendor_keys[0].public_key);
        let trust_bundle = trust_bundle_with_revocations(vec![revoked_vendor]);
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("revoked"));

        let revoked_issuer = package
            .selective_disclosure_proof
            .issuer_fingerprint
            .clone();
        let trust_bundle = trust_bundle_with_revocations(vec![revoked_issuer]);
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("revoked"));
    }

    #[test]
    fn revoked_authority_roots_fail_closed() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let context = verification_context_from_fixture();
        let document = trust_bundle_document_from_fixture();

        let revoked_lease_authority = key_fingerprint(&document.lease_authorities[0].public_key);
        let trust_bundle = trust_bundle_with_revocations(vec![revoked_lease_authority]);
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("revoked"));

        let revoked_governance_authority =
            key_fingerprint(&document.governance_authorities[0].public_key);
        let trust_bundle = trust_bundle_with_revocations(vec![revoked_governance_authority]);
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("revoked"));
    }

    #[test]
    fn authority_lifecycle_and_artifact_time_windows_fail_closed() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let context = verification_context_from_fixture();
        let mut document = trust_bundle_document_from_fixture();
        document.lease_authorities[0].valid_from_unix_ms = Some(1);
        document.lease_authorities[0].valid_until_unix_ms = Some(2);
        let trust_bundle =
            ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses");
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("not active"));

        let mut inactive = trust_bundle_document_from_fixture();
        inactive.governance_authorities[0].status = Some(ChioAuthorityStatus::Inactive);
        let error = ChioVerifierTrustBundle::from_document(inactive).unwrap_err();
        assert!(error.to_string().contains("status"));

        let mut future_package = package.clone();
        future_package.lease_scope_bindings[0].issued_at_unix_ms = 1_766_000_010_000;
        future_package.capability_leases[0].body.issued_at_unix_ms = 1_766_000_010_000;
        future_package.capability_leases[0].body.scope_digest = future_package.lease_scope_bindings
            [0]
        .scope_digest()
        .expect("scope digest rebuilds");
        resign_lease(&mut future_package.capability_leases[0]);
        let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
        let error = verify_package(&future_package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("future"));

        let mut outside_lease = package;
        outside_lease.governance_receipts[0].body.expires_at_unix_ms =
            outside_lease.capability_leases[2].body.expires_at_unix_ms + 1;
        resign_governance_receipt(&mut outside_lease.governance_receipts[0]);
        let error = verify_package(&outside_lease, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("outside lease"));
    }

    #[test]
    fn context_and_disclosure_contract_fail_closed() {
        let mut package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
        let mut context = verification_context_from_fixture();
        context.expires_at_unix_ms = 1_766_000_000_000;
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("expired"));

        let context = verification_context_from_fixture();
        package.selective_disclosure_proof.projection_version =
            "chio.bbs-projection.workflow.v0".to_string();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("projection version"));

        let mut package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        package.selective_disclosure_proof.disclosed_indices.push(4);
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("duplicate disclosed index"));

        let mut package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        package.selective_disclosure_proof.ciphersuite = "unsupported".to_string();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("ciphersuite"));
    }

    #[test]
    fn trusted_issuer_registry_rejects_invalid_empty_and_duplicate_documents() {
        let wrong_schema = TrustedIssuerRegistryDocument {
            schema: "chio.attest.trusted-issuer-registry.v0".to_string(),
            issuers: vec![TrustedBbsIssuer {
                issuer_fingerprint: "a".repeat(64),
                public_key_hex: "aa".repeat(48),
            }],
        };
        let error = TrustedIssuerRegistry::from_document(wrong_schema).unwrap_err();
        assert!(error.to_string().contains("unsupported"));

        let empty = TrustedIssuerRegistryDocument {
            schema: TRUSTED_ISSUER_REGISTRY_SCHEMA.to_string(),
            issuers: Vec::new(),
        };
        let error = TrustedIssuerRegistry::from_document(empty).unwrap_err();
        assert!(error.to_string().contains("empty"));

        let duplicate = TrustedIssuerRegistryDocument {
            schema: TRUSTED_ISSUER_REGISTRY_SCHEMA.to_string(),
            issuers: vec![
                TrustedBbsIssuer {
                    issuer_fingerprint: "a".repeat(64),
                    public_key_hex: "aa".repeat(48),
                },
                TrustedBbsIssuer {
                    issuer_fingerprint: "a".repeat(64),
                    public_key_hex: "bb".repeat(48),
                },
            ],
        };
        let error = TrustedIssuerRegistry::from_document(duplicate).unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn verifier_trust_bundle_rejects_empty_and_duplicate_documents() {
        let mut empty = trust_bundle_document_from_fixture();
        empty.trusted_bbs_issuers.clear();
        let error = ChioVerifierTrustBundle::from_document(empty).unwrap_err();
        assert!(error.to_string().contains("must contain"));

        let mut duplicate_peer = trust_bundle_document_from_fixture();
        duplicate_peer.peers.push(duplicate_peer.peers[0].clone());
        let error = ChioVerifierTrustBundle::from_document(duplicate_peer).unwrap_err();
        assert!(error.to_string().contains("duplicate trusted peer"));

        let mut duplicate_vendor = trust_bundle_document_from_fixture();
        duplicate_vendor
            .vendors
            .push(duplicate_vendor.vendors[0].clone());
        let error = ChioVerifierTrustBundle::from_document(duplicate_vendor).unwrap_err();
        assert!(error.to_string().contains("duplicate trusted vendor"));

        let mut duplicate_action = trust_bundle_document_from_fixture();
        duplicate_action
            .action_classes
            .push(duplicate_action.action_classes[0].clone());
        let error = ChioVerifierTrustBundle::from_document(duplicate_action).unwrap_err();
        assert!(error.to_string().contains("duplicate trusted action class"));

        let mut duplicate_intersection = trust_bundle_document_from_fixture();
        duplicate_intersection
            .workflow_intersections
            .push(duplicate_intersection.workflow_intersections[0].clone());
        let error = ChioVerifierTrustBundle::from_document(duplicate_intersection).unwrap_err();
        assert!(error
            .to_string()
            .contains("duplicate trusted workflow intersection"));
    }

    #[test]
    fn verifier_trust_bundle_requires_reference_workflow_classes() {
        let mut missing_grant = trust_bundle_document_from_fixture();
        missing_grant
            .action_classes
            .retain(|class| class.action_class_id != WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID);
        let error = ChioVerifierTrustBundle::from_document(missing_grant).unwrap_err();
        assert!(error
            .to_string()
            .contains(WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID));

        let mut missing_aggregate = trust_bundle_document_from_fixture();
        missing_aggregate
            .action_classes
            .retain(|class| class.action_class_id != WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID);
        let error = ChioVerifierTrustBundle::from_document(missing_aggregate).unwrap_err();
        assert!(error
            .to_string()
            .contains(WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID));
    }

    #[test]
    fn verifier_trust_bundle_v3_requires_authority_roots() {
        let mut document = serde_json::to_value(trust_bundle_document_from_fixture())
            .expect("trust bundle serializes");
        document["leaseAuthorities"] = serde_json::Value::Array(Vec::new());
        document["governanceAuthorities"] = serde_json::Value::Array(Vec::new());

        let error = verifier_trust_bundle_from_json(
            &serde_json::to_string(&document).expect("trust bundle json serializes"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("authorit"));
    }

    #[test]
    #[ignore = "v1-only collapse: v1 is now the strict schema, not a historical one"]
    fn historical_v1_trust_bundle_is_not_strict_verifier_input() {
        // Predates the Chio-owned pre-release v1-only collapse. Kept here as a
        // marker so the historical-rejection contract can be revived if a
        // future revision reintroduces multiple trust-bundle schema versions.
        let mut document = trust_bundle_document_from_fixture();
        document.schema = VERIFIER_TRUST_BUNDLE_SCHEMA.to_string();

        let error = ChioVerifierTrustBundle::from_document(document).unwrap_err();
        assert!(error.to_string().contains("historical"));
    }

    #[test]
    fn forged_lease_signer_fails_even_when_embedded_signature_is_valid() {
        let mut package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
        let forged_key = Keypair::from_seed(&[88; 32]);
        package.capability_leases[0] =
            SignedExportEnvelope::sign(package.capability_leases[0].body.clone(), &forged_key)
                .expect("lease re-signs");

        let context = verification_context_from_fixture();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("lease authority"));
    }

    #[test]
    fn forged_governance_signer_fails_even_when_embedded_signature_is_valid() {
        let mut package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
        let forged_key = Keypair::from_seed(&[89; 32]);
        package.governance_receipts[0] =
            SignedExportEnvelope::sign(package.governance_receipts[0].body.clone(), &forged_key)
                .expect("governance receipt re-signs");

        let context = verification_context_from_fixture();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("governance authority"));
    }

    #[test]
    fn package_bbs_issuer_must_be_externally_trusted() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let mut document = trust_bundle_document_from_fixture();
        document.trusted_bbs_issuers[0].issuer_fingerprint = "f".repeat(64);
        document.trusted_bbs_issuers[0].public_key_hex = "aa".repeat(48);
        let trust_bundle =
            ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses");

        let context = verification_context_from_fixture();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("issuer"));
        assert!(error.to_string().contains("trusted"));
    }

    #[test]
    fn package_bbs_issuer_key_must_match_trusted_registry() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let mut document = trust_bundle_document_from_fixture();
        document.trusted_bbs_issuers[0].issuer_fingerprint = package
            .selective_disclosure_proof
            .issuer_fingerprint
            .clone();
        document.trusted_bbs_issuers[0].public_key_hex = "aa".repeat(96);
        let trust_bundle =
            ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses");

        let context = verification_context_from_fixture();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("issuer public key"));
    }

    #[test]
    fn wrong_verifier_context_nonce_fails_and_report_keeps_prior_checks() {
        let package = proof_package_from_json(include_str!(
            "../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
        let mut context = verification_context_from_fixture();
        context.challenge = "challenge-mismatch".to_string();

        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("proof nonce"));

        let report = verify_package_report(&package, &trust_bundle, &context);
        assert!(!report.accepted);
        assert_eq!(
            report.failure.as_ref().expect("failure").code,
            "bbs.context_nonce"
        );
        assert!(report
            .checks
            .iter()
            .any(|check| check.code == "trust.bbs_issuer"));
    }
}
