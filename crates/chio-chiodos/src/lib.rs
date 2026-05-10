//! Offline Chiodos buyer and auditor proof package verification.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chio_core_types::canonical::{canonical_json_bytes, canonical_json_string};
use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_core_types::receipt::ChioReceipt;
use chio_federation::{
    verify_chiodos_bilateral_invocation, ActionClassKind, DemoAllowAllRevocationOracle,
    DsseEnvelope, InMemoryGovernanceReceiptStore, InMemoryLeaseRegistry, InMemoryReceiptStore,
    LadderManifestRef, PeerPinSet, PinnedEpoch, PinnedPeer, ResolvedGovernanceReceipt,
    ResolvedLease, StrictChiodosVerifierConfig, UnknownActionClassPolicy, VerifierConfig,
};
use chio_governance::{
    verify_capability_lease, verify_destructive_authorization, verify_step_governance_boundary,
    SignedCapabilityLease, SignedGovernanceReceipt,
};
use chio_selective_disclosure::{
    project_workflow_receipt_body, verify_selective_disclosure_proof, InMemoryIssuerRegistry,
    SelectiveDisclosureProof,
};
use chio_workflow::receipt::{VendorSignatureRequirement, WorkflowReceipt};
use serde::{Deserialize, Serialize};

pub const PROOF_PACKAGE_SCHEMA: &str = "chio.chiodos.proof-package.v1";
pub const VERIFIER_REPORT_SCHEMA: &str = "chio.chiodos.verifier-report.v1";
pub const TRUSTED_ISSUER_REGISTRY_SCHEMA: &str = "chio.chiodos.trusted-issuer-registry.v1";
pub const VERIFIER_TRUST_BUNDLE_SCHEMA: &str = "chio.chiodos.verifier-trust-bundle.v1";
pub const WORKFLOW_INTERSECTION_SCHEMA: &str = "chio.chiodos-workflow-intersection.v1";

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
    ) -> Result<Self, ChiodosPackageError> {
        if document.schema != TRUSTED_ISSUER_REGISTRY_SCHEMA {
            return Err(ChiodosPackageError::TrustedIssuer(format!(
                "trusted issuer registry schema {} is unsupported",
                document.schema
            )));
        }
        if document.issuers.is_empty() {
            return Err(ChiodosPackageError::TrustedIssuer(
                "trusted issuer registry is empty".to_string(),
            ));
        }

        let mut public_keys = BTreeMap::new();
        for issuer in document.issuers {
            validate_non_empty(&issuer.issuer_fingerprint, "issuerFingerprint")?;
            validate_non_empty(&issuer.public_key_hex, "publicKeyHex")?;
            if !is_lower_hex(&issuer.issuer_fingerprint) {
                return Err(ChiodosPackageError::TrustedIssuer(format!(
                    "issuerFingerprint {} is not lowercase hex",
                    issuer.issuer_fingerprint
                )));
            }
            if !is_lower_hex(&issuer.public_key_hex) || issuer.public_key_hex.len() % 2 != 0 {
                return Err(ChiodosPackageError::TrustedIssuer(format!(
                    "publicKeyHex for issuer {} is not lowercase even-length hex",
                    issuer.issuer_fingerprint
                )));
            }
            if public_keys
                .insert(issuer.issuer_fingerprint.clone(), issuer.public_key_hex)
                .is_some()
            {
                return Err(ChiodosPackageError::TrustedIssuer(format!(
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
pub enum ChiodosActionClassKind {
    Routine,
    ReceiptBacked,
}

impl From<ChiodosActionClassKind> for ActionClassKind {
    fn from(value: ChiodosActionClassKind) -> Self {
        match value {
            ChiodosActionClassKind::Routine => ActionClassKind::Routine,
            ChiodosActionClassKind::ReceiptBacked => ActionClassKind::ReceiptBacked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChiodosTrustedActionClass {
    pub action_class_id: String,
    pub tool_name: String,
    pub kind: ChiodosActionClassKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChiodosTrustedWorkflowIntersection {
    pub intersection_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChiodosPinnedRevocationEpoch {
    pub now_unix_ms: u64,
    pub epoch_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChiodosVerifierTrustBundleDocument {
    pub schema: String,
    pub trusted_bbs_issuers: Vec<TrustedBbsIssuer>,
    pub peers: Vec<PeerLadderBinding>,
    pub vendors: Vec<VendorKeyBinding>,
    pub action_classes: Vec<ChiodosTrustedActionClass>,
    pub workflow_intersections: Vec<ChiodosTrustedWorkflowIntersection>,
    pub revocation: ChiodosPinnedRevocationEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChiodosVerifierTrustBundle {
    issuer_registry: TrustedIssuerRegistry,
    peers: BTreeMap<String, PeerLadderBinding>,
    vendors: BTreeMap<String, VendorKeyBinding>,
    action_classes: BTreeMap<String, ChiodosTrustedActionClass>,
    workflow_intersections: BTreeMap<String, String>,
    revocation: ChiodosPinnedRevocationEpoch,
}

impl ChiodosVerifierTrustBundle {
    pub fn from_document(
        document: ChiodosVerifierTrustBundleDocument,
    ) -> Result<Self, ChiodosPackageError> {
        if document.schema != VERIFIER_TRUST_BUNDLE_SCHEMA {
            return Err(ChiodosPackageError::TrustBundle(format!(
                "verifier trust bundle schema {} is unsupported",
                document.schema
            )));
        }
        if document.trusted_bbs_issuers.is_empty()
            || document.peers.is_empty()
            || document.vendors.is_empty()
            || document.action_classes.is_empty()
            || document.workflow_intersections.is_empty()
        {
            return Err(ChiodosPackageError::TrustBundle(
                "verifier trust bundle must contain issuers, peers, vendors, action classes, and workflow intersections"
                    .to_string(),
            ));
        }

        let issuer_registry = TrustedIssuerRegistry::from_document(TrustedIssuerRegistryDocument {
            schema: TRUSTED_ISSUER_REGISTRY_SCHEMA.to_string(),
            issuers: document.trusted_bbs_issuers,
        })
        .map_err(|error| ChiodosPackageError::TrustBundle(error.to_string()))?;

        let mut peers = BTreeMap::new();
        for peer in document.peers {
            validate_trust_field(&peer.kernel_id, "peer.kernelId")?;
            peer.ladder_manifest_ref
                .validate()
                .map_err(|error| ChiodosPackageError::TrustBundle(error.to_string()))?;
            if peers.insert(peer.kernel_id.clone(), peer).is_some() {
                return Err(ChiodosPackageError::TrustBundle(
                    "duplicate trusted peer kernel id".to_string(),
                ));
            }
        }

        let mut vendors = BTreeMap::new();
        for vendor in document.vendors {
            validate_trust_field(&vendor.vendor_id, "vendor.vendorId")?;
            if vendors.insert(vendor.vendor_id.clone(), vendor).is_some() {
                return Err(ChiodosPackageError::TrustBundle(
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
                return Err(ChiodosPackageError::TrustBundle(
                    "duplicate trusted action class id".to_string(),
                ));
            }
            if action_classes
                .insert(action_class.tool_name.clone(), action_class)
                .is_some()
            {
                return Err(ChiodosPackageError::TrustBundle(
                    "duplicate trusted action class tool name".to_string(),
                ));
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
                return Err(ChiodosPackageError::TrustBundle(
                    "duplicate trusted workflow intersection id".to_string(),
                ));
            }
        }

        Ok(Self {
            issuer_registry,
            peers,
            vendors,
            action_classes,
            workflow_intersections,
            revocation: document.revocation,
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

    fn pinned_epoch(&self) -> PinnedEpoch {
        PinnedEpoch {
            now_unix_ms: self.revocation.now_unix_ms,
            epoch_height: self.revocation.epoch_height,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChiodosProofClaims {
    pub bbs_reveal_set: bool,
    pub hidden_range_predicates: bool,
    pub vc_data_integrity_bbs: bool,
    pub zkvm: bool,
}

impl ChiodosProofClaims {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChiodosProofPackage {
    pub schema: String,
    pub generated_at_unix_ms: u64,
    pub workflow_id: String,
    pub claims: ChiodosProofClaims,
    pub peer_ladder_bindings: Vec<PeerLadderBinding>,
    pub vendor_keys: Vec<VendorKeyBinding>,
    pub tool_receipts: Vec<ChioReceipt>,
    pub workflow_receipt: WorkflowReceipt,
    pub bilateral_envelopes: Vec<DsseEnvelope>,
    pub capability_leases: Vec<SignedCapabilityLease>,
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
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierReport {
    pub schema: String,
    pub package_sha256: String,
    pub accepted: bool,
    pub checks: Vec<VerifierCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<VerifierFailure>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChiodosPackageError {
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
    #[error("fixture data is inconsistent: {0}")]
    Inconsistent(String),
    #[error("JSON operation failed: {0}")]
    Json(String),
}

fn validate_trust_field(value: &str, field: &str) -> Result<(), ChiodosPackageError> {
    if value.is_empty() {
        return Err(ChiodosPackageError::TrustBundle(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_sha256_hex(value: &str, field: &str) -> Result<(), ChiodosPackageError> {
    if value.len() != 64 || !is_lower_hex(value) {
        return Err(ChiodosPackageError::TrustBundle(format!(
            "{field} must be a lowercase 64-character SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), ChiodosPackageError> {
    if value.is_empty() {
        return Err(ChiodosPackageError::TrustedIssuer(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChiodosPackageError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChiodosPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn canonical_string<T: Serialize>(value: &T) -> Result<String, ChiodosPackageError> {
    canonical_json_string(value).map_err(|error| ChiodosPackageError::Canonical(error.to_string()))
}

fn verify_claims(claims: &ChiodosProofClaims) -> Result<(), ChiodosPackageError> {
    if !claims.bbs_reveal_set {
        return Err(ChiodosPackageError::UnsupportedClaim(
            "bbs reveal-set support must be claimed for this package".to_string(),
        ));
    }
    if claims.hidden_range_predicates {
        return Err(ChiodosPackageError::UnsupportedClaim(
            "hidden range predicates are not supported by this package".to_string(),
        ));
    }
    if claims.vc_data_integrity_bbs {
        return Err(ChiodosPackageError::UnsupportedClaim(
            "VC Data Integrity BBS interop is not supported by this package".to_string(),
        ));
    }
    if claims.zkvm {
        return Err(ChiodosPackageError::UnsupportedClaim(
            "zkVM support is not supported by this package".to_string(),
        ));
    }
    Ok(())
}

pub fn package_from_fixture_json(json: &str) -> Result<ChiodosProofPackage, ChiodosPackageError> {
    serde_json::from_str(json).map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn report_from_fixture_json(json: &str) -> Result<VerifierReport, ChiodosPackageError> {
    serde_json::from_str(json).map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn trusted_issuer_registry_from_json(
    json: &str,
) -> Result<TrustedIssuerRegistry, ChiodosPackageError> {
    let document: TrustedIssuerRegistryDocument =
        serde_json::from_str(json).map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    TrustedIssuerRegistry::from_document(document)
}

pub fn verifier_trust_bundle_from_json(
    json: &str,
) -> Result<ChiodosVerifierTrustBundle, ChiodosPackageError> {
    let document: ChiodosVerifierTrustBundleDocument =
        serde_json::from_str(json).map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    ChiodosVerifierTrustBundle::from_document(document)
}

pub fn package_json(package: &ChiodosProofPackage) -> Result<String, ChiodosPackageError> {
    serde_json::to_string_pretty(package)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn report_json(report: &VerifierReport) -> Result<String, ChiodosPackageError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn trusted_issuer_registry_json(
    registry: &TrustedIssuerRegistryDocument,
) -> Result<String, ChiodosPackageError> {
    serde_json::to_string_pretty(registry)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn verifier_trust_bundle_json(
    trust_bundle: &ChiodosVerifierTrustBundleDocument,
) -> Result<String, ChiodosPackageError> {
    serde_json::to_string_pretty(trust_bundle)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn package_sha256(package: &ChiodosProofPackage) -> Result<String, ChiodosPackageError> {
    let bytes = canonical_json_bytes(package)
        .map_err(|error| ChiodosPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn verify_package(
    package: &ChiodosProofPackage,
    trust_bundle: &ChiodosVerifierTrustBundle,
) -> Result<VerifierReport, ChiodosPackageError> {
    verify_package_inner(package, trust_bundle)
}

pub fn verify_package_report(
    package: &ChiodosProofPackage,
    trust_bundle: &ChiodosVerifierTrustBundle,
) -> VerifierReport {
    match verify_package_inner(package, trust_bundle) {
        Ok(report) => report,
        Err(error) => rejected_report(package, &error),
    }
}

fn verify_package_inner(
    package: &ChiodosProofPackage,
    trust_bundle: &ChiodosVerifierTrustBundle,
) -> Result<VerifierReport, ChiodosPackageError> {
    if package.schema != PROOF_PACKAGE_SCHEMA {
        return Err(ChiodosPackageError::UnsupportedSchema(
            package.schema.clone(),
        ));
    }
    verify_claims(&package.claims)?;

    let mut checks = Vec::new();
    let mut add_check = |code: &str, name: &str| {
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
        .map_err(|error| ChiodosPackageError::Workflow(error.to_string()))?
    {
        return Err(ChiodosPackageError::Workflow(
            "workflow signature is invalid".to_string(),
        ));
    }
    add_check("workflow.kernel_signature", "workflow-kernel-signature");

    verify_package_hints_match_trust(package, trust_bundle)?;
    add_check("trust.package_hints", "package-trust-hints");

    verify_workflow_intersection(package, trust_bundle)?;
    add_check("workflow.intersection", "workflow-intersection");

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
        .map_err(|error| ChiodosPackageError::Workflow(error.to_string()))?;
    add_check(
        "workflow.vendor_cosignatures",
        "workflow-vendor-cosignatures",
    );

    verify_step_links(package)?;
    add_check("workflow.step_links", "workflow-step-links");

    let mut receipt_store = InMemoryReceiptStore::new();
    for receipt in &package.tool_receipts {
        receipt_store.insert(receipt.clone());
    }
    let mut lease_registry = InMemoryLeaseRegistry::new();
    for lease in &package.capability_leases {
        verify_capability_lease(
            lease,
            trust_bundle.revocation.now_unix_ms,
            Some(lease.body.scope_digest.clone()),
        )
        .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
        lease_registry.insert(ResolvedLease {
            lease_id: lease.body.lease_id.clone(),
            issuer: lease.body.issuer.clone(),
            expires_at_unix_ms: lease.body.expires_at_unix_ms,
            scope_digest_hex: Some(lease.body.scope_digest.clone()),
        });
    }
    add_check("governance.capability_leases", "capability-leases");

    let mut governance_store = InMemoryGovernanceReceiptStore::new();
    for receipt in &package.governance_receipts {
        verify_step_governance_boundary(true, Some(receipt), trust_bundle.revocation.now_unix_ms)
            .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: receipt.body.receipt_id.clone(),
            kernel_id: receipt.body.authorizing_kernel.clone(),
            canonical_json: canonical_string(receipt)?,
        });
    }
    verify_destructive_steps(package, trust_bundle)?;
    add_check("governance.receipts", "governance-receipts");

    let mut peer_pin_set = PeerPinSet::new();
    for peer in trust_bundle.peers.values() {
        peer_pin_set.insert(PinnedPeer {
            kernel_id: peer.kernel_id.clone(),
            public_key: peer.public_key.clone(),
            ladder_manifest_ref: Some(peer.ladder_manifest_ref.clone()),
        });
    }
    let revocation_oracle = DemoAllowAllRevocationOracle;
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
        verify_chiodos_bilateral_invocation(
            envelope,
            &StrictChiodosVerifierConfig {
                base: &verifier_config,
            },
        )
        .map_err(|error| ChiodosPackageError::Federation(error.to_string()))?;
    }
    add_check(
        "federation.strict_bilateral_invocations",
        "strict-bilateral-invocations",
    );

    let workflow_projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    if package.selective_disclosure_proof.subject_sha256_hex
        != workflow_projection.subject_sha256_hex
    {
        return Err(ChiodosPackageError::SelectiveDisclosure(
            "BBS proof subject does not match workflow receipt body".to_string(),
        ));
    }
    let trusted_issuer_key = trust_bundle
        .issuer_public_key_hex(&package.selective_disclosure_proof.issuer_fingerprint)
        .ok_or_else(|| {
            ChiodosPackageError::TrustedIssuer(format!(
                "issuer {} is not trusted",
                package.selective_disclosure_proof.issuer_fingerprint
            ))
        })?;
    if trusted_issuer_key != package.selective_disclosure_proof.issuer_public_key_hex {
        return Err(ChiodosPackageError::TrustedIssuer(format!(
            "issuer public key for {} does not match trusted registry",
            package.selective_disclosure_proof.issuer_fingerprint
        )));
    }
    add_check("trust.bbs_issuer", "trusted-bbs-issuer");

    let mut issuer_registry = InMemoryIssuerRegistry::default();
    issuer_registry.insert(
        package
            .selective_disclosure_proof
            .issuer_fingerprint
            .clone(),
        trusted_issuer_key.to_string(),
    );
    verify_selective_disclosure_proof(&package.selective_disclosure_proof, &issuer_registry)
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    add_check("bbs.selective_disclosure", "bbs-selective-disclosure");

    Ok(VerifierReport {
        schema: VERIFIER_REPORT_SCHEMA.to_string(),
        package_sha256: package_sha256(package)?,
        accepted: true,
        checks,
        failure: None,
    })
}

fn rejected_report(package: &ChiodosProofPackage, error: &ChiodosPackageError) -> VerifierReport {
    VerifierReport {
        schema: VERIFIER_REPORT_SCHEMA.to_string(),
        package_sha256: package_sha256(package).unwrap_or_else(|_| "unavailable".to_string()),
        accepted: false,
        checks: Vec::new(),
        failure: Some(VerifierFailure {
            code: failure_code(error).to_string(),
            detail: error.to_string(),
        }),
    }
}

fn failure_code(error: &ChiodosPackageError) -> &'static str {
    match error {
        ChiodosPackageError::Canonical(_) => "canonical_json",
        ChiodosPackageError::UnsupportedSchema(_) => "package.schema",
        ChiodosPackageError::UnsupportedClaim(_) => "package.claim",
        ChiodosPackageError::Workflow(_) => "workflow",
        ChiodosPackageError::Governance(_) => "governance",
        ChiodosPackageError::Federation(_) => "federation",
        ChiodosPackageError::SelectiveDisclosure(_) => "bbs",
        ChiodosPackageError::TrustedIssuer(_) => "trust.bbs_issuer",
        ChiodosPackageError::TrustBundle(_) => "trust.bundle",
        ChiodosPackageError::WorkflowIntersection(_) => "workflow.intersection",
        ChiodosPackageError::Inconsistent(_) => "package.inconsistent",
        ChiodosPackageError::Json(_) => "json",
    }
}

fn verify_package_hints_match_trust(
    package: &ChiodosProofPackage,
    trust_bundle: &ChiodosVerifierTrustBundle,
) -> Result<(), ChiodosPackageError> {
    if package.peer_ladder_bindings.is_empty() {
        return Err(ChiodosPackageError::TrustBundle(
            "package carries no peer ladder hints".to_string(),
        ));
    }
    let mut package_peer_ids = BTreeSet::new();
    for peer in &package.peer_ladder_bindings {
        if !package_peer_ids.insert(peer.kernel_id.clone()) {
            return Err(ChiodosPackageError::TrustBundle(format!(
                "package carries duplicate peer hint {}",
                peer.kernel_id
            )));
        }
        let trusted = trust_bundle.peer(&peer.kernel_id).ok_or_else(|| {
            ChiodosPackageError::TrustBundle(format!(
                "package peer {} is not trusted by verifier trust bundle",
                peer.kernel_id
            ))
        })?;
        if trusted.public_key != peer.public_key {
            return Err(ChiodosPackageError::TrustBundle(format!(
                "package peer {} public key does not match verifier trust bundle",
                peer.kernel_id
            )));
        }
        if trusted.ladder_manifest_ref != peer.ladder_manifest_ref {
            return Err(ChiodosPackageError::TrustBundle(format!(
                "package peer {} ladder ref does not match verifier trust bundle",
                peer.kernel_id
            )));
        }
        if !trusted
            .ladder_manifest_ref
            .is_fresh(trust_bundle.revocation.now_unix_ms)
        {
            return Err(ChiodosPackageError::TrustBundle(format!(
                "trusted ladder ref for {} is stale",
                peer.kernel_id
            )));
        }
    }

    if package.vendor_keys.is_empty() {
        return Err(ChiodosPackageError::TrustBundle(
            "package carries no vendor key hints".to_string(),
        ));
    }
    let mut package_vendor_ids = BTreeSet::new();
    for vendor in &package.vendor_keys {
        if !package_vendor_ids.insert(vendor.vendor_id.clone()) {
            return Err(ChiodosPackageError::TrustBundle(format!(
                "package carries duplicate vendor hint {}",
                vendor.vendor_id
            )));
        }
        let trusted = trust_bundle.vendors.get(&vendor.vendor_id).ok_or_else(|| {
            ChiodosPackageError::TrustBundle(format!(
                "package vendor {} is not trusted by verifier trust bundle",
                vendor.vendor_id
            ))
        })?;
        if trusted.public_key != vendor.public_key {
            return Err(ChiodosPackageError::TrustBundle(format!(
                "package vendor {} public key does not match verifier trust bundle",
                vendor.vendor_id
            )));
        }
    }
    Ok(())
}

fn verify_workflow_intersection(
    package: &ChiodosProofPackage,
    trust_bundle: &ChiodosVerifierTrustBundle,
) -> Result<(), ChiodosPackageError> {
    let intersection = &package.workflow_intersection;
    if intersection.schema != WORKFLOW_INTERSECTION_SCHEMA {
        return Err(ChiodosPackageError::WorkflowIntersection(format!(
            "workflow intersection schema {} is unsupported",
            intersection.schema
        )));
    }
    if intersection.workflow_id != package.workflow_id {
        return Err(ChiodosPackageError::WorkflowIntersection(
            "workflow intersection workflow id does not match package".to_string(),
        ));
    }
    if intersection.workflow_grant_id != package.workflow_receipt.capability_id {
        return Err(ChiodosPackageError::WorkflowIntersection(
            "workflow intersection grant id does not match workflow receipt".to_string(),
        ));
    }

    let aggregate_hash = canonical_sha256(&package.workflow_receipt)?;
    if intersection.aggregate_workflow_receipt_sha256 != aggregate_hash {
        return Err(ChiodosPackageError::WorkflowIntersection(
            "workflow intersection aggregate workflow receipt hash mismatch".to_string(),
        ));
    }

    let artifact_hash = canonical_sha256(intersection)?;
    let trusted_hash = trust_bundle
        .workflow_intersection_hash(&intersection.intersection_id)
        .ok_or_else(|| {
            ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection {} is not trusted",
                intersection.intersection_id
            ))
        })?;
    if trusted_hash != artifact_hash {
        return Err(ChiodosPackageError::WorkflowIntersection(format!(
            "workflow intersection {} hash does not match verifier trust bundle",
            intersection.intersection_id
        )));
    }

    let mut seen_vendor_ids = BTreeSet::new();
    for signer in &intersection.required_vendor_signers {
        let trusted = trust_bundle.vendors.get(&signer.vendor_id).ok_or_else(|| {
            ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection signer {} is not trusted",
                signer.vendor_id
            ))
        })?;
        if !seen_vendor_ids.insert(signer.vendor_id.clone()) {
            return Err(ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate signer {}",
                signer.vendor_id
            )));
        }
        if trusted.public_key != signer.public_key {
            return Err(ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection signer {} key mismatch",
                signer.vendor_id
            )));
        }
    }

    let mut pairwise_by_peer = BTreeMap::new();
    for pairwise in &intersection.pairwise_intersection_refs {
        let trusted = trust_bundle.peer(&pairwise.peer_kernel_id).ok_or_else(|| {
            ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection peer {} is not trusted",
                pairwise.peer_kernel_id
            ))
        })?;
        if trusted.ladder_manifest_ref != pairwise.ladder_manifest_ref {
            return Err(ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection peer {} ladder ref mismatch",
                pairwise.peer_kernel_id
            )));
        }
        if pairwise_by_peer
            .insert(pairwise.peer_kernel_id.clone(), pairwise)
            .is_some()
        {
            return Err(ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate peer {}",
                pairwise.peer_kernel_id
            )));
        }
    }

    if intersection.step_class_bindings.len() != package.workflow_receipt.steps.len() {
        return Err(ChiodosPackageError::WorkflowIntersection(
            "workflow intersection step binding count does not match workflow receipt".to_string(),
        ));
    }
    let mut seen_steps = BTreeSet::new();
    for binding in &intersection.step_class_bindings {
        if !seen_steps.insert(binding.step_index) {
            return Err(ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate step {}",
                binding.step_index
            )));
        }
        let step = package
            .workflow_receipt
            .steps
            .get(binding.step_index)
            .ok_or_else(|| {
                ChiodosPackageError::WorkflowIntersection(format!(
                    "workflow intersection references missing step {}",
                    binding.step_index
                ))
            })?;
        if step.tool_name != binding.tool_name {
            return Err(ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection step {} tool mismatch",
                binding.step_index
            )));
        }
        if !pairwise_by_peer.contains_key(&binding.peer_kernel_id) {
            return Err(ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection step {} references peer {} without pairwise ref",
                binding.step_index, binding.peer_kernel_id
            )));
        }
        let trusted_class = trust_bundle
            .action_classes
            .get(&binding.tool_name)
            .ok_or_else(|| {
                ChiodosPackageError::WorkflowIntersection(format!(
                    "workflow intersection tool {} has no trusted action class",
                    binding.tool_name
                ))
            })?;
        if trusted_class.action_class_id != binding.action_class_id {
            return Err(ChiodosPackageError::WorkflowIntersection(format!(
                "workflow intersection tool {} action class mismatch",
                binding.tool_name
            )));
        }
    }
    Ok(())
}

fn verify_step_links(package: &ChiodosProofPackage) -> Result<(), ChiodosPackageError> {
    if package.workflow_receipt.steps.len() != package.bilateral_envelopes.len() {
        return Err(ChiodosPackageError::Workflow(
            "step count does not match bilateral envelope count".to_string(),
        ));
    }
    let mut previous_step_sha256: Option<String> = None;
    for (step, envelope) in package
        .workflow_receipt
        .steps
        .iter()
        .zip(package.bilateral_envelopes.iter())
    {
        let envelope_sha256 = canonical_sha256(envelope)?;
        if step.bilateral_dsse_sha256.as_deref() != Some(envelope_sha256.as_str()) {
            return Err(ChiodosPackageError::Workflow(format!(
                "step {} DSSE hash does not match envelope",
                step.step_index
            )));
        }
        if step.parent_receipt_sha256 != previous_step_sha256 {
            return Err(ChiodosPackageError::Workflow(format!(
                "step {} parent hash does not match previous step",
                step.step_index
            )));
        }
        previous_step_sha256 = Some(canonical_sha256(step)?);
    }
    Ok(())
}

fn verify_destructive_steps(
    package: &ChiodosProofPackage,
    trust_bundle: &ChiodosVerifierTrustBundle,
) -> Result<(), ChiodosPackageError> {
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
            ChiodosPackageError::Governance(format!(
                "destructive step {} has no governance receipt id",
                step.step_index
            ))
        })?;
        let governance_receipt = governance_by_id.get(governance_id).ok_or_else(|| {
            ChiodosPackageError::Governance(format!(
                "governance receipt {governance_id} is not present in package"
            ))
        })?;
        let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
            ChiodosPackageError::Governance(format!(
                "destructive step {} has no tool receipt id",
                step.step_index
            ))
        })?;
        let tool_receipt = receipts_by_id.get(tool_receipt_id).ok_or_else(|| {
            ChiodosPackageError::Governance(format!(
                "tool receipt {tool_receipt_id} is not present in package"
            ))
        })?;
        let step_sha256 = canonical_sha256(&tool_receipt.body())?;
        let lease = leases_by_id
            .get(&governance_receipt.body.authorized_lease_id)
            .ok_or_else(|| {
                ChiodosPackageError::Governance(format!(
                    "lease {} is not present in package",
                    governance_receipt.body.authorized_lease_id
                ))
            })?;
        verify_capability_lease(
            lease,
            trust_bundle.revocation.now_unix_ms,
            Some(lease.body.scope_digest.clone()),
        )
        .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
        verify_destructive_authorization(
            governance_receipt,
            &lease.body.lease_id,
            &package.workflow_id,
            &step_sha256,
            trust_bundle.revocation.now_unix_ms,
        )
        .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn trust_bundle_document_from_fixture() -> ChiodosVerifierTrustBundleDocument {
        serde_json::from_str(include_str!(
            "../../../examples/chiodos-3vendor/fixtures/verifier-trust-bundle.json"
        ))
        .expect("trust bundle fixture parses")
    }

    fn trust_bundle_from_fixture() -> Result<ChiodosVerifierTrustBundle, ChiodosPackageError> {
        ChiodosVerifierTrustBundle::from_document(trust_bundle_document_from_fixture())
    }

    #[test]
    fn committed_fixture_verifies_through_production_crate() {
        let package = package_from_fixture_json(include_str!(
            "../../../examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let trust_bundle = trust_bundle_from_fixture().expect("trust bundle parses");
        let report = verify_package(&package, &trust_bundle).expect("package fixture verifies");
        assert!(report.accepted);
        assert!(report
            .checks
            .iter()
            .any(|check| check.code == "workflow.intersection"));
    }

    #[test]
    fn verifier_trust_bundle_may_contain_unrelated_trust_roots() {
        let package = package_from_fixture_json(include_str!(
            "../../../examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
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
            ChiodosVerifierTrustBundle::from_document(document).expect("trust bundle parses");
        let report = verify_package(&package, &trust_bundle).expect("package fixture verifies");

        assert!(report.accepted);
    }

    #[test]
    fn trusted_issuer_registry_rejects_invalid_empty_and_duplicate_documents() {
        let wrong_schema = TrustedIssuerRegistryDocument {
            schema: "chio.chiodos.trusted-issuer-registry.v0".to_string(),
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
        let error = ChiodosVerifierTrustBundle::from_document(empty).unwrap_err();
        assert!(error.to_string().contains("must contain"));

        let mut duplicate_peer = trust_bundle_document_from_fixture();
        duplicate_peer.peers.push(duplicate_peer.peers[0].clone());
        let error = ChiodosVerifierTrustBundle::from_document(duplicate_peer).unwrap_err();
        assert!(error.to_string().contains("duplicate trusted peer"));

        let mut duplicate_vendor = trust_bundle_document_from_fixture();
        duplicate_vendor
            .vendors
            .push(duplicate_vendor.vendors[0].clone());
        let error = ChiodosVerifierTrustBundle::from_document(duplicate_vendor).unwrap_err();
        assert!(error.to_string().contains("duplicate trusted vendor"));

        let mut duplicate_action = trust_bundle_document_from_fixture();
        duplicate_action
            .action_classes
            .push(duplicate_action.action_classes[0].clone());
        let error = ChiodosVerifierTrustBundle::from_document(duplicate_action).unwrap_err();
        assert!(error.to_string().contains("duplicate trusted action class"));

        let mut duplicate_intersection = trust_bundle_document_from_fixture();
        duplicate_intersection
            .workflow_intersections
            .push(duplicate_intersection.workflow_intersections[0].clone());
        let error = ChiodosVerifierTrustBundle::from_document(duplicate_intersection).unwrap_err();
        assert!(error
            .to_string()
            .contains("duplicate trusted workflow intersection"));
    }

    #[test]
    fn package_bbs_issuer_must_be_externally_trusted() {
        let package = package_from_fixture_json(include_str!(
            "../../../examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let mut document = trust_bundle_document_from_fixture();
        document.trusted_bbs_issuers[0].issuer_fingerprint = "f".repeat(64);
        document.trusted_bbs_issuers[0].public_key_hex = "aa".repeat(48);
        let trust_bundle =
            ChiodosVerifierTrustBundle::from_document(document).expect("trust bundle parses");

        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(error.to_string().contains("issuer"));
        assert!(error.to_string().contains("trusted"));
    }

    #[test]
    fn package_bbs_issuer_key_must_match_trusted_registry() {
        let package = package_from_fixture_json(include_str!(
            "../../../examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let mut document = trust_bundle_document_from_fixture();
        document.trusted_bbs_issuers[0].issuer_fingerprint = package
            .selective_disclosure_proof
            .issuer_fingerprint
            .clone();
        document.trusted_bbs_issuers[0].public_key_hex = "aa".repeat(96);
        let trust_bundle =
            ChiodosVerifierTrustBundle::from_document(document).expect("trust bundle parses");

        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(error.to_string().contains("issuer public key"));
    }
}
