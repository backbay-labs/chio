//! Offline Chiodos buyer and auditor proof package verification.

use std::collections::{BTreeMap, HashMap};

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
    pub selective_disclosure_proof: SelectiveDisclosureProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierCheck {
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierReport {
    pub schema: String,
    pub package_sha256: String,
    pub accepted: bool,
    pub checks: Vec<VerifierCheck>,
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
    #[error("fixture data is inconsistent: {0}")]
    Inconsistent(String),
    #[error("JSON operation failed: {0}")]
    Json(String),
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

pub fn package_json(package: &ChiodosProofPackage) -> Result<String, ChiodosPackageError> {
    serde_json::to_string_pretty(package)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn report_json(report: &VerifierReport) -> Result<String, ChiodosPackageError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn package_sha256(package: &ChiodosProofPackage) -> Result<String, ChiodosPackageError> {
    let bytes = canonical_json_bytes(package)
        .map_err(|error| ChiodosPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn verify_package(
    package: &ChiodosProofPackage,
) -> Result<VerifierReport, ChiodosPackageError> {
    if package.schema != PROOF_PACKAGE_SCHEMA {
        return Err(ChiodosPackageError::UnsupportedSchema(
            package.schema.clone(),
        ));
    }
    verify_claims(&package.claims)?;

    let mut checks = Vec::new();
    let mut add_check = |name: &str| {
        checks.push(VerifierCheck {
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
    add_check("workflow-kernel-signature");

    let vendor_requirements = package
        .vendor_keys
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
    add_check("workflow-vendor-cosignatures");

    verify_step_links(package)?;
    add_check("workflow-step-links");

    let mut receipt_store = InMemoryReceiptStore::new();
    for receipt in &package.tool_receipts {
        receipt_store.insert(receipt.clone());
    }
    let mut lease_registry = InMemoryLeaseRegistry::new();
    for lease in &package.capability_leases {
        verify_capability_lease(
            lease,
            package.generated_at_unix_ms,
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
    add_check("capability-leases");

    let mut governance_store = InMemoryGovernanceReceiptStore::new();
    for receipt in &package.governance_receipts {
        verify_step_governance_boundary(true, Some(receipt), package.generated_at_unix_ms)
            .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: receipt.body.receipt_id.clone(),
            kernel_id: receipt.body.authorizing_kernel.clone(),
            canonical_json: canonical_string(receipt)?,
        });
    }
    verify_destructive_steps(package)?;
    add_check("governance-receipts");

    let mut peer_pin_set = PeerPinSet::new();
    for peer in &package.peer_ladder_bindings {
        peer_pin_set.insert(PinnedPeer {
            kernel_id: peer.kernel_id.clone(),
            public_key: peer.public_key.clone(),
            ladder_manifest_ref: Some(peer.ladder_manifest_ref.clone()),
        });
    }
    let revocation_oracle = DemoAllowAllRevocationOracle;
    let mut action_classes = BTreeMap::new();
    for step in &package.workflow_receipt.steps {
        let class = if step.destructive.unwrap_or(false) {
            ActionClassKind::ReceiptBacked
        } else {
            ActionClassKind::Routine
        };
        action_classes.insert(step.tool_name.clone(), class);
    }
    let verifier_config = VerifierConfig {
        peer_pin_set: &peer_pin_set,
        receipt_store: &receipt_store,
        lease_registry: &lease_registry,
        governance_receipt_store: &governance_store,
        revocation_oracle: &revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: package.generated_at_unix_ms,
            epoch_height: 0,
        },
        action_classes,
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
    add_check("strict-bilateral-invocations");

    let workflow_projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    if package.selective_disclosure_proof.subject_sha256_hex
        != workflow_projection.subject_sha256_hex
    {
        return Err(ChiodosPackageError::SelectiveDisclosure(
            "BBS proof subject does not match workflow receipt body".to_string(),
        ));
    }
    let mut issuer_registry = InMemoryIssuerRegistry::default();
    issuer_registry.insert(
        package
            .selective_disclosure_proof
            .issuer_fingerprint
            .clone(),
        package
            .selective_disclosure_proof
            .issuer_public_key_hex
            .clone(),
    );
    verify_selective_disclosure_proof(&package.selective_disclosure_proof, &issuer_registry)
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    add_check("bbs-selective-disclosure");

    Ok(VerifierReport {
        schema: VERIFIER_REPORT_SCHEMA.to_string(),
        package_sha256: package_sha256(package)?,
        accepted: true,
        checks,
    })
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

fn verify_destructive_steps(package: &ChiodosProofPackage) -> Result<(), ChiodosPackageError> {
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
            package.generated_at_unix_ms,
            Some(lease.body.scope_digest.clone()),
        )
        .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
        verify_destructive_authorization(
            governance_receipt,
            &lease.body.lease_id,
            &package.workflow_id,
            &step_sha256,
            package.generated_at_unix_ms,
        )
        .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn committed_fixture_verifies_through_production_crate() {
        let package = package_from_fixture_json(include_str!(
            "../../../examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
        ))
        .expect("package fixture parses");
        let report = verify_package(&package).expect("package fixture verifies");
        assert!(report.accepted);
        assert_eq!(report.checks.len(), 7);
    }
}
