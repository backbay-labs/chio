use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::ChioReceipt;
use chio_federation::DsseEnvelope;
use chio_governance::authorization::SignedGovernanceReceipt;
use chio_governance::lease::SignedCapabilityLease;
use chio_selective_disclosure::SelectiveDisclosureProof;
use chio_workflow::receipt::WorkflowReceipt;
use serde::{Deserialize, Serialize};

use crate::claims::{
    ChioProofClaims, LeaseScopeBindingArtifact, PeerLadderBinding, VendorKeyBinding,
    WorkflowIntersectionArtifact,
};
use crate::error::ChioPackageError;

pub const PROOF_PACKAGE_SCHEMA: &str = "chio.attest.proof-package.v1";

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

pub fn proof_package_from_json(json: &str) -> Result<ChioProofPackage, ChioPackageError> {
    serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn package_json(package: &ChioProofPackage) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(package).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn package_sha256(package: &ChioProofPackage) -> Result<String, ChioPackageError> {
    let bytes = canonical_json_bytes(package)
        .map_err(|error| ChioPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
pub(crate) fn verify_claims(claims: &ChioProofClaims) -> Result<(), ChioPackageError> {
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
