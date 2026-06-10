use chio_core_types::crypto::PublicKey;
use chio_federation::trust_establishment::LadderManifestRef;
use chio_governance::lease::CapabilityLeaseActionClass;
use serde::{Deserialize, Serialize};

use crate::error::ChioPackageError;
use crate::validation::{canonical_sha256, validate_scope_field, validate_sha256_hex_for_scope};

pub const WORKFLOW_INTERSECTION_SCHEMA: &str = "chio.attest.workflow-intersection.v1";
pub const LEASE_SCOPE_BINDING_SCHEMA: &str = "chio.federation.lease-scope-binding.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerLadderBinding {
    pub kernel_id: String,
    pub public_key: PublicKey,
    pub ladder_manifest_ref: LadderManifestRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VendorKeyBinding {
    pub vendor_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowPairwiseIntersectionRef {
    pub peer_kernel_id: String,
    pub intersection_id: String,
    pub ladder_manifest_ref: LadderManifestRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowStepClassBinding {
    pub step_index: usize,
    pub tool_name: String,
    pub action_class_id: String,
    pub peer_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowRequiredVendorSigner {
    pub vendor_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    pub(crate) fn validate(&self) -> Result<(), ChioPackageError> {
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
