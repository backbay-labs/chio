use serde::{Deserialize, Serialize};

use crate::error::GovernanceAuthorizationError;
use crate::receipt::SignedExportEnvelope;
use crate::validation::{validate_non_empty, validate_sha256_hex};

pub const GOVERNANCE_RECEIPT_SCHEMA_V1: &str = "chio.governance-receipt.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceReceiptCaseKind {
    DestructiveAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceReceiptArtifact {
    pub schema: String,
    pub receipt_id: String,
    pub authorizing_kernel: String,
    pub case_kind: GovernanceReceiptCaseKind,
    pub authorized_lease_id: String,
    pub workflow_id: String,
    pub step_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl GovernanceReceiptArtifact {
    pub fn validate(&self) -> Result<(), GovernanceAuthorizationError> {
        if self.schema != GOVERNANCE_RECEIPT_SCHEMA_V1 {
            return Err(GovernanceAuthorizationError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        validate_non_empty(&self.receipt_id, "receipt_id")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.authorizing_kernel, "authorizing_kernel")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.authorized_lease_id, "authorized_lease_id")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.workflow_id, "workflow_id")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_sha256_hex(&self.step_sha256, "step_sha256")?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(GovernanceAuthorizationError::InvalidArtifact(
                "expires_at_unix_ms must be greater than issued_at_unix_ms".to_string(),
            ));
        }
        Ok(())
    }
}

pub type SignedGovernanceReceipt = SignedExportEnvelope<GovernanceReceiptArtifact>;

pub fn verify_destructive_authorization(
    receipt: &SignedGovernanceReceipt,
    expected_lease_id: &str,
    expected_workflow_id: &str,
    expected_step_sha256: &str,
    now_unix_ms: u64,
) -> Result<(), GovernanceAuthorizationError> {
    receipt.body.validate()?;
    validate_sha256_hex(expected_step_sha256, "expected_step_sha256")?;
    if !receipt
        .verify_signature()
        .map_err(|e| GovernanceAuthorizationError::Crypto(e.to_string()))?
    {
        return Err(GovernanceAuthorizationError::InvalidSignature);
    }
    if receipt.body.issued_at_unix_ms > now_unix_ms {
        return Err(GovernanceAuthorizationError::GovernanceReceiptNotYetValid(
            receipt.body.receipt_id.clone(),
        ));
    }
    if receipt.body.expires_at_unix_ms <= now_unix_ms {
        return Err(GovernanceAuthorizationError::LeaseExpiredOrUnknown(
            receipt.body.receipt_id.clone(),
        ));
    }
    if receipt.body.authorized_lease_id != expected_lease_id {
        return Err(GovernanceAuthorizationError::LeaseMismatch);
    }
    if receipt.body.workflow_id != expected_workflow_id {
        return Err(GovernanceAuthorizationError::WorkflowMismatch);
    }
    if receipt.body.step_sha256 != expected_step_sha256 {
        return Err(GovernanceAuthorizationError::StepHashMismatch);
    }
    Ok(())
}

pub fn verify_step_governance_boundary(
    destructive: bool,
    receipt: Option<&SignedGovernanceReceipt>,
    now_unix_ms: u64,
) -> Result<(), GovernanceAuthorizationError> {
    if !destructive {
        return Ok(());
    }
    let Some(receipt) = receipt else {
        return Err(GovernanceAuthorizationError::GovernanceReceiptRequired);
    };
    receipt.body.validate()?;
    if receipt.body.expires_at_unix_ms <= now_unix_ms {
        return Err(GovernanceAuthorizationError::LeaseExpiredOrUnknown(
            receipt.body.receipt_id.clone(),
        ));
    }
    if !receipt
        .verify_signature()
        .map_err(|e| GovernanceAuthorizationError::Crypto(e.to_string()))?
    {
        return Err(GovernanceAuthorizationError::InvalidSignature);
    }
    if receipt.body.issued_at_unix_ms > now_unix_ms {
        return Err(GovernanceAuthorizationError::GovernanceReceiptNotYetValid(
            receipt.body.receipt_id.clone(),
        ));
    }
    Ok(())
}
