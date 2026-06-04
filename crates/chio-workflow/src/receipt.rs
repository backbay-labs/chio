//! Workflow receipts capturing complete execution traces.
//!
//! A `WorkflowReceipt` is a single auditable artifact that captures the
//! entire execution of a skill, including per-step results, timing,
//! cost attribution, and the overall outcome.

use chio_core::capability::MonetaryAmount;
use chio_core::crypto::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// Schema identifier for workflow receipts.
pub const WORKFLOW_RECEIPT_SCHEMA: &str = "chio.workflow-receipt.v1";

/// A signed receipt for a complete skill/workflow execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowReceipt {
    /// Unique receipt ID.
    pub id: String,
    /// Schema version.
    pub schema: String,
    /// Unix timestamp when the workflow started.
    pub started_at: u64,
    /// Unix timestamp when the workflow completed.
    pub completed_at: u64,
    /// Skill ID from the manifest.
    pub skill_id: String,
    /// Skill version from the manifest.
    pub skill_version: String,
    /// Agent that executed the workflow.
    pub agent_id: String,
    /// Session the workflow ran under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Capability ID that authorized the workflow.
    pub capability_id: String,
    /// Overall workflow outcome.
    pub outcome: WorkflowOutcome,
    /// Per-step execution records.
    pub steps: Vec<StepRecord>,
    /// Total cost of the workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_cost: Option<MonetaryAmount>,
    /// Total wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Kernel public key.
    pub kernel_key: PublicKey,
    /// Signature over the receipt body.
    pub signature: Signature,
    /// Detached vendor co-signatures over the canonical workflow body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vendor_signatures: Vec<WorkflowVendorSignature>,
}

/// The body of a workflow receipt (everything except the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowReceiptBody {
    pub id: String,
    pub schema: String,
    pub started_at: u64,
    pub completed_at: u64,
    pub skill_id: String,
    pub skill_version: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub capability_id: String,
    pub outcome: WorkflowOutcome,
    pub steps: Vec<StepRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_cost: Option<MonetaryAmount>,
    pub duration_ms: u64,
    pub kernel_key: PublicKey,
}

/// Detached vendor signature over a canonical workflow receipt body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowVendorSignature {
    pub vendor_id: String,
    pub public_key: PublicKey,
    pub signature: Signature,
}

/// Required vendor signer accepted by a workflow verifier.
#[derive(Debug, Clone)]
pub struct VendorSignatureRequirement {
    pub vendor_id: String,
    pub public_key: PublicKey,
}

/// Verification errors for workflow receipt extensions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkflowReceiptError {
    #[error("vendor signature for {0} is missing")]
    MissingVendorSignature(String),
    #[error("vendor signature for {0} uses an unexpected key")]
    VendorSignatureKeyMismatch(String),
    #[error("vendor signature for {0} is invalid")]
    InvalidVendorSignature(String),
    #[error("canonical signature operation failed: {0}")]
    Crypto(String),
}

/// Outcome of a workflow execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WorkflowOutcome {
    /// All steps completed successfully.
    Completed,
    /// The workflow was denied before execution started.
    Denied { reason: String },
    /// A step failed, halting the workflow.
    StepFailed { step_index: usize, reason: String },
    /// The workflow exceeded its budget envelope.
    BudgetExceeded {
        limit_units: u64,
        spent_units: u64,
        currency: String,
    },
    /// The workflow exceeded its time limit.
    TimedOut { limit_secs: u64, elapsed_secs: u64 },
    /// The workflow was cancelled by the agent or operator.
    Cancelled { reason: String },
}

/// Record of a single step's execution within a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    /// Step index in the manifest.
    pub step_index: usize,
    /// Tool server.
    pub server_id: String,
    /// Tool name.
    pub tool_name: String,
    /// Whether this step was allowed.
    pub allowed: bool,
    /// Receipt ID for the underlying tool call (if it ran).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_receipt_id: Option<String>,
    /// Step outcome.
    pub outcome: StepOutcome,
    /// Step duration in milliseconds.
    pub duration_ms: u64,
    /// Cost attributed to this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<MonetaryAmount>,
    /// SHA-256 hash of the step's output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    /// SHA-256 of the bilateral DSSE envelope for this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bilateral_dsse_sha256: Option<String>,
    /// Governance receipt that authorizes this step when destructive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_id: Option<String>,
    /// SHA-256 of the preceding workflow or tool receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_sha256: Option<String>,
    /// Consistency anchor binding the step to a hash chain or external root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_anchor: Option<String>,
    /// Whether this step performs a destructive action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
}

/// Outcome of a single step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// Step completed successfully.
    Success,
    /// Step was denied by policy.
    Denied,
    /// Step failed during execution.
    Failed,
    /// Step was skipped (e.g. workflow aborted before reaching it).
    Skipped,
}

impl WorkflowReceipt {
    /// Sign a workflow receipt body.
    pub fn sign(body: WorkflowReceiptBody, keypair: &Keypair) -> Result<Self, chio_core::Error> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            schema: body.schema,
            started_at: body.started_at,
            completed_at: body.completed_at,
            skill_id: body.skill_id,
            skill_version: body.skill_version,
            agent_id: body.agent_id,
            session_id: body.session_id,
            capability_id: body.capability_id,
            outcome: body.outcome,
            steps: body.steps,
            total_cost: body.total_cost,
            duration_ms: body.duration_ms,
            kernel_key: body.kernel_key,
            signature,
            vendor_signatures: Vec::new(),
        })
    }

    /// Reconstruct the canonical body signed by the kernel and vendors.
    #[must_use]
    pub fn body(&self) -> WorkflowReceiptBody {
        WorkflowReceiptBody {
            id: self.id.clone(),
            schema: self.schema.clone(),
            started_at: self.started_at,
            completed_at: self.completed_at,
            skill_id: self.skill_id.clone(),
            skill_version: self.skill_version.clone(),
            agent_id: self.agent_id.clone(),
            session_id: self.session_id.clone(),
            capability_id: self.capability_id.clone(),
            outcome: self.outcome.clone(),
            steps: self.steps.clone(),
            total_cost: self.total_cost.clone(),
            duration_ms: self.duration_ms,
            kernel_key: self.kernel_key.clone(),
        }
    }

    /// Verify the receipt signature.
    pub fn verify(&self) -> Result<bool, chio_core::Error> {
        if self.schema != WORKFLOW_RECEIPT_SCHEMA {
            return Ok(false);
        }
        self.kernel_key
            .verify_canonical(&self.body(), &self.signature)
    }

    /// Add a detached vendor co-signature over the canonical workflow body.
    pub fn add_vendor_signature(
        &mut self,
        vendor_id: impl Into<String>,
        keypair: &Keypair,
    ) -> Result<(), WorkflowReceiptError> {
        let (signature, _) = keypair
            .sign_canonical(&self.body())
            .map_err(|e| WorkflowReceiptError::Crypto(e.to_string()))?;
        self.vendor_signatures.push(WorkflowVendorSignature {
            vendor_id: vendor_id.into(),
            public_key: keypair.public_key(),
            signature,
        });
        Ok(())
    }

    /// Verify that every required vendor co-signed this workflow body.
    pub fn verify_vendor_signatures(
        &self,
        required: &[VendorSignatureRequirement],
    ) -> Result<bool, WorkflowReceiptError> {
        let body = self.body();
        for requirement in required {
            let signature = self
                .vendor_signatures
                .iter()
                .find(|sig| sig.vendor_id == requirement.vendor_id)
                .ok_or_else(|| {
                    WorkflowReceiptError::MissingVendorSignature(requirement.vendor_id.clone())
                })?;
            if signature.public_key != requirement.public_key {
                return Err(WorkflowReceiptError::VendorSignatureKeyMismatch(
                    requirement.vendor_id.clone(),
                ));
            }
            let verified = signature
                .public_key
                .verify_canonical(&body, &signature.signature)
                .map_err(|e| WorkflowReceiptError::Crypto(e.to_string()))?;
            if !verified {
                return Err(WorkflowReceiptError::InvalidVendorSignature(
                    requirement.vendor_id.clone(),
                ));
            }
        }
        Ok(true)
    }

    /// Count how many steps completed successfully.
    #[must_use]
    pub fn successful_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.outcome == StepOutcome::Success)
            .count()
    }

    /// Check whether the workflow completed successfully.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.outcome == WorkflowOutcome::Completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_step_record(index: usize, outcome: StepOutcome) -> StepRecord {
        StepRecord {
            step_index: index,
            server_id: "srv".to_string(),
            tool_name: format!("tool_{index}"),
            allowed: matches!(outcome, StepOutcome::Success | StepOutcome::Failed),
            tool_receipt_id: Some(format!("rcpt-{index}")),
            outcome,
            duration_ms: 100,
            cost: None,
            output_hash: None,
            bilateral_dsse_sha256: None,
            governance_receipt_id: None,
            parent_receipt_sha256: None,
            consistency_anchor: None,
            destructive: None,
        }
    }

    #[test]
    fn sign_and_verify_workflow_receipt() {
        let kp = Keypair::generate();
        let body = WorkflowReceiptBody {
            id: "wf-1".to_string(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: 1000,
            completed_at: 2000,
            skill_id: "search-summarize".to_string(),
            skill_version: "1.0.0".to_string(),
            agent_id: "agent-1".to_string(),
            session_id: Some("sess-1".to_string()),
            capability_id: "cap-1".to_string(),
            outcome: WorkflowOutcome::Completed,
            steps: vec![
                make_step_record(0, StepOutcome::Success),
                make_step_record(1, StepOutcome::Success),
            ],
            total_cost: Some(MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            }),
            duration_ms: 1000,
            kernel_key: kp.public_key(),
        };

        let receipt = WorkflowReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify().unwrap());
        assert!(receipt.is_complete());
        assert_eq!(receipt.successful_steps(), 2);
    }

    #[test]
    fn tampered_receipt_fails() {
        let kp = Keypair::generate();
        let body = WorkflowReceiptBody {
            id: "wf-2".to_string(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: 1000,
            completed_at: 2000,
            skill_id: "s".to_string(),
            skill_version: "1.0".to_string(),
            agent_id: "a".to_string(),
            session_id: None,
            capability_id: "c".to_string(),
            outcome: WorkflowOutcome::Completed,
            steps: vec![],
            total_cost: None,
            duration_ms: 500,
            kernel_key: kp.public_key(),
        };

        let mut receipt = WorkflowReceipt::sign(body, &kp).unwrap();
        receipt.duration_ms = 999; // tamper
        assert!(!receipt.verify().unwrap());
    }

    #[test]
    fn unsupported_receipt_schema_fails_verification() {
        let kp = Keypair::generate();
        let body = WorkflowReceiptBody {
            id: "wf-unsupported-schema".to_string(),
            schema: "chio.workflow-receipt.v0".to_string(),
            started_at: 1000,
            completed_at: 2000,
            skill_id: "s".to_string(),
            skill_version: "1.0".to_string(),
            agent_id: "a".to_string(),
            session_id: None,
            capability_id: "c".to_string(),
            outcome: WorkflowOutcome::Completed,
            steps: vec![],
            total_cost: None,
            duration_ms: 500,
            kernel_key: kp.public_key(),
        };

        let receipt = WorkflowReceipt::sign(body, &kp).unwrap();

        assert!(!receipt.verify().unwrap());
    }

    #[test]
    fn partial_failure_stats() {
        let kp = Keypair::generate();
        let body = WorkflowReceiptBody {
            id: "wf-3".to_string(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: 1000,
            completed_at: 1500,
            skill_id: "s".to_string(),
            skill_version: "1.0".to_string(),
            agent_id: "a".to_string(),
            session_id: None,
            capability_id: "c".to_string(),
            outcome: WorkflowOutcome::StepFailed {
                step_index: 1,
                reason: "tool error".to_string(),
            },
            steps: vec![
                make_step_record(0, StepOutcome::Success),
                make_step_record(1, StepOutcome::Failed),
                make_step_record(2, StepOutcome::Skipped),
            ],
            total_cost: None,
            duration_ms: 500,
            kernel_key: kp.public_key(),
        };

        let receipt = WorkflowReceipt::sign(body, &kp).unwrap();
        assert!(!receipt.is_complete());
        assert_eq!(receipt.successful_steps(), 1);
    }

    #[test]
    fn workflow_outcome_serialization() {
        let outcome = WorkflowOutcome::BudgetExceeded {
            limit_units: 1000,
            spent_units: 1100,
            currency: "USD".to_string(),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let deserialized: WorkflowOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, outcome);
    }

    #[test]
    fn v1_receipt_serialization_omits_v2_fields_when_absent() {
        let step = make_step_record(0, StepOutcome::Success);
        let value = serde_json::to_value(&step).unwrap();
        assert!(value.get("bilateral_dsse_sha256").is_none());
        assert!(value.get("governance_receipt_id").is_none());
        assert!(value.get("parent_receipt_sha256").is_none());
        assert!(value.get("consistency_anchor").is_none());
        assert!(value.get("destructive").is_none());
    }

    #[test]
    fn v2_step_linkage_fields_are_signed_by_kernel() {
        let kp = Keypair::generate();
        let mut step = make_step_record(1, StepOutcome::Success);
        step.bilateral_dsse_sha256 = Some("b".repeat(64));
        step.governance_receipt_id = Some("gov:buyer:refund:001".to_string());
        step.parent_receipt_sha256 = Some("a".repeat(64));
        step.consistency_anchor = Some("anchor:buyer:epoch:42".to_string());
        step.destructive = Some(true);

        let body = WorkflowReceiptBody {
            id: "wf-v2".to_string(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: 1000,
            completed_at: 1001,
            skill_id: "refund-underwriting".to_string(),
            skill_version: "0.1.0".to_string(),
            agent_id: "buyer-agent".to_string(),
            session_id: None,
            capability_id: "cap-workflow".to_string(),
            outcome: WorkflowOutcome::Completed,
            steps: vec![step],
            total_cost: None,
            duration_ms: 1000,
            kernel_key: kp.public_key(),
        };

        let mut receipt = WorkflowReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify().unwrap());
        receipt.steps[0].parent_receipt_sha256 = Some("c".repeat(64));
        assert!(!receipt.verify().unwrap());
    }

    #[test]
    fn vendor_cosignatures_verify_required_signers() {
        let kernel = Keypair::generate();
        let vendor_a = Keypair::generate();
        let vendor_b = Keypair::generate();
        let body = WorkflowReceiptBody {
            id: "wf-cosigned".to_string(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: 1000,
            completed_at: 1010,
            skill_id: "refund-underwriting".to_string(),
            skill_version: "0.1.0".to_string(),
            agent_id: "buyer-agent".to_string(),
            session_id: None,
            capability_id: "cap-workflow".to_string(),
            outcome: WorkflowOutcome::Completed,
            steps: vec![make_step_record(0, StepOutcome::Success)],
            total_cost: None,
            duration_ms: 10_000,
            kernel_key: kernel.public_key(),
        };
        let mut receipt = WorkflowReceipt::sign(body, &kernel).unwrap();
        receipt.add_vendor_signature("vendor-a", &vendor_a).unwrap();

        let required = vec![VendorSignatureRequirement {
            vendor_id: "vendor-a".to_string(),
            public_key: vendor_a.public_key(),
        }];
        assert!(receipt.verify_vendor_signatures(&required).unwrap());

        let missing = vec![VendorSignatureRequirement {
            vendor_id: "vendor-b".to_string(),
            public_key: vendor_b.public_key(),
        }];
        assert!(matches!(
            receipt.verify_vendor_signatures(&missing),
            Err(WorkflowReceiptError::MissingVendorSignature(id)) if id == "vendor-b"
        ));

        receipt.vendor_signatures[0].signature = vendor_b.sign(b"not the workflow body");
        assert!(matches!(
            receipt.verify_vendor_signatures(&required),
            Err(WorkflowReceiptError::InvalidVendorSignature(id)) if id == "vendor-a"
        ));
    }
}
