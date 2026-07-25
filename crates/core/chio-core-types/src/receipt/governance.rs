use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::capability::{
    governance::{
        GovernedAutonomyTier, GovernedCallChainContext, GovernedCallChainProvenance,
        MeteredBillingQuote, MeteredSettlementMode,
    },
    runtime_attestation::RuntimeAssuranceTier,
    scope::MonetaryAmount,
    workload_identity::WorkloadIdentity,
};
use crate::runtime_attestation::AttestationVerifierFamily;

use super::economics::EconomicAuthorizationReceiptMetadata;

/// Approval evidence attached to a governed-transaction receipt block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernedApprovalReceiptMetadata {
    /// Approval token identifier.
    pub token_id: String,
    /// Hex-encoded approver public key.
    pub approver_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_artifact_digest: Option<String>,
    /// Whether the token represented a positive approval.
    pub approved: bool,
}

/// Runtime assurance evidence attached to a governed-transaction receipt block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAssuranceReceiptMetadata {
    /// Schema or format identifier of the attestation evidence Chio accepted.
    pub schema: String,
    /// Optional verifier family recognized by Chio's canonical appraisal boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_family: Option<AttestationVerifierFamily>,
    /// Normalized assurance tier accepted for the request.
    pub tier: RuntimeAssuranceTier,
    /// Verifier or relying party that accepted the upstream evidence.
    pub verifier: String,
    /// Stable digest of the attestation payload.
    pub evidence_sha256: String,
    /// Optional normalized workload identity resolved from the attestation evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
}

/// Commerce approval evidence attached to a governed-transaction receipt block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernedCommerceReceiptMetadata {
    /// Seller or payee identifier the approval was scoped to.
    pub seller: String,
    /// Shared payment token or equivalent external commerce approval reference.
    pub shared_payment_token_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_destination_ref: Option<String>,
}

/// Optional post-execution usage evidence attached to metered-billing receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeteredUsageEvidenceReceiptMetadata {
    /// Evidence adapter or source kind that produced the usage record.
    pub evidence_kind: String,
    /// Stable identifier of the usage record in the external billing system.
    pub evidence_id: String,
    /// Observed billable units reported after execution.
    pub observed_units: u64,
    /// Stable digest of the external usage payload when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
}

/// Metered-billing quote and evidence context preserved on governed receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReceiptMetadata {
    /// Settlement posture attached to the governed request.
    pub settlement_mode: MeteredSettlementMode,
    /// Pre-execution metered quote bound into the governed intent.
    pub quote: MeteredBillingQuote,
    /// Optional explicit upper bound on billable units for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billed_units: Option<u64>,
    /// Optional post-execution usage evidence preserved separately from receipt truth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_evidence: Option<MeteredUsageEvidenceReceiptMetadata>,
}

/// Explicit autonomy and delegation-bond context preserved on governed receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAutonomyReceiptMetadata {
    /// Requested autonomy tier for this governed action.
    pub tier: GovernedAutonomyTier,
    /// Optional signed delegation-bond artifact bound to the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_bond_id: Option<String>,
}

/// Governed transaction metadata attached to receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GovernedTransactionReceiptMetadata {
    /// Governed transaction intent identifier.
    pub intent_id: String,
    /// Canonical intent hash used for approval-token binding.
    pub intent_hash: String,
    /// Human or policy-readable purpose.
    pub purpose: String,
    /// Target tool server from the intent.
    pub server_id: String,
    /// Target tool name from the intent.
    pub tool_name: String,
    /// Optional explicit spend bound carried on the intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
    /// Optional seller-scoped commerce approval evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<GovernedCommerceReceiptMetadata>,
    /// Optional metered-billing quote and usage evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_billing: Option<MeteredBillingReceiptMetadata>,
    /// Optional approval evidence that accompanied the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<GovernedApprovalReceiptMetadata>,
    /// Optional runtime assurance evidence that accompanied the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance: Option<RuntimeAssuranceReceiptMetadata>,
    /// Optional delegated call-chain provenance bound through the governed intent hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_chain: Option<GovernedCallChainProvenance>,
    /// Optional autonomy tier and delegation-bond attachment bound through the governed intent hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomy: Option<GovernedAutonomyReceiptMetadata>,
    /// Optional versioned economic envelope that consolidates budget, meter, rail,
    /// and settlement truth in a single typed structure alongside the per-field
    /// convenience accessors (max_amount, commerce, metered_billing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_authorization: Option<EconomicAuthorizationReceiptMetadata>,
}

impl GovernedTransactionReceiptMetadata {
    #[must_use]
    pub fn asserted_call_chain(&self) -> Option<&GovernedCallChainContext> {
        self.call_chain
            .as_ref()
            .and_then(GovernedCallChainProvenance::asserted_context)
    }

    #[must_use]
    pub fn verified_call_chain(&self) -> Option<&GovernedCallChainContext> {
        self.call_chain
            .as_ref()
            .and_then(GovernedCallChainProvenance::verified_context)
    }
}
