use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalAllocationDecisionOutcome {
    Allocate,
    Queue,
    ManualReview,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalAllocationDecisionReasonCode {
    MissingGovernedReceipt,
    AmbiguousGovernedReceipt,
    MissingRequestedAmount,
    FacilityManualReview,
    FacilityDenied,
    ManualCapitalSource,
    ReserveBookMissing,
    UtilizationCeilingExceeded,
    ConcentrationCapExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationInstructionDraft {
    pub source_id: String,
    pub source_kind: CapitalBookSourceKind,
    pub action: CapitalExecutionInstructionAction,
    pub amount: MonetaryAmount,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionFinding {
    pub code: CapitalAllocationDecisionReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionSupportBoundary {
    pub capital_book_authoritative: bool,
    pub simulation_first_only: bool,
    pub automatic_dispatch_supported: bool,
    pub external_execution_authoritative: bool,
}

impl Default for CapitalAllocationDecisionSupportBoundary {
    fn default() -> Self {
        Self {
            capital_book_authoritative: true,
            simulation_first_only: true,
            automatic_dispatch_supported: false,
            external_execution_authoritative: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionArtifact {
    pub schema: String,
    pub allocation_id: String,
    pub issued_at: u64,
    pub query: CapitalBookQuery,
    pub subject_key: String,
    pub governed_receipt_id: String,
    pub intent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<String>,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub requested_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<CapitalBookSourceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_source_id: Option<String>,
    pub outcome: CapitalAllocationDecisionOutcome,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_outstanding_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projected_outstanding_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_delta_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utilization_ceiling_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concentration_cap_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instruction_drafts: Vec<CapitalAllocationInstructionDraft>,
    pub support_boundary: CapitalAllocationDecisionSupportBoundary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CapitalAllocationDecisionFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
    pub description: String,
}

pub type SignedCapitalAllocationDecision = SignedExportEnvelope<CapitalAllocationDecisionArtifact>;
