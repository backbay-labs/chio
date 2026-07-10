use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookSourceKind {
    FacilityCommitment,
    ReserveBook,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookRole {
    OperatorTreasury,
    ExternalCapitalProvider,
    AgentCounterparty,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookEventKind {
    Commit,
    Hold,
    Draw,
    Disburse,
    Release,
    Repay,
    Impair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapitalBookEvidenceKind {
    CreditFacility,
    CreditBond,
    CreditLossLifecycle,
    CommerceOrder,
    Receipt,
    SettlementReconciliation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookEvidenceReference {
    pub kind: CapitalBookEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSupportBoundary {
    pub source_of_funds_authoritative: bool,
    pub mixed_currency_netting_supported: bool,
    pub custody_execution_supported: bool,
    pub automatic_capital_execution_supported: bool,
}

impl Default for CapitalBookSupportBoundary {
    fn default() -> Self {
        Self {
            source_of_funds_authoritative: true,
            mixed_currency_netting_supported: false,
            custody_execution_supported: false,
            automatic_capital_execution_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSource {
    pub source_id: String,
    pub kind: CapitalBookSourceKind,
    pub owner_role: CapitalBookRole,
    pub counterparty_role: CapitalBookRole,
    pub counterparty_id: String,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capital_source: Option<CreditFacilityCapitalSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drawn_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disbursed_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repaid_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impaired_amount: Option<MonetaryAmount>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookEvent {
    pub event_id: String,
    pub kind: CapitalBookEventKind,
    pub occurred_at: u64,
    pub source_id: String,
    pub owner_role: CapitalBookRole,
    pub counterparty_role: CapitalBookRole,
    pub counterparty_id: String,
    pub amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CapitalBookEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub matching_facilities: u64,
    pub returned_facilities: u64,
    pub matching_bonds: u64,
    pub returned_bonds: u64,
    pub matching_loss_events: u64,
    pub returned_loss_events: u64,
    pub currencies: Vec<String>,
    pub mixed_currency_book: bool,
    pub funding_sources: u64,
    pub ledger_events: u64,
    pub truncated_receipts: bool,
    pub truncated_facilities: bool,
    pub truncated_bonds: bool,
    pub truncated_loss_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalBookReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CapitalBookQuery,
    pub subject_key: String,
    pub support_boundary: CapitalBookSupportBoundary,
    pub summary: CapitalBookSummary,
    pub sources: Vec<CapitalBookSource>,
    pub events: Vec<CapitalBookEvent>,
}

pub type SignedCapitalBookReport = SignedExportEnvelope<CapitalBookReport>;
