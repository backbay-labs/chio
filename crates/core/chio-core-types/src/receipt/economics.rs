use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::capability::scope::MonetaryAmount;
use crate::oracle::OracleConversionEvidence;

pub const CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA: &str = "chio.channel.receipt-metadata.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelSettlementModeV1 {
    Channelized,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelReceiptMetadataV1 {
    pub schema: String,
    pub channel_id: String,
    pub open_digest: String,
    pub reservation_id: String,
    pub reservation_digest: String,
    pub sequence: u64,
    pub settlement_mode: ChannelSettlementModeV1,
}

impl ChannelReceiptMetadataV1 {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

        self.schema == CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA
            && [
                &self.channel_id,
                &self.open_digest,
                &self.reservation_id,
                &self.reservation_digest,
            ]
            .into_iter()
            .all(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            && self.sequence > 0
            && self.sequence <= I_JSON_MAX_SAFE_INTEGER
    }
}

/// Financial metadata attached to receipts for monetary grant invocations.
///
/// For allow receipts under a monetary grant, this struct is serialized under
/// the "financial" key in `ChioReceiptBody::metadata`.
///
/// For denial receipts caused by budget exhaustion, `attempted_cost` is
/// populated with the cost that would have been charged.
///
/// # Field Invariants
///
/// Callers constructing this struct must uphold the following invariants:
///
/// - `cost_charged <= budget_total`: the amount charged for a single invocation
///   must not exceed the total budget allocation.
/// - `budget_remaining == budget_total - cost_charged` (approximately): the
///   remaining budget field should reflect the post-charge balance. Due to HA
///   split-brain scenarios, `budget_remaining` may be a best-effort snapshot
///   rather than a strict invariant at read time, but callers must ensure it is
///   computed correctly at write time.
/// - For denial receipts, `cost_charged` should be 0 and `attempted_cost`
///   should hold the cost that was rejected.
///
/// These invariants are not enforced by the type system and must be upheld by
/// the kernel when constructing financial metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialReceiptMetadata {
    /// Index of the matching grant in the capability token's scope.
    pub grant_index: u32,
    /// Cost charged for this invocation in currency minor units (e.g. cents for USD).
    pub cost_charged: u64,
    /// ISO 4217 currency code (e.g. "USD").
    pub currency: String,
    /// Remaining budget after this charge, in currency minor units.
    pub budget_remaining: u64,
    /// Total budget for this grant, in currency minor units.
    pub budget_total: u64,
    /// Depth of the delegation chain at the time of invocation.
    pub delegation_depth: u32,
    /// Identifier of the root budget holder in the delegation chain.
    pub root_budget_holder: String,
    /// Optional payment reference for external settlement systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    /// Settlement status for this charge.
    pub settlement_status: SettlementStatus,
    /// Optional itemized cost breakdown for audit purposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_breakdown: Option<serde_json::Value>,
    /// Oracle price evidence used for cross-currency conversion, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_evidence: Option<OracleConversionEvidence>,
    /// Cost that was attempted but denied (populated only on denial receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
}

/// Authority identity bound to a budget hold lineage record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinancialBudgetHoldAuthorityMetadata {
    pub authority_id: String,
    pub lease_id: String,
    pub lease_epoch: u64,
}

/// Authorize event lineage preserved on a financial receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinancialBudgetAuthorizeReceiptMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_commit_index: Option<u64>,
    pub exposure_units: u64,
    pub committed_cost_units_after: u64,
}

/// Terminal hold mutation lineage preserved on a financial receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinancialBudgetTerminalReceiptMetadata {
    pub disposition: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_commit_index: Option<u64>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub committed_cost_units_after: u64,
}

/// Explicit budget hold lineage and guarantee data attached to a financial receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinancialBudgetAuthorityReceiptMetadata {
    pub guarantee_level: String,
    pub authority_profile: String,
    pub metering_profile: String,
    pub hold_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_term: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<FinancialBudgetHoldAuthorityMetadata>,
    pub authorize: FinancialBudgetAuthorizeReceiptMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<FinancialBudgetTerminalReceiptMetadata>,
}

/// Canonical settlement states for receipt-side financial metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    /// No external settlement applies to this receipt (for example, a pre-execution denial).
    NotApplicable,
    /// Settlement has been initiated but is not yet final.
    Pending,
    /// The recorded charge is final for the current execution path.
    Settled,
    /// Execution completed, but settlement failed or became invalid.
    Failed,
}

/// Version tag for the typed economic authorization envelope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EconomicAuthorizationReceiptMetadataVersion {
    V1,
}

/// Economic mode captured by the typed envelope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EconomicAuthorizationMode {
    BudgetOnly,
    PrepaidFixed,
    HoldCapture,
    MeteredHoldCapture,
    ExternalDispatch,
}

/// Payer binding preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicPayerReceiptMetadata {
    pub party_id: String,
    pub funding_source_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligor_ref: Option<String>,
}

/// Merchant binding preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicMerchantReceiptMetadata {
    pub merchant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merchant_of_record: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_ref: Option<String>,
}

/// Payee binding preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicPayeeReceiptMetadata {
    pub beneficiary_id: String,
    pub settlement_destination_ref: String,
}

/// Rail binding preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicRailReceiptMetadata {
    pub kind: String,
    pub asset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facilitator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_or_account_ref: Option<String>,
}

/// Explicit amount bounds preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicAmountBoundsReceiptMetadata {
    pub approved_max: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_amount: Option<MonetaryAmount>,
    pub settlement_cap: MonetaryAmount,
}

/// Quote and tariff binding preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicPricingBasisReceiptMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tariff_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_expiry: Option<u64>,
}

/// Meter binding preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicMeteringReceiptMetadata {
    pub provider: String,
    pub meter_profile_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billable_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_unit: Option<String>,
}

/// Budget truth preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicBudgetReceiptMetadata {
    pub grant_index: u32,
    pub cost_charged: u64,
    pub currency: String,
    pub budget_remaining: u64,
    pub budget_total: u64,
    pub delegation_depth: u32,
    pub root_budget_holder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
}

/// Settlement truth preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicSettlementReceiptMetadata {
    pub settlement_status: SettlementStatus,
}

/// Optional liability references preserved on the economic envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicLiabilityReceiptMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indemnity_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_policy_ref: Option<String>,
}

/// Versioned typed economic envelope for governed receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct EconomicAuthorizationReceiptMetadata {
    pub version: EconomicAuthorizationReceiptMetadataVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_intent_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee_binding_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_action_authority_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_authority_digest: Option<String>,
    pub economic_mode: EconomicAuthorizationMode,
    pub payer: EconomicPayerReceiptMetadata,
    pub merchant: EconomicMerchantReceiptMetadata,
    pub payee: EconomicPayeeReceiptMetadata,
    pub rail: EconomicRailReceiptMetadata,
    pub amount_bounds: EconomicAmountBoundsReceiptMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing_basis: Option<EconomicPricingBasisReceiptMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering: Option<EconomicMeteringReceiptMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liability_refs: Option<EconomicLiabilityReceiptMetadata>,
    pub budget: EconomicBudgetReceiptMetadata,
    pub settlement: EconomicSettlementReceiptMetadata,
}
