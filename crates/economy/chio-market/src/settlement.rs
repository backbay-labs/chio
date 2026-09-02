//! Liability claim payout and settlement reconciliation artifacts.

use serde::{Deserialize, Serialize};

use crate::capability::scope::MonetaryAmount;
use crate::credit::{
    validate_capital_execution_authority_step_proof, CapitalBookSourceKind,
    CapitalExecutionAuthorityStep, CapitalExecutionInstructionAction, CapitalExecutionObservation,
    CapitalExecutionRail, CapitalExecutionReconciledState, CapitalExecutionRole,
    CapitalExecutionWindow, SignedCapitalBookReport, SignedCapitalExecutionInstruction,
};
use crate::receipt::lineage::SignedExportEnvelope;

use crate::error::MarketError;
use crate::{
    bounded_market_query_limit, liability_claim_adjudication_payable_amount,
    validate_positive_money, verify_signed_artifact, SignedLiabilityClaimAdjudication,
    SignedLiabilityClaimDispute, SignedLiabilityClaimPackage, SignedLiabilityClaimResponse,
    MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT,
};

/// Whether a payout receipt reconciles against its instruction amount.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimPayoutReconciliationState {
    Matched,
    AmountMismatch,
}

/// Which inter-party settlement flow a settlement instruction drives.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimSettlementKind {
    RecoveryClearing,
    ReinsuranceReimbursement,
    FacilityReimbursement,
}

/// Whether a settlement receipt reconciles against its instruction
/// amount and counterparties.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityClaimSettlementReconciliationState {
    Matched,
    AmountMismatch,
    CounterpartyMismatch,
}

/// One settlement party bound to a capital-execution role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementRoleBinding {
    pub role: CapitalExecutionRole,
    pub party_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimSettlementRoleBinding {
    fn validate(&self, field_name: &str) -> Result<(), MarketError> {
        if self.party_id.trim().is_empty() {
            return Err(MarketError::field_invalid(format!(
                "{field_name} requires a non-empty party_id"
            )));
        }
        Ok(())
    }
}

/// The payer/payee (and optional beneficiary) topology of one
/// settlement; payer and payee must not be the same party in the
/// same role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementRoleTopology {
    pub payer: LiabilityClaimSettlementRoleBinding,
    pub payee: LiabilityClaimSettlementRoleBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beneficiary: Option<LiabilityClaimSettlementRoleBinding>,
}

impl LiabilityClaimSettlementRoleTopology {
    fn validate(&self) -> Result<(), MarketError> {
        self.payer.validate("settlement topology payer")?;
        self.payee.validate("settlement topology payee")?;
        if self.payer.role == self.payee.role && self.payer.party_id == self.payee.party_id {
            return Err(MarketError::binding_mismatch(
                "settlement topology payer and payee must not be identical",
            ));
        }
        if let Some(beneficiary) = self.beneficiary.as_ref() {
            beneficiary.validate("settlement topology beneficiary")?;
        }
        Ok(())
    }
}

/// Adjudicator-signed order to pay an awarded claim through one
/// capital-execution instruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPayoutInstructionArtifact {
    pub schema: String,
    pub payout_instruction_id: String,
    pub issued_at: u64,
    pub adjudication: SignedLiabilityClaimAdjudication,
    pub capital_instruction: SignedCapitalExecutionInstruction,
    pub payout_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimPayoutInstructionArtifact {
    /// Fail closed on the instruction shape: the embedded adjudication
    /// and capital instruction must verify and the payout amount must
    /// equal the adjudicated award in its currency.
    pub fn validate(&self) -> Result<(), MarketError> {
        verify_signed_artifact(&self.adjudication, "claim payout instruction adjudication")?;
        self.adjudication.body.validate()?;
        if !self
            .capital_instruction
            .verify_signature()
            .map_err(|error| MarketError::signature_invalid(error.to_string()))?
        {
            return Err(MarketError::signature_invalid(
                "claim payout instruction capital_instruction signature verification failed",
            ));
        }
        validate_positive_money(&self.payout_amount, "payout_amount")?;
        let awarded_amount = liability_claim_adjudication_payable_amount(&self.adjudication.body)?;
        if &self.payout_amount != awarded_amount {
            return Err(MarketError::binding_mismatch(
                "claim payout instruction payout_amount must match adjudication awarded_amount",
            ));
        }
        let capital_instruction = &self.capital_instruction.body;
        if capital_instruction.action != CapitalExecutionInstructionAction::TransferFunds {
            return Err(MarketError::field_invalid(
                "claim payout instructions require capital_instruction action transfer_funds",
            ));
        }
        if capital_instruction.source_kind != CapitalBookSourceKind::FacilityCommitment {
            return Err(MarketError::field_invalid(
"claim payout instructions require capital_instruction source_kind facility_commitment",
));
        }
        let intended_amount = capital_instruction.amount.as_ref().ok_or_else(|| {
            MarketError::field_invalid(
                "claim payout instructions require capital_instruction amount",
            )
        })?;
        if intended_amount != &self.payout_amount {
            return Err(MarketError::binding_mismatch(
                "claim payout instruction capital_instruction amount must match payout_amount",
            ));
        }
        let subject_key = &self
            .adjudication
            .body
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key;
        if &capital_instruction.subject_key != subject_key {
            return Err(MarketError::binding_mismatch(
"claim payout instruction capital_instruction subject_key must match the claim subject",
));
        }
        if capital_instruction.execution_window.not_after <= self.issued_at {
            return Err(MarketError::window_invalid(
"claim payout instructions require a non-stale capital_instruction execution window",
));
        }
        if capital_instruction.reconciled_state != CapitalExecutionReconciledState::NotObserved
            || capital_instruction.observed_execution.is_some()
        {
            return Err(MarketError::state_invalid(
"claim payout instructions require an unreconciled capital_instruction so payout receipts stay explicit",
));
        }
        Ok(())
    }
}

/// Signed payout instruction envelope.
pub type SignedLiabilityClaimPayoutInstruction =
    SignedExportEnvelope<LiabilityClaimPayoutInstructionArtifact>;

/// Receipt that a payout instruction executed, carrying the observed
/// amount and its reconciliation state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPayoutReceiptArtifact {
    pub schema: String,
    pub payout_receipt_id: String,
    pub issued_at: u64,
    pub payout_instruction: SignedLiabilityClaimPayoutInstruction,
    pub payout_receipt_ref: String,
    pub reconciliation_state: LiabilityClaimPayoutReconciliationState,
    pub observed_execution: crate::credit::CapitalExecutionObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimPayoutReceiptArtifact {
    /// Fail closed on the receipt shape: the embedded instruction must
    /// verify and the reconciliation state must agree with whether the
    /// observed amount matches the instructed one.
    pub fn validate(&self) -> Result<(), MarketError> {
        verify_signed_artifact(
            &self.payout_instruction,
            "claim payout receipt payout_instruction",
        )?;
        self.payout_instruction.body.validate()?;
        if self.payout_receipt_ref.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim payout receipts require a non-empty payout_receipt_ref",
            ));
        }
        if self
            .observed_execution
            .external_reference_id
            .trim()
            .is_empty()
        {
            return Err(MarketError::field_invalid(
"claim payout receipts require a non-empty observed_execution external_reference_id",
));
        }
        validate_positive_money(
            &self.observed_execution.amount,
            "claim payout receipt observed_execution amount",
        )?;
        if self.observed_execution.amount.currency
            != self.payout_instruction.body.payout_amount.currency
        {
            return Err(MarketError::currency_mismatch(
                "claim payout receipt observed_execution amount currency must match payout_amount",
            ));
        }
        let execution_window = &self
            .payout_instruction
            .body
            .capital_instruction
            .body
            .execution_window;
        if self.observed_execution.observed_at < execution_window.not_before
            || self.observed_execution.observed_at > execution_window.not_after
        {
            return Err(MarketError::window_invalid(
"claim payout receipt observed_execution timestamp falls outside the payout instruction execution window",
));
        }
        match self.reconciliation_state {
            LiabilityClaimPayoutReconciliationState::Matched => {
                if self.observed_execution.amount != self.payout_instruction.body.payout_amount {
                    return Err(MarketError::state_invalid(
"matched claim payout receipts require observed_execution amount to match payout_amount",
));
                }
            }
            LiabilityClaimPayoutReconciliationState::AmountMismatch => {
                if self.observed_execution.amount == self.payout_instruction.body.payout_amount {
                    return Err(MarketError::state_invalid(
"amount_mismatch claim payout receipts require observed_execution amount to differ from payout_amount",
));
                }
            }
        }
        Ok(())
    }
}

/// Signed payout receipt envelope.
pub type SignedLiabilityClaimPayoutReceipt =
    SignedExportEnvelope<LiabilityClaimPayoutReceiptArtifact>;

/// Order to settle a claim between market parties (recovery,
/// reinsurance, or facility reimbursement) under an explicit role
/// topology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementInstructionArtifact {
    pub schema: String,
    pub settlement_instruction_id: String,
    pub issued_at: u64,
    pub payout_receipt: SignedLiabilityClaimPayoutReceipt,
    pub capital_book: SignedCapitalBookReport,
    pub settlement_kind: LiabilityClaimSettlementKind,
    pub settlement_amount: MonetaryAmount,
    pub topology: LiabilityClaimSettlementRoleTopology,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimSettlementInstructionArtifact {
    /// Fail closed on the instruction shape: the embedded payout receipt
    /// must verify, the topology must validate, and the settlement
    /// amount must be positive in the payout currency.
    pub fn validate(&self) -> Result<(), MarketError> {
        verify_signed_artifact(
            &self.payout_receipt,
            "claim settlement instruction payout_receipt",
        )?;
        self.payout_receipt.body.validate()?;
        if !self
            .capital_book
            .verify_signature()
            .map_err(|error| MarketError::signature_invalid(error.to_string()))?
        {
            return Err(MarketError::signature_invalid(
                "claim settlement instruction capital_book signature verification failed",
            ));
        }
        validate_positive_money(&self.settlement_amount, "settlement_amount")?;
        self.topology.validate()?;
        if self.payout_receipt.body.reconciliation_state
            != LiabilityClaimPayoutReconciliationState::Matched
        {
            return Err(MarketError::state_invalid(
                "claim settlement instructions require a matched payout_receipt",
            ));
        }
        if self.settlement_amount.currency
            != self
                .payout_receipt
                .body
                .payout_instruction
                .body
                .payout_amount
                .currency
        {
            return Err(MarketError::currency_mismatch(
                "claim settlement instruction settlement_amount currency must match payout_amount",
            ));
        }
        if self.settlement_amount.units
            > self
                .payout_receipt
                .body
                .payout_instruction
                .body
                .payout_amount
                .units
        {
            return Err(MarketError::amount_out_of_bounds(
                "claim settlement instruction settlement_amount cannot exceed payout_amount",
            ));
        }
        let subject_key = &self
            .payout_receipt
            .body
            .payout_instruction
            .body
            .adjudication
            .body
            .dispute
            .body
            .provider_response
            .body
            .claim
            .body
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key;
        if self.capital_book.body.subject_key != *subject_key {
            return Err(MarketError::binding_mismatch(
"claim settlement instruction capital_book subject_key must match the claim subject",
));
        }
        if self.capital_book.body.summary.mixed_currency_book {
            return Err(MarketError::state_invalid(
"claim settlement instructions require a capital_book without mixed-currency ambiguity",
));
        }
        if self.authority_chain.is_empty() {
            return Err(MarketError::field_invalid(
                "claim settlement instructions require at least one authority_chain step",
            ));
        }
        if self.rail.rail_id.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim settlement instructions require rail.rail_id",
            ));
        }
        if self.rail.custody_provider_id.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim settlement instructions require rail.custody_provider_id",
            ));
        }
        if self.execution_window.not_before > self.execution_window.not_after {
            return Err(MarketError::window_invalid(
                "claim settlement instructions require execution_window.not_before <= not_after",
            ));
        }
        if self.execution_window.not_after <= self.issued_at {
            return Err(MarketError::window_invalid(
                "claim settlement instructions require a non-stale execution_window",
            ));
        }
        let mut payer_role_present = false;
        let mut custodian_present = false;
        for step in &self.authority_chain {
            if step.principal_id.trim().is_empty() {
                return Err(MarketError::field_invalid(
                    "claim settlement authority_chain principal_id cannot be empty",
                ));
            }
            validate_capital_execution_authority_step_proof(step)
                .map_err(MarketError::signature_invalid)?;
            if step.approved_at > step.expires_at {
                return Err(MarketError::window_invalid(
                    "claim settlement authority_chain requires approved_at <= expires_at",
                ));
            }
            if step.expires_at < self.issued_at {
                return Err(MarketError::window_invalid(format!(
                    "claim settlement authority step `{}` is stale at issuance time",
                    step.principal_id
                )));
            }
            if step.expires_at < self.execution_window.not_after {
                return Err(MarketError::window_invalid(format!("claim settlement authority step `{}` expires before the execution window closes",
                    step.principal_id)));
            }
            if step.role == self.topology.payer.role {
                payer_role_present = true;
            }
            if step.role == CapitalExecutionRole::Custodian
                && step.principal_id == self.rail.custody_provider_id
            {
                custodian_present = true;
            }
        }
        if !payer_role_present {
            return Err(MarketError::binding_mismatch(
                "claim settlement authority_chain is missing payer-role approval",
            ));
        }
        if !custodian_present {
            return Err(MarketError::binding_mismatch(
                "claim settlement authority_chain is missing the custody-provider execution step",
            ));
        }
        Ok(())
    }
}

/// Signed settlement instruction envelope.
pub type SignedLiabilityClaimSettlementInstruction =
    SignedExportEnvelope<LiabilityClaimSettlementInstructionArtifact>;

/// Receipt that a settlement instruction executed, carrying the
/// observed amount, counterparties, and reconciliation state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementReceiptArtifact {
    pub schema: String,
    pub settlement_receipt_id: String,
    pub issued_at: u64,
    pub settlement_instruction: SignedLiabilityClaimSettlementInstruction,
    pub settlement_receipt_ref: String,
    pub reconciliation_state: LiabilityClaimSettlementReconciliationState,
    pub observed_execution: CapitalExecutionObservation,
    pub observed_payer_id: String,
    pub observed_payee_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl LiabilityClaimSettlementReceiptArtifact {
    /// Fail closed on the receipt shape: the embedded instruction must
    /// verify and the reconciliation state must agree with the observed
    /// amount and counterparties.
    pub fn validate(&self) -> Result<(), MarketError> {
        verify_signed_artifact(
            &self.settlement_instruction,
            "claim settlement receipt settlement_instruction",
        )?;
        self.settlement_instruction.body.validate()?;
        if self.settlement_receipt_ref.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim settlement receipts require a non-empty settlement_receipt_ref",
            ));
        }
        if self.observed_payer_id.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim settlement receipts require a non-empty observed_payer_id",
            ));
        }
        if self.observed_payee_id.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "claim settlement receipts require a non-empty observed_payee_id",
            ));
        }
        if self
            .observed_execution
            .external_reference_id
            .trim()
            .is_empty()
        {
            return Err(MarketError::field_invalid(
"claim settlement receipts require a non-empty observed_execution external_reference_id",
));
        }
        validate_positive_money(
            &self.observed_execution.amount,
            "claim settlement receipt observed_execution amount",
        )?;
        if self.observed_execution.amount.currency
            != self.settlement_instruction.body.settlement_amount.currency
        {
            return Err(MarketError::currency_mismatch(
"claim settlement receipt observed_execution amount currency must match settlement_amount",
));
        }
        let execution_window = &self.settlement_instruction.body.execution_window;
        if self.observed_execution.observed_at < execution_window.not_before
            || self.observed_execution.observed_at > execution_window.not_after
        {
            return Err(MarketError::window_invalid(
"claim settlement receipt observed_execution timestamp falls outside the settlement execution window",
));
        }
        let expected_payer = &self.settlement_instruction.body.topology.payer.party_id;
        let expected_payee = &self.settlement_instruction.body.topology.payee.party_id;
        match self.reconciliation_state {
            LiabilityClaimSettlementReconciliationState::Matched => {
                if self.observed_execution.amount
                    != self.settlement_instruction.body.settlement_amount
                {
                    return Err(MarketError::state_invalid(
"matched claim settlement receipts require observed_execution amount to match settlement_amount",
));
                }
                if &self.observed_payer_id != expected_payer
                    || &self.observed_payee_id != expected_payee
                {
                    return Err(MarketError::state_invalid(
"matched claim settlement receipts require observed payer/payee to match the settlement topology",
));
                }
            }
            LiabilityClaimSettlementReconciliationState::AmountMismatch => {
                if self.observed_execution.amount
                    == self.settlement_instruction.body.settlement_amount
                {
                    return Err(MarketError::state_invalid(
"amount_mismatch claim settlement receipts require observed_execution amount to differ from settlement_amount",
));
                }
                if &self.observed_payer_id != expected_payer
                    || &self.observed_payee_id != expected_payee
                {
                    return Err(MarketError::state_invalid(
"amount_mismatch claim settlement receipts still require observed payer/payee to match the settlement topology",
));
                }
            }
            LiabilityClaimSettlementReconciliationState::CounterpartyMismatch => {
                if &self.observed_payer_id == expected_payer
                    && &self.observed_payee_id == expected_payee
                {
                    return Err(MarketError::state_invalid(
"counterparty_mismatch claim settlement receipts require at least one observed counterparty to differ from the settlement topology",
));
                }
            }
        }
        Ok(())
    }
}

/// Signed settlement receipt envelope.
pub type SignedLiabilityClaimSettlementReceipt =
    SignedExportEnvelope<LiabilityClaimSettlementReceiptArtifact>;

/// Filter set for claim workflow reports; unset fields match
/// everything.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimWorkflowQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for LiabilityClaimWorkflowQuery {
    fn default() -> Self {
        Self {
            claim_id: None,
            provider_id: None,
            agent_subject: None,
            jurisdiction: None,
            policy_number: None,
            limit: Some(50),
        }
    }
}

impl LiabilityClaimWorkflowQuery {
    /// The effective limit: the requested one clamped to the workflow
    /// cap.
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        bounded_market_query_limit(self.limit, MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT)
    }

    /// The query with its limit clamped and identity fields
    /// case-normalized.
    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized.claim_id = self.claim_id.as_ref().map(|value| value.trim().to_string());
        normalized.provider_id = self
            .provider_id
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized.agent_subject = self
            .agent_subject
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized.jurisdiction = self
            .jurisdiction
            .as_ref()
            .map(|value| value.trim().to_ascii_lowercase());
        normalized.policy_number = self
            .policy_number
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized
    }
}

/// One claim with every downstream artifact observed for it, in
/// lifecycle order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimWorkflowRow {
    pub claim: SignedLiabilityClaimPackage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_response: Option<SignedLiabilityClaimResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute: Option<SignedLiabilityClaimDispute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adjudication: Option<SignedLiabilityClaimAdjudication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout_instruction: Option<SignedLiabilityClaimPayoutInstruction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout_receipt: Option<SignedLiabilityClaimPayoutReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_instruction: Option<SignedLiabilityClaimSettlementInstruction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_receipt: Option<SignedLiabilityClaimSettlementReceipt>,
}

/// Aggregate counts for one claim workflow report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimWorkflowSummary {
    pub matching_claims: u64,
    pub returned_claims: u64,
    pub provider_responses: u64,
    pub accepted_responses: u64,
    pub denied_responses: u64,
    pub disputes: u64,
    pub adjudications: u64,
    pub payout_instructions: u64,
    pub payout_receipts: u64,
    pub matched_payout_receipts: u64,
    pub mismatched_payout_receipts: u64,
    pub settlement_instructions: u64,
    pub settlement_receipts: u64,
    pub matched_settlement_receipts: u64,
    pub mismatched_settlement_receipts: u64,
    pub counterparty_mismatch_settlement_receipts: u64,
}

/// Query echo, summary, and rows for one claim workflow report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimWorkflowReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: LiabilityClaimWorkflowQuery,
    pub summary: LiabilityClaimWorkflowSummary,
    pub claims: Vec<LiabilityClaimWorkflowRow>,
}
