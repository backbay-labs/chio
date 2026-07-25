//! Liability-market provider, quote, and claims contracts for the Chio
//! protocol.
//!
//! This crate models liability coverage for metered tool access: quoting,
//! binding policies, and settling claims against signed receipt evidence. It
//! defines the insurance flow (`quote_and_bind`, bound policies, coverage
//! limits, premium sources) and the claim-settlement path (claim evidence,
//! decisions, denial reasons, settlement requests), with receipt fingerprints
//! linking claims back to the receipts they cover. It builds on the appraisal,
//! credit, and underwriting surfaces.
//!
//! # Modules
//!
//! - [`insurance_flow`] -- quote/bind and claim-settlement flow.

#![forbid(unsafe_code)]

pub use chio_appraisal as appraisal;
pub use chio_core_types::{capability, crypto, receipt};
pub use chio_credit as credit;
pub use chio_underwriting as underwriting;

pub mod insurance_flow;
pub mod parametric;
pub use insurance_flow::{
    quote_and_bind, BoundPolicy, ClaimDecision, ClaimDenialReason, ClaimEvidence, ClaimSettlement,
    ClaimSettlementRequest, ClaimSettlementSink, CoverageLimit, InsuranceFlowError, PolicyStatus,
    PremiumSource, ReceiptEvidenceSource, ReceiptFingerprint, ResolvedReceiptEvidence,
    StaticPremiumSource,
};
pub use parametric::*;

use serde::Serialize;

use crate::capability::scope::MonetaryAmount;
use crate::receipt::lineage::SignedExportEnvelope;

pub const LIABILITY_PROVIDER_ARTIFACT_SCHEMA: &str = "chio.market.provider.v1";
pub const LIABILITY_PROVIDER_LIST_REPORT_SCHEMA: &str = "chio.market.provider-list.v1";
pub const LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA: &str = "chio.market.provider-resolution.v1";
pub const LIABILITY_QUOTE_REQUEST_ARTIFACT_SCHEMA: &str = "chio.market.quote-request.v1";
pub const LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA: &str = "chio.market.quote-response.v1";
pub const LIABILITY_PRICING_AUTHORITY_ARTIFACT_SCHEMA: &str = "chio.market.pricing-authority.v1";
pub const LIABILITY_PLACEMENT_ARTIFACT_SCHEMA: &str = "chio.market.placement.v1";
pub const LIABILITY_BOUND_COVERAGE_ARTIFACT_SCHEMA: &str = "chio.market.bound-coverage.v1";
pub const LIABILITY_AUTO_BIND_DECISION_ARTIFACT_SCHEMA: &str = "chio.market.auto-bind.v1";
pub const LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA: &str = "chio.market.workflow-list.v1";
pub const LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA: &str = "chio.market.claim-package.v1";
pub const LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA: &str = "chio.market.claim-response.v1";
pub const LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA: &str = "chio.market.claim-dispute.v1";
pub const LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA: &str = "chio.market.claim-adjudication.v1";
pub const LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA: &str =
    "chio.market.claim-payout-instruction.v1";
pub const LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA: &str =
    "chio.market.claim-payout-receipt.v1";
pub const LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA: &str =
    "chio.market.claim-settlement-instruction.v1";
pub const LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA: &str =
    "chio.market.claim-settlement-receipt.v1";
pub const LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA: &str = "chio.market.claim-workflow-list.v1";
pub const MAX_LIABILITY_PROVIDER_LIST_LIMIT: usize = 100;
pub const MAX_LIABILITY_MARKET_WORKFLOW_LIMIT: usize = 100;
pub const MAX_LIABILITY_CLAIM_WORKFLOW_LIMIT: usize = 100;

fn bounded_market_query_limit(limit: Option<usize>, max: usize) -> usize {
    limit.unwrap_or(50).clamp(1, max)
}

mod claim;
mod placement;
mod provider;
mod quote;
mod settlement;
mod workflow;

pub use claim::*;
pub use placement::*;
pub use provider::*;
pub use quote::*;
pub use settlement::*;
pub use workflow::*;

fn liability_claim_adjudication_payable_amount(
    adjudication: &LiabilityClaimAdjudicationArtifact,
) -> Result<&MonetaryAmount, String> {
    match adjudication.outcome {
        LiabilityClaimAdjudicationOutcome::ClaimUpheld
        | LiabilityClaimAdjudicationOutcome::PartialSettlement => {
            adjudication.awarded_amount.as_ref().ok_or_else(|| {
                "claim payout instructions require adjudications with awarded_amount".to_string()
            })
        }
        LiabilityClaimAdjudicationOutcome::ProviderUpheld => {
            Err("claim payout instructions require a payable adjudication outcome".to_string())
        }
    }
}

fn validate_currency_code(value: &str, field_name: &str) -> Result<(), String> {
    let currency = value.trim().to_ascii_uppercase();
    if currency.len() != 3
        || !currency
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(format!(
            "{field_name} must be a three-letter uppercase ISO-style code"
        ));
    }
    Ok(())
}

fn verify_signed_artifact<T>(
    artifact: &SignedExportEnvelope<T>,
    field_name: &str,
) -> Result<(), String>
where
    T: Serialize + Clone,
{
    if artifact
        .verify_signature()
        .map_err(|error| format!("{field_name} signature verification failed: {error}"))?
    {
        Ok(())
    } else {
        Err(format!("{field_name} signature verification failed"))
    }
}

fn validate_positive_money(amount: &MonetaryAmount, field_name: &str) -> Result<(), String> {
    if amount.units == 0 {
        return Err(format!("{field_name} must be greater than zero"));
    }
    validate_currency_code(&amount.currency, &format!("{field_name} currency"))?;
    Ok(())
}

#[cfg(test)]
mod tests;
