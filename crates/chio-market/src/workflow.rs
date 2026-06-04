//! Liability market workflow query, summary, and report types.

use serde::{Deserialize, Serialize};

use crate::{
    bounded_market_query_limit, LiabilityCoverageClass, SignedLiabilityAutoBindDecision,
    SignedLiabilityBoundCoverage, SignedLiabilityPlacement, SignedLiabilityPricingAuthority,
    SignedLiabilityQuoteRequest, SignedLiabilityQuoteResponse, MAX_LIABILITY_MARKET_WORKFLOW_LIMIT,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityMarketWorkflowQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_class: Option<LiabilityCoverageClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for LiabilityMarketWorkflowQuery {
    fn default() -> Self {
        Self {
            quote_request_id: None,
            provider_id: None,
            agent_subject: None,
            jurisdiction: None,
            coverage_class: None,
            currency: None,
            limit: Some(50),
        }
    }
}

impl LiabilityMarketWorkflowQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        bounded_market_query_limit(self.limit, MAX_LIABILITY_MARKET_WORKFLOW_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized.provider_id = self
            .provider_id
            .as_ref()
            .map(|value| value.trim().to_string());
        normalized.quote_request_id = self
            .quote_request_id
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
        normalized.currency = self
            .currency
            .as_ref()
            .map(|value| value.trim().to_ascii_uppercase());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityMarketWorkflowRow {
    pub quote_request: SignedLiabilityQuoteRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_quote_response: Option<SignedLiabilityQuoteResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing_authority: Option<SignedLiabilityPricingAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_auto_bind_decision: Option<SignedLiabilityAutoBindDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<SignedLiabilityPlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_coverage: Option<SignedLiabilityBoundCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityMarketWorkflowSummary {
    pub matching_requests: u64,
    pub returned_requests: u64,
    pub quote_responses: u64,
    pub quoted_responses: u64,
    pub declined_responses: u64,
    pub pricing_authorities: u64,
    pub auto_bind_decisions: u64,
    pub auto_bound_decisions: u64,
    pub manual_review_decisions: u64,
    pub denied_decisions: u64,
    pub placements: u64,
    pub bound_coverages: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityMarketWorkflowReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: LiabilityMarketWorkflowQuery,
    pub summary: LiabilityMarketWorkflowSummary,
    pub workflows: Vec<LiabilityMarketWorkflowRow>,
}
