//! Liability quote request/response and pricing-authority artifacts.

use serde::{Deserialize, Serialize};

use crate::capability::MonetaryAmount;
use crate::credit::{
    CreditFacilityDisposition, CreditFacilityLifecycleState, SignedCapitalBookReport,
    SignedCreditFacility, SignedCreditProviderRiskPackage,
};
use crate::receipt::SignedExportEnvelope;
use crate::underwriting::{
    SignedUnderwritingDecision, UnderwritingBudgetAction, UnderwritingDecisionLifecycleState,
    UnderwritingReviewState,
};

use crate::{
    validate_currency_code, validate_positive_money, LiabilityCoverageClass,
    LiabilityEvidenceRequirement,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityQuoteDisposition {
    Quoted,
    Declined,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderPolicyReference {
    pub provider_id: String,
    pub provider_record_id: String,
    pub display_name: String,
    pub jurisdiction: String,
    pub coverage_class: LiabilityCoverageClass,
    pub currency: String,
    pub required_evidence: Vec<LiabilityEvidenceRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_coverage_amount: Option<MonetaryAmount>,
    pub claims_supported: bool,
    pub quote_ttl_seconds: u64,
    pub bound_coverage_supported: bool,
}

impl LiabilityProviderPolicyReference {
    pub fn validate(&self) -> Result<(), String> {
        if self.provider_id.trim().is_empty() {
            return Err("provider policy reference requires provider_id".to_string());
        }
        if self.provider_record_id.trim().is_empty() {
            return Err("provider policy reference requires provider_record_id".to_string());
        }
        if self.display_name.trim().is_empty() {
            return Err("provider policy reference requires display_name".to_string());
        }
        if self.jurisdiction.trim().is_empty() {
            return Err("provider policy reference requires jurisdiction".to_string());
        }
        validate_currency_code(&self.currency, "provider policy reference currency")?;
        if self.quote_ttl_seconds == 0 {
            return Err(
                "provider policy reference requires quote_ttl_seconds greater than zero"
                    .to_string(),
            );
        }
        if let Some(max_coverage_amount) = self.max_coverage_amount.as_ref() {
            if max_coverage_amount.units == 0 {
                return Err(
                    "provider policy reference max_coverage_amount must be greater than zero"
                        .to_string(),
                );
            }
            if max_coverage_amount.currency.trim().to_ascii_uppercase() != self.currency {
                return Err("provider policy reference max_coverage_amount currency must match policy currency".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityPricingAuthorityEnvelopeKind {
    ProviderDelegate,
    RegulatedRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPricingAuthorityEnvelope {
    pub kind: LiabilityPricingAuthorityEnvelopeKind,
    pub delegate_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regulated_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_chain_ref: Option<String>,
}

impl LiabilityPricingAuthorityEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.delegate_id.trim().is_empty() {
            return Err("pricing authority envelope requires delegate_id".to_string());
        }
        if matches!(
            self.kind,
            LiabilityPricingAuthorityEnvelopeKind::RegulatedRole
        ) && self
            .regulated_role
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(
                "regulated-role pricing authority envelopes require regulated_role".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteRequestArtifact {
    pub schema: String,
    pub quote_request_id: String,
    pub issued_at: u64,
    pub provider_policy: LiabilityProviderPolicyReference,
    pub requested_coverage_amount: MonetaryAmount,
    pub requested_effective_from: u64,
    pub requested_effective_until: u64,
    pub risk_package: SignedCreditProviderRiskPackage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl LiabilityQuoteRequestArtifact {
    pub fn validate(&self) -> Result<(), String> {
        self.provider_policy.validate()?;
        validate_positive_money(
            &self.requested_coverage_amount,
            "quote request requested_coverage_amount",
        )?;
        if self
            .requested_coverage_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(
                "quote request requested_coverage_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.requested_effective_until <= self.requested_effective_from {
            return Err("quote request effective window must have end after start".to_string());
        }
        if !self.risk_package.verify_signature().map_err(|error| {
            format!("quote request risk package signature verification failed: {error}")
        })? {
            return Err("quote request risk package signature verification failed".to_string());
        }
        if self.risk_package.body.subject_key.trim().is_empty() {
            return Err("quote request risk package subject_key must not be empty".to_string());
        }
        if let Some(max_coverage_amount) = self.provider_policy.max_coverage_amount.as_ref() {
            if self.requested_coverage_amount.units > max_coverage_amount.units {
                return Err(
                    "quote request requested_coverage_amount exceeds provider max_coverage_amount"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityQuoteRequest = SignedExportEnvelope<LiabilityQuoteRequestArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteTerms {
    pub quoted_coverage_amount: MonetaryAmount,
    pub quoted_premium_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_deductible_amount: Option<MonetaryAmount>,
    pub expires_at: u64,
}

impl LiabilityQuoteTerms {
    fn validate_for_request(
        &self,
        request: &LiabilityQuoteRequestArtifact,
        issued_at: u64,
    ) -> Result<(), String> {
        validate_positive_money(
            &self.quoted_coverage_amount,
            "quote response quoted_coverage_amount",
        )?;
        validate_positive_money(
            &self.quoted_premium_amount,
            "quote response quoted_premium_amount",
        )?;
        if let Some(quoted_deductible_amount) = self.quoted_deductible_amount.as_ref() {
            validate_positive_money(
                quoted_deductible_amount,
                "quote response quoted_deductible_amount",
            )?;
            if quoted_deductible_amount
                .currency
                .trim()
                .to_ascii_uppercase()
                != request.provider_policy.currency
            {
                return Err(
                    "quote response quoted_deductible_amount currency must match provider policy currency"
                        .to_string(),
                );
            }
        }
        if self
            .quoted_coverage_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != request.provider_policy.currency
        {
            return Err(
                "quote response quoted_coverage_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self
            .quoted_premium_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != request.provider_policy.currency
        {
            return Err(
                "quote response quoted_premium_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.expires_at <= issued_at {
            return Err("quote response expires_at must be after issuance".to_string());
        }
        if self.expires_at
            > request
                .issued_at
                .saturating_add(request.provider_policy.quote_ttl_seconds)
        {
            return Err("quote response expires_at exceeds provider policy quote TTL".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteResponseArtifact {
    pub schema: String,
    pub quote_response_id: String,
    pub issued_at: u64,
    pub quote_request: SignedLiabilityQuoteRequest,
    pub provider_quote_ref: String,
    pub disposition: LiabilityQuoteDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_quote_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_terms: Option<LiabilityQuoteTerms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

impl LiabilityQuoteResponseArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != crate::LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported liability quote response schema: {}",
                self.schema
            ));
        }
        let quote_response_id = self.quote_response_id.trim();
        if quote_response_id.is_empty() {
            return Err("quote response requires quote_response_id".to_string());
        }
        if quote_response_id != self.quote_response_id {
            return Err(
                "quote response quote_response_id must not have leading or trailing whitespace"
                    .to_string(),
            );
        }
        if self.quote_response_id.chars().any(char::is_control) {
            return Err(
                "quote response quote_response_id must not include control characters".to_string(),
            );
        }
        if !self.quote_request.verify_signature().map_err(|error| {
            format!("quote response quote_request signature verification failed: {error}")
        })? {
            return Err("quote response quote_request signature verification failed".to_string());
        }
        self.quote_request.body.validate()?;
        if self.provider_quote_ref.trim().is_empty() {
            return Err("quote response requires provider_quote_ref".to_string());
        }
        match self.disposition {
            LiabilityQuoteDisposition::Quoted => {
                let quoted_terms = self
                    .quoted_terms
                    .as_ref()
                    .ok_or_else(|| "quoted quote responses require quoted_terms".to_string())?;
                quoted_terms.validate_for_request(&self.quote_request.body, self.issued_at)?;
                if self.decline_reason.is_some() {
                    return Err("quoted quote responses cannot include decline_reason".to_string());
                }
            }
            LiabilityQuoteDisposition::Declined => {
                if self.quoted_terms.is_some() {
                    return Err("declined quote responses cannot include quoted_terms".to_string());
                }
                if self
                    .decline_reason
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    return Err("declined quote responses require decline_reason".to_string());
                }
            }
        }
        Ok(())
    }
}

pub type SignedLiabilityQuoteResponse = SignedExportEnvelope<LiabilityQuoteResponseArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPricingAuthorityArtifact {
    pub schema: String,
    pub authority_id: String,
    pub issued_at: u64,
    pub quote_request: SignedLiabilityQuoteRequest,
    pub provider_policy: LiabilityProviderPolicyReference,
    pub facility: SignedCreditFacility,
    pub underwriting_decision: SignedUnderwritingDecision,
    pub capital_book: SignedCapitalBookReport,
    pub envelope: LiabilityPricingAuthorityEnvelope,
    pub max_coverage_amount: MonetaryAmount,
    pub max_premium_amount: MonetaryAmount,
    pub expires_at: u64,
    pub auto_bind_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl LiabilityPricingAuthorityArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if !self.quote_request.verify_signature().map_err(|error| {
            format!("pricing authority quote_request signature verification failed: {error}")
        })? {
            return Err(
                "pricing authority quote_request signature verification failed".to_string(),
            );
        }
        if !self.facility.verify_signature().map_err(|error| {
            format!("pricing authority facility signature verification failed: {error}")
        })? {
            return Err("pricing authority facility signature verification failed".to_string());
        }
        if !self
            .underwriting_decision
            .verify_signature()
            .map_err(|error| {
                format!(
                    "pricing authority underwriting decision signature verification failed: {error}"
                )
            })?
        {
            return Err(
                "pricing authority underwriting decision signature verification failed".to_string(),
            );
        }
        if !self.capital_book.verify_signature().map_err(|error| {
            format!("pricing authority capital book signature verification failed: {error}")
        })? {
            return Err("pricing authority capital book signature verification failed".to_string());
        }
        self.quote_request.body.validate()?;
        self.provider_policy.validate()?;
        self.envelope.validate()?;
        if self.provider_policy != self.quote_request.body.provider_policy {
            return Err(
                "pricing authority provider_policy must match the quote request provider_policy"
                    .to_string(),
            );
        }
        validate_positive_money(
            &self.max_coverage_amount,
            "pricing authority max_coverage_amount",
        )?;
        validate_positive_money(
            &self.max_premium_amount,
            "pricing authority max_premium_amount",
        )?;
        if self
            .max_coverage_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(
                "pricing authority max_coverage_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.max_premium_amount.currency.trim().to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(
                "pricing authority max_premium_amount currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.expires_at <= self.issued_at {
            return Err("pricing authority expires_at must be after issuance".to_string());
        }
        if self.expires_at
            > self
                .quote_request
                .body
                .issued_at
                .saturating_add(self.provider_policy.quote_ttl_seconds)
        {
            return Err(
                "pricing authority expires_at exceeds provider policy quote TTL".to_string(),
            );
        }
        if self.facility.body.lifecycle_state != CreditFacilityLifecycleState::Active {
            return Err("pricing authority requires an active facility".to_string());
        }
        if self.facility.body.report.disposition != CreditFacilityDisposition::Grant {
            return Err("pricing authority requires a granted facility".to_string());
        }
        let facility_terms = self
            .facility
            .body
            .report
            .terms
            .as_ref()
            .ok_or_else(|| "pricing authority requires facility terms".to_string())?;
        if facility_terms
            .credit_limit
            .currency
            .trim()
            .to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(
                "pricing authority facility credit limit currency must match provider policy currency"
                    .to_string(),
            );
        }
        if self.max_coverage_amount.units > facility_terms.credit_limit.units {
            return Err(
                "pricing authority max_coverage_amount exceeds facility credit limit".to_string(),
            );
        }
        if let Some(max_coverage_amount) = self.provider_policy.max_coverage_amount.as_ref() {
            if self.max_coverage_amount.units > max_coverage_amount.units {
                return Err(
                    "pricing authority max_coverage_amount exceeds provider max_coverage_amount"
                        .to_string(),
                );
            }
        }
        if self.underwriting_decision.body.lifecycle_state
            != UnderwritingDecisionLifecycleState::Active
        {
            return Err("pricing authority requires an active underwriting decision".to_string());
        }
        if self.underwriting_decision.body.review_state != UnderwritingReviewState::Approved {
            return Err("pricing authority requires an approved underwriting decision".to_string());
        }
        if matches!(
            self.underwriting_decision.body.budget.action,
            UnderwritingBudgetAction::Hold | UnderwritingBudgetAction::Deny
        ) {
            return Err(
                "pricing authority requires underwriting budget action preserve or reduce"
                    .to_string(),
            );
        }
        if let Some(quoted_amount) = self
            .underwriting_decision
            .body
            .premium
            .quoted_amount
            .as_ref()
        {
            if quoted_amount.currency.trim().to_ascii_uppercase() != self.provider_policy.currency {
                return Err(
                    "pricing authority underwriting premium currency must match provider policy currency"
                        .to_string(),
                );
            }
            if self.max_premium_amount.units > quoted_amount.units {
                return Err(
                    "pricing authority max_premium_amount exceeds underwriting quoted premium"
                        .to_string(),
                );
            }
        }
        let subject_key = self
            .quote_request
            .body
            .risk_package
            .body
            .subject_key
            .as_str();
        if self.capital_book.body.subject_key != subject_key {
            return Err(
                "pricing authority capital book subject must match the quote request subject"
                    .to_string(),
            );
        }
        if self.capital_book.body.summary.mixed_currency_book {
            return Err(
                "pricing authority cannot be issued against a mixed-currency capital book"
                    .to_string(),
            );
        }
        let facility_source = self
            .capital_book
            .body
            .sources
            .iter()
            .find(|source| {
                source.facility_id.as_deref() == Some(self.facility.body.facility_id.as_str())
            })
            .ok_or_else(|| {
                "pricing authority capital book must include the referenced facility source"
                    .to_string()
            })?;
        if facility_source.currency.trim().to_ascii_uppercase() != self.provider_policy.currency {
            return Err(
                "pricing authority capital book source currency must match provider policy currency"
                    .to_string(),
            );
        }
        if let Some(committed_amount) = facility_source.committed_amount.as_ref() {
            let available_units = committed_amount
                .units
                .saturating_sub(
                    facility_source
                        .disbursed_amount
                        .as_ref()
                        .map_or(0, |amount| amount.units),
                )
                .saturating_sub(
                    facility_source
                        .impaired_amount
                        .as_ref()
                        .map_or(0, |amount| amount.units),
                );
            if self.max_coverage_amount.units > available_units {
                return Err(
                    "pricing authority max_coverage_amount exceeds capital book available committed amount"
                        .to_string(),
                );
            }
        }
        if self.auto_bind_enabled
            && (!self.provider_policy.bound_coverage_supported
                || !self.provider_policy.claims_supported)
        {
            return Err(
                "pricing authority cannot enable auto_bind because the provider policy does not support bound coverage and claims"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub type SignedLiabilityPricingAuthority = SignedExportEnvelope<LiabilityPricingAuthorityArtifact>;
