//! Liability quote request/response and pricing-authority artifacts.

use serde::{Deserialize, Serialize};

use crate::capability::scope::MonetaryAmount;
use crate::credit::{
    CreditFacilityDisposition, CreditFacilityLifecycleState, SignedCapitalBookReport,
    SignedCreditFacility, SignedCreditProviderRiskPackage,
};
use crate::receipt::lineage::SignedExportEnvelope;
use crate::underwriting::{
    SignedUnderwritingDecision, UnderwritingBudgetAction, UnderwritingDecisionLifecycleState,
    UnderwritingReviewState,
};

use crate::error::MarketError;
use crate::{
    validate_currency_code, validate_positive_money, LiabilityCoverageClass,
    LiabilityEvidenceRequirement,
};

/// Provider disposition for a quote request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityQuoteDisposition {
    Quoted,
    Declined,
}

/// The exact provider policy a quote request was priced against,
/// denormalized so downstream artifacts cannot drift from it.
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
    /// Fail closed unless every policy identity field is non-empty, the
    /// currency is a three-letter code, and the TTL is positive.
    pub fn validate(&self) -> Result<(), MarketError> {
        if self.provider_id.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "provider policy reference requires provider_id",
            ));
        }
        if self.provider_record_id.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "provider policy reference requires provider_record_id",
            ));
        }
        if self.display_name.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "provider policy reference requires display_name",
            ));
        }
        if self.jurisdiction.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "provider policy reference requires jurisdiction",
            ));
        }
        validate_currency_code(&self.currency, "provider policy reference currency")?;
        if self.quote_ttl_seconds == 0 {
            return Err(MarketError::field_invalid(
                "provider policy reference requires quote_ttl_seconds greater than zero",
            ));
        }
        if let Some(max_coverage_amount) = self.max_coverage_amount.as_ref() {
            if max_coverage_amount.units == 0 {
                return Err(MarketError::amount_out_of_bounds(
                    "provider policy reference max_coverage_amount must be greater than zero",
                ));
            }
            if max_coverage_amount.currency.trim().to_ascii_uppercase() != self.currency {
                return Err(MarketError::currency_mismatch(
"provider policy reference max_coverage_amount currency must match policy currency",
));
            }
        }
        Ok(())
    }
}

/// How pricing authority was delegated to the quoting party.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityPricingAuthorityEnvelopeKind {
    ProviderDelegate,
    RegulatedRole,
}

/// The delegation envelope a pricing authority acts under; a regulated
/// role must name that role.
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
    /// Fail closed unless the delegate is named and a regulated-role
    /// envelope carries its regulated_role.
    pub fn validate(&self) -> Result<(), MarketError> {
        if self.delegate_id.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "pricing authority envelope requires delegate_id",
            ));
        }
        if matches!(
            self.kind,
            LiabilityPricingAuthorityEnvelopeKind::RegulatedRole
        ) && self
            .regulated_role
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(MarketError::field_invalid(
                "regulated-role pricing authority envelopes require regulated_role",
            ));
        }
        Ok(())
    }
}

/// Buyer-signed request for coverage priced against one provider
/// policy reference.
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
    /// Fail closed on the request shape: pinned schema, non-empty
    /// identities, a valid provider policy, positive requested amounts,
    /// and a currency that matches the policy.
    pub fn validate(&self) -> Result<(), MarketError> {
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
            return Err(MarketError::currency_mismatch(
"quote request requested_coverage_amount currency must match provider policy currency",
));
        }
        if self.requested_effective_until <= self.requested_effective_from {
            return Err(MarketError::window_invalid(
                "quote request effective window must have end after start",
            ));
        }
        if !self.risk_package.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "quote request risk package signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "quote request risk package signature verification failed",
            ));
        }
        if self.risk_package.body.subject_key.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "quote request risk package subject_key must not be empty",
            ));
        }
        if let Some(max_coverage_amount) = self.provider_policy.max_coverage_amount.as_ref() {
            if self.requested_coverage_amount.units > max_coverage_amount.units {
                return Err(MarketError::amount_out_of_bounds(
                    "quote request requested_coverage_amount exceeds provider max_coverage_amount",
                ));
            }
        }
        Ok(())
    }
}

/// Signed quote request envelope.
pub type SignedLiabilityQuoteRequest = SignedExportEnvelope<LiabilityQuoteRequestArtifact>;

/// The priced terms of a quoted response, bounded by the request
/// policy currency and the provider quote TTL.
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
    ) -> Result<(), MarketError> {
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
                return Err(MarketError::currency_mismatch(
"quote response quoted_deductible_amount currency must match provider policy currency",
));
            }
        }
        if self
            .quoted_coverage_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != request.provider_policy.currency
        {
            return Err(MarketError::currency_mismatch(
"quote response quoted_coverage_amount currency must match provider policy currency",
));
        }
        if self
            .quoted_premium_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != request.provider_policy.currency
        {
            return Err(MarketError::currency_mismatch(
                "quote response quoted_premium_amount currency must match provider policy currency",
            ));
        }
        if self.expires_at <= issued_at {
            return Err(MarketError::window_invalid(
                "quote response expires_at must be after issuance",
            ));
        }
        if self.expires_at
            > request
                .issued_at
                .saturating_add(request.provider_policy.quote_ttl_seconds)
        {
            return Err(MarketError::window_invalid(
                "quote response expires_at exceeds provider policy quote TTL",
            ));
        }
        Ok(())
    }
}

/// Provider-signed answer to a quote request: quoted terms or a
/// decline reason, never both.
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
    /// Fail closed on the response shape: the embedded request must
    /// verify, and the disposition fixes whether quoted_terms or
    /// decline_reason must be present, with quoted terms validated
    /// against the request policy and TTL.
    pub fn validate(&self) -> Result<(), MarketError> {
        if self.schema != crate::LIABILITY_QUOTE_RESPONSE_ARTIFACT_SCHEMA {
            return Err(MarketError::schema_unsupported(format!(
                "unsupported liability quote response schema: {}",
                self.schema
            )));
        }
        let quote_response_id = self.quote_response_id.trim();
        if quote_response_id.is_empty() {
            return Err(MarketError::field_invalid(
                "quote response requires quote_response_id",
            ));
        }
        if quote_response_id != self.quote_response_id {
            return Err(MarketError::field_invalid(
                "quote response quote_response_id must not have leading or trailing whitespace",
            ));
        }
        if self.quote_response_id.chars().any(char::is_control) {
            return Err(MarketError::field_invalid(
                "quote response quote_response_id must not include control characters",
            ));
        }
        if !self.quote_request.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "quote response quote_request signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "quote response quote_request signature verification failed",
            ));
        }
        self.quote_request.body.validate()?;
        if self.provider_quote_ref.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "quote response requires provider_quote_ref",
            ));
        }
        match self.disposition {
            LiabilityQuoteDisposition::Quoted => {
                let quoted_terms = self.quoted_terms.as_ref().ok_or_else(|| {
                    MarketError::field_invalid("quoted quote responses require quoted_terms")
                })?;
                quoted_terms.validate_for_request(&self.quote_request.body, self.issued_at)?;
                if self.decline_reason.is_some() {
                    return Err(MarketError::field_invalid(
                        "quoted quote responses cannot include decline_reason",
                    ));
                }
            }
            LiabilityQuoteDisposition::Declined => {
                if self.quoted_terms.is_some() {
                    return Err(MarketError::field_invalid(
                        "declined quote responses cannot include quoted_terms",
                    ));
                }
                if self
                    .decline_reason
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    return Err(MarketError::field_invalid(
                        "declined quote responses require decline_reason",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Signed quote response envelope.
pub type SignedLiabilityQuoteResponse = SignedExportEnvelope<LiabilityQuoteResponseArtifact>;

/// Provider-signed grant of pricing authority: who may quote, under
/// which delegation envelope, within which amount and time bounds.
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
    /// Fail closed on the authority shape: pinned schema, a valid
    /// delegation envelope, positive bounds, and a validity window that
    /// has not inverted.
    pub fn validate(&self) -> Result<(), MarketError> {
        if !self.quote_request.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "pricing authority quote_request signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "pricing authority quote_request signature verification failed",
            ));
        }
        if !self.facility.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "pricing authority facility signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "pricing authority facility signature verification failed",
            ));
        }
        if !self
            .underwriting_decision
            .verify_signature()
            .map_err(|error| {
 MarketError::signature_invalid(format!("pricing authority underwriting decision signature verification failed: {error}"))
 })?
        {
            return Err(MarketError::signature_invalid(
"pricing authority underwriting decision signature verification failed",
));
        }
        if !self.capital_book.verify_signature().map_err(|error| {
            MarketError::signature_invalid(format!(
                "pricing authority capital book signature verification failed: {error}"
            ))
        })? {
            return Err(MarketError::signature_invalid(
                "pricing authority capital book signature verification failed",
            ));
        }
        self.quote_request.body.validate()?;
        self.provider_policy.validate()?;
        self.envelope.validate()?;
        if self.provider_policy != self.quote_request.body.provider_policy {
            return Err(MarketError::binding_mismatch(
                "pricing authority provider_policy must match the quote request provider_policy",
            ));
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
            return Err(MarketError::currency_mismatch(
"pricing authority max_coverage_amount currency must match provider policy currency",
));
        }
        if self.max_premium_amount.currency.trim().to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(MarketError::currency_mismatch(
                "pricing authority max_premium_amount currency must match provider policy currency",
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(MarketError::window_invalid(
                "pricing authority expires_at must be after issuance",
            ));
        }
        if self.expires_at
            > self
                .quote_request
                .body
                .issued_at
                .saturating_add(self.provider_policy.quote_ttl_seconds)
        {
            return Err(MarketError::window_invalid(
                "pricing authority expires_at exceeds provider policy quote TTL",
            ));
        }
        if self.facility.body.lifecycle_state != CreditFacilityLifecycleState::Active {
            return Err(MarketError::state_invalid(
                "pricing authority requires an active facility",
            ));
        }
        if self.facility.body.report.disposition != CreditFacilityDisposition::Grant {
            return Err(MarketError::state_invalid(
                "pricing authority requires a granted facility",
            ));
        }
        let facility_terms = self.facility.body.report.terms.as_ref().ok_or_else(|| {
            MarketError::field_invalid("pricing authority requires facility terms")
        })?;
        if facility_terms
            .credit_limit
            .currency
            .trim()
            .to_ascii_uppercase()
            != self.provider_policy.currency
        {
            return Err(MarketError::currency_mismatch(
"pricing authority facility credit limit currency must match provider policy currency",
));
        }
        if self.max_coverage_amount.units > facility_terms.credit_limit.units {
            return Err(MarketError::amount_out_of_bounds(
                "pricing authority max_coverage_amount exceeds facility credit limit",
            ));
        }
        if let Some(max_coverage_amount) = self.provider_policy.max_coverage_amount.as_ref() {
            if self.max_coverage_amount.units > max_coverage_amount.units {
                return Err(MarketError::amount_out_of_bounds(
                    "pricing authority max_coverage_amount exceeds provider max_coverage_amount",
                ));
            }
        }
        if self.underwriting_decision.body.lifecycle_state
            != UnderwritingDecisionLifecycleState::Active
        {
            return Err(MarketError::state_invalid(
                "pricing authority requires an active underwriting decision",
            ));
        }
        if self.underwriting_decision.body.review_state != UnderwritingReviewState::Approved {
            return Err(MarketError::state_invalid(
                "pricing authority requires an approved underwriting decision",
            ));
        }
        if matches!(
            self.underwriting_decision.body.budget.action,
            UnderwritingBudgetAction::Hold | UnderwritingBudgetAction::Deny
        ) {
            return Err(MarketError::state_invalid(
                "pricing authority requires underwriting budget action preserve or reduce",
            ));
        }
        if let Some(quoted_amount) = self
            .underwriting_decision
            .body
            .premium
            .quoted_amount
            .as_ref()
        {
            if quoted_amount.currency.trim().to_ascii_uppercase() != self.provider_policy.currency {
                return Err(MarketError::currency_mismatch(
"pricing authority underwriting premium currency must match provider policy currency",
));
            }
            if self.max_premium_amount.units > quoted_amount.units {
                return Err(MarketError::amount_out_of_bounds(
                    "pricing authority max_premium_amount exceeds underwriting quoted premium",
                ));
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
            return Err(MarketError::binding_mismatch(
                "pricing authority capital book subject must match the quote request subject",
            ));
        }
        if self.capital_book.body.summary.mixed_currency_book {
            return Err(MarketError::state_invalid(
                "pricing authority cannot be issued against a mixed-currency capital book",
            ));
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
                MarketError::binding_mismatch(
                    "pricing authority capital book must include the referenced facility source",
                )
            })?;
        if facility_source.currency.trim().to_ascii_uppercase() != self.provider_policy.currency {
            return Err(MarketError::currency_mismatch(
"pricing authority capital book source currency must match provider policy currency",
));
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
                return Err(MarketError::amount_out_of_bounds(
"pricing authority max_coverage_amount exceeds capital book available committed amount",
));
            }
        }
        if self.auto_bind_enabled
            && (!self.provider_policy.bound_coverage_supported
                || !self.provider_policy.claims_supported)
        {
            return Err(MarketError::state_invalid(
"pricing authority cannot enable auto_bind because the provider policy does not support bound coverage and claims",
));
        }
        Ok(())
    }
}

/// Signed pricing authority envelope.
pub type SignedLiabilityPricingAuthority = SignedExportEnvelope<LiabilityPricingAuthorityArtifact>;
