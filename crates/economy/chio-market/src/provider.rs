//! Liability provider registry types and resolution reports.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capability::scope::MonetaryAmount;
use crate::receipt::lineage::SignedExportEnvelope;

use crate::error::MarketError;
use crate::{bounded_market_query_limit, MAX_LIABILITY_PROVIDER_LIST_LIMIT};

/// Kind of organization standing behind a liability provider record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityProviderType {
    AdmittedCarrier,
    SurplusLine,
    Captive,
    RiskPool,
}

/// Coverage families a provider policy can underwrite.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityCoverageClass {
    ToolExecution,
    DataBreach,
    FinancialLoss,
    ProfessionalLiability,
    RegulatoryResponse,
}

/// Evidence a provider requires before quoting or paying a claim.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityEvidenceRequirement {
    BehavioralFeed,
    UnderwritingDecision,
    CreditProviderRiskPackage,
    RuntimeAttestationAppraisal,
    CertificationArtifact,
    CreditBond,
    AuthorizationReviewPack,
}

/// Lifecycle of a provider record; only active records resolve.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LiabilityProviderLifecycleState {
    Active,
    Suspended,
    Superseded,
    Retired,
}

/// Who configured the provider record and from which source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderProvenance {
    pub configured_by: String,
    pub configured_at: u64,
    pub source_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_reason: Option<String>,
}

/// One jurisdiction-scoped policy offer: coverage class, currency,
/// limits, and required evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityJurisdictionPolicy {
    pub jurisdiction: String,
    pub coverage_classes: Vec<LiabilityCoverageClass>,
    pub supported_currencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<LiabilityEvidenceRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_coverage_amount: Option<MonetaryAmount>,
    pub claims_supported: bool,
    pub quote_ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// What the provider does and does not support, stated explicitly so
/// absence of a capability is a recorded decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderSupportBoundary {
    pub curated_registry_only: bool,
    pub automatic_trust_admission: bool,
    pub permissionless_federation_supported: bool,
    pub bound_coverage_supported: bool,
}

impl Default for LiabilityProviderSupportBoundary {
    fn default() -> Self {
        Self {
            curated_registry_only: true,
            automatic_trust_admission: false,
            permissionless_federation_supported: false,
            bound_coverage_supported: false,
        }
    }
}

/// Operator-configured provider record listing its policies and
/// support boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderReport {
    pub schema: String,
    pub provider_id: String,
    pub display_name: String,
    pub provider_type: LiabilityProviderType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_url: Option<String>,
    pub lifecycle_state: LiabilityProviderLifecycleState,
    pub support_boundary: LiabilityProviderSupportBoundary,
    pub policies: Vec<LiabilityJurisdictionPolicy>,
    pub provenance: LiabilityProviderProvenance,
}

impl LiabilityProviderReport {
    /// Fail closed unless the provider identity, provenance, and every
    /// jurisdiction policy validate.
    pub fn validate(&self) -> Result<(), MarketError> {
        if self.provider_id.trim().is_empty() {
            return Err(MarketError::field_invalid("provider_id must not be empty"));
        }
        if self.display_name.trim().is_empty() {
            return Err(MarketError::field_invalid("display_name must not be empty"));
        }
        if self.provenance.configured_by.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "provenance.configured_by must not be empty",
            ));
        }
        if self.provenance.source_ref.trim().is_empty() {
            return Err(MarketError::field_invalid(
                "provenance.source_ref must not be empty",
            ));
        }
        if let Some(provider_url) = self.provider_url.as_deref() {
            if !(provider_url.starts_with("http://") || provider_url.starts_with("https://")) {
                return Err(MarketError::field_invalid(
                    "provider_url must start with http:// or https://",
                ));
            }
        }
        if self.policies.is_empty() {
            return Err(MarketError::field_invalid(
                "providers require at least one jurisdiction policy",
            ));
        }

        let mut seen_jurisdictions = BTreeSet::new();
        for policy in &self.policies {
            if policy.jurisdiction.trim().is_empty() {
                return Err(MarketError::field_invalid(
                    "jurisdiction policies require a non-empty jurisdiction",
                ));
            }
            let normalized_jurisdiction = policy.jurisdiction.trim().to_ascii_lowercase();
            if !seen_jurisdictions.insert(normalized_jurisdiction) {
                return Err(MarketError::field_invalid(format!(
                    "provider `{}` defines duplicate jurisdiction policy `{}`",
                    self.provider_id, policy.jurisdiction
                )));
            }
            if policy.coverage_classes.is_empty() {
                return Err(MarketError::field_invalid(format!(
                    "jurisdiction policy `{}` requires at least one coverage class",
                    policy.jurisdiction
                )));
            }
            if policy.supported_currencies.is_empty() {
                return Err(MarketError::field_invalid(format!(
                    "jurisdiction policy `{}` requires at least one supported currency",
                    policy.jurisdiction
                )));
            }
            if policy.quote_ttl_seconds == 0 {
                return Err(MarketError::field_invalid(format!(
                    "jurisdiction policy `{}` requires quote_ttl_seconds greater than zero",
                    policy.jurisdiction
                )));
            }
            let mut seen_coverage = BTreeSet::new();
            for coverage_class in &policy.coverage_classes {
                if !seen_coverage.insert(*coverage_class) {
                    return Err(MarketError::field_invalid(format!(
                        "jurisdiction policy `{}` defines duplicate coverage class `{:?}`",
                        policy.jurisdiction, coverage_class
                    )));
                }
            }
            let mut seen_currencies = BTreeSet::new();
            for currency in &policy.supported_currencies {
                let normalized_currency = currency.trim().to_ascii_uppercase();
                if normalized_currency.len() != 3
                    || !normalized_currency
                        .chars()
                        .all(|character| character.is_ascii_uppercase())
                {
                    return Err(MarketError::field_invalid(format!(
                        "jurisdiction policy `{}` contains invalid currency `{}`",
                        policy.jurisdiction, currency
                    )));
                }
                if !seen_currencies.insert(normalized_currency) {
                    return Err(MarketError::field_invalid(format!(
                        "jurisdiction policy `{}` contains duplicate currency `{}`",
                        policy.jurisdiction, currency
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Versioned wrapper binding a provider report to its record id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderArtifact {
    pub schema: String,
    pub provider_record_id: String,
    pub issued_at: u64,
    pub lifecycle_state: LiabilityProviderLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_provider_record_id: Option<String>,
    pub report: LiabilityProviderReport,
}

/// Signed provider record envelope.
pub type SignedLiabilityProvider = SignedExportEnvelope<LiabilityProviderArtifact>;

/// Filter set for provider listings; unset fields match everything.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_class: Option<LiabilityCoverageClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<LiabilityProviderLifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for LiabilityProviderListQuery {
    fn default() -> Self {
        Self {
            provider_id: None,
            jurisdiction: None,
            coverage_class: None,
            currency: None,
            lifecycle_state: None,
            limit: Some(50),
        }
    }
}

impl LiabilityProviderListQuery {
    /// The effective limit: the requested one clamped to the listing cap.
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        bounded_market_query_limit(self.limit, MAX_LIABILITY_PROVIDER_LIST_LIMIT)
    }

    /// The query with its limit clamped and its currency and jurisdiction
    /// normalized to canonical case.
    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized.currency = self
            .currency
            .as_ref()
            .map(|currency| currency.trim().to_ascii_uppercase());
        normalized.jurisdiction = self
            .jurisdiction
            .as_ref()
            .map(|jurisdiction| jurisdiction.trim().to_ascii_lowercase());
        normalized
    }
}

/// One listed provider with its lifecycle state and successor, if
/// superseded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderRow {
    pub provider: SignedLiabilityProvider,
    pub lifecycle_state: LiabilityProviderLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by_provider_record_id: Option<String>,
}

/// Aggregate counts for one provider listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderListSummary {
    pub matching_providers: u64,
    pub returned_providers: u64,
    pub active_providers: u64,
    pub suspended_providers: u64,
    pub superseded_providers: u64,
    pub retired_providers: u64,
}

/// Query echo, summary, and rows for one provider listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderListReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: LiabilityProviderListQuery,
    pub summary: LiabilityProviderListSummary,
    pub providers: Vec<LiabilityProviderRow>,
}

/// Exact-match resolution query: provider, jurisdiction, coverage
/// class, and currency must all match one active policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderResolutionQuery {
    pub provider_id: String,
    pub jurisdiction: String,
    pub coverage_class: LiabilityCoverageClass,
    pub currency: String,
}

impl LiabilityProviderResolutionQuery {
    /// Fail closed unless every field is non-empty and the currency is a
    /// three-letter code.
    pub fn validate(&self) -> Result<(), MarketError> {
        if self.provider_id.trim().is_empty() {
            return Err(MarketError::field_invalid("provider_id must not be empty"));
        }
        if self.jurisdiction.trim().is_empty() {
            return Err(MarketError::field_invalid("jurisdiction must not be empty"));
        }
        let currency = self.currency.trim().to_ascii_uppercase();
        if currency.len() != 3
            || !currency
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            return Err(MarketError::field_invalid(
                "currency must be a three-letter uppercase ISO-style code",
            ));
        }
        Ok(())
    }

    /// The query with identity fields trimmed and case-normalized.
    #[must_use]
    pub fn normalized(&self) -> Self {
        Self {
            provider_id: self.provider_id.trim().to_string(),
            jurisdiction: self.jurisdiction.trim().to_ascii_lowercase(),
            coverage_class: self.coverage_class,
            currency: self.currency.trim().to_ascii_uppercase(),
        }
    }
}

/// The resolved provider, the exact policy that matched, and its
/// support boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderResolutionReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: LiabilityProviderResolutionQuery,
    pub provider: SignedLiabilityProvider,
    pub matched_policy: LiabilityJurisdictionPolicy,
    pub support_boundary: LiabilityProviderSupportBoundary,
}
