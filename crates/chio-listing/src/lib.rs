pub use chio_core_types::capability::MonetaryAmount;
pub use chio_core_types::{canonical_json_bytes, crypto, receipt};

pub mod discovery;
pub use discovery::{
    compare, provider_signing_key, resolve_admissible_listing, search, Listing, ListingComparison,
    ListingComparisonRow, ListingPricingHint, ListingQuery, ListingSearchResponse, ListingSla,
    SignedListingPricingHint, LISTING_COMPARISON_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    LISTING_SEARCH_SCHEMA, MAX_MARKETPLACE_SEARCH_LIMIT,
};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::{sha256_hex, PublicKey};
use crate::receipt::SignedExportEnvelope;

pub const GENERIC_NAMESPACE_ARTIFACT_SCHEMA: &str = "chio.registry.namespace.v1";
pub const GENERIC_LISTING_ARTIFACT_SCHEMA: &str = "chio.registry.listing.v1";
pub const GENERIC_LISTING_REPORT_SCHEMA: &str = "chio.registry.listing-report.v1";
pub const GENERIC_LISTING_NETWORK_SEARCH_SCHEMA: &str = "chio.registry.search.v1";
pub const GENERIC_TRUST_ACTIVATION_ARTIFACT_SCHEMA: &str = "chio.registry.trust-activation.v1";
pub const GENERIC_LISTING_SEARCH_ALGORITHM_V1: &str = "freshness-status-kind-actor-published-at-v1";
pub const MAX_GENERIC_LISTING_LIMIT: usize = 200;
pub const DEFAULT_GENERIC_LISTING_REPORT_MAX_AGE_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GenericListingActorKind {
    ToolServer,
    CredentialIssuer,
    CredentialVerifier,
    LiabilityProvider,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GenericListingStatus {
    Active,
    Suspended,
    Superseded,
    Revoked,
    Retired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericNamespaceLifecycleState {
    Active,
    Transferred,
    Retired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GenericRegistryPublisherRole {
    Origin,
    Mirror,
    Indexer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericListingFreshnessState {
    Fresh,
    Stale,
    Divergent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingBoundary {
    pub visibility_only: bool,
    pub explicit_trust_activation_required: bool,
    pub automatic_trust_admission: bool,
}

impl Default for GenericListingBoundary {
    fn default() -> Self {
        Self {
            visibility_only: true,
            explicit_trust_activation_required: true,
            automatic_trust_admission: false,
        }
    }
}

impl GenericListingBoundary {
    pub fn validate(&self) -> Result<(), String> {
        if !self.visibility_only {
            return Err("generic listings must remain visibility-only".to_string());
        }
        if !self.explicit_trust_activation_required {
            return Err(
                "generic listings must require explicit trust activation outside the listing surface"
                    .to_string(),
            );
        }
        if self.automatic_trust_admission {
            return Err("generic listings must not auto-admit trust".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericNamespaceOwnership {
    pub namespace: String,
    pub owner_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
    pub registry_url: String,
    pub signer_public_key: PublicKey,
    pub registered_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transferred_from_owner_id: Option<String>,
}

impl GenericNamespaceOwnership {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.namespace, "namespace")?;
        validate_non_empty(&self.owner_id, "owner_id")?;
        validate_http_url(&self.registry_url, "registry_url")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericRegistryPublisher {
    pub role: GenericRegistryPublisherRole,
    pub operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    pub registry_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream_registry_urls: Vec<String>,
}

impl GenericRegistryPublisher {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.operator_id, "publisher.operator_id")?;
        validate_http_url(&self.registry_url, "publisher.registry_url")?;
        for (index, upstream) in self.upstream_registry_urls.iter().enumerate() {
            validate_http_url(
                upstream,
                &format!("publisher.upstream_registry_urls[{index}]"),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericNamespaceArtifact {
    pub schema: String,
    pub namespace_id: String,
    pub lifecycle_state: GenericNamespaceLifecycleState,
    pub ownership: GenericNamespaceOwnership,
    pub boundary: GenericListingBoundary,
}

impl GenericNamespaceArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != GENERIC_NAMESPACE_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported generic namespace schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.namespace_id, "namespace_id")?;
        self.ownership.validate()?;
        self.boundary.validate()?;
        Ok(())
    }
}

pub type SignedGenericNamespace = SignedExportEnvelope<GenericNamespaceArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingCompatibilityReference {
    pub source_schema: String,
    pub source_artifact_id: String,
    pub source_artifact_sha256: String,
}

impl GenericListingCompatibilityReference {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.source_schema, "compatibility.source_schema")?;
        validate_non_empty(&self.source_artifact_id, "compatibility.source_artifact_id")?;
        validate_non_empty(
            &self.source_artifact_sha256,
            "compatibility.source_artifact_sha256",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingSubject {
    pub actor_kind: GenericListingActorKind,
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
}

impl GenericListingSubject {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.actor_id, "subject.actor_id")?;
        validate_optional_http_url(self.metadata_url.as_deref(), "subject.metadata_url")?;
        validate_optional_http_url(self.resolution_url.as_deref(), "subject.resolution_url")?;
        validate_optional_http_url(self.homepage_url.as_deref(), "subject.homepage_url")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingArtifact {
    pub schema: String,
    pub listing_id: String,
    pub namespace: String,
    pub published_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub status: GenericListingStatus,
    pub namespace_ownership: GenericNamespaceOwnership,
    pub subject: GenericListingSubject,
    pub compatibility: GenericListingCompatibilityReference,
    pub boundary: GenericListingBoundary,
}

impl GenericListingArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != GENERIC_LISTING_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported generic listing schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.listing_id, "listing_id")?;
        validate_non_empty(&self.namespace, "namespace")?;
        if self.namespace.trim_end_matches('/')
            != self.namespace_ownership.namespace.trim_end_matches('/')
        {
            return Err(format!(
                "listing namespace `{}` does not match namespace ownership `{}`",
                self.namespace, self.namespace_ownership.namespace
            ));
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.published_at {
                return Err("generic listing expiry must be greater than published_at".to_string());
            }
        }
        self.namespace_ownership.validate()?;
        self.subject.validate()?;
        self.compatibility.validate()?;
        self.boundary.validate()?;
        Ok(())
    }
}

pub type SignedGenericListing = SignedExportEnvelope<GenericListingArtifact>;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<GenericListingActorKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<GenericListingStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl GenericListingQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(100)
            .clamp(1, MAX_GENERIC_LISTING_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized.namespace = normalized
            .namespace
            .as_deref()
            .map(normalize_namespace)
            .filter(|value| !value.is_empty());
        normalized.actor_id = normalized
            .actor_id
            .as_deref()
            .map(str::trim)
            .map(str::to_string)
            .filter(|value| !value.is_empty());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingSummary {
    pub matching_listings: u64,
    pub returned_listings: u64,
    pub active_listings: u64,
    pub suspended_listings: u64,
    pub superseded_listings: u64,
    pub revoked_listings: u64,
    pub retired_listings: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: GenericListingQuery,
    pub namespace: GenericNamespaceOwnership,
    pub publisher: GenericRegistryPublisher,
    pub freshness: GenericListingFreshnessWindow,
    pub search_policy: GenericListingSearchPolicy,
    pub summary: GenericListingSummary,
    pub listings: Vec<SignedGenericListing>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingFreshnessWindow {
    pub max_age_secs: u64,
    pub valid_until: u64,
}

impl GenericListingFreshnessWindow {
    pub fn validate(&self, generated_at: u64) -> Result<(), String> {
        if self.max_age_secs == 0 {
            return Err("freshness.max_age_secs must be greater than zero".to_string());
        }
        if self.valid_until <= generated_at {
            return Err("freshness.valid_until must be greater than generated_at".to_string());
        }
        Ok(())
    }

    #[must_use]
    pub fn assess(&self, generated_at: u64, now: u64) -> GenericListingReplicaFreshness {
        let age_secs = now.saturating_sub(generated_at);
        let state = if age_secs > self.max_age_secs || now > self.valid_until {
            GenericListingFreshnessState::Stale
        } else {
            GenericListingFreshnessState::Fresh
        };
        GenericListingReplicaFreshness {
            state,
            age_secs,
            max_age_secs: self.max_age_secs,
            valid_until: self.valid_until,
            generated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingSearchPolicy {
    pub algorithm: String,
    pub reproducible_ordering: bool,
    pub freshness_affects_ranking: bool,
    pub visibility_only: bool,
    pub explicit_trust_activation_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranking_inputs: Vec<String>,
}

impl Default for GenericListingSearchPolicy {
    fn default() -> Self {
        Self {
            algorithm: GENERIC_LISTING_SEARCH_ALGORITHM_V1.to_string(),
            reproducible_ordering: true,
            freshness_affects_ranking: true,
            visibility_only: true,
            explicit_trust_activation_required: true,
            ranking_inputs: vec![
                "freshness".to_string(),
                "status".to_string(),
                "actor_kind".to_string(),
                "actor_id".to_string(),
                "published_at_desc".to_string(),
                "publisher_role".to_string(),
                "listing_id".to_string(),
            ],
        }
    }
}

impl GenericListingSearchPolicy {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty(&self.algorithm, "search_policy.algorithm")?;
        if !self.reproducible_ordering {
            return Err("generic listing search must remain reproducible".to_string());
        }
        if !self.visibility_only {
            return Err("generic listing search must remain visibility-only".to_string());
        }
        if !self.explicit_trust_activation_required {
            return Err(
                "generic listing search must require explicit trust activation outside search"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingReplicaFreshness {
    pub state: GenericListingFreshnessState,
    pub age_secs: u64,
    pub max_age_secs: u64,
    pub valid_until: u64,
    pub generated_at: u64,
}

impl GenericListingReplicaFreshness {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_age_secs == 0 {
            return Err("freshness.max_age_secs must be greater than zero".to_string());
        }
        if self.valid_until <= self.generated_at {
            return Err("freshness.valid_until must be greater than generated_at".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingSearchResult {
    pub rank: u64,
    pub listing: SignedGenericListing,
    pub publisher: GenericRegistryPublisher,
    pub freshness: GenericListingReplicaFreshness,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replica_operator_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingSearchError {
    pub operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,
    pub registry_url: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingDivergence {
    pub divergence_key: String,
    pub actor_id: String,
    pub actor_kind: GenericListingActorKind,
    pub publisher_operator_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericListingSearchResponse {
    pub schema: String,
    pub generated_at: u64,
    pub query: GenericListingQuery,
    pub search_policy: GenericListingSearchPolicy,
    pub peer_count: u64,
    pub reachable_count: u64,
    pub stale_peer_count: u64,
    pub divergence_count: u64,
    pub result_count: u64,
    pub results: Vec<GenericListingSearchResult>,
    pub divergences: Vec<GenericListingDivergence>,
    pub errors: Vec<GenericListingSearchError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GenericTrustAdmissionClass {
    PublicUntrusted,
    Reviewable,
    BondBacked,
    RoleGated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericTrustActivationDisposition {
    PendingReview,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GenericTrustActivationFindingCode {
    MissingActivation,
    ListingUnverifiable,
    ActivationUnverifiable,
    ListingMismatch,
    ListingStale,
    ListingDivergent,
    ActivationExpired,
    ActivationPendingReview,
    ActivationDenied,
    AdmissionClassUntrusted,
    ActorKindIneligible,
    PublisherRoleIneligible,
    ListingStatusIneligible,
    ListingOperatorIneligible,
    BondBackingRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationEligibility {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_actor_kinds: Vec<GenericListingActorKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_publisher_roles: Vec<GenericRegistryPublisherRole>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_statuses: Vec<GenericListingStatus>,
    #[serde(default)]
    pub require_fresh_listing: bool,
    #[serde(default)]
    pub require_bond_backing: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_listing_operator_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_reference: Option<String>,
}

impl GenericTrustActivationEligibility {
    pub fn validate(&self, admission_class: GenericTrustAdmissionClass) -> Result<(), String> {
        for (index, operator_id) in self.required_listing_operator_ids.iter().enumerate() {
            validate_non_empty(
                operator_id,
                &format!("eligibility.required_listing_operator_ids[{index}]"),
            )?;
        }
        if matches!(admission_class, GenericTrustAdmissionClass::RoleGated)
            && self.required_listing_operator_ids.is_empty()
        {
            return Err(
                "role_gated trust activation requires required_listing_operator_ids".to_string(),
            );
        }
        if matches!(admission_class, GenericTrustAdmissionClass::BondBacked)
            && !self.require_bond_backing
        {
            return Err("bond_backed trust activation must require bond backing".to_string());
        }
        if !matches!(admission_class, GenericTrustAdmissionClass::BondBacked)
            && self.require_bond_backing
        {
            return Err(
                "require_bond_backing is only valid for bond_backed trust activation".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationReviewContext {
    pub publisher: GenericRegistryPublisher,
    pub freshness: GenericListingReplicaFreshness,
}

impl GenericTrustActivationReviewContext {
    pub fn validate(&self) -> Result<(), String> {
        self.publisher.validate()?;
        self.freshness.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationArtifact {
    pub schema: String,
    pub activation_id: String,
    pub local_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_operator_name: Option<String>,
    pub listing_id: String,
    pub namespace: String,
    pub listing_sha256: String,
    pub listing_published_at: u64,
    pub admission_class: GenericTrustAdmissionClass,
    pub disposition: GenericTrustActivationDisposition,
    pub eligibility: GenericTrustActivationEligibility,
    pub review_context: GenericTrustActivationReviewContext,
    pub requested_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub requested_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GenericTrustActivationArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != GENERIC_TRUST_ACTIVATION_ARTIFACT_SCHEMA {
            return Err(format!(
                "unsupported generic trust activation schema: {}",
                self.schema
            ));
        }
        validate_non_empty(&self.activation_id, "activation_id")?;
        validate_non_empty(&self.local_operator_id, "local_operator_id")?;
        validate_non_empty(&self.listing_id, "listing_id")?;
        validate_non_empty(&self.namespace, "namespace")?;
        validate_non_empty(&self.listing_sha256, "listing_sha256")?;
        validate_non_empty(&self.requested_by, "requested_by")?;
        self.eligibility.validate(self.admission_class)?;
        self.review_context.validate()?;
        if let Some(reviewed_at) = self.reviewed_at {
            if reviewed_at < self.requested_at {
                return Err("reviewed_at must be greater than or equal to requested_at".to_string());
            }
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.requested_at {
                return Err("expires_at must be greater than requested_at".to_string());
            }
        }
        match self.disposition {
            GenericTrustActivationDisposition::PendingReview => {
                if self.reviewed_at.is_some() || self.reviewed_by.is_some() {
                    return Err(
                        "pending_review trust activation must not carry review completion fields"
                            .to_string(),
                    );
                }
            }
            GenericTrustActivationDisposition::Approved
            | GenericTrustActivationDisposition::Denied => {
                if self.reviewed_at.is_none() || self.reviewed_by.as_deref().is_none() {
                    return Err(
                        "approved or denied trust activation requires reviewed_at and reviewed_by"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub type SignedGenericTrustActivation = SignedExportEnvelope<GenericTrustActivationArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationIssueRequest {
    pub listing: SignedGenericListing,
    pub admission_class: GenericTrustAdmissionClass,
    pub disposition: GenericTrustActivationDisposition,
    pub eligibility: GenericTrustActivationEligibility,
    pub review_context: GenericTrustActivationReviewContext,
    pub requested_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl GenericTrustActivationIssueRequest {
    pub fn validate(&self) -> Result<(), String> {
        ensure_generic_listing_signed_by_namespace_owner(
            &self.listing,
            "trust activation listing",
        )?;
        self.review_context.validate()?;
        self.eligibility.validate(self.admission_class)?;
        validate_non_empty(&self.requested_by, "requested_by")?;
        if matches!(
            self.disposition,
            GenericTrustActivationDisposition::Approved
        ) && self.review_context.freshness.state != GenericListingFreshnessState::Fresh
        {
            return Err(
                "approved trust activation requires fresh listing review context".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationEvaluationRequest {
    pub listing: SignedGenericListing,
    pub current_publisher: GenericRegistryPublisher,
    pub current_freshness: GenericListingReplicaFreshness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<SignedGenericTrustActivation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<u64>,
}

impl GenericTrustActivationEvaluationRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.listing.body.validate()?;
        self.current_publisher.validate()?;
        self.current_freshness.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationFinding {
    pub code: GenericTrustActivationFindingCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenericTrustActivationEvaluation {
    pub listing_id: String,
    pub namespace: String,
    pub evaluated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_class: Option<GenericTrustAdmissionClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<GenericTrustActivationDisposition>,
    pub admitted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<GenericTrustActivationFinding>,
}

pub fn build_generic_trust_activation_artifact(
    local_operator_id: &str,
    local_operator_name: Option<String>,
    request: &GenericTrustActivationIssueRequest,
    issued_at: u64,
) -> Result<GenericTrustActivationArtifact, String> {
    request.validate()?;
    validate_non_empty(local_operator_id, "local_operator_id")?;
    let requested_at = request.requested_at.unwrap_or(issued_at);
    let reviewed_at = request.reviewed_at.or(match request.disposition {
        GenericTrustActivationDisposition::PendingReview => None,
        GenericTrustActivationDisposition::Approved | GenericTrustActivationDisposition::Denied => {
            Some(issued_at)
        }
    });
    let listing_sha256 = generic_listing_body_sha256(&request.listing)?;
    let activation_id = format!(
        "activation-{}",
        sha256_hex(
            &canonical_json_bytes(&(
                local_operator_id,
                &request.listing.body.listing_id,
                &listing_sha256,
                request.admission_class,
                request.disposition,
                requested_at,
            ))
            .map_err(|error| error.to_string())?
        )
    );
    let artifact = GenericTrustActivationArtifact {
        schema: GENERIC_TRUST_ACTIVATION_ARTIFACT_SCHEMA.to_string(),
        activation_id,
        local_operator_id: local_operator_id.to_string(),
        local_operator_name,
        listing_id: request.listing.body.listing_id.clone(),
        namespace: request.listing.body.namespace.clone(),
        listing_sha256,
        listing_published_at: request.listing.body.published_at,
        admission_class: request.admission_class,
        disposition: request.disposition,
        eligibility: request.eligibility.clone(),
        review_context: request.review_context.clone(),
        requested_at,
        reviewed_at,
        expires_at: request.expires_at,
        requested_by: request.requested_by.clone(),
        reviewed_by: request.reviewed_by.clone(),
        note: request.note.clone(),
    };
    artifact.validate()?;
    Ok(artifact)
}

pub fn evaluate_generic_trust_activation(
    request: &GenericTrustActivationEvaluationRequest,
    now: u64,
    trusted_local_operator_signer: &PublicKey,
) -> Result<GenericTrustActivationEvaluation, String> {
    request.validate()?;
    let mut evaluation = GenericTrustActivationEvaluation {
        listing_id: request.listing.body.listing_id.clone(),
        namespace: request.listing.body.namespace.clone(),
        evaluated_at: request.evaluated_at.unwrap_or(now),
        local_operator_id: None,
        admission_class: None,
        disposition: None,
        admitted: false,
        findings: Vec::new(),
    };

    if let Err(error) = ensure_generic_listing_signed_by_namespace_owner(
        &request.listing,
        "trust activation listing",
    ) {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingUnverifiable,
            message: error,
        });
        return Ok(evaluation);
    }

    let Some(activation) = request.activation.as_ref() else {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::MissingActivation,
            message: "listing visibility requires an explicit local trust activation artifact"
                .to_string(),
        });
        return Ok(evaluation);
    };

    if !activation
        .verify_signature()
        .map_err(|error| error.to_string())?
        || activation.signer_key != *trusted_local_operator_signer
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActivationUnverifiable,
            message: "trust activation signature is invalid".to_string(),
        });
        return Ok(evaluation);
    }

    if let Err(error) = activation.body.validate() {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActivationUnverifiable,
            message: error,
        });
        return Ok(evaluation);
    }

    evaluation.local_operator_id = Some(activation.body.local_operator_id.clone());
    evaluation.admission_class = Some(activation.body.admission_class);
    evaluation.disposition = Some(activation.body.disposition);

    let listing_sha256 = generic_listing_body_sha256(&request.listing)?;
    if activation.body.listing_id != request.listing.body.listing_id
        || normalize_namespace(&activation.body.namespace)
            != normalize_namespace(&request.listing.body.namespace)
        || activation.body.listing_sha256 != listing_sha256
        || activation.body.listing_published_at != request.listing.body.published_at
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingMismatch,
            message:
                "trust activation does not match the current listing identity, namespace, or body hash"
                    .to_string(),
        });
        return Ok(evaluation);
    }

    match request.current_freshness.state {
        GenericListingFreshnessState::Stale => {
            evaluation.findings.push(GenericTrustActivationFinding {
                code: GenericTrustActivationFindingCode::ListingStale,
                message:
                    "current listing report is stale and cannot be activated for runtime trust"
                        .to_string(),
            });
            return Ok(evaluation);
        }
        GenericListingFreshnessState::Divergent => {
            evaluation.findings.push(GenericTrustActivationFinding {
                code: GenericTrustActivationFindingCode::ListingDivergent,
                message:
                    "current listing report is divergent and cannot be activated for runtime trust"
                        .to_string(),
            });
            return Ok(evaluation);
        }
        GenericListingFreshnessState::Fresh => {}
    }

    if activation
        .body
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluation.evaluated_at)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActivationExpired,
            message: "trust activation has expired".to_string(),
        });
        return Ok(evaluation);
    }

    match activation.body.disposition {
        GenericTrustActivationDisposition::PendingReview => {
            evaluation.findings.push(GenericTrustActivationFinding {
                code: GenericTrustActivationFindingCode::ActivationPendingReview,
                message: "trust activation remains pending review".to_string(),
            });
            return Ok(evaluation);
        }
        GenericTrustActivationDisposition::Denied => {
            evaluation.findings.push(GenericTrustActivationFinding {
                code: GenericTrustActivationFindingCode::ActivationDenied,
                message: "trust activation was explicitly denied".to_string(),
            });
            return Ok(evaluation);
        }
        GenericTrustActivationDisposition::Approved => {}
    }

    if activation.body.eligibility.require_fresh_listing
        && request.current_freshness.state != GenericListingFreshnessState::Fresh
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingStale,
            message: "trust activation requires fresh listing evidence".to_string(),
        });
        return Ok(evaluation);
    }

    if !activation.body.eligibility.allowed_actor_kinds.is_empty()
        && !activation
            .body
            .eligibility
            .allowed_actor_kinds
            .contains(&request.listing.body.subject.actor_kind)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ActorKindIneligible,
            message: "listing actor kind is not eligible under the activation policy".to_string(),
        });
        return Ok(evaluation);
    }

    if !activation
        .body
        .eligibility
        .allowed_publisher_roles
        .is_empty()
        && !activation
            .body
            .eligibility
            .allowed_publisher_roles
            .contains(&request.current_publisher.role)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::PublisherRoleIneligible,
            message: "listing publisher role is not eligible under the activation policy"
                .to_string(),
        });
        return Ok(evaluation);
    }

    if !activation.body.eligibility.allowed_statuses.is_empty()
        && !activation
            .body
            .eligibility
            .allowed_statuses
            .contains(&request.listing.body.status)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingStatusIneligible,
            message: "listing lifecycle status is not eligible under the activation policy"
                .to_string(),
        });
        return Ok(evaluation);
    }

    if !activation
        .body
        .eligibility
        .required_listing_operator_ids
        .is_empty()
        && !activation
            .body
            .eligibility
            .required_listing_operator_ids
            .contains(&request.current_publisher.operator_id)
    {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::ListingOperatorIneligible,
            message: "listing operator is not eligible under the activation policy".to_string(),
        });
        return Ok(evaluation);
    }

    if matches!(
        activation.body.admission_class,
        GenericTrustAdmissionClass::PublicUntrusted
    ) {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::AdmissionClassUntrusted,
            message: "public_untrusted admission class preserves visibility without runtime trust"
                .to_string(),
        });
        return Ok(evaluation);
    }

    if activation.body.eligibility.require_bond_backing {
        evaluation.findings.push(GenericTrustActivationFinding {
            code: GenericTrustActivationFindingCode::BondBackingRequired,
            message:
                "bond_backed activation remains review-visible only until bond backing is proven"
                    .to_string(),
        });
        return Ok(evaluation);
    }

    evaluation.admitted = true;
    Ok(evaluation)
}

pub fn normalize_namespace(namespace: &str) -> String {
    namespace.trim().trim_end_matches('/').to_string()
}

fn generic_listing_body_sha256(listing: &SignedGenericListing) -> Result<String, String> {
    Ok(sha256_hex(
        &canonical_json_bytes(&listing.body).map_err(|error| error.to_string())?,
    ))
}

pub fn ensure_generic_listing_signed_by_namespace_owner(
    listing: &SignedGenericListing,
    label: &str,
) -> Result<(), String> {
    listing.body.validate()?;
    if !listing
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err(format!("{label} signature is invalid"));
    }
    if listing.signer_key != listing.body.namespace_ownership.signer_public_key {
        return Err(format!(
            "{label} signer does not match the declared namespace ownership signer"
        ));
    }
    Ok(())
}

pub fn ensure_generic_listing_namespace_consistency<'a>(
    listings: impl IntoIterator<Item = &'a GenericListingArtifact>,
) -> Result<(), String> {
    let mut namespaces = BTreeMap::<String, GenericNamespaceOwnership>::new();
    for listing in listings {
        let namespace = normalize_namespace(&listing.namespace);
        if namespace.is_empty() {
            return Err("generic listing namespace must not be empty".to_string());
        }
        let ownership = listing.namespace_ownership.clone();
        if let Some(existing) = namespaces.get(&namespace) {
            if existing.owner_id != ownership.owner_id
                || existing.registry_url != ownership.registry_url
                || existing.signer_public_key != ownership.signer_public_key
            {
                return Err(format!(
                    "generic listing namespace `{namespace}` has conflicting ownership claims"
                ));
            }
        } else {
            namespaces.insert(namespace, ownership);
        }
    }
    Ok(())
}

pub fn aggregate_generic_listing_reports(
    reports: &[GenericListingReport],
    query: &GenericListingQuery,
    now: u64,
) -> GenericListingSearchResponse {
    let normalized_query = query.normalized();
    let mut reachable_count = 0_u64;
    let mut stale_peer_count = 0_u64;
    let mut errors = Vec::<GenericListingSearchError>::new();
    let mut candidates = Vec::<(
        SignedGenericListing,
        GenericRegistryPublisher,
        GenericListingReplicaFreshness,
    )>::new();

    for report in reports {
        if let Err(error) = validate_generic_listing_report(report) {
            errors.push(GenericListingSearchError {
                operator_id: report.publisher.operator_id.clone(),
                operator_name: report.publisher.operator_name.clone(),
                registry_url: report.publisher.registry_url.clone(),
                error,
            });
            continue;
        }

        let freshness = report.freshness.assess(report.generated_at, now);
        if freshness.state == GenericListingFreshnessState::Stale {
            stale_peer_count += 1;
            errors.push(GenericListingSearchError {
                operator_id: report.publisher.operator_id.clone(),
                operator_name: report.publisher.operator_name.clone(),
                registry_url: report.publisher.registry_url.clone(),
                error: format!(
                    "generic registry report is stale: age {}s exceeds max {}s",
                    freshness.age_secs, freshness.max_age_secs
                ),
            });
            continue;
        }

        reachable_count += 1;
        for listing in &report.listings {
            if normalized_query
                .namespace
                .as_deref()
                .is_some_and(|namespace| normalize_namespace(&listing.body.namespace) != namespace)
            {
                continue;
            }
            if normalized_query
                .actor_kind
                .is_some_and(|actor_kind| listing.body.subject.actor_kind != actor_kind)
            {
                continue;
            }
            if normalized_query
                .actor_id
                .as_deref()
                .is_some_and(|actor_id| listing.body.subject.actor_id != actor_id)
            {
                continue;
            }
            if normalized_query
                .status
                .is_some_and(|status| listing.body.status != status)
            {
                continue;
            }
            candidates.push((listing.clone(), report.publisher.clone(), freshness.clone()));
        }
    }

    let mut groups = BTreeMap::<
        String,
        Vec<(
            SignedGenericListing,
            GenericRegistryPublisher,
            GenericListingReplicaFreshness,
        )>,
    >::new();
    for candidate in candidates {
        let divergence_key = generic_listing_divergence_key(&candidate.0.body);
        groups.entry(divergence_key).or_default().push(candidate);
    }

    let mut divergences = Vec::<GenericListingDivergence>::new();
    let mut results = Vec::<GenericListingSearchResult>::new();

    for (divergence_key, mut group) in groups {
        let first = &group[0].0.body;
        let canonical_fingerprint = (
            first.compatibility.source_artifact_sha256.clone(),
            first.status,
            first.namespace_ownership.owner_id.clone(),
            first.namespace_ownership.registry_url.clone(),
        );
        let is_divergent = group.iter().skip(1).any(|(listing, _, _)| {
            (
                listing.body.compatibility.source_artifact_sha256.clone(),
                listing.body.status,
                listing.body.namespace_ownership.owner_id.clone(),
                listing.body.namespace_ownership.registry_url.clone(),
            ) != canonical_fingerprint
        });
        if is_divergent {
            divergences.push(GenericListingDivergence {
                divergence_key,
                actor_id: first.subject.actor_id.clone(),
                actor_kind: first.subject.actor_kind,
                publisher_operator_ids: group
                    .iter()
                    .map(|(_, publisher, _)| publisher.operator_id.clone())
                    .collect(),
                reason:
                    "conflicting source artifact, lifecycle state, or namespace ownership across publishers"
                        .to_string(),
            });
            continue;
        }

        group.sort_by(|left, right| {
            freshness_state_rank(&left.2.state)
                .cmp(&freshness_state_rank(&right.2.state))
                .then(publisher_role_rank(left.1.role).cmp(&publisher_role_rank(right.1.role)))
                .then(left.2.age_secs.cmp(&right.2.age_secs))
                .then((u64::MAX - left.2.generated_at).cmp(&(u64::MAX - right.2.generated_at)))
                .then(status_rank(left.0.body.status).cmp(&status_rank(right.0.body.status)))
                .then(
                    left.0
                        .body
                        .subject
                        .actor_kind
                        .cmp(&right.0.body.subject.actor_kind),
                )
                .then(
                    left.0
                        .body
                        .subject
                        .actor_id
                        .cmp(&right.0.body.subject.actor_id),
                )
                .then(right.0.body.published_at.cmp(&left.0.body.published_at))
                .then(left.1.operator_id.cmp(&right.1.operator_id))
                .then(left.0.body.listing_id.cmp(&right.0.body.listing_id))
        });

        let (listing, publisher, freshness) = group.remove(0);
        results.push(GenericListingSearchResult {
            rank: 0,
            listing,
            publisher,
            freshness,
            replica_operator_ids: group
                .iter()
                .map(|(_, publisher, _)| publisher.operator_id.clone())
                .collect(),
        });
    }

    results.sort_by(|left, right| {
        freshness_state_rank(&left.freshness.state)
            .cmp(&freshness_state_rank(&right.freshness.state))
            .then(
                publisher_role_rank(left.publisher.role)
                    .cmp(&publisher_role_rank(right.publisher.role)),
            )
            .then(left.freshness.age_secs.cmp(&right.freshness.age_secs))
            .then(
                (u64::MAX - left.freshness.generated_at)
                    .cmp(&(u64::MAX - right.freshness.generated_at)),
            )
            .then(
                status_rank(left.listing.body.status).cmp(&status_rank(right.listing.body.status)),
            )
            .then(
                left.listing
                    .body
                    .subject
                    .actor_kind
                    .cmp(&right.listing.body.subject.actor_kind),
            )
            .then(
                left.listing
                    .body
                    .subject
                    .actor_id
                    .cmp(&right.listing.body.subject.actor_id),
            )
            .then(
                right
                    .listing
                    .body
                    .published_at
                    .cmp(&left.listing.body.published_at),
            )
            .then(left.publisher.operator_id.cmp(&right.publisher.operator_id))
            .then(
                left.listing
                    .body
                    .listing_id
                    .cmp(&right.listing.body.listing_id),
            )
    });

    for (index, result) in results.iter_mut().enumerate() {
        result.rank = (index + 1) as u64;
    }
    results.truncate(normalized_query.limit_or_default());

    GenericListingSearchResponse {
        schema: GENERIC_LISTING_NETWORK_SEARCH_SCHEMA.to_string(),
        generated_at: now,
        query: normalized_query,
        search_policy: GenericListingSearchPolicy::default(),
        peer_count: reports.len() as u64,
        reachable_count,
        stale_peer_count,
        divergence_count: divergences.len() as u64,
        result_count: results.len() as u64,
        results,
        divergences,
        errors,
    }
}

fn validate_generic_listing_report(report: &GenericListingReport) -> Result<(), String> {
    if report.schema != GENERIC_LISTING_REPORT_SCHEMA {
        return Err(format!(
            "unsupported generic listing report schema: {}",
            report.schema
        ));
    }
    report.namespace.validate()?;
    report.publisher.validate()?;
    report.freshness.validate(report.generated_at)?;
    report.search_policy.validate()?;
    ensure_generic_listing_namespace_consistency(
        report.listings.iter().map(|listing| &listing.body),
    )?;
    for listing in &report.listings {
        listing.body.validate()?;
        if !listing
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Err(format!(
                "listing `{}` signature is invalid in generic registry report",
                listing.body.listing_id
            ));
        }
        if listing.signer_key != listing.body.namespace_ownership.signer_public_key {
            return Err(format!(
                "listing `{}` signer does not match the declared namespace ownership signer",
                listing.body.listing_id
            ));
        }
        if normalize_namespace(&listing.body.namespace)
            != normalize_namespace(&report.namespace.namespace)
        {
            return Err(format!(
                "listing namespace `{}` falls outside report namespace `{}`",
                listing.body.namespace, report.namespace.namespace
            ));
        }
    }
    Ok(())
}

fn generic_listing_divergence_key(listing: &GenericListingArtifact) -> String {
    format!(
        "{:?}:{}:{}:{}",
        listing.subject.actor_kind,
        listing.subject.actor_id,
        listing.compatibility.source_schema,
        listing.compatibility.source_artifact_id
    )
}

fn publisher_role_rank(role: GenericRegistryPublisherRole) -> u8 {
    match role {
        GenericRegistryPublisherRole::Origin => 0,
        GenericRegistryPublisherRole::Mirror => 1,
        GenericRegistryPublisherRole::Indexer => 2,
    }
}

fn status_rank(status: GenericListingStatus) -> u8 {
    match status {
        GenericListingStatus::Active => 0,
        GenericListingStatus::Suspended => 1,
        GenericListingStatus::Superseded => 2,
        GenericListingStatus::Revoked => 3,
        GenericListingStatus::Retired => 4,
    }
}

fn freshness_state_rank(state: &GenericListingFreshnessState) -> u8 {
    match state {
        GenericListingFreshnessState::Fresh => 0,
        GenericListingFreshnessState::Stale => 1,
        GenericListingFreshnessState::Divergent => 2,
    }
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn validate_http_url(value: &str, field: &str) -> Result<(), String> {
    validate_non_empty(value, field)?;
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(format!("{field} must start with http:// or https://"));
    }
    Ok(())
}

fn validate_optional_http_url(value: Option<&str>, field: &str) -> Result<(), String> {
    if let Some(value) = value {
        validate_http_url(value, field)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn require_ok<T, E>(result: Result<T, E>, context: &'static str) -> T
    where
        E: std::fmt::Debug,
    {
        result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
    }

    fn require_err<T, E>(result: Result<T, E>, context: &'static str) -> E
    where
        T: std::fmt::Debug,
    {
        match result {
            Ok(value) => panic!("{context} unexpectedly succeeded: {value:?}"),
            Err(error) => error,
        }
    }

    fn sample_namespace(owner_id: &str, keypair: &Keypair) -> GenericNamespaceOwnership {
        GenericNamespaceOwnership {
            namespace: "https://registry.chio.example".to_string(),
            owner_id: owner_id.to_string(),
            owner_name: Some("Chio Registry".to_string()),
            registry_url: "https://registry.chio.example".to_string(),
            signer_public_key: keypair.public_key(),
            registered_at: 1,
            transferred_from_owner_id: None,
        }
    }

    fn sample_listing(
        owner_id: &str,
        keypair: &Keypair,
        artifact_id: &str,
        source_sha256: &str,
    ) -> GenericListingArtifact {
        GenericListingArtifact {
            schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
            listing_id: format!("listing-{artifact_id}"),
            namespace: "https://registry.chio.example".to_string(),
            published_at: 10,
            expires_at: Some(20),
            status: GenericListingStatus::Active,
            namespace_ownership: sample_namespace(owner_id, keypair),
            subject: GenericListingSubject {
                actor_kind: GenericListingActorKind::ToolServer,
                actor_id: "demo-server".to_string(),
                display_name: Some("Demo Server".to_string()),
                metadata_url: Some("https://registry.chio.example/metadata".to_string()),
                resolution_url: Some(
                    "https://registry.chio.example/v1/public/certifications/resolve/demo-server"
                        .to_string(),
                ),
                homepage_url: Some("https://demo.chio.example".to_string()),
            },
            compatibility: GenericListingCompatibilityReference {
                source_schema: "chio.certify.check.v1".to_string(),
                source_artifact_id: artifact_id.to_string(),
                source_artifact_sha256: source_sha256.to_string(),
            },
            boundary: GenericListingBoundary::default(),
        }
    }

    fn signed_sample_listing(
        owner_id: &str,
        signing_keypair: &Keypair,
        artifact_id: &str,
        source_sha256: &str,
    ) -> SignedGenericListing {
        require_ok(
            SignedGenericListing::sign(
                sample_listing(owner_id, signing_keypair, artifact_id, source_sha256),
                signing_keypair,
            ),
            "sign sample listing",
        )
    }

    fn sample_publisher(
        role: GenericRegistryPublisherRole,
        operator_id: &str,
    ) -> GenericRegistryPublisher {
        GenericRegistryPublisher {
            role,
            operator_id: operator_id.to_string(),
            operator_name: Some(format!("Operator {operator_id}")),
            registry_url: format!("https://{operator_id}.chio.example"),
            upstream_registry_urls: Vec::new(),
        }
    }

    fn sample_report(
        role: GenericRegistryPublisherRole,
        operator_id: &str,
        generated_at: u64,
        max_age_secs: u64,
        listings: Vec<SignedGenericListing>,
    ) -> GenericListingReport {
        let keypair = Keypair::generate();
        GenericListingReport {
            schema: GENERIC_LISTING_REPORT_SCHEMA.to_string(),
            generated_at,
            query: GenericListingQuery::default(),
            namespace: sample_namespace("https://registry.chio.example", &keypair),
            publisher: sample_publisher(role, operator_id),
            freshness: GenericListingFreshnessWindow {
                max_age_secs,
                valid_until: generated_at + max_age_secs,
            },
            search_policy: GenericListingSearchPolicy::default(),
            summary: GenericListingSummary {
                matching_listings: listings.len() as u64,
                returned_listings: listings.len() as u64,
                active_listings: listings.len() as u64,
                suspended_listings: 0,
                superseded_listings: 0,
                revoked_listings: 0,
                retired_listings: 0,
            },
            listings,
        }
    }

    fn sample_review_context(
        role: GenericRegistryPublisherRole,
        operator_id: &str,
        freshness_state: GenericListingFreshnessState,
    ) -> GenericTrustActivationReviewContext {
        GenericTrustActivationReviewContext {
            publisher: sample_publisher(role, operator_id),
            freshness: GenericListingReplicaFreshness {
                state: freshness_state,
                age_secs: 5,
                max_age_secs: 300,
                valid_until: 400,
                generated_at: 100,
            },
        }
    }

    fn sample_activation_issue_request(
        listing: SignedGenericListing,
        admission_class: GenericTrustAdmissionClass,
        disposition: GenericTrustActivationDisposition,
    ) -> GenericTrustActivationIssueRequest {
        GenericTrustActivationIssueRequest {
            listing,
            admission_class,
            disposition,
            eligibility: GenericTrustActivationEligibility {
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_publisher_roles: vec![GenericRegistryPublisherRole::Origin],
                allowed_statuses: vec![GenericListingStatus::Active],
                require_fresh_listing: true,
                require_bond_backing: false,
                required_listing_operator_ids: Vec::new(),
                policy_reference: Some("policy/open-registry/default".to_string()),
            },
            review_context: sample_review_context(
                GenericRegistryPublisherRole::Origin,
                "origin-a",
                GenericListingFreshnessState::Fresh,
            ),
            requested_by: "ops@chio.example".to_string(),
            reviewed_by: Some("reviewer@chio.example".to_string()),
            requested_at: Some(120),
            reviewed_at: Some(130),
            expires_at: Some(200),
            note: Some("reviewed under default local activation policy".to_string()),
        }
    }

    fn issue_request_for(
        listing: SignedGenericListing,
        admission_class: GenericTrustAdmissionClass,
        disposition: GenericTrustActivationDisposition,
    ) -> GenericTrustActivationIssueRequest {
        GenericTrustActivationIssueRequest {
            reviewed_by: match disposition {
                GenericTrustActivationDisposition::PendingReview => None,
                GenericTrustActivationDisposition::Approved
                | GenericTrustActivationDisposition::Denied => {
                    Some("reviewer@chio.example".to_string())
                }
            },
            reviewed_at: match disposition {
                GenericTrustActivationDisposition::PendingReview => None,
                GenericTrustActivationDisposition::Approved
                | GenericTrustActivationDisposition::Denied => Some(130),
            },
            ..sample_activation_issue_request(listing, admission_class, disposition)
        }
    }

    fn signed_activation(
        listing: SignedGenericListing,
        admission_class: GenericTrustAdmissionClass,
        disposition: GenericTrustActivationDisposition,
    ) -> SignedGenericTrustActivation {
        let authority_keypair = sample_authority_keypair();
        let artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(listing, admission_class, disposition),
                130,
            ),
            "build activation artifact",
        );
        require_ok(
            SignedGenericTrustActivation::sign(artifact, &authority_keypair),
            "sign activation",
        )
    }

    fn sample_authority_keypair() -> Keypair {
        Keypair::from_seed(&[42_u8; 32])
    }

    fn evaluation_request(
        listing: SignedGenericListing,
        activation: Option<SignedGenericTrustActivation>,
        freshness_state: GenericListingFreshnessState,
        publisher_role: GenericRegistryPublisherRole,
        publisher_operator_id: &str,
        evaluated_at: u64,
    ) -> GenericTrustActivationEvaluationRequest {
        GenericTrustActivationEvaluationRequest {
            listing,
            current_publisher: sample_publisher(publisher_role, publisher_operator_id),
            current_freshness: GenericListingReplicaFreshness {
                state: freshness_state,
                age_secs: 5,
                max_age_secs: 300,
                valid_until: 400,
                generated_at: 100,
            },
            activation,
            evaluated_at: Some(evaluated_at),
        }
    }

    #[test]
    fn generic_listing_boundary_rejects_automatic_trust_admission() {
        let boundary = GenericListingBoundary {
            visibility_only: true,
            explicit_trust_activation_required: true,
            automatic_trust_admission: true,
        };
        assert!(
            require_err(boundary.validate(), "automatic trust admission rejected")
                .contains("must not auto-admit trust")
        );
    }

    #[test]
    fn generic_listing_boundary_rejects_missing_explicit_activation_gate() {
        let boundary = GenericListingBoundary {
            visibility_only: true,
            explicit_trust_activation_required: false,
            automatic_trust_admission: false,
        };
        assert!(require_err(
            boundary.validate(),
            "missing explicit trust activation gate rejected",
        )
        .contains("must require explicit trust activation"));
    }

    #[test]
    fn generic_namespace_artifact_rejects_wrong_schema() {
        let keypair = Keypair::generate();
        let artifact = GenericNamespaceArtifact {
            schema: "chio.registry.namespace.v0".to_string(),
            namespace_id: "registry.chio.example".to_string(),
            lifecycle_state: GenericNamespaceLifecycleState::Active,
            ownership: sample_namespace("operator-a", &keypair),
            boundary: GenericListingBoundary::default(),
        };

        assert!(
            require_err(artifact.validate(), "wrong namespace schema rejected")
                .contains("unsupported generic namespace schema")
        );
    }

    #[test]
    fn generic_listing_rejects_namespace_mismatch() {
        let keypair = Keypair::generate();
        let mut listing = sample_listing("operator-a", &keypair, "artifact-1", "deadbeef");
        listing.namespace = "https://other.chio.example".to_string();
        assert!(
            require_err(listing.validate(), "namespace mismatch rejected")
                .contains("does not match namespace ownership")
        );
    }

    #[test]
    fn generic_listing_rejects_non_increasing_expiry() {
        let keypair = Keypair::generate();
        let mut listing = sample_listing("operator-a", &keypair, "artifact-1", "deadbeef");
        listing.expires_at = Some(listing.published_at);

        assert!(
            require_err(listing.validate(), "non-increasing expiry rejected")
                .contains("expiry must be greater")
        );
    }

    #[test]
    fn generic_listing_query_normalizes_namespace_actor_and_limit() {
        let normalized = GenericListingQuery {
            namespace: Some(" https://registry.chio.example/ ".to_string()),
            actor_kind: Some(GenericListingActorKind::ToolServer),
            actor_id: Some("   ".to_string()),
            status: Some(GenericListingStatus::Active),
            limit: Some(999),
        }
        .normalized();

        assert_eq!(
            normalized.namespace.as_deref(),
            Some("https://registry.chio.example")
        );
        assert_eq!(normalized.actor_id, None);
        assert_eq!(normalized.limit, Some(MAX_GENERIC_LISTING_LIMIT));
    }

    #[test]
    fn generic_listing_freshness_window_rejects_invalid_bounds_and_assesses_stale() {
        assert!(require_err(
            GenericListingFreshnessWindow {
                max_age_secs: 0,
                valid_until: 200,
            }
            .validate(100),
            "zero max age rejected",
        )
        .contains("greater than zero"));

        assert!(require_err(
            GenericListingFreshnessWindow {
                max_age_secs: 30,
                valid_until: 100,
            }
            .validate(100),
            "non-increasing valid_until rejected",
        )
        .contains("greater than generated_at"));

        let freshness = GenericListingFreshnessWindow {
            max_age_secs: 30,
            valid_until: 150,
        }
        .assess(100, 200);
        assert_eq!(freshness.state, GenericListingFreshnessState::Stale);
        assert_eq!(freshness.age_secs, 100);
    }

    #[test]
    fn generic_listing_search_policy_rejects_non_reproducible_modes() {
        let policy = GenericListingSearchPolicy {
            reproducible_ordering: false,
            ..GenericListingSearchPolicy::default()
        };
        assert!(
            require_err(policy.validate(), "non-reproducible policy rejected")
                .contains("must remain reproducible")
        );

        let policy = GenericListingSearchPolicy {
            visibility_only: false,
            ..GenericListingSearchPolicy::default()
        };
        assert!(
            require_err(policy.validate(), "non-visibility-only policy rejected")
                .contains("must remain visibility-only")
        );

        let policy = GenericListingSearchPolicy {
            explicit_trust_activation_required: false,
            ..GenericListingSearchPolicy::default()
        };
        assert!(require_err(
            policy.validate(),
            "missing explicit trust activation rejected",
        )
        .contains("must require explicit trust activation"));
    }

    #[test]
    fn generic_listing_replica_freshness_rejects_invalid_window() {
        let freshness = GenericListingReplicaFreshness {
            state: GenericListingFreshnessState::Fresh,
            age_secs: 5,
            max_age_secs: 0,
            valid_until: 100,
            generated_at: 100,
        };
        assert!(
            require_err(freshness.validate(), "invalid freshness rejected")
                .contains("greater than zero")
        );
    }

    #[test]
    fn generic_trust_activation_eligibility_rejects_invalid_role_and_bond_rules() {
        assert!(require_err(
            GenericTrustActivationEligibility {
                required_listing_operator_ids: vec![],
                ..GenericTrustActivationEligibility {
                    allowed_actor_kinds: vec![],
                    allowed_publisher_roles: vec![],
                    allowed_statuses: vec![],
                    require_fresh_listing: true,
                    require_bond_backing: false,
                    required_listing_operator_ids: vec![],
                    policy_reference: None,
                }
            }
            .validate(GenericTrustAdmissionClass::RoleGated),
            "role-gated operators required",
        )
        .contains("requires required_listing_operator_ids"));

        assert!(require_err(
            GenericTrustActivationEligibility {
                require_bond_backing: false,
                ..GenericTrustActivationEligibility {
                    allowed_actor_kinds: vec![],
                    allowed_publisher_roles: vec![],
                    allowed_statuses: vec![],
                    require_fresh_listing: true,
                    require_bond_backing: false,
                    required_listing_operator_ids: vec![],
                    policy_reference: None,
                }
            }
            .validate(GenericTrustAdmissionClass::BondBacked),
            "bond-backed admission must require bonds",
        )
        .contains("must require bond backing"));

        assert!(require_err(
            GenericTrustActivationEligibility {
                require_bond_backing: true,
                ..GenericTrustActivationEligibility {
                    allowed_actor_kinds: vec![],
                    allowed_publisher_roles: vec![],
                    allowed_statuses: vec![],
                    require_fresh_listing: true,
                    require_bond_backing: true,
                    required_listing_operator_ids: vec![],
                    policy_reference: None,
                }
            }
            .validate(GenericTrustAdmissionClass::Reviewable),
            "non-bond admission cannot require bonds",
        )
        .contains("only valid for bond_backed"));
    }

    #[test]
    fn generic_trust_activation_artifact_validate_rejects_review_field_misconfigurations() {
        let keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.reviewed_at = Some(100);
        assert!(require_err(
            artifact.validate(),
            "reviewed_at before requested_at rejected",
        )
        .contains("reviewed_at must be greater"));

        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.expires_at = Some(120);
        assert!(
            require_err(artifact.validate(), "expiry before requested_at rejected")
                .contains("expires_at must be greater")
        );

        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.disposition = GenericTrustActivationDisposition::PendingReview;
        artifact.reviewed_by = Some("reviewer@chio.example".to_string());
        artifact.reviewed_at = Some(130);
        assert!(require_err(
            artifact.validate(),
            "pending review cannot carry review completion",
        )
        .contains("must not carry review completion fields"));

        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing,
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.reviewed_by = None;
        assert!(
            require_err(artifact.validate(), "approved activation requires reviewer",)
                .contains("requires reviewed_at and reviewed_by")
        );
    }

    #[test]
    fn generic_trust_activation_issue_request_validate_rejects_stale_approved_context() {
        let signing_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut request = issue_request_for(
            listing,
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        request.review_context.freshness.state = GenericListingFreshnessState::Stale;

        assert!(require_err(
            request.validate(),
            "approved activation requires fresh context",
        )
        .contains("requires fresh listing review context"));
    }

    #[test]
    fn generic_trust_activation_issue_request_rejects_listing_signer_mismatch() {
        let namespace_keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();
        let listing = require_ok(
            SignedGenericListing::sign(
                sample_listing(
                    "https://registry.chio.example",
                    &namespace_keypair,
                    "artifact-1",
                    "deadbeef",
                ),
                &attacker_keypair,
            ),
            "sign listing with mismatched signer",
        );
        let request = issue_request_for(
            listing,
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );

        assert!(
            require_err(request.validate(), "listing signer mismatch rejected")
                .contains("namespace ownership signer")
        );
    }

    #[test]
    fn build_generic_trust_activation_artifact_defaults_reviewed_at_for_approved() {
        let signing_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut request = issue_request_for(
            listing,
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        request.reviewed_at = None;
        let artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &request,
                130,
            ),
            "build activation",
        );

        assert_eq!(artifact.reviewed_at, Some(130));
    }

    #[test]
    fn generic_listing_namespace_consistency_rejects_conflicting_owners() {
        let keypair_a = Keypair::generate();
        let keypair_b = Keypair::generate();
        let listing_a = sample_listing("operator-a", &keypair_a, "artifact-1", "deadbeef");
        let listing_b = sample_listing("operator-b", &keypair_b, "artifact-1", "deadbeef");
        assert!(require_err(
            ensure_generic_listing_namespace_consistency([&listing_a, &listing_b]),
            "conflicting namespace ownership rejected",
        )
        .contains("conflicting ownership"));
    }

    #[test]
    fn generic_listing_search_prefers_fresh_origin_and_collapses_identical_replicas() {
        let signing_keypair = Keypair::generate();
        let origin = sample_report(
            GenericRegistryPublisherRole::Origin,
            "origin-a",
            100,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );
        let mirror = sample_report(
            GenericRegistryPublisherRole::Mirror,
            "mirror-a",
            105,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );
        let indexer = sample_report(
            GenericRegistryPublisherRole::Indexer,
            "indexer-a",
            106,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );

        let response = aggregate_generic_listing_reports(
            &[origin, mirror, indexer],
            &GenericListingQuery::default(),
            120,
        );
        assert_eq!(response.peer_count, 3);
        assert_eq!(response.reachable_count, 3);
        assert_eq!(response.result_count, 1);
        assert_eq!(response.divergence_count, 0);
        assert_eq!(
            response.results[0].publisher.role,
            GenericRegistryPublisherRole::Origin
        );
        assert_eq!(response.results[0].replica_operator_ids.len(), 2);
    }

    #[test]
    fn generic_listing_search_rejects_stale_reports() {
        let signing_keypair = Keypair::generate();
        let stale = sample_report(
            GenericRegistryPublisherRole::Mirror,
            "mirror-a",
            100,
            10,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );

        let response =
            aggregate_generic_listing_reports(&[stale], &GenericListingQuery::default(), 200);
        assert_eq!(response.peer_count, 1);
        assert_eq!(response.reachable_count, 0);
        assert_eq!(response.stale_peer_count, 1);
        assert_eq!(response.result_count, 0);
        assert_eq!(response.errors.len(), 1);
        assert!(response.errors[0].error.contains("stale"));
    }

    #[test]
    fn generic_listing_search_excludes_divergent_results() {
        let signing_keypair = Keypair::generate();
        let origin = sample_report(
            GenericRegistryPublisherRole::Origin,
            "origin-a",
            100,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );
        let mirror = sample_report(
            GenericRegistryPublisherRole::Mirror,
            "mirror-a",
            101,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "cafebabe",
            )],
        );

        let response = aggregate_generic_listing_reports(
            &[origin, mirror],
            &GenericListingQuery::default(),
            120,
        );
        assert_eq!(response.result_count, 0);
        assert_eq!(response.divergence_count, 1);
        assert_eq!(response.divergences[0].publisher_operator_ids.len(), 2);
    }

    #[test]
    fn generic_listing_search_rejects_reports_with_invalid_listing_signatures() {
        let signing_keypair = Keypair::generate();
        let mut report = sample_report(
            GenericRegistryPublisherRole::Mirror,
            "mirror-a",
            100,
            300,
            vec![signed_sample_listing(
                "https://registry.chio.example",
                &signing_keypair,
                "artifact-1",
                "deadbeef",
            )],
        );
        report.listings[0].body.status = GenericListingStatus::Revoked;

        let response =
            aggregate_generic_listing_reports(&[report], &GenericListingQuery::default(), 120);
        assert_eq!(response.peer_count, 1);
        assert_eq!(response.reachable_count, 0);
        assert_eq!(response.result_count, 0);
        assert_eq!(response.errors.len(), 1);
        assert!(response.errors[0].error.contains("signature is invalid"));
    }

    #[test]
    fn generic_trust_activation_requires_explicit_artifact() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = sample_authority_keypair();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let report = require_ok(
            evaluate_generic_trust_activation(
                &GenericTrustActivationEvaluationRequest {
                    listing,
                    current_publisher: sample_publisher(
                        GenericRegistryPublisherRole::Origin,
                        "origin-a",
                    ),
                    current_freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 5,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                    activation: None,
                    evaluated_at: Some(150),
                },
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate missing activation",
        );
        assert!(!report.admitted);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::MissingActivation
        );
    }

    #[test]
    fn generic_trust_activation_admits_reviewable_activation() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let issue_request = sample_activation_issue_request(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        let activation_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request,
                130,
            ),
            "build activation artifact",
        );
        let activation = require_ok(
            SignedGenericTrustActivation::sign(activation_artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &GenericTrustActivationEvaluationRequest {
                    listing,
                    current_publisher: sample_publisher(
                        GenericRegistryPublisherRole::Origin,
                        "origin-a",
                    ),
                    current_freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 5,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                    activation: Some(activation),
                    evaluated_at: Some(150),
                },
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate activation",
        );
        assert!(report.admitted);
        assert!(report.findings.is_empty());
        assert_eq!(
            report.admission_class,
            Some(GenericTrustAdmissionClass::Reviewable)
        );
    }

    #[test]
    fn generic_trust_activation_fails_closed_on_stale_listing() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let issue_request = sample_activation_issue_request(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        let activation_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request,
                130,
            ),
            "build activation artifact",
        );
        let activation = require_ok(
            SignedGenericTrustActivation::sign(activation_artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &GenericTrustActivationEvaluationRequest {
                    listing,
                    current_publisher: sample_publisher(
                        GenericRegistryPublisherRole::Origin,
                        "origin-a",
                    ),
                    current_freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Stale,
                        age_secs: 500,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                    activation: Some(activation),
                    evaluated_at: Some(700),
                },
                700,
                &authority_keypair.public_key(),
            ),
            "evaluate stale listing",
        );
        assert!(!report.admitted);
        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingStale
        );
    }

    #[test]
    fn generic_trust_activation_public_untrusted_never_admits() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let issue_request = sample_activation_issue_request(
            listing.clone(),
            GenericTrustAdmissionClass::PublicUntrusted,
            GenericTrustActivationDisposition::Approved,
        );
        let activation_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request,
                130,
            ),
            "build activation artifact",
        );
        let activation = require_ok(
            SignedGenericTrustActivation::sign(activation_artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &GenericTrustActivationEvaluationRequest {
                    listing,
                    current_publisher: sample_publisher(
                        GenericRegistryPublisherRole::Origin,
                        "origin-a",
                    ),
                    current_freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 5,
                        max_age_secs: 300,
                        valid_until: 400,
                        generated_at: 100,
                    },
                    activation: Some(activation),
                    evaluated_at: Some(150),
                },
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate public_untrusted",
        );
        assert!(!report.admitted);
        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::AdmissionClassUntrusted
        );
    }

    #[test]
    fn generic_trust_activation_flags_unverifiable_listing_signature() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = sample_authority_keypair();
        let mut listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        listing.body.status = GenericListingStatus::Revoked;

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    None,
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate invalid listing signature",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingUnverifiable
        );
    }

    #[test]
    fn generic_trust_activation_flags_listing_signer_mismatch() {
        let namespace_keypair = Keypair::generate();
        let attacker_keypair = Keypair::generate();
        let authority_keypair = sample_authority_keypair();
        let listing = require_ok(
            SignedGenericListing::sign(
                sample_listing(
                    "https://registry.chio.example",
                    &namespace_keypair,
                    "artifact-1",
                    "deadbeef",
                ),
                &attacker_keypair,
            ),
            "sign listing with mismatched signer",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    None,
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate mismatched listing signer",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingUnverifiable
        );
        assert!(report.findings[0]
            .message
            .contains("namespace ownership signer"));
    }

    #[test]
    fn generic_trust_activation_flags_unverifiable_activation_signature() {
        let signing_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut activation = signed_activation(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        let trusted_signer = activation.signer_key.clone();
        activation.body.local_operator_id = "https://tampered.chio.example".to_string();

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &trusted_signer,
            ),
            "evaluate invalid activation signature",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationUnverifiable
        );
    }

    #[test]
    fn generic_trust_activation_flags_invalid_activation_body() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.reviewed_by = None;
        let activation = require_ok(
            SignedGenericTrustActivation::sign(artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate invalid activation body",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationUnverifiable
        );
    }

    #[test]
    fn generic_trust_activation_rejects_listing_mismatch() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        artifact.listing_sha256 = "different".to_string();
        let activation = require_ok(
            SignedGenericTrustActivation::sign(artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate mismatched activation",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingMismatch
        );
    }

    #[test]
    fn generic_trust_activation_rejects_divergent_listing_context() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = sample_authority_keypair();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let activation = signed_activation(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Divergent,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate divergent listing",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::ListingDivergent
        );
    }

    #[test]
    fn generic_trust_activation_rejects_expired_pending_and_denied_activations() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let default_authority_keypair = sample_authority_keypair();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );

        let mut expired_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        expired_artifact.expires_at = Some(140);
        let expired = require_ok(
            SignedGenericTrustActivation::sign(expired_artifact, &authority_keypair),
            "sign expired activation",
        );
        let expired_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing.clone(),
                    Some(expired),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate expired activation",
        );
        assert_eq!(
            expired_report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationExpired
        );

        let pending = signed_activation(
            listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::PendingReview,
        );
        let pending_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing.clone(),
                    Some(pending),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &default_authority_keypair.public_key(),
            ),
            "evaluate pending activation",
        );
        assert_eq!(
            pending_report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationPendingReview
        );

        let denied = signed_activation(
            listing,
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Denied,
        );
        let denied_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    signed_sample_listing(
                        "https://registry.chio.example",
                        &signing_keypair,
                        "artifact-1",
                        "deadbeef",
                    ),
                    Some(denied),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &default_authority_keypair.public_key(),
            ),
            "evaluate denied activation",
        );
        assert_eq!(
            denied_report.findings[0].code,
            GenericTrustActivationFindingCode::ActivationDenied
        );
    }

    #[test]
    fn generic_trust_activation_rejects_ineligible_actor_publisher_status_and_operator() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );

        let mut actor_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        actor_artifact.eligibility.allowed_actor_kinds =
            vec![GenericListingActorKind::CredentialIssuer];
        let actor_activation = require_ok(
            SignedGenericTrustActivation::sign(actor_artifact, &authority_keypair),
            "sign actor-limited activation",
        );
        let actor_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing.clone(),
                    Some(actor_activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate actor ineligible",
        );
        assert_eq!(
            actor_report.findings[0].code,
            GenericTrustActivationFindingCode::ActorKindIneligible
        );

        let mut publisher_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        publisher_artifact.eligibility.allowed_publisher_roles =
            vec![GenericRegistryPublisherRole::Mirror];
        let publisher_activation = require_ok(
            SignedGenericTrustActivation::sign(publisher_artifact, &authority_keypair),
            "sign publisher-limited activation",
        );
        let publisher_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing.clone(),
                    Some(publisher_activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate publisher ineligible",
        );
        assert_eq!(
            publisher_report.findings[0].code,
            GenericTrustActivationFindingCode::PublisherRoleIneligible
        );

        let status_listing = require_ok(
            SignedGenericListing::sign(
                GenericListingArtifact {
                    status: GenericListingStatus::Suspended,
                    ..sample_listing(
                        "https://registry.chio.example",
                        &signing_keypair,
                        "artifact-1",
                        "deadbeef",
                    )
                },
                &signing_keypair,
            ),
            "sign suspended listing",
        );
        let status_activation = signed_activation(
            status_listing.clone(),
            GenericTrustAdmissionClass::Reviewable,
            GenericTrustActivationDisposition::Approved,
        );
        let default_authority_keypair = sample_authority_keypair();
        let status_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    status_listing,
                    Some(status_activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &default_authority_keypair.public_key(),
            ),
            "evaluate status ineligible",
        );
        assert_eq!(
            status_report.findings[0].code,
            GenericTrustActivationFindingCode::ListingStatusIneligible
        );

        let mut operator_artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &issue_request_for(
                    listing.clone(),
                    GenericTrustAdmissionClass::Reviewable,
                    GenericTrustActivationDisposition::Approved,
                ),
                130,
            ),
            "build activation",
        );
        operator_artifact.eligibility.required_listing_operator_ids = vec!["mirror-a".to_string()];
        let operator_activation = require_ok(
            SignedGenericTrustActivation::sign(operator_artifact, &authority_keypair),
            "sign operator-limited activation",
        );
        let operator_report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(operator_activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate operator ineligible",
        );
        assert_eq!(
            operator_report.findings[0].code,
            GenericTrustActivationFindingCode::ListingOperatorIneligible
        );
    }

    #[test]
    fn generic_trust_activation_bond_backed_policy_remains_review_visible_only() {
        let signing_keypair = Keypair::generate();
        let authority_keypair = Keypair::generate();
        let listing = signed_sample_listing(
            "https://registry.chio.example",
            &signing_keypair,
            "artifact-1",
            "deadbeef",
        );
        let mut request = issue_request_for(
            listing.clone(),
            GenericTrustAdmissionClass::BondBacked,
            GenericTrustActivationDisposition::Approved,
        );
        request.eligibility.require_bond_backing = true;
        let artifact = require_ok(
            build_generic_trust_activation_artifact(
                "https://operator.chio.example",
                Some("Chio Operator".to_string()),
                &request,
                130,
            ),
            "build activation",
        );
        let activation = require_ok(
            SignedGenericTrustActivation::sign(artifact, &authority_keypair),
            "sign activation",
        );

        let report = require_ok(
            evaluate_generic_trust_activation(
                &evaluation_request(
                    listing,
                    Some(activation),
                    GenericListingFreshnessState::Fresh,
                    GenericRegistryPublisherRole::Origin,
                    "origin-a",
                    150,
                ),
                150,
                &authority_keypair.public_key(),
            ),
            "evaluate bond-backed activation",
        );

        assert_eq!(
            report.findings[0].code,
            GenericTrustActivationFindingCode::BondBackingRequired
        );
    }
}
