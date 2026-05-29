//! Generic listing core types: actors, lifecycle status, namespace ownership, artifacts, and reports.

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;
use crate::receipt::SignedExportEnvelope;
use crate::search::GenericListingFreshnessWindow;
use crate::util::{validate_http_url, validate_non_empty, validate_optional_http_url};
use crate::{normalize_namespace, GenericListingSearchPolicy};

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
