//! Generic listing search surface: freshness windows, search policy, results, and divergences.

use serde::{Deserialize, Serialize};

use crate::util::validate_non_empty;
use crate::{
    GenericListingActorKind, GenericListingFreshnessState, GenericListingQuery,
    GenericRegistryPublisher, SignedGenericListing, GENERIC_LISTING_SEARCH_ALGORITHM_V1,
};

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
        let state = if generated_at > now || age_secs > self.max_age_secs || now > self.valid_until
        {
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
