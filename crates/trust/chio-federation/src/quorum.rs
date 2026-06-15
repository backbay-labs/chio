use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::artifacts::{FederationArtifactKind, FederationArtifactReference};
use crate::error::FederationContractError;
use crate::listing::{
    GenericListingFreshnessState, GenericListingReplicaFreshness, GenericRegistryPublisher,
    GenericRegistryPublisherRole,
};
use crate::receipt::lineage::SignedExportEnvelope;
use crate::validation::{
    ensure_non_empty, ensure_unique_strings, validate_anti_eclipse_policy,
    validate_federation_artifact_reference, validate_hex_digest,
};

pub const CHIO_FEDERATION_QUORUM_REPORT_SCHEMA: &str = "chio.federation-quorum-report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationQuorumState {
    Converged,
    Stale,
    Conflicting,
    InsufficientQuorum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationPublisherObservation {
    pub publisher: GenericRegistryPublisher,
    pub report_ref: FederationArtifactReference,
    pub observed_listing_sha256: String,
    pub freshness: GenericListingReplicaFreshness,
    pub observed_at: u64,
    pub upstream_hop_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationConflictEvidence {
    pub divergence_key: String,
    pub publisher_operator_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAntiEclipsePolicy {
    pub minimum_distinct_operators: u32,
    pub require_origin_publisher: bool,
    pub require_indexer_observation: bool,
    pub max_upstream_hops: u32,
}

impl Default for FederationAntiEclipsePolicy {
    fn default() -> Self {
        Self {
            minimum_distinct_operators: 2,
            require_origin_publisher: true,
            require_indexer_observation: true,
            max_upstream_hops: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationQuorumReport {
    pub schema: String,
    pub report_id: String,
    pub generated_at: u64,
    pub namespace: String,
    pub listing_id: String,
    pub origin_operator_id: String,
    pub quorum_threshold: u32,
    pub max_replica_age_secs: u64,
    pub publishers: Vec<FederationPublisherObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<FederationConflictEvidence>,
    pub anti_eclipse_policy: FederationAntiEclipsePolicy,
    pub final_state: FederationQuorumState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedFederationQuorumReport = SignedExportEnvelope<FederationQuorumReport>;

pub fn validate_federation_quorum_report(
    report: &FederationQuorumReport,
) -> Result<(), FederationContractError> {
    if report.schema != CHIO_FEDERATION_QUORUM_REPORT_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    ensure_non_empty(&report.report_id, "federation_quorum.report_id")?;
    ensure_non_empty(&report.namespace, "federation_quorum.namespace")?;
    ensure_non_empty(&report.listing_id, "federation_quorum.listing_id")?;
    ensure_non_empty(
        &report.origin_operator_id,
        "federation_quorum.origin_operator_id",
    )?;
    if report.quorum_threshold == 0 {
        return Err(FederationContractError::InvalidQuorum(
            "quorum_threshold must be non-zero".to_string(),
        ));
    }
    if report.max_replica_age_secs == 0 {
        return Err(FederationContractError::InvalidQuorum(
            "max_replica_age_secs must be non-zero".to_string(),
        ));
    }
    if report.publishers.is_empty() {
        return Err(FederationContractError::MissingField(
            "federation_quorum.publishers",
        ));
    }
    validate_anti_eclipse_policy(&report.anti_eclipse_policy)?;

    let mut publisher_ids = HashSet::new();
    let mut fresh_count = 0_u32;
    let mut stale_count = 0_u32;
    let mut has_origin = false;
    let mut has_indexer = false;
    for publisher in &report.publishers {
        publisher
            .publisher
            .validate()
            .map_err(FederationContractError::InvalidQuorum)?;
        validate_federation_artifact_reference(
            &publisher.report_ref,
            "federation_quorum.publishers.report_ref",
        )?;
        if publisher.report_ref.kind != FederationArtifactKind::ListingReport {
            return Err(FederationContractError::InvalidQuorum(
                "publisher report_ref must reference a listing report".to_string(),
            ));
        }
        if publisher.report_ref.operator_id != publisher.publisher.operator_id {
            return Err(FederationContractError::InvalidQuorum(
                "publisher report_ref operator_id must match publisher.operator_id".to_string(),
            ));
        }
        validate_hex_digest(
            &publisher.observed_listing_sha256,
            "federation_quorum.publishers.observed_listing_sha256",
        )?;
        publisher
            .freshness
            .validate()
            .map_err(FederationContractError::InvalidQuorum)?;
        if publisher.freshness.age_secs >= report.max_replica_age_secs
            || publisher.freshness.state == GenericListingFreshnessState::Stale
        {
            stale_count += 1;
        } else {
            fresh_count += 1;
        }
        if publisher.upstream_hop_count > report.anti_eclipse_policy.max_upstream_hops {
            return Err(FederationContractError::InvalidQuorum(
                "publisher upstream_hop_count exceeds anti-eclipse policy".to_string(),
            ));
        }
        if !publisher_ids.insert(publisher.publisher.operator_id.as_str()) {
            return Err(FederationContractError::DuplicateValue(
                publisher.publisher.operator_id.clone(),
            ));
        }
        if publisher.publisher.role == GenericRegistryPublisherRole::Origin
            && publisher.publisher.operator_id == report.origin_operator_id
        {
            has_origin = true;
        }
        if publisher.publisher.role == GenericRegistryPublisherRole::Indexer {
            has_indexer = true;
        }
    }

    if report.anti_eclipse_policy.require_origin_publisher && !has_origin {
        return Err(FederationContractError::InvalidQuorum(
            "anti-eclipse policy requires an origin publisher observation".to_string(),
        ));
    }
    if report.anti_eclipse_policy.require_indexer_observation && !has_indexer {
        return Err(FederationContractError::InvalidQuorum(
            "anti-eclipse policy requires an indexer observation".to_string(),
        ));
    }
    if publisher_ids.len() < report.anti_eclipse_policy.minimum_distinct_operators as usize {
        return Err(FederationContractError::InvalidQuorum(
            "insufficient distinct operators for anti-eclipse policy".to_string(),
        ));
    }

    let mut divergence_keys = HashSet::new();
    for conflict in &report.conflicts {
        ensure_non_empty(
            &conflict.divergence_key,
            "federation_quorum.conflicts.divergence_key",
        )?;
        ensure_non_empty(&conflict.reason, "federation_quorum.conflicts.reason")?;
        ensure_unique_strings(
            &conflict.publisher_operator_ids,
            "federation_quorum.conflicts.publisher_operator_ids",
        )?;
        if !divergence_keys.insert(conflict.divergence_key.as_str()) {
            return Err(FederationContractError::DuplicateValue(
                conflict.divergence_key.clone(),
            ));
        }
    }

    match report.final_state {
        FederationQuorumState::Converged => {
            if !report.conflicts.is_empty() {
                return Err(FederationContractError::InvalidQuorum(
                    "converged quorum reports cannot include conflicts".to_string(),
                ));
            }
            if fresh_count < report.quorum_threshold {
                return Err(FederationContractError::InvalidQuorum(
                    "converged quorum reports require fresh observations meeting the quorum threshold"
                        .to_string(),
                ));
            }
        }
        FederationQuorumState::Conflicting => {
            if report.conflicts.is_empty() {
                return Err(FederationContractError::InvalidQuorum(
                    "conflicting quorum reports require conflict evidence".to_string(),
                ));
            }
        }
        FederationQuorumState::InsufficientQuorum => {
            if fresh_count >= report.quorum_threshold
                && publisher_ids.len()
                    >= report.anti_eclipse_policy.minimum_distinct_operators as usize
                && (!report.anti_eclipse_policy.require_origin_publisher || has_origin)
                && (!report.anti_eclipse_policy.require_indexer_observation || has_indexer)
            {
                return Err(FederationContractError::InvalidQuorum(
                    "insufficient_quorum requires a real quorum shortfall".to_string(),
                ));
            }
        }
        FederationQuorumState::Stale => {
            if stale_count != report.publishers.len() as u32 {
                return Err(FederationContractError::InvalidQuorum(
                    "stale quorum reports require all observations to be stale".to_string(),
                ));
            }
        }
    }

    Ok(())
}
