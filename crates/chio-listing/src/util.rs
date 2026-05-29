//! Shared validation, normalization, and report-aggregation helpers for generic listings.

use std::collections::BTreeMap;

use crate::crypto::sha256_hex;
use crate::{
    canonical_json_bytes, GenericListingArtifact, GenericListingDivergence,
    GenericListingFreshnessState, GenericListingQuery, GenericListingReplicaFreshness,
    GenericListingReport, GenericListingSearchError, GenericListingSearchPolicy,
    GenericListingSearchResponse, GenericListingSearchResult, GenericListingStatus,
    GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole,
    SignedGenericListing, GENERIC_LISTING_NETWORK_SEARCH_SCHEMA, GENERIC_LISTING_REPORT_SCHEMA,
};

pub fn normalize_namespace(namespace: &str) -> String {
    namespace.trim().trim_end_matches('/').to_string()
}

pub(crate) fn generic_listing_body_sha256(
    listing: &SignedGenericListing,
) -> Result<String, String> {
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

pub(crate) fn validate_non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

pub(crate) fn validate_http_url(value: &str, field: &str) -> Result<(), String> {
    validate_non_empty(value, field)?;
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(format!("{field} must start with http:// or https://"));
    }
    Ok(())
}

pub(crate) fn validate_optional_http_url(value: Option<&str>, field: &str) -> Result<(), String> {
    if let Some(value) = value {
        validate_http_url(value, field)?;
    }
    Ok(())
}
