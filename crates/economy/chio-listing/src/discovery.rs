//! Capability marketplace discovery: search and compare extensions on top of
//! the generic listing surface in [`crate`].
//!
//! A tool server operator annotates a listing with a signed
//! [`ListingPricingHint`] (price-per-call, SLA, revocation rate, recent
//! receipt volume). Agents search a set of `GenericListingReport`s filtered
//! by scope prefix, price ceiling, provider, and freshness, then compare the
//! results in a normalized side-by-side view.
//!
//! Listings with non-`Active` status, stale freshness, or missing/expired
//! pricing hints are filtered out. The search is fail-closed by default: any
//! listing that cannot be verified or would violate the query bounds is
//! rejected rather than returned.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::util::bounded_listing_limit;
use crate::{
    aggregate_generic_listing_reports, normalize_namespace, GenericListingActorKind,
    GenericListingFreshnessState, GenericListingQuery, GenericListingReplicaFreshness,
    GenericListingReport, GenericListingSearchError, GenericListingStatus,
    GenericRegistryPublisher, MonetaryAmount, SignedGenericListing, MAX_GENERIC_LISTING_LIMIT,
};

/// Schema identifier for signed pricing hints.
pub const LISTING_PRICING_HINT_SCHEMA: &str = "chio.marketplace.listing-pricing-hint.v1";

/// Schema identifier for signed marketplace search responses.
pub const LISTING_SEARCH_SCHEMA: &str = "chio.marketplace.search.v1";

/// Schema identifier for marketplace comparison artifacts.
pub const LISTING_COMPARISON_SCHEMA: &str = "chio.marketplace.compare.v1";

/// Maximum number of listings a caller may request back from [`search`].
pub const MAX_MARKETPLACE_SEARCH_LIMIT: usize = MAX_GENERIC_LISTING_LIMIT;

/// Operator-signed pricing + SLA hint paired with a published listing.
///
/// The body is signed separately so that listing publication (subject to
/// registry ownership) and marketplace pricing (subject to the operator's
/// own key) can be decoupled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListingPricingHint {
    pub schema: String,
    /// Listing this hint applies to.
    pub listing_id: String,
    /// Namespace of the listing (must match the listing body).
    pub namespace: String,
    /// Provider / operator advertising the price (must match the listing
    /// publisher).
    pub provider_operator_id: String,
    /// Capability scope prefix covered by this hint (e.g.
    /// `"tools:search"` or `"tools:search:*"`). Queries filter against this.
    pub capability_scope: String,
    /// Fixed price charged per invocation under the advertised scope.
    pub price_per_call: MonetaryAmount,
    /// Advertised SLA for invocations under this hint.
    pub sla: ListingSla,
    /// Rolling revocation rate over recent invocations, in basis points.
    /// `0` means "no revocations in the window"; `10_000` means "100%".
    pub revocation_rate_bps: u32,
    /// Number of receipts the provider has produced in the recent window.
    pub recent_receipts_volume: u64,
    /// Unix seconds when the hint was issued.
    pub issued_at: u64,
    /// Unix seconds when the hint expires. Past expiry, the hint is stale
    /// and the listing falls out of the marketplace.
    pub expires_at: u64,
}

impl ListingPricingHint {
    /// Validate the hint's structural invariants. Does not verify the
    /// signature; callers should use [`SignedListingPricingHint::verify_signature`].
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != LISTING_PRICING_HINT_SCHEMA {
            return Err(format!(
                "unsupported listing pricing hint schema: {}",
                self.schema
            ));
        }
        non_empty(&self.listing_id, "listing_id")?;
        non_empty(&self.namespace, "namespace")?;
        non_empty(&self.provider_operator_id, "provider_operator_id")?;
        non_empty(&self.capability_scope, "capability_scope")?;
        validate_currency_code(&self.price_per_call.currency, "price_per_call.currency")?;
        if self.price_per_call.units == 0 {
            return Err("price_per_call.units must be greater than zero".to_string());
        }
        if self.revocation_rate_bps > 10_000 {
            return Err("revocation_rate_bps must be within [0, 10000]".to_string());
        }
        self.sla.validate()?;
        if self.expires_at <= self.issued_at {
            return Err("expires_at must be greater than issued_at".to_string());
        }
        Ok(())
    }

    /// Returns true when the hint is valid at the given unix timestamp.
    #[must_use]
    pub fn is_live_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }
}

pub type SignedListingPricingHint = SignedExportEnvelope<ListingPricingHint>;

/// Service-level advertisement paired with a pricing hint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListingSla {
    pub max_latency_ms: u64,
    /// Availability SLA expressed in basis points. `10_000` means 100.00%.
    pub availability_bps: u32,
    pub throughput_rps: u64,
}

impl ListingSla {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_latency_ms == 0 {
            return Err("sla.max_latency_ms must be greater than zero".to_string());
        }
        if self.availability_bps == 0 || self.availability_bps > 10_000 {
            return Err("sla.availability_bps must be within (0, 10000]".to_string());
        }
        if self.throughput_rps == 0 {
            return Err("sla.throughput_rps must be greater than zero".to_string());
        }
        Ok(())
    }
}

/// Marketplace query for [`search`].
///
/// All fields are optional filters; an empty [`ListingQuery`] returns every
/// active listing across every report within [`Self::limit_or_default`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListingQuery {
    /// Capability scope prefix to match against the hint's
    /// `capability_scope`. Matching is a literal prefix match after trim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_scope_prefix: Option<String>,
    /// Namespace filter. Same normalization as [`GenericListingQuery`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Actor-kind filter. Defaults to `ToolServer` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<GenericListingActorKind>,
    /// Only return listings whose price per call is less than or equal to
    /// this ceiling. Currency must match; listings with differing currency
    /// are filtered out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_price_per_call: Option<MonetaryAmount>,
    /// Require a specific provider operator id (matches hint and publisher).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_operator_id: Option<String>,
    /// Require fresh listings only. When set to `true` any stale/divergent
    /// listing is rejected. Defaults to `true`.
    #[serde(default = "default_require_fresh")]
    pub require_fresh: bool,
    /// Maximum number of results to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

fn default_require_fresh() -> bool {
    true
}

impl ListingQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        bounded_listing_limit(self.limit, MAX_MARKETPLACE_SEARCH_LIMIT)
    }

    /// Translate this marketplace query into a listing query for use with
    /// [`aggregate_generic_listing_reports`].
    #[must_use]
    pub fn to_listing_query(&self) -> GenericListingQuery {
        GenericListingQuery {
            namespace: self.namespace.clone(),
            actor_kind: Some(
                self.actor_kind
                    .unwrap_or(GenericListingActorKind::ToolServer),
            ),
            actor_id: None,
            status: Some(GenericListingStatus::Active),
            limit: Some(self.limit_or_default()),
        }
    }
}

/// A listing projected into the marketplace with its accompanying pricing
/// hint, publisher, and freshness metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    pub rank: u64,
    pub listing: SignedGenericListing,
    pub pricing: SignedListingPricingHint,
    pub publisher: GenericRegistryPublisher,
    pub freshness: GenericListingReplicaFreshness,
}

impl Listing {
    /// The listing identifier is the primary handle agents reference.
    #[must_use]
    pub fn listing_id(&self) -> &str {
        &self.listing.body.listing_id
    }

    /// Price advertised per call under this listing.
    #[must_use]
    pub fn price_per_call(&self) -> &MonetaryAmount {
        &self.pricing.body.price_per_call
    }

    /// Returns true only when the underlying listing is `Active` and the
    /// pricing hint is live at `now`.
    #[must_use]
    pub fn is_admissible_at(&self, now: u64) -> bool {
        matches!(self.listing.body.status, GenericListingStatus::Active)
            && self.pricing.body.is_live_at(now)
            && self.freshness.state == GenericListingFreshnessState::Fresh
    }
}

/// Signed marketplace search response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ListingSearchResponse {
    pub schema: String,
    pub generated_at: u64,
    pub query: ListingQuery,
    pub result_count: u64,
    pub results: Vec<Listing>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<GenericListingSearchError>,
}

/// Normalized comparison of a set of [`Listing`] entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ListingComparison {
    pub schema: String,
    pub generated_at: u64,
    pub entry_count: u64,
    pub rows: Vec<ListingComparisonRow>,
    /// `true` when every non-empty row shares the same price currency.
    pub currency_consistent: bool,
}

/// One normalized row in a [`ListingComparison`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListingComparisonRow {
    pub listing_id: String,
    pub provider_operator_id: String,
    pub capability_scope: String,
    pub price_per_call: MonetaryAmount,
    /// Price normalized against the row with the minimum price per call
    /// within the same currency. Expressed in basis points where 10_000
    /// means "equal to the minimum".
    pub price_index_bps: u32,
    pub sla: ListingSla,
    pub revocation_rate_bps: u32,
    pub recent_receipts_volume: u64,
    pub freshness_state: GenericListingFreshnessState,
    pub status: GenericListingStatus,
}

/// Search a collection of generic listing reports, filtered by marketplace
/// criteria, and pair each surviving listing with its operator-signed
/// pricing hint.
///
/// Listings without a matching, signed, non-expired pricing hint are
/// dropped. Listings whose verified pricing hint does not satisfy the
/// `capability_scope_prefix`, `max_price_per_call`, or
/// `provider_operator_id` filters are also dropped.
///
/// This function does not panic. All hint signature failures and structural
/// validation errors are returned in
/// [`ListingSearchResponse::errors`].
#[must_use]
pub fn search(
    reports: &[GenericListingReport],
    pricing_hints: &[SignedListingPricingHint],
    query: &ListingQuery,
    now: u64,
) -> ListingSearchResponse {
    let listing_query = query.to_listing_query();
    let aggregated = aggregate_generic_listing_reports(reports, &listing_query, now);
    let mut errors = aggregated.errors;

    // Index structurally valid, self-consistent pricing hints by listing_id.
    // Authority binding requires the verified listing body, so that check is
    // applied after aggregation when the namespace-owner signer is available.
    let mut indexed_hints: BTreeMap<String, Vec<SignedListingPricingHint>> = BTreeMap::new();
    for hint in pricing_hints {
        if let Err(error) = hint.body.validate() {
            errors.push(GenericListingSearchError {
                operator_id: hint.body.provider_operator_id.clone(),
                operator_name: None,
                registry_url: String::new(),
                error: format!("pricing hint `{}` invalid: {error}", hint.body.listing_id),
            });
            continue;
        }
        match hint.verify_signature() {
            Ok(true) => {}
            Ok(false) => {
                errors.push(GenericListingSearchError {
                    operator_id: hint.body.provider_operator_id.clone(),
                    operator_name: None,
                    registry_url: String::new(),
                    error: format!(
                        "pricing hint `{}` signature is invalid",
                        hint.body.listing_id
                    ),
                });
                continue;
            }
            Err(error) => {
                errors.push(GenericListingSearchError {
                    operator_id: hint.body.provider_operator_id.clone(),
                    operator_name: None,
                    registry_url: String::new(),
                    error: format!(
                        "pricing hint `{}` verification failed: {error}",
                        hint.body.listing_id
                    ),
                });
                continue;
            }
        }
        if !hint.body.is_live_at(now) {
            continue;
        }
        indexed_hints
            .entry(hint.body.listing_id.clone())
            .or_default()
            .push(hint.clone());
    }

    let max_price = query.max_price_per_call.as_ref();
    let scope_prefix = query
        .capability_scope_prefix
        .as_deref()
        .map(str::trim)
        .filter(|prefix| !prefix.is_empty());
    let provider_filter = query
        .provider_operator_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());

    let mut results: Vec<Listing> = Vec::new();
    for aggregated_result in aggregated.results {
        if matches!(
            aggregated_result.listing.body.status,
            GenericListingStatus::Revoked
                | GenericListingStatus::Retired
                | GenericListingStatus::Suspended
                | GenericListingStatus::Superseded
        ) {
            continue;
        }
        if query.require_fresh
            && aggregated_result.freshness.state != GenericListingFreshnessState::Fresh
        {
            continue;
        }

        let Some(hints) = indexed_hints.get(&aggregated_result.listing.body.listing_id) else {
            continue;
        };

        let mut selected_hint = None;
        for hint in hints {
            if let Err(error) = validate_pricing_hint_listing_authority(
                hint,
                &aggregated_result.listing,
                &aggregated_result.publisher,
            ) {
                errors.push(GenericListingSearchError {
                    operator_id: hint.body.provider_operator_id.clone(),
                    operator_name: None,
                    registry_url: aggregated_result.publisher.registry_url.clone(),
                    error,
                });
                continue;
            }
            if selected_hint
                .as_ref()
                .is_none_or(|existing: &&SignedListingPricingHint| {
                    existing.body.issued_at < hint.body.issued_at
                })
            {
                selected_hint = Some(hint);
            }
        }
        let Some(hint) = selected_hint else {
            continue;
        };
        if let Some(prefix) = scope_prefix {
            if !hint.body.capability_scope.starts_with(prefix) {
                continue;
            }
        }
        if let Some(max) = max_price {
            if max.currency != hint.body.price_per_call.currency {
                continue;
            }
            if hint.body.price_per_call.units > max.units {
                continue;
            }
        }
        if let Some(provider) = provider_filter {
            if hint.body.provider_operator_id != provider {
                continue;
            }
        }

        results.push(Listing {
            rank: 0,
            listing: aggregated_result.listing,
            pricing: hint.clone(),
            publisher: aggregated_result.publisher,
            freshness: aggregated_result.freshness,
        });
    }

    // Rank by: price ascending (same currency), then revocation rate
    // ascending, then receipts volume descending, then origin-publisher
    // preference, then listing id for stability.
    results.sort_by(|left, right| {
        let left_currency = &left.pricing.body.price_per_call.currency;
        let right_currency = &right.pricing.body.price_per_call.currency;
        left_currency
            .cmp(right_currency)
            .then(
                left.pricing
                    .body
                    .price_per_call
                    .units
                    .cmp(&right.pricing.body.price_per_call.units),
            )
            .then(
                left.pricing
                    .body
                    .revocation_rate_bps
                    .cmp(&right.pricing.body.revocation_rate_bps),
            )
            .then(
                right
                    .pricing
                    .body
                    .recent_receipts_volume
                    .cmp(&left.pricing.body.recent_receipts_volume),
            )
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
    results.truncate(query.limit_or_default());

    ListingSearchResponse {
        schema: LISTING_SEARCH_SCHEMA.to_string(),
        generated_at: now,
        query: query.clone(),
        result_count: results.len() as u64,
        results,
        errors,
    }
}

/// Produce a normalized side-by-side comparison of the given listings.
///
/// The comparison computes a `price_index_bps` column that expresses each
/// row's price relative to the cheapest listing **within the same
/// currency**. Rows with mismatched currency receive `price_index_bps =
/// 10_000` in their own sub-group and a `currency_consistent = false`
/// flag on the comparison.
#[must_use]
pub fn compare(listings: &[Listing]) -> ListingComparison {
    let generated_at = listings
        .iter()
        .map(|entry| entry.pricing.body.issued_at)
        .max()
        .unwrap_or_default();
    let mut currencies: BTreeMap<String, u64> = BTreeMap::new();
    for entry in listings {
        let currency = entry.pricing.body.price_per_call.currency.clone();
        let min = currencies.entry(currency).or_insert(u64::MAX);
        *min = (*min).min(entry.pricing.body.price_per_call.units);
    }

    let currency_consistent = currencies.len() <= 1;

    let rows = listings
        .iter()
        .map(|entry| {
            let currency = entry.pricing.body.price_per_call.currency.clone();
            let min = currencies.get(&currency).copied().unwrap_or(u64::MAX);
            let units = entry.pricing.body.price_per_call.units;
            let price_index_bps = if min == 0 || units == 0 {
                10_000
            } else {
                // Multiply in u128 to avoid overflow; clamp to u32::MAX.
                let numerator = (units as u128).saturating_mul(10_000_u128);
                let value = numerator / (min as u128);
                value.min(u32::MAX as u128) as u32
            };
            ListingComparisonRow {
                listing_id: entry.listing.body.listing_id.clone(),
                provider_operator_id: entry.pricing.body.provider_operator_id.clone(),
                capability_scope: entry.pricing.body.capability_scope.clone(),
                price_per_call: entry.pricing.body.price_per_call.clone(),
                price_index_bps,
                sla: entry.pricing.body.sla.clone(),
                revocation_rate_bps: entry.pricing.body.revocation_rate_bps,
                recent_receipts_volume: entry.pricing.body.recent_receipts_volume,
                freshness_state: entry.freshness.state,
                status: entry.listing.body.status,
            }
        })
        .collect::<Vec<_>>();

    ListingComparison {
        schema: LISTING_COMPARISON_SCHEMA.to_string(),
        generated_at,
        entry_count: rows.len() as u64,
        rows,
        currency_consistent,
    }
}

/// Resolve a listing + pricing-hint pair by id from previously aggregated
/// search results, returning `None` when the listing is absent or fails the
/// fail-closed admission check at `now`.
#[must_use]
pub fn resolve_admissible_listing<'a>(
    search_results: &'a [Listing],
    listing_id: &str,
    now: u64,
) -> Option<&'a Listing> {
    search_results
        .iter()
        .find(|listing| listing.listing_id() == listing_id && listing.is_admissible_at(now))
}

/// Returns the [`PublicKey`] that signed the resolved listing's pricing hint.
/// Used by the bid/ask protocol to bind capability tokens back to the
/// provider's advertised pricing authority.
#[must_use]
pub fn provider_signing_key(listing: &Listing) -> &PublicKey {
    &listing.pricing.signer_key
}

fn validate_pricing_hint_listing_authority(
    hint: &SignedListingPricingHint,
    listing: &SignedGenericListing,
    publisher: &GenericRegistryPublisher,
) -> Result<(), String> {
    if normalize_namespace(&hint.body.namespace) != normalize_namespace(&listing.body.namespace) {
        return Err(format!(
            "pricing hint `{}` namespace mismatch",
            hint.body.listing_id
        ));
    }
    if hint.body.provider_operator_id != publisher.operator_id {
        return Err(format!(
            "pricing hint `{}` provider does not match publisher",
            hint.body.listing_id
        ));
    }
    if hint.body.provider_operator_id != listing.body.namespace_ownership.owner_id {
        return Err(format!(
            "pricing hint `{}` provider does not match listing authority",
            hint.body.listing_id
        ));
    }
    if hint.signer_key != listing.body.namespace_ownership.signer_public_key {
        return Err(format!(
            "pricing hint `{}` signer does not match listing pricing authority",
            hint.body.listing_id
        ));
    }
    Ok(())
}

fn non_empty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_currency_code(value: &str, field: &str) -> Result<(), String> {
    if value.len() == 3
        && value
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(format!(
            "{field} must be a 3-letter uppercase currency code"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::{
        GenericListingArtifact, GenericListingBoundary, GenericListingCompatibilityReference,
        GenericListingFreshnessWindow, GenericListingSearchPolicy, GenericListingSubject,
        GenericListingSummary, GenericNamespaceOwnership, GenericRegistryPublisherRole,
        GENERIC_LISTING_ARTIFACT_SCHEMA, GENERIC_LISTING_REPORT_SCHEMA,
    };

    fn require_ok<T, E>(result: Result<T, E>, context: &'static str) -> T
    where
        E: std::fmt::Debug,
    {
        result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
    }

    fn require_err<T, E>(result: Result<T, E>, context: &'static str) -> E {
        match result {
            Ok(_) => panic!("{context}"),
            Err(error) => error,
        }
    }

    fn require_some<T>(value: Option<T>, context: &'static str) -> T {
        value.unwrap_or_else(|| panic!("{context}"))
    }

    fn sample_namespace(keypair: &Keypair) -> GenericNamespaceOwnership {
        GenericNamespaceOwnership {
            namespace: "https://registry.chio.example".to_string(),
            owner_id: "operator-a".to_string(),
            owner_name: Some("Operator A".to_string()),
            registry_url: "https://registry.chio.example".to_string(),
            signer_public_key: keypair.public_key(),
            registered_at: 1,
            transferred_from_owner_id: None,
        }
    }

    fn sample_listing(
        keypair: &Keypair,
        listing_id: &str,
        status: GenericListingStatus,
    ) -> SignedGenericListing {
        let body = GenericListingArtifact {
            schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
            listing_id: listing_id.to_string(),
            namespace: "https://registry.chio.example".to_string(),
            published_at: 10,
            expires_at: Some(1000),
            status,
            namespace_ownership: sample_namespace(keypair),
            subject: GenericListingSubject {
                actor_kind: GenericListingActorKind::ToolServer,
                actor_id: format!("server-{listing_id}"),
                display_name: None,
                metadata_url: None,
                resolution_url: None,
                homepage_url: None,
            },
            compatibility: GenericListingCompatibilityReference {
                source_schema: "chio.certify.check.v1".to_string(),
                source_artifact_id: format!("artifact-{listing_id}"),
                source_artifact_sha256: format!("sha-{listing_id}"),
            },
            boundary: GenericListingBoundary::default(),
        };
        require_ok(SignedGenericListing::sign(body, keypair), "sign listing")
    }

    fn sample_publisher(operator_id: &str) -> GenericRegistryPublisher {
        GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: operator_id.to_string(),
            operator_name: Some(format!("Operator {operator_id}")),
            registry_url: format!("https://{operator_id}.chio.example"),
            upstream_registry_urls: Vec::new(),
        }
    }

    fn sample_report(
        keypair: &Keypair,
        operator_id: &str,
        generated_at: u64,
        listings: Vec<SignedGenericListing>,
    ) -> GenericListingReport {
        GenericListingReport {
            schema: GENERIC_LISTING_REPORT_SCHEMA.to_string(),
            generated_at,
            query: GenericListingQuery::default(),
            namespace: sample_namespace(keypair),
            publisher: sample_publisher(operator_id),
            freshness: GenericListingFreshnessWindow {
                max_age_secs: 300,
                valid_until: generated_at + 300,
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

    fn sample_pricing_hint(
        operator_keypair: &Keypair,
        operator_id: &str,
        listing_id: &str,
        scope: &str,
        price_units: u64,
        issued_at: u64,
    ) -> SignedListingPricingHint {
        let body = ListingPricingHint {
            schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
            listing_id: listing_id.to_string(),
            namespace: "https://registry.chio.example".to_string(),
            provider_operator_id: operator_id.to_string(),
            capability_scope: scope.to_string(),
            price_per_call: MonetaryAmount {
                units: price_units,
                currency: "USD".to_string(),
            },
            sla: ListingSla {
                max_latency_ms: 250,
                availability_bps: 9_990,
                throughput_rps: 50,
            },
            revocation_rate_bps: 25,
            recent_receipts_volume: 1_000,
            issued_at,
            expires_at: issued_at + 600,
        };
        require_ok(
            SignedListingPricingHint::sign(body, operator_keypair),
            "sign hint",
        )
    }

    #[test]
    fn listing_pricing_hint_rejects_lowercase_currency() {
        let operator_keypair = Keypair::generate();
        let mut hint = sample_pricing_hint(
            &operator_keypair,
            "operator-a",
            "listing-1",
            "tools:search",
            50,
            100,
        );
        hint.body.price_per_call.currency = "usd".to_string();

        let error = require_err(
            hint.body.validate(),
            "lowercase pricing currency must fail closed",
        );
        assert!(error.contains("currency"));
    }

    #[test]
    fn search_filters_by_scope_prefix_and_price_ceiling() {
        let registry_keypair = Keypair::generate();
        let listing_cheap = sample_listing(
            &registry_keypair,
            "listing-cheap",
            GenericListingStatus::Active,
        );
        let listing_pricey = sample_listing(
            &registry_keypair,
            "listing-pricey",
            GenericListingStatus::Active,
        );
        let listing_other_scope = sample_listing(
            &registry_keypair,
            "listing-offscope",
            GenericListingStatus::Active,
        );
        let report = sample_report(
            &registry_keypair,
            "operator-a",
            100,
            vec![
                listing_cheap.clone(),
                listing_pricey.clone(),
                listing_other_scope.clone(),
            ],
        );

        let operator_keypair = registry_keypair.clone();
        let hints = vec![
            sample_pricing_hint(
                &operator_keypair,
                "operator-a",
                "listing-cheap",
                "tools:search",
                50,
                110,
            ),
            sample_pricing_hint(
                &operator_keypair,
                "operator-a",
                "listing-pricey",
                "tools:search:premium",
                500,
                110,
            ),
            sample_pricing_hint(
                &operator_keypair,
                "operator-a",
                "listing-offscope",
                "tools:write",
                10,
                110,
            ),
        ];

        let query = ListingQuery {
            capability_scope_prefix: Some("tools:search".to_string()),
            max_price_per_call: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            ..ListingQuery::default()
        };
        let response = search(&[report], &hints, &query, 120);

        assert_eq!(response.result_count, 1);
        assert_eq!(response.results[0].listing_id(), "listing-cheap");
        assert_eq!(response.results[0].price_per_call().units, 50);
    }

    #[test]
    fn search_rejects_non_active_listings_and_missing_hints() {
        let registry_keypair = Keypair::generate();
        let revoked = sample_listing(
            &registry_keypair,
            "listing-revoked",
            GenericListingStatus::Revoked,
        );
        let active_no_hint = sample_listing(
            &registry_keypair,
            "listing-no-hint",
            GenericListingStatus::Active,
        );
        let report = sample_report(
            &registry_keypair,
            "operator-a",
            100,
            vec![revoked, active_no_hint],
        );
        let response = search(&[report], &[], &ListingQuery::default(), 120);
        assert_eq!(response.result_count, 0);
    }

    #[test]
    fn search_fails_closed_on_tampered_pricing_hint_signature() {
        let registry_keypair = Keypair::generate();
        let listing = sample_listing(&registry_keypair, "listing-1", GenericListingStatus::Active);
        let report = sample_report(&registry_keypair, "operator-a", 100, vec![listing]);

        let operator_keypair = registry_keypair.clone();
        let mut hint = sample_pricing_hint(
            &operator_keypair,
            "operator-a",
            "listing-1",
            "tools:search",
            10,
            110,
        );
        // Tamper: mutate body after signing.
        hint.body.price_per_call.units = 1;

        let response = search(&[report], &[hint], &ListingQuery::default(), 120);
        assert_eq!(response.result_count, 0);
        assert!(response
            .errors
            .iter()
            .any(|error| error.error.contains("signature is invalid")));
    }

    #[test]
    fn search_rejects_stale_pricing_hint() {
        let registry_keypair = Keypair::generate();
        let listing = sample_listing(&registry_keypair, "listing-1", GenericListingStatus::Active);
        let report = sample_report(&registry_keypair, "operator-a", 100, vec![listing]);

        let operator_keypair = registry_keypair.clone();
        // Hint expires at 710.
        let stale = sample_pricing_hint(
            &operator_keypair,
            "operator-a",
            "listing-1",
            "tools:search",
            10,
            110,
        );

        let response = search(&[report], &[stale], &ListingQuery::default(), 2_000);
        assert_eq!(response.result_count, 0);
    }

    #[test]
    fn compare_normalizes_prices_within_currency() {
        let registry_keypair = Keypair::generate();
        let listing_a =
            sample_listing(&registry_keypair, "listing-a", GenericListingStatus::Active);
        let listing_b =
            sample_listing(&registry_keypair, "listing-b", GenericListingStatus::Active);
        let report = sample_report(
            &registry_keypair,
            "operator-a",
            100,
            vec![listing_a, listing_b],
        );

        let operator_keypair = registry_keypair.clone();
        let hints = vec![
            sample_pricing_hint(
                &operator_keypair,
                "operator-a",
                "listing-a",
                "tools:search",
                100,
                110,
            ),
            sample_pricing_hint(
                &operator_keypair,
                "operator-a",
                "listing-b",
                "tools:search",
                200,
                110,
            ),
        ];
        let response = search(&[report], &hints, &ListingQuery::default(), 120);
        let comparison = compare(&response.results);
        assert_eq!(comparison.entry_count, 2);
        assert!(comparison.currency_consistent);
        // listing-a is cheapest; its price_index should be 10_000 (1.0x).
        let row_a = require_some(
            comparison
                .rows
                .iter()
                .find(|row| row.listing_id == "listing-a"),
            "row a present",
        );
        let row_b = require_some(
            comparison
                .rows
                .iter()
                .find(|row| row.listing_id == "listing-b"),
            "row b present",
        );
        assert_eq!(row_a.price_index_bps, 10_000);
        assert_eq!(row_b.price_index_bps, 20_000);
    }

    #[test]
    fn compare_flags_currency_inconsistency() {
        let registry_keypair = Keypair::generate();
        let listing = sample_listing(&registry_keypair, "listing-a", GenericListingStatus::Active);
        let operator_keypair = registry_keypair.clone();

        let hint_usd = require_ok(
            SignedListingPricingHint::sign(
                ListingPricingHint {
                    schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
                    listing_id: "listing-a".to_string(),
                    namespace: "https://registry.chio.example".to_string(),
                    provider_operator_id: "operator-a".to_string(),
                    capability_scope: "tools:search".to_string(),
                    price_per_call: MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    },
                    sla: ListingSla {
                        max_latency_ms: 500,
                        availability_bps: 9_990,
                        throughput_rps: 10,
                    },
                    revocation_rate_bps: 0,
                    recent_receipts_volume: 10,
                    issued_at: 100,
                    expires_at: 500,
                },
                &operator_keypair,
            ),
            "sign usd",
        );
        let hint_eur = require_ok(
            SignedListingPricingHint::sign(
                ListingPricingHint {
                    schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
                    listing_id: "listing-b".to_string(),
                    namespace: "https://registry.chio.example".to_string(),
                    provider_operator_id: "operator-a".to_string(),
                    capability_scope: "tools:search".to_string(),
                    price_per_call: MonetaryAmount {
                        units: 80,
                        currency: "EUR".to_string(),
                    },
                    sla: ListingSla {
                        max_latency_ms: 500,
                        availability_bps: 9_990,
                        throughput_rps: 10,
                    },
                    revocation_rate_bps: 0,
                    recent_receipts_volume: 10,
                    issued_at: 100,
                    expires_at: 500,
                },
                &operator_keypair,
            ),
            "sign eur",
        );

        let listings = vec![
            Listing {
                rank: 1,
                listing: listing.clone(),
                pricing: hint_usd,
                publisher: sample_publisher("operator-a"),
                freshness: GenericListingReplicaFreshness {
                    state: GenericListingFreshnessState::Fresh,
                    age_secs: 10,
                    max_age_secs: 300,
                    valid_until: 400,
                    generated_at: 100,
                },
            },
            Listing {
                rank: 2,
                listing,
                pricing: hint_eur,
                publisher: sample_publisher("operator-a"),
                freshness: GenericListingReplicaFreshness {
                    state: GenericListingFreshnessState::Fresh,
                    age_secs: 10,
                    max_age_secs: 300,
                    valid_until: 400,
                    generated_at: 100,
                },
            },
        ];
        let comparison = compare(&listings);
        assert!(!comparison.currency_consistent);
    }
}
