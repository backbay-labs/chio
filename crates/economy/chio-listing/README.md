# chio-listing

Generic listing and trust-activation contracts for the Chio protocol. The
crate defines the signed `Listing` and namespace artifacts marketplace
participants publish, the report-aggregation and marketplace-discovery
search paths that make listings findable, and the local trust-activation
flow that turns a discovered listing into a runtime-admissible one.
Listings are signed by their namespace owner; every validation, search, and
evaluation path in the crate is pure, with no I/O.

## Responsibilities

- Define the signed generic listing and namespace artifacts and enforce
  their lifecycle, ownership, and visibility-only boundary invariants.
- Aggregate signed listing reports from multiple registry publishers into
  one ranked, divergence-checked view.
- Run capability marketplace discovery: pair listings with operator-signed
  pricing hints, filter and rank them by price and reliability, and produce
  a normalized side-by-side comparison.
- Define the trust-activation artifact and evaluator that convert a visible
  listing into a locally admitted one, gated on freshness, publisher role,
  status, signer authority, and eligibility policy.

## Public API

All names live at the crate root (`chio_listing::*`) unless noted.

- Listing and namespace artifacts: `GenericListingArtifact`,
  `SignedGenericListing`, `GenericNamespaceArtifact`, `SignedGenericNamespace`,
  `GenericNamespaceOwnership`, `GenericRegistryPublisher`,
  `GenericListingBoundary`, `GenericListingQuery`, `GenericListingReport`,
  and the actor/status/lifecycle/role enums.
- Network search types: `GenericListingSearchPolicy`,
  `GenericListingFreshnessWindow`, `GenericListingReplicaFreshness`,
  `GenericListingSearchResult`, `GenericListingDivergence`,
  `GenericListingSearchResponse`.
- Validation and aggregation: `normalize_namespace`,
  `ensure_generic_listing_signed_by_namespace_owner`,
  `ensure_generic_listing_namespace_consistency`,
  `aggregate_generic_listing_reports`.
- Capability marketplace discovery, also reachable under `discovery::`:
  `Listing`, `ListingQuery`, `ListingSla`, `ListingPricingHint`,
  `SignedListingPricingHint`, `ListingSearchResponse`, `ListingComparison`,
  `search`, `compare`, `resolve_admissible_listing`, `provider_signing_key`.
- Trust activation: `GenericTrustActivationArtifact`,
  `SignedGenericTrustActivation`, `GenericTrustActivationEligibility`,
  `GenericTrustActivationEvaluation`, `GenericTrustActivationFindingCode`,
  `build_generic_trust_activation_artifact`,
  `evaluate_generic_trust_activation`.
- Re-exported from `chio-core-types`: `MonetaryAmount`, `canonical_json_bytes`,
  `crypto`, `receipt`.

## Usage

```rust
use chio_listing::{discovery, GenericListingReport, ListingQuery};

// `reports` are signed listing reports collected from registry publishers;
// `hints` are the operators' signed `SignedListingPricingHint`s.
let response = discovery::search(&reports, &hints, &ListingQuery::default(), now);
for listing in &response.results {
    println!("{} @ {:?}", listing.listing_id(), listing.price_per_call());
}
```

## Testing

`cargo test -p chio-listing`

## See also

- `chio-open-market` - resolves listings via `discovery::search` to mint capability tokens in its bid/ask protocol.
- `chio-governance`, `chio-federation` - re-export this crate as `listing` and build policy on its artifacts.
- `chio-core` - re-exports this crate as `chio_core::listing`.
