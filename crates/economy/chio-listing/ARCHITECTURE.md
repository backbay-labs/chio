# chio-listing architecture

## Overview

`chio-listing` is a pure data and validation crate: no I/O, no runtime
state, `#![forbid(unsafe_code)]`. It sits in the economy layer of the
dependency graph, consumed by `chio-open-market`, `chio-governance`, and
`chio-federation` (each re-exports it internally as `listing`) and
re-exported again by `chio-core` as `chio_core::listing`. Its design splits
visibility from trust: listings are freely signable, discoverable, and
comparable, but nothing in the listing, search, or discovery surface can
itself grant runtime trust. Only the `trust_activation` evaluator can set
`admitted = true`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Facade. Declares `pub mod discovery`, re-exports `chio-core-types` (`MonetaryAmount`, `canonical_json_bytes`, `crypto`, `receipt`), and flattens the four private modules below to the crate root via `pub use *`. |
| `src/listing.rs` (private) | Signed listing and namespace artifacts: `GenericListingArtifact`, `GenericNamespaceArtifact`, ownership, boundary, actor/status/lifecycle enums, `GenericListingQuery`, `GenericListingReport`. |
| `src/search.rs` (private) | Network-search result and freshness types: `GenericListingFreshnessWindow`, `GenericListingSearchPolicy`, `GenericListingReplicaFreshness`, `GenericListingSearchResult`, `GenericListingDivergence`, `GenericListingSearchResponse`. |
| `src/util.rs` (private) | Shared validation and normalization helpers plus the report-aggregation engine, `aggregate_generic_listing_reports`. |
| `src/discovery.rs` (public) | Capability marketplace layer: signed `ListingPricingHint` / `ListingSla`, `Listing`, `search`, `compare`, `resolve_admissible_listing`, `provider_signing_key`. |
| `src/trust_activation.rs` (private) | Local trust-activation artifact, eligibility policy, `build_generic_trust_activation_artifact`, `evaluate_generic_trust_activation`. |
| `src/tests.rs` | `#[cfg(test)]` regression coverage for listing, namespace, aggregation, and trust-activation invariants. |

"(private)" modules are declared with `mod`, not `pub mod`: their items are
reachable only through the crate-root re-export, never a qualified path
like `chio_listing::listing::...`. `discovery` is `pub mod`, so
`chio_listing::discovery::search` and the root re-export `chio_listing::search`
name the same function.

## Discovery-to-admission flow

1. **Publish.** A namespace owner signs a `GenericListingArtifact` (or
   `GenericNamespaceArtifact`) into a `SignedGenericListing` /
   `SignedGenericNamespace` (`SignedExportEnvelope`, from `chio-core-types`).
   The artifact's `GenericListingBoundary` fixes it as visibility-only.
2. **Aggregate.** A publisher bundles its listings into a
   `GenericListingReport`. `aggregate_generic_listing_reports` verifies
   every report and listing signature, drops stale reports, groups
   same-identity listings across publishers by actor and compatibility
   source, flags cross-publisher disagreement as a
   `GenericListingDivergence`, and ranks survivors by freshness, publisher
   role, and recency into a `GenericListingSearchResponse`.
3. **Discover.** `discovery::search` calls step 2 internally, pairs each
   surviving listing with a live, signature-verified
   `SignedListingPricingHint` whose signer and provider id are bound to the
   listing's namespace-ownership authority, filters by scope, price, and
   provider, and ranks by price, revocation rate, and receipt volume into a
   `ListingSearchResponse`. `discovery::compare` normalizes a result set
   into `price_index_bps` rows.
4. **Activate.** `build_generic_trust_activation_artifact` builds a
   locally-signed `GenericTrustActivationArtifact` binding an operator's
   admission decision to one listing's identity and body hash.
   `evaluate_generic_trust_activation` later re-verifies that binding and
   the activation's own signature against a caller-supplied trusted key,
   checks freshness, expiry, and disposition, and applies the eligibility
   policy before setting `admitted = true`.

## Invariants and failure modes

- `GenericListingBoundary::validate()` and `GenericListingSearchPolicy::validate()`
  fail closed unless `visibility_only` and `explicit_trust_activation_required`
  are true and `automatic_trust_admission` is false: a listing or search
  policy can never assert its own automatic trust admission.
- `aggregate_generic_listing_reports` never panics on a bad report; it turns
  schema mismatches, invalid publisher or freshness data, non-reproducible
  search policy, namespace-ownership conflicts, and listing signature or
  signer mismatches into `GenericListingSearchError` entries and drops the
  report instead.
- Same-identity listings that disagree across publishers on source-artifact
  hash, status, or namespace ownership are reported as a
  `GenericListingDivergence` and excluded from results rather than resolved
  by majority vote.
- `discovery::search` drops any listing without a structurally valid,
  signature-verified, live pricing hint whose authority is bound to it: the
  hint's signer key and provider id must equal the listing's
  namespace-ownership signer key and owner id. The function does not panic;
  every rejection lands in `ListingSearchResponse::errors`.
- `evaluate_generic_trust_activation` fails closed at every stage:
  unverifiable listing or activation signatures, an untrusted activation
  signer, listing/activation identity mismatch, stale or divergent
  freshness, expiry, a non-`Approved` disposition, actor/publisher/status/
  operator ineligibility, the `PublicUntrusted` admission class, and
  `require_bond_backing` all short-circuit to `admitted = false` with a
  `GenericTrustActivationFindingCode`.
- `ListingPricingHint` currency codes must be exactly three uppercase ASCII
  letters, so marketplace price comparison cannot split buckets on case.

## Dependencies

Internal: `chio-core-types` is the only internal dependency. It supplies
`crypto` (`PublicKey`, `Keypair`, `sha256_hex`, signing and verification),
`receipt::lineage::SignedExportEnvelope` (the signed-artifact envelope every
`Signed*` type alias in this crate wraps), `canonical_json_bytes` (used both
for signing and for the listing and activation content hashes), and
`capability::scope::MonetaryAmount`. External: `serde` only, for artifact
(de)serialization.

## Boundaries

The crate holds no key registry, policy store, or PKI of its own.
`evaluate_generic_trust_activation` takes the trusted local-activation
signer as a caller-supplied argument instead of looking one up internally,
so key management and activation policy stay the caller's responsibility.
