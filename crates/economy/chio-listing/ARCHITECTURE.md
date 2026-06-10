# chio-listing Architecture

## Boundary

`chio-listing` owns Chio's generic listing, discovery, search, comparison, and trust-activation contracts. It is the publishing and admission boundary for marketplace listings before governance, open-market, federation, or runtime components consume them.

## Internal Surfaces

The crate is split between core listing artifacts, search/report aggregation, marketplace discovery with signed pricing hints, shared validation helpers, and the trust-activation flow. Listings are signed by namespace owners, reports aggregate verified listings from publishers, and activation artifacts convert visible listings into locally reviewed trust decisions.

## Source Layout

- `src/lib.rs` is the crate export map.
- `src/listing.rs` owns signed listing and namespace artifacts.
- `src/search.rs` owns generic report aggregation and query normalization.
- `src/discovery.rs` owns marketplace discovery, comparison, and pricing hints.
- `src/trust_activation.rs` owns local admission review artifacts and
  evaluation.
- `src/util.rs` owns shared validation and signature helpers.
- `src/tests.rs` owns root-level regression coverage for the listing and
  activation surfaces.

## Trust Invariants

The security constraint is visibility without ambient admission. A listing may be discoverable, searchable, and comparable, but it cannot imply runtime trust unless the explicit activation path validates freshness, publisher role, status, signer authority, and local review requirements.

## Verification Focus

Tests should distinguish listing visibility from activation, reject stale signed listings, validate publisher role and signer authority, and keep pricing-hint normalization exact. Search and comparison tests should keep unauthenticated visibility separate from local activation, because marketplace discovery is intentionally weaker than runtime trust.

Signed pricing hints require exact uppercase 3-letter currency codes so marketplace search and comparison cannot split price buckets through lowercase money identifiers. The crate rejects malformed hint data before governance or open-market code can rank, compare, or persist it as canonical economic evidence.
