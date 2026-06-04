# chio-appraisal Architecture

## Owner

`chio-appraisal` owns portable runtime-attestation appraisal artifacts and the deterministic marketplace invocation-pricing model derived from those artifacts. It is a pure evaluation crate: it does not fetch evidence, mutate ledgers, settle payments, or read marketplace catalogs.

## Module Boundaries

- `types` defines wire structs, schema constants, appraisal result envelopes, trust-bundle documents, and marketplace-neutral attestation taxonomy.
- `appraisal` derives portable appraisal artifacts from verified runtime evidence and evaluates imported signed appraisal results against local policy.
- `artifact_inventory` publishes static inventories for supported verifier families, normalized claims, and reason taxonomy.
- `descriptor` signs and verifies descriptor, reference-value, and trust-bundle export envelopes.
- `validate` enforces descriptor, reference-value, and trust-bundle structural invariants before signed artifacts are trusted.
- `marketplace_pricing` computes deterministic per-invocation prices from a manifest base price plus tenant reputation tier.

## Pain Points

- The unchecked pricing helper treats tenant ids and currency as caller-validated input. Catalog callers that need settlement-grade pricing must use the checked boundary so empty or padded tenant ids and non-canonical currency codes fail closed before prices are persisted.
- The existing `compute_marketplace_invocation_price` API returns a value rather than a `Result`, so hardening the public function directly would break current callers.
- Downstream marketplace CLI code persists computed prices into install records, so pricing input validation has to fail closed before those records are written.

## Security And API Constraints

- Appraisal derivation and pricing must remain deterministic pure functions of their explicit inputs.
- Imported appraisal evaluation must not widen local runtime-assurance policy.
- Signed appraisal, descriptor, reference-value, and trust-bundle artifacts must keep canonical JSON byte stability.
- Marketplace prices must use stable minor-unit integer arithmetic and must not introduce floating-point rounding.
- Public API compatibility must be preserved. New checked APIs may be added, but existing call signatures should not be removed or changed without approval.

## Affected Dependents

`crates/chio-cli/src/market.rs` consumes marketplace pricing for `guard market list`, `info`, and `install`. The CLI catalog path uses the checked API so malformed catalog prices fail closed instead of being displayed or persisted. Trust-control startup separately validates tenant read-token ids because those tenant principals participate in read-boundary authorization.

## Completed Material Improvement

Add checked pricing constructors and a checked invocation-pricing API that validate tenant id shape and ISO-style uppercase currency codes. Keep the existing unchecked compute function for compatibility, then move settlement-facing marketplace callers onto the checked API.

## Verification Focus

Tests should cover appraisal determinism, signed descriptor and trust-bundle
round trips, imported appraisal policy rejection, checked pricing rejection for
empty or padded tenant ids, uppercase currency enforcement, integer minor-unit
pricing stability, and CLI marketplace paths that persist checked prices rather
than unchecked catalog values.
