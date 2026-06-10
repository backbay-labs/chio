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
- `tests` contains root module unit coverage for appraisal derivation, signed descriptor artifacts, trust bundles, and import-policy edge cases.

## Pricing API Surface

The crate exposes two invocation-pricing entry points. `compute_checked_marketplace_invocation_price` and the checked pricing constructors validate tenant id shape and ISO-style uppercase currency codes, failing closed before any settlement-grade price is computed. `compute_marketplace_invocation_price` returns a value rather than a `Result` and treats tenant ids and currency as caller-validated input; it remains for callers that already validate their inputs. Catalog callers that persist computed prices into install records use the checked boundary so empty or padded tenant ids and non-canonical currency codes fail closed before records are written.

## Security And API Constraints

- Appraisal derivation and pricing are deterministic pure functions of their explicit inputs.
- Imported appraisal evaluation does not widen local runtime-assurance policy.
- Signed appraisal, descriptor, reference-value, and trust-bundle artifacts keep canonical JSON byte stability.
- Marketplace prices use stable minor-unit integer arithmetic with no floating-point rounding.

## Affected Dependents

`crates/products/chio-cli/src/market.rs` consumes marketplace pricing for `guard market list`, `info`, and `install`. The CLI catalog path uses the checked API so malformed catalog prices fail closed instead of being displayed or persisted. Trust-control startup separately validates tenant read-token ids because those tenant principals participate in read-boundary authorization.

## Verification Focus

Tests should cover appraisal determinism, signed descriptor and trust-bundle
round trips, imported appraisal policy rejection, checked pricing rejection for
empty or padded tenant ids, uppercase currency enforcement, integer minor-unit
pricing stability, and CLI marketplace paths that persist checked prices rather
than unchecked catalog values.
