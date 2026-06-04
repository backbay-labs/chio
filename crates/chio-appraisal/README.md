# chio-appraisal

`chio-appraisal` provides Chio's runtime attestation appraisal artifacts and
marketplace pricing. It defines appraisal descriptors and an artifact
inventory, the attestation-verifier family taxonomy, and the marketplace
invocation-pricing model (`compute_marketplace_invocation_price`, base prices,
reputation tiers, and tier discounts).

Use this crate to appraise runtime attestation evidence and to derive
marketplace prices from it. The underwriting, credit, and market crates build
on these types.

Settlement-facing marketplace callers should use
`compute_checked_marketplace_invocation_price` plus the checked constructors on
`MarketplaceBasePrice` and `MarketplacePricingContext`. The older
`compute_marketplace_invocation_price` function remains available for callers
that already validated their inputs.
