# chio-appraisal

Runtime attestation appraisal artifacts and deterministic marketplace pricing
for the Chio protocol. It turns vendor-specific runtime attestation evidence
into a portable, signed appraisal artifact, evaluates imported signed
appraisal results against local trust policy without ever widening it, and
prices marketplace guard invocations from a manifest base price and a
tenant's reputation tier.

The crate is pure data, validation, and cryptography: no I/O, no runtime
state, `#![forbid(unsafe_code)]`. `chio-core` re-exports it as
`chio_core::appraisal`; `chio-kernel`, `chio-underwriting`, `chio-credit`, and
`chio-market` build on its types.

## Responsibilities

- Derive a portable `RuntimeAttestationAppraisal` from vendor-specific
  evidence (Azure MAA, AWS Nitro, Google Confidential VM, enterprise
  verifiers) and verify it into a `VerifiedRuntimeAttestationRecord` against
  an optional local `AttestationTrustPolicy`.
- Evaluate an imported, signed `RuntimeAttestationAppraisalResult` against
  local import policy, producing a fail-closed `Allow` / `Attenuate` /
  `Reject` disposition.
- Publish static catalogs: the supported-verifier-family artifact inventory,
  the normalized-claim vocabulary, and the appraisal reason-code taxonomy.
- Build, validate, and verify signed export envelopes for verifier
  descriptors, reference-value sets, and trust bundles.
- Compute deterministic per-invocation marketplace prices from a guard
  manifest base price and a tenant reputation tier.

## Public API

Appraisal (`appraisal`, `types`):

- `derive_runtime_attestation_appraisal`, `verify_runtime_attestation_record`,
  `evaluate_imported_runtime_attestation_appraisal` - the evaluation entry
  points.
- `RuntimeAttestationAppraisal`, `VerifiedRuntimeAttestationRecord`,
  `RuntimeAttestationAppraisalResult`, `RuntimeAttestationImportedAppraisalPolicy`,
  `RuntimeAttestationAppraisalImportReport` - artifact and report types.
- Per-family schema constants, for example `AZURE_MAA_ATTESTATION_SCHEMA`,
  `AWS_NITRO_ATTESTATION_SCHEMA`, `GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA`,
  `ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA`.

Static catalogs (`artifact_inventory`):

- `runtime_attestation_appraisal_artifact_inventory`,
  `runtime_attestation_normalized_claim_vocabulary`,
  `runtime_attestation_reason_taxonomy`, `verifier_family_for_attestation_schema`.

Signed export artifacts (`descriptor`):

- `create_signed_runtime_attestation_verifier_descriptor` /
  `verify_signed_runtime_attestation_verifier_descriptor`, args in
  `RuntimeAttestationVerifierDescriptorArgs`.
- `create_signed_runtime_attestation_reference_value_set` /
  `verify_signed_runtime_attestation_reference_value_set`, args in
  `RuntimeAttestationReferenceValueSetArgs`.
- `create_signed_runtime_attestation_trust_bundle` /
  `verify_signed_runtime_attestation_trust_bundle` (returns
  `RuntimeAttestationTrustBundleVerification`), args in
  `RuntimeAttestationTrustBundleArgs`.
- Each `create_*` returns a `SignedRuntimeAttestation*` envelope
  (`SignedExportEnvelope<T>` from `chio-core-types`).

Marketplace pricing (`marketplace_pricing`):

- `compute_checked_marketplace_invocation_price` - validates first; the
  settlement-facing entry point.
- `compute_marketplace_invocation_price` - unchecked, for already-validated
  input.
- `MarketplaceBasePrice`, `MarketplacePricingContext`,
  `MarketplaceReputationTier`, `TIER_DISCOUNT_PER_HUNDRED`.

Re-exported from `chio-core-types`: `canonical`, `capability`, `crypto`,
`error`, `receipt`, `Error`, `AttestationVerifierFamily`.

## Usage

```rust
use chio_appraisal::{
    compute_checked_marketplace_invocation_price, MarketplaceBasePrice,
    MarketplacePricingContext, MarketplaceReputationTier,
};

fn price_for_tenant() -> Result<(), chio_appraisal::MarketplacePricingError> {
    let base = MarketplaceBasePrice::try_new(1_000, "USD")?;
    let ctx = MarketplacePricingContext::try_new("tenant-a", MarketplaceReputationTier::Tier1)?;
    let price = compute_checked_marketplace_invocation_price(&base, &ctx)?;
    assert_eq!(price.units, 950);
    Ok(())
}
```

## Testing

`cargo test -p chio-appraisal`

## See also

- `chio-core` - re-exports this crate as `chio_core::appraisal`.
- `chio-kernel` - consumes `VerifiedRuntimeAttestationRecord` for governed
  validation and receipt scopes/metadata.
- `chio-underwriting`, `chio-credit`, `chio-market` - build marketplace and
  credit logic on these appraisal and pricing types.
- `chio-cli` - the `guard market` subcommands price catalog entries through
  the checked pricing boundary.
