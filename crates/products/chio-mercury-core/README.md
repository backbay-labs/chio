# chio-mercury-core

Typed MERCURY evidence contracts layered on Chio receipt truth. MERCURY targets
AI-assisted execution workflow release control: business identifiers such as
`desk_id` and `strategy_id`, and the `contains_market_data` sensitivity flag,
scope it to trading-desk operations. This crate owns the data shapes and
fail-closed validation; command orchestration, storage, and file export live in
`chio-mercury`.

## Responsibilities

- Define `MercuryReceiptMetadata`, the schema-tagged envelope that rides inside a
  signed Chio receipt's `metadata.mercury` field: workflow identifiers, decision
  context, chronology, provenance, sensitivity, disclosure, and approval state.
- Define bundle manifests (`bundle.rs`) with canonical-JSON sha256 digests for the
  artifact sets a receipt's metadata can reference.
- Build and verify `MercuryProofPackage` / `MercuryInquiryPackage` against a Chio
  `EvidenceExportBundle`: receipt and checkpoint signatures, inclusion proofs, and
  checkpoint-transparency publication claims.
- Define 17 schema-versioned "lane" packages, from `governance_workbench` through
  `portfolio_revenue_boundary`, that model an escalating customer-adoption and
  account-expansion chain; each lane's package validates `fail_closed = true` and
  points by file-path reference to its upstream lane's package.
- Provide fixture builders and a scripted pilot / supervised-live scenario
  (`fixtures.rs`, `pilot.rs`, `supervised_live.rs`) used by this crate's own tests.

## Public API

Evidence primitives:
- `receipt_metadata::{MercuryReceiptMetadata, MercuryWorkflowIdentifiers,
  MercuryDecisionContext, MercuryChronology, MercuryProvenance, MercurySensitivity,
  MercuryDisclosurePolicy, MercuryApprovalState, MercuryContractError}`
- `bundle::{MercuryBundleManifest, MercuryArtifactReference, MercuryBundleReference}`
- `proof_package::{MercuryProofPackage, MercuryInquiryPackage,
  MercuryPublicationProfile, MercuryVerificationReport}`
- `query::{MercuryReceiptQuery, MercuryReceiptIndexRecord}` - filter and index
  shapes; this crate does no storage or lookups itself.

Fixtures and scenarios:
- `fixtures::{sample_mercury_receipt_metadata, sample_mercury_bundle_manifest}`
- `pilot::MercuryPilotScenario::gold_release_control()` - a scripted
  propose/approve/release/inquiry path plus a rollback variant.
- `supervised_live::{MercurySupervisedLiveCapture, MercurySupervisedLiveControlState}`

Review, governance, and trust packages:
- `governance_workbench::{MercuryGovernanceDecisionPackage, MercuryGovernanceReviewPackage}`
- `assurance_suite::{MercuryAssuranceSuitePackage, MercuryAssuranceReviewPackage,
  MercuryAssuranceInvestigationPackage, MercuryAssuranceReviewerPopulation}`
- `downstream_review::{MercuryAssurancePackage, MercuryDownstreamReviewPackage}`
- `embedded_oem::MercuryEmbeddedOemPackage`
- `trust_network::MercuryTrustNetworkPackage`

Motion-lane packages (each a `<Name>Profile` + `<Name>Package` pair, schema
`chio.mercury.<name>_{profile,package}.v1`), in escalation order:
`release_readiness`, `controlled_adoption`, `reference_distribution`,
`broader_distribution`, `selective_account_activation`, `delivery_continuity`,
`renewal_qualification`, `second_account_expansion`, `portfolio_program`,
`second_portfolio_program`, `third_program`, `program_family`,
`portfolio_revenue_boundary`.

## Usage

```rust
use chio_mercury_core::{sample_mercury_receipt_metadata, MercuryReceiptMetadata};

let metadata = sample_mercury_receipt_metadata();
let value = metadata.into_receipt_metadata_value()?; // {"mercury": {...}}
let restored = MercuryReceiptMetadata::from_metadata_value(Some(&value))?;
assert_eq!(restored, Some(metadata));
```

## Testing

`cargo test -p chio-mercury-core`

## See also

- `chio-mercury` - CLI that builds, exports, and writes these packages to files;
  depends on this crate's builders and fixtures.
- `chio-core-types` - canonical JSON, hashing, and receipt types, imported here as
  `chio_core` (dependency aliased in `Cargo.toml`).
- `chio-kernel` - checkpoint and evidence-export verification consumed by
  `proof_package.rs`.
