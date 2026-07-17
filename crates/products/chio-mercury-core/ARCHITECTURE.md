# chio-mercury-core architecture

## Overview

`chio-mercury-core` is a pure data and validation crate: serde types, fail-closed
`validate()` methods, and canonical-hash helpers. It has no I/O and no runtime
state of its own. It sits above `chio-kernel` in the stack: it does not evaluate
policy or mint receipts, it defines a business-evidence envelope that rides
inside receipts `chio-kernel` has already signed, and it re-verifies exported
evidence bundles (signatures, checkpoints, inclusion proofs) rather than
re-deriving trust decisions. The design has two parts: an envelope
(`MercuryReceiptMetadata` under `receipt.metadata.mercury`) that lets Mercury
data ride on Chio receipts without Chio knowing about Mercury, and a linear
chain of 17 schema-versioned "lane" packages that gate each stage of a
customer-adoption and account-expansion lifecycle on the validated evidence of
the stage before it.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module list and flat re-export of every module's types. |
| `src/validation.rs` | Private. `ensure_non_empty` / `ensure_optional_non_empty` reject empty and whitespace-padded strings. Used only by `receipt_metadata.rs`, `bundle.rs`, `proof_package.rs`. |
| `src/receipt_metadata.rs` | `MercuryReceiptMetadata` envelope and the shared `MercuryContractError`; embeds in and extracts from `ChioReceipt.metadata`. |
| `src/bundle.rs` | `MercuryBundleManifest`, `MercuryArtifactReference`, `MercuryBundleReference`; canonical bytes and sha256 manifest digest. |
| `src/proof_package.rs` | `MercuryProofPackage` / `MercuryInquiryPackage`: builds and verifies against a Chio `EvidenceExportBundle` (receipt and checkpoint signatures, inclusion proofs, publication claims). |
| `src/query.rs` | `MercuryReceiptQuery` filter shape and `MercuryReceiptIndexRecord` projection. No storage. |
| `src/fixtures.rs` | Public sample `MercuryReceiptMetadata` / `MercuryBundleManifest`, valid under the real validators. |
| `src/pilot.rs` | `MercuryPilotScenario::gold_release_control()`: a scripted propose/approve/release/inquiry path plus a rollback variant. |
| `src/supervised_live.rs` | `MercurySupervisedLiveCapture`: release/rollback gate state, evidence-health, and coverage tracking over a `MercuryPilotScenario`-derived step sequence; fails closed on export readiness. |
| `src/governance_workbench.rs` | `MercuryGovernanceDecisionPackage` / `MercuryGovernanceReviewPackage`: workflow-owner and control-team review over a change-class set. |
| `src/assurance_suite.rs` | `MercuryAssuranceSuitePackage`: per-reviewer-population (internal/auditor/counterparty) disclosure, review, and investigation artifacts, gated on a governance-decision package. `MercuryAssuranceReviewerPopulation` is reused by `trust_network.rs` and `embedded_oem.rs`. |
| `src/downstream_review.rs` | `MercuryAssurancePackage` (audience-scoped disclosure) and `MercuryDownstreamReviewPackage` (role-keyed delivery to an external consumer). Not part of the lane chain. |
| `src/embedded_oem.rs` | `MercuryEmbeddedOemPackage`: partner/SDK-embedded reviewer surface, gated on an assurance-suite and a governance-decision package. |
| `src/trust_network.rs` | `MercuryTrustNetworkPackage`: counterparty proof/inquiry exchange over a checkpoint witness chain, gated on an embedded-OEM package. |
| `src/release_readiness.rs` | `MercuryReleaseReadinessPackage`: reviewer/partner/operator delivery, gated on trust-network and assurance-suite packages. |
| `src/controlled_adoption.rs` | `MercuryControlledAdoptionPackage`: design-partner renewal cohort, gated on release-readiness. |
| `src/reference_distribution.rs` | `MercuryReferenceDistributionPackage`: landed-account reference bundle, gated on controlled-adoption. |
| `src/broader_distribution.rs` | `MercuryBroaderDistributionPackage`: governed multi-account distribution, gated on reference-distribution. |
| `src/selective_account_activation.rs` | `MercurySelectiveAccountActivationPackage`: controlled per-account delivery, gated on broader-distribution. |
| `src/delivery_continuity.rs` | `MercuryDeliveryContinuityPackage`: outcome-evidence renewal gate, gated on selective-account-activation. |
| `src/renewal_qualification.rs` | `MercuryRenewalQualificationPackage`: outcome review and renewal decision, gated on delivery-continuity. |
| `src/second_account_expansion.rs` | `MercurySecondAccountExpansionPackage`: portfolio review for a second account, gated on renewal-qualification. |
| `src/portfolio_program.rs` | `MercuryPortfolioProgramPackage`: program-level review spanning the expansion/renewal/continuity lanes. |
| `src/second_portfolio_program.rs` | `MercurySecondPortfolioProgramPackage`: portfolio reuse review, gated on portfolio-program. |
| `src/third_program.rs` | `MercuryThirdProgramPackage`: multi-program reuse review, gated on second-portfolio-program. |
| `src/program_family.rs` | `MercuryProgramFamilyPackage`: shared review across a program family, gated on third-program. |
| `src/portfolio_revenue_boundary.rs` | `MercuryPortfolioRevenueBoundaryPackage`: commercial/revenue-boundary review, gated on program-family. |

## Escalation chain

Every lane module pairs intent (a `<Name>Profile`: cohort, gate, retained-artifact
policy) with evidence (a `<Name>Package`: owners, a `fail_closed: bool` that
`validate()` asserts is `true`, and named references to the prior lane's package
files). The chain is linear:

```
governance_workbench -> assurance_suite -> embedded_oem -> trust_network
  -> release_readiness -> controlled_adoption -> reference_distribution
  -> broader_distribution -> selective_account_activation -> delivery_continuity
  -> renewal_qualification -> second_account_expansion -> portfolio_program
  -> second_portfolio_program -> third_program -> program_family
  -> portfolio_revenue_boundary
```

Cross-lane references (`release_readiness_package_file`, `proof_package_file`,
and similar `*_file` fields) are non-empty path strings only: `validate()` never
opens or hashes the referenced file, so lane-to-lane chaining is a declared
pointer, not a cryptographic binding. Only `bundle.rs` (`manifest_sha256`) and
`proof_package.rs` (`evidence_export_manifest_hash`, `rendered_export_sha256`)
bind content by digest.

## Invariants and failure modes

- Every `validate()` compares its `schema` field against a `MERCURY_*_SCHEMA`
  constant first and returns `InvalidSchema` on mismatch.
- `MercuryWorkflowIdentifiers` optional business identifiers (account, desk,
  strategy, release, rollback, exception, inquiry) must be absent or non-empty
  and unpadded, enforced through the shared `validation::ensure_non_empty`.
- Every lane and review module outside `receipt_metadata.rs` / `bundle.rs` /
  `proof_package.rs` defines its own private `ensure_non_empty` that rejects
  only empty strings, not padding. None of them route through
  `validation::ensure_non_empty`; this is duplication with a narrower behavior,
  not a deliberate relaxation.
- Lane packages assert their `fail_closed` (and similar `*_required`) booleans
  are literally `true`; `validate()` accepts no other value.
- Artifact lists are checked for duplicate `artifact_kind` (in
  `assurance_suite.rs`, duplicate `(reviewer_population, artifact_kind)` pairs)
  via `HashSet`. `assurance_suite.rs` and `release_readiness.rs` additionally
  require every declared population or audience to have a complete artifact set.
- `proof_package.rs::verify_chio_bundle` fails closed on duplicate receipt,
  checkpoint, or lineage sequence numbers, unverifiable receipt or checkpoint
  signatures, an unsupported checkpoint schema, missing inclusion proofs when
  required, an inclusion-proof root mismatch, and any mismatch between declared
  and derived uncheckpointed receipts.
- `MercuryPublicationProfile.checkpoint_continuity = "append_only"` requires a
  non-empty `trust_anchor` and a `checkpoint_transparency` record anchored to
  it; `audit_only` and `transparency_preview` reject a populated trust anchor.
- `MercurySupervisedLiveCapture::ensure_export_ready` fails closed unless
  `coverage_state` is `Covered`, `evidence_health` is fully healthy, and any
  release or rollback step's gate is `Approved`.

## Dependencies

- `chio-core` is aliased to `chio-core-types`
  (`path = "../../core/chio-core-types"` in `Cargo.toml`): `chio_core::` in this
  crate's source is the protocol types crate (canonical JSON, sha256,
  `ChioReceipt`, Merkle proofs), not the `chio-core` facade crate of the same
  name.
- `chio-kernel` supplies checkpoint construction and verification
  (`checkpoint::{validate_checkpoint_transparency,
  verify_checkpoint_transparency_records, build_checkpoint, build_inclusion_proof,
  ...}`, `verify_checkpoint_signature`, `is_supported_checkpoint_schema`) and
  `evidence_export::EvidenceExportBundle`. Used only by `proof_package.rs`.
- `serde` / `serde_json` for the schema-tagged, camelCase package and profile
  shapes. `thiserror` derives `MercuryContractError`.
