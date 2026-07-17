# chio-market architecture

## Overview

chio-market is a pure data crate in the economy layer: signed-artifact type definitions, schema
constants, and fail-closed validators for liability insurance over metered tool access. It forbids
unsafe code, performs no I/O, and holds no runtime state; every `validate()` operates on
already-constructed, in-memory artifacts and the signatures embedded in their `SignedExportEnvelope`
wrappers. Two independent paths reach a settled claim: a chain of cryptographically linked artifacts
meant for audit and cross-party exchange, and a lightweight `insurance_flow` path for direct,
in-process binding and claims against kernel-verified receipts.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Facade re-exports (`appraisal`, `credit`, `underwriting`, and `chio-core-types`' `capability`/`crypto`/`receipt`), the `LIABILITY_*_SCHEMA` / `MAX_LIABILITY_*_LIMIT` constants, and shared validation helpers (`validate_currency_code`, `validate_positive_money`, `verify_signed_artifact`, `bounded_market_query_limit`, `liability_claim_adjudication_payable_amount`). |
| `src/provider.rs` | Curated provider registry: `LiabilityProviderReport`, `LiabilityProviderArtifact`, list and resolution query/report types. |
| `src/quote.rs` | Provider policy reference, pricing authority envelope, quote request/response artifacts, and `LiabilityPricingAuthorityArtifact`. |
| `src/placement.rs` | `LiabilityPlacementArtifact`, `LiabilityBoundCoverageArtifact`, `LiabilityAutoBindDecisionArtifact`. |
| `src/claim.rs` | Claim package, provider response, dispute, and adjudication artifacts. |
| `src/settlement.rs` | Claim payout instruction/receipt and settlement instruction/receipt artifacts, plus claim-workflow query/report types. |
| `src/workflow.rs` | Market-workflow query/row/summary/report types. |
| `src/insurance_flow.rs` | `quote_and_bind`, `BoundPolicy`, `ClaimEvidence` / `ClaimDecision`, the `PremiumSource` / `ReceiptEvidenceSource` / `ClaimSettlementSink` traits, `ClaimSettlementRequest`. |
| `src/tests.rs` | `#[cfg(test)]` regression coverage for the artifact-chain validators. |

## Claim and coverage lifecycle

### Signed artifact chain

Each type after the first embeds its predecessor in a `SignedExportEnvelope`; `validate()`
re-verifies the embedded signature and recurses into the embedded artifact's own `validate()` before
checking its own fields:

1. `LiabilityQuoteRequestArtifact` embeds a `chio-credit` risk package and references a provider by
   copying `LiabilityProviderPolicyReference` fields (not signature-linked).
2. `LiabilityQuoteResponseArtifact` embeds the request.
3. `LiabilityPlacementArtifact` embeds a quoted (not declined) response.
4. `LiabilityBoundCoverageArtifact` embeds the placement.
5. `LiabilityClaimPackageArtifact` embeds the bound coverage plus a `chio-credit` exposure ledger,
   bond, and loss lifecycle.
6. `LiabilityClaimResponseArtifact`, `LiabilityClaimDisputeArtifact`, and
   `LiabilityClaimAdjudicationArtifact` each embed the previous.
7. `LiabilityClaimPayoutInstructionArtifact` embeds the adjudication plus a `chio-credit` capital
   execution instruction.
8. `LiabilityClaimPayoutReceiptArtifact`, `LiabilityClaimSettlementInstructionArtifact` (also embeds
   a capital book), and `LiabilityClaimSettlementReceiptArtifact` each embed the previous.

`LiabilityPricingAuthorityArtifact` branches off the quote request (embeds the request plus a
`chio-credit` facility, `chio-underwriting` decision, and capital book) for delegated auto-bind.
`LiabilityAutoBindDecisionArtifact` embeds that authority and the quote response; when it auto-binds,
it also embeds a placement and bound coverage, cross-validated for consistency with its own quote
response.

### insurance_flow path

`quote_and_bind` calls a caller-supplied `PremiumSource` (typically backed by kernel compliance and
behavioral signals), prices the premium via `chio_underwriting::price_premium`, and derives a
`BoundPolicy` with a deterministic `policy_id` (canonical-JSON hash of the agent, scope, quote, and
effective window) and a default coverage limit of 100x the quoted premium.
`BoundPolicy::file_claim` re-verifies each `ClaimEvidence` receipt fingerprint through a
caller-supplied `ReceiptEvidenceSource` against the kernel's signing key, denies on the first
unresolved, digest-mismatched, or signature-invalid receipt, caps the payout at the coverage limit,
and hands the result to a caller-supplied `ClaimSettlementSink` as a `ClaimSettlementRequest`. This
path does not touch the signed-artifact chain above.

## Invariants and failure modes

- Every artifact's `validate()` fails closed: malformed shape, unverifiable signatures, currency
  mismatches, amounts exceeding their parent's bound, and stale or inverted time windows all reject
  before the artifact is treated as valid.
- Chain artifacts re-verify every embedded `SignedExportEnvelope` signature and recursively call the
  embedded artifact's own `validate()`; a valid outer signature never shortcuts inner validation.
- `insurance_flow` denies rather than errors on evidence problems (`ClaimDecision::Denied`) but
  returns `Err(InsuranceFlowError::InvalidInput)` on malformed input before any settlement sink runs;
  a rejected path never submits a settlement request.
- `chio-market` takes no dependency on `chio-settle` (`chio-settle` -> `chio-core` -> `chio-autonomy`
  -> `chio-market` would cycle). `ClaimSettlementRequest` is a field-for-field projection of
  `chio_settle::SettlementCommitment` that callers copy across the boundary.
- Currency codes are validated as three-letter uppercase ISO-style strings wherever an artifact
  carries one.
- List and workflow query limits clamp through `bounded_market_query_limit`: unset defaults to 50,
  clamped into `[1, MAX_LIABILITY_*_LIMIT]` (100 for provider, market-workflow, and claim-workflow
  queries).

## Dependencies

Internal: `chio-core-types` supplies `MonetaryAmount`, `SignedExportEnvelope`, and the crypto and
canonical-JSON primitives every artifact and `insurance_flow` type builds on; `chio-credit` supplies
the risk package, facility, capital book, and capital execution types referenced throughout quote,
placement, and settlement; `chio-underwriting` supplies `price_premium`, `PremiumQuote`, and the
underwriting-decision types used by `LiabilityPricingAuthorityArtifact` and `insurance_flow`.
`chio-appraisal` is re-exported as `appraisal` but is not otherwise referenced by this crate's own
types. No dependency aliasing: all four are imported under their real crate names in `Cargo.toml`.
External: `serde` for artifact (de)serialization, `thiserror` for `InsuranceFlowError`.

## Extension points

`insurance_flow` defines three traits for callers to implement: `PremiumSource` (risk inputs for
pricing a premium), `ReceiptEvidenceSource` (resolve a claim's receipt fingerprints back to
kernel-signed evidence), and `ClaimSettlementSink` (submit an approved `ClaimSettlementRequest`,
typically bridging into `chio_settle::SettlementCommitment`).
