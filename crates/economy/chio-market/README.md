# chio-market

chio-market defines Chio's liability-insurance contracts: a chain of signed artifacts running from
provider registration through quote, placement, bound coverage, claims, and settlement, plus a
lightweight `insurance_flow` for binding a policy and filing a claim without the full artifact
chain. It builds on `chio-credit` (risk, facility, and capital types) and `chio-underwriting`
(premium pricing); `chio-core` and `chio-autonomy` re-export it as `market`, extending its types
into `chio-kernel`. The crate forbids unsafe code and performs no I/O.

## Responsibilities

- Define the liability-market artifact chain: provider registry, quote request/response, delegated
  pricing authority, placement, bound coverage, claim package through adjudication, and payout and
  settlement instructions/receipts, each a `SignedExportEnvelope<T>` with a fail-closed `validate()`.
- Provide `LiabilityMarketWorkflowReport` and `LiabilityClaimWorkflowReport` query/row/summary types
  for listing rows through the chain.
- Provide `insurance_flow`: `quote_and_bind` prices and binds a `BoundPolicy` from a `PremiumSource`;
  `BoundPolicy::file_claim` verifies a claim's receipt fingerprints against kernel-signed evidence
  and hands an approved claim to a `ClaimSettlementSink` as a `ClaimSettlementRequest`.
- Re-export `chio-appraisal`, `chio-credit`, `chio-underwriting` (as `appraisal`, `credit`,
  `underwriting`) and `chio-core-types`' `capability`, `crypto`, `receipt` modules.

## Public API

All types below are re-exported flat at the crate root (`chio_market::TypeName`); the left column is
the source file, not an import path. `insurance_flow` is also a public module.

| Source | Key types |
|---|---|
| `provider.rs` | `LiabilityProviderReport`, `LiabilityProviderArtifact` / `SignedLiabilityProvider`, `LiabilityProviderListQuery` / `LiabilityProviderListReport`, `LiabilityProviderResolutionQuery` / `LiabilityProviderResolutionReport` |
| `quote.rs` | `LiabilityProviderPolicyReference`, `LiabilityQuoteRequestArtifact`, `LiabilityQuoteResponseArtifact`, `LiabilityPricingAuthorityArtifact` |
| `placement.rs` | `LiabilityPlacementArtifact`, `LiabilityBoundCoverageArtifact`, `LiabilityAutoBindDecisionArtifact` |
| `claim.rs` | `LiabilityClaimPackageArtifact`, `LiabilityClaimResponseArtifact`, `LiabilityClaimDisputeArtifact`, `LiabilityClaimAdjudicationArtifact` |
| `settlement.rs` | `LiabilityClaimPayoutInstructionArtifact`, `LiabilityClaimPayoutReceiptArtifact`, `LiabilityClaimSettlementInstructionArtifact`, `LiabilityClaimSettlementReceiptArtifact`, `LiabilityClaimWorkflowQuery` / `LiabilityClaimWorkflowReport` |
| `workflow.rs` | `LiabilityMarketWorkflowQuery`, `LiabilityMarketWorkflowReport` |
| `insurance_flow` | `quote_and_bind`, `BoundPolicy`, `ClaimEvidence`, `ClaimDecision`, `ClaimSettlementRequest`, traits `PremiumSource`, `ReceiptEvidenceSource`, `ClaimSettlementSink` |

Each `Liability*Artifact` chain type also has a `Signed<Name>` alias (`SignedExportEnvelope<T>`) and
a `.validate()` method. `LIABILITY_*_SCHEMA` constants pin each artifact's wire `schema` field;
`MAX_LIABILITY_{PROVIDER_LIST,MARKET_WORKFLOW,CLAIM_WORKFLOW}_LIMIT` (all 100) bound query limits.

## Usage

```rust
use chio_market::{quote_and_bind, StaticPremiumSource};
use chio_underwriting::{LookbackWindow, PremiumInputs};

let source = StaticPremiumSource::new(PremiumInputs::new(Some(950), None, 1_000, "USD"));
let window = LookbackWindow::new(1_000_000, 1_000_600)?;
let policy = quote_and_bind("agent-1", "tool:exec", window, &source, 1_000_600, 30 * 86_400)?;
```

`BoundPolicy::file_claim` then verifies a `ClaimEvidence` payload's receipt fingerprints through a
caller-supplied `ReceiptEvidenceSource` and, on approval, submits a `ClaimSettlementRequest` to a
caller-supplied `ClaimSettlementSink`.

## Testing

`cargo test -p chio-market`

## See also

- `chio-credit` - supplies the risk package, facility, capital book, and capital execution types
  embedded throughout the quote, placement, and settlement chain.
- `chio-underwriting` - supplies `price_premium` and the underwriting-decision types used by
  `LiabilityPricingAuthorityArtifact` and `insurance_flow`.
- `chio-core`, `chio-autonomy` - re-export this crate as `market`; `chio-kernel` reaches these types
  through `chio_core::market`.
- `chio-settle` - not a dependency of this crate (would create a cycle); `ClaimSettlementRequest` is
  a field-compatible projection of its `SettlementCommitment` that callers copy across.
