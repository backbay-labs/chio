# chio-market Architecture

## Boundaries

`chio-market` owns Chio's liability-market contract types: provider admission records, quote requests and responses, delegated pricing authority, placement and bound coverage, claim packages and responses, claim adjudication, payout instructions, payout receipts, settlement instructions, settlement receipts, and the small insurance-flow adapter that bridges underwriting into settlement-shaped requests.

The main internal areas are:

- `provider.rs`: curated provider registry reports and provider-list queries.
- `quote.rs`: provider policy references, quote request/response artifacts, and pricing-authority artifacts.
- `placement.rs`: placement, bound coverage, and auto-bind decision artifacts.
- `claim.rs`: claim packages, provider responses, disputes, and adjudications.
- `settlement.rs`: payout and settlement instruction/receipt artifacts.
- `workflow.rs`: market and claim workflow query/report types.
- `insurance_flow.rs`: high-level quote, bind, claim verification, and settlement request handoff without depending on `chio-settle`.
- `tests.rs`: root-level regression coverage for provider, quote, placement,
  claim, payout, settlement, and workflow validators.

## Claim Validation Boundary

`ClaimEvidence` and `ClaimSettlementRequest` own validation for the lightweight insurance-flow path, and `BoundPolicy::file_claim` calls that validation before receipt lookup or settlement handoff. The validation rejects empty or padded claim identifiers, empty incident descriptions, non-positive or invalid requested amounts, missing settlement chain ids, empty settlement request fields, non-claim settlement lanes, zero settlement amounts, and empty receipt fingerprints before the insurance flow can submit a settlement request. `ClaimSettlementRequest` is field-compatible with `chio_settle::SettlementCommitment`, so these checks run at the `chio-market` boundary rather than depending on any sink or settlement runtime to reject malformed requests.

## Security And API Constraints

- Public struct shapes and signed artifact compatibility are preserved.
- The crate takes no hard dependency on `chio-settle`; the crate graph intentionally avoids that cycle.
- Settlement handoff is explicit. Insurance claims may request settlement, but they do not imply ambient settlement authority.
- Claim behavior is fail-closed: malformed evidence does not submit settlement requests.
- Policy ids are deterministic, and quote/bind behavior is stable for valid inputs.

## Dependent Surfaces

`chio-kernel`, `chio-control-plane`, and tests treat `ClaimSettlementRequest` as a field-compatible settlement commitment.
