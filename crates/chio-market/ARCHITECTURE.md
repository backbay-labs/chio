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

## Pain Points

The full liability artifact path has many artifact validators, but the lightweight insurance-flow path can construct a `ClaimSettlementRequest` without an owning validation method on the request itself. That request is field-compatible with `chio_settle::SettlementCommitment`, so empty chain ids, zero settlement amounts, empty receipt references, or the wrong lane kind should be rejected by `chio-market` before any sink or settlement runtime sees the request.

## Security And API Constraints

- Preserve public struct shapes and signed artifact compatibility.
- Do not add a hard dependency on `chio-settle`; the crate graph intentionally avoids that cycle.
- Keep settlement handoff explicit. Insurance claims may request settlement, but they must not imply ambient settlement authority.
- Keep fail-closed claim behavior: malformed evidence must not submit settlement requests.
- Preserve deterministic policy ids and existing quote/bind behavior for valid inputs.

## Affected Dependents

`chio-kernel`, `chio-control-plane`, and tests can continue treating `ClaimSettlementRequest` as a field-compatible settlement commitment. The intended change is additive API hardening: add owning validation and call it inside `BoundPolicy::file_claim` before `ClaimSettlementSink::submit`.

## Material Improvement

`ClaimEvidence` and `ClaimSettlementRequest` own validation for the lightweight insurance-flow path, and `BoundPolicy::file_claim` calls that validation before receipt lookup or settlement handoff. The validation rejects empty or padded claim identifiers, empty incident descriptions, non-positive or invalid requested amounts, missing settlement chain ids, empty settlement request fields, non-claim settlement lanes, zero settlement amounts, and empty receipt fingerprints before the insurance flow can submit a settlement request.
