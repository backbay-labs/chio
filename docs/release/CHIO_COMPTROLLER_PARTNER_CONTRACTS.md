# Chio Comptroller Partner Contracts

## Purpose

This document defines the partner-visible contract package for Chio's governed
economic evidence. It is the review surface a partner uses to decide what Chio
artifacts they can rely on for billing, settlement, dispute, reconciliation,
and audit.

## Authoritative Contract Families

Partners can review Chio's current contract package as four linked families:

1. Receipt and checkpoint evidence
   - governed receipts
   - kernel checkpoints
   - inclusion proofs
   - reconciliation state
2. Settlement and payment evidence
   - settlement reconciliation reports
   - payout and settlement instructions or receipts
   - capital execution and allocation artifacts where applicable
3. Risk and credit evidence
   - underwriting policy inputs, decisions, simulations, and appeals
   - exposure, scorecard, facility, bond, and loss-lifecycle artifacts
4. Liability and market evidence
   - provider registry, quote, placement, bound coverage
   - claim, response, dispute, adjudication, payout, and settlement artifacts

The authoritative machine-readable contract inventory is:

- [CHIO_COMPTROLLER_PARTNER_CONTRACT_PACKAGE.json](../standards/CHIO_COMPTROLLER_PARTNER_CONTRACT_PACKAGE.json)

## Degraded Path Treatment

Partners should treat governed Chio receipt-bearing paths as authoritative.

Legacy multi-language SDKs may expose degraded passthrough explicitly as
`allow_without_receipt`. Current protocol-facing middleware fails closed before
local side effects when the sidecar cannot produce and verify a receipt. Any
legacy degraded mode is not authoritative partner evidence for economic actions.

## Review Flow

1. Confirm the receipt and checkpoint contract semantics.
2. Confirm the settlement and reconciliation artifacts link back to governed
   receipt truth.
3. Confirm underwriting, credit, capital, and liability artifacts reference
   the same governed evidence base instead of ad hoc local state.
4. Confirm degraded compatibility modes remain clearly non-authoritative.

## Qualification Command

```bash
./scripts/qualify-comptroller-partner-contracts.sh
```

Review the resulting bundle under:

`target/release-qualification/comptroller-partner-contracts/`

## Boundaries

This document proves:

- Chio has a partner-consumable contract package over receipts, checkpoints,
  settlement, underwriting, credit, capital, and liability artifacts
- those contracts are typed, governed, and reviewable

This document does not prove:

- broad partner adoption in production
- that partners already depend on Chio as their unavoidable system of record
