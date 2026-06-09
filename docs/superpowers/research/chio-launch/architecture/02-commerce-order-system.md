# Commerce Order And Settlement Context

Status: architecture outline
Primary source: `../agent-drafts/02-commerce-order-settlement-context.md`
Confidence: high for architecture direction, moderate for external protocol naming and provider-specific payment details.

## Position

Autonomous commerce is not "agent calls a payment tool." It is a governed state machine that binds buyer intent, provider selection, quote, mandate, budget, payment, fulfillment, settlement, dispute, and reconciliation.

The launch contract should be `chio.commerce.order-context.v1`, not a demo-specific transcript.

## Core Aggregate

`chio.commerce.order-context.v1` contains:

- `order_id`
- `buyer_subject`
- `agent_subject`
- `merchant_or_provider_subject`
- `intent_ref`
- `provider_passport_ref`
- `reputation_snapshot_ref`
- `federation_trust_bundle_ref`
- `quote_ref`
- `mandate_or_approval_ref`
- `budget_reservation_ref`
- `payment_proof_ref`
- `fulfillment_ref`
- `settlement_packet_ref`
- `dispute_ref`
- `risk_report_ref`
- `event_log_digest`
- `current_state`
- `signature`

The aggregate is materialized from an append-only event log. The event log, not mutable in-memory state, is the verifier source of truth.

## State Machine

States:

1. `intent_recorded`
2. `provider_admitted`
3. `quote_bound`
4. `mandate_bound`
5. `budget_reserved`
6. `payment_challenged`
7. `payment_verified`
8. `fulfillment_requested`
9. `fulfillment_attested`
10. `settlement_packet_assembled`
11. `settlement_dispatched`
12. `settlement_observed`
13. `settlement_reconciled`
14. `completed`
15. `disputed`
16. `refunded`
17. `failed_closed`

Every transition must name:

- prior state;
- next state;
- actor;
- authority receipt;
- evidence refs;
- invariant checks;
- timestamp;
- signature or digest binding.

## External Evidence Projection

External protocols are evidence providers, not replacement authority.

- AP2 mandate refs can prove delegated commercial intent and authorization context.
- x402 challenge/verify/settle transcripts can prove payment requirement and verification context.
- ACP-Commerce delegated-payment bindings can prove shared payment token constraints and token usage context.
- Web3 settlement proof bundles can prove escrow, bond, tx, block, and finality context.

All are subordinate evidence under the Chio order context.

## Commerce Admission Gates

Gate 1: intent and capability admission.

- Verify buyer/agent authority.
- Verify spending cap and policy scope.
- Verify transaction purpose and time bound.

Gate 2: provider admission.

- Verify provider passport.
- Verify reputation snapshot.
- Verify federation trust root.
- Verify sanctions or deny-list policy where applicable.

Gate 3: quote binding.

- Bind amount, currency, expiry, merchant/provider, item/service, and order id.

Gate 4: mandate or approval.

- Bind AP2 mandate, Chio approval token, or ACP-Commerce delegated-payment token to the same order and amount constraints.

Gate 5: budget reservation.

- Reserve funds before payment verification or capture.

Gate 6: payment verification.

- Verify x402, delegated token, prepaid, hold/capture, or escrow proof.

Gate 7: fulfillment.

- Bind fulfillment request and result to the order and quote.

Gate 8: settlement packet and dispatch.

- Assemble dispatch packet only after prior gates pass.

Gate 9: observation and reconciliation.

- Settlement observer evidence is post-dispatch evidence. It must reconcile through a state transition, not mutate state by itself.

## Replay Ledger

`chio.commerce.event-log.v1` is append-only and replayable. The verifier must derive `current_state` from it.

Replay rejects:

- duplicate event ids;
- invalid state transition;
- mismatched order id;
- quote amount drift;
- expired mandate;
- budget overrun;
- payment proof for wrong merchant;
- settlement observer event without dispatch;
- reconciliation that does not bind the settlement packet.

## Passport Integration

`chio.commerce.order-passport.v1` is a compact reviewer artifact that summarizes:

- order identity;
- current state;
- authority chain;
- provider admission;
- quote and mandate;
- budget and payment;
- settlement and dispute posture;
- risk refs;
- redacted fields and selective disclosure policy;
- verifier verdict.

The Transaction Passport should reference the order passport and full order context.
