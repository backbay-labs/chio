# Agent 15 Commerce And Payments Debate

Date: 2026-06-09
Agent: 15
Role: autonomous commerce and payment-network strategist
Confidence: high on the launch gap, moderate on exact schema placement.

## Verdict

Chio should not add more rails before launch. That would make the homepage claim weaker, not stronger. The missing launch muscle is a verifier-grade merchant payment lifecycle that joins AP2 mandates, x402 payment requirements, ACP-Commerce checkout or delegated-payment tokens, PSP objects, refunds, disputes, chargebacks, fraud outcomes, transfer reversals, currency conversion, and recurring mandate use into the same order replay ledger.

AP2 already says the commerce protocol details are outside AP2, while AP2 mandates and receipts can be used as dispute evidence (https://ap2-protocol.org/ap2/specification/). x402 proves HTTP-native payment verification and settlement, including facilitator `/verify` and `/settle` flows (https://docs.x402.org/core-concepts/facilitator). ACP-Commerce keeps the merchant in control of order and payment systems (https://www.agenticcommerce.dev/docs/reference/checkout), and its Delegated Payment Spec says settlement, refunds, chargebacks, and compliance remain with the merchant and PSP (https://agentic-commerce-protocol.com/docs/commerce/specs/payment). Stripe's own flows make the same point: PaymentIntents, authorizations, captures, refunds, Connect transfers, disputes, Radar outcomes, and currencies are separate state machines (https://docs.stripe.com/payments/paymentintents/lifecycle, https://docs.stripe.com/payments/place-a-hold-on-a-payment-method, https://docs.stripe.com/connect/charges, https://docs.stripe.com/refunds, https://docs.stripe.com/disputes/how-disputes-work, https://docs.stripe.com/radar/risk-evaluation, https://docs.stripe.com/currencies).

The sharp claim: "trust network for autonomous commerce" becomes real only when Chio can prove not just "the agent was allowed to buy" or "payment happened", but "this mandate, quote, merchant, PSP object, settlement action, refund or dispute posture, risk state, and currency reserve all reconcile under one signed order context."

## 1. Strongest Feature Additions

1. Add `chio.commerce.payment-lifecycle.v1`.

This should be the missing payment-network subgraph under `chio.commerce.order-context.v1`. It should not be a Stripe-only schema, but the first fixture should use Stripe-shaped evidence because Stripe exposes the right merchant workflow states: PaymentIntent amount and currency, manual capture state, capture deadline, refund object, dispute object, Radar outcome, metadata order id, Connect charge type, transfer group, transfer reversal, and webhook event ids. Stripe docs explicitly distinguish authorization, capture, cancellation, refund, Connect transfer liability, and dispute debit behavior (https://docs.stripe.com/payments/place-a-hold-on-a-payment-method, https://docs.stripe.com/connect/separate-charges-and-transfers, https://docs.stripe.com/connect/charges).

Required fields:

- `payment_lifecycle_id`
- `order_id`
- `merchant_subject`
- `psp`
- `merchant_order_ref`
- `checkout_session_ref`
- `payment_object_refs`
- `authorization_ref`
- `capture_ref`
- `refund_refs`
- `dispute_refs`
- `chargeback_refs`
- `fraud_assessment_refs`
- `transfer_refs`
- `transfer_reversal_refs`
- `webhook_event_refs`
- `idempotency_key_refs`
- `currency_ledger_ref`
- `current_payment_state`
- `signature`

2. Add `chio.commerce.mandate-allowance-ledger.v1`.

AP2 has open and closed mandates, autonomous human-not-present mode, exact mandate version strings, recurring constraints, and a rule that shopping agents must not present subsequent open payment or checkout mandates without a rejection receipt from the previous one (https://ap2-protocol.org/ap2/specification/, https://ap2-protocol.org/ap2/payment_mandate/). x402 has exact, upto, and batch-settlement schemes where the authorized maximum and actual settled amount can diverge within a cap (https://docs.x402.org/getting-started/quickstart-for-sellers). ACP-Commerce delegated payment tokens are single-use, constrained by max amount and expiry (https://agentic-commerce-protocol.com/docs/commerce/specs/payment).

Chio needs one verifier-facing allowance ledger that normalizes those constraints without pretending they are equivalent:

- AP2 mandate hash, `vct`, `cnf`, expiry, amount range, payee, recurrence, occurrence counter, rejection receipt.
- x402 route, scheme, network, asset, payee, authorized maximum, settled amount, facilitator verify and settle refs.
- ACP-Commerce delegated token provider, merchant, checkout session, max amount, expiry, single-use status.
- Chio budget reservation, policy id, spending cap, and settlement dispatch receipt.

3. Add `chio.commerce.dispute-recovery-ledger.v1`.

The existing plans include dispute evidence, but they do not yet model the ugly merchant reality: refund, transfer reversal, card inquiry, chargeback, representment evidence, early fraud warning, open appeal, reserve hold, payout match, and closure are different states. Stripe disputes can debit the disputed amount and fee, block normal refunds while a dispute is open, and run for months (https://docs.stripe.com/disputes/how-disputes-work). Refunds can be full or partial, fail, require action, or be pending because of balance limits (https://docs.stripe.com/refunds). This must be replayable.

Required states:

- `none`
- `refund_requested`
- `refund_pending`
- `refund_succeeded`
- `refund_failed`
- `inquiry_open`
- `dispute_open`
- `representment_submitted`
- `chargeback_debited`
- `chargeback_won`
- `chargeback_lost`
- `transfer_reversal_pending`
- `reserve_held`
- `reserve_released`
- `closed`

4. Add `chio.commerce.fraud-assessment.v1`.

Chio should not build a fraud model for launch. It should bind external fraud signals and prove policy behavior. Stripe Radar evaluates Charges, PaymentIntents, and SetupIntents, can request 3DS, allow, block, or review, and exposes risk levels and scores where available (https://docs.stripe.com/radar/risk-evaluation). Chio should record the risk source, object id, evaluation status, risk level, score if present, action taken, and authority receipt that accepted, denied, escalated, or downgraded the order.

5. Add `chio.commerce.currency-liquidity-ledger.v1`.

Cross-currency support is not "amount plus currency string." It is a reserve and reconciliation problem. Stripe distinguishes presentment currency, settlement currency, conversion, payout currency, and Connect transfer FX (https://docs.stripe.com/currencies, https://docs.stripe.com/connect/currencies). x402 distinguishes network, token asset, atomic units, and chain-specific default assets (https://docs.x402.org/core-concepts/network-and-token-support). The risk plan already rejects mixed-currency netting. Chio should add a per-currency liquidity ledger with no implicit netting:

- `intent_currency`
- `quote_currency`
- `authorization_currency`
- `capture_currency`
- `settlement_currency`
- `payout_currency`
- `asset`
- `network`
- `fx_quote_ref`
- `oracle_conversion_evidence_ref`
- `reserve_amount`
- `reserved_until`
- `realized_amount`
- `conversion_fee_ref`
- `rounding_delta`
- `shortfall_state`

6. Add `chio.commerce.recurring-agent-commerce.v1`.

Recurring agent commerce is not just "subscriptions." It is repeated delegated authority. AP2 payment mandates include an agent recurrence constraint with frequency and max occurrences (https://ap2-protocol.org/ap2/payment_mandate/). Stripe SetupIntents are used to save payment methods for future use, and off-session usage requires permission and an agreement that covers permission, frequency, and amount determination (https://docs.stripe.com/payments/setup-intents). Stripe subscriptions generate invoices and PaymentIntents and have incomplete, active, past_due, unpaid, canceled, and paused states (https://docs.stripe.com/billing/subscriptions/overview). Chio should bind recurrence as an authority ledger:

- recurrence mandate ref;
- occurrence number;
- period start and end;
- max occurrences;
- max amount per occurrence;
- cumulative amount;
- off-session permission evidence;
- failed payment recovery path;
- user re-authentication receipt when required;
- cancellation or pause receipt.

## 2. What To Reject Or Defer

- Reject "Chio is a payment rail." Chio should prove and govern rails, not become a wallet, PSP, issuer, acquirer, facilitator, or card network.
- Reject "x402 payment success means order success." x402 is excellent for paid HTTP resources, but its own flow is payment verification and settlement, not merchant fulfillment, dispute, refund, or chargeback proof.
- Reject "AP2 mandate means Chio authority." AP2 mandate evidence is valuable, but Chio still needs capability receipts, order replay, budget reservation, and policy proof.
- Reject "ACP-Commerce checkout completed means the transaction is final." ACP-Commerce explicitly leaves settlement, refunds, chargebacks, and compliance with the merchant and PSP.
- Defer legal escrow. Build escrow-style technical reserve proof and settlement reconciliation, but do not claim regulated escrow unless the legal and operational product exists.
- Defer autonomous insurer pricing. Keep the risk comptroller to reserve, coverage, claim, appeal, and settlement reconciliation until backtest and capital adequacy artifacts exist.
- Defer broad multi-PSP support. Use one Stripe-shaped fixture plus generic PSP field names. Add other PSPs after the verifier contract stabilizes.
- Defer cross-currency optimization and FX routing. Launch needs fail-closed per-currency reserve accounting, not smart FX.
- Defer "all x402 schemes on every network." Cover one exact payment and one usage-based authorization cap later. Batch settlement can wait until duplicate voucher and escrow accounting are verifier-grade.
- Defer automated chargeback fighting. Chio should assemble evidence and prove the decision path. It should not claim it can win disputes.

## 3. Exact Docs And Plans To Update

- `architecture/02-commerce-order-system.md`: add payment lifecycle, mandate allowance, fraud assessment, dispute recovery, currency liquidity, and recurring commerce refs to the core aggregate; extend the state machine with refund, dispute, chargeback, transfer reversal, recurring occurrence, and currency shortfall states.
- `plans/02-commerce-order-implementation.md`: split Phase 3 into AP2, x402, ACP-Commerce, and PSP lifecycle slices; add a Phase 2.5 for `chio.commerce.payment-lifecycle.v1` before external bridges; add tests for manual capture expiry, wrong merchant, wrong currency, token reuse, refund without transfer reversal, and recurrence overuse.
- `indices/artifact-registry.md`: add `chio.commerce.payment-lifecycle.v1`, `chio.commerce.mandate-allowance-ledger.v1`, `chio.commerce.dispute-recovery-ledger.v1`, `chio.commerce.fraud-assessment.v1`, `chio.commerce.currency-liquidity-ledger.v1`, and `chio.commerce.recurring-agent-commerce.v1`.
- `indices/build-priority-matrix.md`: add a P1 "Merchant payment lifecycle" row after Commerce order context and before Settlement proof bundle; add "Do not add payment rails before PSP lifecycle proof."
- `indices/execution-slice-contract.md`: add a commerce-payments slice with write scope limited to commerce fixtures, commerce schemas, verifier tests, and CLI report sections; require registry owner handoff for schema registration.
- `indices/proof-room-fixture-catalog.md`: expand Stage 1 `commerce-transaction-passport` required positives and negatives with PSP lifecycle, refund/dispute posture, fraud assessment, transfer reversal, and recurring mandate cases.
- `plans/05-public-settlement-passport-implementation.md`: clarify that web3 settlement proof is not enough for card or merchant workflows; add optional references to payment lifecycle and currency liquidity ledgers where settlement proof claims order completion.
- `plans/06-risk-comptroller-implementation.md`: bind fraud assessment, chargeback reserve, dispute recovery, currency liquidity, and recurring exposure into facility state and reserve reconciliation.
- `architecture/06-risk-comptroller-system.md`: add PSP liability, chargeback reserve, Radar or external fraud signal refs, recurring exposure, and per-currency reserve separation.
- `indices/external-standards-source-log.md`: add the official Stripe URLs used above, plus AP2 payment mandate, x402 facilitator, x402 network support, x402 seller quickstart, ACP-Commerce checkout, and ACP-Commerce delegated payment.
- `indices/verification-gates.md`: add a gate that "autonomous commerce" requires order replay plus payment lifecycle replay, not merely a payment proof.

## 4. First Executable Slice

Build one offline `stripe-card-commerce-lifecycle` fixture under the Stage 1 commerce bundle. It should not call Stripe live. It should use Stripe-shaped evidence and official state names so the verifier contract is realistic.

Slice contract:

1. Add draft schemas for `chio.commerce.payment-lifecycle.v1` and `chio.commerce.mandate-allowance-ledger.v1`.
2. Create one positive fixture:
   - order id `order_chio_demo_001`;
   - AP2 closed checkout and payment mandate hashes bound to the same order;
   - ACP-Commerce checkout session with delegated payment token scoped to the merchant, amount, currency, and expiry;
   - Stripe-shaped PaymentIntent evidence with `amount`, `currency`, `metadata.order_id`, manual capture, `requires_capture`, capture before expiry, and final `succeeded`;
   - Radar outcome `normal`;
   - Connect separate charge and transfer with `transfer_group` equal to the order id;
   - no refund, no dispute, no chargeback, no transfer reversal;
   - currency ledger with `usd` from quote through capture and settlement;
   - order replay terminal state `completed`.
3. Implement replay checks in the commerce verifier:
   - same order id across mandate, checkout, PaymentIntent metadata, transfer group, and settlement packet;
   - amount and currency match quote, mandate, delegated token, PaymentIntent, and transfer;
   - capture occurs before `capture_before`;
   - transfer is not accepted before payment success;
   - fraud outcome is bound and policy accepted;
   - no terminal `completed` state while dispute, refund, chargeback, or transfer reversal is unresolved.
4. Add CLI report lines under `chio proof verify`:
   - `commerce.order_replay`
   - `commerce.payment_lifecycle`
   - `commerce.mandate_allowance`
   - `commerce.fraud_assessment`
   - `commerce.currency_liquidity`
5. Stop after one positive fixture and five negative fixtures pass. Do not add more rails.

Executable gate:

```bash
cargo test -p chio-control-plane --test commerce_payment_lifecycle
cargo test -p chio-cli --test proof_verify commerce_payment_lifecycle_fixture_passes
```

## 5. Negative Fixtures

- `ap2-payment-mandate-wrong-checkout-hash`: payment mandate hash does not match checkout mandate hash.
- `ap2-recurring-over-occurrence-limit`: recurrence max occurrences is exceeded.
- `ap2-open-mandate-reused-without-rejection-receipt`: a second open mandate is presented without a rejection receipt for the first.
- `x402-payment-detached-from-order`: `PAYMENT-REQUIRED` and facilitator response are valid but not bound to the Chio order id.
- `x402-upto-settlement-over-authorized-max`: actual settled amount exceeds authorized maximum.
- `x402-batch-voucher-reused`: batch-settlement voucher is replayed against a second resource.
- `acp-commerce-token-wrong-merchant`: delegated payment token is validly shaped but scoped to a different merchant.
- `acp-commerce-token-expired`: complete-checkout uses an expired delegated token.
- `stripe-paymentintent-order-metadata-mismatch`: PaymentIntent metadata order id differs from Chio order id.
- `stripe-manual-capture-expired`: capture occurs after the authorization expiry.
- `stripe-transfer-before-async-success`: transfer is accepted before `charge.succeeded` for an asynchronous payment method.
- `stripe-refund-without-transfer-reversal`: refund succeeds but Connect transfer recovery is missing.
- `stripe-dispute-open-completed-order`: order tries to remain terminal `completed` while a chargeback is open.
- `stripe-radar-highest-risk-auto-accepted`: highest-risk or blocked fraud outcome is accepted without an explicit override receipt.
- `mixed-currency-netting`: USD reserve is used to satisfy EUR exposure without conversion evidence.
- `fx-quote-expired`: currency conversion uses an expired FX quote or stale oracle conversion evidence.
- `recurring-agent-charge-without-occurrence-receipt`: recurring payment occurs without an occurrence receipt bound to the recurring mandate.
- `recurring-agent-off-session-authentication-required`: off-session charge requires user action but the order advances anyway.

## Final Position

The best addition is not "more payments." It is a Chio-native commerce clearing proof: order replay plus payment lifecycle replay plus mandate allowance plus liquidity reserve plus dispute recovery plus risk reconciliation. Build it over one Stripe-shaped fixture, one AP2 mandate fixture, one ACP-Commerce delegated-token fixture, and one x402 detached-payment negative. That makes the homepage claim real without pretending Chio is the payment network.
