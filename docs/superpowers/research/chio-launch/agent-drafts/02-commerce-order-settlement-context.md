# Agent B: Commerce Order And Settlement Context

Date: 2026-06-09

Mode: research and planning only. This document proposes the commerce context
contract Chio needs for launch trust-network work. It does not propose code edits
in this branch.

Confidence: high on the repository inventory and Chio-local gaps. Moderate on
external ACP naming because Stripe now documents parts of this space under
agentic commerce and UCP while the ACP repository and OpenAI/Stripe maintained
ACP docs still describe delegated payment.

## Executive Conclusion

Chio already has most of the hard ingredients for agent commerce: capabilities,
budget holds, governed approval tokens, x402-style evidence, ACP-style shared
payment token adapters, settlement dispatch artifacts, settlement observation,
passports, reputation, federation, disputes, and verifier bundles. The missing
piece is not another rail adapter. The missing piece is a canonical commerce
order context that binds all of those ingredients to one order, one quote, one
authority chain, one payment challenge or delegated token, one settlement packet,
and one reconciliation path.

The current launch risk is therefore architectural fragmentation: the flagship
examples prove the story, but the order lifecycle lives in scenario-specific JSON
and Python control flow. A reviewer can inspect the bundle, but a runtime cannot
yet enforce a Chio-wide order state machine with replay resistance, mandate
binding, x402 verification transcripts, ACP delegated-payment constraints, and
settlement reconciliation as one typed contract.

## Current Assets With File References

### Example Surface Inventory

- `examples/EXAMPLE_SURFACE_MATRIX.md:9` identifies
  `examples/agent-commerce-network/` as a flagship commerce workflow covering
  approvals, budgets, settlement, disputes, and reviewer verification.
- `examples/EXAMPLE_SURFACE_MATRIX.md:11` identifies
  `examples/internet-of-agents-web3-network/` as the richer flagship surface for
  recursive agent commerce, RFQ routing, x402 requirements, web3 settlement
  dispatch, passports, reputation, federation, budgets, guardrails, and optional
  Base Sepolia evidence.

### Agent Commerce Network

- `examples/agent-commerce-network/README.md:3-16` frames the example as
  governed buyer-provider service procurement where Chio controls capabilities,
  budget enforcement, receipt signing, provider MCP access, and price-threshold
  approval.
- `examples/agent-commerce-network/README.md:39-45` names the governed surfaces:
  budget limits on capability grants, receipt signing, guard policies, split
  budget endpoints, exposure ledger, and settlement reconciliation.
- `examples/agent-commerce-network/buyer/app.py:31-47` constructs a
  settlement-reconciliation object from a job, quote amount, approved amount,
  settled amount, currency, status, and buyer/provider positions.
- `examples/agent-commerce-network/buyer/app.py:50-72` defines the local request
  shapes for quote requests, job creation, approval, and disputes.
- `examples/agent-commerce-network/buyer/app.py:285-399` implements the local
  state transitions: quote request creates a quote record, job creation stages or
  denies or waits for approval or executes, approval executes, dispute mutates a
  fulfilled job into disputed/reversal-pending, and execution emits fulfillment
  plus settlement.
- `examples/agent-commerce-network/buyer/app.py:447-480` exposes the commerce
  API endpoints for quote requests, jobs, approval, and disputes.

What this gives Chio: a simple, readable B2B procurement skeleton. What it lacks:
a canonical order schema, external payment transcript, quote hash binding,
mandate binding, budget-hold identity as a first-class order artifact, and a
verifier that proves more than non-negative financial values.

### Internet Of Agents Web3 Network

- `examples/internet-of-agents-web3-network/README.md:24-32` describes the core
  launch-relevant flow: treasury delegates a bounded budget, procurement runs a
  three-provider RFQ through a Chio-protected market broker, selection uses
  policy over passport/reputation/budget/runtime/federation, the provider
  subcontracts through a narrowed capability, settlement routes the rail and maps
  the packet into Chio web3 dispatch, and an auditor verifies the bundle.
- `examples/internet-of-agents-web3-network/README.md:37-52` lists the control
  surfaces: `chio trust serve`, `chio api protect`, `chio mcp serve-http`,
  passport/challenge/presentation/reputation/federation evidence, negative
  controls, signed approval, x402-style payment proof, cross-rail settlement,
  runtime degradation, telemetry, and adversarial denials.
- `examples/internet-of-agents-web3-network/README.md:150-187` defines the
  evidence bundle contract, including `approvals/`, `chio/budgets/`,
  `contracts/`, `financial/`, `identity/passports/`, `market/`, `payments/`,
  `settlement/`, `web3/`, `review-result.json`, and `summary.json`.
- `examples/internet-of-agents-web3-network/README.md:189-219` documents
  fail-closed verifier posture and the critical commerce claims: x402-style
  payment requirements are not settlement truth, budget exposure happens before
  quote acceptance, high-risk release requires signed approval before exposure
  and payment proof, and settlement can route to Base Sepolia or local devnet
  while denying unsupported rails.
- `examples/internet-of-agents-web3-network/internet_web3/scenario.py:341-525`
  orchestrates the full flow from evidence load, capability issuance, RFQ,
  reputation/admission, provider selection, passport workflow, market flow,
  service order, validation index, provider review, rail selection, settlement
  packet, web3 dispatch, execution receipt, reconciliation, dispute workflow,
  and budget reconciliation.
- `examples/internet-of-agents-web3-network/internet_web3/scenario.py:643-749`
  issues the root, procurement, provider, settlement, auditor, and sidecar
  capabilities. It narrows provider authority away from funds and narrows
  settlement authority to Base Sepolia USDC.
- `examples/internet-of-agents-web3-network/internet_web3/scenario.py:807-881`
  builds the quote request, requests the quote, writes a signed approval
  checkpoint, authorizes a Chio budget hold, creates the x402-style payment
  handshake, and accepts fulfillment.
- `examples/internet-of-agents-web3-network/internet_web3/scenario.py:883-922`
  emits the current `chio.example.ioa-web3.service-order.v1` artifact. It binds
  order id, buyer, provider, quote amount, x402 protocol hint, payment proof,
  payment status, capability ids, and market refs.
- `examples/internet-of-agents-web3-network/internet_web3/scenario.py:964-1134`
  builds `chio.web3-settlement-dispatch.v1`,
  `chio.web3-settlement-execution-receipt.v1`, and
  `chio.example.ioa-web3.reconciliation.v1`.
- `examples/internet-of-agents-web3-network/internet_web3/marketplace.py:35-47`
  builds the RFQ request artifact with order id, buyer id, requested scope,
  provider ids, max budget, currency, capability id, and issuance time.
- `examples/internet-of-agents-web3-network/internet_web3/marketplace.py:92-174`
  writes reputation history, scorecards, passport drift verdicts, and federation
  admission verdicts.
- `examples/internet-of-agents-web3-network/internet_web3/marketplace.py:177-235`
  selects the provider by rejecting over-budget, low-reputation, passport-drift,
  and federation-failed providers.
- `examples/internet-of-agents-web3-network/internet_web3/marketplace.py:238-280`
  writes the x402-style payment-required document, the Chio payment proof, and
  the payment-satisfaction document. The proof explicitly says Chio budget and
  receipts are the source of truth.
- `examples/internet-of-agents-web3-network/internet_web3/budgeting.py:17-65`
  coordinates the budget authorization hold around quote acceptance and writes
  `chio.example.ioa-web3.budget-authorization.v1`.
- `examples/internet-of-agents-web3-network/internet_web3/budgeting.py:67-118`
  reconciles settlement spend and writes the budget summary.
- `examples/internet-of-agents-web3-network/internet_web3/budgeting.py:120-161`
  runs the overspend negative control against
  `/v1/budgets/authorize-exposure`.
- `examples/internet-of-agents-web3-network/services/market_broker.py:21-61`
  defines the service-side Pydantic request shapes for quotes, RFQs, payment
  requirements, payment proofs, and fulfillment.
- `examples/internet-of-agents-web3-network/services/market_broker.py:102-167`
  implements RFQ, quote, and local x402 payment-required documents.
- `examples/internet-of-agents-web3-network/services/market_broker.py:169-225`
  implements local payment satisfaction and fulfillment endpoints.

What this gives Chio: an excellent launch proof bundle and an almost complete
order story. What it lacks: a reusable order aggregate, canonical hashes across
each transition, first-class AP2 mandate binding, real x402 facilitator verify
and settle transcripts, real ACP delegated-payment token lifecycle evidence, and
runtime enforcement of state transitions outside the example.

### Kernel Payment And Approval Surface

- `crates/chio-kernel/src/payment.rs:60-96` defines
  `GovernedPaymentContext`, `CommercePaymentContext`, and
  `PaymentAuthorizeRequest`. Commerce context currently includes seller,
  shared payment token id, and optional max amount.
- `crates/chio-kernel/src/payment.rs:149-224` defines the `PaymentAdapter`
  trait and the two concrete bridge structs: `X402PaymentAdapter` and
  `AcpPaymentAdapter`.
- `crates/chio-kernel/src/payment.rs:286-459` implements x402 as a thin prepaid
  authorization bridge and ACP/shared-payment-token as a hold/capture bridge.
- `crates/chio-kernel/src/kernel/governed_validation.rs:932-1066` validates
  governed transaction intent, seller-scoped commerce context, shared payment
  token reference, explicit max amount, seller exactness, runtime assurance,
  amount bounds, and approval tokens above threshold.
- `spec/PROTOCOL.md:496-538` documents governed intent, seller-scoped commerce
  approval context, metered billing quote context, approval-token binding, and
  seller-exact enforcement.
- `spec/PROTOCOL.md:861-913` documents the signed receipt metadata strategy:
  keep economic authorization, payment, settlement, approval, and runtime
  metadata additive while keeping mutable settlement reconciliation outside the
  signed receipt.
- `docs/reference/AGENT_ECONOMY.md:688-706` records that x402 and ACP adapters
  are implemented, with governed x402 context and seller-scoped ACP shared
  payment token evidence.
- `docs/reference/AGENT_ECONOMY.md:731-770` documents the runtime rule set:
  authorize before tool execution, deny if authorization fails, capture or
  reconcile after execution, release/refund on abort, and keep settlement
  recovery out-of-band when failure happens after the tool has run.

What this gives Chio: real runtime hooks for payment authorization. What it
lacks: a canonical commerce order object passed through those hooks, AP2 mandate
references, x402 verify/settle transcript capture, ACP delegated token
introspection evidence, and an order-level replay/idempotency ledger.

### Budget Reservation Surface

- `crates/chio-kernel/src/budget_store.rs:16-40` tracks invocation count,
  exposed cost, realized spend, and mutation kinds for authorize, reverse,
  release, and reconcile.
- `crates/chio-kernel/src/budget_store.rs:94-150` defines budget guarantee,
  authority, and metering profiles, including max-cost preauthorization followed
  by actual reconciliation.
- `crates/chio-kernel/src/budget_store.rs:175-217` defines hold request shapes
  for authorize, release, reverse, and reconcile.
- `crates/chio-kernel/src/budget_store.rs:507-661` implements hold
  authorization, reversal, release, reconciliation, and capture.

What this gives Chio: a strong monetary primitive. What it lacks: a canonical
order-bound reservation schema with required order id, quote hash, mandate or
approval id, payment requirement hash, and state-transition reference.

### chio-settle And Web3 Settlement Surface

- `crates/chio-settle/ARCHITECTURE.md:3-17` defines the settlement runtime
  boundary: preparation, runtime controls, retry envelopes, cross-chain delivery
  reconciliation, receipt projection, and deterministic fail-closed handling.
- `crates/chio-settle/ARCHITECTURE.md:19-25` highlights current x402 hardening:
  public payment requirements reject blank or whitespace facilitator, resource,
  and token fields.
- `crates/chio-settle/src/payments.rs:11-33` defines
  `X402PaymentRequirements`, including version, chain id, facilitator URL,
  resource, pay-to, accepted tokens, dispatch id, capability id, amount,
  settlement mode, and governed authorization requirement.
- `crates/chio-settle/src/payments.rs:114-165` builds and validates x402
  payment requirements from a web3 settlement dispatch.
- `crates/chio-settle/src/payments.rs:247-340` keeps Circle nanopayment and
  ERC-4337/paymaster compatibility bounded by explicit custody, chain, token,
  amount, gas, and settlement-deduction policy.
- `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md:5-10` says payment interop
  sits on governed Chio dispatch and settlement truth and does not replace
  signed receipts or approval context.
- `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md:25-64` freezes the guardrails
  and non-goals: explicit facilitator/resource/token lists, chain allowlists,
  ceilings, no receipt mutation from facilitator state, and no generic payment
  marketplace.
- `docs/standards/CHIO_WEB3_PROFILE.md:61-83` lists the official machine-readable
  web3 artifacts, including settlement dispatch and execution receipt.
- `docs/standards/CHIO_WEB3_PROFILE.md:85-111` states that external execution,
  chain anchors, automation, CCIP, and payment interop remain subordinate to
  Chio receipt and settlement artifacts.
- `docs/standards/CHIO_WEB3_PROFILE.md:140-169` describes the shipped settlement
  model and payment-interop projection.
- `docs/standards/CHIO_SETTLE_PROFILE.md:29-57` freezes the bounded runtime
  boundary for ERC-20 approval, escrow create/release/refund, deterministic
  capital-instruction mapping, finality, and receipt projection.
- `docs/standards/CHIO_SETTLE_PROFILE.md:120-160` records fail-closed dispatch
  and explicit settlement observation states.

What this gives Chio: strong post-order settlement semantics. What it lacks:
canonical intake from a commerce order context into dispatch preparation and a
normative order-to-settlement packet binding.

### Settlement Observer Surface

- `crates/chio-kernel/src/kernel/settlement_observer.rs:1-12` states that the
  settlement observer runs only after a receipt has been signed and durably
  stored and that hook failure never blocks dispatch.
- `crates/chio-kernel/src/kernel/settlement_observer.rs:70-180` builds
  observations only for trusted, signed, allowed, priced receipts and records
  observer outcomes without mutating dispatch success.

Implication: the observer is not a commerce authorization gate. The commerce
state machine must gate before tool execution and before settlement dispatch.
The observer can drive reconciliation, retry, and dead-letter workflows only
after signed receipt truth exists.

### ACP Name Collision

- `spec/BRIDGES.md:290-300` and `crates/chio-acp-edge/README.md:1-22` define
  `chio-acp-edge` as an Agent Client Protocol bridge for editors and IDEs. That
  is not the same thing as the external Agentic Commerce Protocol delegated
  payment model.
- The commerce-relevant ACP surface in this repo is the `AcpPaymentAdapter` and
  `CommercePaymentContext` in `crates/chio-kernel/src/payment.rs:73-96` and
  `crates/chio-kernel/src/payment.rs:212-224`.

Launch docs should use "ACP delegated payment" only for the external
OpenAI/Stripe Agentic Commerce Protocol or shared-payment-token payment flow,
and "Agent Client Protocol ACP edge" for the IDE bridge.

## External Protocol Alignment

External primary references used for this section:

- AP2 specification: <https://ap2-protocol.org/ap2/specification/>
- AP2 repository: <https://github.com/google-agentic-commerce/AP2>
- x402 docs: <https://docs.x402.org/>
- x402 buyer quickstart: <https://docs.x402.org/getting-started/quickstart-for-buyers>
- x402 seller quickstart: <https://docs.x402.org/getting-started/quickstart-for-sellers>
- ACP docs: <https://www.agenticcommerce.dev/docs>
- ACP repository: <https://github.com/agentic-commerce-protocol/agentic-commerce-protocol>
- ACP delegated payment spec: <https://agentic-commerce-protocol.com/docs/commerce/specs/payment>
- Stripe shared payment tokens: <https://docs.stripe.com/agentic-commerce/concepts/shared-payment-tokens.md?agent-seller=seller>

### AP2 Mandates

AP2's key contribution is not settlement execution. It is verifiable authority:
intent, checkout, and payment authorization are carried by signed mandates and
receipts. AP2 distinguishes human-present and human-not-present flows; in the
autonomous mode, open user mandates constrain later closed mandates signed by
the agent. Payment mandates are bound to checkout contents by hash, and dispute
evidence combines checkout mandate/receipt and payment mandate/receipt.

Chio alignment:

- Chio capabilities already constrain agent authority, but AP2 mandates add
  user-commerce intent evidence that can travel to merchants, credential
  providers, networks, and payment processors.
- Chio approval tokens already bind approval to subject, request id, governed
  intent hash, and time bounds. Those should be mapped into an
  `ap2_mandate_refs` block rather than replaced.
- Chio receipts and AP2 receipts should be cross-referenced by digest. Chio
  should not ingest an AP2 mandate as ambient authority unless the mandate hash,
  checkout hash, amount, currency, merchant/provider identity, expiration, and
  agent key binding match the Chio order context.

Required Chio addition:

- Add `mandate_binding` to the commerce order context with slots for
  `ap2_intent_mandate`, `ap2_checkout_mandate`, `ap2_payment_mandate`,
  `ap2_checkout_receipt`, and `ap2_payment_receipt`.
- Require each AP2 artifact reference to include `digest`, `issuer`,
  `subject_or_agent_key`, `expires_at`, `constraints_digest`,
  `checkout_hash` where applicable, and `verification_status`.
- Deny if an AP2 artifact is open-ended when the order state requires a closed
  quote or payment amount.

### x402 Challenge, Verify, And Settle

x402 makes payment a normal HTTP negotiation. The resource server can return
HTTP 402 with payment requirements; a buyer chooses a requirement, signs a
payment payload, retries with the payment header, and the server or facilitator
verifies and settles. x402 also has payment result headers and explicit
settlement outcomes. The exact scheme requires strict amount matching, while
other schemes support bounded variants such as up-to or batch settlement.

Chio alignment:

- Chio already projects governed settlement dispatch into x402 requirements
  (`X402PaymentRequirements`) and already has a kernel x402 payment adapter.
- The flagship web3 example already produces local `payment-required`,
  `chio-payment-proof`, and `payment-satisfaction` artifacts.
- Chio's correct stance is already documented: x402 may be a payment interop
  surface, but Chio receipts, budget holds, and settlement dispatch remain the
  source of truth for Chio-governed execution.

Required Chio addition:

- Split local x402 evidence into three canonical transcript artifacts:
  `chio.commerce.x402.challenge.v1`,
  `chio.commerce.x402.verify.v1`, and
  `chio.commerce.x402.settle.v1`.
- For live x402, capture facilitator URL, payment requirement digest, accepted
  requirement, signed payment payload digest, verify response, settle response,
  payment response header digest, settlement tx/ref, chain id, token, amount,
  resource, and idempotency key.
- Deny settlement dispatch if x402 verify succeeds for a different order,
  quote, amount, currency, resource, payee, chain, token, capability, or
  mandate/approval binding.
- Treat x402 settlement failure after fulfillment as a recovery state, not as a
  retroactive mutation of the signed Chio receipt.

### ACP Delegated Payment

ACP's commerce model places the agent in the checkout experience while the
seller remains merchant of record and the payment provider tokenizes payment
credentials with allowance constraints. The delegated payment spec returns a
single-use, constrained token. Stripe's shared payment token implementation
scopes usage with limits such as currency, max amount, expiration, and seller
details, and the seller uses the token to create or confirm its payment.

Chio alignment:

- Chio already has `CommercePaymentContext { seller, shared_payment_token_id,
  max_amount }`.
- Chio already has an `AcpPaymentAdapter` that performs a remote authorization
  hop before execution and models later capture, release, and refund as
  hold/capture bookkeeping.
- Chio governed validation already requires shared payment token reference and
  explicit max amount when commerce context is present.

Required Chio addition:

- Promote `shared_payment_token_id` from a thin reference into a
  `delegated_payment_binding` block with token digest, seller scope, max amount,
  currency, expiration, checkout/session id, PSP/provider id, revocation status,
  usage status, and verification evidence.
- Bind ACP token usage to the Chio order id, quote hash, merchant/provider id,
  amount, currency, approval/mandate id, and capability id.
- Record `capture`, `release`, `refund`, `revoked`, and `expired` events as
  order state transitions with idempotency keys.
- Do not claim the existing `chio-acp-edge` is this integration. It is Agent
  Client Protocol bridging for tools.

## Exact Gaps

1. No canonical commerce order aggregate exists. The example emits
   `chio.example.ioa-web3.service-order.v1`, but there is no
   `chio.commerce.order-context.v1` shared across runtime, CLI, verifier,
   settlement, and docs.
2. Order state is scenario-owned. The examples encode transitions in Python
   control flow and local JSON, not in a reusable Chio state machine.
3. Quote binding is too weak. Quote id, amount, provider, and scope are present,
   but there is no canonical quote digest that must match budget hold, approval,
   payment proof, fulfillment, settlement packet, and dispatch.
4. AP2 mandates are not represented as first-class authority. Chio approval
   tokens exist, but AP2 open/closed mandates, mandate constraints, checkout
   hashes, and payment receipts have no order-context slots.
5. x402 evidence is local and stylized in the flagship example. It proves
   shape, but not a real challenge, verify response, settle response, payment
   response header, facilitator transcript, or strict amount/resource binding.
6. ACP delegated payment is adapter-thin. The kernel adapter can authorize a
   shared payment token reference, but Chio does not yet model token issuance,
   allowance, seller scope, expiration, usage, revocation, or PSP verification
   as order evidence.
7. ACP naming is ambiguous. The repo's `chio-acp-edge` is Agent Client Protocol
   for IDE tool access, not Agentic Commerce Protocol delegated payment.
8. Budget holds are not order-native. They can carry hold ids and event ids, but
   the order contract should require quote hash, mandate/approval binding, and
   payment requirement hash before exposure is authorized.
9. Settlement packet intake is example-specific. `contracts/settlement-packet`
   exists in the example, but there is no canonical
   `chio.commerce.settlement-packet.v1` accepted by `chio-settle`.
10. Settlement observer is post-dispatch by design. It cannot be used to enforce
    pre-settlement order gates, so a separate pre-dispatch commerce gate is
    required.
11. Dispute and refund are not canonical. The example covers weak deliverable,
    partial payment, refund, remediation, and dispute audit, but these are not
    typed as reusable commerce transitions.
12. Idempotency and replay controls are incomplete at the order level. Approval
    replay is handled, but quote replay, payment proof replay, mandate reuse,
    delegated payment token reuse, and settlement packet replay need one order
    ledger.
13. Provider passports are used for selection, but not bound directly into the
    order, quote, and settlement context. A valid passport should be digest-bound
    to the bid/quote it supports.
14. There is no unified CLI/API for order lifecycle operations. Current surfaces
    are example endpoints, trust-control budget endpoints, kernel payment
    adapters, and settlement reports.
15. Verifier coverage is strongest in the web3 example, not in a reusable gate.
    `agent-commerce-network` remains a simpler teaching example and should not
    be treated as the launch-grade verifier.

## Proposed Commerce State Machine

The state machine should be monotonic except for explicit dispute, refund, and
recovery transitions. Each transition writes a canonical event with
`order_id`, `previous_state`, `next_state`, `event_id`, `idempotency_key`,
`actor_subject`, `capability_id`, `artifact_refs`, `artifact_hashes`,
`issued_at`, and `signature_or_receipt_ref`.

| State | Entry evidence | Allowed next states | Fail-closed denial conditions |
| --- | --- | --- | --- |
| `drafted` | Buyer intent, requested scope, max budget, currency, buyer identity, optional AP2 open mandate | `rfq_opened`, `cancelled` | Missing buyer identity, missing max budget for autonomous flow, expired mandate |
| `rfq_opened` | RFQ request digest, provider candidate set, procurement capability | `provider_selected`, `cancelled` | Direct unmediated path, provider list outside policy, capability lacks market scope |
| `provider_selected` | Selection receipt, provider bid digest, passport verdict, reputation scorecard, federation verdict | `quote_requested`, `cancelled` | Passport drift, reputation below threshold, federation denial, provider over budget |
| `quote_requested` | Quote request digest, provider id, scope, max budget, currency | `quote_issued`, `quote_denied`, `quote_expired` | Provider mismatch, quote request exceeds policy, stale capability |
| `quote_issued` | Quote id, quote digest, amount, currency, service terms, expiry, provider signature or receipt | `quote_bound`, `quote_rejected`, `quote_expired` | Expired quote, amount over max budget, currency mismatch, unsigned mutable terms |
| `quote_bound` | Quote acceptance event, quote digest, selected provider digest | `mandate_bound`, `approval_required`, `budget_denied` | Quote digest mismatch, provider not selected, duplicate acceptance id |
| `mandate_bound` | AP2 mandate refs or Chio approval token or ACP delegated-payment binding | `approved`, `approval_denied`, `mandate_expired` | Mandate/approval does not bind order, quote, amount, merchant/provider, agent key, or expiry |
| `approval_required` | Approval challenge and threshold reason | `approved`, `approval_denied`, `approval_expired` | Missing approval authority, parameter hash mismatch, token TTL above Chio maximum |
| `approved` | Approval token or verified mandate/delegated payment binding | `budget_reserved`, `cancelled` | Approval not single-use, subject mismatch, governed intent hash mismatch |
| `budget_reserved` | Chio hold id, quote digest, exposure amount, max budget, trust-control response | `payment_challenged`, `budget_released`, `budget_reversed` | Hold denied, hold amount below quote, hold not bound to order/quote |
| `payment_challenged` | x402 challenge or ACP delegated token request, payment requirement digest | `payment_verified`, `payment_failed`, `payment_expired` | Payment requirement amount/resource/payee/currency does not match order |
| `payment_verified` | x402 verify transcript, ACP token verification, or prepaid authorization id | `fulfillment_requested`, `payment_released`, `payment_refunded` | Verify response mismatch, token revoked/expired, duplicate token use, strict amount mismatch |
| `fulfillment_requested` | Provider invocation receipt and fulfillment request digest | `fulfilled`, `fulfillment_failed`, `disputed` | Provider capability lacks tool scope, runtime assurance degraded below policy |
| `fulfilled` | Fulfillment package, provider receipt, evidence refs | `settlement_packet_ready`, `disputed` | Missing deliverable evidence, evidence digest mismatch, fulfillment after quote expiry without extension |
| `settlement_packet_ready` | Order, quote, fulfillment, validation index, rail selection, budget hold, payment verification | `dispatch_prepared`, `disputed` | Missing budget hold, payment verification, approval/mandate binding, or rail selection |
| `dispatch_prepared` | Chio settlement dispatch artifact and capital instruction | `dispatch_submitted`, `dispatch_denied` | Invalid capital instruction, rail mismatch, wrong chain/token/beneficiary, missing key binding |
| `dispatch_submitted` | Settlement runtime submission ref or local qualified dispatch ref | `awaiting_finality`, `settlement_failed` | Submission outside approved execution window, unapproved rail, mainnet blocked |
| `awaiting_finality` | Chain observation or local qualification observation | `settled`, `reorged`, `timed_out`, `settlement_failed` | Confirmation shortfall after deadline, indexer drift, amount/counterparty mismatch |
| `settled` | Execution receipt, observed amount, finality evidence | `reconciled`, `disputed` | Settlement amount does not match quote or approved partial settlement |
| `reconciled` | Budget reconciliation, financial reconciliation, immutable receipt refs | Terminal unless `disputed` | Realized spend greater than exposure, receipt mutation attempt |
| `disputed` | Dispute claim, evidence refs, affected settlement refs | `partial_settlement`, `refunded`, `remediated`, `chargeback_pending` | Dispute lacks signed claimant or order/fulfillment binding |
| `partial_settlement` | Adjudication or remediation plan, partial amount, refund amount | `reconciled`, `refunded` | Partial amount exceeds settled amount, missing payer/payee authority |
| `refunded` | Refund receipt, payment rail refund ref, budget reversal/reconciliation | `reconciled` | Refund not bound to original transaction or exceeds captured amount |
| `reorged` | Finality report, canonical-chain drift evidence | `dispatch_prepared`, `refunded`, `manual_review` | Retry without preserving original order and dispatch refs |
| `manual_review` | Operator hold reason and receipt refs | `dispatch_prepared`, `refunded`, `cancelled` | Unsigned operator override |
| `cancelled` | Cancellation event and released/reversed holds | Terminal | Outstanding budget hold, active delegated token, or unsettled payment authorization |

### Transition Invariants

- The order id is stable from `drafted` through terminal state.
- Quote digest is required before budget reservation.
- Provider selection digest must match the quote provider.
- AP2 mandate, Chio approval token, or ACP delegated payment binding must be
  present before budget reservation when the order is autonomous or above
  threshold.
- Budget reservation must happen before x402 payment proof or ACP capture.
- x402 verify or ACP delegated-token verification must happen before provider
  fulfillment if the rail is prepaid or hold-gated.
- Fulfillment must happen before settlement packet assembly unless the order is
  explicitly prepaid-for-access rather than pay-on-delivery.
- Settlement dispatch must bind quote amount, fulfilled order id, provider id,
  budget hold id, payment verification id, approval/mandate id, rail selection,
  and settlement capability id.
- Mutable reconciliation state must never mutate signed Chio receipt bytes.
- Disputes and refunds are new transitions with their own receipts, not edits to
  prior settled facts.

## Schema List

### Core Aggregate

`chio.commerce.order-context.v1`

Required fields:

- `order_id`
- `state`
- `buyer { subject, organization_id, credential_refs }`
- `agent { subject, capability_id, runtime_assurance_ref, autonomy_tier }`
- `merchant_or_provider { provider_id, seller_scope, passport_ref, federation_ref }`
- `intent { scope, purpose, constraints, max_amount, currency, expires_at }`
- `quote_ref`
- `approval_or_mandate_ref`
- `budget_ref`
- `payment_ref`
- `fulfillment_ref`
- `settlement_ref`
- `dispute_ref`
- `receipt_refs`
- `event_log_digest`
- `created_at`
- `updated_at`

Purpose: one canonical order aggregate that all other commerce schemas bind to
by digest. It should be append-only at the event layer and materialized as a
latest-state view.

### Intent And Mandate

- `chio.commerce.order-intent.v1`: buyer goal, constraints, max budget,
  currency, delivery requirements, autonomy tier, privacy disclosure policy.
- `chio.commerce.ap2-mandate-binding.v1`: AP2 intent, checkout, payment,
  checkout receipt, and payment receipt refs with digests, issuers, subjects,
  constraints, expiry, checkout hash, and verification outcome.
- `chio.commerce.approval-binding.v1`: Chio approval challenge, decision, token,
  governed intent hash, approver, trusted authority key, TTL, and replay status.
- `chio.commerce.delegated-payment-binding.v1`: ACP/SPT token digest, PSP,
  seller scope, max amount, currency, expiration, checkout/session id,
  revocation status, usage status, and verification receipt.

### Market And Quote

- `chio.commerce.rfq-request.v1`: order id, buyer id, requested scope,
  candidate provider ids, max budget, currency, capability id, issued at,
  expires at.
- `chio.commerce.provider-bid.v1`: provider id, service id, price, currency,
  deliverables, terms, trust claims, passport ref, reputation ref, expiry.
- `chio.commerce.provider-selection.v1`: ranking, rejection reasons, selected
  provider id, selected bid id, policy digest, receipt ref.
- `chio.commerce.quote-request.v1`: selected provider, scope, max budget,
  currency, requested deliverables, capability id.
- `chio.commerce.quote.v1`: quote id, order id, provider id, amount, currency,
  terms digest, deliverables digest, payment protocol hints, issued at, expires
  at, provider signature or Chio receipt.
- `chio.commerce.quote-acceptance.v1`: quote digest, acceptance actor, accepted
  at, approval/mandate requirement, idempotency key.

### Budget And Payment

- `chio.commerce.budget-reservation.v1`: order id, quote digest, hold id,
  capability id, grant index, exposure amount, max budget, authorization
  response digest, authority profile, event id.
- `chio.commerce.budget-reconciliation.v1`: order id, hold id, exposed amount,
  realized spend, release/reverse/refund refs, trust-control response digest.
- `chio.commerce.x402.challenge.v1`: HTTP 402 challenge, resource, facilitator,
  accepted tokens, amount, currency, chain id, payee, requirement digest,
  idempotency key, order and quote binding.
- `chio.commerce.x402.verify.v1`: accepted requirement digest, payment payload
  digest, signer, verify response, status, failure reason, order and quote
  binding.
- `chio.commerce.x402.settle.v1`: settle request digest, settle response,
  payment response header digest, tx/ref, chain, token, amount, final status.
- `chio.commerce.acp-token-verification.v1`: shared payment token or delegated
  vault token ref, seller scope, PSP, max amount, currency, expiry, revocation
  check, usage check, verification response.
- `chio.commerce.payment-authorization.v1`: normalized rail-independent
  authorization result from x402, ACP, prepaid, hold/capture, or escrow-backed
  rail.

### Fulfillment, Settlement, And Dispute

- `chio.commerce.fulfillment-request.v1`: order id, quote id, provider id,
  capability id, requested deliverables, evidence requirements.
- `chio.commerce.fulfillment.v1`: fulfillment id, order id, quote id,
  provider id, status, evidence refs, delivered at, provider receipt refs.
- `chio.commerce.settlement-packet.v1`: order, quote, fulfillment, validation
  index, budget reservation, payment verification, approval/mandate binding,
  rail selection, and settlement policy digest.
- `chio.commerce.settlement-dispatch-binding.v1`: Chio order id to
  `chio.web3-settlement-dispatch.v1` with capital instruction digest, authority
  chain, rail, chain, token, beneficiary, amount, and execution window.
- `chio.commerce.settlement-reconciliation.v1`: order id, quote id,
  fulfillment id, dispatch id, execution receipt id, observed amount,
  budget reconciliation id, final state, mutable reconciliation status.
- `chio.commerce.dispute.v1`: claimant, reason code, disputed deliverable refs,
  requested remedy, affected payment/settlement refs, evidence digest.
- `chio.commerce.dispute-resolution.v1`: adjudication or remediation decision,
  partial settlement amount, refund amount, budget reversal/reconcile refs,
  reputation/passport update refs.

### Review And Passport

- `chio.commerce.provider-proof.v1`: provider passport, presentation,
  federation admission, reputation scorecard, runtime appraisal, SPIFFE
  workload identity, and selection digest.
- `chio.commerce.order-passport.v1`: compact reviewer-facing passport for the
  order, aggregating authority, budget, payment, fulfillment, settlement, and
  dispute evidence with selective disclosure support.

## Runtime Gating Model

### Gate 1: Intent And Capability Admission

Input: order intent, buyer identity, agent capability, runtime attestation, max
amount, currency, optional AP2 open mandate.

Checks:

- Capability subject matches agent subject.
- Runtime assurance meets policy for autonomous commerce.
- Intent has bounded amount, currency, expiry, and scope.
- AP2 open mandate, if present, binds the agent key and constraints.

Failure: deny before RFQ and write a denial receipt.

### Gate 2: Provider Admission Before Quote

Input: RFQ request, provider bids, passports, presentations, reputation,
federation admission, runtime identity.

Checks:

- Provider passport is valid and not drifted from reputation claims.
- Provider federation verdict is pass.
- Bid amount is within policy.
- Provider runtime and SPIFFE identity satisfy policy.

Failure: reject provider from ranking. If no admitted provider remains, stop the
order without budget exposure.

### Gate 3: Quote Binding

Input: quote, selected provider, RFQ selection receipt, terms digest.

Checks:

- Quote provider equals selected provider.
- Quote amount and currency are within buyer constraints.
- Quote is unexpired.
- Terms and deliverables are digest-bound.

Failure: move to `quote_rejected` or `quote_expired`.

### Gate 4: Mandate Or Approval

Input: AP2 mandates, Chio approval token, ACP delegated payment binding, quote
digest, governed intent.

Checks:

- At least one authority path satisfies policy: AP2 mandate, Chio approval, or
  ACP delegated payment token plus governed intent.
- The artifact binds order id, quote digest, amount, currency, provider/seller,
  agent key, subject, and expiry.
- Approval tokens are single-use and under max TTL.
- Autonomous AP2 open mandate constraints cover the closed quote and checkout.

Failure: deny before budget reservation.

### Gate 5: Budget Reservation

Input: quote digest, authority binding, capability id, grant index, exposure
amount.

Checks:

- Exposure amount equals or exceeds quote amount.
- Max budget equals governed intent or mandate bound.
- Hold id is deterministic from order, capability, and grant index.
- Trust-control authorizes the hold.

Failure: move to `budget_denied` and do not request payment proof.

### Gate 6: Payment Verification

Input: x402 challenge/verify/settle transcript or ACP delegated token
verification, budget hold, quote digest.

Checks:

- Payment requirement or token scope matches order, quote, amount, currency,
  resource or seller, payee, chain/token, and expiry.
- x402 verify response is captured before fulfillment for prepaid access.
- ACP token is single-use or unused, unrevoked, unexpired, and seller scoped.
- Idempotency key has not been consumed for another order.

Failure: release or reverse budget hold and move to `payment_failed`.

### Gate 7: Fulfillment

Input: provider invocation, capability, runtime assurance, required evidence,
payment verification.

Checks:

- Provider capability can invoke only the required service.
- Provider cannot move funds.
- Fulfillment evidence satisfies quote terms.
- Runtime degradation since provider selection either re-attests or blocks.

Failure: move to `fulfillment_failed` or `disputed`; release, refund, or hold
payment according to settlement mode.

### Gate 8: Settlement Packet And Dispatch

Input: order context, quote, fulfillment, validation index, budget hold, payment
verification, rail selection, settlement capability.

Checks:

- All required prior state digests match the order event log.
- Settlement capability has rail and amount authority.
- Rail selection is allowed, mainnet policy is obeyed, token and chain match.
- Dispatch execution window is inside authority chain expiry.
- `chio-settle` validation passes before any external call.

Failure: no dispatch. Move to `dispatch_denied` or `manual_review`.

### Gate 9: Observation, Reconciliation, And Recovery

Input: signed receipt, settlement observer outcome, finality report, budget
reconciliation.

Checks:

- Observer output is post-dispatch only.
- Reconciliation is mutable sidecar state keyed by receipt/order ids.
- Budget realized spend does not exceed exposure.
- Reorg, timeout, failed release, refund, and partial settlement stay explicit.

Failure: move to recovery state without mutating signed receipt truth.

## CLI And API Proposal

### CLI

Add a `chio commerce` command group. Suggested commands:

- `chio commerce order init --buyer <id> --scope <scope> --max-amount <minor> --currency <code> --out <path>`
- `chio commerce rfq create --order <order.json> --providers <providers.json> --capability <cap.json>`
- `chio commerce rfq select --rfq <rfq.json> --bids <bids.json> --passports <dir> --reputation <dir> --federation <dir>`
- `chio commerce quote request --order <order.json> --provider <id>`
- `chio commerce quote accept --order <order.json> --quote <quote.json>`
- `chio commerce mandate bind --order <order.json> --ap2-intent <jwt> --ap2-checkout <jwt> --ap2-payment <jwt>`
- `chio commerce approval bind --order <order.json> --approval-token <token.json>`
- `chio commerce acp bind-token --order <order.json> --seller <seller> --shared-payment-token <token-ref> --max-amount <minor> --currency <code>`
- `chio commerce budget reserve --order <order.json> --quote <quote.json> --capability <id> --grant-index <n>`
- `chio commerce payment x402 challenge --order <order.json> --quote <quote.json> --resource <url>`
- `chio commerce payment x402 verify --order <order.json> --payment <payload> --facilitator <url>`
- `chio commerce payment x402 settle --order <order.json> --verify <verify.json>`
- `chio commerce payment acp verify --order <order.json> --token <token-ref>`
- `chio commerce fulfill accept --order <order.json> --fulfillment <fulfillment.json>`
- `chio commerce settlement packet --order <order.json> --validation-index <index.json>`
- `chio commerce settlement dispatch --packet <packet.json>`
- `chio commerce reconcile --order <order.json> --receipt <receipt.json>`
- `chio commerce dispute open --order <order.json> --reason <code> --evidence <path>`
- `chio commerce verify --bundle <dir>`

### API

Add a narrow trust-control or commerce-control API. Suggested endpoints:

- `POST /v1/commerce/orders`
- `GET /v1/commerce/orders/{order_id}`
- `POST /v1/commerce/orders/{order_id}/rfqs`
- `POST /v1/commerce/orders/{order_id}/provider-selection`
- `POST /v1/commerce/orders/{order_id}/quotes`
- `POST /v1/commerce/orders/{order_id}/quotes/{quote_id}/accept`
- `POST /v1/commerce/orders/{order_id}/mandates/ap2`
- `POST /v1/commerce/orders/{order_id}/approvals/chio`
- `POST /v1/commerce/orders/{order_id}/payments/acp/token-binding`
- `POST /v1/commerce/orders/{order_id}/budget-reservations`
- `POST /v1/commerce/orders/{order_id}/payments/x402/challenge`
- `POST /v1/commerce/orders/{order_id}/payments/x402/verify`
- `POST /v1/commerce/orders/{order_id}/payments/x402/settle`
- `POST /v1/commerce/orders/{order_id}/fulfillments`
- `POST /v1/commerce/orders/{order_id}/settlement-packets`
- `POST /v1/commerce/orders/{order_id}/settlement-dispatches`
- `POST /v1/commerce/orders/{order_id}/reconcile`
- `POST /v1/commerce/orders/{order_id}/disputes`
- `GET /v1/commerce/orders/{order_id}/passport`
- `GET /v1/commerce/orders/{order_id}/event-log`

API invariants:

- All mutating endpoints require idempotency keys.
- Every transition response returns latest state, event id, artifact digest, and
  Chio receipt ref or explicit denial.
- All endpoint handlers fail closed if previous state is not the expected state.
- APIs accept external protocol refs by digest and verification result, not by
  unchecked opaque strings.

## Proof And Passport Integration

The provider passport should move from a selection-side artifact into an
order-bound proof chain.

Required proof links:

- Provider passport digest is bound to provider bid digest.
- Provider bid digest is bound to provider selection digest.
- Provider selection digest is bound to quote request.
- Quote digest is bound to approval/mandate and budget hold.
- Payment verification digest is bound to quote digest and budget hold.
- Fulfillment digest is bound to quote digest and provider capability.
- Settlement packet digest is bound to payment verification, fulfillment, and
  budget hold.
- Final order passport aggregates the digests for selective disclosure.

Commerce-specific passport claims:

- `provider_id`
- `seller_scope`
- `service_families`
- `supported_payment_protocols`
- `supported_settlement_rails`
- `max_order_amount`
- `currency_support`
- `refund_policy_ref`
- `dispute_policy_ref`
- `fulfillment_sla_ref`
- `runtime_assurance_tier`
- `spiffe_workload_identity`
- `federation_authority`
- `reputation_score_ref`
- `x402_facilitator_refs`
- `ap2_merchant_or_processor_refs`
- `acp_seller_details`

Order passport output:

- `chio.commerce.order-passport.v1` should be the compact reviewer artifact.
- It should include all public proof refs and redacted private values.
- It should carry a `selective_disclosure_policy` so amount caps, mandate
  constraints, and token scopes can be proved without exposing unnecessary
  payment data.
- It should be accepted by the existing evidence review flow and rendered in the
  web3 evidence console.

## Tests And Gates

### Unit And Schema Gates

- Schema parse and canonical JSON hash tests for every `chio.commerce.*.v1`
  artifact.
- Golden hash tests for order context event logs.
- Transition table tests: every valid transition passes and every invalid
  transition fails closed.
- Quote digest binding tests across quote, approval, budget, payment,
  fulfillment, settlement packet, and reconciliation.
- AP2 mandate binding tests for direct, autonomous, expired, wrong agent key,
  wrong checkout hash, wrong merchant, wrong amount, and reused mandate cases.
- x402 transcript tests for challenge, verify, settle, strict amount mismatch,
  wrong resource, wrong payee, wrong chain, wrong token, facilitator failure,
  duplicate payment payload, and settlement failure after fulfillment.
- ACP delegated payment tests for wrong seller, amount over limit, currency
  mismatch, expired token, revoked token, duplicate use, missing PSP proof, and
  refund/capture reconciliation.
- Budget reservation tests for hold denied, hold below quote, stale hold,
  duplicate hold id, release, reverse, and reconcile.
- Settlement packet tests for missing budget hold, missing payment verification,
  wrong provider, wrong rail, wrong beneficiary, execution-window expiry, and
  amount mismatch.
- Dispute/refund tests for partial settlement amount ceiling, refund over
  captured amount, missing claimant signature, and receipt mutation attempt.

### Integration Gates

- Extend `examples/internet-of-agents-web3-network/smoke.sh` so the generated
  bundle contains `commerce/order-context.json`, `commerce/event-log.json`, and
  canonical commerce payment transcripts.
- Extend `internet_web3/verify.py` so bundle pass requires order state terminal
  `reconciled` or an explicit allowed recovery state.
- Add a negative fixture for every fail-closed transition listed above.
- Keep `agent-commerce-network` as the teaching example, but add a verifier note
  that launch-grade commerce verification lives in the web3 network bundle.
- Add UI fail-closed checks in the evidence console for missing commerce order
  context, mismatched quote/payment/settlement digests, and stale mandate/token.

### Existing Commands To Keep In The Gate Set

- `cargo test -p chio-kernel payment`
- `cargo test -p chio-kernel governed`
- `cargo test -p chio-settle payments`
- `cargo test -p chio-market`
- `examples/internet-of-agents-web3-network/smoke.sh`
- `CHIO_RUN_E2E=1 examples/internet-of-agents-web3-network/smoke.sh`
- `./scripts/qualify-web3-examples.sh`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace -- -D warnings`

Exact package test names may need adjustment when implementation lands, but the
gate categories should not shrink.

## Phased Implementation Plan

### Phase 0: Freeze The Contract In Docs And Schemas

Deliverables:

- Add `chio.commerce.order-context.v1` and the schema family listed above.
- Define the state machine as normative protocol text.
- Define AP2, x402, and ACP projection blocks as subordinate evidence, not as
  replacements for Chio receipts.
- Add sample artifacts derived from the current web3 example.

Exit gate:

- Schema examples hash deterministically.
- No state transition can be interpreted without an order id and previous-state
  assertion.

### Phase 1: Promote The Web3 Example To Commerce Context

Deliverables:

- Generate `commerce/order-context.json` and `commerce/event-log.json` from the
  existing `internet-of-agents-web3-network` flow.
- Bind existing RFQ, quote, approval, budget, payment, fulfillment, settlement,
  and dispute artifacts by digest into the order context.
- Preserve the current bundle paths for compatibility while adding canonical
  commerce refs.

Exit gate:

- Existing smoke still passes.
- New verifier fails on quote replay, missing budget hold, stale approval,
  mismatched payment proof, and settlement amount mismatch.

### Phase 2: Add Runtime Commerce Admission

Deliverables:

- Add a runtime validator for order transition events.
- Wire governed intent, approval token, budget hold, and payment adapter context
  to the order context.
- Add idempotency and replay ledger keyed by order id plus event id.
- Keep settlement observer post-dispatch only.

Exit gate:

- Payment adapter authorization cannot run unless the order is in the expected
  state and quote/budget/approval bindings match.
- Settlement dispatch cannot run unless the settlement packet verifies against
  the order context.

### Phase 3: Add External Protocol Bridges

Deliverables:

- AP2 mandate verifier/import path for mandate refs and checkout/payment receipt
  refs.
- x402 live facilitator challenge/verify/settle transcript capture.
- ACP/SPT delegated token verification capture with seller scope, max amount,
  expiry, revocation, and usage evidence.

Exit gate:

- Each protocol has a live or fixture-backed positive case and a matrix of
  negative cases.
- External protocol evidence cannot widen Chio authority beyond capability,
  budget, and settlement policy.

### Phase 4: Launch-Grade Review Surface

Deliverables:

- Add `chio commerce verify`.
- Add `/v1/commerce/orders/{order_id}/passport`.
- Render order passport and state machine in the evidence console.
- Add partner-facing docs that explain AP2, x402, ACP, and Chio responsibility
  boundaries without conflating payment interop with settlement truth.

Exit gate:

- A reviewer can start from one order passport and verify authority, budget,
  payment, fulfillment, settlement, reconciliation, and dispute status without
  reading scenario Python.

## Top Recommendations

1. Promote `chio.commerce.order-context.v1` to the launch contract before adding
   more rail integrations. The current examples are strong, but the order
   aggregate is still missing.
2. Treat AP2, x402, and ACP as evidence projections under Chio authority, not as
   authority replacements. Chio capabilities, budgets, receipts, and settlement
   dispatch remain the enforcement source.
3. Add the state machine and replay ledger before live x402 or ACP expansion.
   Otherwise every rail adapter will invent its own idempotency and failure
   semantics.
4. Bind provider passport/reputation/federation evidence directly into bid,
   quote, and settlement context. Selection proof without quote binding is too
   easy to replay.
5. Keep the settlement observer out of pre-dispatch gating. Build a separate
   commerce admission gate before payment authorization, fulfillment, and
   settlement dispatch; use the observer only for post-receipt reconciliation and
   recovery.
