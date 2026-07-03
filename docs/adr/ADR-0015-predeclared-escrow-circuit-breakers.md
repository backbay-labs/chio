# ADR-0015: Predeclared Non-Discretionary Escrow Circuit Breakers

- Status: Proposed
- Decision owner: economy and settlement lane
- Related invariant: invariant 10 (no discretionary emergency intervention; circuit breakers are predeclared)
- Related plan items: M4 slashing/adjudication gate; also touches invariant 9 (penalty proceeds never accrue to insiders)

## Context

On 2025-03-26 Hyperliquid delisted the JELLY (JELLYJELLY) perpetual after its
HLP vault was squeezed in a roughly $13.5M tussle. Rather than let the position
settle at the prevailing market mark, validators intervened at their discretion
and force-settled the disputed market at the attacker's entry price. That single
discretionary re-pricing flipped a ~$13.5M vault loss into a reported ~$700k
protocol profit and drew "FTX 2.0" criticism
(https://www.coindesk.com/markets/2025/03/26/hyperliquid-delists-jellyjelly-after-vault-squeezed-in-usd13m-tussle).

The failure had three distinct components, and it is worth separating them
because Chio inherits the risk surface for each:

1. **Discretion.** A privileged quorum chose, after the fact, to close a live
   market that no predeclared rule required closing.
2. **Re-pricing.** The forced-close settlement price was selected (the attacker's
   entry price) rather than derived from a committed, evidenced value.
3. **Self-dealing direction.** The chosen price moved value toward the protocol
   treasury, converting a counterparty loss into protocol profit.

Chio's token-invariants one-pager encodes the lesson as a hard invariant, not a
preference. Invariant 10 requires that "Dispute conditions and settlement prices
are written ex ante into contracts and ADRs, with no override path, and never a
settlement price that turns protocol loss into protocol profit," and it binds
"escrow dispute handling and the M4 slashing/adjudication ADRs (anti-JELLY
policy)" (invariant 10; the related invariant 9 requires that slash, tax, or trap proceeds
"go to harmed parties or the community fund, never team wallets"). Under the
house fail-closed rule a violation is a design rejection, not a trade-off.

This ADR is the anti-JELLY policy that invariant 10 points at. It records the
circuit-breaker posture for Chio's escrow, bond, and claim settlement paths, and
maps each existing function to that posture so future changes cannot silently
re-open a JELLY-shaped lane.

## Decision

Chio adopts the following posture for any forced or contested closure of an
escrow, bond, or liability-claim settlement. It is a posture of subtraction: the
default is that no discretionary closure exists, and the only terminal states are
the ones already committed at open time.

### D1. No discretionary emergency intervention on the value-movement path

The value-movement contracts (`ChioEscrow`, `ChioBondVault`) carry no owner,
no admin, no guardian, no pause, and no upgrade or emergency lane, and they must
not acquire one. There is no address that can move, freeze, re-route, or
re-price escrowed or bonded funds outside the functions enumerated at open time.
This property exists today and is now normative: adding a privileged override to
these contracts is a rejected design.

### D2. Terminal states are predeclared and price-free

Every escrow has exactly two predeclared terminal outcomes, both fixed at
`createEscrow` time and neither of which selects a price:

- **Release**: the pre-named beneficiary is paid the amount proven by a signed
  receipt (Merkle inclusion against an operator-signed root, or an operator
  settlement-key signature), capped at the deposit.
- **Refund**: after the committed `deadline`, the unspent remainder returns to
  the depositor.

There is no third "forced settlement at a chosen price" state. The Chio analog
of a "settlement price" is an evidenced amount (`settledAmount`,
`awarded_amount`, `settlement_amount`), never a quoted or after-the-fact mark.
Each such amount must be monotone non-increasing down the chain
(coverage >= claim >= award >= settlement) and must be backed by a signed
artifact.

### D3. Circuit-breaker conditions are enumerated ex ante or they do not fire

If Chio ever needs an early-closure circuit breaker (for example: operator-key
compromise, a frozen or forked root registry, or a sanctioned counterparty),
the triggering condition, the resulting routing, and the amount rule must all be
written into contract code and into this ADR before the breaker can fire. A
breaker that is decided after the triggering event, by a human or a quorum, is
prohibited. Absence of a predeclared breaker means the escrow runs to its
existing release-or-refund terminal states; it is never closed ad hoc.

### D4. A forced closure never re-prices, and never pays the protocol

No circuit breaker may select a settlement price. A predeclared breaker may only
route an already-committed, evidenced amount to a predeclared destination. The
permitted destinations are exhausted by:

- the **harmed counterparty** (the depositor, the bond principal, or the
  coverage beneficiary/subject of record), or
- a **registered community fund** address anchored ex ante (for example, in
  `ChioRootRegistry`).

A settlement or slash that would send value to the protocol treasury, an
operator wallet, an insider, or any address outside that enumerated set is
rejected at validation time. In particular, no closure may set an amount that
converts a counterparty loss into protocol or insider gain. This is the
structural form of invariants 9 and 10.

### D5. Adjudication chooses among fixed outcomes; it does not invent them

Liability-claim adjudication remains a choice among the predeclared outcomes
(`claim_upheld`, `provider_upheld`, `partial_settlement`) within the existing
amount envelope (award never exceeds the claim; a partial award is strictly
less). Adjudication is not a lane for setting a novel price or a novel payee. Who
may adjudicate, and the rule they apply, must be predeclared (see Required
follow-up B); the amount ceiling is already enforced.

## Rationale

The cheapest way to be un-JELLY-able is to have nowhere for discretion to live.
Chio's escrow and bond contracts already have that shape: they hold only the
depositor's own funds, pay out only to parties named at open time, cap every
release at the deposit, and expose no privileged function. There is no "disputed
market" object for a quorum to seize, because the only contested dimension on
chain is release-versus-refund, and both branches are predeclared and
price-free. Encoding that as policy (rather than leaving it an accident of the
current code) means a future PR that adds a pause or an admin-settled path is
visibly a violation of this ADR and of invariant 10, not a judgement call.

Keeping settlement amounts evidenced and monotone non-increasing closes the
re-pricing vector directly. JELLY's harm was choosing a price; Chio never
chooses one, it proves one, and the proven amount can only shrink as it flows
from coverage to claim to award to settlement.

Constraining destinations to the harmed party or a pre-registered community fund
closes the self-dealing direction. The comptroller already enforces this for the
`market_slash` lane (payee must be the coverage beneficiary or subject) and caps
each slash by a signed sanction authority. The residual work (Required follow-up
A and B) is to push the same enforcement down into `ChioBondVault.impairBond`
and into the adjudicator identity, so the property holds structurally rather than
by the good behavior of whoever signs.

## Consequences

### Positive

- The escrow and bond settlement path is provably free of discretionary
  intervention: there is no address that can force a close or pick a price.
- Every payout amount is traceable to a signed artifact and is bounded above by
  the deposit or coverage, so no closure can mint protocol profit from a
  counterparty loss.
- Invariants 9 and 10 gain a concrete, testable home; a reviewer can reject a
  pause, an admin re-route, or a treasury-payee path by pointing at this ADR.
- The policy is legible to counterparties: depositors know at open time that the
  only outcomes are proven-release and post-deadline-refund.

### Negative

- Chio cannot "make a victim whole" by fiat after an incident. If a counterparty
  is harmed by something outside the predeclared breakers, the remedy is a future
  predeclared breaker plus off-chain restitution, not an emergency on-chain
  re-route. This is the intended cost of being un-JELLY-able.
- Adjacent admin surfaces (see the mapping below) still exist and must be watched;
  the no-discretion property is only as strong as the constraints on operator
  deactivation and price-feed administration.
- Two follow-ups (A, B) are needed before the destination and adjudicator
  constraints are fully structural rather than partly trusted.

## Mapping to current functions

Read against the code as it stands. "Complies" means the function already
satisfies D1-D5; "Change" means a proposed follow-up is required (tracked below,
not implemented here).

### Solidity value-movement path

- **`ChioEscrow.createEscrow` / `createEscrowWithPermit`**
  ([../../contracts/src/ChioEscrow.sol](../../contracts/src/ChioEscrow.sol)):
  Complies. Terms (beneficiary, token, `maxAmount`, `deadline`, operator) are
  fixed at open time; the escrow id is a deterministic hash of the terms; the
  depositor funds only its own escrow.
- **`ChioEscrow.releaseWithProofDetailed` / `releaseWithSignature` /
  `partialReleaseWithProofDetailed`**: Comply. Release is gated on a signed
  receipt (Merkle inclusion against an operator-signed root, or the operator
  settlement key), routed only to `escrow.terms.beneficiary`
  (`_requireBeneficiary`), allowed only while live (`_ensureLive`), and capped at
  the deposit (`_ensureReleaseAmount`). No price is selected and the protocol is
  never the payee. The `releaseWithProof` / `partialReleaseWithProof` non-detailed
  entrypoints revert `ProofMetadataRequired`, which is fail-closed.
- **`ChioEscrow.refund`**: Complies. Callable only after the committed `deadline`;
  returns `deposited - released` to the depositor. Predeclared and price-free.
- **`ChioEscrow`** overall: Complies with D1. No owner, admin, pause, guardian,
  upgrade, `selfdestruct`, or `delegatecall`; the constructor only wires two
  immutable registries.
- **`ChioBondVault.lockBond` / `releaseBondDetailed` / `expireRelease`**
  ([../../contracts/src/ChioBondVault.sol](../../contracts/src/ChioBondVault.sol)):
  Comply. Collateral is self-locked by the principal; release and expiry return
  `lockedAmount - slashedAmount` to the principal only; no admin lane exists.
- **`ChioBondVault.impairBondDetailed`**: Partial. It is evidence-gated (Merkle
  proof against an operator-signed root), operator-only, bounded by the remaining
  locked amount, and requires `sum(shares) == slashAmount` exactly. But the
  `beneficiaries[]` set is chosen by the operator at call time; nothing on chain
  constrains it to the harmed party or a registered community fund. This is the
  residual discretionary destination surface. **Change: follow-up A.**

### Rust claim / adjudication / comptroller path

- **`quote_and_bind`**
  ([../../crates/economy/chio-market/src/insurance_flow.rs](../../crates/economy/chio-market/src/insurance_flow.rs)):
  Complies. Deterministic pricing then bind; fail-closed on a missing premium
  source. It is the pricing side, not a settlement lane.
- **`BoundPolicy::file_claim` / `ClaimDecision`** (same file): Comply. Deterministic
  and fail-closed; every denial is an enumerated `ClaimDenialReason`; the payout
  is capped at the coverage limit (`requested.min(coverage_limit)`). No discretion,
  no protocol payee.
- **`LiabilityClaimAdjudicationArtifact`**
  ([../../crates/economy/chio-market/src/claim.rs](../../crates/economy/chio-market/src/claim.rs)):
  Partial. The outcome set is a fixed enum (`claim_upheld`, `provider_upheld`,
  `partial_settlement`) and the amount envelope is enforced (award <= claim; a
  partial award is strictly less than the claim), so no re-pricing above the
  claim is possible. But `adjudicator` is a free string and the choice among
  outcomes is discretionary, with no predeclared adjudicator roster and no
  reference to the ex-ante rule applied. **Change: follow-up B.**
- **`LiabilityClaimPayoutInstructionArtifact` /
  `LiabilityClaimSettlementInstructionArtifact`**
  ([../../crates/economy/chio-market/src/settlement.rs](../../crates/economy/chio-market/src/settlement.rs)):
  Comply. The amount chain is monotone non-increasing (`payout_amount` matches
  the adjudicated award; `settlement_amount` cannot exceed `payout_amount`); the
  payer/payee are explicit party bindings threaded from the claim subject; the
  protocol is never the payee.
- **Comptroller `market_slash` lane**
  ([../../crates/platform/chio-risk-comptroller/src/ledger.rs](../../crates/platform/chio-risk-comptroller/src/ledger.rs),
  [../../crates/platform/chio-risk-comptroller/src/lib.rs](../../crates/platform/chio-risk-comptroller/src/lib.rs)):
  Complies. Each `market_slash` entry must carry a signed sanction bridge with a
  predeclared `maximum_slash_units` cap (`units > maximum_slash_units` is
  rejected), evidence, authority, and jurisdiction refs; and the settlement
  counterparty check forces the payee to be the coverage `beneficiary_subject`
  (or the coverage `subject`), never the protocol. This is the reference
  implementation of D4 that follow-up A should mirror on chain.

### Adjacent admin surfaces (watch list, not part of the settlement path)

- **`ChioIdentityRegistry`**
  ([../../contracts/src/ChioIdentityRegistry.sol](../../contracts/src/ChioIdentityRegistry.sol))
  has an `admin` that can `deactivateOperator`, and **`ChioPriceResolver`**
  ([../../contracts/src/ChioPriceResolver.sol](../../contracts/src/ChioPriceResolver.sol))
  has an `admin` that can set prices. Neither can move escrowed or bonded funds,
  so neither is a JELLY lane on its own. But operator deactivation and price-feed
  administration are the two places where upstream discretion could indirectly
  starve or mis-value a settlement. They are out of scope for this ADR's
  guarantees and are called out so a future change does not turn one of them into
  a back door around D1-D4.

## Required follow-up

These are proposed changes, not part of this ADR. They exist to make D4 and D5
structural rather than partly trusted.

- **A. Constrain `ChioBondVault.impairBondDetailed` slash destinations.** Bind the
  `beneficiaries[]` set to a predeclared allowlist: the harmed party of record
  derived from the bond terms plus a registered community-fund address anchored
  ex ante (for example in `ChioRootRegistry`). Reject any beneficiary outside the
  allowlist. This lifts invariants 9 and 10 from "the operator routes correctly"
  to "the contract cannot route anywhere else," matching what the comptroller
  `market_slash` lane already enforces off chain.
- **B. Constrain adjudicator identity and record the rule.** Constrain
  `LiabilityClaimAdjudicationArtifact.adjudicator` to a predeclared roster or
  authority anchored in a registry, and require the artifact to reference the
  predeclared decision rule (or circuit-breaker condition id) it applied. Keep the
  existing fixed outcome set and amount envelope. No new discretionary override
  lane is introduced.
- **C. Guard the adjacent admin surfaces.** Document and, where feasible,
  constrain `ChioIdentityRegistry` operator deactivation and `ChioPriceResolver`
  price administration so neither can be used to indirectly force or mis-value a
  settlement in a way D1-D4 would otherwise forbid on the value path.

## Non-goals

- Introducing any new on-chain circuit breaker in this ADR. This ADR sets the
  conditions a future breaker must satisfy; it does not add one.
- Adding a mechanism to make harmed parties whole by discretionary on-chain
  re-route after an unforeseen incident. That is precisely the JELLY lane this
  ADR forecloses.
- Changing pricing, premium, or coverage logic; those sit upstream of the
  settlement posture governed here.
