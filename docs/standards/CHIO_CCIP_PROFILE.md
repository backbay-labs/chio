# Chio CCIP Profile

## Purpose

This profile freezes Chio's bounded CCIP coordination surface.

The shipped lane is not a generic bridge. It transports one bounded settlement
coordination message family and reconciles delivery back to canonical Chio
execution receipts.

## Shipped Boundary

Chio now ships one CCIP message family with these properties:

- the source and destination chains must be distinct and explicitly pinned
- the router address, payload size ceiling, execution gas ceiling, and
  expected latency are configured per lane
- the message payload is derived from one canonical
  `chio.web3-settlement-execution-receipt.v2`
- delivery is accepted only if the destination chain and payload hash match
  the prepared message exactly
- duplicate delivery is suppressed fail closed
- delayed delivery remains explicit rather than being treated as normal success

## Supported Coordination Scope

The shipped payload carries:

- dispatch id
- execution receipt id
- settlement reference
- lifecycle state
- settled amount
- beneficiary address

This is enough to coordinate one bounded settlement handoff without claiming
generic cross-chain execution.

## Reference Artifacts

- `docs/standards/CHIO_CCIP_MESSAGE_EXAMPLE.json`
- `docs/standards/CHIO_CCIP_RECONCILIATION_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json`

## Failure Posture

The runtime rejects or downgrades when:

- the CCIP lane names the same source and destination chain
- the validity window is shorter than twice the expected latency
- the payload exceeds the bounded maximum
- delivery arrives on an unsupported chain
- the observed payload hash differs from the prepared message
- the same message id is seen more than once
- delivery arrives after the bounded validity window

## Non-Goals

This profile does not claim:

- arbitrary cross-chain routing or solver networks
- fund custody transfer by CCIP alone
- permissionless chain discovery
- silent reconciliation that mutates prior Chio receipt truth

The shipped lane is settlement coordination only.
