# Chio Functions Fallback Profile

## Purpose

This profile closes phase `161` by freezing Chio's bounded Chainlink Functions
fallback for Ed25519-constrained proof verification on EVM rails.

The shipped surface is intentionally narrow. It exists to audit or spot-check
receipt batches when the EVM environment cannot natively verify the required
Ed25519 material. It does not authorize direct fund release, mutate canonical
Chio receipts, or widen trust from DON execution alone.

## Shipped Boundary

Chio now ships one bounded Functions fallback with these rules:

- supported purposes are `anchor_audit_batch` and `receipt_spot_check`
- every receipt in a submitted batch must already pass local Chio signature
  verification before a request is prepared
- batch size, request size, callback gas, returned bytes, and notional value
  are all bounded by explicit policy
- the fallback remains audit-only: `allow_direct_fund_release` must stay
  `false`
- successful DON execution still requires the receipt batch root, target
  chain, and verified receipt count to match the prepared request exactly
- rejected or unsupported results remain explicit and fail closed

## Bounded Default Policy

The default runtime policy in `crates/economy/chio-anchor/src/functions.rs` is:

- maximum receipt batch size: `25`
- maximum request size: `30000` bytes
- maximum callback gas limit: `300000`
- maximum return payload: `256` bytes
- maximum notional value: `1000000` USD cents
- direct fund release: disabled
- receipt event log requirement: enabled
- challenge window: `3600` seconds

## Reference Artifacts

The bounded reference set for this fallback is:

- `docs/standards/CHIO_FUNCTIONS_REQUEST_EXAMPLE.json`
- `docs/standards/CHIO_FUNCTIONS_RESPONSE_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_AUTOMATION_QUALIFICATION_MATRIX.json`

## Failure Posture

The fallback rejects or downgrades when:

- the batch is empty or exceeds the configured bounds
- the callback gas limit or request payload exceeds the bounded policy
- a receipt fails local signature verification before submission
- the DON response names the wrong chain, wrong request id, wrong batch root,
  or an excessive return size
- the DON returns `rejected` or `unsupported`

In all of those cases, Chio retains local signed receipt truth and denies any
attempt to treat the Functions outcome as a hidden execution authority.

## Non-Goals

This profile does not claim:

- native on-chain Ed25519 verification on EVM
- arbitrary JavaScript compute or generalized DON workflows
- direct escrow release, refund, or settlement authority from Functions
- permissionless fallback discovery or multi-DON trust expansion

Those surfaces would require a separate bounded contract and are not part of
the shipped profile.
