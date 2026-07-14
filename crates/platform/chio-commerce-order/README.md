# chio-commerce-order

Offline verifier for a Chio commerce order proof bundle. Given an order
context and the raw bytes of every artifact it references (event log,
payment lifecycle, mandate allowance ledger, provider trust evidence,
settlement packet, kernel authority receipts, and optional risk-coverage and
trust-market evidence), it replays the order's state transitions, checks
every digest, signature, and cross-reference, and emits a passport report
summarizing what verified.

The crate is pure verification: no I/O, no network calls, no runtime state,
and no market, payment, or risk decisions of its own (see `DESIGN.md`).
`chio-cli`, `chio-proof-room`, and `chio-control-plane` assemble the bundle
from stored artifacts and call into this crate to judge it.

## Responsibilities

- Validate the shape of a `CommerceOrderContext`: schema id, required
  fields, money invariants, sha256-hex digest format, and bundle-relative
  artifact paths (rejects absolute paths and `..` traversal).
- Bind every referenced artifact to its declared digest
  (`sha256(bytes) == context.*_sha256`) before parsing it.
- Replay the order's event log against a fixed transition table, requiring
  monotonic timestamps, unique event and idempotency ids, evidence refs per
  transition, and a kernel-issued authority receipt (verified signature,
  action hash, and decision) behind every event.
- Cross-check the payment lifecycle, the mandate allowance ledger (AP2,
  x402, ACP-Commerce, and Chio protocol projections), provider trust
  evidence (passport, reputation snapshot, federation trust bundle), and
  the settlement packet against the order context and against each other.
- Verify an optional risk-comptroller coverage decision report
  (`chio-risk-comptroller`) by digest and signature, and cross-check its
  coverage id, order, verdict, and currency against the order context, when
  required.
- Cross-check an optional trust-market context, asserted by the caller and
  not independently verified here, against the order context's declared
  requirement refs.
- Emit a `CommerceOrderPassportReport` carrying a fixed selective-disclosure
  policy naming which passport fields may be shared and which underlying
  artifact fields must stay redacted.

## Public API

- `verify_commerce_order(&CommerceOrderVerificationBundle) ->
  Result<CommerceOrderPassportReport, CommerceOrderError>` - the sole entry
  point.
- `CommerceOrderVerificationBundle` - the order context, every referenced
  artifact's raw bytes, trusted signer key sets, and optional
  coverage/trust-market evidence.
- `CommerceOrderContext`, `CommerceCoverageRequirement`,
  `CommerceTrustMarketRequirement`, `CommerceVerifiedTrustMarketContext` -
  the order-context wire type and its two optional requirement/evidence
  pairs.
- `CommerceMandateProtocolPayload`, `CommerceEventAuthorityReceiptArtifact`
  - side artifacts referenced by ref from the context rather than embedded
  in it.
- `CommerceOrderPassportReport` - the verifier's output: verdict, replayed
  `current_state`, artifact digests, disclosure policy, and
  `verified_claims`.
- `CommerceOrderError` - `thiserror` enum, one variant per validation
  domain (schema, artifact shape, digest, replay, payment, mandate,
  provider trust, settlement, coverage).
- Schema id constants: `COMMERCE_ORDER_CONTEXT_SCHEMA_ID`,
  `COMMERCE_EVENT_LOG_SCHEMA_ID`, `COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID`,
  `COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID`,
  `COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID`,
  `COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID`,
  `COMMERCE_PROVIDER_PASSPORT_SCHEMA_ID`,
  `COMMERCE_REPUTATION_SNAPSHOT_SCHEMA_ID`,
  `COMMERCE_FEDERATION_TRUST_BUNDLE_SCHEMA_ID`,
  `COMMERCE_ORDER_PASSPORT_SCHEMA_ID`.

## Testing

`cargo test -p chio-commerce-order`

Integration tests in `tests/commerce_order.rs` read fixtures from
`fixtures/proof-room/commerce-payments/` and
`fixtures/proof-room/enterprise-export/` at the workspace root.

## See also

- `chio-risk-comptroller` - produces the coverage decision report this
  crate optionally verifies.
- `chio-core-types` - canonical JSON, hashing, receipt, and signing types
  this crate verifies against.
- `chio-cli`, `chio-proof-room` - assemble a
  `CommerceOrderVerificationBundle` from stored artifacts and call
  `verify_commerce_order`.
- `chio-control-plane` - re-exports this crate as `commerce_order`.
- `chio-market`, `chio-credit`, `chio-settle` - own the live marketplace,
  credit, and settlement execution this crate only verifies evidence of.
