# chio-commerce-order architecture

## Overview

`chio-commerce-order` is a pure verification library: no I/O, no network
calls, no runtime state. It sits downstream of a commerce order's artifacts
(order context, event log, payment lifecycle, mandate allowance ledger,
provider trust evidence, settlement packet, kernel authority receipts) and
answers one question: are these artifacts internally consistent with each
other and with the order context. Per `DESIGN.md`, it does not move funds,
price markets, select providers, or issue risk decisions; those concerns
belong to `chio-market`, `chio-credit`, and `chio-settle`. This crate only
replays and cross-checks evidence those systems already produced.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `verify_commerce_order`: shape validation, quote and artifact digest binding, optional coverage/trust-market checks, deserialization, dispatch into the other modules, and passport assembly. |
| `src/types.rs` | Wire types: `CommerceOrderContext`, `CommerceOrderVerificationBundle`, the coverage and trust-market requirement/evidence pairs, `CommerceOrderPassportReport` and its digest/disclosure sub-types, and the crate-private artifact structs (payment lifecycle, settlement packet, provider passport, reputation snapshot, federation trust bundle). |
| `src/ids.rs` | Schema id constants, one per artifact kind. |
| `src/error.rs` | `CommerceOrderError`, one variant per validation domain. |
| `src/validation.rs` | Shared low-level checks: non-empty, sha256-hex, bundle-relative path, money, RFC 3339 parsing. |
| `src/replay.rs` | Event log deserialization and FSM replay; per-event authority-receipt verification. |
| `src/provider.rs` | Provider passport, reputation snapshot, and federation trust bundle cross-checks and signature verification. |
| `src/mandate.rs` | Mandate allowance ledger cross-checks and AP2 / x402 / ACP-Commerce / Chio protocol-projection binding. |
| `src/payment.rs` | Payment lifecycle cross-checks, PSP object-ref conventions, and signature verification. |
| `src/settlement.rs` | Settlement packet cross-checks and dispatch-receipt verification. |

## Verification pipeline

`verify_commerce_order` runs a fixed sequence; any failure returns
`Err(CommerceOrderError)` and no report is produced.

1. Shape-validate the order context: schema id, required fields, money
   invariants, digest formats, and artifact paths.
2. Recompute and check the canonical quote digest and the seven per-artifact
   digests against the context's declared `*_sha256` fields, before any
   artifact is parsed.
3. If declared required, verify the risk-comptroller coverage report
   (digest and `chio-risk-comptroller` signature) and cross-check the
   caller-asserted trust-market context's refs against the requirement.
4. Deserialize the seven artifacts (`#[serde(deny_unknown_fields)]`).
5. Replay the event log against the transition table in `replay.rs`,
   verifying per-event evidence refs and authority receipts. The final
   replayed state must equal `context.current_state`.
6. Cross-check provider trust evidence, the mandate ledger, the payment
   lifecycle, and the settlement packet (which also binds to the replayed
   dispatch event) against the context and against each other.
7. Assemble `verified_claims` and return the `CommerceOrderPassportReport`.

## Invariants and failure modes

- No artifact is trusted before its digest matches the context's declared
  value; digests are recomputed locally (sha256 over raw bytes, or sha256
  over RFC 8785 canonical JSON for the quote binding and event bodies).
- Every authority receipt, per-event and settlement-dispatch, must carry
  `ReceiptKind::MediatedDecision`, `BoundaryClass::Prevent`,
  `TrustLevel::Mediated`, and `Decision::Allow`, and its kernel key must be
  in the caller-supplied trusted set. No other receipt shape authorizes an
  event.
- The settlement dispatch receipt must match the specific dispatch event
  observed during replay, by ref and content hash; a matching
  `dispatch_receipt_ref` string alone is insufficient. Settlement binds to replayed
  history, not to an independently supplied receipt.
- The trust-market context is a caller assertion: this crate checks its
  refs are consistent with the order context's declared requirement but
  does not verify how it was produced.
- A `current_state` of `"failed_closed"` relaxes several checks: payment
  `payment_status` may be `"succeeded"` or `"failed"` (otherwise only
  `"succeeded"` is accepted), payment recovery posture (dispute, refund,
  chargeback, transfer-reversal status) is not checked at all, and replay
  does not require having observed `mandate_bound` or `payment_verified`
  events.
- Bundle-relative paths reject absolute paths, drive letters, backslashes,
  and `..` components. The crate validates path shape only; it never reads
  from or resolves against a filesystem itself.
- The selective-disclosure policy on the passport report is declarative: it
  names underlying-artifact fields (buyer/agent subjects, payment intent
  id, mandate protocol hashes) the caller must keep redacted. The crate
  does not enforce redaction itself.
- Mandate protocol projections and payloads are matched by
  `(protocol, purpose)` pairs and must be duplicate-free; each of the five
  expected pairs (`ap2/checkout_mandate`, `ap2/payment_mandate`,
  `acp-commerce/delegated_payment_token`, `x402/payment_requirements`,
  `chio/authority_projection`) must be present with a payload whose sha256
  matches the projection's declared digest.

## Dependencies

Internal: `chio-core-types` supplies canonical JSON, the `PublicKey` /
`Signature` crypto types and `verify_canonical`, and the `ChioReceipt` type
this crate verifies signatures and content hashes against (no dependency
aliasing; it is imported under its own name). `chio-risk-comptroller`
supplies `validate_risk_report_signature` for the optional coverage report.

External: `chrono` (RFC 3339 parsing and ordering), `sha2` / `hex` (digest
computation), `serde` / `serde_json` (artifact deserialization with
`deny_unknown_fields`), `thiserror` (`CommerceOrderError`). Dev-only:
`chio-test-support`.
