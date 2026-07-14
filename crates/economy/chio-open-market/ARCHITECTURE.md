# chio-open-market architecture

## Overview

`chio-open-market` is a pure logic crate: no I/O, no runtime state, and
`#![forbid(unsafe_code)]`. It implements two state machines for Chio's open
capability marketplace: the bid/ask/accept protocol that mints capability
tokens against a published listing, and the penalty state machine that holds
or slashes bonds under governance sanction. It sits above `chio-listing`
(listings, pricing hints) and `chio-governance` (charters, cases) in the
economy layer; every entry point takes already-fetched signed artifacts and is
the fail-closed judge of whether they satisfy market rules, without fetching,
storing, or mutating that state itself.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate documentation, re-exports from `chio-core-types`/`chio-governance`/`chio-listing`, and module declarations. |
| `src/bidding.rs` (+ `bidding/tests.rs`) | Bid/ask/accept protocol: request validation, listing and pricing admissibility, capability token minting, settlement acceptance. |
| `src/fee_schedule.rs` | Economics scope, bond requirements, signed fee-schedule artifacts, and the fee-schedule builder. |
| `src/penalty.rs` | Abuse classes, penalty actions/states, signed penalty artifacts, and the penalty builders. |
| `src/evidence.rs` | Evidence-reference and finding-code types shared by evaluation output. |
| `src/evaluation.rs` | Penalty evaluation request/result types and the fail-closed evaluation state machine. |
| `src/authority.rs` | `pub(crate)` signature verification wrappers and trusted-governing-signer checks shared by issuance and evaluation. |
| `src/validation.rs` | `pub(crate)` monetary-amount, non-empty, and SHA-256-hex field validators. |
| `src/tests.rs` | Crate-level penalty and fee-schedule evaluation tests. |

## Bid and penalty lifecycles

`bid` validates the signed `BidRequest`, verifies the listing and pricing-hint
signatures, checks listing/pricing identity and provider-authority binding,
rejects an inactive, stale, or expired-pricing listing, then mints a scoped
`CapabilityToken` and returns a signed `AskResponse`. `accept` verifies the ask
and its token, checks acceptance timing against the ask's issued/expires
window, and matches a `VerifiedReservationReceipt` against the ask's total
token liability before returning a signed `AcceptedBid`.

`evaluate_open_market_penalty[_with_trusted_signers]` verifies every signed
input (listing, fee schedule, activation, charter, case, penalty, prior
penalty) and trusted-signer membership, cross-checks namespace and operator
linkage between them, rejects expired artifacts, resolves the fee schedule's
bond requirement for the penalty's bond class, applies action-specific rules,
and derives the effective state. A failure at any of these steps short-circuits
into a successful `OpenMarketPenaltyEvaluation` carrying one `OpenMarketFinding`
rather than an `Err`; the outer `Result` is `Err` only when the request's own
listing or publisher shape is invalid.

## Invariants and failure modes

- Requested capability scope may only narrow the listing's advertised
  `capability_scope` prefix (checked segment-wise), never widen or diverge
  from it; the requested `server_id` must equal the listing subject's
  `actor_id`.
- Bidding fails closed on an inactive/stale listing, expired pricing, a
  listing/pricing identity mismatch, a provider-authority mismatch, a currency
  mismatch, a bid ceiling below the quoted price, and `u64` total-cost
  overflow when minting a multi-invocation token.
- `accept` requires the acceptor's key to equal the token subject, requires
  `accepted_at` in `[ask.issued_at, ask.expires_at)`, and requires the
  reservation's `agent_id`/`listing_id`/`ask_digest` to match the ask exactly
  and its `reserved_amount` to cover the ask's total token liability (same
  currency, units at least the required amount).
- `HoldBond` and `SlashBond` require an enforced `Sanction` governance case;
  `SlashBond` additionally requires the resolved bond requirement to be
  `slashable`. `ReverseSlash` requires an `Appeal` case and a
  `supersedes_penalty_id`-referenced `prior_penalty` that is itself an
  enforced hold or slash for the same listing, fee schedule, and bond class.
- Penalty issuance requires the fee schedule, charter, and case to share the
  issuing operator's `governing_operator_id`, and any trust activation to be
  issued by that same operator; both issuance and evaluation require every
  artifact's signer to appear in the caller-supplied trusted-signer list.
- The crate holds no runtime state and does not persist balances, dispatch
  tools, or issue receipts; `bidding.rs` notes it deliberately does not depend
  on a receipt store.

## Dependencies

Internal: `chio-core-types` supplies `capability` (scope and token types),
`crypto` (`Keypair`, `PublicKey`, `sha256_hex`),
`receipt::lineage::SignedExportEnvelope` (the signed-envelope wrapper every
artifact in this crate uses), and `canonical_json_bytes`. `chio-listing`
supplies listing, pricing-hint, namespace, and trust-activation types plus
`normalize_namespace` and `provider_signing_key`. `chio-governance` supplies
the generic governance charter and case types. No dependency aliasing.
External: `serde` for artifact (de)serialization, `thiserror` for
`BiddingError`.
