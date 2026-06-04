# chio-open-market Architecture

## Boundary

`chio-open-market` owns Chio open bidding plus market fee schedules, bond requirements, and penalty state machines. It depends on listing and governance artifacts, then adds economic constraints around publication fees, participation fees, collateral classes, holds, slashes, and reverse slashes.

The crate models market authorization and economics. It does not run settlement rails, persist balances, dispatch tools, or issue receipts. Callers provide signed listings, signed pricing hints, governance material, provider keys, and the current evaluation time.

## Bid Flow

Bidding verifies signed listings and pricing hints before minting scoped capability offers. The bid path must reject stale pricing, inactive listings, scope widening, token issuer mismatches, and total-cost overflow before an ask can be accepted.

Accepted bids bind the original bid digest, ask digest, quoted price, receipt id, token id, token subject, and expiry. This keeps settlement and replay verification anchored to the same canonical bid/ask pair.

## Penalty Flow

Penalty evaluation verifies fee-schedule, governance, activation, listing, and penalty signatures before applying market rules. Evidence references are part of that authorization trail, so optional digests must be syntactically valid SHA-256 hex when present.

Penalty state changes are explicit: hold, slash, reverse slash, deny, and supersede are separate outcomes. The effective state should be derivable from signed inputs without hidden mutable state in this crate.

## Invariants

- Signed listing and pricing artifacts must verify before bids mint offers.
- Requested scope may narrow a listing, never widen it.
- Monetary amounts must reject empty currencies and arithmetic overflow.
- Penalty evidence digests must be valid when present.
- Market logic returns structured findings instead of silently accepting gaps.
