# chio-open-market

`chio-open-market` defines Chio's open-market economics and penalty contracts.
It provides the bidding flow (`bid`, `accept`, and the bid/ask/accepted-bid
artifacts) plus bond requirements, collateral references, abuse classes, and
penalty state machines. `accept` returns a signed accepted-bid record, requires
the agent/token subject to sign the acceptance, and binds it to an opaque
`VerifiedReservationReceipt` produced from a signed funds-reservation receipt
covering the accepted ask, quoted price, listing, and agent. It builds on the
listing and governance surfaces in `chio-listing` and `chio-governance`.

Use this crate to model open bidding for tool access along with the bonds and
penalties that back it.
