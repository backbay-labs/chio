# chio-listing

`chio-listing` defines Chio's generic listing and trust-activation contracts.
It provides the signed `Listing` artifact, listing search and comparison, SLA
and pricing-hint shapes, and the trust-activation flow that turns a discovered
listing into a locally admissible one. Listings are signed by their namespace
owner and verification is pure.

Use this crate to publish, discover, compare, and activate marketplace
listings. Governance and open-market contracts (`chio-governance`,
`chio-open-market`) build on these types.
