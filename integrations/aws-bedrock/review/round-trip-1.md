# AWS Marketplace Reviewer Round Trip 1

Date opened: 2026-05-02
Date resolved: 2026-05-02

Reviewer comment:

The listing package needs a single customer-shape evidence trail that
connects Quick Launch, IAM customer attach, entitlement lookup, first
receipt under base quota, overage metering, and a customer-visible
failure envelope.

Resolution:

The P4 approval package now records that trail as the post-listing smoke
contract in the M10 audit doc. The implementation lands as
`integrations/aws-bedrock/tests/post_listing_smoke.rs` in P4.T5 and is
registered against the `chio-bedrock-control-plane` crate so the listed
gate exercises the customer-shape path.

Freeze impact:

This is inside `m10-bedrock-listing-pivot` and does not change the
single-region D03 scope. The resolution keeps the listing on the
existing AWS Bedrock plus AWS Marketplace control-plane boundary.
