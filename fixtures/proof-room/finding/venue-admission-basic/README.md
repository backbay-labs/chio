# Venue admission fixture

`admission.json` is generated deterministically by the ignored
`regenerate_market_golden_fixtures` test in `chio-finding`
(`tests/market_schemas.rs`). The venue authority, who signs the envelope
for `venue_id` `venue-wedge`, uses the test-only seed `[6_u8; 32]`; the
embedded purchase and failed-delivery key policies use seeds `[16_u8; 32]`
and `[17_u8; 32]`.

The fixture proves JSON Schema conformance, strict canonical parsing,
content-address integrity, and envelope-signature integrity for
`chio.finding.admission.v1` as a `SignedExportEnvelope`
(`body`, `signerKey`, `signature`), including the required `publication`
and first `participation_epoch` fee terminals and distinct audit and
challenge-administration pools.

Interoperability preimages retain all members. For the admission id, set
only `body.admission_id` to `""`; the RFC 8785 bytes of the body hash to
`d54f98cf25f7e4ae5812ad1a38ee4b25fe0d007014d09e99c0d7d6f70ef883be`.
The envelope signature is Ed25519 over the RFC 8785 bytes of the populated
`body`; the signature lives outside the body. The exact signed envelope
digest (sha256 of the RFC 8785 bytes of the whole envelope) is
`8a1e718a55f7500ab56c62f7f806e2d6ca4b4beb6eceebfa39e5b2d69d32fd5c`.
No preimage omits a member or encodes it as `null`.

Validating this fixture does not prove that any venue authority exists,
that any fee was actually settled (the terminal instruction and
observation digests are placeholders), that the pools, rails, or payee
destinations are real, or that the referenced Finding, authorization,
listing, report, terms, profile, and backing artifacts resolve. All
cross-artifact digests are fixed placeholders, not resolvable artifacts.
