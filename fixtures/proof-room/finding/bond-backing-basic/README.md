# Bond backing fixture

`backing.json` is generated deterministically by the ignored
`regenerate_market_golden_fixtures` test in `chio-finding`
(`tests/market_schemas.rs`). The collateral authority, who signs the
envelope, uses the test-only seed `[4_u8; 32]`; the backed seller uses
seed `[2_u8; 32]`.

The fixture proves JSON Schema conformance, strict canonical parsing,
content-address integrity, and envelope-signature integrity for
`chio.finding.bond-backing.v1` as a `SignedExportEnvelope`
(`body`, `signerKey`, `signature`).

Interoperability preimages retain all members. For the allocation id, set
only `body.allocation_id` to `""`; the RFC 8785 bytes of the body hash to
`2586e92a398e6dbbea299408add0610a881a847ec3523e839ef9eb9e175ef482`.
The envelope signature is Ed25519 over the RFC 8785 bytes of the populated
`body`; the signature lives outside the body. The exact signed envelope
digest (sha256 of the RFC 8785 bytes of the whole envelope) is
`dd924dc6577ffb36d42a81726652f51121ace3859eebf8fe6edbd5f82bd47f0e`.
No preimage omits a member or encodes it as `null`.

Validating this fixture does not prove that any collateral is actually
locked in the named venue-ledger vault, that the collateral authority
controls any funds, that the allocation is live or exclusive, or that the
referenced authorization, terms, profile, and fee artifacts resolve. All
cross-artifact digests are fixed placeholders, not resolvable artifacts.
