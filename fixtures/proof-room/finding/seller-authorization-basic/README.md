# Seller authorization fixture

`authorization.json` is generated deterministically by the ignored
`regenerate_market_golden_fixtures` test in `chio-finding`
(`tests/market_schemas.rs`). The issuer, who signs the envelope, uses the
test-only seed `[3_u8; 32]`; the authorized seller uses seed `[2_u8; 32]`.

The fixture proves JSON Schema conformance, strict canonical parsing,
content-address integrity, and envelope-signature integrity for
`chio.finding.seller-authorization.v1` as a `SignedExportEnvelope`
(`body`, `signerKey`, `signature`).

Interoperability preimages retain all members. For the authorization id,
set only `body.authorization_id` to `""`; the RFC 8785 bytes of the body
hash to
`cd595cde853c1d2c42732748e9894cf0166b99bf85df47031eb89d4cf58a2af4`.
The envelope signature is Ed25519 over the RFC 8785 bytes of the populated
`body`; the signature lives outside the body. The exact signed envelope
digest (sha256 of the RFC 8785 bytes of the whole envelope) is
`04a5959477ee012a70616ed91d6c612849b7be34154744ac60b46dd28a5af66f`.
No preimage omits a member or encodes it as `null`.

Validating this fixture does not prove that the embedded issuer actually
issued the referenced Finding (that cross-check happens at the surface that
resolves both artifacts), that the payee destination exists or is payable,
that the revocation feed exists, or that the authorization is unrevoked.
The `finding_id` and `finding_artifact_sha256` digests are fixed
placeholders, not resolvable artifacts.
