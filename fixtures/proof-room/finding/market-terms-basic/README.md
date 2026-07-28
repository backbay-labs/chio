# Market terms fixture

`terms.json` is generated deterministically by the ignored
`regenerate_market_golden_fixtures` test in `chio-finding`
(`tests/market_schemas.rs`). The seller, who both authors the terms and
signs the envelope, uses the test-only seed `[2_u8; 32]`.

The fixture proves JSON Schema conformance, strict canonical parsing,
content-address integrity, and envelope-signature integrity for
`chio.finding.market-terms.v1` as a `SignedExportEnvelope`
(`body`, `signerKey`, `signature`).

Interoperability preimages retain all members. For the terms id, set only
`body.terms_id` to `""`; the RFC 8785 bytes of the body hash to
`00e03f40ee7e96c48fa13cf05f8f0d932b47cc4524d5fdd06c524d8aa1142e77`.
The envelope signature is Ed25519 over the RFC 8785 bytes of the populated
`body`; the signature lives outside the body. The exact signed envelope
digest (sha256 of the RFC 8785 bytes of the whole envelope) is
`3a9cf540163aa9547bc39741e14c30df3afa0f64b65780c6eaca8dfa8ab8af24`.
No preimage omits a member or encodes it as `null`.

Validating this fixture does not prove that the referenced Finding exists
or is true, that the seller holds or has locked any collateral, that the
filing, claim, appeal, or audit windows are enforced anywhere, or that the
referenced verifier profile resolves. The `finding_id`,
`finding_artifact_sha256`, and `verifier_profile_envelope_sha256` digests
are fixed placeholders, not resolvable artifacts.
