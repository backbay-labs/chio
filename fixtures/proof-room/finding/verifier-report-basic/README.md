# Verifier report fixture

`report.json` is generated deterministically by the ignored
`regenerate_market_golden_fixtures` test in `chio-finding`
(`tests/market_schemas.rs`). The verifier authority, who signs the
envelope, uses the test-only seed `[15_u8; 32]`, matching the
verifier-report signer policy pinned by the profile fixture.

The fixture proves JSON Schema conformance, strict canonical parsing,
content-address integrity, and envelope-signature integrity for
`chio.finding.verifier-report.v1` as a `SignedExportEnvelope`
(`body`, `signerKey`, `signature`), including the closed 13-facet
vocabulary in normative order with `status_liveness` reported
`unavailable` and every other facet `verified`.

Interoperability preimages retain all members. For the report id, set only
`body.report_id` to `""`; the RFC 8785 bytes of the body hash to
`99ee33f3026405bacd50047f4e063e12bdd85c382c5a64a54c7be9987af69c9c`.
The envelope signature is Ed25519 over the RFC 8785 bytes of the populated
`body`; the signature lives outside the body. The exact signed envelope
digest (sha256 of the RFC 8785 bytes of the whole envelope) is
`6a63e923995cc50df2127746f8ffe8e04fe7ffca6875ebfbce3fae5c16f169d2`.
No preimage omits a member or encodes it as `null`.

Validating this fixture does not prove that any evidence was actually
resolved or any facet actually evaluated; the facet outcomes are claims
signed by a test key, not the product of a real verification run. It does
not prove the referenced Finding, profile, evidence bundle, trust-root
snapshot, or backing allocation exists. All cross-artifact digests are
fixed placeholders, not resolvable artifacts.
