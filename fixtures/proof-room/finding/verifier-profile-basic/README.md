# Challenge-verifier profile fixture

`profile.json` is generated deterministically by the ignored
`regenerate_market_golden_fixtures` test in `chio-finding`
(`tests/market_schemas.rs`). The governance authority that signs the
envelope uses the test-only seed `[1_u8; 32]`; the embedded receipt-signer,
checkpoint, verifier-report, purchase, and failed-delivery key policies use
seeds `[11_u8; 32]` through `[17_u8; 32]`.

The fixture proves JSON Schema conformance, strict canonical parsing,
content-address integrity, and envelope-signature integrity for
`chio.finding.challenge-verifier-profile.v1` as a `SignedExportEnvelope`
(`body`, `signerKey`, `signature`).

Interoperability preimages retain all members. For the profile id, set only
`body.profile_id` to `""`; the RFC 8785 bytes of the body hash to
`26845afc58111332f29b3f5e90766406061d151515e7a0957bafbfc1b1754681`.
The envelope signature is Ed25519 over the RFC 8785 bytes of the populated
`body`; the signature lives outside the body. The exact signed envelope
digest (sha256 of the RFC 8785 bytes of the whole envelope) is
`1cc32ce68d85c5711669e93abf270222796115f4b4a2bc774e457ebb66a04e88`.
No preimage omits a member or encodes it as `null`.

Validating this fixture does not prove that the named governance root has
any real authority, that the pinned signer keys are live, unrevoked, or
operated by anyone, that the referenced runner manifest, resolver policy,
or revocation feeds exist, or that any venue enforces this profile. The
runner-manifest digest is a fixed placeholder, not a resolvable artifact.
