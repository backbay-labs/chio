# Verified fix finding fixture

`finding.json` is generated deterministically by the ignored
`regenerate_golden_fixture` test in `chio-finding`, using the test-only seed
`[9_u8; 32]`.

The fixture proves JSON Schema conformance, strict canonical parsing,
content-address integrity, and issuer-signature integrity for
`chio.finding.v1`. It does not prove that the referenced evidence, checkpoint,
bond, status feed, or underlying finding is true, live, or trustworthy.

Interoperability preimages retain all members. For the finding id, set
`finding_id` and `signature` to `""`; the resulting RFC 8785 bytes hash to
the fixture's `finding_id`
`dc721f80b183eb65945ba4754d9ba6b131d3c8309d8a7bff710f4160b9d7d817`.
For the signature, retain that populated id and set only `signature` to `""`.
Neither preimage omits a member or encodes it as `null`.
