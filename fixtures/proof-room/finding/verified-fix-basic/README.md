# Verified fix finding fixture

`finding.json` is generated deterministically by the ignored
`regenerate_golden_fixture` test in `chio-finding`, using the test-only seed
`[9_u8; 32]`.

The fixture proves JSON Schema conformance, strict canonical parsing,
content-address integrity, and issuer-signature integrity for
`chio.finding.v1`. It does not prove that the referenced evidence, checkpoint,
bond, status feed, or underlying finding is true, live, or trustworthy.
