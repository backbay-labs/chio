# Replay recipe input fixture

`recipe.json` is generated deterministically by the ignored
`regenerate_market_golden_fixtures` test in `chio-finding`
(`tests/market_schemas.rs`). The artifact is unsigned by design (it is
committed by digest from a Finding), so no key seed is involved; every
member is a fixed deterministic constant.

The fixture proves JSON Schema conformance, strict canonical parsing, and
digest stability for `chio.finding.replay-recipe-input.v1`, including the
normative two-phase order (`baseline` first, `candidate` second).

Interoperability preimage: the artifact has no cleared-member id. Its
identity is the sha256 of the RFC 8785 bytes of the whole document,
`9ac1ef84a974f386b07ced3f0284da47744770e7ea119041c06b837c95e8ddf7`,
the value a Finding's `replay_recipe_sha256` would commit to. No member is
omitted or encoded as `null`.

Validating this fixture does not prove that the replay was ever executed,
that the claimed verdict holds, that the runner, runtime image, input
bundles, parameters, or pre-run template exist, or that the referenced
verifier profile resolves. All digests are fixed placeholders, not
resolvable artifacts.
