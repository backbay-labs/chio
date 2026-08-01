# M9: Qualification, Claims, And Release Boundary

Status: complete. The promoted-default cumulative workspace and release gates
passed on 2026-07-31. This record names the exact bounded profile and
deliberately leaves conditional M7 and usage-gated R&D extensions unshipped.

## Qualified Profile

The qualified surface is the single-operator cognition-market wedge from M0
through M6 plus M8's authenticated SQLite pool profile. The named
`cognition_market_qualified_profile` control-plane test composes independent
production-facing fixtures for publish and discovery, verified purchase and
identity-profile reveal, challenge enforcement, the outbox-backed retraction
transition, portable status rejection, and governed-memory quarantine. The
same test name in `chio-transaction-passport` verifies the persisted proof
bundle golden.

M7 was re-evaluated on 2026-07-31. No real bilateral seller and buyer pair or
deployment request is recorded in the repository or roadmap handoff. Its
trigger is therefore false. `cognition_market_cross_org_escrow` remains an
ignored fail-first test, and ADR-C remains unstarted.

No wedge usage dataset exists for stochastic replication policy, experiment
descriptor taxonomy, evidence-cost bucketing, or cross-organization feed
governance. Those R&D extensions remain gated and unimplemented. A future
stochastic challenge design must use a sibling artifact family rather than
changing the frozen M5 v1 vocabulary.

## Claims And Assumptions

The approved qualified claims are:

- `claim.finding.delivery_digest_bound`
- `claim.finding.evidence_bound`
- `claim.finding.status_fresh`
- `claim.finding.bond_backed`

Each has a row in `spec/registries/claim-registry.v1.json`, a proof manifest,
and a scoped public description. `claim.finding.status_fresh` means only that
the named feed, root, path, and validity interval verified at the checked
time. It does not prove external operator insert completeness.

The two surviving operator boundaries stay labeled as audited assumptions:

- `ASSUME-FINDING-STATUS-OPERATOR-COMPLETENESS`
- `ASSUME-FINDING-SELLER-TOOL-SERVER`

The release-candidate guarantees separately state the single-operator pending
and outbox behavior, proof-passport guarantees, status non-claim, and
delivery/bond non-claims.

## Proof Bundle Ownership

`chio-transaction-passport` owns cognition-market proof-bundle integration.
The verifier requires one signed registered
`chio.finding.verifier-report.v1` authority node, exact ClaimSet evidence
references, and content-addressed replay-recipe and status-proof attachments.
The signed report commits both attachment digests. An independent verifier
strict-parses and rechecks their types, signatures, digest pins, replay
recipe, status authorization, freshness, sparse path, and required facets.

Unsigned recipe and status inputs are accepted only under the
`advisory-observation` role. Wrong role, wrong schema, wrong graph digest, and
attachment substitution all reject. The persisted golden lives at
`fixtures/proof-room/finding/cognition-market-qualified-profile/`.

## Qualification Gates

The bounded matrix includes three cognition-market conditions:

- `COGM9-01`: the single-operator end-to-end wedge and challenge/status exits;
- `COGM9-02`: the signed report, ClaimSet, proof graph, passport, and golden;
- `COGM9-03`: approved scoped claims and the two audited assumptions.

`cargo xtask qualify bounded-chio` validates the matrix contract and every
repo-relative witness. Feature removal and ADR-0017 acceptance occur only
after the focused exits, schema and formal registries, generated artifacts,
and the full workspace build, test, Clippy, and formatting gates pass.

## Recorded Results

| Gate | Result |
|---|---|
| `cognition_market_qualified_profile` control-plane composition | passed, 1 test |
| transaction-passport positive and substitution-negative suite | passed |
| claim-registry integrity | passed, 10 tests |
| bounded matrix contract and witness resolution | passed, 12 tests |
| `cargo xtask qualify bounded-chio` | passed, 9 conditions |
| strict formal proof report and public harness mapping | passed |
| generated Rust, Python, TypeScript, and Go artifacts | passed, no drift |
| final full workspace build, test, Clippy, and formatting | passed |
