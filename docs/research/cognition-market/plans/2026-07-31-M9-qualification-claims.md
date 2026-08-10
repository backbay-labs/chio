# M9: Qualification, Claims, And Release Boundary

Status: implementation and stack-owned cumulative qualification were completed
on 2026-08-01 and requalified after the stack rebase and security repair on
2026-08-10. Promoted-default, proof-bundle, schema, registry, build, test,
Clippy, formatting, code-generation, and bounded-profile gates pass on the
current tree. Earlier formal and strict Rust verification evidence remains
cumulative and was not rerun during the rebase. This record names the exact
bounded profile and deliberately leaves conditional M7 and usage-gated R&D
extensions unshipped.

## Qualified Profile

The qualified surface is the single-operator cognition-market wedge from M0
through M6 plus M8's authenticated SQLite pool profile. The named
`cognition_market_qualified_profile` control-plane test composes independent
production-facing fixtures for publish and discovery, verified purchase and
identity-profile reveal, challenge enforcement, the outbox-backed retraction
transition, portable status rejection, and governed-memory quarantine. The
same test name in `chio-transaction-passport` verifies the persisted proof
bundle golden.

M7 was re-evaluated on 2026-08-01 and rechecked during the 2026-08-10 stack
rebase. No real bilateral seller and buyer pair or deployment request is
recorded in the repository or roadmap handoff, and no M7 branch or pull
request exists. Its trigger is therefore false.
`cognition_market_cross_org_escrow` remains an ignored fail-first test, and
ADR-C remains unstarted.

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
references, and only the content-addressed attachments selected by the
verified Finding claim rows. The evidence-bound claim selects the replay
recipe, the status-fresh claim selects the portable status proof, and the
delivery-digest and bond-backed claims require only the signed report. The
signed report commits each selected attachment digest. An independent
verifier strict-parses and rechecks the selected types, signatures, digest
pins, replay recipe, status authorization, freshness, sparse path, and claim
specific facets. The verifier profile fixes the minimum required facet set,
and the report binds the deployment-pinned trust-root snapshot used for the
decision. The CLI verifier requires both pins and additionally requires its
portable status proof to cross the same durable per-feed rollback floor used
by the status surface before it emits a successful report.

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
repo-relative witness. Feature removal and ADR-0017 acceptance are backed by
the focused exits, schema and formal registries, generated artifacts, formal
and strict Rust verification, and cumulative workspace gates recorded below.

## Recorded Results

| Gate | Result |
|---|---|
| `cognition_market_qualified_profile` control-plane composition | passed, 1 test |
| Finding verifier evidence and portable-status suite | passed, 37 tests |
| transaction-passport cognition-market suite | passed, 20 tests; 1 golden-regeneration helper ignored |
| claim-registry integrity | passed, 10 tests |
| bounded matrix contract and witness resolution | passed, 12 tests |
| `cargo xtask qualify bounded-chio` | passed, 9 conditions |
| Lean proof build, strict Rust verification, and public harness mapping | inherited cumulative evidence from 2026-08-01; 1,532 Lean jobs, 32 Creusot files, 44 core Kani harnesses, 30 public-core Kani harnesses, and 17 non-core PR harnesses; not rerun during the rebase |
| schema registry and deterministic schema manifest | passed |
| promoted-default marketplace and SQLite pool exits | passed, 41 and 11 focused tests; conditional M7 test ignored |
| generated Rust, Python, TypeScript, and Go artifacts | passed, `make codegen-check` |
| full workspace build | passed, `cargo build --workspace` |
| full workspace test sweep | passed, `cargo test --workspace`; explicitly ignored tests remain reported as ignored |
| full workspace Clippy | passed, `cargo clippy --workspace --lib --bins --examples -- -D warnings` |
| formatting | passed, `cargo fmt --all -- --check` |
