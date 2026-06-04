# cross-provider-policy Architecture Notes

## Module Boundaries

This package owns the offline cross-provider policy demo. It loads a local YAML
policy, replays the providers that expose deep replay hooks, reads deterministic
NDJSON kernel verdict captures for every provider, enforces the fixture contract,
and proves normalized receipt bodies and verdicts are byte-equal through
canonical JSON.

## Pain Points

The package currently places CLI parsing, policy validation, provider matrix
selection, fixture reading, receipt construction, equality assertions, and tests
inside `src/main.rs`. That makes the binary the only usable boundary even though
the real API is a deterministic offline evaluation flow. The policy validation
test has to reach private binary internals, and future fixture-contract tests
would have to keep growing the binary.

## Security And API Constraints

The command must remain dry-run only and must never call live provider APIs. It
must preserve the eight-provider matrix, deterministic fixture paths,
provider-provenance output, canonical JSON byte equality, fail-closed YAML and
NDJSON parsing, unpadded policy fields, and one-kernel-verdict-per-fixture
invariant. The public command name and flags must stay compatible.

## Affected Dependents

The package is invoked by humans and by the example surface documentation
through `cargo run -p cross-provider-policy -- --dry-run`. The provider
conformance workflow owns the stricter shared oracle in
`crates/chio-provider-conformance/tests/cross_provider_equality.rs`; this
example mirrors that oracle for a policy-demo surface. No transitive crate API
changes are required.

## Completed Material Improvement

The offline evaluation flow now lives in a library entrypoint used by the
binary. CLI parsing is a thin edge, and library tests cover dry-run enforcement,
policy validation, and full eight-provider receipt equivalence. This separates
the policy/equality API from process startup while preserving the existing
command-line surface.
