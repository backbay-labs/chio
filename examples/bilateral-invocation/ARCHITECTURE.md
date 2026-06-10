# bilateral-invocation Architecture Notes

## Boundary

The example boundary is the local bilateral fixture itself: it constructs a
small signed invocation scenario, runs the production partial verifier, and
prints the resulting evidence summary. It must not become a mock-only demo or a
generic receipt pretty-printer because the value of the example is exercising
the real bilateral co-signing path.

## Module Boundaries

This package is an executable example for the local bilateral invocation
fixture. It depends on `chio-core-types` for receipt construction and
`chio-federation` for the local fixture runner, in-memory verifier roots,
bilateral co-signing protocol, and partial local verifier. It is not a
production library and is not published.

## Security And API Constraints

The example must keep using the production fixture helper and verifier, not
mock the bilateral DSSE path. It must keep the strict
`UnknownActionClassPolicy::Reject` configuration and explicitly register the
demo tool action class. It must not normalize or relax receipt, lease, policy,
or peer-pin material. Because this is an example package, public API
compatibility is local to the package.

## Affected Dependents

There are no workspace crates depending on this example. The relevant
compatibility gates are `cargo test -p bilateral-invocation` and
`cargo run -p bilateral-invocation`, with `chio-federation` and
`chio-core-types` providing the transitive protocol semantics.

## Library And Binary Split

Deterministic fixture execution lives in a package library that returns a typed
summary of the artifacts and verifier result. `main.rs` is a thin presentation
layer, and tests cover the fixture summary so example correctness does not
depend on stdout formatting.
