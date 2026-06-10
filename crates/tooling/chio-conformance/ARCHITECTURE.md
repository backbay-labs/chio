# chio-conformance Architecture Notes

## Module Boundaries

`chio-conformance` owns Chio's conformance evidence harness. `load` reads
cross-language scenario and result JSON, `runner` starts the hosted MCP edge
and peer adapters, `native_suite` exercises native capability and receipt
fixtures, `peers` validates the peer-binary lockfile, and `report` renders the
compatibility matrix. The binaries under `src/bin` are thin CLI wrappers over
those library surfaces.

The crate depends on core protocol and kernel crates because conformance is a
test-support boundary, not a minimal runtime library. Its public API is the
loader, runner, native-suite, peer-lock, and report surface re-exported from
`src/lib.rs`.

## Fixture Discovery

Fixture discovery supports in-repo defaults, source-installed crate defaults,
and caller-supplied absolute paths. Both the cross-language fixture tree and the
native scenario tree are listed in `Cargo.toml` `include`, so they travel with
the installable package and resolve through `default_repo_root()`. A shared
fixture-directory validation boundary gates cross-language and native scenario
loading: missing or non-directory roots, symlinked fixture escapes, malformed
JSON, and empty scenario directories are reported as errors before a report is
written, so a packaging or path mistake fails closed rather than producing a
green empty run.

## Security and API Constraints

Conformance evidence must fail closed. Missing scenario roots, symlinked
fixture escapes, malformed JSON, and absent package assets must be reported as
errors before a report is written. Existing public function signatures should
remain stable, and error reporting should stay within the current public error
types so downstream callers are not forced through a breaking enum change.

The harness must continue to support in-repo defaults, source-installed crate
defaults, and caller-supplied absolute paths through `ConformanceRunOptions`
and `NativeConformanceRunOptions`.

## Dependents

`chio-cli conformance`, the direct runner binaries, integration tests, and
external callers all flow through the same loader functions, so fixture
validation is centralized in this crate. Valid fixture trees produce
compatibility evidence; invalid or incomplete fixture trees fail before any
report is generated.
