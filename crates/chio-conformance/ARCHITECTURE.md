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

## Pain Points

Fixture discovery is split across repository-root defaults and crate-local
packaging. The cross-language fixture tree is included in the installable
package, but the native scenario tree is resolved through the same
`default_repo_root()` path while not being listed in `Cargo.toml` `include`.
At the same time, both JSON scenario loaders silently return an empty suite for
a missing directory. That turns a packaging or path mistake into a green empty
run or an unhelpful empty report.

## Security and API Constraints

Conformance evidence must fail closed. Missing scenario roots, symlinked
fixture escapes, malformed JSON, and absent package assets must be reported as
errors before a report is written. Existing public function signatures should
remain stable, and error reporting should stay within the current public error
types so downstream callers are not forced through a breaking enum change.

The harness must continue to support in-repo defaults, source-installed crate
defaults, and caller-supplied absolute paths through `ConformanceRunOptions`
and `NativeConformanceRunOptions`.

## Affected Dependents

No transitive crate edits are expected. `chio-cli conformance`, the direct
runner binaries, integration tests, and external callers all flow through the
same loader functions, so the behavior change is centralized in this crate.
Valid fixture trees keep their existing behavior. Invalid or incomplete fixture
trees fail before generating compatibility evidence.

## Planned Material Improvement

Add a shared fixture-directory validation boundary for cross-language and
native scenario loading. Missing or non-directory roots should return an
existing I/O-style error, symlinks should remain rejected, and the native
scenario tree should be packaged alongside the existing cross-language
fixtures. Empty scenario directories should also fail closed instead of
producing empty evidence. This preserves public API signatures while making
packaged and standalone conformance runs fail closed instead of producing
empty evidence.
