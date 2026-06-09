# chio-test-support Architecture

## Module Boundaries

`src/lib.rs` owns the full public surface. The `plain` module provides the
default context-free helper family re-exported by `prelude`; the `ctx` module
provides context-carrying helpers for call sites that want the context argument
on every unwrap. The `loopback` module owns local listener probes used by
integration tests that spawn short-lived HTTP or trust-control services. The
crate intentionally has no runtime dependencies and is consumed only as a
dev-dependency across the workspace.

## Pain Points

These helpers replace banned `unwrap` and `expect` calls in test code. If a
helper panic reports the implementation line inside `chio-test-support`, the
failure loses the most important diagnostic: the actual test assertion call
that made the bad assumption. The `ctx` family also currently uses
`unwrap_or_else` internally, which makes call-site location tracking harder to
reason about than a direct match at the assertion boundary.

## Security And API Constraints

The public trait names, method names, module names, and prelude exports must
stay source-compatible. The crate must stay dependency-free and test-only.
Helper failure must remain an explicit panic, not a production error type.
Trait implementations must not add `Debug` or `Display` bounds for payloads
that are not rendered in the panic message, because several downstream tests
unwrap opaque handles.

Loopback helpers must distinguish environmental socket permission denials from
real bind failures. A locked-down local sandbox may skip a socket-backed test
after a failed probe, but address conflicts, malformed addresses, and service
startup failures must still fail loudly so CI continues to catch regressions.

## Affected Dependents

Existing downstream imports from `chio_test_support::prelude::*` and
`chio_test_support::ctx::*` should keep compiling. CLI integration tests that
spawn loopback services can import `chio_test_support::loopback::*` instead of
copying local socket probes. A representative context-family dependent, a
representative prelude-family dependent, and a socket-backed CLI test should be
checked after the change.

## Planned Material Improvement

Make each helper method preserve the test call site with `#[track_caller]`,
replace context-family `unwrap_or_else` calls with direct matches, and add
unit tests that capture panic hook metadata to prove panics report the caller
line rather than the helper implementation. Also strengthen native coverage for
payload-bound behavior so future edits do not reintroduce unnecessary bounds.
Centralize loopback socket probes so broad local workspace gates fail only for
real regressions. The shared helper keeps CI behavior strict while allowing
developer sandboxes that deny local binds to report explicit environmental
skips in the affected integration tests.
