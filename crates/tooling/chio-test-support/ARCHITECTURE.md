# chio-test-support Architecture

## Module Boundaries

`src/lib.rs` owns the full public surface. The `plain` module provides the
default context-free helper family re-exported by `prelude`; the `ctx` module
provides context-carrying helpers for call sites that want the context argument
on every unwrap. The `loopback` module owns local listener probes used by
integration tests that spawn short-lived HTTP or trust-control services. The
crate intentionally has no runtime dependencies and is consumed only as a
dev-dependency across the workspace.

## Call-Site Diagnostics

These helpers replace banned `unwrap` and `expect` calls in test code. Every
helper method carries `#[track_caller]` so a helper panic reports the test
assertion call that made the bad assumption, not the implementation line inside
`chio-test-support`. The `ctx` family matches the value directly at the
assertion boundary rather than routing through `unwrap_or_else`, which keeps
call-site location tracking exact.

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

## Dependents

Downstream code imports from `chio_test_support::prelude::*` and
`chio_test_support::ctx::*`. CLI integration tests that spawn loopback services
import `chio_test_support::loopback::*` rather than copying local socket probes.
The centralized loopback probe keeps broad local workspace gates strict while
letting developer sandboxes that deny local binds report explicit environmental
skips in the affected integration tests.
