# chio-test-support architecture

## Overview

`chio-test-support` is a pure, dependency-free test-support library outside the
kernel trust boundary: nothing in it runs in production, and it exists only to
satisfy the workspace's fail-closed `unwrap_used`/`expect_used` lint policy
inside `#[cfg(test)]` code and integration test binaries. The design keeps two
non-overlapping trait families (`plain`, `ctx`) that both terminate in a
`panic!`, so a failed assumption always fails the test rather than propagating
an `Err`.

## Module map

All modules live in `src/lib.rs`; the crate has no submodule files.

| Module | Responsibility |
|--------|-----------------|
| `plain` | Context-free `TestResultOk` / `TestResultErr` traits for `Result` / `Option`; the dominant workspace convention. |
| `ctx` | Context-carrying `TestUnwrap` / `TestUnwrapErr` traits; every call takes a `&str` label. |
| `prelude` | Re-exports `plain::{TestResultOk, TestResultErr}` as the default glob import. |
| `loopback` | `TcpListener`-based probes: detect whether the sandbox permits loopback binds, and reserve an ephemeral address for a local test server. |
| `tests` (`#[cfg(test)]`) | Unit tests asserting panic message text and `#[track_caller]` location for both trait families, and loopback-denial classification. |

## Boundaries

- No production code path reaches this crate; every public function either
  panics (test-fail) or probes a local socket.
- `loopback` functions hold no state across calls: probes bind and immediately
  drop a `TcpListener` rather than keeping a listener open for a caller.
- `#![forbid(unsafe_code)]` - no `unsafe` is permitted anywhere in the crate.

## Invariants and failure modes

- Every helper carries `#[track_caller]`, so a panic reports the caller's
  source location, not a line inside `chio-test-support`.
- `plain::TestResultErr` omits a `T: Debug` bound on purpose, so call sites can
  unwrap the error of a `Result` whose `Ok` payload (for example a store
  connection handle) does not implement `Debug`.
- `plain` and `ctx` both define `test_unwrap`; a source file must import only
  one family (`prelude::*` or `ctx::*`). Importing both makes the call
  ambiguous.
- `is_loopback_bind_denied` matches only `ErrorKind::PermissionDenied`. Address
  conflicts (`AddrInUse`) and other bind errors are excluded on purpose so they
  still fail the test instead of being treated as an environmental skip.
- `reserve_listen_addr_for` panics on any bind failure other than a permission
  denial, and its panic message points the caller at
  `skip_when_loopback_bind_denied`.

## Dependencies

None. `[dependencies]` is empty in `Cargo.toml`; the crate uses only `std`
(`std::fmt`, `std::io`, `std::net`, and `std::panic` in tests) and is
`publish = false`. It is consumed exclusively as a `[dev-dependencies]` entry
by 30 crates workspace-wide.
