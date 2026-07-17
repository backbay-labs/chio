# chio-test-support

Shared test-only assertion helpers for the Chio workspace. The workspace denies
`clippy::unwrap_used` and `clippy::expect_used` everywhere, including test code,
so this crate supplies extension traits that fail a test with a `panic!` instead
of the banned inherent methods, plus loopback-bind probes for integration tests
that spawn local listeners.

## Responsibilities

- Provide `test_unwrap` / `test_expect` / `test_unwrap_err` / `test_expect_err`
  extension methods on `Result` and `Option` as drop-in replacements for the
  banned `.unwrap()` / `.expect()`.
- Preserve the calling test's panic location with `#[track_caller]`, so a
  failure points at the assertion, not at this crate's internals.
- Provide loopback-bind probes so integration tests can distinguish an
  environmental sandbox denial (skip) from a real bind regression (fail).

## Public API

- `plain::{TestResultOk, TestResultErr}` - context-free `test_unwrap()` /
  `test_expect(context)` on `Result<T, E: Debug>` and `Option<T>`, and
  `test_unwrap_err()` / `test_expect_err(context)` on `Result<T, E>`.
- `prelude::*` - re-exports `plain::{TestResultOk, TestResultErr}`; the default
  import for the dominant workspace convention.
- `ctx::{TestUnwrap, TestUnwrapErr}` - context-carrying `test_unwrap(context)`
  on `Result<T, E: Display>` and `Option<T>`, and `test_unwrap_err(context)` on
  `Result<T, E>`.
- `loopback::{loopback_bind_available, skip_when_loopback_bind_denied,
  reserve_listen_addr, reserve_listen_addr_for, is_loopback_bind_denied}`.

`plain` and `ctx` both define a `test_unwrap` method, so a source file should
import exactly one family, never both.

## Usage

```rust
use chio_test_support::prelude::*;

let value = compute_result().test_unwrap();
```

```rust
use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};

if skip_when_loopback_bind_denied("my_test") {
    return;
}
let addr = reserve_listen_addr();
```

## Testing

`cargo test -p chio-test-support`

## See also

- `chio-cli` - the only current consumer of the `loopback` probes, used by CLI
  integration tests that spin up local HTTP and trust-control servers.
- Added as a `[dev-dependencies]` entry (`prelude` / `ctx`) by 30 further
  crates spanning the core, kernel, economy, platform, protocol, observability,
  sdk, and trust layers.
