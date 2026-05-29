# chio-test-support

Shared test-only assertion helpers for the Chio workspace.

## What it does

The workspace denies `clippy::unwrap_used` and `clippy::expect_used` everywhere,
including test code. This crate provides small extension traits that give tests
the same fail-on-unexpected-variant ergonomics through explicit `panic!` calls,
so test bodies stay readable without reaching for the banned inherent methods.

Two intentionally distinct families are exposed:

- `prelude` (the dominant convention): context-free `value.test_unwrap()` for
  `Result` and `Option`, plus `test_expect(context)` / `test_unwrap_err()` /
  `test_expect_err(context)`.
- `ctx`: context-carrying `value.test_unwrap(context)` and
  `result.test_unwrap_err(context)`.

Both families deliberately use the `test_unwrap` method name, so a single source
file imports exactly one of them.

## Where it fits

Add it as a `[dev-dependencies]` entry and import the helpers from a
`#[cfg(test)]` module:

```rust
use chio_test_support::prelude::*; // or: use chio_test_support::ctx::*;
```

The crate is `publish = false`, has no dependencies, and carries no runtime
code; it exists purely to deduplicate the assertion helpers that previously
lived as copy-pasted traits across the workspace's test suites.
