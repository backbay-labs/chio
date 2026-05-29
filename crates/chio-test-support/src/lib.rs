//! Shared test-only assertion helpers for the Chio workspace.
//!
//! The workspace enforces `clippy::unwrap_used = "deny"` and
//! `clippy::expect_used = "deny"` everywhere, including test code. To keep
//! tests readable without reaching for the banned `.unwrap()` / `.expect()`
//! inherent methods, this crate provides small extension traits that perform
//! the same fail-the-test-on-error behaviour through explicit `panic!` calls.
//!
//! Two families of helpers exist for two call conventions that are
//! intentionally kept distinct:
//!
//! - The default family (re-exported from [`prelude`]) takes no context
//!   argument: `value.test_unwrap()`. An optional `test_expect(context)` is
//!   available when a caller wants a human-readable label on the panic.
//! - The [`ctx`] family always takes a `&str` context: `value.test_unwrap(ctx)`
//!   and `result.test_unwrap_err(ctx)`.
//!
//! The two families deliberately collide on the `test_unwrap` method name, so a
//! single source file should import exactly one of them.
//!
//! These helpers are intended for use from `#[cfg(test)]` code only. Add the
//! crate as a `[dev-dependencies]` entry and bring the traits into scope with
//! `use chio_test_support::prelude::*;` (or `use chio_test_support::ctx::*;`).

#![forbid(unsafe_code)]

/// Context-free unwrap helpers (the dominant workspace convention).
///
/// Methods here mirror `Result::unwrap` / `Option::unwrap` /
/// `Result::unwrap_err`, panicking (and thereby failing the test) on the
/// unexpected variant. Error and value payloads are rendered with their
/// [`std::fmt::Debug`] representation so failures are diagnosable.
pub mod plain {
    use std::fmt::Debug;

    /// Extract the `Ok`/`Some` value or fail the test.
    pub trait TestResultOk<T> {
        /// Return the contained value, panicking on the error/none variant.
        fn test_unwrap(self) -> T;

        /// Return the contained value, panicking with `context` on the
        /// error/none variant.
        fn test_expect(self, context: &str) -> T;
    }

    /// Extract the `Err` value or fail the test.
    pub trait TestResultErr<E> {
        /// Return the contained error, panicking on the `Ok` variant.
        fn test_unwrap_err(self) -> E;

        /// Return the contained error, panicking with `context` on the `Ok`
        /// variant.
        fn test_expect_err(self, context: &str) -> E;
    }

    impl<T, E: Debug> TestResultOk<T> for Result<T, E> {
        fn test_unwrap(self) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("expected Ok(..), got Err({error:?})"),
            }
        }

        fn test_expect(self, context: &str) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("{context}: expected Ok(..), got Err({error:?})"),
            }
        }
    }

    impl<T> TestResultOk<T> for Option<T> {
        fn test_unwrap(self) -> T {
            match self {
                Some(value) => value,
                None => panic!("expected Some(..), got None"),
            }
        }

        fn test_expect(self, context: &str) -> T {
            match self {
                Some(value) => value,
                None => panic!("{context}: expected Some(..), got None"),
            }
        }
    }

    // No `T: Debug` bound here on purpose: some call sites unwrap the error of a
    // `Result` whose `Ok` payload is a non-`Debug` handle (for example a store
    // connection), so the `Ok` value is not interpolated into the panic.
    impl<T, E> TestResultErr<E> for Result<T, E> {
        fn test_unwrap_err(self) -> E {
            match self {
                Ok(_) => panic!("expected Err(..), got Ok(..)"),
                Err(error) => error,
            }
        }

        fn test_expect_err(self, context: &str) -> E {
            match self {
                Ok(_) => panic!("{context}: expected Err(..), got Ok(..)"),
                Err(error) => error,
            }
        }
    }
}

/// Context-carrying unwrap helpers.
///
/// Every method takes a `&str` context label that is prefixed onto the panic
/// message. Used by call sites written as `value.test_unwrap("loading config")`.
pub mod ctx {
    use std::fmt::{Debug, Display};

    /// Extract the `Ok`/`Some` value or fail the test with a context label.
    pub trait TestUnwrap<T> {
        /// Return the contained value, panicking with `context` on the
        /// error/none variant.
        fn test_unwrap(self, context: &str) -> T;
    }

    /// Extract the `Err` value or fail the test with a context label.
    pub trait TestUnwrapErr<E> {
        /// Return the contained error, panicking with `context` on the `Ok`
        /// variant.
        fn test_unwrap_err(self, context: &str) -> E;
    }

    impl<T, E: Display> TestUnwrap<T> for Result<T, E> {
        fn test_unwrap(self, context: &str) -> T {
            self.unwrap_or_else(|error| panic!("{context}: {error}"))
        }
    }

    impl<T> TestUnwrap<T> for Option<T> {
        fn test_unwrap(self, context: &str) -> T {
            self.unwrap_or_else(|| panic!("{context}"))
        }
    }

    impl<T: Debug, E> TestUnwrapErr<E> for Result<T, E> {
        fn test_unwrap_err(self, context: &str) -> E {
            match self {
                Ok(value) => panic!("{context}: unexpected Ok({value:?})"),
                Err(error) => error,
            }
        }
    }
}

/// Glob-import target for the default (context-free) helper family.
///
/// `use chio_test_support::prelude::*;` brings [`plain::TestResultOk`] and
/// [`plain::TestResultErr`] into scope.
pub mod prelude {
    pub use crate::plain::{TestResultErr, TestResultOk};
}
