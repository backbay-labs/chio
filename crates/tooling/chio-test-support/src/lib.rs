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
//! The [`loopback`] module provides shared helpers for integration tests that
//! need to bind local listeners. Tests can probe whether the current sandbox
//! permits loopback sockets and return early only when the operating system
//! denies the bind itself.
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
        #[track_caller]
        fn test_unwrap(self) -> T;

        /// Return the contained value, panicking with `context` on the
        /// error/none variant.
        #[track_caller]
        fn test_expect(self, context: &str) -> T;
    }

    /// Extract the `Err` value or fail the test.
    pub trait TestResultErr<E> {
        /// Return the contained error, panicking on the `Ok` variant.
        #[track_caller]
        fn test_unwrap_err(self) -> E;

        /// Return the contained error, panicking with `context` on the `Ok`
        /// variant.
        #[track_caller]
        fn test_expect_err(self, context: &str) -> E;
    }

    impl<T, E: Debug> TestResultOk<T> for Result<T, E> {
        #[track_caller]
        fn test_unwrap(self) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("expected Ok(..), got Err({error:?})"),
            }
        }

        #[track_caller]
        fn test_expect(self, context: &str) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("{context}: expected Ok(..), got Err({error:?})"),
            }
        }
    }

    impl<T> TestResultOk<T> for Option<T> {
        #[track_caller]
        fn test_unwrap(self) -> T {
            match self {
                Some(value) => value,
                None => panic!("expected Some(..), got None"),
            }
        }

        #[track_caller]
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
        #[track_caller]
        fn test_unwrap_err(self) -> E {
            match self {
                Ok(_) => panic!("expected Err(..), got Ok(..)"),
                Err(error) => error,
            }
        }

        #[track_caller]
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
    use std::fmt::Display;

    /// Extract the `Ok`/`Some` value or fail the test with a context label.
    pub trait TestUnwrap<T> {
        /// Return the contained value, panicking with `context` on the
        /// error/none variant.
        #[track_caller]
        fn test_unwrap(self, context: &str) -> T;
    }

    /// Extract the `Err` value or fail the test with a context label.
    pub trait TestUnwrapErr<E> {
        /// Return the contained error, panicking with `context` on the `Ok`
        /// variant.
        #[track_caller]
        fn test_unwrap_err(self, context: &str) -> E;
    }

    impl<T, E: Display> TestUnwrap<T> for Result<T, E> {
        #[track_caller]
        fn test_unwrap(self, context: &str) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("{context}: {error}"),
            }
        }
    }

    impl<T> TestUnwrap<T> for Option<T> {
        #[track_caller]
        fn test_unwrap(self, context: &str) -> T {
            match self {
                Some(value) => value,
                None => panic!("{context}"),
            }
        }
    }

    impl<T, E> TestUnwrapErr<E> for Result<T, E> {
        #[track_caller]
        fn test_unwrap_err(self, context: &str) -> E {
            match self {
                Ok(_) => panic!("{context}: unexpected Ok(..)"),
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

/// Loopback listener helpers for integration tests that spawn local services.
///
/// CI runners should normally allow `127.0.0.1:0` binds. Locked-down local
/// sandboxes can deny the bind with `PermissionDenied`, in which case tests may
/// return early after calling [`skip_when_loopback_bind_denied`]. Other bind
/// errors still fail the test because they may indicate a real regression.
pub mod loopback {
    use std::io::{self, ErrorKind};
    use std::net::{SocketAddr, TcpListener};

    /// Return true when this process can bind an ephemeral IPv4 loopback port.
    pub fn loopback_bind_available() -> bool {
        TcpListener::bind(("127.0.0.1", 0)).is_ok()
    }

    /// Return true only when the local environment denies loopback binding.
    ///
    /// Unexpected probe failures panic instead of being treated as a skip so a
    /// broken test environment does not hide production bind regressions.
    #[track_caller]
    pub fn skip_when_loopback_bind_denied(test_name: &str) -> bool {
        match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => {
                drop(listener);
                false
            }
            Err(error) if is_loopback_bind_denied(&error) => {
                eprintln!("skipping {test_name}: loopback bind denied: {error}");
                true
            }
            Err(error) => panic!("probe loopback bind for {test_name}: {error}"),
        }
    }

    /// Reserve an ephemeral loopback address for a local test server.
    ///
    /// Callers should invoke [`skip_when_loopback_bind_denied`] at the start of
    /// a socket-backed test before reserving an address. If they do not, a
    /// sandbox permission failure is reported with a diagnostic that points at
    /// the missing probe.
    #[track_caller]
    pub fn reserve_listen_addr() -> SocketAddr {
        reserve_listen_addr_for("integration test")
    }

    /// Reserve an ephemeral loopback address with a diagnostic label.
    #[track_caller]
    pub fn reserve_listen_addr_for(label: &str) -> SocketAddr {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                let addr = match listener.local_addr() {
                    Ok(addr) => addr,
                    Err(error) => panic!("read listener addr for {label}: {error}"),
                };
                drop(listener);
                addr
            }
            Err(error) if is_loopback_bind_denied(&error) => panic!(
                "loopback bind denied while reserving address for {label}: {error}; \
                 call skip_when_loopback_bind_denied at test start"
            ),
            Err(error) => panic!("bind temp listener for {label}: {error}"),
        }
    }

    /// True for operating-system permission denials caused by locked-down test
    /// sandboxes. This intentionally excludes address conflicts and malformed
    /// addresses, which should still fail tests.
    pub fn is_loopback_bind_denied(error: &io::Error) -> bool {
        error.kind() == ErrorKind::PermissionDenied
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, Location, UnwindSafe};
    use std::sync::{Arc, Mutex, MutexGuard};

    use crate::ctx;
    use crate::plain;

    struct NonDebugHandle;

    #[test]
    fn ctx_unwrap_err_accepts_non_debug_ok_payloads() {
        use ctx::TestUnwrapErr;

        let result: Result<NonDebugHandle, &str> = Err("denied");

        assert_eq!(result.test_unwrap_err("expected denial"), "denied");
    }

    #[test]
    fn plain_unwraps_do_not_require_debug_value_payloads() {
        use plain::{TestResultErr, TestResultOk};

        let ok: Result<NonDebugHandle, &str> = Ok(NonDebugHandle);
        let _: NonDebugHandle = ok.test_unwrap();

        let some = Some(NonDebugHandle);
        let _: NonDebugHandle = some.test_unwrap();

        let err: Result<NonDebugHandle, &str> = Err("denied");
        assert_eq!(err.test_unwrap_err(), "denied");
    }

    #[test]
    fn plain_panic_reports_test_call_site() {
        use plain::TestResultOk;

        let expected_line = line!() + 1;
        let panic = capture_panic(|| Option::<u8>::None.test_unwrap());

        assert_eq!(panic.location_line, Some(expected_line));
        assert!(
            panic
                .location_file
                .as_deref()
                .is_some_and(|file| file.ends_with("crates/chio-test-support/src/lib.rs")),
            "unexpected panic location file: {:?}",
            panic.location_file
        );
        assert_eq!(panic.message, "expected Some(..), got None");
    }

    #[test]
    fn ctx_panic_reports_test_call_site() {
        use ctx::TestUnwrap;

        let expected_line = line!() + 1;
        let panic = capture_panic(|| Result::<u8, &str>::Err("denied").test_unwrap("ctx"));

        assert_eq!(panic.location_line, Some(expected_line));
        assert!(
            panic
                .location_file
                .as_deref()
                .is_some_and(|file| file.ends_with("crates/chio-test-support/src/lib.rs")),
            "unexpected panic location file: {:?}",
            panic.location_file
        );
        assert_eq!(panic.message, "ctx: denied");
    }

    #[test]
    fn loopback_denied_helper_recognizes_permission_denied() {
        let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

        assert!(crate::loopback::is_loopback_bind_denied(&error));
    }

    #[test]
    fn loopback_denied_helper_rejects_address_conflicts() {
        let error = std::io::Error::from(std::io::ErrorKind::AddrInUse);

        assert!(!crate::loopback::is_loopback_bind_denied(&error));
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CapturedPanic {
        message: String,
        location_file: Option<String>,
        location_line: Option<u32>,
    }

    fn capture_panic<F, R>(f: F) -> CapturedPanic
    where
        F: FnOnce() -> R + UnwindSafe,
    {
        static HOOK_LOCK: Mutex<()> = Mutex::new(());

        let _guard = lock(&HOOK_LOCK);
        let previous_hook = panic::take_hook();
        let captured = Arc::new(Mutex::new(None));
        let captured_for_hook = Arc::clone(&captured);

        panic::set_hook(Box::new(move |info| {
            let message = if let Some(message) = info.payload().downcast_ref::<&'static str>() {
                (*message).to_string()
            } else if let Some(message) = info.payload().downcast_ref::<String>() {
                message.clone()
            } else {
                "<non-string panic>".to_string()
            };
            let (location_file, location_line) =
                info.location().map_or((None, None), location_parts);
            *lock(&captured_for_hook) = Some(CapturedPanic {
                message,
                location_file,
                location_line,
            });
        }));

        let result = panic::catch_unwind(f);
        panic::set_hook(previous_hook);

        match result {
            Ok(_) => panic!("expected closure to panic"),
            Err(_) => match lock(&captured).clone() {
                Some(panic) => panic,
                None => panic!("panic hook did not capture panic"),
            },
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn location_parts(location: &Location<'_>) -> (Option<String>, Option<u32>) {
        (Some(location.file().to_string()), Some(location.line()))
    }
}
