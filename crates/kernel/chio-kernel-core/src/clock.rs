//! Abstract clock for capability time-bound enforcement.
//!
//! The kernel core never calls `std::time::SystemTime::now()`. All time
//! enters the pure evaluation surface through a `&dyn Clock` so that
//! browser, WASM, and embedded adapters can inject `Date.now()`,
//! `instant::now()`, or a fuzzed/mock clock for deterministic testing.

/// Abstract monotonic wall-clock exposing Unix seconds.
///
/// Implementations MUST return a value consistent with the signed
/// `issued_at` / `expires_at` fields on capabilities. The verdict path is
/// fail-closed against clock errors: if `now_unix_secs` returns a value in
/// the past of `issued_at` or past `expires_at`, the capability is rejected.
pub trait Clock {
    /// Current Unix timestamp in seconds.
    fn now_unix_secs(&self) -> u64;
}

/// Test-only clock that returns a fixed value.
///
/// Useful for deterministic evaluation harnesses (e.g. the wasm
/// platform adapter's `evaluate_at_time()` helper and the
/// `portable_build.rs` integration test).
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    now_unix_secs: u64,
}

impl FixedClock {
    /// Build a fixed clock pinned to `now_unix_secs`.
    #[must_use]
    pub const fn new(now_unix_secs: u64) -> Self {
        Self { now_unix_secs }
    }
}

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        self.now_unix_secs
    }
}

impl<T: Clock + ?Sized> Clock for &T {
    fn now_unix_secs(&self) -> u64 {
        (**self).now_unix_secs()
    }
}
