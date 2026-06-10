//! Browser clock adapter.
//!
//! Wraps `js_sys::Date::now()` so the portable [`chio_kernel_core::Clock`]
//! trait can drive capability time-bound enforcement inside a browser
//! (or any wasm32-unknown-unknown host that ships a JS `Date` global).
//!
//! `Date::now()` returns milliseconds since the Unix epoch as an `f64`.
//! Capability tokens encode `issued_at` / `expires_at` as `u64` Unix
//! seconds, so this adapter divides by `1000.0` and truncates. The
//! truncation is fail-closed by design: a sub-second fractional residue
//! would only ever make `now` slightly smaller, which biases toward
//! "capability not yet valid" rather than "capability still valid past
//! its expiry". That is the safer failure mode for a time-bound check.
//!
//! Negative `Date::now()` values are only possible on a machine with a
//! misconfigured system clock sitting before 1970-01-01 UTC, which is
//! extremely rare on any browser environment. In that case this adapter
//! returns `0`, which means every capability with a non-zero
//! `issued_at` will be treated as not-yet-valid -- again the fail-closed
//! branch.

use chio_kernel_core::Clock;

/// [`Clock`] implementation that reads the browser's wall clock via
/// `js_sys::Date::now()`.
///
/// Instances are zero-sized and cheap to construct; the browser adapter
/// constructs one per wasm entry-point call.
#[derive(Debug, Default, Clone, Copy)]
pub struct BrowserClock;

impl BrowserClock {
    /// Construct a new browser clock. The clock is stateless so this is
    /// purely a convenience constructor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for BrowserClock {
    #[cfg(target_arch = "wasm32")]
    fn now_unix_secs(&self) -> u64 {
        // `Date::now()` returns milliseconds since the Unix epoch as an
        // f64. Convert to seconds and clamp negatives fail-closed to 0.
        let millis = js_sys::Date::now();
        if !millis.is_finite() || millis <= 0.0 {
            return 0;
        }
        let secs = millis / 1000.0;
        // Saturating cast: any f64 larger than u64::MAX maps to u64::MAX,
        // which is far past any plausible capability expiry and is still
        // fail-closed (every capability with a finite expiry is expired).
        secs as u64
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn now_unix_secs(&self) -> u64 {
        // Native builds never use BrowserClock in production; the host
        // path uses `std::time::SystemTime`. We still provide a safe
        // stub so `cargo test -p chio-kernel-browser` can link and run
        // without pulling wasm-bindgen on the host.
        //
        // The stub intentionally returns `0`. Any native test that needs
        // a realistic timestamp uses `FixedClock` from `chio-kernel-core`,
        // which is what the portable_build.rs integration test already
        // does.
        0
    }
}
