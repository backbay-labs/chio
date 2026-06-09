//! Real-time `Clock` implementation for mobile hosts.
//!
//! Both iOS and Android expose `std::time::SystemTime::now()` through
//! the standard Rust libstd shim, so the mobile adapter can read the
//! wall clock directly instead of injecting the time through FFI on
//! every call.
//!
//! If `SystemTime::now()` ever falls before `UNIX_EPOCH` (clock set
//! badly wrong on the device), the impl clamps to `0`. The verdict
//! path is fail-closed against ancient timestamps, so a capability
//! issued in the last 60 years will still be rejected as
//! `NotYetValid` until the device clock corrects.

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel_core::Clock;

/// Mobile-suitable `Clock` implementation that reads the device
/// wall-clock via `SystemTime::now()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MobileClock;

impl MobileClock {
    /// Construct a new mobile clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for MobileClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_clock_returns_recent_timestamp() {
        let clock = MobileClock::new();
        let now = clock.now_unix_secs();
        // Any time after 2020-01-01 is "plausibly current".
        assert!(now > 1_577_836_800);
    }
}
