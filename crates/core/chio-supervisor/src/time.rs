//! Wall-clock helpers shared by the supervisor loops and the health flag.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch, saturating on a clock set before 1970 or
/// after the year the count overflows a `u64`. Never panics, so it is safe on the
/// pre-dispatch hot path and inside a `catch_unwind` boundary.
#[must_use]
pub fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

/// Milliseconds in a `Duration`, saturating at `u64::MAX`.
#[must_use]
pub(crate) fn as_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
