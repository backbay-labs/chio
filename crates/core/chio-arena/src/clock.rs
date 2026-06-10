//! Deterministic virtual clock for arena scenarios.
//!
//! The arena never reads the system clock. Time is advanced explicitly by the
//! scheduler in fixed-tick increments derived from the scenario witness so two
//! runs of the same scenario observe the same `virtual_now` sequence.
//!
//! `VirtualClock` is the only authority for time inside `ArenaRuntime`. The
//! determinism gate greps `runtime.rs` and `clock.rs` for any
//! wall-clock readers and fails the build if it finds one.

use std::time::Duration;

use thiserror::Error;

/// Default virtual tick when a scenario does not specify one.
///
/// One millisecond is large enough to be human-readable in receipts and small
/// enough that thousands of ticks remain comfortably representable as `u64`
/// nanoseconds.
pub const DEFAULT_TICK_NANOS: u64 = 1_000_000;

/// Deterministic virtual clock used by the arena scheduler.
///
/// The clock is keyed by an RFC-3339 start instant and a fixed tick width. It
/// exposes a monotonic `virtual_now_nanos` counter measured against the start
/// instant. Wall-clock readers are forbidden in arena code; the determinism
/// gate greps for them in `runtime.rs` and `clock.rs`.
#[derive(Debug, Clone)]
pub struct VirtualClock {
    start_iso: String,
    start_nanos: u64,
    tick_nanos: u64,
    elapsed_nanos: u64,
}

impl VirtualClock {
    /// Create a new clock starting at `start_iso` with `tick_nanos` width.
    pub fn new(start_iso: impl Into<String>, tick_nanos: u64) -> Result<Self, ClockError> {
        if tick_nanos == 0 {
            return Err(ClockError::ZeroTick);
        }
        let start_iso = start_iso.into();
        let start_nanos = parse_rfc3339_nanos(&start_iso)?;
        Ok(Self {
            start_iso,
            start_nanos,
            tick_nanos,
            elapsed_nanos: 0,
        })
    }

    /// Create a clock with the default tick width.
    pub fn with_default_tick(start_iso: impl Into<String>) -> Result<Self, ClockError> {
        Self::new(start_iso, DEFAULT_TICK_NANOS)
    }

    /// Returns the canonical RFC-3339 start instant supplied by the scenario.
    pub fn start_iso(&self) -> &str {
        &self.start_iso
    }

    /// Returns the elapsed virtual time since the scenario start, in
    /// nanoseconds.
    pub fn virtual_now_nanos(&self) -> u64 {
        self.elapsed_nanos
    }

    /// Returns the elapsed virtual time as a `Duration`.
    pub fn virtual_elapsed(&self) -> Duration {
        Duration::from_nanos(self.elapsed_nanos)
    }

    /// Returns the absolute virtual time as nanoseconds since the unix epoch.
    pub fn absolute_now_nanos(&self) -> u64 {
        self.start_nanos.saturating_add(self.elapsed_nanos)
    }

    /// Advance the clock by exactly one tick.
    pub fn tick(&mut self) {
        self.elapsed_nanos = self.elapsed_nanos.saturating_add(self.tick_nanos);
    }

    /// Advance the clock by `count` ticks.
    pub fn advance_ticks(&mut self, count: u64) {
        self.elapsed_nanos = self
            .elapsed_nanos
            .saturating_add(self.tick_nanos.saturating_mul(count));
    }
}

/// Errors raised by [`VirtualClock`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClockError {
    /// Tick width must be at least one nanosecond.
    #[error("virtual clock tick width must be non-zero")]
    ZeroTick,
    /// Scenario start instant could not be parsed as RFC-3339.
    #[error("invalid RFC-3339 virtual_clock_start: {0}")]
    InvalidStart(String),
}

/// Parse a strict RFC-3339 timestamp into nanoseconds since the unix epoch.
///
/// The arena requires fixed-format timestamps (`YYYY-MM-DDTHH:MM:SS[.fff]Z`)
/// so two hosts with different locale settings still observe the same epoch
/// value. Anything outside the strict subset is rejected.
fn parse_rfc3339_nanos(value: &str) -> Result<u64, ClockError> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || !value.ends_with('Z') {
        return Err(ClockError::InvalidStart(value.to_string()));
    }
    let date = &value[..10];
    if date.len() != 10 || &value[10..11] != "T" {
        return Err(ClockError::InvalidStart(value.to_string()));
    }
    let year =
        parse_uint(&date[0..4]).ok_or_else(|| ClockError::InvalidStart(value.to_string()))?;
    let month =
        parse_uint(&date[5..7]).ok_or_else(|| ClockError::InvalidStart(value.to_string()))?;
    let day =
        parse_uint(&date[8..10]).ok_or_else(|| ClockError::InvalidStart(value.to_string()))?;
    let time_section = &value[11..value.len() - 1];
    if time_section.len() < 8 {
        return Err(ClockError::InvalidStart(value.to_string()));
    }
    let hour = parse_uint(&time_section[0..2])
        .ok_or_else(|| ClockError::InvalidStart(value.to_string()))?;
    let minute = parse_uint(&time_section[3..5])
        .ok_or_else(|| ClockError::InvalidStart(value.to_string()))?;
    let second = parse_uint(&time_section[6..8])
        .ok_or_else(|| ClockError::InvalidStart(value.to_string()))?;
    let fractional_nanos = if time_section.len() == 8 {
        0
    } else if time_section.as_bytes().get(8) == Some(&b'.') {
        let frac = &time_section[9..];
        if frac.is_empty() || frac.len() > 9 {
            return Err(ClockError::InvalidStart(value.to_string()));
        }
        let scaled = parse_uint(frac).ok_or_else(|| ClockError::InvalidStart(value.to_string()))?;
        scale_fractional(scaled, frac.len())
    } else {
        return Err(ClockError::InvalidStart(value.to_string()));
    };

    if !(1970..=2999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || minute >= 60
        || second >= 60
    {
        return Err(ClockError::InvalidStart(value.to_string()));
    }
    // Reject impossible dates such as `2026-02-31`. Without this guard the
    // civil-day algorithm silently normalises the input, which would shift
    // the determinism witness anchor on malformed scenarios.
    if day > days_in_month(year, month) {
        return Err(ClockError::InvalidStart(value.to_string()));
    }

    let days = days_from_civil(year, month, day);
    let seconds = days
        .saturating_mul(86_400)
        .saturating_add(hour.saturating_mul(3_600))
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(second);
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(fractional_nanos))
}

fn parse_uint(value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
    }
    Some(acc)
}

fn scale_fractional(value: u64, len: usize) -> u64 {
    // `len` is bounded by 9 in the parser above.
    let mut scaled = value;
    for _ in len..9 {
        scaled = scaled.saturating_mul(10);
    }
    scaled
}

/// Maximum valid day in `month` of `year` under the proleptic Gregorian
/// calendar. Used to reject impossible dates like `2026-02-31` before they
/// reach `days_from_civil`, which would otherwise normalise rather than
/// fault.
fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Civil days since 1970-01-01 using Howard Hinnant's chrono algorithm,
/// adapted to `u64`. The algorithm is deterministic and platform-independent.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let m = month;
    let d = day;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_tick() {
        match VirtualClock::new("2026-04-30T00:00:00Z", 0) {
            Err(err) => assert_eq!(err, ClockError::ZeroTick),
            Ok(_) => panic!("expected ZeroTick error"),
        }
    }

    #[test]
    fn rejects_non_rfc3339_start() {
        match VirtualClock::with_default_tick("2026-04-30 00:00:00") {
            Err(ClockError::InvalidStart(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
            Ok(_) => panic!("expected InvalidStart error"),
        }
    }

    #[test]
    fn epoch_zero_aligns_with_unix_epoch() -> Result<(), ClockError> {
        let clock = VirtualClock::with_default_tick("1970-01-01T00:00:00Z")?;
        assert_eq!(clock.absolute_now_nanos(), 0);
        Ok(())
    }

    #[test]
    fn ticks_are_deterministic() -> Result<(), ClockError> {
        let mut a = VirtualClock::new("2026-04-30T00:00:00.000Z", 1_000_000)?;
        let mut b = VirtualClock::new("2026-04-30T00:00:00.000Z", 1_000_000)?;
        for _ in 0..100 {
            a.tick();
            b.tick();
        }
        assert_eq!(a.virtual_now_nanos(), b.virtual_now_nanos());
        assert_eq!(a.virtual_now_nanos(), 100 * 1_000_000);
        Ok(())
    }

    #[test]
    fn fractional_seconds_parse() -> Result<(), ClockError> {
        let clock = VirtualClock::with_default_tick("2026-04-30T00:00:00.500Z")?;
        assert_eq!(clock.absolute_now_nanos() % 1_000_000_000, 500_000_000);
        Ok(())
    }

    #[test]
    fn rejects_impossible_calendar_day() {
        // February 31 is never valid; the civil-day algorithm would silently
        // normalise it without this check, shifting the determinism witness
        // anchor on malformed scenarios.
        match VirtualClock::with_default_tick("2026-02-31T00:00:00Z") {
            Err(ClockError::InvalidStart(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
            Ok(_) => panic!("expected InvalidStart error for 2026-02-31"),
        }
    }

    #[test]
    fn rejects_april_31() {
        match VirtualClock::with_default_tick("2026-04-31T00:00:00Z") {
            Err(ClockError::InvalidStart(_)) => {}
            other => panic!("expected InvalidStart for 2026-04-31, got {other:?}"),
        }
    }

    #[test]
    fn accepts_leap_day_in_leap_year() -> Result<(), ClockError> {
        VirtualClock::with_default_tick("2024-02-29T00:00:00Z")?;
        Ok(())
    }

    #[test]
    fn rejects_leap_day_in_non_leap_year() {
        match VirtualClock::with_default_tick("2023-02-29T00:00:00Z") {
            Err(ClockError::InvalidStart(_)) => {}
            other => panic!("expected InvalidStart for 2023-02-29, got {other:?}"),
        }
    }
}
