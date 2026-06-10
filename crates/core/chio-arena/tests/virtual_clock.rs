use chio_arena::{ClockError, VirtualClock, DEFAULT_TICK_NANOS};

#[test]
fn clock_advances_in_fixed_ticks() -> Result<(), ClockError> {
    let mut clock = VirtualClock::with_default_tick("2026-04-30T00:00:00.000Z")?;
    assert_eq!(clock.virtual_now_nanos(), 0);
    for _ in 0..1000 {
        clock.tick();
    }
    assert_eq!(clock.virtual_now_nanos(), 1000 * DEFAULT_TICK_NANOS);
    Ok(())
}

#[test]
fn two_clocks_with_identical_inputs_match_byte_for_byte() -> Result<(), ClockError> {
    let mut a = VirtualClock::new("2026-04-30T00:00:00.000Z", 250)?;
    let mut b = VirtualClock::new("2026-04-30T00:00:00.000Z", 250)?;
    let mut a_trace: Vec<u64> = Vec::with_capacity(100);
    let mut b_trace: Vec<u64> = Vec::with_capacity(100);
    for _ in 0..100 {
        a.tick();
        b.tick();
        a_trace.push(a.absolute_now_nanos());
        b_trace.push(b.absolute_now_nanos());
    }
    assert_eq!(a_trace, b_trace);
    Ok(())
}

#[test]
fn invalid_start_format_is_rejected() {
    match VirtualClock::with_default_tick("2026-04-30 00:00:00") {
        Err(ClockError::InvalidStart(_)) => {}
        other => panic!("expected InvalidStart, got {other:?}"),
    }
    match VirtualClock::with_default_tick("not-a-date") {
        Err(ClockError::InvalidStart(_)) => {}
        other => panic!("expected InvalidStart, got {other:?}"),
    }
    match VirtualClock::new("2026-04-30T00:00:00Z", 0) {
        Err(err) => assert_eq!(err, ClockError::ZeroTick),
        Ok(_) => panic!("expected ZeroTick"),
    }
}

#[test]
fn advance_ticks_matches_repeated_tick() -> Result<(), ClockError> {
    let mut a = VirtualClock::new("2026-04-30T00:00:00.000Z", 1_000_000)?;
    let mut b = VirtualClock::new("2026-04-30T00:00:00.000Z", 1_000_000)?;
    for _ in 0..256 {
        a.tick();
    }
    b.advance_ticks(256);
    assert_eq!(a.virtual_now_nanos(), b.virtual_now_nanos());
    Ok(())
}
