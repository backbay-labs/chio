//! Public symbolic checks for checked monetary conversion.
//!
//! The rounding harness exhaustively covers the four-bit input domain. The
//! separate boundary harness exercises the full-width narrowing overflow that
//! cannot occur inside that bounded domain. Full-width randomized coverage is
//! provided by the property test in `formal_economy`.

use crate::formal_economy::{convert_ceil_scalar, convert_floor_scalar};

#[kani::proof]
#[kani::unwind(8)]
pub fn public_convert_rounding_envelope() {
    let units_input: u8 = kani::any();
    let numerator_input: u8 = kani::any();
    let denominator_input: u8 = kani::any();
    kani::assume(units_input <= 15);
    kani::assume(numerator_input <= 15);
    kani::assume(denominator_input <= 15);
    let units = u64::from(units_input);
    let numerator = u64::from(numerator_input);
    let denominator = u64::from(denominator_input);
    let target = u16::from(units_input) * u16::from(numerator_input);

    if numerator == 0 || denominator == 0 {
        assert_eq!(convert_ceil_scalar(units, numerator, denominator), None);
        assert_eq!(convert_floor_scalar(units, numerator, denominator), None);
        return;
    }

    let wide_denominator = u16::from(denominator_input);
    if let Some(value) = convert_ceil_scalar(units, numerator, denominator) {
        assert!(u16::try_from(value).is_ok());
        let value = value as u16;
        let rounded = value * wide_denominator;
        assert!(rounded >= target);
        if value == 0 {
            assert_eq!(target, 0);
        } else {
            assert!((value - 1) * wide_denominator < target);
        }
    }

    if let Some(value) = convert_floor_scalar(units, numerator, denominator) {
        assert!(u16::try_from(value).is_ok());
        let value = value as u16;
        let rounded = value * wide_denominator;
        assert!(rounded <= target);
        assert!(target < (value + 1) * wide_denominator);
    }
}

#[kani::proof]
#[kani::unwind(8)]
pub fn public_convert_overflow_fails_closed() {
    assert_eq!(convert_ceil_scalar(u64::MAX, u64::MAX, 1), None);
    assert_eq!(convert_floor_scalar(u64::MAX, u64::MAX, 1), None);
    assert_eq!(convert_ceil_scalar(u64::MAX, 1, 1), Some(u64::MAX));
    assert_eq!(convert_floor_scalar(u64::MAX, 1, 1), Some(u64::MAX));
    assert_eq!(convert_ceil_scalar(0, u64::MAX, 1), Some(0));
    assert_eq!(convert_floor_scalar(0, u64::MAX, 1), Some(0));
}
