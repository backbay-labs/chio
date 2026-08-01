//! Pure checked-arithmetic helpers for monetary conversion.

/// Converts `units` by `numerator / denominator`, rounding upward.
///
/// Zero rates and results that do not fit in `u64` fail closed.
#[must_use]
#[allow(clippy::manual_is_multiple_of)]
pub fn convert_ceil_scalar(units: u64, numerator: u64, denominator: u64) -> Option<u64> {
    if numerator == 0 || denominator == 0 {
        return None;
    }

    let product = (units as u128) * (numerator as u128);
    let denominator = denominator as u128;
    let quotient = product / denominator;
    let rounded = if product % denominator == 0 {
        quotient
    } else {
        quotient + 1
    };
    if rounded > u64::MAX as u128 {
        None
    } else {
        Some(rounded as u64)
    }
}

/// Converts `units` by `numerator / denominator`, rounding downward.
///
/// Zero rates and results that do not fit in `u64` fail closed.
#[must_use]
pub fn convert_floor_scalar(units: u64, numerator: u64, denominator: u64) -> Option<u64> {
    if numerator == 0 || denominator == 0 {
        return None;
    }

    let product = (units as u128) * (numerator as u128);
    let quotient = product / denominator as u128;
    if quotient > u64::MAX as u128 {
        None
    } else {
        Some(quotient as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::{convert_ceil_scalar, convert_floor_scalar};
    use proptest::prelude::*;

    #[test]
    fn conversion_rounding_examples_are_exact() {
        assert_eq!(convert_ceil_scalar(5, 3, 2), Some(8));
        assert_eq!(convert_floor_scalar(5, 3, 2), Some(7));
        assert_eq!(convert_ceil_scalar(8, 3, 2), Some(12));
        assert_eq!(convert_floor_scalar(8, 3, 2), Some(12));
    }

    #[test]
    fn conversion_rejects_zero_rates_and_narrowing_overflow() {
        assert_eq!(convert_ceil_scalar(1, 0, 1), None);
        assert_eq!(convert_ceil_scalar(1, 1, 0), None);
        assert_eq!(convert_floor_scalar(1, 0, 1), None);
        assert_eq!(convert_floor_scalar(1, 1, 0), None);
        assert_eq!(convert_ceil_scalar(u64::MAX, u64::MAX, 1), None);
        assert_eq!(convert_floor_scalar(u64::MAX, u64::MAX, 1), None);
        assert_eq!(convert_ceil_scalar(u64::MAX, 1, 1), Some(u64::MAX));
        assert_eq!(convert_floor_scalar(u64::MAX, 1, 1), Some(u64::MAX));
    }

    #[test]
    fn zero_units_have_zero_rounded_value() {
        assert_eq!(convert_ceil_scalar(0, u64::MAX, 1), Some(0));
        assert_eq!(convert_floor_scalar(0, u64::MAX, 1), Some(0));
    }

    proptest! {
        #[test]
        fn converted_values_stay_inside_the_rounding_envelope(
            units in any::<u64>(),
            numerator in any::<u64>(),
            denominator in any::<u64>(),
        ) {
            let target = u128::from(units) * u128::from(numerator);

            if numerator == 0 || denominator == 0 {
                prop_assert_eq!(convert_ceil_scalar(units, numerator, denominator), None);
                prop_assert_eq!(convert_floor_scalar(units, numerator, denominator), None);
                return Ok(());
            }

            let wide_denominator = u128::from(denominator);
            if let Some(value) = convert_ceil_scalar(units, numerator, denominator) {
                let rounded = u128::from(value) * wide_denominator;
                prop_assert!(rounded >= target);
                if value == 0 {
                    prop_assert_eq!(target, 0);
                } else {
                    prop_assert!((u128::from(value) - 1) * wide_denominator < target);
                }
            }

            if let Some(value) = convert_floor_scalar(units, numerator, denominator) {
                let rounded = u128::from(value) * wide_denominator;
                prop_assert!(rounded <= target);
                prop_assert!(target < (u128::from(value) + 1) * wide_denominator);
            }
        }
    }
}
