use crate::{ExchangeRate, PriceOracleError};

const NORMALIZATION_SCALE: u128 = 1_000_000_000_000;
const BPS_DENOMINATOR: u128 = 10_000;

fn normalized_price(rate: &ExchangeRate) -> Result<u128, PriceOracleError> {
    let scaled = rate
        .rate_numerator
        .checked_mul(NORMALIZATION_SCALE)
        .ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "normalizing price overflowed for {}",
                rate.pair()
            ))
        })?;
    Ok(scaled / rate.rate_denominator)
}

pub fn divergence_bps(
    primary: &ExchangeRate,
    secondary: &ExchangeRate,
) -> Result<u32, PriceOracleError> {
    let left = normalized_price(primary)?;
    let right = normalized_price(secondary)?;
    let (smaller, larger) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    if smaller == 0 {
        return Err(PriceOracleError::ArithmeticOverflow(
            "cannot compute divergence against zero price".to_string(),
        ));
    }
    let diff = larger - smaller;
    let bps = diff
        .checked_mul(BPS_DENOMINATOR)
        .ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(
                "divergence calculation overflowed numerator".to_string(),
            )
        })?
        .div_ceil(smaller);
    u32::try_from(bps).map_err(|_| {
        PriceOracleError::ArithmeticOverflow("divergence bps overflowed u32".to_string())
    })
}

pub fn ensure_within_threshold(
    primary: &ExchangeRate,
    secondary: &ExchangeRate,
    threshold_bps: u32,
) -> Result<(), PriceOracleError> {
    let pair = primary.pair();
    let divergence = divergence_bps(primary, secondary)?;
    if divergence > threshold_bps {
        return Err(PriceOracleError::CircuitBreakerTripped {
            pair,
            divergence_pct: divergence as f64 / 100.0,
            threshold_pct: threshold_bps as f64 / 100.0,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestUnwrap, TestUnwrapErr};
    use crate::ExchangeRate;

    use super::{divergence_bps, ensure_within_threshold};

    fn sample_rate(source: &str, numerator: u128) -> ExchangeRate {
        ExchangeRate {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            rate_numerator: numerator,
            rate_denominator: 100,
            updated_at: 1_743_292_740,
            fetched_at: 1_743_292_785,
            source: source.to_string(),
            feed_reference: source.to_string(),
            max_age_seconds: 600,
            conversion_margin_bps: 200,
            confidence_numerator: None,
            confidence_denominator: None,
        }
    }

    #[test]
    fn divergence_computes_basis_points() {
        let left = sample_rate("chainlink", 300_000);
        let right = sample_rate("pyth", 306_000);
        assert_eq!(divergence_bps(&left, &right).test_unwrap("divergence"), 200);
    }

    #[test]
    fn threshold_trips_on_large_gap() {
        let left = sample_rate("chainlink", 300_000);
        let right = sample_rate("pyth", 330_000);
        let error = ensure_within_threshold(&left, &right, 500).test_unwrap_err("should trip");
        assert!(error.to_string().contains("diverge"));
    }
}
