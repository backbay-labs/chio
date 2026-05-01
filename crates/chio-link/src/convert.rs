use crate::{ExchangeRate, PriceOracleError};

const BPS_DENOMINATOR: u128 = 10_000;

pub fn minor_units_for_currency(currency: &str) -> Result<u64, PriceOracleError> {
    match currency.trim().to_ascii_uppercase().as_str() {
        "USD" | "EUR" | "GBP" => Ok(100),
        "JPY" => Ok(1),
        "USDC" | "USDT" => Ok(1_000_000),
        "BTC" => Ok(100_000_000),
        "ETH" | "LINK" => Ok(1_000_000_000_000_000_000),
        other => Err(PriceOracleError::InvalidConfiguration(format!(
            "no default minor-unit scale is pinned for currency {other}"
        ))),
    }
}

pub fn convert_supported_units(
    original_units: u64,
    rate: &ExchangeRate,
    margin_bps: u32,
) -> Result<u64, PriceOracleError> {
    convert_units(
        original_units,
        minor_units_for_currency(&rate.base)?,
        minor_units_for_currency(&rate.quote)?,
        rate,
        margin_bps,
    )
}

pub fn convert_units(
    original_units: u64,
    base_minor_units_per_unit: u64,
    quote_minor_units_per_unit: u64,
    rate: &ExchangeRate,
    margin_bps: u32,
) -> Result<u64, PriceOracleError> {
    if base_minor_units_per_unit == 0 || quote_minor_units_per_unit == 0 {
        return Err(PriceOracleError::InvalidConfiguration(
            "currency scales must be non-zero".to_string(),
        ));
    }
    if rate.rate_denominator == 0 {
        return Err(PriceOracleError::InvalidFeed(format!(
            "{} returned a zero rate denominator",
            rate.pair()
        )));
    }
    let numerator = u128::from(original_units)
        .checked_mul(rate.rate_numerator)
        .and_then(|value| value.checked_mul(u128::from(quote_minor_units_per_unit)))
        .ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "conversion numerator overflowed for {}",
                rate.pair()
            ))
        })?;
    let denominator = u128::from(base_minor_units_per_unit)
        .checked_mul(rate.rate_denominator)
        .ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "conversion denominator overflowed for {}",
                rate.pair()
            ))
        })?;
    let converted = numerator.div_ceil(denominator);
    let with_margin = if margin_bps == 0 {
        converted
    } else {
        converted
            .checked_mul(BPS_DENOMINATOR + u128::from(margin_bps))
            .ok_or_else(|| {
                PriceOracleError::ArithmeticOverflow(format!(
                    "margin application overflowed for {}",
                    rate.pair()
                ))
            })?
            .div_ceil(BPS_DENOMINATOR)
    };
    u64::try_from(with_margin).map_err(|_| {
        PriceOracleError::ArithmeticOverflow(format!(
            "converted units exceeded u64 for {}",
            rate.pair()
        ))
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::TestUnwrap;
    use crate::ExchangeRate;

    use super::{convert_supported_units, convert_units, minor_units_for_currency};

    fn sample_rate() -> ExchangeRate {
        ExchangeRate {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            rate_numerator: 300_000,
            rate_denominator: 100,
            updated_at: 1_743_292_740,
            fetched_at: 1_743_292_785,
            source: "chainlink".to_string(),
            feed_reference: "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70".to_string(),
            max_age_seconds: 600,
            conversion_margin_bps: 200,
            confidence_numerator: None,
            confidence_denominator: None,
        }
    }

    #[test]
    fn converts_with_ceiling_rounding() {
        let converted = convert_units(
            1_000_000_000_000_000,
            1_000_000_000_000_000_000,
            100,
            &sample_rate(),
            0,
        )
        .test_unwrap("converted");
        assert_eq!(converted, 300);
    }

    #[test]
    fn applies_margin_conservatively() {
        let converted = convert_units(
            1_000_000_000_000_000,
            1_000_000_000_000_000_000,
            100,
            &sample_rate(),
            200,
        )
        .test_unwrap("converted");
        assert_eq!(converted, 306);
    }

    #[test]
    fn resolves_supported_currency_scales() {
        assert_eq!(minor_units_for_currency("USD").test_unwrap("usd"), 100);
        assert_eq!(
            minor_units_for_currency("ETH").test_unwrap("eth"),
            10_u64.pow(18)
        );
    }

    #[test]
    fn converts_with_default_supported_scales() {
        let converted = convert_supported_units(1_000_000_000_000_000, &sample_rate(), 0)
            .test_unwrap("converted");
        assert_eq!(converted, 300);
    }
}
