use std::collections::{BTreeMap, VecDeque};

use crate::config::PairConfig;
use crate::{ExchangeRate, PriceOracleError};

const TWAP_SCALE: u128 = 1_000_000_000_000;

#[derive(Debug, Clone)]
pub struct CacheEntry {
    latest: ExchangeRate,
    observations: VecDeque<ExchangeRate>,
}

#[derive(Debug, Default)]
pub struct PriceCache {
    entries: BTreeMap<String, CacheEntry>,
}

impl PriceCache {
    pub fn record(
        &mut self,
        pair: &PairConfig,
        rate: ExchangeRate,
        now: u64,
    ) -> Result<(), PriceOracleError> {
        rate.ensure_matches_pair(pair)?;
        rate.ensure_fresh(now)?;
        let key = pair.pair();
        let entry = self.entries.entry(key).or_insert_with(|| CacheEntry {
            latest: rate.clone(),
            observations: VecDeque::new(),
        });
        entry.latest = rate.clone();
        entry.observations.push_back(rate);
        trim_observations(entry, pair, now);
        Ok(())
    }

    pub fn resolve(
        &mut self,
        pair: &PairConfig,
        now: u64,
    ) -> Result<Option<ExchangeRate>, PriceOracleError> {
        let key = pair.pair();
        let Some(entry) = self.entries.get_mut(&key) else {
            return Ok(None);
        };
        trim_observations(entry, pair, now);
        entry.latest.ensure_matches_pair(pair)?;
        entry.latest.ensure_fresh(now)?;
        if !pair.policy.twap_enabled || entry.observations.len() <= 1 {
            return Ok(Some(entry.latest.clone()));
        }
        Ok(Some(build_twap(pair, entry)?))
    }

    #[must_use]
    pub fn latest(&self, pair: &PairConfig) -> Option<ExchangeRate> {
        self.entries
            .get(&pair.pair())
            .map(|entry| entry.latest.clone())
    }
}

fn trim_observations(entry: &mut CacheEntry, pair: &PairConfig, now: u64) {
    while entry.observations.len() > pair.policy.twap_max_observations {
        let _ = entry.observations.pop_front();
    }
    while let Some(oldest) = entry.observations.front() {
        if now.saturating_sub(oldest.fetched_at) <= pair.policy.twap_window_seconds {
            break;
        }
        let _ = entry.observations.pop_front();
    }
}

fn build_twap(pair: &PairConfig, entry: &CacheEntry) -> Result<ExchangeRate, PriceOracleError> {
    let mut count: u128 = 0;
    let mut total_scaled = 0_u128;
    for rate in &entry.observations {
        let scaled = normalized_price(rate)?;
        total_scaled = total_scaled.checked_add(scaled).ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "TWAP accumulation overflowed for {}",
                pair.pair()
            ))
        })?;
        count += 1;
    }
    let average = total_scaled.div_ceil(count);
    let mut twap = entry.latest.clone();
    twap.rate_numerator = average;
    twap.rate_denominator = TWAP_SCALE;
    twap.source = format!("{}:twap", twap.source);
    twap.conversion_margin_bps = pair.policy.exchange_rate_margin_bps;
    Ok(twap)
}

fn normalized_price(rate: &ExchangeRate) -> Result<u128, PriceOracleError> {
    let scaled = rate.rate_numerator.checked_mul(TWAP_SCALE).ok_or_else(|| {
        PriceOracleError::ArithmeticOverflow(format!(
            "normalizing TWAP price overflowed for {}",
            rate.pair()
        ))
    })?;
    Ok(scaled / rate.rate_denominator)
}

#[cfg(test)]
mod tests {
    use super::PriceCache;
    use crate::config::PriceOracleConfig;
    use crate::test_support::TestUnwrap;
    use crate::ExchangeRate;

    fn sample_rate(numerator: u128, fetched_at: u64) -> ExchangeRate {
        ExchangeRate {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            rate_numerator: numerator,
            rate_denominator: 100,
            updated_at: fetched_at.saturating_sub(30),
            fetched_at,
            source: "chainlink".to_string(),
            feed_reference: "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70".to_string(),
            max_age_seconds: 600,
            conversion_margin_bps: 200,
            confidence_numerator: None,
            confidence_denominator: None,
        }
    }

    #[test]
    fn returns_twap_when_enabled() {
        let config = PriceOracleConfig::base_mainnet_default("https://example.invalid");
        let pair = config.pair("ETH", "USD").test_unwrap("pair").clone();
        let mut cache = PriceCache::default();
        cache
            .record(&pair, sample_rate(300_000, 1_743_292_700), 1_743_292_700)
            .test_unwrap("record");
        cache
            .record(&pair, sample_rate(306_000, 1_743_292_760), 1_743_292_760)
            .test_unwrap("record");
        let rate = cache
            .resolve(&pair, 1_743_292_780)
            .test_unwrap("resolve")
            .test_unwrap("rate");
        assert_eq!(rate.source, "chainlink:twap");
        assert_eq!(rate.rate_numerator, 3_030_000_000_000_000);
        assert_eq!(rate.rate_denominator, 1_000_000_000_000);
    }

    #[test]
    fn drops_expired_observations() {
        let config = PriceOracleConfig::base_mainnet_default("https://example.invalid");
        let pair = config.pair("ETH", "USD").test_unwrap("pair").clone();
        let mut cache = PriceCache::default();
        cache
            .record(&pair, sample_rate(300_000, 1_743_292_000), 1_743_292_000)
            .test_unwrap("record");
        cache
            .record(&pair, sample_rate(306_000, 1_743_292_760), 1_743_292_760)
            .test_unwrap("record");
        let rate = cache
            .resolve(&pair, 1_743_292_780)
            .test_unwrap("resolve")
            .test_unwrap("rate");
        assert_eq!(rate.rate_numerator, 306_000);
        assert_eq!(rate.rate_denominator, 100);
    }
}
