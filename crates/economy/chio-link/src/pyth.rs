use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};
use reqwest::{Client, Url};
use serde::Deserialize;

use crate::config::{PairConfig, PythFeedConfig};
use crate::{ExchangeRate, OracleBackend, OracleBackendKind, OracleFuture, PriceOracleError};

#[derive(Debug)]
pub struct PythHermesClient {
    base_url: String,
    http_client: Client,
    egress_contract: HttpEgressContract,
}

impl PythHermesClient {
    /// Construct a [`PythHermesClient`] bound to a typed
    /// [`HttpEgressContract`]. The contract is required: every Hermes
    /// dispatch routes through `send_with_contract` so the URL, every
    /// redirect target, and the response body size are validated before
    /// bytes leave the substrate.
    pub fn new(
        base_url: impl Into<String>,
        egress_contract: HttpEgressContract,
    ) -> Result<Self, PriceOracleError> {
        let base_url = base_url.into();
        egress_contract
            .validate_dispatchable_with_pinned_dns()
            .map_err(|err| {
                PriceOracleError::InvalidConfiguration(format!(
                    "Pyth Hermes HttpEgressContract is not dispatchable with pinned DNS: {err}"
                ))
            })?;
        let http_client = client_builder_with_contract(&egress_contract)
            .build()
            .map_err(|err| {
                PriceOracleError::Unavailable(format!("building Hermes client failed: {err}"))
            })?;
        Ok(Self {
            base_url,
            http_client,
            egress_contract,
        })
    }

    /// Backwards-compatible alias for [`PythHermesClient::new`]. The
    /// contract is required in production paths; tests that need a
    /// permissive contract should use
    /// [`HttpEgressContract::permissive_for_tests`].
    pub fn with_contract(
        base_url: impl Into<String>,
        egress_contract: HttpEgressContract,
    ) -> Result<Self, PriceOracleError> {
        Self::new(base_url, egress_contract)
    }
}

impl OracleBackend for PythHermesClient {
    fn kind(&self) -> OracleBackendKind {
        OracleBackendKind::Pyth
    }

    fn read_rate<'a>(&'a self, pair: &'a PairConfig, now: u64) -> OracleFuture<'a> {
        Box::pin(async move {
            let feed = pair
                .pyth
                .as_ref()
                .ok_or_else(|| PriceOracleError::NoPairAvailable {
                    base: pair.base.clone(),
                    quote: pair.quote.clone(),
                })?;
            read_pyth_rate(
                &self.http_client,
                &self.base_url,
                pair,
                feed,
                now,
                &self.egress_contract,
            )
            .await
        })
    }
}

async fn read_pyth_rate(
    http_client: &Client,
    base_url: &str,
    pair: &PairConfig,
    feed: &PythFeedConfig,
    now: u64,
    egress_contract: &HttpEgressContract,
) -> Result<ExchangeRate, PriceOracleError> {
    let url = build_latest_price_url(base_url, &feed.id)?;
    // HttpEgressContract: route every Hermes dispatch through
    // send_with_contract so the URL, redirect chain, and response size are
    // validated by the typed egress contract before bytes leave the
    // substrate.
    let request = http_client.get(url).build().map_err(|err| {
        PriceOracleError::Unavailable(format!("building Hermes request failed: {err}"))
    })?;
    let response = send_with_contract(egress_contract, http_client, request)
        .await
        .map_err(|err| {
            PriceOracleError::Unavailable(format!(
                "Hermes request rejected by HttpEgressContract for {} id {}: {err}",
                pair.pair(),
                feed.id
            ))
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(PriceOracleError::Unavailable(format!(
            "Hermes returned HTTP {} for {} id {}",
            status,
            pair.pair(),
            feed.id
        )));
    }
    let feeds: Vec<PythLatestPriceFeed> = response.json().await.map_err(|err| {
        PriceOracleError::InvalidFeed(format!(
            "Hermes JSON decode failed for {} id {}: {err}",
            pair.pair(),
            feed.id
        ))
    })?;
    let latest = feeds.into_iter().next().ok_or_else(|| {
        PriceOracleError::InvalidFeed(format!(
            "Hermes returned no price feeds for {} id {}",
            pair.pair(),
            feed.id
        ))
    })?;
    let expected = canonicalize_pyth_feed_id(&feed.id);
    let actual = canonicalize_pyth_feed_id(&latest.id);
    if expected != actual {
        return Err(PriceOracleError::InvalidFeed(format!(
            "Hermes returned feed id {} but {} was requested for {}",
            latest.id,
            feed.id,
            pair.pair()
        )));
    }
    build_exchange_rate(pair, feed, latest.price, now)
}

fn build_latest_price_url(base_url: &str, id: &str) -> Result<Url, PriceOracleError> {
    let trimmed = base_url.trim_end_matches('/');
    let base = format!("{trimmed}/api/latest_price_feeds");
    Url::parse_with_params(
        &base,
        [(String::from("ids[]"), canonicalize_pyth_feed_id(id))],
    )
    .map_err(|err| {
        PriceOracleError::InvalidConfiguration(format!("invalid Hermes base URL {base_url}: {err}"))
    })
}

fn build_exchange_rate(
    pair: &PairConfig,
    feed: &PythFeedConfig,
    price: PythPriceComponent,
    now: u64,
) -> Result<ExchangeRate, PriceOracleError> {
    let (rate_numerator, rate_denominator) =
        decimal_components_to_ratio(&price.price, price.expo, pair, feed)?;
    let confidence = decimal_components_to_ratio(&price.conf, price.expo, pair, feed).ok();
    let rate = ExchangeRate {
        base: pair.base.clone(),
        quote: pair.quote.clone(),
        rate_numerator,
        rate_denominator,
        updated_at: price.publish_time,
        fetched_at: now,
        source: "pyth".to_string(),
        feed_reference: feed.id.clone(),
        max_age_seconds: pair.policy.max_age_seconds,
        conversion_margin_bps: pair.policy.exchange_rate_margin_bps,
        confidence_numerator: confidence.as_ref().map(|value| value.0),
        confidence_denominator: confidence.as_ref().map(|value| value.1),
    };
    rate.ensure_fresh(now)?;
    Ok(rate)
}

fn decimal_components_to_ratio(
    raw_value: &str,
    expo: i32,
    pair: &PairConfig,
    feed: &PythFeedConfig,
) -> Result<(u128, u128), PriceOracleError> {
    let signed = raw_value.parse::<i128>().map_err(|err| {
        PriceOracleError::InvalidFeed(format!(
            "Pyth value parse failed for {} id {}: {err}",
            pair.pair(),
            feed.id
        ))
    })?;
    let value = u128::try_from(signed).map_err(|_| {
        PriceOracleError::InvalidFeed(format!(
            "Pyth returned a negative value for {} id {}",
            pair.pair(),
            feed.id
        ))
    })?;
    if value == 0 {
        return Err(PriceOracleError::InvalidFeed(format!(
            "Pyth returned zero for {} id {}",
            pair.pair(),
            feed.id
        )));
    }
    if expo >= 0 {
        let scale = 10_u128.checked_pow(expo as u32).ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "Pyth positive exponent overflowed for {} id {}",
                pair.pair(),
                feed.id
            ))
        })?;
        let numerator = value.checked_mul(scale).ok_or_else(|| {
            PriceOracleError::ArithmeticOverflow(format!(
                "Pyth numerator overflowed for {} id {}",
                pair.pair(),
                feed.id
            ))
        })?;
        return Ok((numerator, 1));
    }
    let denominator = 10_u128.checked_pow(expo.unsigned_abs()).ok_or_else(|| {
        PriceOracleError::ArithmeticOverflow(format!(
            "Pyth denominator overflowed for {} id {}",
            pair.pair(),
            feed.id
        ))
    })?;
    Ok((value, denominator))
}

fn canonicalize_pyth_feed_id(id: &str) -> String {
    id.trim_start_matches("0x").to_ascii_lowercase()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythLatestPriceFeed {
    id: String,
    price: PythPriceComponent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythPriceComponent {
    price: String,
    conf: String,
    expo: i32,
    publish_time: u64,
}

#[cfg(test)]
mod tests {
    use crate::config::{PairConfig, PairPolicy, PythFeedConfig, BASE_MAINNET_CHAIN_ID};
    use crate::test_support::{TestUnwrap, TestUnwrapErr};
    use crate::OracleBackend;

    use super::{
        build_exchange_rate, build_latest_price_url, canonicalize_pyth_feed_id,
        decimal_components_to_ratio, PythHermesClient, PythPriceComponent,
    };

    fn pair() -> PairConfig {
        PairConfig {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            chain_id: BASE_MAINNET_CHAIN_ID,
            chainlink: None,
            pyth: Some(PythFeedConfig {
                id: "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"
                    .to_string(),
            }),
            policy: PairPolicy::volatile_default(),
        }
    }

    #[test]
    fn normalizes_pyth_decimal_components() {
        let rate = build_exchange_rate(
            &pair(),
            pair().pyth.as_ref().test_unwrap("feed"),
            PythPriceComponent {
                price: "184136023127".to_string(),
                conf: "177166324".to_string(),
                expo: -8,
                publish_time: 1_743_292_740,
            },
            1_743_292_780,
        )
        .test_unwrap("exchange rate");
        assert_eq!(rate.rate_numerator, 184_136_023_127);
        assert_eq!(rate.rate_denominator, 100_000_000);
        assert_eq!(rate.confidence_numerator, Some(177_166_324));
    }

    #[test]
    fn canonicalizes_feed_ids() {
        assert_eq!(
            canonicalize_pyth_feed_id(
                "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"
            ),
            "ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"
        );
    }

    #[test]
    fn latest_price_url_normalizes_ids_and_base_urls() {
        let url = build_latest_price_url(
            "https://hermes.pyth.network/",
            "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace",
        )
        .test_unwrap("latest price url");

        assert_eq!(
            url.as_str(),
            "https://hermes.pyth.network/api/latest_price_feeds?ids%5B%5D=ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"
        );
    }

    #[test]
    fn rejects_invalid_base_urls() {
        let error = build_latest_price_url("not a url", "0xfeed").test_unwrap_err("invalid url");

        assert!(matches!(
            error,
            crate::PriceOracleError::InvalidConfiguration(_)
        ));
    }

    #[test]
    fn decimal_component_conversion_handles_positive_exponents() {
        let ratio =
            decimal_components_to_ratio("15", 2, &pair(), pair().pyth.as_ref().test_unwrap("feed"))
                .test_unwrap("ratio");

        assert_eq!(ratio, (1_500, 1));
    }

    #[test]
    fn decimal_component_conversion_rejects_negative_values() {
        let error = decimal_components_to_ratio(
            "-5",
            -8,
            &pair(),
            pair().pyth.as_ref().test_unwrap("feed"),
        )
        .test_unwrap_err("negative values should fail");

        assert!(matches!(error, crate::PriceOracleError::InvalidFeed(_)));
    }

    #[test]
    fn decimal_component_conversion_rejects_zero_and_overflow() {
        let zero_error =
            decimal_components_to_ratio("0", -8, &pair(), pair().pyth.as_ref().test_unwrap("feed"))
                .test_unwrap_err("zero values should fail");
        assert!(matches!(
            zero_error,
            crate::PriceOracleError::InvalidFeed(_)
        ));

        let overflow_error =
            decimal_components_to_ratio("1", 39, &pair(), pair().pyth.as_ref().test_unwrap("feed"))
                .test_unwrap_err("positive exponent overflow");
        assert!(matches!(
            overflow_error,
            crate::PriceOracleError::ArithmeticOverflow(_)
        ));
    }

    #[test]
    fn exchange_rates_fail_when_the_quote_is_stale() {
        let error = build_exchange_rate(
            &pair(),
            pair().pyth.as_ref().test_unwrap("feed"),
            PythPriceComponent {
                price: "184136023127".to_string(),
                conf: "177166324".to_string(),
                expo: -8,
                publish_time: 1_743_292_000,
            },
            1_743_292_780,
        )
        .test_unwrap_err("stale rates should fail");

        assert!(matches!(error, crate::PriceOracleError::Stale { .. }));
    }

    #[tokio::test]
    async fn backend_rejects_pairs_without_pyth_feeds() {
        let contract =
            chio_egress_contract::HttpEgressContract::permissive_for_tests("127.0.0.1:8080");
        let backend =
            PythHermesClient::new("http://127.0.0.1:8080", contract).test_unwrap("client");
        let pair = PairConfig {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            chain_id: BASE_MAINNET_CHAIN_ID,
            chainlink: None,
            pyth: None,
            policy: PairPolicy::volatile_default(),
        };

        let error = backend
            .read_rate(&pair, 1_743_292_780)
            .await
            .test_unwrap_err("missing feed");

        assert!(matches!(
            error,
            crate::PriceOracleError::NoPairAvailable { .. }
        ));
    }

    #[test]
    fn new_accepts_hostname_contract_with_pinned_dns() {
        let client = PythHermesClient::new(
            "https://hermes.pyth.network",
            chio_egress_contract::HttpEgressContract::permissive_for_tests("hermes.pyth.network"),
        )
        .test_unwrap("hostname contract is resolver-enforced at dispatch");

        assert_eq!(client.base_url, "https://hermes.pyth.network");
    }
}
