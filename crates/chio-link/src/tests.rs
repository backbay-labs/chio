use std::collections::BTreeMap;

use super::*;
use crate::config::{
    build_default_egress_contract, DegradedModePolicy, PriceOracleConfig, BASE_MAINNET_CHAIN_ID,
};
use crate::test_support::{TestUnwrap, TestUnwrapErr};

struct StaticBackend {
    kind: OracleBackendKind,
    responses: BTreeMap<String, Result<ExchangeRate, PriceOracleError>>,
}

impl StaticBackend {
    fn new(
        kind: OracleBackendKind,
        responses: impl IntoIterator<Item = (String, Result<ExchangeRate, PriceOracleError>)>,
    ) -> Self {
        Self {
            kind,
            responses: responses.into_iter().collect(),
        }
    }
}

impl OracleBackend for StaticBackend {
    fn kind(&self) -> OracleBackendKind {
        self.kind
    }

    fn read_rate<'a>(&'a self, pair: &'a PairConfig, _now: u64) -> OracleFuture<'a> {
        let response = self
            .responses
            .get(&pair.pair())
            .cloned()
            .unwrap_or_else(|| {
                Err(PriceOracleError::NoPairAvailable {
                    base: pair.base.clone(),
                    quote: pair.quote.clone(),
                })
            });
        Box::pin(async move { response })
    }
}

fn sample_rate(source: &str, feed_reference: &str, numerator: u128) -> ExchangeRate {
    let fetched_at = now_unix().test_unwrap("now");
    ExchangeRate {
        base: "ETH".to_string(),
        quote: "USD".to_string(),
        rate_numerator: numerator,
        rate_denominator: 100,
        updated_at: fetched_at.saturating_sub(45),
        fetched_at,
        source: source.to_string(),
        feed_reference: feed_reference.to_string(),
        max_age_seconds: 600,
        conversion_margin_bps: 200,
        confidence_numerator: None,
        confidence_denominator: None,
    }
}

fn test_config() -> PriceOracleConfig {
    let mut config =
        PriceOracleConfig::base_arbitrum_default("http://127.0.0.1:8545", "http://127.0.0.1:9545");
    config.pyth.hermes_url = "http://127.0.0.1:9000".to_string();
    for chain in &mut config.operator.chains {
        chain.sequencer_uptime_feed = None;
    }
    config.egress_contract = build_default_egress_contract(&config.pyth, &config.operator.chains);
    config.egress_contract.deny_loopback = false;
    config
}

#[test]
fn invalid_configuration_constructor_preserves_message() {
    let error = PriceOracleError::invalid_configuration("bad oracle config");
    assert!(matches!(
        error,
        PriceOracleError::InvalidConfiguration(message) if message == "bad oracle config"
    ));
}

#[test]
fn future_rate_updates_fail_closed() {
    let now = now_unix().test_unwrap("now");
    let mut rate = sample_rate("chainlink", "feed-1", 300_000);
    rate.updated_at = now + 1;

    assert!(matches!(
        rate.ensure_fresh(now),
        Err(PriceOracleError::InvalidFeed(message))
            if message.contains("future updated_at")
    ));
}

#[tokio::test]
async fn falls_back_when_primary_is_unavailable() {
    let config = test_config();
    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        [(
            "ETH/USD".to_string(),
            Err(PriceOracleError::Unavailable("chainlink down".to_string())),
        )],
    ));
    let fallback = Arc::new(StaticBackend::new(
        OracleBackendKind::Pyth,
        [(
            "ETH/USD".to_string(),
            Ok(sample_rate(
                "pyth",
                "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace",
                305_000,
            )),
        )],
    ));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, Some(fallback))
        .test_unwrap("oracle config");

    let rate = oracle
        .get_rate("ETH", "USD")
        .await
        .test_unwrap("fallback rate");
    assert_eq!(rate.source, "pyth");
}

#[tokio::test]
async fn divergence_trips_fail_closed_policy() {
    let config = test_config();
    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        [(
            "ETH/USD".to_string(),
            Ok(sample_rate(
                "chainlink",
                "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70",
                300_000,
            )),
        )],
    ));
    let fallback = Arc::new(StaticBackend::new(
        OracleBackendKind::Pyth,
        [(
            "ETH/USD".to_string(),
            Ok(sample_rate(
                "pyth",
                "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace",
                330_000,
            )),
        )],
    ));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, Some(fallback))
        .test_unwrap("oracle config");

    let error = oracle
        .refresh_pair("ETH", "USD")
        .await
        .test_unwrap_err("should fail closed");
    assert!(matches!(
        error,
        PriceOracleError::CircuitBreakerTripped { .. }
    ));
}

#[tokio::test]
async fn backend_pair_mismatch_fails_closed_before_cache_insert() {
    let config = test_config();
    let mut mismatched = sample_rate(
        "chainlink",
        "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70",
        300_000,
    );
    mismatched.quote = "EUR".to_string();
    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        [("ETH/USD".to_string(), Ok(mismatched))],
    ));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, None).test_unwrap("oracle");

    let error = oracle
        .refresh_pair("ETH", "USD")
        .await
        .test_unwrap_err("pair mismatch must fail closed");

    assert!(matches!(
        error,
        PriceOracleError::InvalidFeed(message)
            if message.contains("returned ETH/EUR for ETH/USD")
    ));
    assert!(
        oracle
            .cached_rate("ETH", "USD")
            .await
            .test_unwrap("cache lookup")
            .is_none(),
        "mismatched backend rates must not enter the cache"
    );
}

#[tokio::test]
async fn global_pause_stops_budget_resolution() {
    let config = test_config();
    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        [(
            "ETH/USD".to_string(),
            Ok(sample_rate(
                "chainlink",
                "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70",
                300_000,
            )),
        )],
    ));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, None).test_unwrap("oracle");
    oracle
        .set_global_pause(true, Some("manual operator stop".to_string()))
        .await
        .test_unwrap("pause");
    let error = oracle
        .get_rate("ETH", "USD")
        .await
        .test_unwrap_err("paused");
    assert!(matches!(error, PriceOracleError::OperatorPaused { .. }));
}

#[tokio::test]
async fn disabling_trusted_chain_blocks_the_pair() {
    let config = test_config();
    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        [(
            "ETH/USD".to_string(),
            Ok(sample_rate(
                "chainlink",
                "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70",
                300_000,
            )),
        )],
    ));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, None).test_unwrap("oracle");
    oracle
        .set_chain_enabled(BASE_MAINNET_CHAIN_ID, false)
        .await
        .test_unwrap("disable chain");
    let error = oracle
        .get_rate("ETH", "USD")
        .await
        .test_unwrap_err("disabled chain should fail");
    assert!(matches!(error, PriceOracleError::ChainDisabled { .. }));
}

#[tokio::test]
async fn operator_can_force_specific_backend() {
    let config = test_config();
    let primary = Arc::new(StaticBackend::new(
        OracleBackendKind::Chainlink,
        [(
            "ETH/USD".to_string(),
            Ok(sample_rate(
                "chainlink",
                "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70",
                300_000,
            )),
        )],
    ));
    let fallback = Arc::new(StaticBackend::new(
        OracleBackendKind::Pyth,
        [(
            "ETH/USD".to_string(),
            Ok(sample_rate(
                "pyth",
                "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace",
                305_000,
            )),
        )],
    ));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, Some(fallback))
        .test_unwrap("oracle config");
    oracle
        .set_pair_override(PairRuntimeOverride {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            enabled: true,
            force_backend: Some(OracleBackendKind::Pyth),
            allow_fallback: false,
            divergence_threshold_bps: None,
            degraded_mode: None,
        })
        .await
        .test_unwrap("override");

    let rate = oracle
        .get_rate("ETH", "USD")
        .await
        .test_unwrap("forced backend");
    assert_eq!(rate.source, "pyth");
}

#[tokio::test]
async fn unsupported_pair_fails_closed() {
    let config = test_config();
    let primary = Arc::new(StaticBackend::new(OracleBackendKind::Chainlink, []));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, None).test_unwrap("oracle");
    let error = oracle
        .get_rate("EUR", "USD")
        .await
        .test_unwrap_err("unsupported pair");
    assert!(matches!(error, PriceOracleError::NoPairAvailable { .. }));
}

#[test]
fn degraded_mode_reuses_stale_cached_rate_with_extra_margin() {
    let mut pair = test_config().pair("ETH", "USD").test_unwrap("pair").clone();
    pair.policy.degraded_mode = DegradedModePolicy::conservative_default();
    let stale_rate = ExchangeRate {
        updated_at: 100,
        fetched_at: 150,
        max_age_seconds: 600,
        conversion_margin_bps: 200,
        ..sample_rate(
            "chainlink",
            "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70",
            300_000,
        )
    };
    let override_config = PairRuntimeOverride::from_pair(&pair);
    let degraded = degraded_rate_if_allowed(&pair, &override_config, stale_rate, 850)
        .test_unwrap("degraded rate");
    assert_eq!(degraded.max_age_seconds, 900);
    assert_eq!(degraded.conversion_margin_bps, 1_000);
    assert!(degraded.source.ends_with(":degraded"));
}

#[tokio::test]
async fn runtime_report_surfaces_pause_alert() {
    let config = test_config();
    let primary = Arc::new(StaticBackend::new(OracleBackendKind::Chainlink, []));
    let oracle = ChioLinkOracle::new_with_backends(config, primary, None).test_unwrap("oracle");
    oracle
        .set_global_pause(true, Some("manual operator stop".to_string()))
        .await
        .test_unwrap("pause");
    let report = oracle.runtime_report().await.test_unwrap("report");
    assert!(report.global_pause);
    assert!(report
        .alerts
        .iter()
        .any(|alert| alert.code == "global_pause"));
}

#[test]
fn builds_conversion_evidence() {
    let rate = sample_rate(
        "chainlink",
        "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70",
        300_000,
    );
    let now = rate.fetched_at + 35;
    let evidence = rate
        .to_conversion_evidence(100_000_000_000_000, "ETH", "USD", 300, now)
        .test_unwrap("evidence");
    assert_eq!(evidence.schema, CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA);
    assert_eq!(evidence.authority, CHIO_LINK_ORACLE_AUTHORITY);
    assert_eq!(
        evidence.feed_address,
        "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70"
    );
    assert_eq!(evidence.cache_age_seconds, 35);
}
