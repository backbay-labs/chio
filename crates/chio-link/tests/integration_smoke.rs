use chio_link::config::{build_default_egress_contract, PriceOracleConfig};
use chio_link::ExchangeRate;

#[test]
fn exchange_rate_helpers_reflect_public_contract() {
    let rate = ExchangeRate {
        base: "eth".to_string(),
        quote: "usd".to_string(),
        rate_numerator: 3_000,
        rate_denominator: 1,
        updated_at: 100,
        fetched_at: 110,
        source: "chainlink:base".to_string(),
        feed_reference: "feed-1".to_string(),
        max_age_seconds: 60,
        conversion_margin_bps: 25,
        confidence_numerator: None,
        confidence_denominator: None,
    };

    assert_eq!(rate.pair(), "ETH/USD");
    assert_eq!(rate.age_seconds(120), 20);
    assert!(rate.ensure_fresh(120).is_ok());
}

#[test]
fn default_price_oracle_config_validates() {
    let mut config =
        PriceOracleConfig::base_arbitrum_default("http://127.0.0.1:8545", "http://127.0.0.1:9545");
    config.pyth.hermes_url = "http://127.0.0.1:9000".to_string();
    config.egress_contract = build_default_egress_contract(&config.pyth, &config.operator.chains);
    config.egress_contract.deny_loopback = false;

    assert!(config.validate().is_ok());
}
