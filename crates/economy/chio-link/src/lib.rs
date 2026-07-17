//! Oracle runtime for Chio cross-currency budget enforcement.
//!
//! Reads price feeds (Chainlink, Pyth) behind a pluggable backend, caches and
//! monitors them, applies circuit-breaker thresholds, and converts amounts
//! across currencies to back budget enforcement with conversion evidence.
//! Evidence leaves this crate unsigned ([`ExchangeRate::to_conversion_evidence`]
//! sets `oracle_public_key` and `signature` to `None`); signing happens downstream.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::web3::anchors::{
    OracleConversionEvidence, CHIO_LINK_ORACLE_AUTHORITY, CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA,
};
use tokio::sync::RwLock;

pub mod cache;
#[cfg_attr(feature = "web3", path = "chainlink.rs")]
#[cfg_attr(not(feature = "web3"), path = "chainlink_disabled.rs")]
pub mod chainlink;
pub mod circuit_breaker;
pub mod config;
pub mod control;
pub mod convert;
pub mod monitor;
pub mod pyth;
mod reports;
#[cfg_attr(feature = "web3", path = "sequencer.rs")]
#[cfg_attr(not(feature = "web3"), path = "sequencer_disabled.rs")]
pub mod sequencer;

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use chio_test_support::ctx::{TestUnwrap, TestUnwrapErr};
}

use cache::PriceCache;
#[cfg(feature = "web3")]
use chainlink::ChainlinkFeedReader;
use circuit_breaker::ensure_within_threshold;
use config::{
    pair_key, OperatorConfig, OracleBackendKind, PairConfig, PairRuntimeOverride, PriceOracleConfig,
};
use monitor::{
    AlertSeverity, ChainHealthReport, ChainHealthStatus, OracleAlert, OracleRuntimeReport,
    PairHealthReport,
};
use pyth::PythHermesClient;
use reports::{
    alert_for_chain, alert_for_pair, classify_error_status, classify_success_status,
    confidence_bps, pair_success_note,
};
use sequencer::{read_sequencer_status, SequencerAvailability};

pub type OracleFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ExchangeRate, PriceOracleError>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRate {
    pub base: String,
    pub quote: String,
    pub rate_numerator: u128,
    pub rate_denominator: u128,
    pub updated_at: u64,
    pub fetched_at: u64,
    pub source: String,
    pub feed_reference: String,
    pub max_age_seconds: u64,
    pub conversion_margin_bps: u32,
    pub confidence_numerator: Option<u128>,
    pub confidence_denominator: Option<u128>,
}

impl ExchangeRate {
    #[must_use]
    pub fn pair(&self) -> String {
        pair_key(&self.base, &self.quote)
    }

    pub fn ensure_matches_pair(&self, pair: &PairConfig) -> Result<(), PriceOracleError> {
        if self.base != pair.base || self.quote != pair.quote {
            return Err(PriceOracleError::InvalidFeed(format!(
                "oracle backend returned {}/{} for {}",
                self.base,
                self.quote,
                pair.pair()
            )));
        }
        Ok(())
    }

    #[must_use]
    pub fn age_seconds(&self, now: u64) -> u64 {
        now.saturating_sub(self.updated_at)
    }

    #[must_use]
    pub fn cache_age_seconds(&self, now: u64) -> u64 {
        now.saturating_sub(self.fetched_at)
    }

    pub fn ensure_fresh(&self, now: u64) -> Result<(), PriceOracleError> {
        if self.rate_denominator == 0 {
            return Err(PriceOracleError::InvalidFeed(format!(
                "{} returned a zero rate denominator",
                self.pair()
            )));
        }
        if self.updated_at > now {
            return Err(PriceOracleError::InvalidFeed(format!(
                "{} returned a future updated_at timestamp",
                self.pair()
            )));
        }
        let age_seconds = self.age_seconds(now);
        if age_seconds > self.max_age_seconds {
            return Err(PriceOracleError::Stale {
                pair: self.pair(),
                age_seconds,
                max_age_seconds: self.max_age_seconds,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn backend_label(&self) -> String {
        self.source
            .split(':')
            .next()
            .unwrap_or(self.source.as_str())
            .to_string()
    }

    #[must_use]
    pub fn with_degraded_mode(
        mut self,
        max_age_seconds: u64,
        extra_margin_bps: u32,
        source_suffix: &str,
    ) -> Self {
        self.max_age_seconds = max_age_seconds;
        self.conversion_margin_bps = self.conversion_margin_bps.saturating_add(extra_margin_bps);
        self.source = format!("{}:{source_suffix}", self.source);
        self
    }

    pub fn to_conversion_evidence(
        &self,
        original_cost_units: u64,
        original_currency: impl Into<String>,
        grant_currency: impl Into<String>,
        converted_cost_units: u64,
        now: u64,
    ) -> Result<OracleConversionEvidence, PriceOracleError> {
        self.ensure_fresh(now)?;
        Ok(OracleConversionEvidence {
            schema: CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA.to_string(),
            base: self.base.clone(),
            quote: self.quote.clone(),
            authority: CHIO_LINK_ORACLE_AUTHORITY.to_string(),
            rate_numerator: u64::try_from(self.rate_numerator).map_err(|_| {
                PriceOracleError::ArithmeticOverflow(format!(
                    "{} rate_numerator does not fit the receipt contract",
                    self.pair()
                ))
            })?,
            rate_denominator: u64::try_from(self.rate_denominator).map_err(|_| {
                PriceOracleError::ArithmeticOverflow(format!(
                    "{} rate_denominator does not fit the receipt contract",
                    self.pair()
                ))
            })?,
            source: self.source.clone(),
            feed_address: self.feed_reference.clone(),
            updated_at: self.updated_at,
            max_age_seconds: self.max_age_seconds,
            cache_age_seconds: self.cache_age_seconds(now),
            converted_cost_units,
            original_cost_units,
            original_currency: original_currency.into(),
            grant_currency: grant_currency.into(),
            oracle_public_key: None,
            signature: None,
        })
    }
}

#[derive(Debug, thiserror::Error, Clone)]
pub enum PriceOracleError {
    #[error("no feed configured for {base}/{quote}")]
    NoPairAvailable { base: String, quote: String },
    #[error("invalid price oracle configuration: {0}")]
    InvalidConfiguration(String),
    #[error("unsupported oracle backend: {0}")]
    UnsupportedBackend(String),
    #[error("price stale: age {age_seconds}s exceeds max {max_age_seconds}s for {pair}")]
    Stale {
        pair: String,
        age_seconds: u64,
        max_age_seconds: u64,
    },
    #[error(
        "oracle sources diverge by {divergence_pct:.2}% for {pair} (threshold: {threshold_pct:.2}%)"
    )]
    CircuitBreakerTripped {
        pair: String,
        divergence_pct: f64,
        threshold_pct: f64,
    },
    #[error("operator pause is active{pair_suffix}: {reason}")]
    OperatorPaused { pair_suffix: String, reason: String },
    #[error("trusted chain {chain_id} is disabled for {pair}")]
    ChainDisabled { pair: String, chain_id: u64 },
    #[error("L2 sequencer is down for chain {chain_id} while resolving {pair} ({feed_address})")]
    SequencerDown {
        pair: String,
        chain_id: u64,
        feed_address: String,
    },
    #[error(
        "L2 sequencer recovery grace remains active for chain {chain_id} while resolving {pair} ({feed_address}); {remaining_seconds}s remaining"
    )]
    SequencerRecovering {
        pair: String,
        chain_id: u64,
        feed_address: String,
        remaining_seconds: u64,
    },
    #[error("oracle backend unavailable: {0}")]
    Unavailable(String),
    #[error("invalid feed response: {0}")]
    InvalidFeed(String),
    #[error("arithmetic overflow: {0}")]
    ArithmeticOverflow(String),
}

impl PriceOracleError {
    pub(crate) fn invalid_configuration(message: impl Into<String>) -> Self {
        Self::InvalidConfiguration(message.into())
    }
}

pub trait PriceOracle: Send + Sync {
    fn get_rate<'a>(&'a self, base: &'a str, quote: &'a str) -> OracleFuture<'a>;

    fn supported_pairs(&self) -> Vec<String>;
}

pub trait OracleBackend: Send + Sync {
    fn kind(&self) -> OracleBackendKind;

    fn read_rate<'a>(&'a self, pair: &'a PairConfig, now: u64) -> OracleFuture<'a>;
}

pub struct ChioLinkOracle {
    config: PriceOracleConfig,
    primary: Arc<dyn OracleBackend>,
    fallback: Option<Arc<dyn OracleBackend>>,
    cache: RwLock<PriceCache>,
    operator: RwLock<OperatorConfig>,
}

impl ChioLinkOracle {
    pub fn new(config: PriceOracleConfig) -> Result<Self, PriceOracleError> {
        config.validate()?;
        let primary = build_backend(config.primary, &config)?;
        let fallback = match config.fallback {
            Some(kind) => Some(build_backend(kind, &config)?),
            None => None,
        };
        Self::new_with_backends(config, primary, fallback)
    }

    pub fn new_with_backends(
        config: PriceOracleConfig,
        primary: Arc<dyn OracleBackend>,
        fallback: Option<Arc<dyn OracleBackend>>,
    ) -> Result<Self, PriceOracleError> {
        config.validate()?;
        if primary.kind() != config.primary {
            return Err(PriceOracleError::InvalidConfiguration(format!(
                "configured primary backend {:?} does not match implementation {:?}",
                config.primary,
                primary.kind()
            )));
        }
        if let (Some(expected), Some(backend)) = (config.fallback, fallback.as_ref()) {
            if backend.kind() != expected {
                return Err(PriceOracleError::InvalidConfiguration(format!(
                    "configured fallback backend {:?} does not match implementation {:?}",
                    expected,
                    backend.kind()
                )));
            }
        }
        Ok(Self {
            operator: RwLock::new(config.operator.clone()),
            config,
            primary,
            fallback,
            cache: RwLock::new(PriceCache::default()),
        })
    }

    #[must_use]
    pub fn config(&self) -> &PriceOracleConfig {
        &self.config
    }

    pub async fn operator_config(&self) -> OperatorConfig {
        self.operator.read().await.clone()
    }

    pub async fn set_global_pause(
        &self,
        paused: bool,
        reason: Option<String>,
    ) -> Result<(), PriceOracleError> {
        let mut operator = self.operator.write().await;
        operator.global_pause = paused;
        operator.pause_reason = reason;
        self.config.validate()?;
        Ok(())
    }

    pub async fn set_chain_enabled(
        &self,
        chain_id: u64,
        enabled: bool,
    ) -> Result<(), PriceOracleError> {
        let mut operator = self.operator.write().await;
        let chain = operator.chain(chain_id).cloned().ok_or_else(|| {
            PriceOracleError::InvalidConfiguration(format!(
                "cannot toggle unknown operator chain_id {}",
                chain_id
            ))
        })?;
        let index = operator
            .chains
            .iter()
            .position(|current| current.chain_id == chain.chain_id)
            .ok_or_else(|| {
                PriceOracleError::InvalidConfiguration(format!(
                    "operator chain_id {} vanished during update",
                    chain_id
                ))
            })?;
        operator.chains[index].enabled = enabled;
        Ok(())
    }

    pub async fn set_pair_override(
        &self,
        pair_override: PairRuntimeOverride,
    ) -> Result<(), PriceOracleError> {
        self.config
            .pair(&pair_override.base, &pair_override.quote)
            .ok_or_else(|| {
                PriceOracleError::InvalidConfiguration(format!(
                    "cannot override unsupported pair {}",
                    pair_override.pair()
                ))
            })?;
        let mut operator = self.operator.write().await;
        let pair_key = pair_override.pair();
        if let Some(index) = operator
            .pair_overrides
            .iter()
            .position(|current| current.pair() == pair_key)
        {
            operator.pair_overrides[index] = pair_override;
        } else {
            operator.pair_overrides.push(pair_override);
        }
        Ok(())
    }

    pub async fn cached_rate(
        &self,
        base: &str,
        quote: &str,
    ) -> Result<Option<ExchangeRate>, PriceOracleError> {
        let pair =
            self.pair_config(base, quote)?
                .ok_or_else(|| PriceOracleError::NoPairAvailable {
                    base: base.to_ascii_uppercase(),
                    quote: quote.to_ascii_uppercase(),
                })?;
        let now = now_unix()?;
        let operator = self.operator_config().await;
        self.resolve_cached_rate(&pair, now, &operator).await
    }

    pub async fn refresh_pair(
        &self,
        base: &str,
        quote: &str,
    ) -> Result<ExchangeRate, PriceOracleError> {
        let pair =
            self.pair_config(base, quote)?
                .ok_or_else(|| PriceOracleError::NoPairAvailable {
                    base: base.to_ascii_uppercase(),
                    quote: quote.to_ascii_uppercase(),
                })?;
        let now = now_unix()?;
        let operator = self.operator_config().await;
        self.refresh_pair_inner(&pair, now, &operator).await
    }

    pub async fn runtime_report(&self) -> Result<OracleRuntimeReport, PriceOracleError> {
        let now = now_unix()?;
        let operator = self.operator_config().await;
        let mut report = OracleRuntimeReport::new(now);
        report.global_pause = operator.global_pause;
        report.pause_reason = operator.pause_reason.clone();

        for chain in &operator.chains {
            let chain_report = self.chain_health_report(chain, now).await;
            if operator.monitoring.alert_on_sequencer {
                if let Some(alert) = alert_for_chain(&chain_report, now) {
                    report.alerts.push(alert);
                }
            }
            report.chains.push(chain_report);
        }

        for pair in &self.config.pairs {
            let pair_report = self.pair_health_report(pair, &operator, now).await;
            if let Some(alert) = alert_for_pair(&pair_report, &operator.monitoring, now) {
                report.alerts.push(alert);
            }
            report.pairs.push(pair_report);
        }

        if operator.global_pause && operator.monitoring.alert_on_pause {
            report.alerts.push(OracleAlert {
                code: "global_pause".to_string(),
                severity: AlertSeverity::Critical,
                message: operator
                    .pause_reason
                    .clone()
                    .unwrap_or_else(|| "chio-link global pause is active".to_string()),
                pair: None,
                chain_id: None,
                observed_at: now,
            });
        }

        Ok(report)
    }

    async fn chain_health_report(
        &self,
        chain: &config::ChainlinkNetworkConfig,
        now: u64,
    ) -> ChainHealthReport {
        if !chain.enabled {
            return ChainHealthReport {
                chain_id: chain.chain_id,
                label: chain.label.clone(),
                caip2: chain.caip2.clone(),
                enabled: false,
                status: ChainHealthStatus::Disabled,
                sequencer_uptime_feed: chain.sequencer_uptime_feed.clone(),
                checked_at: Some(now),
                status_started_at: None,
                note: Some("operator disabled this chain".to_string()),
            };
        }

        match read_sequencer_status(chain, now, &self.config.egress_contract).await {
            Ok(Some(status)) => {
                let (health, note) = match status.availability {
                    SequencerAvailability::Up => (ChainHealthStatus::Healthy, None),
                    SequencerAvailability::Down => (
                        ChainHealthStatus::Down,
                        Some("L2 sequencer is down; fail closed".to_string()),
                    ),
                    SequencerAvailability::Recovering => (
                        ChainHealthStatus::Recovering,
                        Some("L2 sequencer recently recovered; grace window active".to_string()),
                    ),
                };
                ChainHealthReport {
                    chain_id: chain.chain_id,
                    label: chain.label.clone(),
                    caip2: chain.caip2.clone(),
                    enabled: true,
                    status: health,
                    sequencer_uptime_feed: Some(status.feed_address),
                    checked_at: Some(status.checked_at),
                    status_started_at: Some(status.status_started_at),
                    note,
                }
            }
            Ok(None) => ChainHealthReport {
                chain_id: chain.chain_id,
                label: chain.label.clone(),
                caip2: chain.caip2.clone(),
                enabled: true,
                status: ChainHealthStatus::Unmonitored,
                sequencer_uptime_feed: None,
                checked_at: Some(now),
                status_started_at: None,
                note: Some("no sequencer uptime feed configured".to_string()),
            },
            Err(error) => ChainHealthReport {
                chain_id: chain.chain_id,
                label: chain.label.clone(),
                caip2: chain.caip2.clone(),
                enabled: true,
                status: ChainHealthStatus::Unavailable,
                sequencer_uptime_feed: chain.sequencer_uptime_feed.clone(),
                checked_at: Some(now),
                status_started_at: None,
                note: Some(error.to_string()),
            },
        }
    }

    async fn pair_health_report(
        &self,
        pair: &PairConfig,
        operator: &OperatorConfig,
        now: u64,
    ) -> PairHealthReport {
        let pair_override = self.effective_pair_override(operator, pair);
        match self.rate_for_pair(pair, now, operator).await {
            Ok(rate) => {
                let pair_status =
                    classify_success_status(&rate, &pair_override, self.config.primary);
                PairHealthReport {
                    pair: pair.pair(),
                    chain_id: pair.chain_id,
                    status: pair_status,
                    active_backend: Some(rate.backend_label()),
                    active_source: Some(rate.source.clone()),
                    feed_reference: Some(rate.feed_reference.clone()),
                    updated_at: Some(rate.updated_at),
                    cache_age_seconds: Some(rate.cache_age_seconds(now)),
                    conversion_margin_bps: Some(rate.conversion_margin_bps),
                    confidence_bps: confidence_bps(&rate),
                    note: pair_success_note(&rate, &pair_override),
                    last_error: None,
                }
            }
            Err(error) => PairHealthReport {
                pair: pair.pair(),
                chain_id: pair.chain_id,
                status: classify_error_status(&error),
                active_backend: None,
                active_source: None,
                feed_reference: None,
                updated_at: None,
                cache_age_seconds: None,
                conversion_margin_bps: None,
                confidence_bps: None,
                note: None,
                last_error: Some(error.to_string()),
            },
        }
    }

    async fn rate_for_pair(
        &self,
        pair: &PairConfig,
        now: u64,
        operator: &OperatorConfig,
    ) -> Result<ExchangeRate, PriceOracleError> {
        if let Some(rate) = self.resolve_cached_rate(pair, now, operator).await? {
            return Ok(rate);
        }
        self.refresh_pair_inner(pair, now, operator).await
    }

    async fn resolve_cached_rate(
        &self,
        pair: &PairConfig,
        now: u64,
        operator: &OperatorConfig,
    ) -> Result<Option<ExchangeRate>, PriceOracleError> {
        self.enforce_operator_controls(pair, now, operator).await?;
        let pair_override = self.effective_pair_override(operator, pair);
        let mut cache = self.cache.write().await;
        match cache.resolve(pair, now) {
            Ok(rate) => Ok(rate),
            Err(error @ PriceOracleError::Stale { .. }) => {
                if let Some(stale_rate) = cache.latest(pair) {
                    if let Some(rate) =
                        degraded_rate_if_allowed(pair, &pair_override, stale_rate, now)
                    {
                        return Ok(Some(rate));
                    }
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    async fn refresh_pair_inner(
        &self,
        pair: &PairConfig,
        now: u64,
        operator: &OperatorConfig,
    ) -> Result<ExchangeRate, PriceOracleError> {
        self.enforce_operator_controls(pair, now, operator).await?;
        let rate = self.fetch_authoritative_rate(pair, now, operator).await?;
        let mut cache = self.cache.write().await;
        cache.record(pair, rate, now)?;
        cache.resolve(pair, now)?.ok_or_else(|| {
            PriceOracleError::Unavailable(format!(
                "cache entry missing after refresh for {}",
                pair.pair()
            ))
        })
    }

    async fn fetch_authoritative_rate(
        &self,
        pair: &PairConfig,
        now: u64,
        operator: &OperatorConfig,
    ) -> Result<ExchangeRate, PriceOracleError> {
        let pair_override = self.effective_pair_override(operator, pair);

        if let Some(kind) = pair_override.force_backend {
            let backend = self.backend_for_kind(kind).ok_or_else(|| {
                PriceOracleError::UnsupportedBackend(format!(
                    "forced backend {:?} is not available in chio-link",
                    kind
                ))
            })?;
            if !pair_supports_backend(pair, kind) {
                return Err(PriceOracleError::UnsupportedBackend(format!(
                    "{} does not support forced backend {:?}",
                    pair.pair(),
                    kind
                )));
            }
            return read_validated_backend_rate(backend.as_ref(), pair, now).await;
        }

        match read_validated_backend_rate(self.primary.as_ref(), pair, now).await {
            Ok(primary_rate) => {
                if let Some(secondary) = self.secondary_backend_for_pair(pair, &pair_override) {
                    if let Ok(secondary_rate) =
                        read_validated_backend_rate(secondary.as_ref(), pair, now).await
                    {
                        ensure_within_threshold(
                            &primary_rate,
                            &secondary_rate,
                            pair_override
                                .divergence_threshold_bps
                                .unwrap_or(pair.policy.divergence_threshold_bps),
                        )?;
                    }
                }
                Ok(primary_rate)
            }
            Err(primary_error) => {
                if let Some(secondary) = self.secondary_backend_for_pair(pair, &pair_override) {
                    read_validated_backend_rate(secondary.as_ref(), pair, now).await
                } else {
                    Err(primary_error)
                }
            }
        }
    }

    async fn enforce_operator_controls(
        &self,
        pair: &PairConfig,
        now: u64,
        operator: &OperatorConfig,
    ) -> Result<(), PriceOracleError> {
        if operator.global_pause {
            return Err(PriceOracleError::OperatorPaused {
                pair_suffix: format!(" for {}", pair.pair()),
                reason: operator
                    .pause_reason
                    .clone()
                    .unwrap_or_else(|| "operator global pause is active".to_string()),
            });
        }

        let pair_override = self.effective_pair_override(operator, pair);
        if !pair_override.enabled {
            return Err(PriceOracleError::OperatorPaused {
                pair_suffix: format!(" for {}", pair.pair()),
                reason: "pair-specific operator disable is active".to_string(),
            });
        }

        let chain = operator.chain(pair.chain_id).ok_or_else(|| {
            PriceOracleError::InvalidConfiguration(format!(
                "{} references unknown operator chain_id {}",
                pair.pair(),
                pair.chain_id
            ))
        })?;
        if !chain.enabled {
            return Err(PriceOracleError::ChainDisabled {
                pair: pair.pair(),
                chain_id: chain.chain_id,
            });
        }

        if let Some(status) =
            read_sequencer_status(chain, now, &self.config.egress_contract).await?
        {
            match status.availability {
                SequencerAvailability::Up => {}
                SequencerAvailability::Down => {
                    return Err(PriceOracleError::SequencerDown {
                        pair: pair.pair(),
                        chain_id: chain.chain_id,
                        feed_address: status.feed_address,
                    });
                }
                SequencerAvailability::Recovering => {
                    let elapsed = now.saturating_sub(status.status_started_at);
                    return Err(PriceOracleError::SequencerRecovering {
                        pair: pair.pair(),
                        chain_id: chain.chain_id,
                        feed_address: status.feed_address,
                        remaining_seconds: chain
                            .sequencer_grace_period_seconds
                            .saturating_sub(elapsed),
                    });
                }
            }
        }

        Ok(())
    }

    fn pair_config(&self, base: &str, quote: &str) -> Result<Option<PairConfig>, PriceOracleError> {
        self.config.validate()?;
        Ok(self.config.pair(base, quote).cloned())
    }

    fn backend_for_kind(&self, kind: OracleBackendKind) -> Option<&Arc<dyn OracleBackend>> {
        if self.primary.kind() == kind {
            Some(&self.primary)
        } else if self
            .fallback
            .as_ref()
            .is_some_and(|backend| backend.kind() == kind)
        {
            self.fallback.as_ref()
        } else {
            None
        }
    }

    fn effective_pair_override(
        &self,
        operator: &OperatorConfig,
        pair: &PairConfig,
    ) -> PairRuntimeOverride {
        operator
            .pair_override(&pair.base, &pair.quote)
            .cloned()
            .unwrap_or_else(|| PairRuntimeOverride::from_pair(pair))
    }

    fn secondary_backend_for_pair(
        &self,
        pair: &PairConfig,
        pair_override: &PairRuntimeOverride,
    ) -> Option<&Arc<dyn OracleBackend>> {
        if !pair_override.allow_fallback {
            return None;
        }
        let backend = self.fallback.as_ref()?;
        if pair_supports_backend(pair, backend.kind()) {
            Some(backend)
        } else {
            None
        }
    }
}

impl PriceOracle for ChioLinkOracle {
    fn get_rate<'a>(&'a self, base: &'a str, quote: &'a str) -> OracleFuture<'a> {
        Box::pin(async move {
            let pair = self.pair_config(base, quote)?.ok_or_else(|| {
                PriceOracleError::NoPairAvailable {
                    base: base.to_ascii_uppercase(),
                    quote: quote.to_ascii_uppercase(),
                }
            })?;
            let now = now_unix()?;
            let operator = self.operator_config().await;
            self.rate_for_pair(&pair, now, &operator).await
        })
    }

    fn supported_pairs(&self) -> Vec<String> {
        self.config.supported_pairs()
    }
}

fn build_backend(
    kind: OracleBackendKind,
    config: &PriceOracleConfig,
) -> Result<Arc<dyn OracleBackend>, PriceOracleError> {
    let backend: Arc<dyn OracleBackend> = match kind {
        OracleBackendKind::Chainlink => {
            #[cfg(feature = "web3")]
            {
                Arc::new(ChainlinkFeedReader::new(
                    config.operator.chains.clone(),
                    config.egress_contract.clone(),
                ))
            }
            #[cfg(not(feature = "web3"))]
            {
                let _ = config;
                return Err(PriceOracleError::UnsupportedBackend(
                    "Chainlink backend requires the `web3` feature".to_string(),
                ));
            }
        }
        OracleBackendKind::Pyth => Arc::new(PythHermesClient::new(
            config.pyth.hermes_url.clone(),
            config.egress_contract.clone(),
        )?),
    };
    Ok(backend)
}

fn pair_supports_backend(pair: &PairConfig, kind: OracleBackendKind) -> bool {
    match kind {
        OracleBackendKind::Chainlink => pair.chainlink.is_some(),
        OracleBackendKind::Pyth => pair.pyth.is_some(),
    }
}

async fn read_validated_backend_rate(
    backend: &dyn OracleBackend,
    pair: &PairConfig,
    now: u64,
) -> Result<ExchangeRate, PriceOracleError> {
    let rate = backend.read_rate(pair, now).await?;
    rate.ensure_matches_pair(pair)?;
    rate.ensure_fresh(now)?;
    Ok(rate)
}

fn degraded_rate_if_allowed(
    pair: &PairConfig,
    pair_override: &PairRuntimeOverride,
    stale_rate: ExchangeRate,
    now: u64,
) -> Option<ExchangeRate> {
    let degraded_mode = pair_override
        .degraded_mode
        .clone()
        .unwrap_or_else(|| pair.policy.degraded_mode.clone());
    if !degraded_mode.enabled {
        return None;
    }
    let allowed_age = pair
        .policy
        .max_age_seconds
        .saturating_add(degraded_mode.max_stale_age_seconds);
    if stale_rate.age_seconds(now) > allowed_age {
        return None;
    }
    Some(stale_rate.with_degraded_mode(allowed_age, degraded_mode.extra_margin_bps, "degraded"))
}

fn now_unix() -> Result<u64, PriceOracleError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| {
            PriceOracleError::Unavailable(format!("system clock is before UNIX epoch: {err}"))
        })
}

#[cfg(test)]
mod tests;
