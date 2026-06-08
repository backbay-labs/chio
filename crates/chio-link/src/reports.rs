use crate::config::{MonitoringConfig, OracleBackendKind, PairRuntimeOverride};
use crate::monitor::{
    AlertSeverity, ChainHealthReport, ChainHealthStatus, OracleAlert, PairHealthReport,
    PairHealthStatus,
};
use crate::{ExchangeRate, PriceOracleError};

pub(crate) fn confidence_bps(rate: &ExchangeRate) -> Option<u32> {
    let (Some(confidence_numerator), Some(confidence_denominator)) =
        (rate.confidence_numerator, rate.confidence_denominator)
    else {
        return None;
    };
    let numerator = confidence_numerator
        .checked_mul(rate.rate_denominator)?
        .checked_mul(10_000)?;
    let denominator = confidence_denominator.checked_mul(rate.rate_numerator)?;
    if denominator == 0 {
        return None;
    }
    u32::try_from(numerator.div_ceil(denominator)).ok()
}

pub(crate) fn classify_success_status(
    rate: &ExchangeRate,
    pair_override: &PairRuntimeOverride,
    primary_kind: OracleBackendKind,
) -> PairHealthStatus {
    if rate.source.contains(":degraded") {
        return PairHealthStatus::DegradedGrace;
    }
    if pair_override.force_backend.is_none()
        && rate.backend_label() == "pyth"
        && primary_kind == OracleBackendKind::Chainlink
    {
        return PairHealthStatus::FallbackActive;
    }
    PairHealthStatus::Healthy
}

pub(crate) fn classify_error_status(error: &PriceOracleError) -> PairHealthStatus {
    match error {
        PriceOracleError::OperatorPaused { .. } | PriceOracleError::ChainDisabled { .. } => {
            PairHealthStatus::Paused
        }
        PriceOracleError::CircuitBreakerTripped { .. }
        | PriceOracleError::SequencerDown { .. }
        | PriceOracleError::SequencerRecovering { .. } => PairHealthStatus::Tripped,
        _ => PairHealthStatus::Unavailable,
    }
}

pub(crate) fn pair_success_note(
    rate: &ExchangeRate,
    pair_override: &PairRuntimeOverride,
) -> Option<String> {
    if rate.source.contains(":degraded") {
        return Some("using degraded stale-cache grace policy".to_string());
    }
    pair_override.force_backend.map(|backend| {
        format!(
            "operator forced backend {}",
            match backend {
                OracleBackendKind::Chainlink => "chainlink",
                OracleBackendKind::Pyth => "pyth",
            }
        )
    })
}

pub(crate) fn alert_for_chain(chain: &ChainHealthReport, observed_at: u64) -> Option<OracleAlert> {
    let (code, severity, message) = match chain.status {
        ChainHealthStatus::Down => (
            "sequencer_down",
            AlertSeverity::Critical,
            chain
                .note
                .clone()
                .unwrap_or_else(|| "sequencer is down".to_string()),
        ),
        ChainHealthStatus::Recovering => (
            "sequencer_recovering",
            AlertSeverity::Warning,
            chain
                .note
                .clone()
                .unwrap_or_else(|| "sequencer recovery grace is active".to_string()),
        ),
        ChainHealthStatus::Unavailable => (
            "sequencer_monitor_unavailable",
            AlertSeverity::Warning,
            chain
                .note
                .clone()
                .unwrap_or_else(|| "sequencer monitor failed".to_string()),
        ),
        _ => return None,
    };
    Some(OracleAlert {
        code: code.to_string(),
        severity,
        message,
        pair: None,
        chain_id: Some(chain.chain_id),
        observed_at,
    })
}

pub(crate) fn alert_for_pair(
    pair: &PairHealthReport,
    monitoring: &MonitoringConfig,
    observed_at: u64,
) -> Option<OracleAlert> {
    let (code, severity, enabled) = match pair.status {
        PairHealthStatus::FallbackActive => (
            "fallback_active",
            AlertSeverity::Warning,
            monitoring.alert_on_fallback,
        ),
        PairHealthStatus::DegradedGrace => (
            "degraded_grace_active",
            AlertSeverity::Warning,
            monitoring.alert_on_degraded,
        ),
        PairHealthStatus::Paused => (
            "pair_paused",
            AlertSeverity::Critical,
            monitoring.alert_on_pause,
        ),
        PairHealthStatus::Tripped => ("pair_tripped", AlertSeverity::Critical, true),
        PairHealthStatus::Unavailable => ("pair_unavailable", AlertSeverity::Warning, true),
        PairHealthStatus::Healthy => return None,
    };
    if !enabled {
        return None;
    }
    Some(OracleAlert {
        code: code.to_string(),
        severity,
        message: pair
            .last_error
            .clone()
            .or_else(|| pair.note.clone())
            .unwrap_or_else(|| format!("{} status is {:?}", pair.pair, pair.status)),
        pair: Some(pair.pair.clone()),
        chain_id: Some(pair.chain_id),
        observed_at,
    })
}
